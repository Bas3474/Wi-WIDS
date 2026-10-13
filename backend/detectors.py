"""Detection rules (Phase 2)

ไม่พึ่ง pydantic/scapy เพื่อให้ทดสอบด้วย unit test ล้วน ๆ ได้
ทุก detector รับ Event ทีละตัว (feed) แล้วคืน list ของ Detection
เวลาอ้างอิงจาก Event.ts เสมอ (ไม่ใช้ time.time()) เพื่อให้ replay pcap/ทดสอบได้
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field

BROADCAST = "FF:FF:FF:FF:FF:FF"

# ค่าต้องตรงกับ schemas.AttackType / Severity / Layer
DEAUTH = "Deauth Attack"
EVIL_TWIN = "Evil Twin"
MITM = "MITM"
WPA_CRACK = "WPA Key Cracking"
RECON = "Recon / Probe Flood"
CAPTIVE = "Captive Portal Phishing"
AUTH_DOS = "Auth DoS Attack"
BEACON_FLOOD = "Beacon Flood / AP Anomaly"
CRITICAL, SUSPICIOUS = "Critical", "Suspicious"
L2, L3, DNS = "802.11", "ARP/IP", "DNS"

# kind ของ Event ที่ระบบรู้จัก (sensor ภายนอกอย่าง ESP32 ก็ใช้ชุดเดียวกัน)
KINDS = {"deauth", "beacon", "probe_req", "auth", "eapol", "arp", "dns"}


@dataclass
class Event:
    kind: str
    ts: float
    src: str = ""      # MAC ต้นทาง (arp/dns: dns ใช้ IP ของ resolver)
    dst: str = ""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    rssi: int = 0
    extra: dict = field(default_factory=dict)


@dataclass
class Detection:
    attack_type: str
    severity: str
    layer: str
    src_mac: str
    bssid: str
    ssid: str
    victim_count: int
    channel: int
    rssi: int
    frame_rate: float
    impact: str
    action: str


def norm_mac(m: str) -> str:
    return (m or "").upper()


class Detector:
    cooldown = 30.0

    def __init__(self, cooldown: float | None = None):
        if cooldown is not None:
            self.cooldown = cooldown
        self._last: dict = {}

    def _ready(self, key, ts: float) -> bool:
        """กันแจ้งซ้ำ key เดิมในช่วง cooldown"""
        if ts - self._last.get(key, float("-inf")) < self.cooldown:
            return False
        self._last[key] = ts
        return True

    def feed(self, ev: Event) -> list[Detection]:
        raise NotImplementedError


def _slide(q: deque, ts: float, window: float) -> None:
    while q and ts - q[0][0] > window:
        q.popleft()


def _gc(table: dict, ts: float, window: float, limit: int = 5000) -> None:
    """MAC ปลอมสุ่มจำนวนมากไม่ควรทำให้หน่วยความจำโต"""
    if len(table) <= limit:
        return
    for k in [k for k, q in table.items() if not q or ts - q[-1][0] > window]:
        del table[k]


class DeauthDetector(Detector):
    """1. Deauth/Disassoc flood detector รองรับทั้งการโจมตีแบบ 2-way spoofing, broadcast, และ randomized MAC"""

    def __init__(self, window=5.0, threshold=10, cooldown=None):
        super().__init__(cooldown)
        self.window, self.threshold = window, threshold
        self.win: dict = defaultdict(deque)

    def feed(self, ev):
        if ev.kind != "deauth":
            return []
        src = norm_mac(ev.src)
        bssid = norm_mac(ev.bssid)
        dst = norm_mac(ev.dst)

        # ใช้ target BSSID เป็นหลัก (หากไม่มีให้ใช้ src/dst)
        # เพื่อรวมเฟรม Deauth ทั้ง AP->Client และ Client->AP รวมถึงกรณี Attacker สุ่ม MAC
        target = bssid if (bssid and bssid != BROADCAST) else (src or dst)
        key = target
        if not key:
            return []

        q = self.win[key]
        q.append((ev.ts, dst, ev.rssi, ev.channel, src))
        _slide(q, ev.ts, self.window)
        _gc(self.win, ev.ts, self.window)

        if len(q) < self.threshold or not self._ready(key, ev.ts):
            return []

        victims = {d for _, d, _, _, _ in q if d != BROADCAST}
        bcast = any(d == BROADCAST for _, d, _, _, _ in q)
        primary_src = src or (q[-1][4] if q else "")
        return [Detection(
            DEAUTH, CRITICAL, L2, primary_src, bssid or key, ev.ssid,
            max(len(victims), 1 if bcast else 0), ev.channel, ev.rssi,
            round(len(q) / self.window, 1),
            "Client ถูกตัดการเชื่อมต่อซ้ำ ๆ" + (" (broadcast ทั้ง BSS)" if bcast else ""),
            "ตรวจสอบต้นทาง MAC, เปิดใช้ 802.11w (PMF)")]


class AuthDosDetector(Detector):
    """6. ตรวจจับ Authentication Flood / Auth DoS Attack (mdk3/mdk4/scapy Auth Flood)
    ตรวจจับเมื่อมีการยิงเฟรม 802.11 Authentication Request ถล่ม Access Point (BSSID) ในเวลาสั้น ๆ
    เพื่อทำให้ตาราง Client / Authentication State ของ AP ล้น จน Client อื่นเชื่อมต่อไม่ได้
    """

    def __init__(self, window=5.0, threshold=15, cooldown=None):
        super().__init__(cooldown)
        self.window, self.threshold = window, threshold
        self.win: dict = defaultdict(deque)

    def feed(self, ev):
        if ev.kind != "auth":
            return []
        src = norm_mac(ev.src)
        bssid = norm_mac(ev.bssid)
        dst = norm_mac(ev.dst)

        # เป้าหมายหลักคือ AP ที่ถูกโจมตี (BSSID หรือ Destination ที่ไม่ใช่ Broadcast)
        target = bssid if (bssid and bssid != BROADCAST) else (dst if (dst and dst != BROADCAST) else "")
        if not target:
            return []

        q = self.win[target]
        q.append((ev.ts, src, ev.rssi, ev.channel))
        _slide(q, ev.ts, self.window)
        _gc(self.win, ev.ts, self.window)

        if len(q) < self.threshold or not self._ready(target, ev.ts):
            return []

        sources = {s for _, s, _, _ in q if s and s != BROADCAST}
        rate = round(len(q) / self.window, 1)
        primary_src = src or (q[-1][1] if q else "")
        if len(sources) > 3:
            impact = f"พบการยิง Authentication Flood (Auth DoS) ถล่ม AP ({len(sources)} MAC ปลอมแปลง, {rate} เฟรม/วิ) เสี่ยงทำให้ AP หน่วยความจำเต็ม/ค้าง"
        else:
            impact = f"พบการส่ง Authentication Request ถี่ผิดปกติ ({len(q)} ครั้ง ใน {self.window} วินาที, {rate} เฟรม/วิ) ไปยัง AP"

        return [Detection(
            AUTH_DOS, CRITICAL, L2, primary_src, target, ev.ssid,
            len(sources), ev.channel, ev.rssi, rate,
            impact,
            "เปิดใช้งาน 802.11w (PMF / Management Frame Protection), ตั้งค่า Rate Limiting บน AP, ตรวจหาพิกัดสัญญาณผู้โจมตี")]


class EvilTwinDetector(Detector):
    """2. ตรวจจับ Evil Twin / Rogue AP (ตรงตามฟังก์ชัน Evil Twin ของ airgeddon)
    - ตรวจจับตาม Profile (config.json): BSSID ไม่อยู่ในรายการที่อนุญาต หรือช่องสัญญาณไม่ตรง
    - ตรวจจับแบบ Dynamic อัตโนมัติ: หากพบ BSSID ใหม่ปล่อย SSID ซ้ำกับ AP เดิมที่เคยตรวจพบ
    """

    def __init__(self, profiles: list[dict], cooldown=None):
        super().__init__(cooldown)
        self.profiles = {p["ssid"]: p for p in profiles}
        self.seen_ssids: dict[str, set[str]] = defaultdict(set)
        self.last_deauth: dict[str, float] = {}

    def reload_profiles(self, profiles: list[dict]) -> None:
        """อัปเดตโปรไฟล์เครือข่ายที่อนุญาตแบบเรียลไทม์ (เมื่อผู้ใช้กดระบุ Wi-Fi หอพัก/มหาลัย)"""
        self.profiles = {p["ssid"]: p for p in profiles}

    def feed(self, ev):
        if ev.kind == "deauth":
            bssid = norm_mac(ev.bssid)
            if bssid:
                self.last_deauth[bssid] = ev.ts
            if ev.ssid:
                self.last_deauth[f"ssid_{ev.ssid}"] = ev.ts
            return []
        if ev.kind != "beacon":
            return []
        ssid = (ev.ssid or "").strip()
        if not ssid:
            return []
        bssid = norm_mac(ev.bssid or ev.src)
        if not bssid:
            return []

        # 1. ตรวจสอบตาม Profile ที่กำหนดใน config.json
        prof = self.profiles.get(ssid)
        if prof:
            allowed = {norm_mac(b) for b in prof.get("bssids", [])}
            chans = prof.get("channels", [])
            is_dorm = bool(prof.get("is_dorm_campus", False))

            # เช็คว่ามี Deauth เกิดขึ้นกับ AP ใดๆ ในเครือข่ายนี้หรือไม่
            has_recent_deauth = any(
                ev.ts - self.last_deauth.get(b, float("-inf")) < 60
                for b in (allowed or self.seen_ssids[ssid])
            ) or (ev.ts - self.last_deauth.get(f"ssid_{ssid}", float("-inf")) < 60)

            bad_bssid = bool(allowed) and (bssid not in allowed)
            bad_chan = bool(chans) and ev.channel and (ev.channel not in chans)
            if is_dorm:
                # ในเครือข่ายหอพัก/มหาวิทยาลัย อนุญาตให้กระจายช่องสัญญาณได้ (Multi-AP Roaming)
                bad_chan = False

            if bad_bssid or bad_chan:
                if self._ready(f"{ssid}_{bssid}", ev.ts):
                    why = "BSSID แปลกปลอม ไม่อยู่ใน profile" if bad_bssid else f"อยู่ช่อง {ev.channel} ผิดจาก profile"
                    tag = " (เครือข่ายหอ/มหาลัย)" if is_dorm else ""
                    msg = f"พบ Evil Twin (airgeddon Rogue AP) ใช้ SSID '{ssid}' ({why}){tag}"
                    if has_recent_deauth:
                        msg += " ร่วมกับการยิง Deauth ตัดสัญญาณ AP จริง (airgeddon Attack Pattern)"
                    return [Detection(
                        EVIL_TWIN, CRITICAL, L2, bssid, bssid, ssid, 0, ev.channel, ev.rssi, 0.0,
                        msg,
                        "แจ้งเตือนผู้ใช้ห้ามเชื่อมต่อเด็ดขาด, ตรวจสอบตำแหน่ง AP ปลอม")]
                return []

            if allowed or is_dorm:
                self.seen_ssids[ssid].add(bssid)
                return []

        # 2. ตรวจสอบแบบ Dynamic: หาก SSID เดียวกันถูกปล่อยจาก BSSID ใหม่ที่ไม่เคยพบ
        known = self.seen_ssids[ssid]
        if known and bssid not in known:
            # มี Deauth เกิดขึ้นกับ AP เดิมหรือไม่ (พฤติกรรมเฉพาะของ airgeddon Captive Portal)
            has_recent_deauth = any(
                ev.ts - self.last_deauth.get(old_b, float("-inf")) < 60
                for old_b in known
            ) or (ev.ts - self.last_deauth.get(f"ssid_{ssid}", float("-inf")) < 60)

            if self._ready(f"dyn_{ssid}_{bssid}", ev.ts):
                msg = f"ตรวจพบ AP ที่ 2 ใช้ชื่อ SSID '{ssid}' ซ้ำกับ AP เดิม (BSSID: {bssid})"
                if has_recent_deauth:
                    msg += " ร่วมกับการยิง Deauth ตัดสัญญาณ AP จริง (รูปแบบการโจมตี Evil Twin + Captive Portal ของ airgeddon)"
                else:
                    msg += " (Rogue AP BSSID แปลกปลอม)"
                return [Detection(
                    EVIL_TWIN, CRITICAL, L2, bssid, bssid, ssid, 1, ev.channel, ev.rssi, 0.0,
                    msg,
                    "ตัดการเชื่อมต่อทันที, สแกนหาตำแหน่ง BSSID แปลกปลอม")]
        known.add(bssid)
        return []


class BeaconFloodDetector(Detector):
    """8. ตรวจจับ Beacon Flood Attack และ AP Beacon Anomaly (mdk3/mdk4/ESP8266 Fake AP Spammer)
    - กรณีที่ 1 (Beacon Flood): ตรวจพบ AP/BSSID ปลอมแปลงปริมาณมากผิดปกติถูกประกาศขึ้นมาบนช่องสัญญาณพร้อมๆ กัน
    - กรณีที่ 2 (AP Beacon Anomaly): ตรวจพบ AP ตัวใดตัวหนึ่งส่งเฟรม Beacon ถี่เกินมาตรฐานอย่างรุนแรง แย่งชิง Airtime
    """

    def __init__(self, window=5.0, threshold=25, single_ap_threshold=75, cooldown=None):
        super().__init__(cooldown)
        self.window = window
        self.threshold = threshold                  # จำนวน unique BSSID ใน window (ค่าเริ่มต้น 25)
        self.single_ap_threshold = single_ap_threshold  # จำนวน beacon จาก AP เดียวใน window (ค่าเริ่มต้น 75, ปกติ ~10/s)
        self.ch_win: dict[int, deque] = defaultdict(deque)     # channel -> deque[(ts, bssid, ssid, rssi)]
        self.ap_win: dict[str, deque] = defaultdict(deque)     # bssid -> deque[(ts, channel, rssi)]

    def feed(self, ev: Event) -> list[Detection]:
        if ev.kind != "beacon":
            return []
        bssid = norm_mac(ev.bssid or ev.src)
        if not bssid or bssid == BROADCAST:
            return []
        ch = ev.channel or 0

        # 1. บันทึกและเลื่อนหน้าต่างเวลาสำหรับช่องสัญญาณ (ตรวจจับ Multi-AP Beacon Flood)
        ch_q = self.ch_win[ch]
        ch_q.append((ev.ts, bssid, ev.ssid or "", ev.rssi))
        _slide(ch_q, ev.ts, self.window)
        _gc(self.ch_win, ev.ts, self.window)

        # 2. บันทึกและเลื่อนหน้าต่างเวลาสำหรับ BSSID รายตัว (ตรวจจับ Single AP Beacon Anomaly)
        ap_q = self.ap_win[bssid]
        ap_q.append((ev.ts, ch, ev.rssi))
        _slide(ap_q, ev.ts, self.window)
        _gc(self.ap_win, ev.ts, self.window)

        # ตรวจสอบกรณีที่ 1: Beacon Flood (ตรวจพบ Fake APs / BSSIDs จำนวนมากพร้อมกัน)
        unique_bssids = {b for _, b, _, _ in ch_q}
        if len(unique_bssids) >= self.threshold:
            flood_key = f"bcast_flood_{ch}"
            if self._ready(flood_key, ev.ts):
                unique_ssids = {s for _, _, s, _ in ch_q if s}
                rate = round(len(ch_q) / self.window, 1)
                impact = (f"พบการแพร่กระจายเฟรม Beacon ปลอมจำนวนมาก (Beacon Flood) บนช่อง {ch} "
                          f"({len(unique_bssids)} BSSID / {len(unique_ssids)} SSID, {rate} เฟรม/วิ) "
                          f"เสี่ยงทำให้ตัวสแกน Wi-Fi ของเครื่อง Client ค้าง")
                return [Detection(
                    BEACON_FLOOD, CRITICAL, L2, bssid, bssid, ev.ssid,
                    len(unique_bssids), ch, ev.rssi, rate,
                    impact,
                    "หลีกเลี่ยงการเชื่อมต่อ Wi-Fi แปลกปลอม, ตรวจหาตำแหน่งผู้โจมตี (mdk3/mdk4/ESP8266 Beacon Spammer)")]

        # ตรวจสอบกรณีที่ 2: Single AP Beacon Anomaly (AP ตัวเดียวส่ง Beacon ถี่ผิดปกติอย่างรุนแรง)
        if len(ap_q) >= self.single_ap_threshold:
            ap_key = f"bcast_anomaly_{bssid}"
            if self._ready(ap_key, ev.ts):
                rate = round(len(ap_q) / self.window, 1)
                impact = (f"พบ AP ({bssid}) ส่งเฟรม Beacon ถี่ผิดปกติอย่างรุนแรง ({len(ap_q)} ครั้ง ใน {self.window} วิ, "
                          f"{rate} เฟรม/วิ) ก่อให้เกิดความผิดปกติของช่องสัญญาณ (AP Beacon Anomaly / Airtime Hogging)")
                return [Detection(
                    BEACON_FLOOD, SUSPICIOUS, L2, bssid, bssid, ev.ssid,
                    1, ch, ev.rssi, rate,
                    impact,
                    "ตรวจสอบการตั้งค่า Beacon Interval ของ AP (มาตรฐาน 100ms) หรือตรวจสอบว่ามีมัลแวร์/อุปกรณ์ผิดปกติ")]

        return []


class ReconDetector(Detector):
    """5. ตรวจจับ Probe Request Flood / Reconnaissance ใน airgeddon"""

    def __init__(self, window=10.0, threshold=25, cooldown=None):
        super().__init__(cooldown)
        self.window, self.threshold = window, threshold
        self.win: dict = defaultdict(deque)

    def feed(self, ev):
        if ev.kind != "probe_req":
            return []
        key = norm_mac(ev.src)
        q = self.win[key]
        q.append((ev.ts, ev.ssid, ev.rssi, ev.channel))
        _slide(q, ev.ts, self.window)
        _gc(self.win, ev.ts, self.window)
        if len(q) < self.threshold or not self._ready(key, ev.ts):
            return []
        ssids = {s for _, s, _, _ in q if s}
        return [Detection(
            RECON, SUSPICIOUS, L2, key, "", "", 0, ev.channel, ev.rssi,
            round(len(q) / self.window, 1),
            f"สแกนหา AP/Client ถี่ผิดปกติ ({len(ssids)} SSID ที่ต่างกัน)",
            "เฝ้าระวัง, บันทึก MAC ต้นทาง")]


class WpaCrackDetector(Detector):
    """4. ตรวจจับการดักจับ Handshake (WPA Handshake Capture ใน airgeddon):
    เมื่อ airgeddon ยิง Deauth เพื่อบังคับให้ Client ส่ง EAPOL 4-Way Handshake
    """

    def __init__(self, window=30.0, threshold=2, threshold_no_deauth=12, cooldown=None):
        super().__init__(cooldown)
        self.window = window
        self.threshold = threshold  # 2 เฟรมหลัง Deauth ชี้ชัดว่ามีการจับ Handshake
        self.threshold_no_deauth = threshold_no_deauth
        self.eapol: dict = defaultdict(deque)
        self.last_deauth: dict = {}

    def feed(self, ev):
        bssid = norm_mac(ev.bssid)
        if ev.kind == "deauth":
            if bssid:
                self.last_deauth[bssid] = ev.ts
            return []
        if ev.kind != "eapol":
            return []
        q = self.eapol[bssid]
        q.append((ev.ts, norm_mac(ev.src)))
        _slide(q, ev.ts, self.window)
        _gc(self.eapol, ev.ts, self.window)
        correlated = ev.ts - self.last_deauth.get(bssid, float("-inf")) <= self.window
        need = self.threshold if correlated else self.threshold_no_deauth
        if len(q) < need or not self._ready(bssid, ev.ts):
            return []
        clients = {m for _, m in q}
        return [Detection(
            WPA_CRACK, CRITICAL if correlated else SUSPICIOUS, L2, bssid, bssid, ev.ssid, len(clients), ev.channel,
            ev.rssi, round(len(q) / self.window, 1),
            "ตรวจพบการดักจับ EAPOL 4-Way Handshake" + (" ทันทีหลังถูกยิง Deauth (การโจมตี Handshake Capture ของ airgeddon)" if correlated else " ผิดปกติ"),
            "ระวังการนำ Handshake ไปถอดรหัส WPA, แนะนำเปิดใช้ WPA3 หรือตั้งรหัสผ่านยาวเกิน 16 ตัวอักษร")]


class ArpDetector(Detector):
    """3. MITM (ARP poisoning): IP เดียวกันแต่ MAC เปลี่ยน / gateway MAC ไม่ตรง config
    ต้องการ Event 'arp' จาก sensor ที่เชื่อมต่อเครือข่ายจริง (card ตัวที่ 2 หรือ ESP32)
    extra: {"ip": "192.168.1.1", "op": 1|2}
    """

    def __init__(self, gateway_ip="", gateway_mac="", cooldown=None):
        super().__init__(cooldown)
        self.gateway_ip = gateway_ip
        self.gateway_mac = norm_mac(gateway_mac)
        self.table: dict[str, str] = {}

    def feed(self, ev):
        if ev.kind != "arp":
            return []
        ip, mac = ev.extra.get("ip", ""), norm_mac(ev.src)
        if not ip or ip == "0.0.0.0" or not mac:
            return []
        is_gw = bool(self.gateway_ip) and ip == self.gateway_ip
        pinned_bad = is_gw and bool(self.gateway_mac) and mac != self.gateway_mac
        previous = self.table.get(ip)
        self.table[ip] = mac
        conflict = previous is not None and previous != mac
        if not (conflict or pinned_bad) or not self._ready((ip, mac), ev.ts):
            return []
        sev = CRITICAL if is_gw else SUSPICIOUS
        return [Detection(
            MITM, sev, L3, mac, ev.bssid, ev.ssid, 1, ev.channel, ev.rssi, 0.0,
            f"IP {ip} ถูกอ้างโดย MAC ใหม่ (เดิม {previous or self.gateway_mac})"
            + (" — เป็น gateway: traffic อาจถูกดักผ่านเครื่องผู้โจมตี" if is_gw else " (heuristic: อาจเป็น DHCP ออก IP ซ้ำ)"),
            "ตรวจ ARP table ของ gateway, ใช้ static ARP / Dynamic ARP Inspection")]


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class DnsDetector(Detector):
    """6. DNS ปลอม / Captive Portal Phishing
    extra: {"qname": "example.com", "answers": ["1.2.3.4"]}, src = IP ของ resolver ที่ตอบ
    กฎ: (ก) คำตอบไม่อยู่ใน dns_expected → Critical  (ข) resolver ไม่อยู่ใน trusted_resolvers → Critical
        (ค) โดเมนสาธารณะตอบเป็น IP private → Suspicious (heuristic)
    """

    def __init__(self, expected: dict | None = None, trusted_resolvers: list | None = None,
                 private_ok_suffixes=(".local", ".lan", ".home.arpa", ".internal"), cooldown=60.0):
        super().__init__(cooldown)
        self.expected = {k.lower(): set(v) for k, v in (expected or {}).items()}
        self.trusted = set(trusted_resolvers or [])
        self.private_ok = tuple(private_ok_suffixes)

    def feed(self, ev):
        if ev.kind != "dns":
            return []
        q = ev.extra.get("qname", "").rstrip(".").lower()
        answers = ev.extra.get("answers", [])
        if not q or not answers:
            return []
        reason, sev = None, SUSPICIOUS
        if q in self.expected and any(a not in self.expected[q] for a in answers):
            reason, sev = f"{q} ตอบ {answers} ไม่ตรงค่าที่คาดไว้", CRITICAL
        elif self.trusted and ev.src not in self.trusted:
            reason, sev = f"คำตอบ DNS มาจาก resolver ที่ไม่รู้จัก ({ev.src})", CRITICAL
        elif q not in self.expected and not q.endswith(self.private_ok) and any(_is_private(a) for a in answers):
            reason = f"โดเมนสาธารณะ {q} ถูกตอบเป็น IP ภายใน {answers} (อาจเป็น Captive Portal ปลอม)"
        if not reason or not self._ready((q, ev.src), ev.ts):
            return []
        mac = norm_mac(ev.extra.get("mac", "")) or ev.src
        return [Detection(
            CAPTIVE, sev, DNS, mac, ev.bssid, ev.ssid, 1, ev.channel, ev.rssi, 0.0,
            reason + " (heuristic)",
            "ตรวจ DNS/DHCP ของเครือข่าย, ปิด AP/Resolver ปลอม, แจ้งผู้ใช้อย่ากรอกรหัสผ่าน")]
