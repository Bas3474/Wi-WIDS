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


def same_oui(m1: str, m2: str) -> bool:
    """ตรวจสอบว่า MAC ทั้งสองมาจากผู้ผลิต (Vendor OUI) เดียวกันหรือไม่ (3 คู่แรก เช่น BE:27:7A)"""
    p1 = norm_mac(m1).split(":")
    p2 = norm_mac(m2).split(":")
    return len(p1) >= 3 and len(p2) >= 3 and p1[:3] == p2[:3]


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


class EvilTwinDetector(Detector):
    """2. ตรวจจับ Evil Twin / Rogue AP (ตรงตามฟังก์ชัน Evil Twin ของ airgeddon)
    รองรับทั้ง:
      - หอพัก / มหาวิทยาลัย (Multi-AP / Enterprise Mesh Roaming):
        Router หลายตัวยี่ห้อเดียวกัน (Same OUI) กระจายหลายช่องสัญญาณ ทำงานร่วมกันอย่างสงบ
      - ตรวจจับตาม Profile (config.json) พร้อมตัวเลือก multi_ap
      - ตรวจจับแบบ Dynamic อัตโนมัติ (ตรวจจับ Deauth correlation ของ airgeddon และ Vendor OUI mismatch)
    """

    def __init__(self, profiles: list[dict], cooldown=None):
        super().__init__(cooldown)
        self.profiles = {p["ssid"]: p for p in profiles}
        self.seen_ssids: dict[str, set[str]] = defaultdict(set)
        self.last_deauth: dict[str, float] = {}

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
            is_multi_ap = bool(prof.get("multi_ap", False))

            # เช็คว่ามี Deauth เกิดขึ้นกับ AP ใดๆ ในเครือข่ายนี้หรือไม่
            has_recent_deauth = any(
                ev.ts - self.last_deauth.get(b, float("-inf")) < 60
                for b in (allowed or self.seen_ssids[ssid])
            ) or (ev.ts - self.last_deauth.get(f"ssid_{ssid}", float("-inf")) < 60)

            same_vendor = any(same_oui(a, bssid) for a in allowed)

            bad_bssid = False
            if allowed:
                if bssid in allowed:
                    bad_bssid = False
                elif is_multi_ap and same_vendor and not has_recent_deauth:
                    # โหมดเน็ตหอพัก/มหาลัย: ยี่ห้อเดียวกัน (OUI ตรงกัน) และไม่มีการยิง Deauth -> เป็น Router จุดอื่นที่ปลอดภัย
                    bad_bssid = False
                elif is_multi_ap and not has_recent_deauth:
                    # โหมดเน็ตหอพัก/มหาลัย: มีหลาย Router ทำงานร่วมกันอย่างสงบ ไม่มีการยิง Deauth
                    bad_bssid = False
                else:
                    # นอก Whitelist และไม่ใช่ multi_ap หรือมีการยิง Deauth ตัดสัญญาณ -> ตรวจพบ Evil Twin!
                    bad_bssid = True

            bad_chan = bool(chans) and ev.channel and ev.channel not in chans
            if is_multi_ap:
                # ในโหมด multi_ap อนุญาตให้กระจายช่องสัญญาณได้ (เช่น 1, 6, 11) ไม่มองว่าผิดช่อง
                bad_chan = False

            if (bad_bssid or bad_chan) and self._ready(f"{ssid}_{bssid}", ev.ts):
                why = "BSSID ไม่อยู่ใน profile" if bad_bssid else f"อยู่ช่อง {ev.channel} ผิดจาก profile"
                msg = f"พบ Evil Twin (airgeddon Rogue AP) ใช้ SSID '{ssid}' ({why})"
                if has_recent_deauth:
                    msg += " ร่วมกับการยิง Deauth ตัดสัญญาณ AP จริง (airgeddon Attack Pattern)"
                return [Detection(
                    EVIL_TWIN, CRITICAL, L2, bssid, bssid, ssid, 0, ev.channel, ev.rssi, 0.0,
                    msg,
                    "แจ้งเตือนผู้ใช้ห้ามเชื่อมต่อเด็ดขาด, ตรวจสอบตำแหน่ง AP ปลอม")]

        # 2. ตรวจสอบแบบ Dynamic: หาก SSID เดียวกันถูกปล่อยจาก BSSID ใหม่ที่ไม่เคยพบ
        known = self.seen_ssids[ssid]
        if known and bssid not in known:
            # มี Deauth เกิดขึ้นกับ AP เดิมหรือไม่ (พฤติกรรมเฉพาะของ airgeddon Captive Portal)
            has_recent_deauth = any(
                ev.ts - self.last_deauth.get(old_b, float("-inf")) < 60
                for old_b in known
            ) or (ev.ts - self.last_deauth.get(f"ssid_{ssid}", float("-inf")) < 60)

            same_vendor = any(same_oui(old_b, bssid) for old_b in known)

            # เน็ตหอพัก/มหาลัย: ถ้าเป็น Router ยี่ห้อเดียวกัน (Same OUI) และไม่มีการยิง Deauth -> ถือเป็น Multi-AP Roaming ที่ปลอดภัย
            is_benign_multi_ap = same_vendor and not has_recent_deauth

            if not is_benign_multi_ap:
                if self._ready(f"dyn_{ssid}_{bssid}", ev.ts):
                    msg = f"ตรวจพบ AP ที่ 2 ใช้ชื่อ SSID '{ssid}' ซ้ำกับ AP เดิม (BSSID: {bssid})"
                    if has_recent_deauth:
                        msg += " ร่วมกับการยิง Deauth ตัดสัญญาณ AP จริง (รูปแบบการโจมตี Evil Twin + Captive Portal ของ airgeddon)"
                        return [Detection(
                            EVIL_TWIN, CRITICAL, L2, bssid, bssid, ssid, 1, ev.channel, ev.rssi, 0.0,
                            msg,
                            "ตัดการเชื่อมต่อทันที, สแกนหาตำแหน่ง BSSID แปลกปลอม")]
                    elif not same_vendor:
                        msg += " และตรวจพบว่าเป็นคนละยี่ห้อ (Vendor OUI Mismatch) — ยังไม่พบการตัดสัญญาณ"
                        return [Detection(
                            EVIL_TWIN, SUSPICIOUS, L2, bssid, bssid, ssid, 1, ev.channel, ev.rssi, 0.0,
                            msg,
                            "เฝ้าระวัง หากพบการตัดสัญญาณหรือหลุดบ่อยครั้งให้ตรวจสอบ")]
        known.add(bssid)
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
