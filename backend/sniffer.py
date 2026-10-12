"""Scapy capture -> Event  (ต้องรันบน Linux ด้วยสิทธิ์ root)

- MonitorSniffer: card ใน Monitor Mode  -> deauth/beacon/probe_req/auth/eapol
- NetSniffer:     interface ที่เชื่อมต่อเครือข่าย -> arp/dns  (card ตัวที่ 2 หรือเครื่องในวงเดียวกัน)
- replay_pcap:    อ่านไฟล์ .pcap เข้า engine (ใช้ทดสอบ/วัด Detection Rate โดยไม่ต้องมี card)
scapy ถูก import ตอนใช้งานเท่านั้น เพื่อให้โมดูลอื่นไม่พังถ้ายังไม่ได้ติดตั้ง
"""
import logging
import subprocess
import threading
from typing import Optional

from detectors import Event

log = logging.getLogger("sniffer")


def dot11_to_event(pkt) -> Optional[Event]:
    from scapy.all import (EAPOL, Dot11, Dot11Auth, Dot11Beacon, Dot11Deauth,
                           Dot11Disas, Dot11ProbeReq)
    if not pkt.haslayer(Dot11):
        return None
    d = pkt[Dot11]
    ts = float(pkt.time)
    rssi = int(getattr(pkt, "dBm_AntSignal", 0) or 0)
    src, dst, bssid = d.addr2 or "", d.addr1 or "", d.addr3 or ""
    if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
        return Event("deauth", ts, src, dst, bssid, rssi=rssi)
    if pkt.haslayer(Dot11Beacon):
        try:
            st = pkt[Dot11Beacon].network_stats()
            return Event("beacon", ts, src, dst, bssid, st.get("ssid", ""),
                         int(st.get("channel") or 0), rssi)
        except Exception:
            return None
    if pkt.haslayer(Dot11ProbeReq):
        try:
            ssid = pkt.info.decode(errors="ignore")
        except Exception:
            ssid = ""
        return Event("probe_req", ts, src, dst, bssid, ssid, rssi=rssi)
    if pkt.haslayer(Dot11Auth):
        return Event("auth", ts, src, dst, bssid, rssi=rssi)
    if pkt.haslayer(EAPOL):
        return Event("eapol", ts, src, dst, bssid, rssi=rssi)
    return None


def net_to_event(pkt) -> Optional[Event]:
    from scapy.all import ARP, DNS, DNSQR, IP, Ether
    ts = float(pkt.time)
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return Event("arp", ts, src=a.hwsrc, dst=a.hwdst, extra={"ip": a.psrc, "op": int(a.op)})
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt.haslayer(DNSQR):
        dns = pkt[DNS]
        answers = []
        try:
            for i in range(dns.ancount):
                rr = dns.an[i]
                if rr.type == 1:  # A record
                    answers.append(str(rr.rdata))
        except Exception:
            pass
        qname = pkt[DNSQR].qname.decode(errors="ignore")
        mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        resolver = pkt[IP].src if pkt.haslayer(IP) else ""
        return Event("dns", ts, src=resolver, extra={"qname": qname, "answers": answers, "mac": mac})
    return None


class _Capture(threading.Thread):
    daemon = True

    def __init__(self, iface, engine, converter, bpf=None, source="live"):
        super().__init__(name=f"capture-{iface}")
        self.iface, self.engine, self.convert, self.bpf, self.source = iface, engine, converter, bpf, source
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def _handle_packet(self, pkt):
        try:
            ev = self.convert(pkt)
            if ev:
                self.engine.feed(ev, self.source)
        except Exception:
            log.exception("packet handling failed")

    def run(self):
        from scapy.all import sniff
        try:
            sniff(iface=self.iface, prn=self._handle_packet, store=False, filter=self.bpf,
                  stop_filter=lambda _p: self._stop_evt.is_set())
        except Exception:
            log.exception("capture on %s failed (ต้องใช้ root / interface ถูกต้อง?)", self.iface)


class MonitorSniffer(_Capture):
    def __init__(self, iface, engine, channels=(1, 6, 11), hop_interval=0.4):
        super().__init__(iface, engine, dot11_to_event)
        self.channels, self.hop_interval = list(channels), hop_interval

    def _hop(self):
        i = 0
        while not self._stop_evt.wait(self.hop_interval):
            ch = self.channels[i % len(self.channels)]
            i += 1
            subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run(self):
        if len(self.channels) > 1:
            threading.Thread(target=self._hop, daemon=True).start()
        super().run()


class NetSniffer(_Capture):
    def __init__(self, iface, engine):
        super().__init__(iface, engine, net_to_event, bpf="arp or udp port 53")


def start_all(engine, cfg: dict) -> list:
    """เริ่ม sniffer ตาม config; คืน list ของ thread เพื่อสั่ง stop ตอนปิดระบบ"""
    threads = []
    if cfg.get("interface"):
        threads.append(MonitorSniffer(cfg["interface"], engine, cfg.get("channels", [1, 6, 11]),
                                      cfg.get("hop_interval_sec", 0.4)))
    else:
        log.warning("ไม่ได้ตั้ง 'interface' ใน config.json -> ไม่ดักจับ 802.11")
    if cfg.get("net_interface"):
        threads.append(NetSniffer(cfg["net_interface"], engine))
    for t in threads:
        t.start()
    return threads


def replay_pcap(path: str, engine, net: bool = False) -> int:
    """อ่าน pcap เข้า engine; คืนจำนวน event ที่ส่ง"""
    from scapy.all import PcapReader
    conv = net_to_event if net else dot11_to_event
    n = 0
    with PcapReader(path) as r:
        for pkt in r:
            ev = conv(pkt)
            if ev:
                engine.feed(ev, "pcap")
                n += 1
    return n
