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
            try:
                subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                break

    def run(self):
        if len(self.channels) > 1:
            threading.Thread(target=self._hop, daemon=True).start()
        super().run()


class NetSniffer(_Capture):
    def __init__(self, iface, engine):
        super().__init__(iface, engine, net_to_event, bpf="arp or udp port 53")


class SerialSniffer(threading.Thread):
    """อ่านข้อมูลจาก ESP32 Sniffer ผ่านสาย USB Serial โดยตรง (ทั้ง Windows COMx และ Linux ttyUSBx/ttyACMx)"""
    daemon = True

    def __init__(self, port_cfg: str, baud: int, engine, on_sensor=None):
        super().__init__(name="serial-sniffer")
        self.port_cfg = (port_cfg or "auto").strip()
        self.baud = int(baud or 115200)
        self.engine = engine
        self.on_sensor = on_sensor
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def _find_port(self) -> Optional[str]:
        import serial.tools.list_ports
        if self.port_cfg and self.port_cfg.lower() != "auto":
            return self.port_cfg
        for p in serial.tools.list_ports.comports():
            dev = p.device or ""
            desc = (p.description or "").lower()
            if (p.vid is not None or "usb" in dev.lower() or "acm" in dev.lower()
                    or any(k in desc for k in ("cp210", "ch340", "ch910", "uart", "jtag", "esp", "serial"))):
                if dev.startswith("/dev/ttyS"):
                    continue
                return dev
        return None

    def _process_line(self, line: str, port: str) -> None:
        import json
        import time
        from detectors import KINDS
        if "WIDS_JSON:" in line:
            raw = line.split("WIDS_JSON:", 1)[1].strip()
        elif line.startswith("{") and '"events"' in line:
            raw = line
        else:
            return
        data = json.loads(raw)
        sensor = data.get("sensor", "esp32-usb")
        events = data.get("events", [])
        now = time.time()
        accepted = 0
        for e in events:
            kind = e.get("kind", "")
            if kind not in KINDS:
                continue
            self.engine.feed(
                Event(kind, e.get("ts") or now, e.get("src", ""), e.get("dst", ""),
                      e.get("bssid", ""), e.get("ssid", ""), int(e.get("channel") or 0),
                      int(e.get("rssi") or 0), e.get("extra") or {}),
                source=f"sensor:{sensor}",
            )
            accepted += 1
        if accepted and self.on_sensor:
            self.on_sensor(f"{sensor} ({port})", accepted)

    def run(self):
        try:
            import serial
        except ImportError:
            log.warning("ไม่ได้ติดตั้ง pyserial -> ข้ามการอ่าน ESP32 ผ่านสาย USB")
            return

        while not self._stop_evt.is_set():
            port = self._find_port()
            if not port:
                self._stop_evt.wait(2.0)
                continue
            try:
                with serial.Serial(port, self.baud, timeout=1.0) as ser:
                    print(f"🔌 [USB-SERIAL] เชื่อมต่อ ESP32 ผ่านสายที่พอร์ต {port} ({self.baud} baud) สำเร็จ!")
                    while not self._stop_evt.is_set():
                        raw_bytes = ser.readline()
                        if not raw_bytes:
                            continue
                        line = raw_bytes.decode("utf-8", errors="ignore").strip()
                        if line:
                            try:
                                self._process_line(line, port)
                            except Exception:
                                pass
            except Exception:
                self._stop_evt.wait(2.0)


def start_all(engine, cfg: dict, on_sensor=None) -> list:
    """เริ่ม sniffer ตาม config; รองรับทั้งสาย USB Serial (ESP32) และ Monitor Mode (Linux)"""
    import os
    from pathlib import Path
    threads = []

    # 1. เริ่มตัวรับข้อมูลผ่านสาย USB Serial จาก ESP32 (ทั้งบน Windows และ Linux)
    serial_port = cfg.get("serial_port", "auto")
    if serial_port and str(serial_port).lower() != "none":
        threads.append(SerialSniffer(str(serial_port), int(cfg.get("serial_baud", 115200)), engine, on_sensor))

    # 2. เริ่ม Monitor Mode ในเครื่อง (เฉพาะกรณีตั้งค่า interface บน Linux)
    iface = cfg.get("interface", "").strip()
    if os.name == "nt":
        log.info("โหมด Windows: รับข้อมูลจาก ESP32 (สาย USB Serial / Wi-Fi /api/ingest)")
    elif iface:
        if Path(f"/sys/class/net/{iface}").exists():
            threads.append(MonitorSniffer(iface, engine, cfg.get("channels", [1, 6, 11]),
                                          cfg.get("hop_interval_sec", 0.4)))
        else:
            log.info("ไม่พบ interface '%s' -> รับข้อมูลจาก ESP32 (สาย USB / Wi-Fi)", iface)
    if cfg.get("net_interface") and os.name != "nt":
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
