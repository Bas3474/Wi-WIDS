"""รวม detector ทั้งหมด รับ Event จากหลายแหล่ง (sniffer/net monitor/remote sensor) แล้วส่ง Incident ออก"""
import threading
from collections import Counter
from typing import Callable

import detectors as D
from schemas import Incident

FRAME_LABEL = {"beacon": "Beacon", "probe_req": "Probe", "auth": "Auth", "deauth": "Deauth"}


class Engine:
    def __init__(self, cfg: dict, emit: Callable[[Incident], None]):
        th = cfg.get("thresholds", {})
        net = cfg.get("network", {})
        self.emit = emit
        self.lock = threading.Lock()
        self.frames: Counter = Counter()
        self.detectors = [
            D.DeauthDetector(**th.get("deauth", {})),
            D.EvilTwinDetector(cfg.get("profiles", [])),
            D.ReconDetector(**th.get("recon", {})),
            D.WpaCrackDetector(**th.get("wpa", {})),
            D.ArpDetector(net.get("gateway_ip", ""), net.get("gateway_mac", "")),
            D.DnsDetector(net.get("dns_expected"), net.get("trusted_resolvers")),
        ]

    def feed(self, ev: D.Event, source: str = "live") -> None:
        if ev.kind not in D.KINDS:
            return
        with self.lock:
            if ev.kind in FRAME_LABEL:
                self.frames[FRAME_LABEL[ev.kind]] += 1
            found = [d for det in self.detectors for d in det.feed(ev)]
        for d in found:  # emit นอก lock เพื่อไม่ให้ callback ค้าง engine
            self.emit(Incident(timestamp=ev.ts, source=source, **d.__dict__))

    def pop_frame_counts(self) -> dict:
        with self.lock:
            out = {k: self.frames.get(k, 0) for k in ("Beacon", "Probe", "Auth", "Deauth")}
            self.frames.clear()
        return out
