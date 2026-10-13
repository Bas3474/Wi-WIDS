"""รวม detector ทั้งหมด รับ Event จากหลายแหล่ง (sniffer/net monitor/remote sensor) แล้วส่ง Incident ออก"""
import threading
import time
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
        self.start_time = time.time()
        self.startup_grace_sec = float(cfg.get("startup_grace_sec", 15.0))
        self.bssid_to_ssid: dict[str, str] = {}
        for p in cfg.get("profiles", []):
            s = p.get("ssid", "")
            for b in p.get("bssids", []):
                self.bssid_to_ssid[D.norm_mac(b)] = s
        self.detectors = [
            D.DeauthDetector(**th.get("deauth", {})),
            D.AuthDosDetector(**th.get("auth_dos", {})),
            D.BeaconFloodDetector(**th.get("beacon_flood", {})),
            D.EvilTwinDetector(cfg.get("profiles", [])),
            D.ReconDetector(**th.get("recon", {})),
            D.WpaCrackDetector(**th.get("wpa", {})),
        ]

    def grace_remaining(self) -> int:
        return max(0, int(self.startup_grace_sec - (time.time() - self.start_time)))

    def is_in_grace_period(self) -> bool:
        return (time.time() - self.start_time) < self.startup_grace_sec

    def feed(self, ev: D.Event, source: str = "live") -> None:
        self.feed_batch([ev], source=source)

    def feed_batch(self, events: list[D.Event], source: str = "live") -> None:
        """ประมวลผล event เป็นชุด ลด Overhead จากการ Acquire/Release Lock ทีละตัว"""
        valid_events = [e for e in events if e.kind in D.KINDS]
        if not valid_events:
            return

        all_found = []
        with self.lock:
            for ev in valid_events:
                if ev.kind in FRAME_LABEL:
                    self.frames[FRAME_LABEL[ev.kind]] += 1
                if ev.bssid and ev.ssid:
                    self.bssid_to_ssid[D.norm_mac(ev.bssid)] = ev.ssid
                if not ev.ssid and ev.bssid:
                    ev.ssid = self.bssid_to_ssid.get(D.norm_mac(ev.bssid), "")
                for det in self.detectors:
                    dets = det.feed(ev)
                    if dets:
                        all_found.extend(dets)

        if self.is_in_grace_period() and "simulator" not in source:
            return

        for d in all_found:
            if not d.ssid and d.bssid:
                d.ssid = self.bssid_to_ssid.get(D.norm_mac(d.bssid), "")
            self.emit(Incident(timestamp=valid_events[-1].ts, source=source, **d.__dict__))

    def pop_frame_counts(self) -> dict:
        with self.lock:
            out = {k: self.frames.get(k, 0) for k in ("Beacon", "Probe", "Auth", "Deauth")}
            self.frames.clear()
        return out

    def reload_profiles(self, profiles: list[dict]) -> None:
        """อัปเดตโปรไฟล์เครือข่ายที่อนุญาตแบบเรียลไทม์ (เมื่อผู้ใช้กดระบุ Wi-Fi หอพัก/มหาลัย)"""
        with self.lock:
            self.bssid_to_ssid.clear()
            for p in profiles:
                s = p.get("ssid", "")
                for b in p.get("bssids", []):
                    self.bssid_to_ssid[D.norm_mac(b)] = s
            for det in self.detectors:
                if hasattr(det, "reload_profiles"):
                    det.reload_profiles(profiles)

