"""ตัวจำลองเหตุการณ์ (Phase 1) - โครงสร้างผลลัพธ์ตรงกับที่ detection engine จริงจะส่ง"""
import random
import time
from typing import Optional

from schemas import AttackType, Incident, Layer, Severity

SSIDS = [("CampusWiFi", "AA:BB:CC:11:22:33", 6), ("Lab-Net", "AA:BB:CC:44:55:66", 11)]

# attack -> (severity, layer, impact, action, frame_rate range, victims range)
PROFILES = {
    AttackType.DEAUTH: (Severity.CRITICAL, Layer.L2,
                        "Client ถูกตัดการเชื่อมต่อซ้ำ ๆ",
                        "ตรวจสอบต้นทาง MAC, เปิดใช้ 802.11w (PMF)", (80, 400), (1, 12)),
    AttackType.EVIL_TWIN: (Severity.CRITICAL, Layer.L2,
                           "Client อาจเชื่อมต่อ AP ปลอมและถูกดักข้อมูล",
                           "แจ้งผู้ใช้ไม่ให้เชื่อมต่อ, ระบุตำแหน่ง AP ปลอม", (5, 30), (1, 8)),
    AttackType.MITM: (Severity.SUSPICIOUS, Layer.L3,
                      "พบ ARP reply ผิดปกติ (heuristic)",
                      "ตรวจ ARP table ของ gateway", (10, 60), (1, 6)),
    AttackType.WPA_CRACK: (Severity.SUSPICIOUS, Layer.L2,
                           "พบ EAPOL handshake ซ้ำในเวลาสั้น (สัมพันธ์กับ Deauth)",
                           "เปลี่ยนรหัสผ่าน Wi-Fi ให้ซับซ้อน", (3, 20), (1, 4)),
    AttackType.RECON: (Severity.SUSPICIOUS, Layer.L2,
                       "มีการสแกนหา AP/Client จำนวนมาก",
                       "เฝ้าระวัง, บันทึก MAC ต้นทาง", (30, 150), (0, 3)),
    AttackType.CAPTIVE_PHISH: (Severity.CRITICAL, Layer.DNS,
                               "DNS ถูกเปลี่ยนเส้นทางไปหน้าล็อกอินปลอม (heuristic)",
                               "ปิด AP ปลอม, แจ้งผู้ใช้เปลี่ยนรหัสผ่าน", (2, 15), (1, 10)),
}


def _mac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def make_incident(attack: Optional[AttackType] = None) -> Incident:
    attack = attack or random.choice(list(AttackType))
    sev, layer, impact, action, (fr_lo, fr_hi), (v_lo, v_hi) = PROFILES[attack]
    ssid, bssid, channel = random.choice(SSIDS)
    if attack is AttackType.EVIL_TWIN:  # AP ปลอม: SSID เดิม BSSID/ช่องต่างกัน
        bssid, channel = _mac(), random.choice([1, 3, 9, 13])
    return Incident(
        timestamp=time.time(), attack_type=attack, severity=sev, layer=layer,
        src_mac=_mac(), bssid=bssid, ssid=ssid,
        victim_count=random.randint(v_lo, v_hi), channel=channel,
        rssi=random.randint(-85, -35), frame_rate=round(random.uniform(fr_lo, fr_hi), 1),
        impact=impact, action=action, source="mock",
    )


def make_frame_counts() -> dict:
    """จำนวนเฟรมต่อวินาที (จำลอง) แยกตามประเภท"""
    return {
        "Beacon": random.randint(8, 14),
        "Probe": random.randint(2, 15),
        "Auth": random.randint(0, 4),
        "Deauth": random.choice([0, 0, 0, 1, 2, 30]),
    }
