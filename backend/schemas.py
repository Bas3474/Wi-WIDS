from enum import Enum
from typing import Optional

from pydantic import BaseModel


class AttackType(str, Enum):
    DEAUTH = "Deauth Attack"
    EVIL_TWIN = "Evil Twin"
    MITM = "MITM"
    WPA_CRACK = "WPA Key Cracking"
    RECON = "Recon / Probe Flood"
    CAPTIVE_PHISH = "Captive Portal Phishing"
    AUTH_DOS = "Auth DoS Attack"
    BEACON_FLOOD = "Beacon Flood / AP Anomaly"


class Severity(str, Enum):
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    CRITICAL = "Critical"


class Layer(str, Enum):
    L2 = "802.11"   # ตรวจได้จาก monitor mode โดยตรง
    L3 = "ARP/IP"   # ต้องเชื่อมต่อเครือข่าย (heuristic)
    DNS = "DNS"     # ต้องเชื่อมต่อเครือข่าย (heuristic)


class Incident(BaseModel):
    id: Optional[int] = None
    timestamp: float
    attack_type: AttackType
    severity: Severity
    layer: Layer
    src_mac: str
    bssid: str
    ssid: str
    victim_count: int
    channel: int
    rssi: int
    frame_rate: float
    impact: str
    action: str
    source: str = "mock"  # mock | live
