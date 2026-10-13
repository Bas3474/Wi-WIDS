#!/usr/bin/env python3
"""จำลองการโจมตีทั้ง 6 แบบส่งเข้า /api/ingest เพื่อทดสอบ detector -> DB -> Dashboard -> LINE
ไม่ต้องมี Wi-Fi card/ESP32 ใช้เฉพาะ stdlib

  python3 scripts/simulate_attacks.py all
  python3 scripts/simulate_attacks.py deauth --url http://localhost:8000 --token SECRET

MAC/โดเมนสุ่มทุกครั้ง จึงรันซ้ำได้โดยไม่ติด cooldown ของ detector
Evil Twin / ARP gateway ใช้ค่าจาก configs/config.json (CampusWiFi AA:BB:CC:11:22:33 ช่อง 6, gateway 192.168.1.1)
"""
import argparse
import json
import random
import urllib.request

from pathlib import Path

CFG_PATH = Path(__file__).resolve().parent.parent / "configs" / "config.json"
SSID = "CampusWiFi"
AP = "AA:BB:CC:11:22:33"
GW_IP = "192.168.1.1"

if CFG_PATH.exists():
    try:
        cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        profiles = cfg.get("profiles", [])
        if profiles:
            p = profiles[0]
            SSID = p.get("ssid", SSID)
            bssids = p.get("bssids", [])
            if bssids:
                AP = bssids[0]
        net = cfg.get("network", {})
        if net.get("gateway_ip"):
            GW_IP = net["gateway_ip"]
    except Exception:
        pass


def rmac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def deauth():
    atk = rmac()
    return [dict(kind="deauth", src=atk, dst="FF:FF:FF:FF:FF:FF", bssid=AP, ssid=SSID, channel=6, rssi=-45)
            for _ in range(60)]


def evil_twin():
    fake = rmac()
    atk = rmac()
    # ส่ง 3 เฟรมจำลอง Evil Twin / airgeddon pattern:
    # 1. Legit AP beacon (ให้ dynamic baseline รู้จักหากไม่มีใน profile)
    # 2. Deauth frame ตัดสัญญาณจาก AP จริง (พฤติกรรมเฉพาะของ airgeddon)
    # 3. Rogue AP beacon สวมรอย SSID เดียวกันจาก BSSID แปลกปลอม
    return [
        dict(kind="beacon", src=AP, bssid=AP, ssid=SSID, channel=6, rssi=-40),
        dict(kind="deauth", src=atk, dst="FF:FF:FF:FF:FF:FF", bssid=AP, ssid=SSID, channel=6, rssi=-45),
        dict(kind="beacon", src=fake, bssid=fake, ssid=SSID, channel=11, rssi=-50),
    ]


def recon():
    atk = rmac()
    return [dict(kind="probe_req", src=atk, ssid=f"net{i}", channel=6, rssi=-60) for i in range(60)]


def wpa():
    bssid, atk = AP, rmac()
    return ([dict(kind="deauth", src=atk, dst=rmac(), bssid=bssid, ssid=SSID, channel=6)]
            + [dict(kind="eapol", src=rmac(), bssid=bssid, channel=6) for _ in range(10)])


def mitm():
    return [dict(kind="arp", src=rmac(), extra={"ip": GW_IP, "op": 2}),
            dict(kind="arp", src=rmac(), extra={"ip": GW_IP, "op": 2})]


def dns():
    return [dict(kind="dns", src=GW_IP,
                 extra={"qname": f"x{random.randint(1000, 9999)}.example.com", "answers": ["192.168.1.99"]})]


def auth_dos():
    # จำลอง mdk3/mdk4 auth flood: ยิง authentication request รัว ๆ เข้า AP ด้วย MAC สุ่ม
    return [dict(kind="auth", src=rmac(), dst=AP, bssid=AP, ssid=SSID, channel=6, rssi=-48)
            for _ in range(40)]


def beacon_flood():
    # จำลอง mdk3/mdk4 beacon flood: สร้าง AP ปลอม 35 ตัวต่าง BSSID และ SSID บนช่องสัญญาณเดียวกัน
    return [dict(kind="beacon", src=rmac(), bssid=rmac(), ssid=f"FreeWiFi_{i}", channel=6, rssi=-60)
            for i in range(35)]


SCENARIOS = {"deauth": deauth, "auth_dos": auth_dos, "beacon_flood": beacon_flood,
             "evil_twin": evil_twin, "recon": recon, "wpa": wpa}


def send(url, token, name, events):
    req = urllib.request.Request(
        url.rstrip("/") + "/api/ingest",
        data=json.dumps({"sensor": "simulator", "events": events}).encode(),
        headers={"Content-Type": "application/json", **({"X-Token": token} if token else {})})
    with urllib.request.urlopen(req, timeout=10) as r:
        print(f"{name:10s} -> {len(events):3d} events sent, server: {r.read().decode()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=[*SCENARIOS, "all"])
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--token", default="")
    a = ap.parse_args()

    token = a.token
    if not token:
        from pathlib import Path
        env_file = Path(__file__).resolve().parent.parent / "configs" / ".env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("DASHBOARD_TOKEN="):
                    token = line.split("=", 1)[1].strip()
                    break

    for n in (SCENARIOS if a.scenario == "all" else [a.scenario]):
        send(a.url, token, n, SCENARIOS[n]())
