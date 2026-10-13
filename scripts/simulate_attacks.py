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

AP = "AA:BB:CC:11:22:33"


def rmac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def deauth():
    atk = rmac()
    return [dict(kind="deauth", src=atk, dst="FF:FF:FF:FF:FF:FF", bssid=AP, channel=6, rssi=-45)
            for _ in range(60)]


def evil_twin():
    fake = rmac()
    return [dict(kind="beacon", src=fake, bssid=fake, ssid="CampusWiFi", channel=11, rssi=-50)]


def recon():
    atk = rmac()
    return [dict(kind="probe_req", src=atk, ssid=f"net{i}", channel=6, rssi=-60) for i in range(60)]


def wpa():
    bssid, atk = rmac(), rmac()
    return ([dict(kind="deauth", src=atk, dst=rmac(), bssid=bssid, channel=6)]
            + [dict(kind="eapol", src=rmac(), bssid=bssid, channel=6) for _ in range(10)])


def mitm():
    return [dict(kind="arp", src=rmac(), extra={"ip": "192.168.1.1", "op": 2}),
            dict(kind="arp", src=rmac(), extra={"ip": "192.168.1.1", "op": 2})]


def dns():
    return [dict(kind="dns", src="192.168.1.1",
                 extra={"qname": f"x{random.randint(1000, 9999)}.example.com", "answers": ["192.168.1.99"]})]


SCENARIOS = {"deauth": deauth, "evil_twin": evil_twin, "recon": recon,
             "wpa": wpa, "mitm": mitm, "dns": dns}


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
