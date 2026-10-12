# Sensor Protocol (ESP32 / เครื่องที่ 2 → Server)

Sensor ที่เชื่อมต่อเครือข่ายอยู่ (เช่น ESP32 ของเพื่อน) ส่งสิ่งที่ "เห็น" มาให้ Server วิเคราะห์ โดยไม่ต้องตัดสินเอง

```
POST http://<server-ip>:8000/api/ingest
Content-Type: application/json
X-Token: <DASHBOARD_TOKEN>      # ถ้าตั้งไว้ใน .env
```

```json
{
  "sensor": "esp32-1",
  "events": [
    {"kind": "arp", "src": "AA:BB:CC:00:00:01", "extra": {"ip": "192.168.1.1", "op": 2}},
    {"kind": "dns", "src": "192.168.1.1", "extra": {"qname": "google.com", "answers": ["192.168.1.99"], "mac": "AA:BB:CC:00:00:01"}},
    {"kind": "deauth", "src": "DE:AD:BE:EF:00:01", "dst": "FF:FF:FF:FF:FF:FF", "bssid": "AA:BB:CC:11:22:33", "channel": 6, "rssi": -50}
  ]
}
```

| kind | ฟิลด์ที่ต้องมี | ใช้ตรวจ |
|---|---|---|
| `arp` | `src` (MAC ผู้ส่ง), `extra.ip` (IP ที่อ้าง) | MITM |
| `dns` | `src` (IP resolver), `extra.qname`, `extra.answers[]` (A record), `extra.mac` (ถ้ามี) | Captive Portal / DNS ปลอม |
| `deauth` | `src`, `dst`, `bssid`, `channel`, `rssi` | Deauth, WPA crack |
| `beacon` | `bssid`, `ssid`, `channel`, `rssi` | Evil Twin |
| `probe_req` | `src`, `ssid` | Recon |
| `eapol` | `src`, `bssid` | WPA crack |

- `ts` (epoch วินาที) เว้นได้ Server จะใช้เวลาที่รับ
- ส่งเป็นชุดได้สูงสุด 500 events ต่อ request (แนะนำรวมทุก 0.5–1 วินาที)
- ESP32 ทำ promiscuous mode ได้ (`esp_wifi_set_promiscuous`) จึงส่ง `deauth/beacon/probe_req` ได้ด้วย แต่ ARP/DNS ต้องต่อ Wi-Fi เป็น station แล้วดักจาก lwIP — ฟังก์ชันสองแบบนี้ใช้พร้อมกันบนชิปเดียวไม่ได้ จึงควรเลือกบทบาทเดียวต่อบอร์ด
- ถ้ายังไม่มีบอร์ด ทดสอบด้วย `curl` ได้เลย (ตัวอย่างใน README)
