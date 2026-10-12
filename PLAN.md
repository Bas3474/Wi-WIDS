# Wi-Fi Micro-WIDS: Management-Frame Attack Detection — Project Plan

## 1. Overview & Architecture
ระบบตรวจจับการโจมตีเครือข่ายไร้สาย (WIDS) ไม่ใช้ ESP32

| บทบาท | อุปกรณ์ | หมายเหตุ |
|---|---|---|
| Attacker (พักไว้) | Laptop/PC + Wi-Fi card (Monitor + Injection) | Phase 4 |
| Defender / Sensor | Laptop รัน FastAPI + Detection Engine | Phase 2 เป็น Linux เท่านั้น |
| Dashboard | Web App (Vue 3 + Tailwind) เปิดจากมือถือ/คอมผ่าน LAN | `0.0.0.0:8000` |
| Alert | WebSocket + LINE Messaging API (เฉพาะ Critical, มี throttle) | |

> Browser เปิด Monitor Mode ไม่ได้ จึงให้ Python service บน Laptop เป็นผู้ดักจับ แล้วให้เบราว์เซอร์เป็นแค่หน้าแสดงผล

## 2. Threat Scenarios & ความสามารถในการตรวจจับจริง

| # | ภัยคุกคาม | วิธีตรวจ | Layer | ความน่าเชื่อถือ |
|---|---|---|---|---|
| 1 | Deauth Attack | Rate ของ Deauth/Disassoc ต่อ source/BSSID สูงผิดปกติ | 802.11 | สูง |
| 2 | Evil Twin | SSID เดียวกันแต่ BSSID/Channel/Vendor ไม่อยู่ใน profile (`config.json`) | 802.11 | สูง |
| 3 | MITM | ARP poisoning (MAC ซ้อนกับ IP เดียวกัน) | ARP/IP | heuristic — ต้องเชื่อมต่อเครือข่ายด้วย card ตัวที่ 2 |
| 4 | WPA Key Cracking | EAPOL handshake ซ้ำสั้น ๆ **สัมพันธ์กับ Deauth** (correlation) | 802.11 | กลาง |
| 5 | Recon / Probe Flood | Probe Request ถี่จาก MAC เดียว/หลาย MAC | 802.11 | กลาง (Eavesdropping แบบ passive ตรวจไม่ได้) |
| 6 | Captive Portal Phishing | DNS ตอบ IP ต่างจาก resolver จริง / พบ Open AP ที่ SSID ซ้ำ | DNS | heuristic — ต้องเชื่อมต่อเครือข่าย |

## 3. Tech Stack
- Backend: Python 3.10+, FastAPI, Uvicorn, WebSocket, Pydantic, HTTPX, SQLite
- Frontend: Vue 3, Tailwind, Chart.js (CDN; ออฟไลน์ให้เก็บไว้ใน `frontend/static/`)
- Phase 2: Scapy

## 4. Phases

### Phase 1: Web App + Mock + LINE (ไฟล์เสร็จแล้ว รอทดสอบบนมือถือ)
- [x] Schemas (`schemas.py`) พร้อมฟิลด์ `layer`, `source`
- [x] FastAPI + WebSocket (`main.py`)
- [x] Mock generator 6 รูปแบบ (`mock_generator.py`)
- [x] SQLite เก็บประวัติถาวร (`db.py`)
- [x] Dashboard: Status card, Doughnut chart, Live feed, Modal, ค้นหา, CSV, Mute, WS auto-reconnect
- [x] LINE notifier + throttle (`line_notifier.py`) — รอ Token
- [x] Endpoint `/api/simulate` สำหรับทดสอบ (ป้องกันด้วย `DASHBOARD_TOKEN` ถ้าตั้งไว้)
- [ ] ทดสอบเปิดพร้อมกันบนมือถือ + คอม
- [ ] ใส่ LINE Token แล้วทดสอบส่งจริง

### Phase 2: Real Sniffer & Detection Engine (Linux) — โค้ดเสร็จ, unit test ผ่าน 19 ข้อ, รอทดสอบกับ card จริง
- [x] `sniffer.py` — Scapy Monitor Mode + channel hopping, `NetSniffer` (ARP/DNS), `replay_pcap`
- [x] Sliding window (Deauth 5s / Recon 10s / EAPOL 30s) ใน `detectors.py`
- [x] Detector ครบ 6 rule + cooldown กันแจ้งซ้ำ + unit test (`tests/`)
- [x] Correlation Deauth ↔ EAPOL
- [x] `MODE=live` ใน `.env` + `configs/config.json`
- [x] `/api/ingest` + `docs/SENSOR_PROTOCOL.md` สำหรับ ESP32 / เครื่องที่ 2 (ยังไม่มีเฟิร์มแวร์ ESP32)
- [ ] ทดสอบกับ card จริง (`scripts/setup_monitor.sh`) และปรับ threshold
- [ ] เก็บ `.pcap` ตัวอย่างสำหรับทดสอบ replay

### Phase 3: Config & Packaging
- [ ] `configs/config.json` (interface, SSID/BSSID profile, threshold)
- [ ] `install.sh` / สคริปต์ตั้ง Monitor Mode
- [ ] README เรื่องข้อจำกัด และข้อควรระวังทางกฎหมาย

### Phase 4: Field Test
- [ ] Attacker: `aireplay-ng`, `mdk4` (ในเครือข่ายตัวเองเท่านั้น)
- [ ] วัด Detection Rate / False Positive / Latency

## 5. Directory Structure
```text
Network_Project/
├── backend/ (main.py, schemas.py, db.py, mock_generator.py, line_notifier.py, requirements.txt)
├── frontend/index.html
├── configs/.env.example   # คัดลอกเป็น configs/.env
├── incidents.db           # สร้างอัตโนมัติ (ถูก ignore)
├── PLAN.md
└── README.md
```