# Wi-Fi Micro-WIDS

ดูแผนและความสามารถที่ [PLAN.md](PLAN.md)

## Run (Phase 1, mock mode)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt
cp configs/.env.example configs/.env
cd backend && python main.py
```
เปิด `http://localhost:8000` หรือจากมือถือ (Wi-Fi เดียวกัน) `http://<IP เครื่อง>:8000`
(`hostname -I` เพื่อดู IP)

## LINE
ใส่ `LINE_CHANNEL_ACCESS_TOKEN` และ `LINE_USER_ID` ใน `configs/.env` แล้วกด "จำลองเหตุการณ์" เพื่อทดสอบ (ส่งเฉพาะ Critical)

## ข้อควรระวัง
ทดสอบการโจมตีเฉพาะเครือข่ายของตัวเองหรือที่ได้รับอนุญาตเท่านั้น
ข้อ MITM และ Captive Portal ตรวจแบบ heuristic ต้องเชื่อมต่อเครือข่าย ไม่ใช่ Monitor Mode อย่างเดียว

## Phase 2: โหมด live
```bash
sudo scripts/setup_monitor.sh wlan0 6      # ตั้ง Monitor Mode (card จะเชื่อมต่อ Wi-Fi ไม่ได้ระหว่างนี้)
# แก้ configs/config.json: interface, profiles (SSID/BSSID ที่เชื่อถือ), network.gateway_ip
# แก้ configs/.env: MODE=live
sudo venv/bin/python backend/main.py       # sniff ต้องใช้ root
python3 -m unittest discover -s tests -v   # รัน unit test ของ detector
```
ถ้า `net_interface` ว่าง จะไม่ตรวจ ARP/DNS ในเครื่องนี้ แต่รับจาก sensor อื่นได้ผ่าน `/api/ingest` ([โปรโตคอล](docs/SENSOR_PROTOCOL.md)) ทดสอบโดยไม่ต้องมีฮาร์ดแวร์:
```bash
curl -X POST localhost:8000/api/ingest -H 'Content-Type: application/json' -d '{"sensor":"test","events":[
 {"kind":"arp","src":"AA:AA:AA:AA:AA:01","extra":{"ip":"192.168.1.1"}},
 {"kind":"arp","src":"BB:BB:BB:BB:BB:02","extra":{"ip":"192.168.1.1"}}]}'
```
ควรตั้ง `DASHBOARD_TOKEN` เมื่อเปิด `/api/ingest` บนเครือข่ายที่คนอื่นเข้าถึงได้
