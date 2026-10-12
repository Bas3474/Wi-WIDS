# ESP32 Firmware (PlatformIO, draft — ยังไม่ได้ทดสอบกับบอร์ด)

| Environment | โค้ด | บทบาท | ส่ง event |
|---|---|---|---|
| `sniffer` | `src/sniffer/main.cpp` | ดักเฟรม 802.11 แบบ promiscuous | deauth, beacon, probe_req, auth, eapol |
| `netwatch` | `src/netwatch/main.cpp` | ตรวจ ARP gateway + DNS แบบ active | arp, dns |

ใช้ **1 บอร์ดต่อ 1 บทบาท** (ถ้ามีบอร์ดเดียวก็สลับ upload ได้)

## ใช้งานใน VS Code + PlatformIO
1. ติดตั้ง extension **PlatformIO IDE** (โปรเจกต์แนะนำให้อัตโนมัติ) แล้ว **เปิดโฟลเดอร์ `firmware/`** ใน VS Code (ไม่ใช่โฟลเดอร์รากของโปรเจกต์ ไม่งั้น PlatformIO จะไม่เจอ `platformio.ini`)
2. ตั้งค่า: คัดลอกไฟล์ตัวอย่างของ environment ที่จะใช้
   ```bash
   cp src/sniffer/config.example.h src/sniffer/config.h      # หรือ src/netwatch/...
   ```
   แล้วแก้ Wi-Fi, `SERVER_URL` (IP ของ Laptop ที่รัน server), `SERVER_TOKEN`
3. ต่อ ESP32 ด้วย USB แล้วเลือก environment ที่แถบล่างของ VS Code (`env:sniffer` / `env:netwatch`) กด **→ Upload** และ **Serial Monitor** (115200) หรือใช้ terminal:
   ```bash
   pio run -e sniffer -t upload
   pio device monitor
   ```
4. ควรเห็น `sent N events -> HTTP 200` และ Dashboard แสดง incident ที่ `source` เป็น `sensor:<SENSOR_NAME>`

### ปัญหาที่พบบ่อยบน Linux
- `Permission denied: /dev/ttyUSB0` → `sudo usermod -aG dialout $USER` แล้ว logout/login ใหม่ (ลง udev rules ของ PlatformIO เพิ่มได้)
- upload ค้างที่ `Connecting....` → กดค้างปุ่ม **BOOT** ตอนเริ่ม upload
- พอร์ตไม่ขึ้น → ลองสาย USB ที่ส่งข้อมูลได้ / ตรวจ `ls /dev/ttyUSB* /dev/ttyACM*`

## ตั้งค่าฝั่ง server (`configs/config.json`) ให้ netwatch
- `network.gateway_ip` และ `gateway_mac` (`ip neigh show <gateway_ip>` บน Laptop ตอนที่ยังปลอดภัย) → ถ้า ARP ของ gateway เปลี่ยนจะเป็น Critical
- `network.trusted_resolvers`: IP ของ DNS ที่เชื่อถือ (มักเป็น IP ของ router) → คำตอบจาก resolver อื่นเป็น Critical
- อย่าใส่ `dns_expected` สำหรับโดเมนที่ IP เปลี่ยนตาม CDN (เช่น google.com)

## ข้อจำกัดที่ต้องรู้
- sniffer ฟังได้ช่องเดียวกับ AP ที่เชื่อมต่อ ไม่ hop ช่อง (ถ้าอยากครอบคลุมหลายช่อง ให้ใช้ card ของ Laptop)
- ESP32 ไม่สามารถ inject/ยิงโจมตีด้วยเฟิร์มแวร์นี้ (เป็น sensor อย่างเดียว)
- Beacon ถูกลดเหลือ ≤ 1 ครั้ง/5 วินาที/BSSID ดังนั้นกราฟ Frame Breakdown จากบอร์ดไม่ใช่จำนวนเฟรมจริง
- เวลาของ event คือเวลาที่ server รับ (batch ทุก 1 วินาที)
- ถ้าคอมไพล์ไม่ผ่าน ส่วนที่น่าจะต้องแก้คือ `lwip/etharp.h` ใน netwatch และ field ของ `wifi_promiscuous_filter_t`
