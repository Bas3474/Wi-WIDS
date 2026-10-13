// คัดลอกไฟล์นี้เป็น config.h แล้วแก้ค่า (config.h ถูก .gitignore ไว้ ไม่หลุดขึ้น git)
#pragma once

// โหมดส่งข้อมูล:
//   1 = ส่งผ่านสาย USB Serial เข้าคอมโดยตรง (แนะนำ! ไม่ต้องต่อ Wi-Fi, สลับสแกนได้หลายช่อง, ไม่หลุดตอนโดนยิง Deauth)
//   0 = ส่งไร้สายผ่าน Wi-Fi HTTP ไปยัง SERVER_URL
#define USE_USB_SERIAL 1

// ช่องสัญญาณ 2.4 GHz ที่จะให้ ESP32 สลับสแกน (ใช้เมื่อ USE_USB_SERIAL = 1)
#define HOP_CHANNELS {1, 6, 11}
#define HOP_INTERVAL_MS 350

#define SENSOR_NAME "esp32-sniffer-usb"

// ตั้งค่าด้านล่างนี้ใช้เฉพาะกรณีตั้ง USE_USB_SERIAL = 0 (โหมดส่งไร้สายผ่าน Wi-Fi)
#define WIFI_SSID "Yes_Yes_Yes"
#define WIFI_PASS "thecoachofdream"
#define SERVER_URL "http://10.77.167.200:8000/api/ingest"
#define SERVER_TOKEN "tae_warakorn"
