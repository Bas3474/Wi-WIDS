// คัดลอกไฟล์นี้เป็น config.h แล้วแก้ค่า (config.h ถูก .gitignore ไว้ ไม่หลุดขึ้น git)
#pragma once

#define WIFI_SSID "Yes_Yes_Yes"
#define WIFI_PASS "thecoachofdream"

// IP ของเครื่อง Laptop ที่รัน backend (ล็อกไว้ที่ 10.77.167.200)
#define SERVER_URL "http://10.77.167.200:8000/api/ingest"
#define SERVER_TOKEN "tae_warakorn" // ตรงกับ DASHBOARD_TOKEN ใน .env (เว้นว่างถ้าไม่ได้ตั้ง)
#define SENSOR_NAME "esp32-sniffer-1"
