@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [WARN] ยังไม่ได้ติดตั้งสภาพแวดล้อม กำลังรัน setup.bat ก่อน...
    call setup.bat
)

echo ============================================================
echo กำลังเปิด Wi-Fi Micro-WIDS Server...
echo  - หน้าเว็บบนเครื่องนี้ : http://localhost:8000
echo  - หน้าเว็บบนมือถือ   : http://10.77.167.200:8000
echo  - รับข้อมูล ESP32   : http://10.77.167.200:8000/api/ingest
echo  (กด Ctrl+C เพื่อหยุดการทำงาน)
echo ============================================================
start "" "http://localhost:8000"
"venv\Scripts\python.exe" "backend\main.py"
pause
