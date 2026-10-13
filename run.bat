@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Wi-Fi Micro-WIDS Server

if not exist "venv\Scripts\python.exe" (
    echo [WARN] ยังไม่ได้ติดตั้งระบบ กำลังรัน setup.bat อัตโนมัติ...
    call setup.bat
)

echo ============================================================
echo   กำลังเริ่มต้น Wi-Fi Micro-WIDS Server...
echo ============================================================
echo  - หน้าเว็บ Dashboard : http://localhost:8000
echo  - เซนเซอร์ ESP32     : เชื่อมต่อผ่านสาย USB Plug ^& Play
echo                         (เสียบสายแล้วระบบจะรับข้อมูลทันที)
echo.
echo  กด Ctrl+C เพื่อหยุดการทำงานของเซิร์ฟเวอร์
echo ============================================================
echo.

:: เปิด Browser อัตโนมัติหลังจากรอ 1.5 วินาที
start "" "http://localhost:8000"

"venv\Scripts\python.exe" "backend\main.py"

echo.
echo [INFO] เซิร์ฟเวอร์หยุดทำงานแล้ว
pause
