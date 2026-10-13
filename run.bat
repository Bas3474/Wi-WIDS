@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Wi-Fi Micro-WIDS Server

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if not exist "venv\Scripts\python.exe" (
    echo [WARN] ยังไม่ได้ติดตั้งระบบ กำลังรัน setup.bat อัตโนมัติ...
    call setup.bat
    if not exist "venv\Scripts\python.exe" (
        echo.
        echo [ERROR] ไม่พบ Virtual Environment ไม่สามารถเริ่มต้นระบบได้!
        pause
        exit /b 1
    )
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

:: เปิด Browser อัตโนมัติในเบื้องหลังหลังจากรอเซิร์ฟเวอร์เริ่มทำงาน 2 วินาที
start /b "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8000"

"venv\Scripts\python.exe" "backend\main.py"

echo.
echo [INFO] เซิร์ฟเวอร์หยุดทำงานแล้ว
pause
