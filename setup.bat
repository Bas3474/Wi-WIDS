@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: ==============================================================================
:: Wi-Fi Micro-WIDS: Windows Setup Script (Plug & Play - No Monitor Mode Required)
:: ==============================================================================

:: 1. ตรวจสอบสิทธิ์ Administrator (จำเป็นสำหรับการเปิด Firewall พอร์ต 8000)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] กำลังขอสิทธิ์ Administrator เพื่อตั้งค่าระบบและ Firewall...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Wi-Fi Micro-WIDS Installer

set "PORT=8000"

echo ============================================================
echo   Wi-Fi Micro-WIDS: Windows Setup (Plug ^& Play Architecture)
echo ============================================================
echo.

:: 2. ตรวจสอบ Python ที่ใช้งานได้จริง (ตรวจทั้ง python, py, python3 และเช็คว่าไม่ใช่ Microsoft Store dummy)
echo [1/4] ตรวจสอบ Python ในเครื่อง...
set "PY_CMD="

:: ตรวจสอบ py launcher
py -3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py -3"
    goto :python_found
)

:: ตรวจสอบ python.exe
python --version >nul 2>&1
if %errorlevel% equ 0 (
    :: ตรวจสอบว่าไม่ใช่ Windows Store alias ที่เปิด Store
    python -c "import sys; print(sys.version)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_CMD=python"
        goto :python_found
    )
)

:: ตรวจสอบ python3
python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python3"
    goto :python_found
)

:python_not_found
echo.
echo [ERROR] ไม่พบ Python ที่พร้อมใช้งานในระบบ!
echo ------------------------------------------------------------
echo  วิธีแก้ไข:
echo  1. ดาวน์โหลด Python 3.10+ จาก https://www.python.org/downloads/
echo  2. ตอนติดตั้ง *สำคัญมาก*: ให้ติ๊กถูกที่ [x] "Add python.exe to PATH"
echo  3. หากเคยติดตั้งแล้ว ให้ปิด "App execution aliases" ของ Python ใน Windows Settings
echo ------------------------------------------------------------
pause
exit /b 1

:python_found
echo [OK] พบ Python: !PY_CMD!
!PY_CMD! --version

:: 3. สร้าง Virtual Environment (venv)
echo.
echo [2/4] ตรวจสอบ Virtual Environment (venv)...
if not exist "venv\Scripts\python.exe" (
    echo กำลังสร้าง venv ใหม่...
    !PY_CMD! -m venv venv
    if not exist "venv\Scripts\python.exe" (
        echo [ERROR] สร้าง venv ไม่สำเร็จ กรุณาตรวจสอบสิทธิ์การเขียนโฟลเดอร์
        pause
        exit /b 1
    )
    echo [OK] สร้าง Virtual Environment สำเร็จ
) else (
    echo [OK] พบ Virtual Environment เดิมอยู่แล้ว
)

:: 4. ติดตั้ง Packages
echo.
echo [3/4] ติดตั้ง Packages ที่จำเป็นสำหรับ WIDS...
"venv\Scripts\python.exe" -m pip install --upgrade pip
"venv\Scripts\python.exe" -m pip install -r "backend\requirements.txt"
if %errorlevel% neq 0 (
    echo [WARN] การติดตั้ง package บางตัวอาจมีปัญหา กำลังลองติดตั้งแพ็กเกจหลัก...
    "venv\Scripts\python.exe" -m pip install fastapi uvicorn pydantic httpx pyserial esptool
)
echo [OK] ติดตั้ง Python Packages เรียบร้อย

:: 5. คัดลอกไฟล์ตั้งค่าเริ่มต้น (ถ้ายังไม่มี)
if not exist "configs\.env" (
    copy /y "configs\.env.example" "configs\.env" >nul
    echo [OK] สร้าง configs\.env
)
if not exist "firmware\src\sniffer\config.h" (
    copy /y "firmware\src\sniffer\config.example.h" "firmware\src\sniffer\config.h" >nul
    echo [OK] สร้าง firmware\src\sniffer\config.h
)
if not exist "firmware\src\netwatch\config.h" (
    copy /y "firmware\src\netwatch\config.example.h" "firmware\src\netwatch\config.h" >nul
    echo [OK] สร้าง firmware\src\netwatch\config.h
)

:: 6. เปิด Windows Firewall พอร์ต 8000
echo.
echo [4/4] ตั้งค่า Windows Firewall อนุญาตพอร์ต %PORT%/TCP...
netsh advfirewall firewall delete rule name="Wi-Fi Micro-WIDS Port %PORT%" >nul 2>&1
netsh advfirewall firewall add rule name="Wi-Fi Micro-WIDS Port %PORT%" dir=in action=allow protocol=TCP localport=%PORT% profile=any >nul
echo [OK] เปิดพอร์ต %PORT%/TCP บน Windows Firewall เรียบร้อย

echo.
echo ============================================================
echo   ติดตั้งระบบสำหรับ Windows เสร็จสมบูรณ์แล้ว!
echo ============================================================
echo  สถาปัตยกรรม : ESP32 Plug ^& Play (ไม่ต้องใช้ Monitor Mode)
echo  วิธีใช้งาน  :
echo    1. เสียบสาย USB ESP32 เข้าคอมพิวเตอร์
echo    2. แฟลชบอร์ด (ครั้งแรก): ดับเบิลคลิก flash_esp32.bat
echo    3. รันระบบ WIDS        : ดับเบิลคลิก run.bat
echo    4. เปิดดู Dashboard    : http://localhost:%PORT%
echo ============================================================
echo.
pause
