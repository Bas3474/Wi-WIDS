@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   Wi-Fi Micro-WIDS: ESP32 Plug ^& Play Firmware Flasher
echo ============================================================

set "PY_BIN=python"
if exist "venv\Scripts\python.exe" (
    set "PY_BIN=venv\Scripts\python.exe"
)

"%PY_BIN%" "scripts\flash_esp32.py"

echo.
pause
