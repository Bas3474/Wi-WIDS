@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   Wi-Fi Micro-WIDS: ESP32 Plug ^& Play Firmware Flasher
echo ============================================================

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "PY_BIN=python"
if exist "venv\Scripts\python.exe" (
    set "PY_BIN=venv\Scripts\python.exe"
) else (
    py -3 --version >nul 2>&1 && set "PY_BIN=py -3"
)

"%PY_BIN%" "scripts\flash_esp32.py"

echo.
pause
