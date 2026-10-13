#!/usr/bin/env bash
# ============================================================
# Wi-Fi Micro-WIDS: Server Launcher for Linux (Debian / Ubuntu)
# ============================================================
set -e
cd "$(dirname "$0")"

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

# ตรวจสอบ virtual environment
PYTHON_BIN=""
if [ -f "venv/bin/python3" ]; then
    PYTHON_BIN="venv/bin/python3"
elif [ -f "venv/bin/python" ]; then
    PYTHON_BIN="venv/bin/python"
else
    echo "⚠️ ไม่พบ Virtual Environment กำลังติดตั้งแพ็กเกจ..."
    python3 -m venv venv
    venv/bin/pip install --upgrade pip -q
    venv/bin/pip install -r backend/requirements.txt -q
    PYTHON_BIN="venv/bin/python3"
fi

echo "============================================================"
echo "🚀 กำลังเริ่มต้น Wi-Fi Micro-WIDS Server..."
echo "============================================================"
echo "  - หน้าเว็บ Dashboard : http://localhost:8000"
echo "  - เซนเซอร์ ESP32     : เชื่อมต่อผ่านสาย USB Plug & Play"
echo "                         (เสียบสายแล้วระบบจะตรวจพบและรับข้อมูลทันที)"
echo "  - กด Ctrl+C เพื่อหยุดการทำงานของเซิร์ฟเวอร์"
echo "============================================================"
echo ""

# เปิดเบราว์เซอร์อัตโนมัติในเบื้องหลัง (หากมี Desktop GUI)
if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    (sleep 2 && (xdg-open http://localhost:8000 2>/dev/null || sensible-browser http://localhost:8000 2>/dev/null || true)) &
fi

exec "$PYTHON_BIN" "backend/main.py"
