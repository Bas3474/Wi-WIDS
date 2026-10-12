#!/usr/bin/env bash
# ==============================================================================
# Wi-Fi Micro-WIDS: Full Environment Setup & Static IP Lock Script
# วิธีใช้: sudo ./setup.sh [ชื่อ_Hotspot] [รหัสผ่าน_Hotspot]
# ค่าเริ่มต้นดึงจากที่ตั้งค้างไว้: SSID="Yes_Yes_Yes", IP="10.77.167.200"
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

HOTSPOT_SSID="${1:-Yes_Yes_Yes}"
HOTSPOT_PASS="${2:-thecoachofdream}"
STATIC_IP="10.77.167.200"
STATIC_CIDR="${STATIC_IP}/24"
PORT="8000"

if [[ $EUID -ne 0 ]]; then
  echo "⚠️  กรุณารันด้วย sudo:  sudo ./setup.sh"
  exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"

echo "============================================================"
echo "🚀 [1/5] ติดตั้ง System Packages ที่จำเป็น..."
echo "============================================================"
apt-get update -qq
apt-get install -y -qq \
  python3 \
  python3-venv \
  python3-pip \
  iw \
  iproute2 \
  net-tools \
  wireless-tools \
  tcpdump \
  network-manager \
  curl

echo ""
echo "============================================================"
echo "🐍 [2/5] สร้าง Virtual Environment (venv) และติดตั้ง Python Packages..."
echo "============================================================"
if [[ ! -d "$ROOT_DIR/venv" ]]; then
  sudo -u "$REAL_USER" python3 -m venv "$ROOT_DIR/venv"
fi

"$ROOT_DIR/venv/bin/pip" install --upgrade pip -q
"$ROOT_DIR/venv/bin/pip" install -r "$ROOT_DIR/backend/requirements.txt" -q
echo "✅ ติดตั้ง Python packages (FastAPI, Uvicorn, Pydantic, HTTPX, Scapy) เรียบร้อย"

echo ""
echo "============================================================"
echo "⚙️  [3/5] ตรวจสอบไฟล์ตั้งค่า (.env และ Firmware config.h)..."
echo "============================================================"
if [[ ! -f "$ROOT_DIR/configs/.env" ]]; then
  cp "$ROOT_DIR/configs/.env.example" "$ROOT_DIR/configs/.env"
  chown "$REAL_USER:$REAL_USER" "$ROOT_DIR/configs/.env"
  echo "✅ สร้าง configs/.env จากไฟล์ตัวอย่างแล้ว"
else
  echo "ℹ️  พบ configs/.env อยู่แล้ว (ข้ามการเขียนทับ)"
fi

for role in sniffer netwatch; do
  CFG_DIR="$ROOT_DIR/firmware/src/$role"
  if [[ -d "$CFG_DIR" && ! -f "$CFG_DIR/config.h" ]]; then
    cp "$CFG_DIR/config.example.h" "$CFG_DIR/config.h"
    chown "$REAL_USER:$REAL_USER" "$CFG_DIR/config.h"
    echo "✅ สร้าง firmware/src/$role/config.h (ชี้ไปที่ http://${STATIC_IP}:${PORT}/api/ingest)"
  fi
done

echo ""
echo "============================================================"
echo "🌐 [4/5] ตั้งค่าเชื่อมต่อ Hotspot '${HOTSPOT_SSID}' และล็อก IP ${STATIC_IP}..."
echo "============================================================"

# หาชื่อ Wi-Fi Interface อัตโนมัติ (เช่น wlp2s0 หรือ wlan0)
WIFI_IFACE="$(nmcli -t -f DEVICE,TYPE dev status 2>/dev/null | awk -F: '$2=="wifi"{print $1; exit}' || true)"
if [[ -z "$WIFI_IFACE" ]]; then
  WIFI_IFACE="$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2; exit}' || true)"
fi
WIFI_IFACE="${WIFI_IFACE:-wlp2s0}"
echo "🔎 ตรวจพบ Wi-Fi Interface: ${WIFI_IFACE}"

# หากการ์ดค้างอยู่ใน Monitor Mode ให้สลับกลับมาเป็น Managed Mode ก่อนเพื่อให้เกาะ Hotspot ได้
CUR_TYPE="$(iw dev "$WIFI_IFACE" info 2>/dev/null | awk '$1=="type"{print $2}' || true)"
if [[ "$CUR_TYPE" == "monitor" ]]; then
  echo "🔄 สลับ ${WIFI_IFACE} จาก Monitor Mode กลับเป็น Managed Mode ชั่วคราว..."
  ip link set "$WIFI_IFACE" down || true
  iw dev "$WIFI_IFACE" set type managed || true
  ip link set "$WIFI_IFACE" up || true
  systemctl restart NetworkManager || true
  sleep 2
fi

if command -v nmcli >/dev/null 2>&1; then
  nmcli radio wifi on || true
  nmcli dev wifi rescan ifname "$WIFI_IFACE" 2>/dev/null || true

  # ตรวจสอบว่ามีโปรไฟล์ของ Hotspot นี้หรือยัง
  CON_NAME="$(nmcli -t -f NAME,TYPE connection show | awk -F: -v s="$HOTSPOT_SSID" '$1==s{print $1; exit}')"
  if [[ -z "$CON_NAME" ]]; then
    echo "➕ สร้างโปรไฟล์เชื่อมต่อ Hotspot '${HOTSPOT_SSID}'..."
    nmcli dev wifi connect "$HOTSPOT_SSID" password "$HOTSPOT_PASS" ifname "$WIFI_IFACE" name "$HOTSPOT_SSID" || true
    CON_NAME="$HOTSPOT_SSID"
  fi

  if nmcli connection show "$CON_NAME" >/dev/null 2>&1; then
    # ตั้งให้รับ Gateway/DNS จาก Hotspot อัตโนมัติ พร้อมล็อก IP 10.77.167.200/24 ค้างไว้เสมอ
    nmcli connection modify "$CON_NAME" \
      ipv4.method auto \
      ipv4.addresses "$STATIC_CIDR" \
      connection.autoconnect yes
    echo "🔒 บันทึกการล็อก IP ${STATIC_CIDR} ลงในโปรไฟล์ '${CON_NAME}' เรียบร้อย"
    nmcli connection up "$CON_NAME" >/dev/null 2>&1 || true
  fi
fi

# ผูก IP 10.77.167.200/24 เข้ากับ Interface ทันที (เผื่อกรณีไม่ได้เชื่อมต่อผ่าน nmcli)
ip addr replace "$STATIC_CIDR" dev "$WIFI_IFACE" 2>/dev/null || true

echo ""
echo "============================================================"
echo "🛡️  [5/5] เปิด Firewall Port ${PORT} สำหรับรับข้อมูลจาก ESP32 และมือถือ..."
echo "============================================================"
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
  echo "✅ เปิดพอร์ต ${PORT}/tcp บน UFW เรียบร้อย"
fi

echo ""
echo "============================================================"
echo "🎉 ตั้งค่าระบบเสร็จสมบูรณ์!"
echo "============================================================"
echo "📌 Wi-Fi Interface : ${WIFI_IFACE}"
echo "📌 Hotspot SSID    : ${HOTSPOT_SSID}"
echo "📌 Locked Server IP: ${STATIC_IP}"
echo "📌 Dashboard URL   : http://${STATIC_IP}:${PORT}"
echo "📌 ESP32 Ingest URL: http://${STATIC_IP}:${PORT}/api/ingest"
echo ""
echo "▶️  คำสั่งรันเซิร์ฟเวอร์:"
echo "   sudo ./venv/bin/python backend/main.py"
echo "============================================================"
