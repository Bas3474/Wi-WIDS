#!/usr/bin/env bash
# ตั้ง Wi-Fi card เป็น Monitor Mode  ใช้: sudo scripts/setup_monitor.sh wlan0 [channel]
# หมายเหตุ: ระหว่างอยู่ใน Monitor Mode card ตัวนี้จะเชื่อมต่อ Wi-Fi ไม่ได้
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"
IFACE="${1:?usage: $0 <iface> [channel]}"
AUTO_CH=$(iw dev "$IFACE" info 2>/dev/null | awk '/channel/ {print $2}' || true)
CH="${2:-${AUTO_CH:-6}}"
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$IFACE" managed no 2>/dev/null || true
fi
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
iw dev "$IFACE" set channel "$CH"
echo "$IFACE -> monitor mode, channel $CH"
echo "คืนค่า: sudo nmcli device set $IFACE managed yes 2>/dev/null || true; sudo ip link set $IFACE down && sudo iw dev $IFACE set type managed && sudo ip link set $IFACE up"
