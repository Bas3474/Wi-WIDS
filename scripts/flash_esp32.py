#!/usr/bin/env python3
"""
Wi-Fi Micro-WIDS: เครื่องมือ Auto-Flash Firmware ESP32 แบบ One-Click
ค้นหาพอร์ตอัตโนมัติและแฟลช Firmware โดยไม่ต้องเปิด PlatformIO ใน VS Code
"""
import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / "firmware" / ".pio" / "build" / "sniffer"
BIN_DIR = ROOT / "firmware" / "bin" / "sniffer"


def get_firmware_dir(env_name: str = "sniffer") -> Path:
    build_dir = ROOT / "firmware" / ".pio" / "build" / env_name
    bin_dir = ROOT / "firmware" / "bin" / env_name
    if (build_dir / "firmware.bin").exists() and (build_dir / "bootloader.bin").exists() and (build_dir / "partitions.bin").exists():
        return build_dir
    if (bin_dir / "firmware.bin").exists() and (bin_dir / "bootloader.bin").exists() and (bin_dir / "partitions.bin").exists():
        return bin_dir
    return build_dir


def find_all_esp32_ports() -> list[str]:
    found = []
    try:
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            dev = p.device or ""
            desc = (p.description or "").lower()
            hwid = (p.hwid or "").lower()

            # ข้ามพอร์ตเสมือน Bluetooth และพอร์ตสื่อสารของเมนบอร์ด
            if dev.startswith("/dev/ttyS"):
                continue
            if "bluetooth" in desc or "bth" in hwid or "bt" in desc.split():
                continue
            if "communications port" in desc or "standard modem" in desc:
                continue

            is_usb = (
                p.vid is not None
                or dev.startswith("/dev/ttyUSB")
                or dev.startswith("/dev/ttyACM")
                or "usb" in dev.lower()
                or "usb" in desc
                or "acm" in dev.lower()
            )
            is_esp_chip = any(k in desc or k in hwid for k in (
                "cp210", "ch340", "ch341", "ch910", "ftdi", "espressif", "esp32", "uart", "jtag"
            ))

            if is_usb and (is_esp_chip or p.vid in (0x1A86, 0x10C4, 0x0403, 0x303A, 0x2341)):
                if dev not in found:
                    found.append(dev)
            elif is_usb and (dev.startswith("/dev/ttyUSB") or dev.startswith("/dev/ttyACM") or "usb-serial" in desc or "usb serial" in desc):
                if dev not in found:
                    found.append(dev)
    except ImportError:
        pass
    return found


def flash_single_port(port: str, fw_dir: Path, esptool_cmd: list | None, env_name: str = "sniffer") -> bool:
    bootloader = fw_dir / "bootloader.bin"
    partitions = fw_dir / "partitions.bin"
    firmware = fw_dir / "firmware.bin"

    if esptool_cmd and firmware.exists() and bootloader.exists() and partitions.exists():
        print(f"\n🚀 กำลังแฟลชเฟิร์มแวร์ [{env_name}] เข้าสู่ ESP32 บนพอร์ต {port}...")
        print("⚠️ หากหน้าจอขึ้น Connecting........_____..... ให้ 'กดปุ่ม BOOT บนบอร์ดค้างไว้' ทันที!\n")
        cmd = esptool_cmd + [
            "--chip", "esp32",
            "--port", port,
            "--baud", "460800",
            "--before", "default_reset",
            "--after", "hard_reset",
            "write_flash", "-z",
            "--flash_mode", "dio",
            "--flash_freq", "40m",
            "--flash_size", "detect",
            "0x1000", str(bootloader),
            "0x8000", str(partitions),
            "0x10000", str(firmware)
        ]
        ret = subprocess.run(cmd)
        if ret.returncode == 0:
            print(f"🎉 สำเร็จ! บอร์ดบนพอร์ต {port} แฟลช [{env_name}] เรียบร้อย 100%")
            return True
        else:
            print(f"\n⚠️ การแฟลช {port} ผ่าน esptool ไม่สำเร็จ กำลังลองวิธีสำรองผ่าน PlatformIO...")

    import shutil
    if shutil.which("pio"):
        print(f"\n🚀 รัน PlatformIO Upload [{env_name}] ไปที่ {port}...")
        cmd = ["pio", "run", "-d", str(ROOT / "firmware"), "-e", env_name, "-t", "upload", "--upload-port", port]
        ret = subprocess.run(cmd)
        return ret.returncode == 0
    else:
        print(f"\n❌ ไม่สามารถแฟลชบอร์ด {port} ได้ (ไม่พบ esptool หรือ PlatformIO)")
        return False


def main():
    print("=" * 60)
    print("🔌 Wi-Fi Micro-WIDS: ESP32 Firmware Flasher (Plug & Play Tool)")
    print("=" * 60)

    ports = find_all_esp32_ports()
    if not ports:
        print("❌ ไม่พบพอร์ต ESP32 ที่เชื่อมต่ออยู่!")
        print("💡 คำแนะนำ:")
        print("  1. ตรวจสอบว่าเสียบสาย USB แน่นหนาดีแล้ว")
        print("  2. สำหรับ Windows ตรวจสอบว่าลงไดรเวอร์ CH340 / CP2102 แล้ว")
        print("  3. ลองถอดแล้วเสียบสายใหม่อีกครั้ง")
        sys.exit(1)

    print("\n📦 เลือกประเภทเฟิร์มแวร์ (Environment) ที่ต้องการแฟลช:")
    print("  [1] sniffer  - Wi-Fi 802.11 Layer-2 Sniffer (USB Plug & Play - แนะนำ)")
    print("  [2] netwatch - ARP / DNS Layer-3 Watcher (เกาะ Wi-Fi)")
    try:
        env_choice = input("\n👉 เลือก Environment [กด Enter เพื่อใช้ sniffer]: ").strip()
    except (EOFError, KeyboardInterrupt):
        env_choice = "1"
    env_name = "netwatch" if env_choice == "2" else "sniffer"

    fw_dir = get_firmware_dir(env_name)

    # ลองหา esptool ก่อน
    esptool_cmd = None
    try:
        import esptool  # noqa
        esptool_cmd = [sys.executable, "-m", "esptool"]
    except ImportError:
        pass

    if not esptool_cmd:
        import shutil
        if shutil.which("esptool.py"):
            esptool_cmd = ["esptool.py"]
        elif shutil.which("esptool"):
            esptool_cmd = ["esptool"]

    target_ports = []
    if len(ports) == 1:
        print(f"\n✅ ตรวจพบ ESP32 เชื่อมต่ออยู่ที่พอร์ต: {ports[0]}")
        target_ports = [ports[0]]
    else:
        print(f"\n✅ ตรวจพบ ESP32 เชื่อมต่ออยู่ {len(ports)} บอร์ด:")
        for idx, p in enumerate(ports, 1):
            print(f"  [{idx}] พอร์ต {p}")
        print(f"  [A] แฟลชทุกบอร์ดอัตโนมัติ (Flash All - แนะนำ)")

        try:
            choice = input(f"\n👉 เลือกบอร์ดที่ต้องการแฟลช [{env_name}] (กด Enter เพื่อแฟลชทุกบอร์ด): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "a"

        if not choice or choice in ("a", "all"):
            target_ports = ports
        else:
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(ports):
                    target_ports = [ports[selected_idx]]
                else:
                    target_ports = ports
            except ValueError:
                target_ports = ports

    success_count = 0
    for idx, p in enumerate(target_ports, 1):
        print("\n" + "=" * 60)
        print(f"📦 [{idx}/{len(target_ports)}] กำลังแฟลชเฟิร์มแวร์ [{env_name}] เข้าสู่พอร์ต: {p}")
        print("=" * 60)
        if flash_single_port(p, fw_dir, esptool_cmd, env_name):
            success_count += 1

    print("\n" + "=" * 60)
    if success_count == len(target_ports):
        print(f"🎉 สำเร็จครบทั้งหมด! แฟลช ESP32 สำเร็จ {success_count}/{len(target_ports)} บอร์ด")
        print("บอร์ดของคุณกลายเป็นตัวรับสัญญาณ Plug & Play เต็มรูปแบบแล้ว:")
        print("  - เสียบสาย USB ทั้งหมดค้างไว้ที่คอมพิวเตอร์")
        print("  - ดับเบิลคลิก run.bat เพื่อเริ่มต้นระบบ")
        print("  - ระบบจะสตรีมข้อมูลขึ้น Dashboard อัตโนมัติ!")
    else:
        print(f"⚠️ ดำเนินการเสร็จสิ้น: สำเร็จ {success_count}/{len(target_ports)} บอร์ด")
    print("=" * 60)


if __name__ == "__main__":
    main()
