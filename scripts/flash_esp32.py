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


def get_firmware_dir() -> Path:
    if (BUILD_DIR / "firmware.bin").exists() and (BUILD_DIR / "bootloader.bin").exists() and (BUILD_DIR / "partitions.bin").exists():
        return BUILD_DIR
    if (BIN_DIR / "firmware.bin").exists() and (BIN_DIR / "bootloader.bin").exists() and (BIN_DIR / "partitions.bin").exists():
        return BIN_DIR
    return BUILD_DIR


def find_esp32_port() -> str:
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
                return dev
            elif is_usb and (dev.startswith("/dev/ttyUSB") or dev.startswith("/dev/ttyACM") or "usb-serial" in desc or "usb serial" in desc):
                return dev
    except ImportError:
        pass
    return ""


def main():
    print("=" * 60)
    print("🔌 Wi-Fi Micro-WIDS: ESP32 Firmware Flasher (Plug & Play Tool)")
    print("=" * 60)

    port = find_esp32_port()
    if not port:
        print("❌ ไม่พบพอร์ต ESP32 ที่เชื่อมต่ออยู่!")
        print("💡 คำแนะนำ:")
        print("  1. ตรวจสอบว่าเสียบสาย USB แน่นหนาดีแล้ว")
        print("  2. สำหรับ Windows ตรวจสอบว่าลงไดรเวอร์ CH340 / CP2102 แล้ว")
        print("  3. ลองถอดแล้วเสียบสายใหม่อีกครั้ง")
        sys.exit(1)

    print(f"✅ ตรวจพบ ESP32 เชื่อมต่ออยู่ที่พอร์ต: {port}")

    fw_dir = get_firmware_dir()
    bootloader = fw_dir / "bootloader.bin"
    partitions = fw_dir / "partitions.bin"
    firmware = fw_dir / "firmware.bin"

    # ลองใช้ esptool ก่อน
    esptool_cmd = None
    try:
        import esptool  # noqa
        esptool_cmd = [sys.executable, "-m", "esptool"]
    except ImportError:
        pass

    if not esptool_cmd:
        # ลองหา esptool ในระบบ
        import shutil
        if shutil.which("esptool.py"):
            esptool_cmd = ["esptool.py"]
        elif shutil.which("esptool"):
            esptool_cmd = ["esptool"]

    if esptool_cmd and firmware.exists() and bootloader.exists() and partitions.exists():
        print(f"\n🚀 กำลังแฟลชเฟิร์มแวร์เข้าสู่ ESP32 บนพอร์ต {port}...")
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
            print("\n" + "=" * 60)
            print("🎉 สำเร็จ! ESP32 ได้รับการแฟลชเฟิร์มแวร์เรียบร้อยแล้ว 100%")
            print("บอร์ดของคุณกลายเป็นตัวรับสัญญาณ Plug & Play เต็มรูปแบบแล้ว:")
            print("  - เสียบสาย USB ค้างไว้ที่คอมพิวเตอร์")
            print("  - รันเซิร์ฟเวอร์ด้วย run.bat (หรือ backend/main.py)")
            print("  - ระบบจะสตรีมข้อมูลขึ้น Dashboard อัตโนมัติ!")
            print("=" * 60)
            return
        else:
            print("\n⚠️ การแฟลชผ่าน esptool ไม่สำเร็จ กำลังลองวิธีสำรองผ่าน PlatformIO...")

    # วิธีสำรอง: PlatformIO
    pio_bin = "pio"
    import shutil
    if shutil.which("pio"):
        print(f"\n🚀 รัน PlatformIO Upload ไปที่ {port}...")
        cmd = ["pio", "run", "-d", str(ROOT / "firmware"), "-e", "sniffer", "-t", "upload", "--upload-port", port]
        subprocess.run(cmd)
    else:
        print("\n❌ ไม่พบคำสั่ง PlatformIO หรือ esptool ใน Environment ปัจจุบัน")
        print("💡 ให้เปิดโปรเจกต์ใน VS Code แล้วกดปุ่ม Upload (รูปเครื่องหมายลูกศรขวาด้านล่างของ PlatformIO)")


if __name__ == "__main__":
    main()
