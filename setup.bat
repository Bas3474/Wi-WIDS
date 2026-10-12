@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: ==============================================================================
:: Wi-Fi Micro-WIDS: Windows Setup & Static IP Lock Script (No Monitor Mode)
:: วิธีใช้: คลิกขวา Run as Administrator (หรือดับเบิลคลิก ระบบจะขอสิทธิ์ Admin อัตโนมัติ)
:: ==============================================================================

:: ตรวจสอบสิทธิ์ Administrator หากยังไม่มีให้ขอสิทธิ์อัตโนมัติ
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] กำลังขอสิทธิ์ Administrator เพื่อตั้งค่า IP และ Firewall...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

set "HOTSPOT_SSID=Yes_Yes_Yes"
set "HOTSPOT_PASS=thecoachofdream"
set "STATIC_IP=10.77.167.200"
set "SUBNET_MASK=255.255.255.0"
set "DEFAULT_GW=10.77.167.1"
set "PORT=8000"

echo ============================================================
echo [1/5] ตรวจสอบ Python และสร้าง Virtual Environment (venv)...
echo ============================================================
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] ไม่พบ Python ในระบบ กรุณาติดตั้ง Python 3.10+ จาก python.org
    echo         ^(อย่าลืมติ๊ก "Add python.exe to PATH" ตอนติดตั้ง^)
    pause
    exit /b 1
)

if not exist "venv\Scripts\python.exe" (
    echo กำลังสร้าง Virtual Environment...
    python -m venv venv
)

echo ============================================================
echo [2/5] ติดตั้ง Python Packages ที่ต้องใช้ทั้งหมด...
echo ============================================================
"venv\Scripts\python.exe" -m pip install --upgrade pip -q
"venv\Scripts\python.exe" -m pip install -r "backend\requirements.txt" -q
echo [OK] ติดตั้ง FastAPI, Uvicorn, Pydantic, HTTPX, Scapy เรียบร้อย

echo.
echo ============================================================
echo [3/5] ตรวจสอบไฟล์ตั้งค่า (.env และ Firmware config.h)...
echo ============================================================
if not exist "configs\.env" (
    copy /y "configs\.env.example" "configs\.env" >nul
    echo [OK] สร้าง configs\.env เรียบร้อย
) else (
    echo [INFO] พบ configs\.env อยู่แล้ว
)

if not exist "firmware\src\sniffer\config.h" (
    copy /y "firmware\src\sniffer\config.example.h" "firmware\src\sniffer\config.h" >nul
    echo [OK] สร้าง firmware\src\sniffer\config.h เรียบร้อย
)
if not exist "firmware\src\netwatch\config.h" (
    copy /y "firmware\src\netwatch\config.example.h" "firmware\src\netwatch\config.h" >nul
    echo [OK] สร้าง firmware\src\netwatch\config.h เรียบร้อย
)

echo.
echo ============================================================
echo [4/5] เชื่อมต่อ Hotspot "%HOTSPOT_SSID%" และล็อก IP %STATIC_IP%...
echo ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ssid = '%HOTSPOT_SSID%'; $pass = '%HOTSPOT_PASS%'; $ip = '%STATIC_IP%'; $mask = '%SUBNET_MASK%'; $defGw = '%DEFAULT_GW%'; " ^
  "$xml = '<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>' + $ssid + '</name><SSIDConfig><SSID><name>' + $ssid + '</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>auto</connectionMode><MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>' + $pass + '</keyMaterial></sharedKey></security></MSM></WLANProfile>'; " ^
  "$tmp = Join-Path $env:TEMP 'wids_wlan.xml'; $xml | Set-Content -Path $tmp -Encoding UTF8; " ^
  "netsh wlan add profile filename=\"$tmp\" user=all | Out-Null; Remove-Item $tmp -Force -ErrorAction SilentlyContinue; " ^
  "netsh wlan connect name=\"$ssid\" ssid=\"$ssid\" | Out-Null; Start-Sleep -Seconds 3; " ^
  "$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Wireless|Wi-Fi|802\.11|WLAN' -or $_.Name -match 'Wi-Fi|WLAN') } | Select-Object -First 1; " ^
  "if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wireless|Wi-Fi|802\.11|WLAN' -or $_.Name -match 'Wi-Fi|WLAN' } | Select-Object -First 1 }; " ^
  "if ($adapter) { " ^
  "  $ifName = $adapter.Name; Write-Host ('[INFO] ตรวจพบการ์ด Wi-Fi: ' + $ifName); " ^
  "  $gwObj = (Get-NetIPConfiguration -InterfaceAlias $ifName -ErrorAction SilentlyContinue).IPv4DefaultGateway; " ^
  "  $gw = if ($gwObj -and $gwObj.NextHop) { $gwObj.NextHop } else { $defGw }; " ^
  "  Write-Host ('[INFO] ใช้ Gateway: ' + $gw + ' และล็อก IP: ' + $ip); " ^
  "  netsh interface ipv4 set address name=\"$ifName\" static $ip $mask $gw 1 | Out-Null; " ^
  "  netsh interface ipv4 set dns name=\"$ifName\" static $gw primary | Out-Null; " ^
  "  netsh interface ipv4 add dns name=\"$ifName\" 8.8.8.8 index=2 | Out-Null; " ^
  "  Write-Host ('[OK] ล็อก IP ' + $ip + ' บน ' + $ifName + ' สำเร็จ!'); " ^
  "} else { Write-Host '[WARN] ไม่พบการ์ด Wi-Fi ในเครื่อง กรุณาตรวจสอบอะแดปเตอร์' }"

echo.
echo ============================================================
echo [5/5] เปิด Windows Firewall พอร์ต %PORT% (สำหรับ ESP32 และมือถือ)...
echo ============================================================
netsh advfirewall firewall delete rule name="Wi-Fi Micro-WIDS Port %PORT%" >nul 2>&1
netsh advfirewall firewall add rule name="Wi-Fi Micro-WIDS Port %PORT%" dir=in action=allow protocol=TCP localport=%PORT% profile=any >nul
echo [OK] เปิดพอร์ต %PORT%/TCP บน Windows Firewall ทุกโปรไฟล์ (Public/Private) เรียบร้อย

echo.
echo ============================================================
echo ตั้งค่าระบบบน Windows เสร็จสมบูรณ์!
echo ============================================================
echo  Hotspot SSID     : %HOTSPOT_SSID%
echo  Locked Server IP : %STATIC_IP%
echo  Dashboard URL    : http://%STATIC_IP%:%PORT%
echo  ESP32 Ingest URL : http://%STATIC_IP%:%PORT%/api/ingest
echo.
echo  วิธีรันเซิร์ฟเวอร์: ดับเบิลคลิกไฟล์ run.bat หรือรันคำสั่ง:
echo     venv\Scripts\python.exe backend\main.py
echo ============================================================
pause
