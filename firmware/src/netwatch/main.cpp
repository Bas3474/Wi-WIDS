/*
 * ESP32 Layer-3/DNS sensor: เป็น station ในเครือข่ายแล้ว "ตรวจแบบ active" ทุก CHECK_INTERVAL_MS
 *   1) ถาม ARP หา MAC ของ gateway  -> ส่ง event "arp"  (server เทียบกับ MAC เดิม / gateway_mac ใน config)
 *   2) ถาม DNS โดเมน PROBE_DOMAIN  -> ส่ง event "dns"  (server ตรวจ resolver/IP ผิดปกติ)
 *
 * ทำไมไม่ sniff ARP/DNS ของคนอื่น: ใน WPA2 เฟรมข้อมูลถูกเข้ารหัส ESP32 ถอดรหัสใน promiscuous ไม่ได้
 * จึงตรวจได้เฉพาะ "สิ่งที่ตัว ESP32 เองเห็น" (ถ้าถูก ARP poison/DNS spoof มันก็จะเห็นค่าที่ผิดเหมือนเหยื่อ)
 * ยังไม่เคยคอมไพล์/ทดสอบกับบอร์ดจริง (ส่วน lwIP etharp อาจต้องปรับตามเวอร์ชัน core)
 */
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "config.h"

static bool gatewayMac(uint8_t mac[6]) {
  ip4_addr_t gw;
  gw.addr = (uint32_t)WiFi.gatewayIP();
  struct netif* nif = netif_default;
  if (!nif) return false;
  etharp_request(nif, &gw);     // บังคับให้ถาม ARP ใหม่ แทนที่จะเชื่อค่าใน cache เดิม
  delay(200);
  struct eth_addr* eth = nullptr;
  const ip4_addr_t* ipRet = nullptr;
  if (etharp_find_addr(nif, &gw, &eth, &ipRet) >= 0 && eth) {
    memcpy(mac, eth->addr, 6);
    return true;
  }
  return false;
}

static void connectWifi() {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(250);
  Serial.println(WiFi.status() == WL_CONNECTED ? "WiFi connected" : "WiFi connect failed");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  connectWifi();
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last < CHECK_INTERVAL_MS) { delay(50); return; }
  last = millis();
  if (WiFi.status() != WL_CONNECTED) { connectWifi(); return; }

  String events = "";
  String gwIp = WiFi.gatewayIP().toString();

  uint8_t mac[6];
  if (gatewayMac(mac)) {
    char m[18];
    snprintf(m, sizeof(m), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    events += "{\"kind\":\"arp\",\"src\":\"" + String(m) + "\",\"extra\":{\"ip\":\"" + gwIp + "\",\"op\":2}}";
  }

  IPAddress ans;
  if (WiFi.hostByName(PROBE_DOMAIN, ans)) {   // ใช้ DNS ที่ได้จาก DHCP (ตัวเดียวกับที่เหยื่อใช้)
    if (events.length()) events += ",";
    events += "{\"kind\":\"dns\",\"src\":\"" + WiFi.dnsIP(0).toString() +
              "\",\"extra\":{\"qname\":\"" PROBE_DOMAIN "\",\"answers\":[\"" + ans.toString() + "\"]}}";
  }
  if (!events.length()) return;

  String body = "{\"sensor\":\"" SENSOR_NAME "\",\"events\":[" + events + "]}";
  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  if (SERVER_TOKEN[0]) http.addHeader("X-Token", SERVER_TOKEN);
  int code = http.POST(body);
  Serial.printf("gw=%s dns->%s HTTP %d\n", gwIp.c_str(), ans.toString().c_str(), code);
  http.end();
}
