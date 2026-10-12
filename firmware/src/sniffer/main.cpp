/*
 * ESP32 Layer-2 sensor: ดักเฟรม 802.11 (promiscuous) แล้วส่งเป็น event เข้า /api/ingest
 * ตรวจ: deauth/disassoc, beacon (Evil Twin), probe_req, auth, eapol
 *
 * ข้อจำกัด: ESP32 เชื่อมต่อ Wi-Fi เพื่อส่งข้อมูล จึงฟังได้เฉพาะ "ช่องเดียวกับ AP ที่เชื่อมต่ออยู่"
 * (วางให้ตรงกับช่องของ AP ที่ต้องเฝ้า) ดู docs/SENSOR_PROTOCOL.md
 * ยังไม่เคยคอมไพล์/ทดสอบกับบอร์ดจริง
 */
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include "esp_wifi.h"
#include "config.h"

enum Kind : uint8_t { K_DEAUTH, K_BEACON, K_PROBE, K_AUTH, K_EAPOL };
static const char* KIND_NAME[] = {"deauth", "beacon", "probe_req", "auth", "eapol"};

struct Ev {
  uint8_t kind;
  uint8_t src[6], dst[6], bssid[6];
  uint8_t ch;
  int8_t rssi;
  char ssid[33];
};

static QueueHandle_t evQueue;

// Beacon ถี่มาก (~10/วินาที/AP) ส่งต่อ BSSID ไม่เกินทุก 5 วินาทีก็พอสำหรับตรวจ Evil Twin
struct BeaconSeen { uint8_t bssid[6]; uint32_t t; };
static BeaconSeen beaconSeen[24];
static uint8_t beaconNext = 0;

static bool beaconDue(const uint8_t* b) {
  uint32_t now = millis();
  for (auto& s : beaconSeen) {
    if (memcmp(s.bssid, b, 6) == 0) {
      if (now - s.t < 5000) return false;
      s.t = now;
      return true;
    }
  }
  memcpy(beaconSeen[beaconNext].bssid, b, 6);
  beaconSeen[beaconNext].t = now;
  beaconNext = (beaconNext + 1) % 24;
  return true;
}

static void parseTags(const uint8_t* d, int len, int off, Ev& e) {
  while (off + 2 <= len) {
    uint8_t id = d[off], l = d[off + 1];
    if (off + 2 + l > len) break;
    if (id == 0) {                       // SSID
      int n = l > 32 ? 32 : l;
      memcpy(e.ssid, d + off + 2, n);
      e.ssid[n] = 0;
    } else if (id == 3 && l == 1) {      // DS Parameter Set = channel
      e.ch = d[off + 2];
    }
    off += 2 + l;
  }
}

// callback ทำงานใน WiFi task: ต้องเร็ว ไม่ block จึงส่งเข้า queue แล้วให้ loop() ส่ง HTTP
static void onPacket(void* buf, wifi_promiscuous_pkt_type_t type) {
  auto* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* d = p->payload;
  int len = p->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t fc0 = d[0], fc1 = d[1];
  uint8_t ftype = (fc0 >> 2) & 3, sub = (fc0 >> 4) & 0xF;

  Ev e;
  memset(&e, 0, sizeof(e));
  e.rssi = p->rx_ctrl.rssi;
  e.ch = p->rx_ctrl.channel;
  memcpy(e.dst, d + 4, 6);
  memcpy(e.src, d + 10, 6);
  memcpy(e.bssid, d + 16, 6);

  if (type == WIFI_PKT_MGMT) {
    switch (sub) {
      case 0xC: case 0xA: e.kind = K_DEAUTH; break;        // deauth / disassoc
      case 0x8:                                            // beacon
        if (len < 38) return;
        e.kind = K_BEACON;
        parseTags(d, len, 36, e);
        if (!beaconDue(e.bssid)) return;
        break;
      case 0x4:                                            // probe request
        e.kind = K_PROBE;
        parseTags(d, len, 24, e);
        break;
      case 0xB: e.kind = K_AUTH; break;
      default: return;
    }
  } else if (type == WIFI_PKT_DATA && ftype == 2) {
    int off = 24;
    if (sub & 0x8) off += 2;                    // QoS control
    if ((fc1 & 0x03) == 0x03) off += 6;         // WDS 4-address
    if (len < off + 8) return;
    static const uint8_t eapolLlc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    if (memcmp(d + off, eapolLlc, 8) != 0) return;
    e.kind = K_EAPOL;
    // ToDS: addr1=BSSID | FromDS: addr2=BSSID
    memcpy(e.bssid, (fc1 & 0x01) ? d + 4 : d + 10, 6);
  } else {
    return;
  }
  xQueueSend(evQueue, &e, 0);   // เต็มก็ทิ้ง (flood เกินรับไหว)
}

static void macStr(const uint8_t* m, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// SSID อาจมีไบต์แปลก ๆ ทำให้ JSON พัง -> เหลือเฉพาะ ASCII ที่พิมพ์ได้
static void appendEvent(String& out, const Ev& e) {
  char s[18], dst[18], b[18];
  macStr(e.src, s); macStr(e.dst, dst); macStr(e.bssid, b);
  out += "{\"kind\":\""; out += KIND_NAME[e.kind];
  out += "\",\"src\":\""; out += s;
  out += "\",\"dst\":\""; out += dst;
  out += "\",\"bssid\":\""; out += b;
  out += "\",\"ssid\":\"";
  for (const char* c = e.ssid; *c; c++) {
    if (*c < 0x20 || *c > 0x7E) out += '?';
    else if (*c == '"' || *c == '\\') { out += '\\'; out += *c; }
    else out += *c;
  }
  out += "\",\"channel\":"; out += e.ch;
  out += ",\"rssi\":"; out += (int)e.rssi;
  out += "}";
}

static void connectWifi() {
  esp_wifi_set_promiscuous(false);
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(250);
  if (WiFi.status() == WL_CONNECTED) {
    esp_wifi_set_promiscuous(true);
    Serial.printf("WiFi connected -> sniffing on channel %d\n", WiFi.channel());
  } else {
    Serial.println("WiFi connect failed");
  }
}

void setup() {
  Serial.begin(115200);
  evQueue = xQueueCreate(200, sizeof(Ev));
  WiFi.mode(WIFI_STA);

  wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
  };
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&onPacket);
  connectWifi();
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last < 1000) { delay(20); return; }
  last = millis();

  if (WiFi.status() != WL_CONNECTED) { connectWifi(); return; }

  String body = "{\"sensor\":\"" SENSOR_NAME "\",\"events\":[";
  Ev e;
  int n = 0;
  while (n < 100 && xQueueReceive(evQueue, &e, 0) == pdTRUE) {
    if (n++) body += ",";
    appendEvent(body, e);
  }
  if (n == 0) return;
  body += "]}";

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  if (SERVER_TOKEN[0]) http.addHeader("X-Token", SERVER_TOKEN);
  int code = http.POST(body);
  Serial.printf("sent %d events -> HTTP %d\n", n, code);
  http.end();
}
