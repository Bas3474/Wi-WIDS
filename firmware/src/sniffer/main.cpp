/*
 * ESP32 Layer-2 sensor: ดักเฟรม 802.11 (promiscuous) แล้วส่งเข้า Backend
 * รองรับ 2 โหมด (ตั้งค่าใน config.h):
 *   1. USE_USB_SERIAL = 1 (ค่าเริ่มต้น): ส่งผ่านสาย USB Serial เข้าคอมโดยตรง
 *      - ไม่ต้องต่อ Wi-Fi AP, ไม่หลุดแม้โดนยิง Deauth Flood, และสลับสแกนได้หลายช่อง (Channel Hopping)
 *   2. USE_USB_SERIAL = 0: ต่อ Wi-Fi แล้วส่งผ่าน HTTP POST ไปที่ /api/ingest
 */
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include "esp_wifi.h"
#include "config.h"

#ifndef USE_USB_SERIAL
#define USE_USB_SERIAL 1
#endif
#ifndef HOP_CHANNELS
#define HOP_CHANNELS {1, 6, 11}
#endif
#ifndef HOP_INTERVAL_MS
#define HOP_INTERVAL_MS 350
#endif

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
static const uint8_t hopChannels[] = HOP_CHANNELS;
static const size_t numChannels = sizeof(hopChannels) / sizeof(hopChannels[0]);
static size_t chIndex = 0;

// Beacon ถี่มาก (~10/วินาที/AP) ส่งต่อ BSSID ไม่เกินทุก 3 วินาทีก็พอสำหรับตรวจ Evil Twin + กราฟ
struct BeaconSeen { uint8_t bssid[6]; uint32_t t; };
static BeaconSeen beaconSeen[32];
static uint8_t beaconNext = 0;

static bool beaconDue(const uint8_t* b) {
  uint32_t now = millis();
  for (auto& s : beaconSeen) {
    if (memcmp(s.bssid, b, 6) == 0) {
      if (now - s.t < 3000) return false;
      s.t = now;
      return true;
    }
  }
  memcpy(beaconSeen[beaconNext].bssid, b, 6);
  beaconSeen[beaconNext].t = now;
  beaconNext = (beaconNext + 1) % 32;
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

  if (type == WIFI_PKT_MGMT || ftype == 0) {
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
    memcpy(e.bssid, (fc1 & 0x01) ? d + 4 : d + 10, 6);
  } else {
    return;
  }
  xQueueSend(evQueue, &e, 0);
}

static void macStr(const uint8_t* m, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

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

#if !USE_USB_SERIAL
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
#endif

static char actualSensorName[32] = SENSOR_NAME;

void setup() {
  Serial.begin(115200);
  evQueue = xQueueCreate(250, sizeof(Ev));
  WiFi.mode(WIFI_STA);

  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(actualSensorName, sizeof(actualSensorName), "esp32-%02X%02X", mac[4], mac[5]);

  wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
  };
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&onPacket);

#if USE_USB_SERIAL
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
  if (numChannels > 0) {
    esp_wifi_set_channel(hopChannels[0], WIFI_SECOND_CHAN_NONE);
  }
  Serial.printf("USB Serial Sniffer [%s] started (Promiscuous + Channel Hopping)\n", actualSensorName);
#else
  connectWifi();
#endif
}

void loop() {
  uint32_t now = millis();

#if USE_USB_SERIAL
  // สลับช่องสัญญาณ (Channel Hopping)
  static uint32_t lastHop = 0;
  if (numChannels > 1 && now - lastHop >= HOP_INTERVAL_MS) {
    lastHop = now;
    chIndex = (chIndex + 1) % numChannels;
    esp_wifi_set_channel(hopChannels[chIndex], WIFI_SECOND_CHAN_NONE);
  }
#endif

  // ส่งข้อมูลทุก 500 ms
  static uint32_t lastSend = 0;
  if (now - lastSend < 500) {
    delay(10);
    return;
  }
  lastSend = now;

#if !USE_USB_SERIAL
  if (WiFi.status() != WL_CONNECTED) { connectWifi(); return; }
#endif

  String body = "{\"sensor\":\"";
  body += actualSensorName;
  body += "\",\"events\":[";
  Ev e;
  int n = 0;
  while (n < 100 && xQueueReceive(evQueue, &e, 0) == pdTRUE) {
    if (n++) body += ",";
    appendEvent(body, e);
  }
  if (n == 0) {
#if USE_USB_SERIAL
    // ส่ง Heartbeat ทุก 3 วินาทีเพื่อให้ Backend ทราบว่า ESP32 กำลังดักฟังอยู่
    static uint32_t lastHb = 0;
    if (now - lastHb >= 3000) {
      lastHb = now;
      Serial.printf("WIDS_JSON:{\"sensor\":\"%s\",\"events\":[],\"heartbeat\":true,\"uptime\":%u}\n", actualSensorName, (unsigned int)(now / 1000));
    }
#endif
    return;
  }
  body += "]}";

  // ส่งผ่านสาย USB Serial เสมอ (Backend อ่านบรรทัดที่ขึ้นต้นด้วย WIDS_JSON:)
  Serial.print("WIDS_JSON:");
  Serial.println(body);

#if !USE_USB_SERIAL
  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  if (SERVER_TOKEN[0]) http.addHeader("X-Token", SERVER_TOKEN);
  int code = http.POST(body);
  Serial.printf("sent %d events -> HTTP %d\n", n, code);
  http.end();
#endif
}
