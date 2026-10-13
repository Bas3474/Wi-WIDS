import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from detectors import (AuthDosDetector, BeaconFloodDetector, DeauthDetector, Event,  # noqa: E402
                       EvilTwinDetector, ReconDetector, WpaCrackDetector)

AP = "AA:BB:CC:11:22:33"
ATK = "DE:AD:BE:EF:00:01"


def feed_all(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out


class TestBeaconFlood(unittest.TestCase):
    def test_beacon_flood_multi_ap_detected(self):
        # มี 30 AP ปลอมต่าง BSSID ปรากฏขึ้นมาบนช่อง 6 ในเวลาสั้นๆ
        ev = [Event("beacon", i * 0.1, f"00:11:22:33:44:{i:02X}", bssid=f"00:11:22:33:44:{i:02X}", ssid=f"Fake_{i}", channel=6)
              for i in range(30)]
        out = feed_all(BeaconFloodDetector(threshold=25), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Beacon Flood / AP Anomaly")
        self.assertEqual(out[0].severity, "Critical")
        self.assertIn("Beacon Flood", out[0].impact)

    def test_normal_ap_beacons_ignored(self):
        # มี AP ปกติ 5 ตัวในสิ่งแวดล้อม ส่ง beacon ต่อเนื่อง ไม่ควรแจ้งเตือน
        ev = []
        for i in range(20):
            for ap_idx in range(5):
                b = f"AA:BB:CC:DD:EE:{ap_idx:02X}"
                ev.append(Event("beacon", i * 0.2, b, bssid=b, ssid=f"Net_{ap_idx}", channel=6))
        out = feed_all(BeaconFloodDetector(threshold=25, single_ap_threshold=75), ev)
        self.assertEqual(out, [])

    def test_single_ap_beacon_anomaly_detected(self):
        # AP ตัวเดียวส่ง beacon รัวเกินมาตรฐานอย่างรุนแรง (80 เฟรม ใน 4 วินาที)
        ev = [Event("beacon", i * 0.05, AP, bssid=AP, ssid="SpamAP", channel=6) for i in range(80)]
        out = feed_all(BeaconFloodDetector(threshold=25, single_ap_threshold=75), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Beacon Flood / AP Anomaly")
        self.assertEqual(out[0].severity, "Suspicious")
        self.assertIn("AP Beacon Anomaly", out[0].impact)

    def test_cooldown_prevents_flood_spam(self):
        # เมื่อเกิด Beacon Flood ต่อเนื่อง Cooldown ต้องป้องกันการแจ้งเตือนรัว
        ev = [Event("beacon", i * 0.05, f"00:11:22:33:44:{i:02X}", bssid=f"00:11:22:33:44:{i:02X}", ssid=f"Fake_{i}", channel=6)
              for i in range(60)]
        out = feed_all(BeaconFloodDetector(threshold=25), ev)
        self.assertEqual(len(out), 1)


class TestAuthDos(unittest.TestCase):
    def test_auth_flood_detected(self):
        # ยิง Auth request ถี่ผิดปกติ 30 เฟรมในเวลาสั้น ๆ
        ev = [Event("auth", i * 0.1, ATK, AP, AP, channel=6) for i in range(30)]
        out = feed_all(AuthDosDetector(threshold=15), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Auth DoS Attack")
        self.assertEqual(out[0].severity, "Critical")

    def test_normal_rate_ignored(self):
        # อัตราปกติ: มี client ต่อ Wi-Fi ห่าง ๆ กัน ไม่ควรแจ้งเตือน
        ev = [Event("auth", i * 2.0, ATK, AP, AP, channel=6) for i in range(10)]
        out = feed_all(AuthDosDetector(threshold=15), ev)
        self.assertEqual(out, [])

    def test_randomized_src_mac_flood_detected(self):
        # จำลอง mdk3/mdk4 auth flood: ผู้โจมตีสุ่ม MAC ทุกแพ็กเก็ต
        ev = [Event("auth", i * 0.05, f"00:11:22:33:44:{i:02X}", AP, AP, channel=6) for i in range(25)]
        out = feed_all(AuthDosDetector(threshold=15), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Auth DoS Attack")
        self.assertIn("MAC ปลอมแปลง", out[0].impact)

    def test_other_kind_ignored(self):
        # เฟรมที่ไม่ใช่ auth ไม่ควรถูกตรวจจับ
        ev = [Event("beacon", i * 0.1, ATK, AP, AP, channel=6) for i in range(30)]
        out = feed_all(AuthDosDetector(threshold=15), ev)
        self.assertEqual(out, [])

    def test_normal_multiple_clients_retrying_ignored(self):
        # อุปกรณ์ปกติ 3 เครื่องต่อ Wi-Fi หรือ retry ซ้ำๆ ในหอพัก (รวม 27 เฟรม) ต้องไม่แจ้งเตือนมั่ว
        d = AuthDosDetector(threshold=35, min_sources=5, single_source_threshold=50)
        clients = ["11:22:33:44:55:01", "11:22:33:44:55:02", "11:22:33:44:55:03"]
        ev = []
        for i in range(9):
            for c in clients:
                ev.append(Event("auth", len(ev) * 0.1, c, AP, AP, channel=6))
        out = feed_all(d, ev)
        self.assertEqual(out, [])

    def test_cooldown_prevents_auth_dos_spam(self):
        # เมื่อเกิดการโจมตีอย่างต่อเนื่อง คูลดาวน์ 45 วิ ต้องไม่ทำให้แจ้งเตือนรัว
        d = AuthDosDetector(threshold=35, min_sources=5, cooldown=45.0)
        # ชุดที่ 1: วิที่ 0 ถึง 2 (ยิง 40 เฟรมจาก 40 MACs) -> ตรวจพบ 1 ครั้ง
        ev1 = [Event("auth", i * 0.05, f"00:11:22:33:44:{i:02X}", AP, AP, channel=6) for i in range(40)]
        out1 = feed_all(d, ev1)
        self.assertEqual(len(out1), 1)

        # ชุดที่ 2: วิที่ 10 ถึง 12 (ยิงอีก 40 เฟรมในคูลดาวน์) -> ต้องไม่แจ้งเตือนซ้ำ
        ev2 = [Event("auth", 10.0 + i * 0.05, f"00:11:22:33:55:{i:02X}", AP, AP, channel=6) for i in range(40)]
        out2 = feed_all(d, ev2)
        self.assertEqual(out2, [])

        # ชุดที่ 3: วิที่ 50 (พ้นคูลดาวน์ 45 วิแล้ว) -> ตรวจพบอีก 1 ครั้ง
        ev3 = [Event("auth", 50.0 + i * 0.05, f"00:11:22:33:66:{i:02X}", AP, AP, channel=6) for i in range(40)]
        out3 = feed_all(d, ev3)
        self.assertEqual(len(out3), 1)


class TestDeauth(unittest.TestCase):
    def test_flood_detected_once(self):
        ev = [Event("deauth", i * 0.05, ATK, "FF:FF:FF:FF:FF:FF", AP, channel=6) for i in range(60)]
        out = feed_all(DeauthDetector(), ev)
        self.assertEqual(len(out), 1)  # cooldown กันแจ้งซ้ำ
        self.assertEqual(out[0].attack_type, "Deauth Attack")
        self.assertEqual(out[0].severity, "Critical")

    def test_normal_rate_ignored(self):
        ev = [Event("deauth", i * 2.0, ATK, "11:22:33:44:55:66", AP) for i in range(30)]
        self.assertEqual(feed_all(DeauthDetector(), ev), [])

    def test_two_way_spoofing_detected(self):
        # จำลองการโจมตีแบบ aireplay-ng: 5 เฟรม AP->Client และ 5 เฟรม Client->AP รวมเป็น 10 เฟรม
        ev = [Event("deauth", i * 0.1, AP, "11:22:33:44:55:66", AP) for i in range(5)]
        ev += [Event("deauth", 0.5 + i * 0.1, "11:22:33:44:55:66", AP, AP) for i in range(5)]
        out = feed_all(DeauthDetector(threshold=10), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Deauth Attack")

    def test_randomized_src_mac_detected(self):
        # ผู้โจมตีสุ่ม MAC ทุกแพ็กเก็ต แต่ยิงเข้า BSSID เดียวกัน
        ev = [Event("deauth", i * 0.1, f"00:11:22:33:44:{i:02X}", "FF:FF:FF:FF:FF:FF", AP) for i in range(12)]
        out = feed_all(DeauthDetector(threshold=10), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Deauth Attack")


class TestEvilTwin(unittest.TestCase):
    prof = [{"ssid": "Campus", "bssids": [AP], "channels": [6]}]

    def setUp(self):
        BeaconFloodDetector.active_floods.clear()

    def test_legit_ap_ok(self):
        self.assertEqual(EvilTwinDetector(self.prof).feed(Event("beacon", 1, AP, bssid=AP, ssid="Campus", channel=6)), [])

    def test_rogue_bssid(self):
        out = EvilTwinDetector(self.prof).feed(Event("beacon", 1, "66:66:66:66:66:66", bssid="66:66:66:66:66:66", ssid="Campus", channel=6))
        self.assertEqual(out[0].attack_type, "Evil Twin")

    def test_wrong_channel(self):
        out = EvilTwinDetector(self.prof).feed(Event("beacon", 1, AP, bssid=AP, ssid="Campus", channel=11))
        self.assertEqual(len(out), 1)

    def test_other_ssid_ignored(self):
        self.assertEqual(EvilTwinDetector(self.prof).feed(Event("beacon", 1, "1:2", bssid="1:2", ssid="Other", channel=1)), [])

    def test_dynamic_rogue_bssid_without_profile(self):
        # ตรวจพบ AP ปลอมอัตโนมัติแม้ไม่ได้ตั้ง profile ล่วงหน้า
        d = EvilTwinDetector([])
        self.assertEqual(d.feed(Event("beacon", 1, AP, bssid=AP, ssid="MyHome")), [])
        out = d.feed(Event("beacon", 2, "EE:EE:EE:EE:EE:EE", bssid="EE:EE:EE:EE:EE:EE", ssid="MyHome"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Evil Twin")

    def test_airgeddon_evil_twin_with_deauth_correlated(self):
        # จำลอง airgeddon: ปล่อย Rogue AP พร้อมกับยิง Deauth ตัดสัญญาณ AP จริง
        d = EvilTwinDetector([])
        d.feed(Event("beacon", 1, AP, bssid=AP, ssid="VictimAP"))
        d.feed(Event("deauth", 2, "XX:XX:XX:XX:XX:XX", bssid=AP))
        out = d.feed(Event("beacon", 3, "66:66:66:66:66:66", bssid="66:66:66:66:66:66", ssid="VictimAP"))
        self.assertEqual(len(out), 1)
        self.assertIn("airgeddon", out[0].impact)

    def test_rogue_bssid_without_deauth_detected(self):
        # BSSID แปลกปลอมปล่อย SSID เดียวกัน ตรวจจับ Evil Twin ทันทีแม้ไม่ได้ยิง Deauth
        prof = [{"ssid": "MySecureNet", "bssids": ["BE:27:7A:00:11:22"], "channels": [6]}]
        d = EvilTwinDetector(prof)
        out = d.feed(Event("beacon", 1, "00:C0:CA:99:99:99", bssid="00:C0:CA:99:99:99", ssid="MySecureNet", channel=6))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Evil Twin")
        self.assertEqual(out[0].severity, "Critical")

    def test_dynamic_second_ap_detected_immediately(self):
        # โหมด Dynamic: หากพบ AP ที่สองปล่อย SSID เดียวกัน ตรวจจับเป็น Evil Twin ทันที
        d = EvilTwinDetector([])
        d.feed(Event("beacon", 1, "AA:BB:CC:11:22:33", bssid="AA:BB:CC:11:22:33", ssid="TestNet", channel=6))
        out = d.feed(Event("beacon", 2, "66:66:66:66:66:66", bssid="66:66:66:66:66:66", ssid="TestNet", channel=6))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Evil Twin")
        self.assertEqual(out[0].severity, "Critical")

    def test_dorm_campus_multi_ap_and_channels_allowed(self):
        # เครือข่ายหอพัก/มหาวิทยาลัย: มีหลาย AP ต่าง BSSID และต่าง Channel ที่ถูกระบุอนุญาตไว้
        prof = [{"ssid": "CampusWiFi", "bssids": ["AA:BB:CC:11:22:33", "11:22:33:44:55:66"], "channels": [1], "is_dorm_campus": True}]
        d = EvilTwinDetector(prof)
        out1 = d.feed(Event("beacon", 1, "AA:BB:CC:11:22:33", bssid="AA:BB:CC:11:22:33", ssid="CampusWiFi", channel=1))
        out2 = d.feed(Event("beacon", 2, "11:22:33:44:55:66", bssid="11:22:33:44:55:66", ssid="CampusWiFi", channel=11))
        self.assertEqual(out1, [])
        self.assertEqual(out2, [])

    def test_dorm_campus_unwhitelisted_bssid_flagged(self):
        # เครือข่ายหอพัก/มหาวิทยาลัย: หากมี BSSID แปลกปลอมที่ไม่ได้รับอนุญาต ต้องตรวจจับเป็น Evil Twin
        prof = [{"ssid": "CampusWiFi", "bssids": ["AA:BB:CC:11:22:33"], "channels": [1], "is_dorm_campus": True}]
        d = EvilTwinDetector(prof)
        out = d.feed(Event("beacon", 1, "66:66:66:66:66:66", bssid="66:66:66:66:66:66", ssid="CampusWiFi", channel=6))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Evil Twin")
        self.assertIn("เครือข่ายหอ/มหาลัย", out[0].impact)

    def test_dorm_campus_reload_profiles(self):
        # ทดสอบ hot-reload profile เมื่อผู้ใช้กดอนุญาต BSSID เพิ่มเติม
        prof = [{"ssid": "CampusWiFi", "bssids": ["AA:BB:CC:11:22:33"], "channels": [1], "is_dorm_campus": True}]
        d = EvilTwinDetector(prof)
        out_before = d.feed(Event("beacon", 1, "22:33:44:55:66:77", bssid="22:33:44:55:66:77", ssid="CampusWiFi", channel=6))
        self.assertEqual(len(out_before), 1)
        # ผู้ใช้กดปุ่มระบุว่าเป็น Wi-Fi หอพัก -> reload profiles
        prof[0]["bssids"].append("22:33:44:55:66:77")
        d.reload_profiles(prof)
        out_after = d.feed(Event("beacon", 100, "22:33:44:55:66:77", bssid="22:33:44:55:66:77", ssid="CampusWiFi", channel=6))
        self.assertEqual(out_after, [])

    def test_evil_twin_cooldown_prevents_spam(self):
        # มี AP จริง และ Rogue AP ส่ง Beacon ซ้ำๆ ในรอบ Cooldown ต้องแจ้งเตือนเพียง 1 ครั้ง
        d = EvilTwinDetector([])
        d.feed(Event("beacon", 1.0, AP, bssid=AP, ssid="TestNet", channel=6))
        # Rogue AP ส่ง beacon ซ้ำๆ 10 ครั้ง
        ROGUE = "66:66:66:66:66:66"
        out = []
        for i in range(10):
            out += d.feed(Event("beacon", 3.0 + i * 0.1, ROGUE, bssid=ROGUE, ssid="TestNet", channel=6))
        self.assertEqual(len(out), 1)

    def test_evil_twin_suppressed_during_beacon_flood(self):
        # ขณะเกิด Beacon Flood บนช่องสัญญาณ ต้องระงับการแจ้งเตือน Evil Twin
        BeaconFloodDetector.active_floods[6] = 10.0
        d = EvilTwinDetector([{"ssid": "Target", "bssids": [AP], "channels": [6]}])
        out = d.feed(Event("beacon", 10.5, "EE:EE:EE:EE:EE:EE", bssid="EE:EE:EE:EE:EE:EE", ssid="Target", channel=6))
        self.assertEqual(out, [])
        BeaconFloodDetector.active_floods.clear()


class TestRecon(unittest.TestCase):
    def test_single_mac_probe_scan_detected(self):
        # ตรวจจับการสแกน Probe Request ถี่ผิดปกติจาก MAC เดียว (>= 10 ครั้ง ใน 10 วิ)
        ev = [Event("probe_req", i * 0.5, ATK, ssid=f"Target_{i}", channel=6) for i in range(12)]
        out = feed_all(ReconDetector(threshold=10), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Recon / Probe Flood")
        self.assertEqual(out[0].severity, "Suspicious")

    def test_randomized_mac_probe_surge_detected(self):
        # ตรวจจับคลื่น Probe Scan ที่สุ่ม MAC Address หลากหลายรายการ
        ev = [Event("probe_req", i * 0.2, f"00:C0:CA:11:22:{i:02X}", ssid=f"Scan_{i}", channel=6) for i in range(18)]
        out = feed_all(ReconDetector(threshold=10), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].attack_type, "Recon / Probe Flood")
        self.assertEqual(out[0].severity, "Suspicious")
        self.assertIn("Probe Scan", out[0].impact)

    def test_few_probes_ok(self):
        ev = [Event("probe_req", i * 2.0, ATK) for i in range(5)]
        self.assertEqual(feed_all(ReconDetector(threshold=10), ev), [])


class TestWpa(unittest.TestCase):
    def test_correlated_with_deauth(self):
        ev = [Event("deauth", 0, ATK, bssid=AP)] + [Event("eapol", 1 + i * 0.5, AP, bssid=AP) for i in range(10)]
        out = feed_all(WpaCrackDetector(), ev)
        self.assertEqual(len(out), 1)
        self.assertIn("Deauth", out[0].impact)

    def test_normal_handshakes_not_flagged(self):  # 4 เฟรม = 1 handshake ปกติ
        ev = [Event("eapol", i, AP, bssid=AP) for i in range(4)]
        self.assertEqual(feed_all(WpaCrackDetector(), ev), [])

    def test_eapol_without_deauth_needs_more(self):
        ev = [Event("eapol", i * 0.5, AP, bssid=AP) for i in range(10)]
        self.assertEqual(feed_all(WpaCrackDetector(), ev), [])

    def test_airgeddon_single_handshake_capture(self):
        # จำลอง airgeddon: ยิง Deauth แล้วเหยื่อ 1 รายส่ง 4-Way Handshake (4 เฟรม)
        ev = [Event("deauth", 0, ATK, bssid=AP)] + [Event("eapol", 1 + i * 0.1, AP, bssid=AP) for i in range(4)]
        out = feed_all(WpaCrackDetector(), ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "Critical")


if __name__ == "__main__":
    unittest.main()
