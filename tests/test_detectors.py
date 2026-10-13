import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from detectors import (ArpDetector, AuthDosDetector, DeauthDetector, DnsDetector, Event,  # noqa: E402
                       EvilTwinDetector, ReconDetector, WpaCrackDetector)

AP = "AA:BB:CC:11:22:33"
ATK = "DE:AD:BE:EF:00:01"


def feed_all(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out


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


class TestRecon(unittest.TestCase):
    def test_probe_flood(self):
        ev = [Event("probe_req", i * 0.1, ATK, ssid=f"net{i}") for i in range(60)]
        self.assertEqual(len(feed_all(ReconDetector(), ev)), 1)

    def test_few_probes_ok(self):
        ev = [Event("probe_req", i * 2.0, ATK) for i in range(10)]
        self.assertEqual(feed_all(ReconDetector(), ev), [])


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


class TestArp(unittest.TestCase):
    def test_gateway_spoof_is_critical(self):
        d = ArpDetector(gateway_ip="192.168.1.1")
        out = feed_all(d, [Event("arp", 1, "AA:AA:AA:AA:AA:01", extra={"ip": "192.168.1.1"}),
                           Event("arp", 2, "BB:BB:BB:BB:BB:02", extra={"ip": "192.168.1.1"})])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "Critical")
        self.assertEqual(out[0].src_mac, "BB:BB:BB:BB:BB:02")

    def test_pinned_gateway_mac_flags_immediately(self):
        d = ArpDetector("192.168.1.1", "AA:AA:AA:AA:AA:01")
        out = d.feed(Event("arp", 1, "BB:BB:BB:BB:BB:02", extra={"ip": "192.168.1.1"}))
        self.assertEqual(out[0].severity, "Critical")

    def test_normal_arp_ok(self):
        d = ArpDetector("192.168.1.1")
        ev = [Event("arp", i, "AA:AA:AA:AA:AA:01", extra={"ip": "192.168.1.1"}) for i in range(5)]
        self.assertEqual(feed_all(d, ev), [])

    def test_non_gateway_conflict_is_suspicious(self):
        d = ArpDetector("192.168.1.1")
        out = feed_all(d, [Event("arp", 1, "AA:AA:AA:AA:AA:01", extra={"ip": "192.168.1.50"}),
                           Event("arp", 2, "BB:BB:BB:BB:BB:02", extra={"ip": "192.168.1.50"})])
        self.assertEqual(out[0].severity, "Suspicious")


class TestDns(unittest.TestCase):
    def test_expected_mismatch(self):
        d = DnsDetector(expected={"login.campus.edu": ["10.0.0.5"]})
        out = d.feed(Event("dns", 1, "192.168.1.1", extra={"qname": "login.campus.edu.", "answers": ["192.168.1.99"]}))
        self.assertEqual(out[0].severity, "Critical")
        self.assertEqual(out[0].attack_type, "Captive Portal Phishing")

    def test_rogue_resolver(self):
        d = DnsDetector(trusted_resolvers=["192.168.1.1"])
        out = d.feed(Event("dns", 1, "192.168.1.66", extra={"qname": "a.com", "answers": ["1.2.3.4"]}))
        self.assertEqual(out[0].severity, "Critical")

    def test_public_domain_to_private_ip_suspicious(self):
        out = DnsDetector().feed(Event("dns", 1, "192.168.1.1", extra={"qname": "google.com", "answers": ["192.168.1.99"]}))
        self.assertEqual(out[0].severity, "Suspicious")

    def test_local_domain_ok_and_public_ip_ok(self):
        d = DnsDetector()
        self.assertEqual(d.feed(Event("dns", 1, "x", extra={"qname": "printer.lan", "answers": ["192.168.1.9"]})), [])
        self.assertEqual(d.feed(Event("dns", 2, "x", extra={"qname": "google.com", "answers": ["142.250.1.1"]})), [])


if __name__ == "__main__":
    unittest.main()
