import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from detectors import (ArpDetector, DeauthDetector, DnsDetector, Event,  # noqa: E402
                       EvilTwinDetector, ReconDetector, WpaCrackDetector)

AP = "AA:BB:CC:11:22:33"
ATK = "DE:AD:BE:EF:00:01"


def feed_all(det, events):
    out = []
    for e in events:
        out += det.feed(e)
    return out


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
