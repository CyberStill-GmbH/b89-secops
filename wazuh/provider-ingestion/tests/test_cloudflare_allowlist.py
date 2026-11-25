"""Lista blanca de la API de pagos: veredicto del colector para las reglas 101546-101549 y 102020-102025."""
import gzip
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloudflare_allowlist", ROOT / "cloudflare/allowlist.py")
AL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(AL)

FEED = {
    "revision": 7,
    "entries": [
        {"id": "terrapay", "name": "Terrapay", "status": "with_ip", "ips": ["54.76.150.47"], "markers": ["terrapay"]},
        {"id": "monnet", "name": "Monnet", "status": "with_ip", "ips": ["18.214.182.0/24"], "markers": []},
        {"id": "paypros", "name": "Paypros", "status": "not_required", "ips": [], "markers": ["merchant/paypros"]},
    ],
}


def http(ip, path, method="POST", host="apipayments.b89.io"):
    return {"host": host, "client_ip": ip, "method": method, "path": path, "request_target": path.lower()}


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.allowlist = AL.parse(FEED)

    def test_ip_in_list_is_allowed_also_by_cidr(self):
        self.assertEqual(AL.classify(http("54.76.150.47", "/v1/payouts"), self.allowlist)["allowlist_verdict"], "allowed")
        verdict = AL.classify(http("18.214.182.99", "/v1/payins"), self.allowlist)
        self.assertEqual((verdict["allowlist_verdict"], verdict["allowlist_client"]), ("allowed", "Monnet"))

    def test_client_with_ip_from_another_ip_is_outside(self):
        verdict = AL.classify(http("203.0.113.9", "/v1/terrapay/payouts"), self.allowlist)
        self.assertEqual(verdict["allowlist_verdict"], "outside")
        self.assertEqual(verdict["allowlist_client"], "Terrapay")
        self.assertEqual(verdict["allowlist_sensitive"], "true")

    def test_client_with_ip_using_someone_elses_ip_is_still_outside(self):
        verdict = AL.classify(http("18.214.182.10", "/v1/terrapay/login"), self.allowlist)
        self.assertEqual(verdict["allowlist_verdict"], "outside")

    def test_client_without_ip_never_alerts(self):
        verdict = AL.classify(http("198.51.100.7", "/merchant/paypros/payments"), self.allowlist)
        self.assertEqual((verdict["allowlist_verdict"], verdict["allowlist_client"]), ("client_without_ip", "Paypros"))

    def test_unknown_ip_marks_sensitive_paths(self):
        login = AL.classify(http("198.51.100.7", "/auth/login"), self.allowlist)
        self.assertEqual((login["allowlist_verdict"], login["allowlist_sensitive"]), ("unknown", "true"))
        other = AL.classify(http("198.51.100.7", "/v1/status"), self.allowlist)
        self.assertEqual((other["allowlist_verdict"], other["allowlist_sensitive"]), ("unknown", "false"))

    def test_only_payments_api_and_no_preflight(self):
        self.assertIsNone(AL.classify(http("198.51.100.7", "/auth/login", host="www.b89.io"), self.allowlist))
        self.assertIsNone(AL.classify(http("198.51.100.7", "/auth/login", method="OPTIONS"), self.allowlist))

    def test_without_list_there_is_no_verdict(self):
        self.assertIsNone(AL.classify(http("198.51.100.7", "/auth/login"), None))
        self.assertIsNone(AL.parse({"entries": "x"}))



class NoiseReductionTests(unittest.TestCase):
    """Revisión 2 (2026-11-25): menos falsos positivos sin perder los verdaderos."""

    def setUp(self):
        self.allowlist = AL.parse(FEED)

    def classify(self, ip, path, status="200", deduper=None, **extra):
        request = http(ip, path)
        request.update({"status": status, **extra})
        return AL.classify(request, self.allowlist, AL.DEFAULT_HOSTS, deduper)

    def test_query_string_and_partial_words_are_not_sensitive(self):
        self.assertEqual(self.classify("198.51.100.7", "/v1/status", query="?token=abc",
                                       request_target="/v1/status?token=abc")["allowlist_sensitive"], "false")
        for path in ("/v1/authors", "/v1/sessionless-health", "/v1/chargers", "/v1/catalog"):
            self.assertEqual(self.classify("198.51.100.7", path)["allowlist_sensitive"], "false", path)

    def test_real_login_and_money_paths_stay_sensitive(self):
        for path in ("/auth/login", "/v1/payouts", "/api/v2/sign-in", "/v1/pay-out/batch", "/oauth2/token",
                     "/v1/withdrawals/123", "/auth-service/v1/refresh-token"):
            self.assertEqual(self.classify("198.51.100.7", path)["allowlist_sensitive"], "true", path)

    def test_marker_must_be_a_whole_word(self):
        self.assertEqual(self.classify("203.0.113.9", "/v1/terrapayments/status")["allowlist_verdict"], "unknown")
        self.assertEqual(self.classify("203.0.113.9", "/v1/terrapay/status")["allowlist_verdict"], "outside")
        self.assertEqual(self.classify("203.0.113.9", "/v1/status?client=terrapay")["allowlist_verdict"], "outside")

    def test_effect_comes_from_origin_then_edge_and_security_action(self):
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "200")["allowlist_effect"], "accepted")
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "401")["allowlist_effect"], "rejected")
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "502")["allowlist_effect"], "error")
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "200", origin_status="403")["allowlist_effect"],
                         "rejected")
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "403",
                                       security_action="managed_challenge")["allowlist_effect"], "blocked")
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", "")["allowlist_effect"], "unknown")

    def test_verified_bot_is_not_unknown_but_client_rules_still_win(self):
        bot = self.classify("66.249.66.1", "/login", verified_bot_category="Search Engine Crawler")
        self.assertEqual(bot["allowlist_verdict"], "verified_bot")
        self.assertNotIn("allowlist_first", bot)
        foreign = self.classify("66.249.66.1", "/v1/terrapay/payouts", verified_bot_category="Search Engine Crawler")
        self.assertEqual(foreign["allowlist_verdict"], "outside")

    def test_first_alert_per_client_ip_and_kind_within_window(self):
        dedup = AL.Deduper({}, now=1_000.0, window=3600)
        first = self.classify("198.51.100.7", "/auth/login", deduper=dedup)
        again = self.classify("198.51.100.7", "/v1/payouts", deduper=dedup)
        other_ip = self.classify("198.51.100.8", "/auth/login", deduper=dedup)
        rejected = self.classify("198.51.100.7", "/auth/login", "401", deduper=dedup)
        self.assertEqual([first["allowlist_first"], again["allowlist_first"], other_ip["allowlist_first"],
                          rejected["allowlist_first"]], ["true", "false", "true", "true"])
        later = AL.Deduper(dedup.export(), now=1_000.0 + 3600, window=3600)
        self.assertEqual(self.classify("198.51.100.7", "/auth/login", deduper=later)["allowlist_first"], "true")

    def test_without_deduper_every_request_is_first_and_allowed_has_no_flag(self):
        self.assertEqual(self.classify("198.51.100.7", "/auth/login")["allowlist_first"], "true")
        self.assertNotIn("allowlist_first", self.classify("54.76.150.47", "/v1/payouts"))

    def test_deduper_ignores_corrupt_state_and_caps_size(self):
        self.assertEqual(AL.Deduper("broken", now=10.0).seen, {})
        self.assertEqual(AL.Deduper({"k": "x", 3: 1.0, "ok": 5.0}, now=10.0).seen, {"ok": 5.0})
        with patch.object(AL, "MAX_DEDUP_KEYS", 2):
            big = AL.Deduper({"a": 1.0, "b": 2.0, "c": 3.0}, now=10.0)
            self.assertEqual(big.export(), {"b": 2.0, "c": 3.0})

class CollectorIntegrationTests(unittest.TestCase):
    def test_logpush_adds_the_verdict_from_the_synced_file(self):
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            (base / "allowlist.json").write_text(json.dumps(FEED), encoding="utf-8")
            source = base / "batch"
            record = {"ClientIP": "203.0.113.9", "ClientRequestHost": "apipayments.b89.io", "ClientRequestMethod": "POST",
                      "ClientRequestPath": "/v1/terrapay/payouts", "EdgeResponseStatus": 200}
            source.write_bytes(gzip.compress((json.dumps(record) + "\n").encode()))
            with patch.dict(os.environ, {"B89_CF_ALLOWLIST_FILE": str(base / "allowlist.json")}):
                lp_spec = importlib.util.spec_from_file_location("cloudflare_logpush_al", ROOT / "cloudflare/logpush.py")
                LP = importlib.util.module_from_spec(lp_spec)
                lp_spec.loader.exec_module(LP)
                LP.ingest(source, base / "out.jsonl", base / "state.json", "http_requests", "zone1")
            event = json.loads((base / "out.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(event["cloudflare"]["http"]["allowlist_verdict"], "outside")
            self.assertEqual(event["cloudflare"]["http"]["allowlist_client"], "Terrapay")
            self.assertEqual(event["cloudflare"]["http"]["allowlist_revision"], "7")
            self.assertEqual(event["cloudflare"]["http"]["allowlist_first"], "true")
            self.assertEqual(event["cloudflare"]["http"]["allowlist_effect"], "accepted")
            second = base / "batch2"
            record["RayID"] = "second"
            second.write_bytes(gzip.compress((json.dumps(record) + "\n").encode()))
            with patch.dict(os.environ, {"B89_CF_ALLOWLIST_FILE": str(base / "allowlist.json")}):
                LP.ingest(second, base / "out.jsonl", base / "state.json", "http_requests", "zone1")
            repeat = json.loads((base / "out.jsonl").read_text(encoding="utf-8").splitlines()[1])
            self.assertEqual(repeat["cloudflare"]["http"]["allowlist_first"], "false")
            self.assertIn("allowlist_seen", json.loads((base / "state.json").read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
