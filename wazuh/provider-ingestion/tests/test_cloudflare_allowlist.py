"""Lista blanca de la API de pagos: veredicto del colector para las reglas 101546-101549."""
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


if __name__ == "__main__":
    unittest.main()
