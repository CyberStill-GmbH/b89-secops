"""Cloudflare Logpush over HTTP: HTTP/DNS normalization, validation record and spool consumer."""
import gzip
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cloudflare"))
spec = importlib.util.spec_from_file_location("cloudflare_logpush_spool", ROOT / "cloudflare/logpush_spool.py")
SP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SP)
LP = SP.logpush


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.spool = self.base / "spool"
        for sub in ("tmp", "incoming"):
            (self.spool / sub).mkdir(parents=True)
        self.output = self.base / "out" / "cloudflare-logpush.jsonl"
        self.ledger = self.base / "ledger.json"
        self.heartbeat = self.base / "heartbeat.json"
        self.seq = 0

    def drop(self, dataset, scope, records, gz=True, raw=None):
        self.seq += 1
        body = raw if raw is not None else "".join(json.dumps(r) + "\n" for r in records).encode()
        if gz and raw is None:
            body = gzip.compress(body)
        name = f"{1763470000000 + self.seq}-{'a' * 23}{self.seq}.{dataset}.{scope}.ndjson"
        (self.spool / "incoming" / name).write_bytes(body)
        return name

    def drain(self):
        return SP.drain(self.spool, self.output, self.ledger, self.heartbeat)

    def events(self):
        return [json.loads(line) for line in self.output.read_text().splitlines()]

    def test_http_and_dns_are_normalized_and_raw_preserved(self):
        http = {"ClientIP": "192.0.2.7", "ClientRequestHost": "b89.io", "ClientRequestPath": "/.env",
                "ClientRequestMethod": "GET", "EdgeResponseStatus": 404, "RayID": "r1", "Unknown": [1]}
        dns = {"QueryName": "x.b89.io", "QueryType": 252, "ResponseCode": 5, "SourceIP": "198.51.100.9"}
        self.drop("http_requests", "zoneA", [http])
        self.drop("dns_logs", "zoneA", [dns], gz=False)
        summary = self.drain()
        self.assertEqual(summary["run"], {"objects": 2, "events": 2, "failed": 0, "deferred": 0})
        first, second = self.events()
        self.assertEqual(first["b89"]["event_type"], "http")
        self.assertEqual(first["cloudflare"]["http"]["path"], "/.env")
        self.assertEqual(first["cloudflare"]["http"]["status"], "404")
        self.assertEqual(first["cloudflare"]["raw"], http)
        self.assertEqual(second["b89"]["event_type"], "dns")
        self.assertEqual(second["cloudflare"]["dns"]["query_type"], "252")
        self.assertEqual(len(list((self.spool / "done").iterdir())), 2)
        self.assertEqual(json.loads(self.heartbeat.read_text())["datasets"], {"http_requests": 1, "dns_logs": 1})

    def test_cloudflare_validation_object_is_accepted_without_events(self):
        self.drop("http_requests", "zoneA", [LP.VALIDATION_RECORD])
        summary = self.drain()
        self.assertEqual(summary["run"]["objects"], 1)
        self.assertEqual(summary["run"]["events"], 0)
        self.assertFalse(self.output.exists() and self.output.read_text().strip())

    def test_redelivery_is_suppressed_and_invalid_goes_to_failed(self):
        record = {"ClientIP": "192.0.2.1", "EdgeResponseStatus": 200}
        self.drop("http_requests", "zoneA", [record], gz=False)
        self.drop("http_requests", "zoneA", [record], gz=False)  # mismo contenido: reenvío
        self.drop("http_requests", "zoneA", [], raw=b'{"a":1}\nnot-json')
        summary = self.drain()
        self.assertEqual(summary["run"]["events"], 1)
        self.assertEqual(summary["run"]["failed"], 1)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(len(list((self.spool / "failed").iterdir())), 1)
        self.assertEqual(summary["backlog"], 0)

    def test_transient_error_keeps_order_and_object(self):
        self.drop("http_requests", "zoneA", [{"ClientIP": "192.0.2.1"}])
        self.drop("http_requests", "zoneA", [{"ClientIP": "192.0.2.2"}])
        original = LP.ingest
        LP.ingest = lambda *a: (_ for _ in ()).throw(LP.ProviderError("Logpush output writer is busy; retry batch"))
        try:
            summary = self.drain()
        finally:
            LP.ingest = original
        self.assertEqual(summary["run"]["deferred"], 1)
        self.assertEqual(summary["backlog"], 2)
        self.assertIsNone(summary["last_success"])
        self.assertEqual(self.drain()["run"]["events"], 2)

    def test_ledger_is_bounded(self):
        old = LP.MAX_LEDGER
        LP.MAX_LEDGER = 3
        try:
            for i in range(5):
                self.drop("http_requests", "zoneA", [{"ClientIP": f"192.0.2.{i}"}])
            self.drain()
        finally:
            LP.MAX_LEDGER = old
        self.assertEqual(len(json.loads(self.ledger.read_text())["batches"]), 3)

    def test_unexpected_names_are_ignored(self):
        (self.spool / "incoming" / "evil.ndjson").write_text("{}")
        self.assertEqual(self.drain()["run"]["objects"], 0)


if __name__ == "__main__":
    unittest.main()
