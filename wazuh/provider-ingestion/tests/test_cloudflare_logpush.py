"""Offline durability and preservation tests for Cloudflare Logpush spool ingestion."""
import gzip
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloudflare_logpush", ROOT / "cloudflare/logpush.py")
LP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LP)


class LogpushTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.source = self.base / "batch"
        self.output = self.base / "out.jsonl"
        self.state = self.base / "state.json"

    def ingest(self, dataset="firewall_events", scope="zone1"):
        return LP.ingest(self.source, self.output, self.state, dataset, scope)

    def test_gzip_preserves_full_record_and_normalizes_firewall(self):
        record = {"Action": "allow", "ClientIP": "192.0.2.1", "ClientRequestPath": "/" + "x" * 1000,
                  "FutureField": {"unknown": [1, True]}}
        self.source.write_bytes(gzip.compress((json.dumps(record) + "\n").encode()))
        self.assertEqual(self.ingest(), 1)
        event = json.loads(self.output.read_text())
        self.assertEqual(event["cloudflare"]["raw"], record)
        self.assertEqual(event["cloudflare"]["firewall"]["action"], "allow")
        self.assertEqual(event["cloudflare"]["firewall"]["path"], record["ClientRequestPath"])
        self.assertEqual(self.ingest(), 0)
        self.assertEqual(len(self.output.read_text().splitlines()), 1)

    def test_unknown_dataset_is_retained_and_scoped(self):
        self.source.write_text('{"future":"data"}\n')
        self.assertEqual(self.ingest("future_dataset"), 1)
        self.assertEqual(self.ingest("future_dataset", "zone2"), 1)
        events = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(events[0]["b89"]["event_type"], "logpush")
        self.assertEqual(events[0]["cloudflare"]["raw"], {"future": "data"})

    def test_invalid_record_never_partially_commits(self):
        for content in [b'{}\ninvalid', b'{}\n[]', b'{}\n{"v":NaN}', b'{}\n\xff', b'{"a":1,"a":2}']:
            with self.subTest(content=content):
                self.source.write_bytes(content)
                with self.assertRaises(LP.ProviderError):
                    self.ingest()
                self.assertFalse(self.output.exists())
                self.assertFalse(self.state.exists())

    def test_gzip_expansion_and_record_limits_preserve_batch(self):
        self.source.write_bytes(gzip.compress(b'"' + b'x' * 1000 + b'"'))
        with patch.object(LP, "MAX_INPUT_BYTES", 100), self.assertRaises(LP.ProviderError):
            self.ingest()
        self.source.write_text('{"long":"' + 'x' * 1000 + '"}')
        with patch.object(LP, "MAX_RECORD_BYTES", 100), self.assertRaises(LP.ProviderError):
            self.ingest()
        self.assertFalse(self.state.exists())
        self.assertTrue(self.source.exists())

    def test_committed_batch_recovers_without_reappend_after_state_failure(self):
        self.source.write_text('{"Action":"block"}\n')
        import b89_collector as common
        original = common.save_state
        calls = 0
        def fail_final(path, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated crash")
            original(path, value)
        with patch.object(common, "save_state", fail_final), self.assertRaises(OSError):
            self.ingest()
        before = self.output.read_bytes()
        self.assertEqual(self.ingest(), 0)
        self.assertEqual(self.output.read_bytes(), before)
        self.assertNotIn("pending", json.loads(self.state.read_text()))

    def test_reusing_state_for_different_output_rejected(self):
        self.source.write_text('{}\n')
        self.ingest()
        with self.assertRaises(LP.ProviderError):
            LP.ingest(self.source, self.base / "other.jsonl", self.state, "firewall_events", "zone1")


if __name__ == "__main__":
    unittest.main()
