import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

FILE = pathlib.Path(__file__).resolve().parents[1] / "cloudflare" / "backfill.py"
SPEC = importlib.util.spec_from_file_location("cf_backfill", FILE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = pathlib.Path(self.temp.name) / "recovery.jsonl"
        self.state = pathlib.Path(self.temp.name) / "state.json"
        self.start = MOD.cf.parse_iso("2026-11-16T05:00:00Z")
        self.end = MOD.cf.parse_iso("2026-11-16T06:00:00Z")

    def test_resume_does_not_append_completed_zone_twice(self):
        with patch.object(MOD.cf, "discover", return_value=[{"id": "z1", "name": "test"}]), patch.object(
            MOD.cf, "collect_firewall", return_value=([{"raw": "event"}], self.end, [])
        ) as collect:
            for _ in range(2):
                result = MOD.recover({"audit": False}, self.start, self.end, self.output, self.state, object())
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(len(self.output.read_text().splitlines()), 1)
        self.assertFalse(result["coverage"]["exhaustive"])

    def test_denied_zone_does_not_block_other_zone(self):
        with patch.object(MOD.cf, "discover", return_value=[{"id": "bad"}, {"id": "ok"}]), patch.object(
            MOD.cf, "collect_firewall", side_effect=[MOD.cf.ProviderError("Denied", 403), ([{"ok": True}], self.end, [])]
        ):
            result = MOD.recover({"audit": False}, self.start, self.end, self.output, self.state, object())
        self.assertTrue(result["streams"]["firewall:ok"]["done"])
        self.assertEqual(result["coverage"]["failures"][0]["stream"], "firewall:bad")

    def test_no_progress_is_visible_and_no_event_commit(self):
        with patch.object(MOD.cf, "discover", return_value=[{"id": "z"}]), patch.object(
            MOD.cf, "collect_firewall", return_value=([{"unsafe": True}], self.start, [])
        ):
            result = MOD.recover({"audit": False}, self.start, self.end, self.output, self.state, object())
        self.assertFalse(self.output.exists())
        self.assertFalse(result["coverage"]["requested_streams_finished"])

    def test_live_paths_are_rejected(self):
        with self.assertRaises(MOD.cf.ProviderError):
            MOD.recover({"output_file": str(self.output)}, self.start, self.end, self.output, self.state, object())

    def test_audit_is_limited_to_half_open_requested_interval(self):
        records = [{"cloudflare": {"audit": {"when": stamp}}} for stamp in (
            "2026-11-16T04:59:59Z", "2026-11-16T05:00:00Z", "2026-11-16T06:00:00Z")]
        with patch.object(MOD.cf, "collect_audit", return_value=(records, "unused", [])):
            result = MOD.recover({"firewall": False, "account_ids": ["a"]}, self.start, self.end, self.output, self.state, object())
        self.assertEqual(result["streams"]["audit:a"]["events"], 1)


if __name__ == "__main__":
    unittest.main()
