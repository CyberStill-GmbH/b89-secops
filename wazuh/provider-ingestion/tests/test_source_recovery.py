"""Recovery policy tests: checkpoints are durable before the next API batch."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / "common" / "b89_collector.py"
spec = importlib.util.spec_from_file_location("recovery_runtime", PATH)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
NOW = runtime.parse_iso("2026-11-16T12:00:00Z")
CONFIG = {"output_file": "output", "state_file": "state", "catchup_cursor_field": "cursors",
          "catchup_max_batches": 2, "catchup_delay_seconds": 0}


class RecoveryTests(unittest.TestCase):
    def run_batches(self, collect, initial=None):
        with patch.object(runtime, "load_config", return_value=CONFIG), \
             patch.object(runtime, "read_state", return_value=initial or {}), \
             patch.object(runtime, "recover_pending", side_effect=lambda o, p, s: (s, False)), \
             patch.object(runtime, "rotate_if_needed"), \
             patch.object(runtime, "utc_now", return_value=NOW), \
             patch.object(runtime, "commit_batch", return_value=1) as commit:
            return runtime.run_collector("test", pathlib.Path("config"), collect), commit.call_args_list

    def test_catches_up_and_passes_committed_cursor_to_next_batch(self):
        seen = []
        def collect(config, state):
            seen.append(state)
            cursor = "2026-11-16T11:00:00Z" if len(seen) == 1 else runtime.iso(NOW)
            return [{}], {"cursors": {"zone": cursor}}
        code, commits = self.run_batches(collect)
        self.assertEqual(code, 0)
        self.assertEqual(len(commits), 2)
        self.assertEqual(seen[1]["cursors"]["zone"], "2026-11-16T11:00:00Z")
        self.assertEqual(commits[-1].args[4]["recovery"]["status"], "caught_up")

    def test_bounded_batches_leave_backlog_visible(self):
        count = 0
        def collect(config, state):
            nonlocal count
            count += 1
            return [], {"cursors": {"zone": f"2026-11-16T0{count}:00:00Z"}}
        code, commits = self.run_batches(collect)
        self.assertEqual((code, count), (0, 2))
        self.assertEqual(commits[-1].args[4]["recovery"]["status"], "catching_up")

    def test_regression_does_not_commit(self):
        code, commits = self.run_batches(lambda c, s: ([], {"cursors": {"zone": "2026-11-15T00:00:00Z"}}),
                                        {"cursors": {"zone": "2026-11-16T00:00:00Z"}})
        self.assertEqual(code, 1)
        self.assertEqual(commits, [])

    def test_stall_commits_visible_status_then_stops(self):
        code, commits = self.run_batches(lambda c, s: ([], s), {"cursors": {"zone": "2026-11-16T00:00:00Z"}})
        self.assertEqual(code, 1)
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0].args[4]["recovery"]["status"], "stalled")

    def test_provider_failure_preserves_preceding_successful_batch(self):
        def collect(c, s):
            if s:
                raise runtime.ProviderError("unavailable", 503)
            return [{}], {"cursors": {"zone": "2026-11-16T00:00:00Z"}}
        code, commits = self.run_batches(collect)
        self.assertEqual(code, 1)
        self.assertEqual(len(commits), 1)

    def test_missing_stream_is_not_caught_up(self):
        with self.assertRaises(runtime.ProviderError):
            runtime.catchup_status(CONFIG, {"cursors": {"lost": runtime.iso(NOW)}},
                                   {"cursors": {"other": runtime.iso(NOW)}}, NOW)

    def test_non_watermark_collector_is_not_opted_in(self):
        self.assertIsNone(runtime.catchup_status({}, {}, {}, NOW))


if __name__ == "__main__":
    unittest.main()
