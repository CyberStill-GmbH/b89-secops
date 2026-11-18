"""GraphQL traffic collector: 31-day backfill, live edge, window splitting, Logpush-shaped events."""
import importlib.util
import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cloudflare"))
sys.path.insert(0, str(ROOT / "common"))
spec = importlib.util.spec_from_file_location("cloudflare_traffic", ROOT / "cloudflare/traffic.py")
TR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TR)

NOW = datetime(2026, 11, 18, 16, 0, tzinfo=timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeClient:
    """One HTTP row every 30 min, one DNS row every hour; optional dense minute."""

    def __init__(self, dense_at=None):
        self.queries = []
        self.dense_at = dense_at

    def graphql(self, query, variables):
        since = datetime.strptime(variables["since"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        until = datetime.strptime(variables["until"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.queries.append((since, until))
        http = "httpRequestsAdaptive" in query
        rows = []
        if self.dense_at and since <= self.dense_at < until and http:
            rows = [{"datetime": iso(self.dense_at), "clientIP": "192.0.2.9"}] * variables["limit"]
            return {"viewer": {"zones": [{"httpRequestsAdaptive": rows}]}}
        step = timedelta(minutes=30 if http else 60)
        t = since.replace(minute=0, second=0)
        while t < until:
            if t >= since:
                rows.append({"datetime": iso(t), "clientIP": "192.0.2.1", "clientRequestPath": "/a",
                             "clientRequestQuery": "?x=1", "edgeResponseStatus": 200} if http else
                            {"datetime": iso(t), "queryName": "b89.io", "queryType": "A", "responseCode": "NOERROR",
                             "sampleInterval": 1})
            t += step
        return {"viewer": {"zones": [{("httpRequestsAdaptive" if http else "dnsAnalyticsAdaptive"): rows}]}}


def run(config, state, client):
    with patch.object(TR, "utc_now", return_value=NOW), \
         patch.object(TR, "discover", return_value=[{"id": "z1", "name": "example.test"}]):
        return TR.collect(config, state, client)


class TrafficTests(unittest.TestCase):
    def test_first_run_starts_30_days_back_and_is_budgeted(self):
        client = FakeClient()
        events, state = run({"max_rows_per_batch": 100}, {}, client)
        self.assertGreaterEqual(len(events), 100)
        self.assertLess(len(events), 110)
        self.assertEqual(client.queries[0][0], NOW - timedelta(days=30))
        self.assertTrue(state["catching_up"])
        first = events[0]
        self.assertEqual(first["b89"]["source"], "graphql-history")
        self.assertTrue(first["b89"]["sampled"])
        self.assertEqual(first["b89"]["event_type"], "http")
        self.assertEqual(first["cloudflare"]["http"]["uri"], "/a?x=1")
        self.assertEqual(first["cloudflare"]["zone_name"], "example.test")

    def test_resumes_from_cursor_until_live_edge_without_gaps(self):
        client = FakeClient()
        state = {"cursors": {"z1": {"http_requests": iso(NOW - timedelta(hours=3)),
                                    "dns_logs": iso(NOW - timedelta(hours=3))}}}
        events, state = run({"lag_minutes": 5}, state, client)
        edge = iso(NOW - timedelta(minutes=5))
        self.assertEqual(state["cursors"]["z1"], {"http_requests": edge, "dns_logs": edge})
        self.assertFalse(state["catching_up"])
        http = [e for e in events if e["b89"]["event_type"] == "http"]
        self.assertEqual(len(http), 6)  # 3 h, una cada 30 min
        self.assertEqual({e["b89"]["source"] for e in http}, {"graphql-history", "graphql-live"})
        windows = sorted(q for q in client.queries)
        self.assertEqual(windows[0][0], NOW - timedelta(hours=3))

    def test_full_page_is_split_and_full_minute_is_reported(self):
        dense = NOW - timedelta(minutes=30)
        client = FakeClient(dense_at=dense)
        state = {"cursors": {"z1": {"http_requests": iso(NOW - timedelta(hours=1)),
                                    "dns_logs": iso(NOW - timedelta(minutes=5))}}}
        events, state = run({"max_rows_per_batch": 10**6}, state, client)
        self.assertEqual(state["truncated_windows"], 1)
        self.assertTrue(any(until - since <= TR.MIN_WINDOW for since, until in client.queries))

    def test_never_older_than_retention(self):
        client = FakeClient()
        run({"history_days": 90, "max_rows_per_batch": 1}, {}, client)
        self.assertGreaterEqual(client.queries[0][0], NOW - timedelta(days=31))

    def test_until_closes_the_range_when_logpush_takes_over(self):
        client = FakeClient()
        stop = NOW - timedelta(hours=2)
        state = {"cursors": {"z1": {"http_requests": iso(NOW - timedelta(hours=3)),
                                    "dns_logs": iso(NOW - timedelta(hours=3))}}}
        _, state = run({"until": iso(stop)}, state, client)
        self.assertEqual(state["cursors"]["z1"]["http_requests"], iso(stop))
        self.assertTrue(all(until <= stop for _, until in client.queries))

    def test_field_denied_by_plan_is_dropped_and_remembered(self):
        class Denying(FakeClient):
            def graphql(self, query, variables):
                if "coloCode" in query:
                    return None
                return super().graphql(query, variables)
        with patch.object(TR, "graphql", side_effect=lambda c, q, v: (None, ["zone 'z1' does not have access to the field 'colocode' from the path"]) if "coloCode" in q else (c.graphql(q, v), [])):
            events, state = run({}, {"cursors": {"z1": {"http_requests": iso(NOW - timedelta(hours=2)),
                                                        "dns_logs": iso(NOW - timedelta(minutes=5))}}}, Denying())
        self.assertTrue(events)
        self.assertEqual(state["denied_fields"], {"z1": ["colocode"]})

    def test_skip_windows_are_never_requested(self):
        client = FakeClient()
        gap_from, gap_to = NOW - timedelta(hours=3), NOW - timedelta(hours=2)
        state = {"cursors": {"z1": {"http_requests": iso(NOW - timedelta(hours=4)),
                                    "dns_logs": iso(NOW - timedelta(hours=4))}}}
        run({"skip_windows": [[iso(gap_from), iso(gap_to)]]}, state, client)
        self.assertFalse([q for q in client.queries if q[0] < gap_to and q[1] > gap_from])


if __name__ == "__main__":
    unittest.main()
