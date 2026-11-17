"""Regression coverage for safe Graph continuation and durable audit checkpoints."""
import unittest
from datetime import timedelta
from unittest.mock import patch

from test_sharepoint_collector import MG, SP, NOW, FakeGraph, FakeTokens, record


class RecoveryTests(unittest.TestCase):
    def test_foreign_continuation_never_receives_token(self):
        graph = MG.Graph(FakeTokens([]))
        with patch.object(MG, "http_json") as request:
            for url in ("https://evil.example/next", "//evil.example/next", "http://graph.microsoft.com/next"):
                with self.assertRaises(MG.ProviderError):
                    graph.get(url)
            request.assert_not_called()

    def test_get_refreshes_rejected_token_once(self):
        cache = MG.TokenCache(MG.Credentials("t", "c", "s"))
        with patch.object(cache, "_request", side_effect=[("old", 3600), ("new", 3600)]), \
             patch.object(MG, "http_json", side_effect=[(401, {}), (200, {"value": []})]) as request:
            self.assertEqual(MG.Graph(cache).get("/v1.0/sites"), {"value": []})
            self.assertEqual([c.args[2]["Authorization"] for c in request.call_args_list], ["Bearer old", "Bearer new"])

    def test_collection_budget_and_malformed_page_fail_visibly(self):
        graph = FakeGraph(FakeTokens([]), {("GET", "/sites"): (200, {"value": [], "@odata.nextLink": "/next"})})
        with self.assertRaisesRegex(SP.ProviderError, "budget"):
            list(graph.pages("/sites", max_pages=1))
        graph = FakeGraph(FakeTokens([]), {("GET", "/sites"): (200, {})})
        with self.assertRaisesRegex(SP.ProviderError, "invalid"):
            list(graph.pages("/sites"))

    def test_old_checkpoint_is_not_silently_skipped(self):
        state = {"cursor": SP.iso(NOW - timedelta(days=8))}
        graph = FakeGraph(FakeTokens(["AuditLogsQuery.Read.All"]), {})
        with self.assertRaisesRegex(SP.ProviderError, "retention"):
            SP.collect_audit({}, state, graph, NOW)
        self.assertEqual(state["cursor"], SP.iso(NOW - timedelta(days=8)))
        self.assertEqual(graph.calls, [])

    def test_empty_page_loop_does_not_advance_checkpoint(self):
        query = {"id": "q", "start": SP.iso(NOW-timedelta(hours=2)), "end": SP.iso(NOW), "created": SP.iso(NOW)}
        state = {"query": query}
        graph = FakeGraph(FakeTokens(["AuditLogsQuery.Read.All"]), {
            ("GET", "/records"): (200, {"value": [], "@odata.nextLink": "/v1.0/records"}),
            ("GET", "/queries/q"): (200, {"status": "succeeded"}),
        })
        with self.assertRaisesRegex(SP.ProviderError, "repeated"):
            SP.collect_audit({}, state, graph, NOW)
        self.assertNotIn("cursor", state)
        self.assertEqual(state["query"], query)

    def test_malformed_audit_record_does_not_advance_checkpoint(self):
        state = {"query": {"id": "q", "start": SP.iso(NOW), "end": SP.iso(NOW), "created": SP.iso(NOW)}}
        graph = FakeGraph(FakeTokens(["AuditLogsQuery.Read.All"]), {
            ("GET", "/records"): (200, {"value": [record(1), {}]}),
            ("GET", "/queries/q"): (200, {"status": "succeeded"}),
        })
        with self.assertRaisesRegex(SP.ProviderError, "identity"):
            SP.collect_audit({}, state, graph, NOW)
        self.assertNotIn("cursor", state)


if __name__ == "__main__":
    unittest.main()
