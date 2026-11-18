"""Cloudflare traffic index: real event time, deterministic ids, tailing with rotation."""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "common"))
spec = importlib.util.spec_from_file_location("cloudflare_traffic_index", ROOT / "cloudflare/traffic_index.py")
TI = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TI)


def http_event(source="graphql-history", ray="r1", when="2026-11-17T17:22:05Z"):
    return {"b89": {"vendor": "cloudflare", "source": source, "event_type": "http", "sampled": True,
                    "collected_at": "2026-11-18T16:00:00Z"},
            "cloudflare": {"dataset": "http_requests", "scope_id": "z1", "zone_name": "b89.io",
                           "http": {"datetime": when, "client_ip": "106.51.247.10", "country": "IN", "asn": "24309",
                                    "host": "prodv2-apipayments.b89.io", "method": "GET",
                                    "path": "/backoffice/v2/balances/export", "status": "200", "ray": ray},
                           "raw": {"ClientASNDescription": "Atria", "ClientRequestQuery": "?x=1"}}}


class FakeIndexer:
    def __init__(self):
        self.docs = {}

    def bulk(self, payload):
        lines = payload.decode().splitlines()
        items = []
        for meta, doc in zip(lines[::2], lines[1::2]):
            m = json.loads(meta)["index"]
            self.docs[(m["_index"], m["_id"])] = json.loads(doc)
            items.append({"index": {"status": 201}})
        return {"items": items}


class IndexTests(unittest.TestCase):
    def test_http_document_keeps_event_time_and_fields(self):
        index, doc_id, doc = TI.to_document(http_event())
        self.assertEqual(index, "b89-cloudflare-traffic-2026.11.17")
        self.assertEqual(doc["@timestamp"], "2026-11-17T17:22:05.000000Z")
        self.assertEqual(doc["http"]["status"], 200)
        self.assertEqual(doc["client"], {"ip": "106.51.247.10", "country": "IN", "asn": 24309, "asn_name": "Atria"})
        self.assertEqual(doc["event"], {"dataset": "http", "source": "graphql-history", "sampled": True,
                                        "history": True})
        self.assertEqual(doc["zone"], {"name": "b89.io", "id": "z1"})

    def test_same_request_from_graphql_and_logpush_has_same_id(self):
        a = TI.to_document(http_event("graphql-live"))
        b = TI.to_document(http_event("logpush"))
        self.assertEqual(a[1], b[1])

    def test_logpush_epoch_timestamp_and_backfill_audit_and_heartbeat(self):
        event = http_event("logpush", when="1763400125000000000")
        self.assertTrue(TI.to_document(event)[2]["@timestamp"].startswith("2025-11-17"))
        audit = {"b89": {"vendor": "cloudflare", "source": "audit_logs", "event_type": "audit", "history": True,
                         "collected_at": "2026-11-18T16:00:00Z"},
                 "cloudflare": {"account_id": "a", "audit": {"id": "x1", "when": "2026-06-01T10:00:00Z",
                                                             "action": "delete", "actor_email": "a@b.c",
                                                             "actor_ip": "192.0.2.1"}}}
        index, _, doc = TI.to_document(audit)
        self.assertEqual(index, "b89-cloudflare-traffic-2026.06.01")
        self.assertEqual(doc["event"]["source"], "backfill")
        self.assertEqual(doc["client"]["ip"], "192.0.2.1")
        self.assertIsNone(TI.to_document({"b89": {"vendor": "cloudflare", "event_type": "heartbeat"}}))

    def test_tail_resumes_and_follows_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cloudflare-traffic.jsonl"
            path.write_text(json.dumps(http_event(ray="a")) + "\n" + json.dumps(http_event(ray="b")) + "\n")
            state, fake = {}, FakeIndexer()
            stats = TI.process_file(path, state, fake, 100, lambda s: None)
            self.assertEqual(stats["indexed"], 2)
            with path.open("a") as fh:
                fh.write(json.dumps(http_event(ray="c")) + "\n" + '{"partial":')
            self.assertEqual(TI.process_file(path, state, fake, 100, lambda s: None)["indexed"], 1)
            os.replace(path, path.with_name(path.name + ".1"))
            with path.with_name(path.name + ".1").open("a") as fh:
                fh.write(' 1}\n')
            path.write_text(json.dumps(http_event(ray="d")) + "\n")
            stats = TI.process_file(path, state, fake, 100, lambda s: None)
            self.assertEqual(stats["indexed"], 1)
            self.assertEqual(stats["skipped"], 1)
            self.assertEqual(len(fake.docs), 4)


if __name__ == "__main__":
    unittest.main()
