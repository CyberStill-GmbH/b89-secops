"""Logpush job reconciliation: create, keep, update, never touch foreign jobs, no permission."""
import importlib.util
import pathlib
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloudflare_provision", ROOT / "cloudflare/provision_logpush.py")
PV = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PV)

ENDPOINT = "https://soc.example.test/hooks/cloudflare-logpush"
SECRET = "s" * 48


class FakeClient:
    def __init__(self, jobs=None, deny=False):
        self.jobs = jobs or {}
        self.deny = deny
        self.calls = []

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path.startswith("/zones?"):
            return [{"id": "z1", "name": "example.test"}]
        if self.deny and "/logpush/jobs" in path:
            raise PV.NoPermission("HTTP 403")
        if path.endswith("/logpush/jobs") and method == "GET":
            return list(self.jobs.values())
        if "/fields" in path:
            return {"ClientIP": "", "EdgeResponseStatus": "", "QueryName": "", "NotWanted": ""}
        return {}


class ProvisionTests(unittest.TestCase):
    def test_creates_one_job_per_dataset_with_header_secret_and_plan_fields(self):
        client = FakeClient()
        report = PV.reconcile(client, ENDPOINT, SECRET)
        self.assertEqual([r["action"] for r in report], ["create", "create"])
        posts = [c for c in client.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 2)
        body = posts[0][2]
        self.assertEqual(body["name"], "b89-http-requests")
        self.assertEqual(body["output_options"]["field_names"], ["ClientIP", "EdgeResponseStatus"])
        url = urllib.parse.urlsplit(body["destination_conf"])
        self.assertEqual(url.path, "/hooks/cloudflare-logpush/http_requests/z1")
        self.assertEqual(urllib.parse.parse_qs(url.query), {"header_X-B89-Logpush-Token": [SECRET]})
        self.assertNotIn(SECRET, repr(report))

    def test_existing_identical_job_is_left_alone_and_drift_is_updated(self):
        dest = PV.destination(ENDPOINT, "http_requests", "z1", SECRET)
        jobs = {
            "b89-http-requests": {"id": 7, "name": "b89-http-requests", "destination_conf": dest, "enabled": True,
                                  "output_options": {"field_names": ["ClientIP", "EdgeResponseStatus"]}},
            "b89-dns-logs": {"id": 8, "name": "b89-dns-logs", "destination_conf": "https://old", "enabled": True},
            "someone-else": {"id": 9, "name": "someone-else"},
        }
        client = FakeClient(jobs)
        report = PV.reconcile(client, ENDPOINT, SECRET)
        self.assertEqual([r["action"] for r in report], ["ok", "update"])
        writes = [c for c in client.calls if c[0] in ("POST", "PUT", "DELETE")]
        self.assertEqual([(m, p) for m, p, _ in writes], [("PUT", "/zones/z1/logpush/jobs/8")])

    def test_dry_run_never_writes(self):
        client = FakeClient()
        PV.reconcile(client, ENDPOINT, SECRET, dry_run=True)
        self.assertFalse([c for c in client.calls if c[0] != "GET"])

    def test_missing_permission_is_reported_as_such(self):
        with self.assertRaises(PV.NoPermission):
            PV.reconcile(FakeClient(deny=True), ENDPOINT, SECRET)


if __name__ == "__main__":
    unittest.main()
