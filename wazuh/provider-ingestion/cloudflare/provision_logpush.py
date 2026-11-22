#!/usr/bin/env python3
"""Create or reconcile the B89 Cloudflare Logpush jobs (HTTP destination → B89 receiver).

For every zone the token can see, one job per dataset in ``DATASETS`` named ``b89-<dataset>``:
destination ``<endpoint>/<dataset>/<zone_id>`` with the shared secret sent by Cloudflare as the
``X-B89-Logpush-Token`` header. Fields are the intersection of ``WANTED_FIELDS`` with what the
zone's plan offers (``/logpush/datasets/<dataset>/fields``). Idempotent: existing jobs with the
same name are updated in place; foreign jobs are never touched.

Firewall events and account audit logs keep coming from the API collector (security.py), so they
are not duplicated here. Requires the token permission «Logs: Write» (zone scope).
Exit codes: 0 all jobs in place; 2 token without Logpush permission; 1 other failure.
Never prints the token, the shared secret or the destination string.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
from b89_collector import ProviderError, http_json, load_config, read_secret  # noqa: E402

API = "https://api.cloudflare.com/client/v4"
HEADER = "X-B89-Logpush-Token"
DATASETS = ("http_requests", "firewall_events", "dns_logs")
WANTED_FIELDS = {
    "http_requests": [
        "EdgeStartTimestamp", "RayID", "ClientIP", "ClientCountry", "ClientASN", "ClientRequestHost",
        "ClientRequestMethod", "ClientRequestPath", "ClientRequestURI", "ClientRequestProtocol",
        "ClientRequestUserAgent", "ClientRequestReferer", "ClientSSLProtocol", "EdgeResponseStatus",
        "OriginResponseStatus", "EdgeResponseBytes", "CacheCacheStatus", "SecurityAction",
        "SecuritySource", "BotScore", "WAFAttackScore",
        "WAFSQLiAttackScore", "WAFXSSAttackScore", "WAFRCEAttackScore",
        "WAFRequestSignatureCategories", "WAFRequestSignatureRefs",
        "SecurityRuleID", "SecurityRuleDescription",
    ],
    "firewall_events": [
        "Action", "Source", "Datetime", "ClientIP", "ClientCountry", "ClientASN", "ClientRequestHost",
        "ClientRequestPath", "ClientRequestMethod", "RayID", "RuleID", "Description", "UserAgent",
        "EdgeResponseStatus", "WAFAttackScore", "WAFSQLiAttackScore", "WAFXSSAttackScore", "WAFRCEAttackScore",
        "WAFRequestSignatureCategories", "WAFRequestSignatureRefs",
    ],
    "dns_logs": [
        "Timestamp", "QueryName", "QueryType", "ResponseCode", "SourceIP", "ColoCode", "EDNSSubnet",
        "ResponseCached",
    ],
}


class NoPermission(ProviderError):
    pass


class Client:
    def __init__(self, token: str, opener=None) -> None:
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.opener = opener

    def call(self, method: str, path: str, body: dict | None = None) -> object:
        status, payload = http_json(method, API + path, dict(self.headers), body, opener=self.opener)
        if status in (401, 403):
            raise NoPermission(f"Cloudflare {method} {path.split('?')[0]}: HTTP {status} (falta «Logs: Write»)")
        if status >= 400 or not isinstance(payload, dict) or not payload.get("success", False):
            codes = [e.get("code") for e in (payload or {}).get("errors", [])] if isinstance(payload, dict) else []
            raise ProviderError(f"Cloudflare {method} {path.split('?')[0]}: HTTP {status} {codes}")
        return payload.get("result")


def destination(endpoint: str, dataset: str, zone_id: str, secret: str) -> str:
    query = urllib.parse.urlencode({f"header_{HEADER}": secret})
    return f"{endpoint.rstrip('/')}/{dataset}/{zone_id}?{query}"


def job_body(name: str, dataset: str, dest: str, fields: list[str]) -> dict:
    return {
        "name": name,
        "dataset": dataset,
        "destination_conf": dest,
        "enabled": True,
        "output_options": {
            "output_type": "ndjson",
            "field_names": fields,
            "timestamp_format": "rfc3339",
            "sample_rate": 1,
        },
    }


def reconcile(client: Client, endpoint: str, secret: str, dry_run: bool = False) -> list[dict]:
    zones = client.call("GET", "/zones?per_page=50") or []
    report = []
    for zone in zones:
        jobs = {job.get("name"): job for job in client.call("GET", f"/zones/{zone['id']}/logpush/jobs") or []}
        for dataset in DATASETS:
            offered = client.call("GET", f"/zones/{zone['id']}/logpush/datasets/{dataset}/fields") or {}
            fields = [name for name in WANTED_FIELDS[dataset] if name in offered]
            name = f"b89-{dataset.replace('_', '-')}"
            body = job_body(name, dataset, destination(endpoint, dataset, zone["id"], secret), fields)
            current = jobs.get(name)
            if current is None:
                action = "create"
                if not dry_run:
                    client.call("POST", f"/zones/{zone['id']}/logpush/jobs", body)
            else:
                same = (current.get("destination_conf") == body["destination_conf"] and current.get("enabled")
                        and (current.get("output_options") or {}).get("field_names") == fields)
                action = "ok" if same else "update"
                if not same and not dry_run:
                    update = {k: v for k, v in body.items() if k not in ("name", "dataset")}
                    client.call("PUT", f"/zones/{zone['id']}/logpush/jobs/{current['id']}", update)
            report.append({"zone": zone.get("name"), "dataset": dataset, "fields": len(fields), "action": action})
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        creds = pathlib.Path(config["credentials_dir"])
        client = Client(read_secret(creds / "cloudflare-api-token"))
        secret = read_secret(creds / "cloudflare-logpush-token")
        report = reconcile(client, config["endpoint"], secret, args.dry_run)
    except NoPermission as error:
        print(f"b89-cloudflare-logpush-provision: {error}", file=sys.stderr)
        return 2
    except (ProviderError, OSError, KeyError) as error:
        message = str(error) if isinstance(error, ProviderError) else type(error).__name__
        print(f"b89-cloudflare-logpush-provision: failed: {message}", file=sys.stderr)
        return 1
    for row in report:
        print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
