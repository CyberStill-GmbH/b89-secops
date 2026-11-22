#!/usr/bin/env python3
"""Cloudflare account audit logs and zone security (firewall) events → JSONL for Wazuh. Read-only.

Verified token scope (2026-11-03): ``/user/tokens/verify`` active; 1 account, 3 zones; account
audit logs readable; GraphQL ``firewallEventsAdaptive`` readable for every zone.

- ``audit``: ``GET /accounts/{id}/audit_logs?since=&direction=asc`` paginated; dedupe by log id;
  cursor = newest ``when``.
- ``firewall``: GraphQL ``firewallEventsAdaptive`` per zone in windows of at most 1 h, from the
  cursor to now-2 min (Cloudflare indexes with a short delay). Events carry no id, so the dedupe
  key is a hash of the record. Saturated windows are subdivided before advancing; saturation
  at one second fails visibly. The cursor advances only to the end of an unsaturated window.
  This adaptive API is not an exhaustive archive of all datasets. Normalized fields are bounded
  for detection; ``cloudflare.raw_json`` keeps the provider record as one bounded JSON string
  (never as nested fields: audit ``newValueJson``/``metadata`` vary per resource type and, as
  dynamic Indexer fields, would cause mapping conflicts that reject the whole alert, or keyword
  terms over 32 KiB). The shared durable writer rejects oversized batches without advancing
  their checkpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.parse
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
from b89_collector import (  # noqa: E402
    ProviderError,
    bounded_ids,
    http_json,
    iso,
    oldest_cursor,
    parse_iso,
    read_secret,
    run_collector,
    utc_now,
)

API = "https://api.cloudflare.com/client/v4"
FIREWALL_FIELDS = (
    "action source datetime clientIP clientCountryName clientAsn clientRequestHTTPHost "
    "clientRequestPath clientRequestHTTPMethodName rayName ruleId description userAgent edgeResponseStatus"
)
FIREWALL_QUERY = (
    "query($zone:String!,$since:Time!,$until:Time!,$limit:Int!){viewer{zones(filter:{zoneTag:$zone}){"
    "firewallEventsAdaptive(limit:$limit,filter:{datetime_geq:$since,datetime_lt:$until},"
    "orderBy:[datetime_ASC]){" + FIREWALL_FIELDS + "}}}}"
)
FIREWALL_LIMIT = 5000
WINDOW = timedelta(hours=1)
INGEST_DELAY = timedelta(minutes=2)
MAX_WINDOWS_PER_RUN = 24
MAX_AUDIT_PAGES = 50
MAX_DISCOVERY_PAGES = 1000
# Below the Indexer keyword term limit (32766 bytes) and well inside Wazuh's 64 KiB event line.
RAW_JSON_MAX_CHARS = 8000


def raw_evidence(record: dict) -> dict:
    """Provider record as a bounded, compact JSON string plus an explicit truncation flag."""
    text = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    truncated = len(text) > RAW_JSON_MAX_CHARS
    return {"raw_json": text[:RAW_JSON_MAX_CHARS], "raw_truncated": "true" if truncated else "false"}


def discover(client, resource: str) -> list[dict]:
    """Enumerate every accessible resource; never silently accept a partial inventory."""
    result, ids = [], set()
    for page in range(1, MAX_DISCOVERY_PAGES + 1):
        payload = client.rest(f"/{resource}?per_page=50&page={page}")
        records = payload.get("result")
        if not isinstance(records, list):
            raise ProviderError("Cloudflare resource inventory is invalid")
        for record in records:
            if not isinstance(record, dict) or not record.get("id"):
                raise ProviderError("Cloudflare resource inventory contains invalid records")
            if record["id"] in ids:
                raise ProviderError("Cloudflare resource inventory pagination repeated")
            ids.add(record["id"])
            result.append(record)
        if len(records) < 50:
            return result
    raise ProviderError("Cloudflare resource inventory exceeded pagination budget")


class Cloudflare:
    def __init__(self, token: str, opener=None) -> None:
        self.headers = {"Authorization": f"Bearer {token}"}
        self.opener = opener

    def rest(self, path: str) -> dict:
        status, payload = http_json("GET", API + path, dict(self.headers), opener=self.opener)
        if status in (401, 403):
            raise ProviderError("Cloudflare denied the request", status)
        if status != 200 or not isinstance(payload, dict) or payload.get("success") is not True:
            raise ProviderError("Cloudflare request failed", status)
        return payload

    def graphql(self, query: str, variables: dict) -> dict:
        status, payload = http_json(
            "POST", API + "/graphql", dict(self.headers), {"query": query, "variables": variables}, opener=self.opener
        )
        if status in (401, 403):
            raise ProviderError("Cloudflare GraphQL denied the request", status)
        if status != 200 or not isinstance(payload, dict) or payload.get("errors") or not isinstance(payload.get("data"), dict):
            raise ProviderError("Cloudflare GraphQL request failed", status)
        return payload["data"]


def audit_event(record: dict, account_id: str, now: str) -> dict:
    action = record.get("action") if isinstance(record.get("action"), dict) else {}
    actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    resource = record.get("resource") if isinstance(record.get("resource"), dict) else {}
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    return {
        "b89": {"vendor": "cloudflare", "source": "audit_logs", "event_type": "audit", "collected_at": now},
        "cloudflare": {
            "account_id": account_id,
            **raw_evidence(record),
            "audit": {
                "id": str(record.get("id") or ""),
                "when": str(record.get("when") or ""),
                "action": str(action.get("type") or "")[:100],
                "result": ("true" if action.get("result") is True else
                           "false" if action.get("result") is False else "unknown"),
                "actor_type": str(actor.get("type") or "")[:32],
                "actor_email": str(actor.get("email") or "")[:200],
                "actor_ip": str(actor.get("ip") or "")[:64],
                "resource_type": str(resource.get("type") or "")[:100],
                "resource_id": str(resource.get("id") or "")[:100],
                "zone_name": str(metadata.get("zone_name") or "")[:255],
                "interface": str(record.get("interface") or "")[:32],
            },
        },
    }


def firewall_event(record: dict, zone: dict, now: str) -> dict:
    return {
        "b89": {"vendor": "cloudflare", "source": "firewall_events", "event_type": "firewall", "collected_at": now},
        "cloudflare": {
            "zone_id": zone["id"],
            "zone_name": zone["name"],
            **raw_evidence(record),
            "firewall": {
                "datetime": str(record.get("datetime") or ""),
                "action": str(record.get("action") or "")[:32],
                "source": str(record.get("source") or "")[:64],
                "client_ip": str(record.get("clientIP") or "")[:64],
                "country": str(record.get("clientCountryName") or "")[:8],
                "asn": str(record.get("clientAsn") or "")[:16],
                "host": str(record.get("clientRequestHTTPHost") or "")[:255],
                "path": str(record.get("clientRequestPath") or "")[:512],
                "method": str(record.get("clientRequestHTTPMethodName") or "")[:16],
                "ray": str(record.get("rayName") or "")[:32],
                "rule_id": str(record.get("ruleId") or "")[:64],
                "rule_description": str(record.get("description") or "")[:255],
                "user_agent": str(record.get("userAgent") or "")[:300],
                "status": str(record.get("edgeResponseStatus") or "")[:8],
            },
        },
    }


def record_key(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()[:24]


def collect_audit(client: Cloudflare, account_id: str, since_text: str, seen: set, now: str) -> tuple[list[dict], str, list[str]]:
    events, keys, newest = [], [], since_text
    for page in range(1, MAX_AUDIT_PAGES + 1):
        query = urllib.parse.urlencode({"since": since_text, "direction": "asc", "per_page": 100, "page": page})
        records = client.rest(f"/accounts/{account_id}/audit_logs?{query}").get("result")
        if not isinstance(records, list):
            raise ProviderError("Cloudflare audit response is invalid")
        for record in records:
            if not isinstance(record, dict) or not record.get("id") or not record.get("when"):
                raise ProviderError("Cloudflare audit record is invalid")
            if record["id"] in seen:
                continue
            keys.append(record["id"])
            events.append(audit_event(record, account_id, now))
            when = str(record.get("when") or "")
            if when:
                try:
                    if parse_iso(when) > parse_iso(newest):
                        newest = iso(parse_iso(when))
                except ValueError:
                    raise ProviderError("Cloudflare audit timestamp is invalid")
        if len(records) < 100:
            break
    else:
        raise ProviderError("Cloudflare audit pagination exhausted; checkpoint preserved")
    return events, newest, keys


def collect_firewall(client: Cloudflare, zone: dict, since, until, seen: set, now: str) -> tuple[list[dict], object, list[str]]:
    events, keys, cursor = [], [], since
    windows = 0
    span = WINDOW
    while cursor < until and windows < MAX_WINDOWS_PER_RUN:
        windows += 1
        window_end = min(cursor + span, until)
        data = client.graphql(FIREWALL_QUERY, {"zone": zone["id"], "since": iso(cursor), "until": iso(window_end), "limit": FIREWALL_LIMIT})
        zones = ((data.get("viewer") or {}).get("zones")) or []
        if len(zones) != 1 or not isinstance(zones[0], dict):
            raise ProviderError("Cloudflare zone missing from GraphQL response")
        records = zones[0].get("firewallEventsAdaptive")
        if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
            raise ProviderError("Cloudflare firewall response is invalid")
        if len(records) >= FIREWALL_LIMIT:
            # Never advance past a saturated instant. Retry a smaller half-open window.
            seconds = int((window_end - cursor).total_seconds())
            if seconds <= 1:
                raise ProviderError("Cloudflare firewall second saturated; use unsampled Logpush")
            span = timedelta(seconds=max(1, seconds // 2))
            continue
        for record in records:
            key = record_key(record)
            try:
                parse_iso(str(record.get("datetime")))
            except ValueError:
                raise ProviderError("Cloudflare firewall timestamp is invalid")
            if key in seen:
                continue
            keys.append(key)
            seen.add(key)
            events.append(firewall_event(record, zone, now))
        cursor = window_end
        span = WINDOW
    return events, cursor, keys


def collect(config: dict, state: dict, client: Cloudflare | None = None) -> tuple[list[dict], dict]:
    if client is None:
        client = Cloudflare(read_secret(pathlib.Path(config["token_file"])))
    now = utc_now()
    now_text = iso(now)
    lookback = timedelta(hours=int(config.get("initial_lookback_hours", 1)))
    events: list[dict] = []

    audit_cursors = dict(state.get("audit_cursors") or {})
    audit_seen = list(state.get("audit_seen") or [])
    accounts: list[str] = []
    zones: list[dict] = []
    if config.get("audit", True):
        accounts = config.get("account_ids") or [str(a["id"]) for a in discover(client, "accounts")]
        for account_id in accounts:
            since_text = audit_cursors.get(account_id) or iso(now - lookback)
            batch, newest, keys = collect_audit(client, account_id, since_text, set(audit_seen), now_text)
            events.extend(batch)
            audit_seen.extend(keys)
            audit_cursors[account_id] = newest

    fw_cursors = dict(state.get("firewall_cursors") or {})
    fw_seen = list(state.get("firewall_seen") or [])
    firewall_logpush_active = False
    activation_file = config.get("firewall_logpush_active_file")
    if activation_file:
        marker = pathlib.Path(activation_file)
        if marker.exists():
            try:
                parse_iso(marker.read_text(encoding="ascii").strip())
            except (OSError, UnicodeError, ValueError) as error:
                raise ProviderError("Cloudflare Logpush activation marker is invalid") from error
            firewall_logpush_active = True
    firewall_configured = bool(config.get("firewall", True))
    firewall_enabled = firewall_configured and not firewall_logpush_active
    if firewall_configured:
        zones = [
            {"id": str(z.get("id")), "name": str(z.get("name") or "")}
            for z in discover(client, "zones")
            if isinstance(z, dict) and z.get("id")
        ]
        if config.get("zone_ids"):
            zones = [z for z in zones if z["id"] in set(config["zone_ids"])]
            if {z["id"] for z in zones} != set(config["zone_ids"]):
                raise ProviderError("Cloudflare configured zones are missing or inaccessible")
    if firewall_enabled:
        until = now - INGEST_DELAY
        seen_set = set(fw_seen)
        for zone in zones:
            cursor_text = fw_cursors.get(zone["id"])
            since = parse_iso(cursor_text) if cursor_text else until - lookback
            # Preserve backlog: retention failures must be visible, never silently skip time.
            batch, cursor, keys = collect_firewall(client, zone, since, until, seen_set, now_text)
            events.extend(batch)
            fw_seen.extend(keys)
            fw_cursors[zone["id"]] = iso(cursor)

    return events, {
        # Alcance vigilado en ESTA pasada (descubierto en la API, no fijo): lo publica el monitor de
        # plataforma para que la consola muestre las zonas reales, también las que no tienen eventos.
        "scope": {
            "accounts": len(accounts),
            "zones": [{"id": z["id"], "name": z["name"][:255]} for z in zones][:500],
            "firewall": firewall_enabled,
            "firewall_logpush_active": firewall_logpush_active,
            "audit": bool(config.get("audit", True)),
            "at": now_text,
        },
        "coverage": {"mode": "audit_and_logpush_firewall" if firewall_logpush_active else "audit_and_adaptive_firewall",
                     "exhaustive": False,
                     "reason": "firewall_events Logpush active; account audit remains on API" if firewall_logpush_active
                     else "GraphQL adaptive firewall is a sampled fallback, not an all-dataset log archive"},
        "audit_cursors": audit_cursors,
        "audit_seen": bounded_ids(audit_seen, 20000),
        "firewall_cursors": fw_cursors,
        "firewall_seen": bounded_ids(fw_seen, 50000),
    }


def probe(config: dict, opener=None) -> None:
    """Read-only auth check. ``/user/tokens/verify`` reports ``active``/``disabled``/``expired`` for a
    user token; an account-owned token is verified by listing one visible account instead."""
    headers = {"Authorization": f"Bearer {read_secret(pathlib.Path(config['token_file']))}"}
    status, payload = http_json("GET", API + "/user/tokens/verify", dict(headers), opener=opener)
    if status == 200 and isinstance(payload, dict) and payload.get("success") is True:
        token_status = str((payload.get("result") or {}).get("status") or "").lower()
        if token_status == "expired":
            raise ProviderError("Cloudflare token is expired", 200, auth="expired")
        if token_status and token_status != "active":
            raise ProviderError("Cloudflare token is not active", 200, auth="denied")
        return
    status, payload = http_json("GET", API + "/accounts?per_page=1", dict(headers), opener=opener)
    if status in (401, 403):
        raise ProviderError("Cloudflare refused the token", status, auth="denied")
    if status != 200 or not isinstance(payload, dict) or payload.get("success") is not True:
        raise ProviderError("Cloudflare token check failed", status)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    return run_collector("b89-cloudflare", parser.parse_args().config, collect, source_id="cloudflare",
                         vendor="cloudflare", source="security", probe=probe,
                         watermark=oldest_cursor("audit_cursors", "firewall_cursors"))


if __name__ == "__main__":
    raise SystemExit(main())
