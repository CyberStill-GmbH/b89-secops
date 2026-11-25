#!/usr/bin/env python3
"""B89 Cloudflare traffic collector: HTTP requests and DNS queries from the GraphQL Analytics API.

Bridges what Logpush cannot do: Logpush never backfills and needs «Logs: Write». The adaptive
datasets ``httpRequestsAdaptive`` and ``dnsAnalyticsAdaptive`` keep 31 days of per-record data on
every plan, **sampled** (one record may stand for several requests; DNS reports ``sampleInterval``).

- First run starts ``history_days`` back (bounded by the zone's retention) and catches up in
  budgeted batches, so 30 days reach Wazuh progressively instead of in one flood.
- Afterwards it follows the live edge ``lag_minutes`` behind (data settles in Cloudflare).
- Records are converted to Logpush field names and normalized by ``logpush.normalize`` so the same
  rules apply. ``b89.source`` is ``graphql-history`` for records older than one hour at collection
  time and ``graphql-live`` otherwise; burst (frequency) rules only count real-time Logpush.
- A window that returns the page limit is split in halves down to one minute; a full one-minute
  window is kept and reported as truncated (never silently skipped).
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
import logpush  # noqa: E402
import re  # noqa: E402

from b89_collector import ProviderError, http_json, iso, parse_iso, read_secret, run_collector, utc_now  # noqa: E402
from security import API, Cloudflare, discover  # noqa: E402

PAGE_LIMIT = 10_000
MIN_WINDOW = timedelta(minutes=1)
RETENTION_MARGIN = timedelta(hours=1)
# El plan de la zona puede negar campos (p. ej. coloCode en Free): se quitan para esa zona y se reintenta.
DENIED_RE = re.compile(r"does not have access to the field '([A-Za-z0-9_]+)'")

HTTP_FIELDS = {
    "datetime": "EdgeStartTimestamp", "rayName": "RayID", "clientIP": "ClientIP",
    "clientCountryName": "ClientCountry", "clientAsn": "ClientASN", "clientASNDescription": "ClientASNDescription",
    "clientRequestHTTPHost": "ClientRequestHost", "clientRequestHTTPMethodName": "ClientRequestMethod",
    "clientRequestPath": "ClientRequestPath", "clientRequestQuery": "ClientRequestQuery",
    "clientRequestHTTPProtocol": "ClientRequestProtocol", "clientRequestScheme": "ClientRequestScheme",
    "clientRequestReferer": "ClientRequestReferer", "userAgent": "ClientRequestUserAgent",
    "clientSSLProtocol": "ClientSSLProtocol", "edgeResponseStatus": "EdgeResponseStatus",
    "originResponseStatus": "OriginResponseStatus", "cacheStatus": "CacheCacheStatus",
    "securityAction": "SecurityAction", "securitySource": "SecuritySource",
    "verifiedBotCategory": "VerifiedBotCategory", "coloCode": "EdgeColoCode", "requestSource": "RequestSource",
}
DNS_FIELDS = {
    "datetime": "Timestamp", "queryName": "QueryName", "queryType": "QueryType", "responseCode": "ResponseCode",
    "sourceIP": "SourceIP", "coloName": "ColoCode", "responseCached": "ResponseCached",
    "sampleInterval": "SampleInterval", "protocol": "Protocol",
}
# dataset Logpush → (nodo GraphQL, campos)
DATASETS = {
    "http_requests": ("httpRequestsAdaptive", HTTP_FIELDS),
    "dns_logs": ("dnsAnalyticsAdaptive", DNS_FIELDS),
}


def query_for(node: str, fields: dict) -> str:
    return (
        "query($zone:String!,$since:Time!,$until:Time!,$limit:Int!){viewer{zones(filter:{zoneTag:$zone}){"
        f"{node}(limit:$limit,orderBy:[datetime_ASC],filter:{{datetime_geq:$since,datetime_lt:$until}})"
        "{" + " ".join(fields) + "}}}}"
    )


def to_logpush(row: dict, fields: dict) -> dict:
    record = {fields[key]: value for key, value in row.items() if key in fields and value not in (None, "")}
    if "ClientRequestPath" in record and record.get("ClientRequestQuery"):
        record["ClientRequestURI"] = f"{record['ClientRequestPath']}{record['ClientRequestQuery']}"
    return record


def graphql(client, query: str, variables: dict) -> tuple[dict | None, list[str]]:
    """``(data, error messages)``; the messages never include the token."""
    if not hasattr(client, "headers"):  # cliente de prueba
        return client.graphql(query, variables), []
    status, payload = http_json("POST", API + "/graphql", dict(client.headers),
                                {"query": query, "variables": variables}, opener=client.opener)
    if status in (401, 403):
        raise ProviderError("Cloudflare GraphQL denied the request", status)
    if status != 200 or not isinstance(payload, dict):
        raise ProviderError("Cloudflare GraphQL request failed", status)
    errors = [str(e.get("message") or "") for e in payload.get("errors") or [] if isinstance(e, dict)]
    return payload.get("data") if isinstance(payload.get("data"), dict) else None, errors


def fetch(client: Cloudflare, zone_id: str, dataset: str, since: datetime, until: datetime,
          denied: set | None = None) -> tuple[list[dict], bool]:
    """Rows of [since, until) in ascending time. ``True`` when a 1-minute window was still full."""
    denied = denied if denied is not None else set()
    node, all_fields = DATASETS[dataset]
    variables = {"zone": zone_id, "since": iso(since), "until": iso(until), "limit": PAGE_LIMIT}
    while True:
        fields = [name for name in all_fields if name.lower() not in denied]
        data, errors = graphql(client, query_for(node, fields), variables)
        blocked = {m.group(1).lower() for m in map(DENIED_RE.search, errors) if m}
        if errors and blocked and not blocked <= denied and "datetime" not in blocked:
            denied |= blocked
            continue
        if errors or data is None:
            raise ProviderError(f"Cloudflare GraphQL {node} failed: {errors[0][:160] if errors else 'no data'}")
        break
    zones = ((data or {}).get("viewer") or {}).get("zones") or []
    rows = zones[0].get(node) if zones else None
    if not isinstance(rows, list):
        raise ProviderError(f"Cloudflare GraphQL {node}: unexpected response")
    if len(rows) < PAGE_LIMIT:
        return rows, False
    if until - since <= MIN_WINDOW:
        return rows, True
    middle = since + (until - since) / 2
    first, cut_a = fetch(client, zone_id, dataset, since, middle, denied)
    second, cut_b = fetch(client, zone_id, dataset, middle, until, denied)
    return first + second, cut_a or cut_b


def collect(config: dict, state: dict, client: Cloudflare | None = None) -> tuple[list[dict], dict]:
    if client is None:
        client = Cloudflare(read_secret(pathlib.Path(config["token_file"])))
    now = utc_now()
    now_text = iso(now)
    until_edge = now - timedelta(minutes=int(config.get("lag_minutes", 5)))
    # Con Logpush activo el instalador fija "until" (inicio de los jobs): desde ahí el tráfico llega
    # completo y en tiempo real por Logpush, y este collector solo termina la recuperación.
    if config.get("until"):
        until_edge = min(until_edge, parse_iso(str(config["until"])))
    # Con Logpush activo el instalador fija "until" (inicio de los jobs): desde ahí el tráfico llega
    # completo y en tiempo real por Logpush, y este collector solo termina la recuperación.
    if config.get("until"):
        until_edge = min(until_edge, parse_iso(str(config["until"])))
    oldest_allowed = now - timedelta(days=31) + RETENTION_MARGIN
    start = max(now - timedelta(days=float(config.get("history_days", 30))), oldest_allowed)
    window = timedelta(minutes=int(config.get("window_minutes", 60)))
    budget = int(config.get("max_rows_per_batch", 50_000))
    history_cut = now - timedelta(hours=1)
    datasets = [d for d in config.get("datasets", list(DATASETS)) if d in DATASETS]
    # Tramos ya entregados a Wazuh por otra vía (p. ej. carga urgente de un incidente): se saltan.
    skips = [(parse_iso(a), parse_iso(b)) for a, b in config.get("skip_windows", [])]

    zones = [{"id": str(z["id"]), "name": str(z.get("name") or "")} for z in discover(client, "zones")
             if isinstance(z, dict) and z.get("id")]
    cursors = {key: dict(value) for key, value in (state.get("cursors") or {}).items()}
    truncated = int(state.get("truncated_windows", 0))
    denied_fields = {zone: set(names) for zone, names in (state.get("denied_fields") or {}).items()}
    events: list[dict] = []
    # Lista blanca de la API de pagos: una alerta por clave y ventana (como Logpush). Los registros
    # históricos (recuperación de hasta 30 días) quedan indexados con nivel bajo: nunca abren alertas.
    deduper = logpush.payments_allowlist.Deduper(
        state.get("allowlist_seen"), now.timestamp(), logpush.payments_allowlist.dedup_window())
    # Ronda por zona y dataset: cada uno avanza una ventana por vuelta hasta agotar el presupuesto.
    progressing = True
    while progressing and len(events) < budget:
        progressing = False
        for zone in zones:
            for dataset in datasets:
                if len(events) >= budget:
                    break
                zone_cursors = cursors.setdefault(zone["id"], {})
                cursor = parse_iso(zone_cursors[dataset]) if zone_cursors.get(dataset) else start
                cursor = max(cursor, oldest_allowed)
                for skip_from, skip_to in skips:
                    if skip_from <= cursor < skip_to:
                        cursor = skip_to
                if cursor >= until_edge:
                    zone_cursors[dataset] = iso(max(cursor, parse_iso(zone_cursors.get(dataset) or iso(cursor))))
                    continue
                end = min(cursor + window, until_edge)
                for skip_from, _ in skips:
                    if cursor < skip_from < end:
                        end = skip_from
                denied = denied_fields.setdefault(zone["id"], set())
                rows, cut = fetch(client, zone["id"], dataset, cursor, end, denied)
                truncated += int(cut)
                _, fields = DATASETS[dataset]
                for row in rows:
                    happened = parse_iso(str(row.get("datetime"))) if row.get("datetime") else now
                    history = happened < history_cut
                    event = logpush.normalize(to_logpush(row, fields), dataset, zone["id"], "graphql", now_text,
                                              None if history else deduper)
                    event["b89"]["source"] = "graphql-history" if history else "graphql-live"
                    http_section = event["cloudflare"].get("http") or {}
                    if history and "allowlist_first" in http_section:
                        http_section["allowlist_first"] = "false"
                    event["b89"]["sampled"] = True
                    event["cloudflare"]["zone_name"] = zone["name"][:255]
                    events.append(event)
                zone_cursors[dataset] = iso(end)
                progressing = True

    behind = [
        parse_iso(value) for zone in zones for dataset, value in cursors.get(zone["id"], {}).items()
        if dataset in datasets and value
    ]
    oldest = min(behind) if behind else start
    return events, {
        "cursors": cursors,
        "truncated_windows": truncated,
        "allowlist_seen": deduper.export(),
        "denied_fields": {zone: sorted(names) for zone, names in denied_fields.items() if names},
        "history_start": iso(start) if not state.get("history_start") else state["history_start"],
        "catching_up": oldest < until_edge - window,
        "oldest_cursor": iso(oldest),
        "coverage": {"mode": "graphql_adaptive_sampled", "exhaustive": False,
                     "reason": "Adaptive datasets are sampled; Logpush is the exhaustive real-time path"},
        "scope": {"zones": [{"id": z["id"], "name": z["name"][:255]} for z in zones][:500],
                  "datasets": datasets, "at": now_text},
    }


def watermark(state: dict) -> str | None:
    return state.get("oldest_cursor")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    return run_collector("b89-cloudflare-traffic", parser.parse_args().config, collect,
                         source_id="cloudflare-traffic", vendor="cloudflare", source="traffic",
                         watermark=watermark)


if __name__ == "__main__":
    raise SystemExit(main())
