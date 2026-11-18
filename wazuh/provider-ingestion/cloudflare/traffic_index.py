#!/usr/bin/env python3
"""Index every Cloudflare event into ``b89-cloudflare-traffic-YYYY.MM.DD`` with its REAL event time.

Wazuh alerts carry the time the manager processed them and drop level-0 events, so traffic
(HTTP requests, DNS queries) was invisible in the SOC and recovered history looked like "now".
This indexer tails the Cloudflare JSONL outputs (GraphQL traffic, Logpush spool, API security
collector, history backfill) and bulk-indexes one document per event:

- ``@timestamp`` = when it happened at Cloudflare (UTC); daily index by that date.
- deterministic ``_id`` (RayID for HTTP, audit id, or a content hash): re-reading a file, a
  re-run of the backfill or the same request from GraphQL and Logpush never duplicates.
- offsets per file (inode + byte offset) advance only after a successful bulk; a rotated file
  (``.1``) is finished before the new one is read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
from b89_collector import ProviderError, read_secret  # noqa: E402

INDEX_PREFIX = "b89-cloudflare-traffic-"
BULK_DOCS = 2000
DATASETS = {"http", "dns", "firewall", "audit"}


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    return str(value).lower() in ("true", "1", "yes")


def _ts(*values) -> str | None:
    for value in values:
        if not value:
            continue
        text = str(value)
        try:
            if text.isdigit():  # epoch (s, ms, ns)
                number = int(text)
                seconds = number / (1e9 if number > 1e14 else 1e3 if number > 1e11 else 1)
                return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            continue
    return None


def _clean(obj):
    if isinstance(obj, dict):
        out = {k: _clean(v) for k, v in obj.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    return obj


def to_document(event: dict) -> tuple[str, str, dict] | None:
    """``(index, _id, doc)`` for a Cloudflare event, or ``None`` for anything else (heartbeats)."""
    b89 = event.get("b89") or {}
    cf = event.get("cloudflare") or {}
    if b89.get("vendor") != "cloudflare":
        return None
    dataset = b89.get("event_type")
    if dataset not in DATASETS:
        return None
    raw = cf.get("raw") if isinstance(cf.get("raw"), dict) else {}
    source = str(b89.get("source") or "")
    if source not in ("logpush", "graphql-live", "graphql-history"):
        source = "backfill" if b89.get("history") else "api"
    doc: dict = {
        "event": {
            "dataset": dataset,
            "source": source,
            "sampled": bool(b89.get("sampled")),
            "history": bool(b89.get("history")) or source == "graphql-history",
        },
        "zone": {"name": cf.get("zone_name") or (cf.get("audit") or {}).get("zone_name"),
                 "id": cf.get("scope_id") or cf.get("zone_id")},
        "ingested_at": _ts(b89.get("collected_at")),
    }
    if dataset == "http":
        h = cf.get("http") or {}
        doc["@timestamp"] = _ts(h.get("datetime"), raw.get("EdgeStartTimestamp"), b89.get("collected_at"))
        doc["client"] = {"ip": h.get("client_ip"), "country": h.get("country"), "asn": _int(h.get("asn")),
                         "asn_name": raw.get("ClientASNDescription")}
        doc["http"] = {
            "host": h.get("host"), "method": h.get("method"), "path": h.get("path"),
            "query": raw.get("ClientRequestQuery"), "uri": h.get("uri"), "status": _int(h.get("status")),
            "origin_status": _int(h.get("origin_status")), "user_agent": h.get("user_agent"),
            "referer": h.get("referer"), "ray": h.get("ray"), "cache": h.get("cache"),
            "protocol": h.get("protocol"), "tls": h.get("tls"), "security_action": h.get("security_action"),
            "security_source": h.get("security_source"), "bytes": _int(h.get("bytes")),
        }
        key = h.get("ray") or json.dumps(raw or h, sort_keys=True)
    elif dataset == "dns":
        d = cf.get("dns") or {}
        doc["@timestamp"] = _ts(d.get("datetime"), raw.get("Timestamp"), b89.get("collected_at"))
        doc["client"] = {"ip": d.get("client_ip")}
        doc["dns"] = {"query": d.get("query"), "type": d.get("query_type"), "rcode": d.get("response_code"),
                      "colo": d.get("colo"), "cached": _bool(d.get("cached")), "protocol": raw.get("Protocol")}
        interval = raw.get("SampleInterval")
        if interval is not None:
            doc["event"]["sample_interval"] = float(interval)
        key = json.dumps(raw or d, sort_keys=True)
    elif dataset == "firewall":
        f = cf.get("firewall") or {}
        doc["@timestamp"] = _ts(f.get("datetime"), b89.get("collected_at"))
        doc["client"] = {"ip": f.get("client_ip"), "country": f.get("country"), "asn": _int(f.get("asn"))}
        doc["http"] = {"host": f.get("host"), "path": f.get("path"), "method": f.get("method"),
                       "user_agent": f.get("user_agent"), "status": _int(f.get("status"))}
        doc["firewall"] = {"action": f.get("action"), "source": f.get("source"), "rule_id": f.get("rule_id"),
                           "description": f.get("rule_description") or f.get("description"), "ray": f.get("ray")}
        key = "|".join(str(f.get(k) or "") for k in ("ray", "datetime", "rule_id", "action", "client_ip", "path"))
    else:
        a = cf.get("audit") or {}
        doc["@timestamp"] = _ts(a.get("when"), b89.get("collected_at"))
        doc["audit"] = {"action": a.get("action"), "result": a.get("result"), "actor_email": a.get("actor_email"),
                        "actor_ip": a.get("actor_ip"), "resource_type": a.get("resource_type"),
                        "zone_name": a.get("zone_name"), "id": a.get("id")}
        if a.get("actor_ip"):
            doc["client"] = {"ip": a.get("actor_ip")}
        key = a.get("id") or json.dumps(a, sort_keys=True)
    if not doc.get("@timestamp"):
        return None
    zone_key = doc["zone"].get("id") or doc["zone"].get("name") or ""
    doc_id = hashlib.sha256(f"{dataset}|{zone_key}|{key}".encode("utf-8")).hexdigest()[:40]
    index = INDEX_PREFIX + doc["@timestamp"][:10].replace("-", ".")
    return index, doc_id, _clean(doc)


# ------------------------------------------------------------------ indexer HTTP


class _Pinned(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, sni: str) -> None:
        super().__init__(context=context)
        self._ctx, self._sni = context, sni

    def https_open(self, req):
        import http.client
        ctx, sni = self._ctx, self._sni

        class Conn(http.client.HTTPSConnection):
            def connect(inner):  # noqa: N805
                sock = socket.create_connection((inner.host, inner.port), inner.timeout)
                inner.sock = ctx.wrap_socket(sock, server_hostname=sni)

        return self.do_open(lambda host, **kw: Conn(host, timeout=kw.get("timeout", 60)), req)


class Indexer:
    def __init__(self, config: dict) -> None:
        ctx = ssl.create_default_context(cafile=config["ca_file"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(_Pinned(ctx, config.get("server_hostname", "wazuh.indexer")))
        self.url = config.get("url", "https://127.0.0.1:9200").rstrip("/")
        import base64
        password = read_secret(pathlib.Path(config["password_file"]))
        self.auth = "Basic " + base64.b64encode(f"{config['user']}:{password}".encode()).decode()

    def bulk(self, payload: bytes) -> dict:
        req = urllib.request.Request(self.url + "/_bulk", data=payload, method="POST",
                                     headers={"Authorization": self.auth, "Content-Type": "application/x-ndjson"})
        try:
            with self.opener.open(req, timeout=120) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as error:
            raise ProviderError(f"indexer bulk HTTP {error.code}") from error
        except (urllib.error.URLError, OSError) as error:
            raise ProviderError("indexer unreachable") from error


def send(indexer, docs: list[tuple[str, str, dict]]) -> tuple[int, int]:
    lines = []
    for index, doc_id, doc in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc, ensure_ascii=False))
    result = indexer.bulk(("\n".join(lines) + "\n").encode("utf-8"))
    failed = 0
    retryable = False
    for item in result.get("items", []):
        status = (item.get("index") or {}).get("status", 500)
        if status >= 300:
            failed += 1
            retryable = retryable or status in (429, 503)
    if retryable:
        raise ProviderError("indexer is throttling (429/503); offsets kept")
    return len(docs) - failed, failed


# ------------------------------------------------------------------ tail


def read_lines(path: pathlib.Path, offset: int, max_lines: int) -> tuple[list[bytes], int]:
    lines = []
    with path.open("rb") as stream:
        stream.seek(offset)
        while len(lines) < max_lines:
            line = stream.readline()
            if not line or not line.endswith(b"\n"):
                break  # línea incompleta: se relee en la próxima pasada
            lines.append(line)
            offset += len(line)
    return lines, offset


def process_file(path: pathlib.Path, state: dict, indexer, budget: int, save) -> dict:
    stats = {"lines": 0, "indexed": 0, "failed": 0, "skipped": 0}
    entry = state.get(str(path)) or {}
    try:
        inode = path.stat().st_ino
    except FileNotFoundError:
        return stats
    # Rotación: terminar la generación anterior (.1) desde el offset guardado.
    targets = []
    rotated = path.with_name(path.name + ".1")
    if entry.get("inode") and entry["inode"] != inode and rotated.exists() and rotated.stat().st_ino == entry["inode"]:
        targets.append((rotated, entry.get("offset", 0), entry["inode"]))
        targets.append((path, 0, inode))
    elif entry.get("inode") == inode:
        targets.append((path, entry.get("offset", 0), inode))
    else:
        targets.append((path, 0, inode))
    for target, offset, node in targets:
        while stats["lines"] < budget:
            lines, new_offset = read_lines(target, offset, min(BULK_DOCS, budget - stats["lines"]))
            if not lines:
                break
            docs = []
            for line in lines:
                try:
                    converted = to_document(json.loads(line))
                except (ValueError, TypeError, AttributeError):
                    converted = None
                if converted:
                    docs.append(converted)
                else:
                    stats["skipped"] += 1
            if docs:
                ok, bad = send(indexer, docs)
                stats["indexed"] += ok
                stats["failed"] += bad
            stats["lines"] += len(lines)
            offset = new_offset
            if target == path:
                state[str(path)] = {"inode": node, "offset": offset}
            else:
                state[str(path)] = {"inode": node, "offset": offset}
            save(state)
        if target != path:
            if stats["lines"] >= budget:
                return stats
            state[str(path)] = {"inode": inode, "offset": 0}
            save(state)
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--budget", type=int, default=200_000, help="líneas por archivo y pasada")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        state_path = pathlib.Path(config["state_file"])
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        files = state.setdefault("files", {})

        def save(_):
            tmp = state_path.with_name(state_path.name + ".tmp")
            tmp.write_text(json.dumps(state), encoding="utf-8")
            os.replace(tmp, state_path)

        indexer = Indexer(config)
        totals = {"lines": 0, "indexed": 0, "failed": 0, "skipped": 0}
        for name in config["files"]:
            stats = process_file(pathlib.Path(name), files, indexer, args.budget, save)
            for key in totals:
                totals[key] += stats[key]
        state["last_success"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        state["last_run"] = totals
        save(state)
    except (ProviderError, OSError, KeyError, ValueError) as error:
        message = str(error) if isinstance(error, ProviderError) else type(error).__name__
        print(f"b89-cloudflare-index: failed: {message}", file=sys.stderr)
        return 1
    print(f"b89-cloudflare-index: ok indexed={totals['indexed']} failed={totals['failed']} "
          f"skipped={totals['skipped']} lines={totals['lines']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
