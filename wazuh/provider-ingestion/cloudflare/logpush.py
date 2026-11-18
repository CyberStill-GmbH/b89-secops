#!/usr/bin/env python3
"""Durably import a trusted local Cloudflare Logpush NDJSON/gzip object.

This is a spool consumer, not an HTTP receiver. The delivery service must atomically
publish complete files and invoke one writer per output. Objects are never deleted.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
from b89_collector import ProviderError, commit_batch, iso, read_state, recover_pending, utc_now

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 60_000
# Lotes ya confirmados que se recuerdan para suprimir reenvíos exactos (Logpush entrega cada pocos
# minutos por job: sin tope el estado crecería sin límite).
MAX_LEDGER = 20_000
# Cloudflare valida un destino HTTP enviando este objeto: no es un registro del conjunto de datos.
VALIDATION_RECORD = {"content": "tests"}

HTTP_FIELDS = {
    "ClientIP": "client_ip", "ClientCountry": "country", "ClientASN": "asn", "ClientASNDescription": "asn_name",
    "ClientRequestHost": "host", "ClientRequestMethod": "method", "ClientRequestPath": "path",
    "ClientRequestURI": "uri", "ClientRequestProtocol": "protocol", "ClientRequestUserAgent": "user_agent",
    "ClientRequestReferer": "referer", "EdgeResponseStatus": "status", "OriginResponseStatus": "origin_status",
    "EdgeStartTimestamp": "datetime", "RayID": "ray", "CacheCacheStatus": "cache", "SecurityAction": "security_action",
    "SecuritySource": "security_source", "BotScore": "bot_score", "WAFAttackScore": "waf_attack_score",
    "EdgeResponseBytes": "bytes", "ClientSSLProtocol": "tls",
}
DNS_FIELDS = {
    "Timestamp": "datetime", "QueryName": "query", "QueryType": "query_type", "ResponseCode": "response_code",
    "SourceIP": "client_ip", "ColoCode": "colo", "EDNSSubnet": "edns_subnet", "ResponseCached": "cached",
}
FIREWALL_FIELDS = {
    "Action": "action", "Source": "source", "Datetime": "datetime",
    "ClientIP": "client_ip", "ClientCountry": "country", "ClientASN": "asn",
    "ClientRequestHost": "host", "ClientRequestPath": "path",
    "ClientRequestMethod": "method", "RayID": "ray", "RuleID": "rule_id",
    "Description": "rule_description", "UserAgent": "user_agent",
    "EdgeResponseStatus": "status",
}
# dataset → (event_type, sección normalizada, campos)
DATASETS = {
    "firewall_events": ("firewall", "firewall", FIREWALL_FIELDS),
    "http_requests": ("http", "http", HTTP_FIELDS),
    "dns_logs": ("dns", "dns", DNS_FIELDS),
}


def read_batch(path: pathlib.Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ProviderError("Logpush input must be a regular file")
    with path.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ProviderError("Logpush object exceeds input limit; split upstream")
    if raw.startswith(b"\x1f\x8b"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
                raw = source.read(MAX_INPUT_BYTES + 1)
        except (OSError, EOFError) as error:
            raise ProviderError("Logpush gzip object is invalid") from error
    if len(raw) > MAX_INPUT_BYTES:
        raise ProviderError("Logpush expanded object exceeds input limit; split upstream")
    return raw


def normalize(record: dict, dataset: str, scope: str, batch: str, now: str) -> dict:
    event = {
        "b89": {"vendor": "cloudflare", "source": "logpush", "event_type": "logpush", "collected_at": now},
        "cloudflare": {"dataset": dataset, "scope_id": scope, "batch_sha256": batch, "raw": record},
    }
    known = DATASETS.get(dataset)
    if known:
        event_type, section, names = known
        event["b89"]["event_type"] = event_type
        event["cloudflare"][section] = {
            dest: str(record[source]) for source, dest in names.items() if record.get(source) is not None
        }
    return event


def ingest(path: pathlib.Path, output: pathlib.Path, state_path: pathlib.Path, dataset: str, scope: str) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.with_name(output.name + ".lock")
    if lock.is_symlink():
        raise ProviderError("Logpush output lock is invalid")
    with lock.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0, 2)
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise ProviderError("Logpush output writer is busy; retry batch") from error
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise ProviderError("Logpush output writer is busy; retry batch") from error
        try:
            return _ingest(path, output, state_path, dataset, scope)
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def _ingest(path: pathlib.Path, output: pathlib.Path, state_path: pathlib.Path, dataset: str, scope: str) -> int:
    """One serialized writer; retained SHA ledger suppresses exact batch replays."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", dataset) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scope):
        raise ProviderError("Logpush dataset or scope is invalid")
    paths = [item.resolve() for item in (path, output, state_path)]
    if len(set(paths)) != 3:
        raise ProviderError("Logpush input, output and state must be distinct")
    raw = read_batch(path)
    digest = hashlib.sha256(raw).hexdigest()
    key = f"{scope}:{dataset}:{digest}"
    state = read_state(state_path)
    binding = str(output.resolve())
    if state.get("output", binding) != binding:
        raise ProviderError("Logpush state belongs to another output")
    state, _ = recover_pending(output, state_path, state)
    committed = state.get("batches", [])
    if not isinstance(committed, list) or any(not isinstance(item, str) for item in committed):
        raise ProviderError("Logpush batch ledger is invalid")
    if key in committed:
        return 0
    now = iso(utc_now())
    events = []
    try:
        for line in raw.decode("utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line, object_pairs_hook=unique_object,
                                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(record, dict):
                raise ValueError()
            if record == VALIDATION_RECORD:
                continue
            event = normalize(record, dataset, scope, digest, now)
            if len(json.dumps(event, ensure_ascii=False).encode("utf-8")) > MAX_RECORD_BYTES:
                raise ProviderError("Logpush record exceeds delivery limit; retained for remediation")
            events.append(event)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ProviderError("Logpush batch contains an invalid JSON record; no records committed") from error
    return commit_batch(output, state_path, state, events, {
        "output": binding, "batches": (committed + [key])[-MAX_LEDGER:], "last_success": now,
    })


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--state", required=True, type=pathlib.Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--scope-id", required=True)
    args = parser.parse_args()
    try:
        count = ingest(args.input, args.output, args.state, args.dataset, args.scope_id)
        print(f"b89-cloudflare-logpush: committed events={count}", file=sys.stderr)
        return 0
    except (ProviderError, OSError) as error:
        # Never print object content, filenames or provider secrets.
        message = str(error) if isinstance(error, ProviderError) else type(error).__name__
        print(f"b89-cloudflare-logpush: failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
