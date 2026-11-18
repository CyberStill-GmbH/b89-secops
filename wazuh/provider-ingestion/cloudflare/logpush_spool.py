#!/usr/bin/env python3
"""Drain the Cloudflare Logpush spool written by the HTTPS receiver into Wazuh JSONL.

The receiver (receiver/logpush-receiver.mjs) publishes each delivery atomically as
``incoming/<epoch_ms>-<id>.<dataset>.<scope>.ndjson``. This consumer, the single writer of the
output, imports them oldest first through ``logpush.ingest`` (SHA ledger: exact re-deliveries are
suppressed), then moves each object to ``done/`` (kept ``--keep-hours``) or, if the content is
invalid, to ``failed/`` for remediation. A transient error (writer busy, disk) leaves the object in
``incoming/`` for the next run. The state file doubles as the collector heartbeat for the monitor.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "common"))
import logpush  # noqa: E402
from b89_collector import ProviderError, iso, rotate_if_needed, utc_now  # noqa: E402

NAME_RE = re.compile(r"^(\d{13})-([A-Za-z0-9]{8,64})\.([a-z][a-z0-9_]{0,99})\.([A-Za-z0-9_-]{1,128})\.ndjson$")
ROTATE_BYTES = 512 * 1024 * 1024
# Errores de contenido: reintentar no los arregla; el objeto pasa a failed/ sin bloquear la cola.
PERMANENT = (
    "Logpush input must be a regular file",
    "Logpush object exceeds input limit",
    "Logpush gzip object is invalid",
    "Logpush expanded object exceeds input limit",
    "Logpush dataset or scope is invalid",
    "Logpush record exceeds delivery limit",
    "Logpush batch contains an invalid JSON record",
)


def pending(spool: pathlib.Path) -> list[tuple[pathlib.Path, str, str]]:
    items = []
    for path in (spool / "incoming").iterdir():
        match = NAME_RE.match(path.name)
        if match and path.is_file() and not path.is_symlink():
            items.append((path, match.group(3), match.group(4)))
    return sorted(items, key=lambda item: item[0].name)


def move(path: pathlib.Path, folder: pathlib.Path) -> None:
    folder.mkdir(mode=0o750, exist_ok=True)
    os.replace(path, folder / path.name)


def prune(folder: pathlib.Path, keep_seconds: float, now: float) -> None:
    if not folder.is_dir():
        return
    for path in folder.iterdir():
        try:
            if path.is_file() and now - path.stat().st_mtime > keep_seconds:
                path.unlink()
        except OSError:
            pass


def write_heartbeat(path: pathlib.Path, summary: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def drain(spool: pathlib.Path, output: pathlib.Path, ledger: pathlib.Path, heartbeat: pathlib.Path,
          keep_hours: float = 24, limit: int = 500) -> dict:
    started = utc_now()
    counts = {"objects": 0, "events": 0, "failed": 0, "deferred": 0}
    datasets: dict[str, int] = {}
    for path, dataset, scope in pending(spool)[:limit]:
        try:
            committed = logpush.ingest(path, output, ledger, dataset, scope)
        except ProviderError as error:
            if str(error).startswith(PERMANENT):
                move(path, spool / "failed")
                counts["failed"] += 1
                continue
            counts["deferred"] += 1
            break  # orden: no adelantar lotes posteriores a uno pendiente
        move(path, spool / "done")
        counts["objects"] += 1
        counts["events"] += committed
        datasets[dataset] = datasets.get(dataset, 0) + committed
    rotate_if_needed(output, ROTATE_BYTES)
    now = time.time()
    prune(spool / "done", keep_hours * 3600, now)
    prune(spool / "failed", 7 * 86400, now)
    backlog = len(pending(spool))
    previous = {}
    if heartbeat.exists():
        try:
            previous = json.loads(heartbeat.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {}
    summary = {
        "last_run": iso(started),
        # Sin errores transitorios la ejecución cuenta como éxito aunque no hubiera entregas.
        "last_success": iso(started) if counts["deferred"] == 0 else previous.get("last_success"),
        "last_delivery": iso(started) if counts["objects"] else previous.get("last_delivery"),
        "backlog": backlog,
        "run": counts,
        "datasets": datasets or previous.get("datasets", {}),
    }
    write_heartbeat(heartbeat, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--heartbeat", required=True, type=pathlib.Path)
    parser.add_argument("--keep-hours", type=float, default=24)
    args = parser.parse_args()
    try:
        summary = drain(args.spool, args.output, args.ledger, args.heartbeat, args.keep_hours)
    except (ProviderError, OSError) as error:
        message = str(error) if isinstance(error, ProviderError) else type(error).__name__
        print(f"b89-cloudflare-logpush: failed: {message}", file=sys.stderr)
        return 1
    run = summary["run"]
    print(f"b89-cloudflare-logpush: ok objects={run['objects']} events={run['events']} "
          f"failed={run['failed']} backlog={summary['backlog']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
