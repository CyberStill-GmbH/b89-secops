#!/usr/bin/env python3
"""Recover a fixed Cloudflare interval into isolated JSONL, never live cursors.

Run a single writer. Audit and adaptive firewall coverage is not all-dataset
coverage. Output requires subsequent verified ingestion into Wazuh.
"""
from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import security as cf
from b89_collector import commit_batch, read_state, recover_pending, save_state


def recover(config, since, until, output, state_path, client=None, mark_history=False):
    if since >= until:
        raise cf.ProviderError("Recovery interval must be increasing")
    protected = [pathlib.Path(config[key]).resolve() for key in ("output_file", "state_file", "token_file") if config.get(key)]
    if output.resolve() == state_path.resolve() or output.resolve() in protected or state_path.resolve() in protected:
        raise cf.ProviderError("Recovery output and state must be isolated from live files")
    binding = {"since": cf.iso(since), "until": cf.iso(until), "output": str(output.resolve())}
    state = read_state(state_path)
    if state and state.get("recovery") != binding:
        raise cf.ProviderError("Recovery state belongs to another interval or output")
    state, _ = recover_pending(output, state_path, state)
    state.setdefault("recovery", binding)
    state.setdefault("streams", {})
    client = client or cf.Cloudflare(cf.read_secret(pathlib.Path(config["token_file"])))
    failures = []

    def commit(stream, events, cursor, done=False):
        nonlocal state
        if mark_history:
            # Reglas 101508/101509: visibles a nivel 3, sin disparar avisos ni investigaciones de hoy.
            for event in events:
                event.setdefault("b89", {})["history"] = True
        next_state = copy.deepcopy(state)
        previous = next_state["streams"].get(stream, {})
        next_state["streams"][stream] = {"cursor": cf.iso(cursor), "done": done,
            "events": previous.get("events", 0) + len(events)}
        commit_batch(output, state_path, state, events, next_state)
        state = next_state
        print(json.dumps({"stream": stream, **state["streams"][stream]}), flush=True)

    if config.get("audit", True):
        try:
            accounts = config.get("account_ids") or [a["id"] for a in cf.discover(client, "accounts")]
        except cf.ProviderError as error:
            accounts = []
            failures.append({"stream": "audit:discovery", "error": str(error)})
        for account in accounts:
            stream = "audit:" + account
            if state["streams"].get(stream, {}).get("done"):
                continue
            try:
                events, _, _ = cf.collect_audit(client, account, cf.iso(since), set(), cf.iso(cf.utc_now()))
                events = [event for event in events if since <= cf.parse_iso(event["cloudflare"]["audit"]["when"]) < until]
                commit(stream, events, until, True)
            except cf.ProviderError as error:
                failures.append({"stream": stream, "error": str(error)})

    if config.get("firewall", True):
        try:
            zones = cf.discover(client, "zones")
            if config.get("zone_ids"):
                wanted = set(config["zone_ids"])
                zones = [z for z in zones if z["id"] in wanted]
                for missing in wanted - {z["id"] for z in zones}:
                    failures.append({"stream": "firewall:" + missing, "error": "Configured zone inaccessible"})
        except cf.ProviderError as error:
            zones = []
            failures.append({"stream": "firewall:discovery", "error": str(error)})
        for zone in zones:
            stream = "firewall:" + zone["id"]
            cursor = cf.parse_iso(state["streams"].get(stream, {}).get("cursor", cf.iso(since)))
            try:
                while cursor < until:
                    events, next_cursor, _ = cf.collect_firewall(client, zone, cursor, until, set(), cf.iso(cf.utc_now()))
                    if not cursor < next_cursor <= until:
                        raise cf.ProviderError("Recovery made no progress; checkpoint preserved")
                    commit(stream, events, next_cursor, next_cursor == until)
                    cursor = next_cursor
            except cf.ProviderError as error:
                failures.append({"stream": stream, "error": str(error)})

    state["coverage"] = {"exhaustive": False, "mode": "audit_and_adaptive_firewall",
        "failures": failures, "requested_streams_finished": not failures}
    save_state(state_path, state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--state", required=True, type=pathlib.Path)
    parser.add_argument("--mark-history", action="store_true",
                        help="marca b89.history=true (recuperación de días pasados que no debe alertar como actual)")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8-sig"))
        result = recover(config, cf.parse_iso(args.since), cf.parse_iso(args.until), args.output, args.state,
                         mark_history=args.mark_history)
        print(json.dumps(result["coverage"]))
        return 0 if result["coverage"]["requested_streams_finished"] else 2
    except (cf.ProviderError, OSError, ValueError) as error:
        print(str(error) if isinstance(error, cf.ProviderError) else type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
