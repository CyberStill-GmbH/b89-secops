#!/usr/bin/env python3
"""Shared runtime for the B89 read-only provider collectors (Bitdefender, Snyk, Cloudflare).

Contract shared with ``cato/events_feed.py``:

- Secrets are read from local files only (0600, never symlinks) and never printed.
- Output is JSONL appended with ``fsync``; Wazuh reads it via ``<localfile log_format="json">``.
- The cursor/state is committed with a write-ahead checkpoint: before appending, the state file
  records ``{offset, length, sha256, next}`` of the batch. On restart a complete durable batch is
  recognised and the cursor advances without a second append; a partial batch is truncated back
  to its offset and fetched again from the unchanged cursor.
- Errors are reported with a generic message and, at most, the HTTP status code. Provider
  response bodies are not logged: they can echo request headers or tenant data.

Runs on the Wazuh manager's bundled Python (3.10) or any CPython >= 3.10; stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_BATCH_BYTES = 64 * 1024 * 1024
DEFAULT_ROTATE_BYTES = 256 * 1024 * 1024
USER_AGENT = "b89-soc-collector/1.0"

# Source-health heartbeat (docs/20 «Salud por fuente»). One event per run, in the same JSONL as the
# data, so its arrival proves collector → logcollector → analysisd → indexer even with zero events.
COLLECTOR_VERSION = "2026.11.17"
HEARTBEAT_SCHEMA = 1
HEARTBEAT_EVENT_TYPE = "source_heartbeat"
AUTH_STATES = ("ok", "denied", "expired", "unknown")
RUN_OUTCOMES = ("ok", "partial", "failed")
# Sanitized error enum: the heartbeat never carries free text, provider bodies, URLs or secrets.
ERROR_CODES = (
    "auth_denied", "auth_expired", "rate_limited", "provider_server_error", "provider_client_error",
    "network", "invalid_response", "config_invalid", "secret_unavailable", "local_io",
    "recovery_stalled", "pagination_limit", "unknown",
)


class ProviderError(Exception):
    """A connector failure that is safe to report (no secrets, no provider payload).

    ``code`` is an optional member of ``ERROR_CODES``; ``auth`` (``denied``/``expired``) is set
    when the provider answered that the credential or its permission was refused.
    """

    def __init__(self, message: str, status: int | None = None, code: str | None = None,
                 auth: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code if code in ERROR_CODES else None
        self.auth = auth if auth in ("denied", "expired") else None


# Last HTTP status seen by ``http_json`` in this process (reset per run by ``run_collector``).
RUN_HTTP = {"last_status": None}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def read_secret(path: pathlib.Path) -> str:
    """Read one secret value from a restricted local file."""
    if path.is_symlink():
        raise ProviderError("secret file is invalid")
    try:
        metadata = path.stat()
    except OSError as error:
        raise ProviderError("secret file is missing") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ProviderError("secret file is invalid")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise ProviderError("secret file permissions are too open (expected 0600)")
    value = path.read_text(encoding="utf-8").strip()
    if not value or len(value) > 8192 or any(char in value for char in "\r\n\x00"):
        raise ProviderError("secret file content is invalid")
    return value


def load_config(path: pathlib.Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProviderError("collector configuration is unreadable") from error
    if not isinstance(raw, dict):
        raise ProviderError("collector configuration is invalid")
    return raw


# --------------------------------------------------------------------------- HTTP


def http_json(
    method: str,
    url: str,
    headers: dict[str, str],
    body: object | None = None,
    timeout: float = 30,
    opener=None,
) -> tuple[int, object]:
    """Call a JSON API over HTTPS. Returns ``(status, payload)``; raises on transport errors.

    HTTP error statuses are returned (not raised) so callers can map 401/403/429 explicitly;
    the error body is parsed but callers must not log it.
    """
    if not url.startswith("https://"):
        raise ProviderError("provider endpoint must be https")
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    headers = dict(headers)
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", headers.pop("Accept", "application/json"))
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        request.add_header(name, value)
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        try:
            raw = error.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            raw = b""
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ProviderError("provider request failed (network)", code="network") from error
    RUN_HTTP["last_status"] = status
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError("provider response is too large", status)
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if status >= 400:
            return status, None
        raise ProviderError("provider response is not JSON", status) from error


# --------------------------------------------------------------------------- state


def read_state(path: pathlib.Path) -> dict:
    if path.is_symlink():
        raise ProviderError("local state is invalid")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        raise ProviderError("local state is invalid") from error
    if not isinstance(raw, dict):
        raise ProviderError("local state is invalid")
    pending = raw.get("pending")
    if pending is not None and (
        not isinstance(pending, dict)
        or type(pending.get("offset")) is not int
        or pending["offset"] < 0
        or type(pending.get("length")) is not int
        or not 0 < pending["length"] <= MAX_BATCH_BYTES
        or not isinstance(pending.get("sha256"), str)
        or len(pending["sha256"]) != 64
        or not isinstance(pending.get("next"), dict)
    ):
        raise ProviderError("local pending batch state is invalid")
    return raw


def save_state(path: pathlib.Path, state: dict) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".b89-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), 0o640)
            json.dump(state, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# --------------------------------------------------------------------------- JSONL


def serialize_events(events: list[dict]) -> bytes:
    return b"".join(
        (json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        for event in events
    )


def output_size(path: pathlib.Path) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return 0
    if not stat.S_ISREG(metadata.st_mode):
        raise ProviderError("local event output is not a regular file")
    return metadata.st_size


def append_bytes(path: pathlib.Path, payload: bytes) -> None:
    if not payload:
        return
    if path.is_symlink():
        raise ProviderError("local event output is invalid")
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o640)
    with os.fdopen(fd, "ab") as stream:
        view = memoryview(payload)
        while view:
            written = stream.write(view)
            if written is None or written <= 0:
                raise OSError("short write to local event output")
            view = view[written:]
        stream.flush()
        os.fsync(stream.fileno())


def recover_pending(output: pathlib.Path, state_path: pathlib.Path, state: dict) -> tuple[dict, bool]:
    """Resolve a write-ahead checkpoint left by an interrupted run."""
    pending = state.get("pending")
    if pending is None:
        return state, False
    size = output_size(output)
    offset, length = pending["offset"], pending["length"]
    if size < offset:
        raise ProviderError("local event output changed during a pending batch")
    if size == offset + length:
        with output.open("rb") as stream:
            stream.seek(offset)
            written = stream.read(length)
        if len(written) == length and hashlib.sha256(written).hexdigest() == pending["sha256"]:
            committed = dict(pending["next"])
            save_state(state_path, committed)
            return committed, True
    if size > offset + length:
        raise ProviderError("local event output has unexpected data after a pending batch")
    if output.exists():
        with output.open("r+b") as stream:
            stream.truncate(offset)
            stream.flush()
            os.fsync(stream.fileno())
    rolled_back = {key: value for key, value in state.items() if key != "pending"}
    save_state(state_path, rolled_back)
    return rolled_back, False


def rotate_if_needed(output: pathlib.Path, limit: int) -> None:
    """Keep one previous generation; Wazuh logcollector follows the new inode."""
    if output_size(output) > limit:
        os.replace(output, output.with_name(output.name + ".1"))


def commit_batch(output: pathlib.Path, state_path: pathlib.Path, state: dict, events: list[dict], next_state: dict) -> int:
    """Append ``events`` durably, then advance the state to ``next_state``."""
    payload = serialize_events(events)
    if len(payload) > MAX_BATCH_BYTES:
        raise ProviderError("provider event batch is too large")
    if not payload:
        save_state(state_path, next_state)
        return 0
    offset = output_size(output)
    pending = {
        "offset": offset,
        "length": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "next": next_state,
    }
    checkpoint = {key: value for key, value in state.items() if key != "pending"}
    checkpoint["pending"] = pending
    save_state(state_path, checkpoint)
    append_bytes(output, payload)
    save_state(state_path, next_state)
    return len(events)


def catchup_status(config: dict, previous: dict, current: dict, target: datetime) -> dict | None:
    """Only watermark cursors opt in. Last-event timestamps cannot prove coverage."""
    field = config.get("catchup_cursor_field")
    if not field:
        return None
    cursors = current.get(field)
    if not isinstance(cursors, dict) or not cursors:
        raise ProviderError("recovery watermark is unavailable")
    before = previous.get(field) or {}
    parsed = {key: parse_iso(value) for key, value in cursors.items()}
    if any(key in before and value < parse_iso(before[key]) for key, value in parsed.items()):
        raise ProviderError("recovery watermark regressed; checkpoint preserved")
    if any(key not in parsed for key in before):
        raise ProviderError("recovery stream disappeared; checkpoint preserved")
    lag = max(0, int((target - min(parsed.values())).total_seconds()))
    progress = not before or any(key not in before or value > parse_iso(before[key]) for key, value in parsed.items())
    return {"status": "caught_up" if lag == 0 else "catching_up" if progress else "stalled",
            "lag_seconds": lag, "target": iso(target), "streams": len(parsed)}


def http_status_class(status: object) -> str:
    """``2xx``/``3xx``/``4xx``/``5xx`` or ``none`` when no HTTP response was received."""
    if type(status) is not int or not 100 <= status <= 599:
        return "none"
    return f"{status // 100}xx"


def classify_failure(error: BaseException) -> tuple[str, str]:
    """``(auth, error_code)`` for a failed run. Uses only the status and our own messages."""
    if isinstance(error, ProviderError):
        status = error.status
        if error.auth == "expired":
            return "expired", "auth_expired"
        if error.auth == "denied" or status in (401, 403):
            return "denied", "auth_denied"
        if error.code:
            return "unknown", error.code
        if status == 429:
            return "unknown", "rate_limited"
        if type(status) is int and status >= 500:
            return "unknown", "provider_server_error"
        if type(status) is int and status >= 400:
            return "unknown", "provider_client_error"
        message = str(error).lower()
        for needle, code in (
            ("secret", "secret_unavailable"), ("configuration", "config_invalid"), ("local", "local_io"),
            ("recovery", "recovery_stalled"), ("pagination", "pagination_limit"), ("not json", "invalid_response"),
            ("too large", "invalid_response"), ("invalid", "invalid_response"),
        ):
            if needle in message:
                return "unknown", code
        return "unknown", "unknown"
    if isinstance(error, OSError):
        return "unknown", "local_io"
    return "unknown", "unknown"


_VOLATILE_STATE_KEYS = frozenset({"last_success", "recovery", "pending", "coverage"})


def cursor_advanced(previous: dict, current: dict) -> bool:
    """True when the persisted cursor/dedupe state moved (volatile bookkeeping excluded)."""
    def view(state: dict) -> dict:
        return {key: value for key, value in state.items() if key not in _VOLATILE_STATE_KEYS}
    return view(previous) != view(current)


def oldest_cursor(*fields: str):
    """Watermark helper: the oldest ISO timestamp among the cursor maps named by ``fields``."""
    def position(state: dict) -> str | None:
        values = []
        for field in fields:
            cursors = state.get(field)
            if isinstance(cursors, dict):
                for value in cursors.values():
                    try:
                        values.append(parse_iso(str(value)))
                    except ValueError:
                        continue
        return iso(min(values)) if values else None
    return position


def heartbeat_event(*, source_id: str, vendor: str, source: str, run_id: str, started: datetime,
                    finished: datetime, outcome: str, auth: str, http_class: str, items: int,
                    advanced: bool, position: str | None = None, lag_seconds: int | None = None,
                    error_code: str | None = None, extra: dict | None = None) -> dict:
    """The structured heartbeat (allowlisted fields only: no URLs, tokens or provider text)."""
    heartbeat = {
        "schema": HEARTBEAT_SCHEMA,
        "source_id": source_id,
        "run_id": run_id,
        "started_at": iso(started),
        "finished_at": iso(finished),
        "outcome": outcome if outcome in RUN_OUTCOMES else "failed",
        "auth": auth if auth in AUTH_STATES else "unknown",
        "http_status_class": http_class,
        "items_fetched": max(0, int(items)),
        "cursor_advanced": bool(advanced),
        "collector_version": COLLECTOR_VERSION,
    }
    if position:
        heartbeat["cursor_position"] = position
    if lag_seconds is not None:
        heartbeat["provider_lag_seconds"] = max(0, int(lag_seconds))
    if error_code:
        heartbeat["error_code"] = error_code if error_code in ERROR_CODES else "unknown"
    if extra:
        heartbeat.update(extra)
    return {"b89": {"vendor": vendor, "source": source, "event_type": HEARTBEAT_EVENT_TYPE,
                    "collected_at": iso(finished), "heartbeat": heartbeat}}


def emit_heartbeat(config: dict | None, event: dict, name: str) -> bool:
    """Append the heartbeat to the collector's own JSONL, never over a pending batch."""
    if not config or config.get("heartbeat", True) is False:
        return False
    try:
        output = pathlib.Path(config["output_file"])
        state = read_state(pathlib.Path(config["state_file"]))
        if state.get("pending") is not None:
            # Appending now would break the write-ahead recovery of the interrupted batch.
            print(f"{name}: heartbeat skipped (pending batch)", file=sys.stderr)
            return False
        append_bytes(output, serialize_events([event]))
        return True
    except (ProviderError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"{name}: heartbeat not written ({type(error).__name__})", file=sys.stderr)
        return False


def run_collector(name: str, config_path: pathlib.Path, collect, *, source_id: str | None = None,
                  vendor: str | None = None, source: str | None = None, probe=None, watermark=None) -> int:
    """Generic driver. ``collect(config, state) -> (events, next_state)``.

    ``probe(config)`` is an optional cheap read-only auth/permission check that runs before
    collecting; it raises ``ProviderError`` (with ``auth``) when the credential is refused.
    ``watermark(state)`` returns the cursor position (ISO) for the heartbeat. Every run ends
    with one heartbeat appended to the same JSONL, whatever the outcome.
    """
    RUN_HTTP["last_status"] = None
    source_id = source_id or name.removeprefix("b89-")
    started = utc_now()
    run = {"outcome": "failed", "auth": "unknown", "items": 0, "advanced": False, "position": None,
           "lag": None, "error_code": None}
    config = None
    try:
        config = load_config(config_path)
        output = pathlib.Path(config["output_file"])
        state_path = pathlib.Path(config["state_file"])
        state = read_state(state_path)
        state, recovered = recover_pending(output, state_path, state)
        if recovered:
            print(f"{name}: recovered a durable batch from the previous run", file=sys.stderr)
            run["outcome"] = "ok"
            run["position"] = watermark(state) if watermark else None
            return 0
        rotate_if_needed(output, int(config.get("rotate_bytes", DEFAULT_ROTATE_BYTES)))
        batches = int(config.get("catchup_max_batches", 4)) if config.get("catchup_cursor_field") else 1
        if not 1 <= batches <= 10:
            raise ProviderError("recovery batch limit must be between 1 and 10", code="config_invalid")
        delay = int(config.get("catchup_delay_seconds", 120))
        if not 0 <= delay <= 86400:
            raise ProviderError("recovery delay is invalid", code="config_invalid")
        if probe is not None:
            probe(config)
            run["auth"] = "ok"
        target = utc_now() - timedelta(seconds=delay)
        recovery = None
        for _ in range(batches):
            events, next_state = collect(config, state)
            # A successful authenticated read proves the credential, with or without a probe.
            run["auth"] = "ok"
            next_state = {key: value for key, value in next_state.items() if key != "pending"}
            recovery = catchup_status(config, state, next_state, target)
            if recovery:
                next_state["recovery"] = recovery
            next_state["last_success"] = iso(utc_now())
            written = commit_batch(output, state_path, state, events, next_state)
            run["items"] += written
            run["advanced"] = run["advanced"] or cursor_advanced(state, next_state)
            state = next_state
            print(f"{name}: ok events={written}" + (f" recovery={recovery['status']} lag_seconds={recovery['lag_seconds']}" if recovery else ""), file=sys.stderr)
            if not recovery or recovery["status"] == "caught_up":
                break
            if recovery["status"] == "stalled":
                run["lag"] = recovery["lag_seconds"]
                raise ProviderError("recovery stalled; retained cursor requires investigation", code="recovery_stalled")
        run["position"] = watermark(state) if watermark else None
        if recovery:
            run["lag"] = recovery["lag_seconds"]
        run["outcome"] = "partial" if recovery and recovery["status"] != "caught_up" else "ok"
        return 0
    except ProviderError as error:
        status = f" (HTTP {error.status})" if error.status else ""
        print(f"{name}: poll failed: {error}{status}; cursor preserved", file=sys.stderr)
        auth, run["error_code"] = classify_failure(error)
        if auth != "unknown" or run["auth"] != "ok":
            run["auth"] = auth
        # Earlier batches of this run were committed: the run moved, but did not finish.
        run["outcome"] = "partial" if run["items"] or run["advanced"] else "failed"
        return 1
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"{name}: poll failed ({type(error).__name__}); cursor preserved", file=sys.stderr)
        _, run["error_code"] = classify_failure(error)
        run["outcome"] = "partial" if run["items"] or run["advanced"] else "failed"
        return 1
    finally:
        finished = utc_now()
        emit_heartbeat(config, heartbeat_event(
            source_id=source_id, vendor=vendor or source_id, source=source or "collector",
            run_id=f"{source_id}-{finished.strftime('%Y%m%dT%H%M%SZ')}-{os.urandom(3).hex()}",
            started=started, finished=finished, outcome=run["outcome"], auth=run["auth"],
            http_class=http_status_class(RUN_HTTP["last_status"]), items=run["items"],
            advanced=run["advanced"], position=run["position"], lag_seconds=run["lag"],
            error_code=run["error_code"]), name)


def bounded_ids(values, limit: int) -> list:
    """Keep the most recent ``limit`` dedupe keys (insertion order)."""
    values = list(dict.fromkeys(values))
    return values[-limit:]
