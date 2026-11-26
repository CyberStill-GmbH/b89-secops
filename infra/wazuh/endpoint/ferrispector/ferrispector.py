#!/usr/bin/env python3
"""Ferrispector Unix runner. Reads only configured roots and emits redacted JSONL."""
import argparse
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_RULES = {
    "B89_CRED_PRIVATE_KEY_PEM", "B89_CRED_GITHUB_TOKEN", "B89_CRED_SLACK_TOKEN",
    "B89_CRED_GOOGLE_API_KEY", "B89_CRED_AZURE_STORAGE_KEY", "B89_CRED_OPENAI_API_KEY",
}
ALLOWED_RULES = DEFAULT_RULES | {
    "B89_CRED_AWS_ACCESS_KEY_PAIR", "B89_SECRET_DATABASE_CONNECTION",
    "B89_SECRET_CREDENTIAL_ASSIGNMENT", "B89_PII_PERU_DNI_CONTEXTUAL",
    "B89_PII_PERU_RUC_CONTEXTUAL",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_path(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".ferrispector-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def load_json(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def request_json(url, method="GET", token=None, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(1024 * 1024)
    return json.loads(raw.decode("utf-8"))


def read_fingerprints(path):
    result = set()
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            value = line.strip().lower()
            if not value or value.startswith("#"):
                continue
            if not re.fullmatch(r"[a-f0-9]{64}", value) or len(result) >= 100000:
                raise ValueError("fingerprint catalog invalid")
            result.add(value)
    return result


def emit(config, event):
    event.update({"integration": "b89_ferrispector", "observed_at": utc_now()})
    path = Path(config["events_path"])
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def policy_hash(config, enabled, fingerprints, version):
    rules_sha = hashlib.sha256(Path(config["rules_path"]).read_bytes()).hexdigest()
    canonical = "\n".join([rules_sha, version, *sorted(enabled), *sorted(fingerprints)])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def quarantine_exact_file(config, path, expected_hash, info):
    root = Path(config["quarantine_path"])
    objects = root / "objects"
    records = root / "records"
    objects.mkdir(parents=True, exist_ok=True, mode=0o700)
    records.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    os.chmod(objects, 0o700)
    os.chmod(records, 0o700)
    item_id = uuid.uuid4().hex
    object_path = objects / (item_id + ".bin")
    record_path = records / (item_id + ".json")
    temporary = objects / ("." + item_id + ".tmp")
    source = path.resolve(strict=True)
    try:
        if sha256_path(source) != expected_hash:
            return {"status": "failed", "id": None, "code": "FILE_CHANGED"}
        digest = hashlib.sha256()
        with open(source, "rb") as original, os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as copy:
            for chunk in iter(lambda: original.read(1024 * 1024), b""):
                copy.write(chunk)
                digest.update(chunk)
            copy.flush()
            os.fsync(copy.fileno())
        if digest.hexdigest() != expected_hash:
            temporary.unlink(missing_ok=True)
            return {"status": "failed", "id": None, "code": "QUARANTINE_VERIFY_FAILED"}
        os.replace(temporary, object_path)
        manifest = {
            "id": item_id,
            "sha256": expected_hash,
            "original_path": str(source),
            "original_mode": stat.S_IMODE(info.st_mode),
            "original_uid": info.st_uid,
            "original_gid": info.st_gid,
            "file_size_bytes": info.st_size,
            "created_at": utc_now(),
            "state": "pending-delete",
        }
        atomic_json(record_path, manifest)
        current = source.stat(follow_symlinks=False)
        if (sha256_path(source) != expected_hash or current.st_ino != info.st_ino or
                current.st_dev != info.st_dev or current.st_size != info.st_size or current.st_mtime_ns != info.st_mtime_ns):
            object_path.unlink(missing_ok=True)
            record_path.unlink(missing_ok=True)
            return {"status": "failed", "id": None, "code": "FILE_CHANGED"}
        source.unlink()
        manifest["state"] = "quarantined"
        try:
            atomic_json(record_path, manifest)
        except OSError:
            pass  # The pending-delete manifest is already sufficient for recovery.
        return {"status": "quarantined", "id": item_id, "code": "QUARANTINED"}
    except OSError:
        temporary.unlink(missing_ok=True)
        if not record_path.exists():
            object_path.unlink(missing_ok=True)
        return {"status": "failed", "id": None, "code": "QUARANTINE_IO_FAILED"}


def restore_quarantine(config, item_id):
    if not re.fullmatch(r"[a-f0-9]{32}", item_id):
        raise ValueError("quarantine ID invalid")
    root = Path(config["quarantine_path"])
    object_path = root / "objects" / (item_id + ".bin")
    record_path = root / "records" / (item_id + ".json")
    record = load_json(record_path)
    if (record.get("id") != item_id or record.get("state") not in {"pending-delete", "quarantined"}
            or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("sha256", ""))) or not object_path.is_file()):
        raise ValueError("quarantine record invalid")
    if sha256_path(object_path) != record["sha256"]:
        raise ValueError("quarantined file hash mismatch")
    destination = Path(record["original_path"])
    parent = destination.parent
    if not destination.is_absolute() or not parent.is_dir() or parent.is_symlink() or destination.exists() or destination.is_symlink():
        raise FileExistsError("original destination is missing or already occupied")
    # Reject any symlink component so a changed mount/path can't redirect the restore.
    current = parent
    while current != current.parent:
        if current.is_symlink():
            raise ValueError("original destination now traverses a symbolic link")
        current = current.parent
    temporary = parent / (".rabbitdlp-restore-" + item_id + ".tmp")
    try:
        with open(object_path, "rb") as source, os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if sha256_path(temporary) != record["sha256"]:
            raise ValueError("restored copy hash mismatch")
        os.chmod(temporary, int(record["original_mode"]) & 0o777)
        os.chown(temporary, int(record["original_uid"]), int(record["original_gid"]))
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        object_path.unlink()
        record_path.unlink()
        return str(destination)
    finally:
        temporary.unlink(missing_ok=True)


def sync_policy(config, state):
    url = config.get("control_plane_url")
    token = config.get("agent_credential")
    if not url or not token:
        return state
    try:
        policy = request_json(url.rstrip("/") + "/api/dlp/agent/policy", token=token)
        if isinstance(policy.get("policy"), dict):
            policy = policy["policy"]
        revision = policy.get("revision")
        version = policy.get("policyVersion")
        enabled = policy.get("enabledRuleIds")
        fingerprints = policy.get("fingerprintsSha256")
        quarantine = policy.get("quarantineExactFingerprints")
        usb_control = policy.get("usbControl")
        if (not isinstance(revision, int) or revision < 0 or not isinstance(version, str) or len(version) > 64
                or not isinstance(enabled, list) or not isinstance(fingerprints, list)
                or not isinstance(quarantine, bool) or not isinstance(usb_control, dict)
                or not isinstance(usb_control.get("enabled"), bool)
                or not isinstance(usb_control.get("allowedGroups"), list)
                or len(enabled) > len(ALLOWED_RULES) or any(rule not in ALLOWED_RULES for rule in enabled)
                or len(fingerprints) > 100000 or any(not isinstance(item, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", item) for item in fingerprints)):
            raise ValueError("policy invalid")
        enabled = sorted(set(enabled))
        fingerprints = sorted(set(item.lower() for item in fingerprints))
        changed = revision != state.get("revision") or version != state.get("policy_version")
        fingerprint_file = Path(config["fingerprints_path"])
        temp_path = str(fingerprint_file) + ".catalog"
        with open(temp_path, "w", encoding="ascii") as stream:
            stream.write("\n".join(fingerprints) + ("\n" if fingerprints else ""))
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, fingerprint_file)
        state.update({"revision": revision, "policy_version": version, "enabled_rule_ids": enabled,
                      "quarantine_exact_fingerprints": quarantine,
                      "policy_sha256": policy_hash(config, enabled, fingerprints, version)})
        # Rescan before acknowledging: if the ack fails, the next sync sees the same revision as
        # "unchanged", so clearing afterwards would leave files unscanned with the new policy.
        if changed:
            state["files"] = {}
        state["remote_policy_ready"] = True
        request_json(url.rstrip("/") + "/api/dlp/agent/ack", method="POST", token=token,
                     body={"revision": revision, "policyVersion": version,
                           "usbControl": {"status": "not-applicable", "code": "NOT_WINDOWS"}})
        return state
    except Exception:
        emit(config, {"event_type": "policy_sync_error", "error_code": "DLP_POLICY_UNAVAILABLE"})
        return state


def process_file(config, path, state):
    try:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            return
        signature = f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}"
        key = str(path)
        if state.setdefault("files", {}).get(key) == signature:
            return
        if config.get("control_plane_url") and not state.get("remote_policy_ready"):
            return
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        file_hash = digest.hexdigest()
        extension = path.suffix.lower()[:24]
        fingerprint_match = file_hash in read_fingerprints(config["fingerprints_path"])
        fingerprint_event = None
        if fingerprint_match:
            fingerprint_event = {"event_type": "match", "endpoint": platform.node(),
                                 "yara_rule_id": "B89_DLP_EXACT_FILE_FINGERPRINT", "file_sha256": file_hash,
                                 "file_extension": extension, "file_size_bytes": info.st_size,
                                 "policy_sha256": state["policy_sha256"]}
        result = subprocess.run([config["yara_path"], "scan", "--compiled-rules", config["rules_path"],
                                 "--output-format=ndjson", "-m", "-g", str(path)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, check=False)
        if result.returncode:
            emit(config, {"event_type": "scan_error", "file_sha256": file_hash,
                          "file_extension": extension, "error_code": "YARA_X_SCAN_FAILED"})
        else:
            for line in result.stdout.splitlines():
                try:
                    matched = json.loads(line)
                    ids = {item.get("identifier") for item in matched.get("rules", []) if isinstance(item, dict)}
                    for rule_id in sorted(ids & set(state["enabled_rule_ids"])):
                        emit(config, {"event_type": "match", "endpoint": platform.node(),
                                      "yara_rule_id": rule_id, "file_sha256": file_hash,
                                      "file_extension": extension, "file_size_bytes": info.st_size,
                                      "policy_sha256": state["policy_sha256"]})
                except (ValueError, TypeError, AttributeError):
                    emit(config, {"event_type": "scan_error", "file_sha256": file_hash,
                                  "file_extension": extension, "error_code": "YARA_X_OUTPUT_INVALID"})
        if fingerprint_event:
            if state.get("quarantine_exact_fingerprints"):
                result = quarantine_exact_file(config, path, file_hash, info)
                fingerprint_event.update({"quarantine_status": result["status"], "action_code": result["code"]})
                if result["id"]:
                    fingerprint_event["quarantine_id"] = result["id"]
            else:
                fingerprint_event["quarantine_status"] = "disabled"
            emit(config, fingerprint_event)
        state["files"][key] = signature
    except (OSError, ValueError, subprocess.SubprocessError):
        emit(config, {"event_type": "scan_error", "error_code": "FILE_SCAN_FAILED"})


def walk(config, state, tick=lambda: None):
    for root in config["watch_roots"]:
        for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    process_file(config, path, state)
                tick()


def run(config_path):
    if os.geteuid() != 0:
        raise SystemExit("Ferrispector necesita permisos de administrador para ejecutarse como servicio.")
    config = load_json(config_path)
    if config.get("schema_version") != 2:
        raise SystemExit("Configuración v1 reutiliza el token de inscripción; reinstala Ferrispector con un token nuevo.")
    roots = config.get("watch_roots")
    if not isinstance(roots, list) or not roots:
        raise SystemExit("No hay carpetas aprobadas configuradas.")
    for root in roots:
        path = Path(root)
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise SystemExit("Una carpeta aprobada ya no está disponible o no es válida.")
    state_path = Path(config["state_path"])
    try:
        state = load_json(state_path)
    except (OSError, ValueError):
        state = {"files": {}, "revision": 0, "policy_version": "1.0.0",
                 "enabled_rule_ids": sorted(DEFAULT_RULES), "remote_policy_ready": not bool(config.get("control_plane_url"))}
    if not config.get("control_plane_url"):
        fingerprints = read_fingerprints(config["fingerprints_path"])
        state["policy_sha256"] = policy_hash(config, state["enabled_rule_ids"], fingerprints, state.get("policy_version", "1.0.0"))
        state["remote_policy_ready"] = True
    os.umask(0o077)
    last_sync = [0.0]

    def tick():
        # The policy poll is also the heartbeat: keep it every 30 s even during a long walk,
        # otherwise the console shows the endpoint offline after 2 minutes of scanning.
        if config.get("control_plane_url") and time.monotonic() - last_sync[0] >= 30:
            sync_policy(config, state)
            last_sync[0] = time.monotonic()

    while True:
        tick()
        walk(config, state, tick)
        atomic_json(state_path, state)
        time.sleep(30)


def enroll(config_path, url):
    if os.geteuid() != 0:
        raise SystemExit("Ejecuta la instalación como administrador.")
    url = url.rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("La URL del servicio debe ser HTTPS y no incluir credenciales ni parámetros.")
    token = getpass.getpass("Clave de instalación de RabbitDLP (entrada oculta, se usa una vez): ").strip()
    if not token:
        raise SystemExit("No se proporcionó la clave de instalación.")
    agent_id = uuid.uuid4().hex[:16]
    # The server accepts [A-Za-z0-9_.-]{1,128}; a name such as "Ana's MacBook" would be rejected.
    hostname = re.sub(r"[^A-Za-z0-9_.-]", "-", platform.node()).strip("-.")[:128] or "equipo-" + agent_id[:8]
    endpoint_credential = ""
    try:
        response = request_json(url + "/api/dlp/agent/enroll", method="POST", token=token,
                                body={"hostname": hostname, "agentId": agent_id})
        endpoint_credential = response.get("endpointCredential")
        if (not response.get("endpointId") or not isinstance(endpoint_credential, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", endpoint_credential)):
            raise ValueError("enrollment rejected")
        config = load_json(config_path)
        config.update({"schema_version": 2, "control_plane_url": url,
                       "agent_credential": endpoint_credential, "agent_id": agent_id})
        atomic_json(config_path, config)
    except Exception:
        token = ""
        endpoint_credential = ""
        raise SystemExit("No se pudo completar la inscripción. Si el equipo aparece en la consola, revócalo; crea una clave nueva e inténtalo otra vez.")
    token = ""
    endpoint_credential = ""
    print("Equipo inscrito; credencial exclusiva guardada con permisos solo para administrador.")
def main():
    parser = argparse.ArgumentParser(description="RabbitDLP para endpoints de B89")
    sub = parser.add_subparsers(dest="action", required=True)
    initialize = sub.add_parser("init")
    initialize.add_argument("--config", required=True)
    initialize.add_argument("--release", required=True)
    initialize.add_argument("--data", required=True)
    initialize.add_argument("--watch-root", action="append", required=True)
    initialize.add_argument("--control-plane-url")
    service = sub.add_parser("run")
    service.add_argument("--config", required=True)
    enrollment = sub.add_parser("enroll")
    enrollment.add_argument("--config", required=True)
    enrollment.add_argument("--url", required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--config", required=True)
    restore.add_argument("--id", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--config", required=True)
    args = parser.parse_args()
    if args.action == "init":
        if os.geteuid() != 0:
            raise SystemExit("Ejecuta la instalación como administrador.")
        roots = []
        for value in args.watch_root:
            path = Path(value).expanduser()
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise SystemExit("Cada carpeta aprobada debe existir, ser absoluta y no ser un enlace simbólico.")
            roots.append(str(path.resolve(strict=True)))
        if len(set(roots)) != len(roots):
            raise SystemExit("Hay carpetas aprobadas repetidas.")
        data = Path(args.data)
        config = {"schema_version": 2, "rules_path": str(Path(args.release) / "policy/dlp-rules.yarc"),
                  "fingerprints_path": str(data / "fingerprints.sha256"), "events_path": str(data / "events.jsonl"),
                  "state_path": str(data / "state.json"), "quarantine_path": str(data / "quarantine"),
                  "yara_path": str(Path(args.release) / "bin/yr"),
                  "watch_roots": roots, "include_subdirectories": True, "reconcile_interval_minutes": 1}
        import shutil
        shutil.copy2(Path(args.release, 'policy/fingerprints.sha256'), data / 'fingerprints.sha256')
        atomic_json(args.config, config)
        if args.control_plane_url:
            enroll(args.config, args.control_plane_url)
        print("Configuración local creada.")
    elif args.action == "run":
        run(args.config)
    elif args.action == "enroll":
        enroll(args.config, args.url)
    elif args.action == "restore":
        if os.geteuid() != 0:
            raise SystemExit("La restauración necesita permisos de administrador.")
        config = load_json(args.config)
        try:
            print("Restaurado:", restore_quarantine(config, args.id))
        except (OSError, ValueError, KeyError) as error:
            raise SystemExit("No se pudo restaurar el archivo de cuarentena: " + str(error))
    else:
        if os.geteuid() != 0:
            raise SystemExit("La lista de cuarentena requiere permisos de administrador.")
        config = load_json(args.config)
        records = Path(config["quarantine_path"]) / "records"
        if not records.is_dir():
            print("No hay elementos en cuarentena.")
            return
        found = False
        for record_path in sorted(records.glob("*.json")):
            record = load_json(record_path)
            if (not re.fullmatch(r"[a-f0-9]{32}", str(record.get("id", ""))) or
                    not re.fullmatch(r"[a-f0-9]{64}", str(record.get("sha256", "")))):
                raise SystemExit("El registro de cuarentena no es válido.")
            print("\t".join((record["id"], str(record.get("state", "desconocido")),
                             record["sha256"], str(record.get("file_size_bytes", "")),
                             str(record.get("created_at", "")))))
            found = True
        if not found:
            print("No hay elementos en cuarentena.")


if __name__ == "__main__":
    main()
