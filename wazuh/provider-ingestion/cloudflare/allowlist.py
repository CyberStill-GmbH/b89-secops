"""Lista blanca de la API de pagos: veredicto por petición para las reglas 101546-101549.

Regla del dueño (2026-11-23), solo sobre los hosts de la API de pagos (por defecto
``apipayments.b89.io``):

- ``allowed``: la IP de origen está en la lista blanca (cliente, proveedor o infraestructura B89).
- ``client_without_ip``: la petición trae el identificador de un cliente SIN IPs registradas
  («No requiere», «Pendiente»…): no alerta, venga de la IP que venga.
- ``outside``: la petición trae el identificador de un cliente CON IPs y llega desde otra IP:
  alerta crítica.
- ``unknown``: ni la IP ni un identificador son conocidos. Crítica en login, pagos, payins y payouts
  (los clientes sin IP operan por subida de archivos); informativa en el resto.

La lista llega de la API (``GET /api/cloudflare/allowlist/feed``) por ``sync_allowlist.py`` a un
archivo JSON local; si falta o está dañado, no se marca nada (sin veredicto no hay alerta falsa).

Revisión 2 (2026-11-25, reducción de falsos positivos; registro en
docs/detection-engineering/07-ajuste-falsos-positivos.md):

- ``allowlist_sensitive`` mira solo los **segmentos de la ruta** (palabras completas), no la cadena de
  consulta: ``?token=…`` o ``/v1/authors`` ya no convierten una petición en «login o pago».
- Los identificadores de cliente (``markers``) se buscan como palabra completa: ``terrapay`` ya no
  coincide dentro de ``/terrapayments``.
- ``allowlist_effect``: ``accepted`` (1xx-3xx), ``rejected`` (4xx), ``error`` (5xx, cuenta como aceptada),
  ``blocked`` (Cloudflare bloqueó o desafió) o ``unknown`` (sin código). Un sondeo rechazado no es un
  login exitoso.
- ``verified_bot``: una IP desconocida que Cloudflare verificó como bot (buscadores, monitores) deja de
  ser «unknown».
- ``allowlist_first``: ``true`` la primera vez que se ve la misma combinación (veredicto, cliente, IP,
  tipo) en la ventana de deduplicación (``B89_CF_ALLOWLIST_DEDUP_SECONDS``, 3600 s por defecto); las
  repeticiones quedan indexadas con nivel bajo en vez de abrir una alerta crítica por petición.
"""

from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re

# Estado de los colectores en el host (install-b89-collectors.sh): lo escribe el timer de sincronización.
DEFAULT_FILE = "/opt/b89/collectors/state/cloudflare-allowlist.json"
DEFAULT_HOSTS = ("apipayments.b89.io",)
# Palabras de la ruta que marcan login o movimiento de dinero. Se comparan contra los segmentos de la ruta
# separados por cualquier carácter no alfanumérico (y contra la unión de dos segmentos vecinos, para
# ``sign-in`` o ``pay-out``); nunca contra la cadena de consulta.
SENSITIVE_WORDS = frozenset({
    "login", "logout", "signin", "auth", "oauth", "oauth2", "token", "tokens", "session", "sessions",
    "password", "otp", "2fa", "mfa",
    "payment", "payments", "payout", "payouts", "payin", "payins", "transfer", "transfers",
    "withdraw", "withdrawal", "withdrawals", "refund", "refunds", "disburse", "disbursement",
    "disbursements", "charge", "charges", "settlement", "settlements", "balance", "balances",
})
# Acciones de Cloudflare que impiden que la petición llegue al origen (campo SecurityAction).
BLOCKING_ACTIONS = frozenset({
    "block", "challenge", "managed_challenge", "managedchallenge", "jschallenge", "js_challenge",
    "challengefailed", "challenge_failed", "connectionclose", "connection_close", "drop", "ban",
})
DEFAULT_DEDUP_SECONDS = 3600
MAX_DEDUP_KEYS = 50_000

_cache: dict = {"path": None, "mtime": None, "value": None}


class Allowlist:
    def __init__(self, revision: int, entries: list[dict]):
        self.revision = revision
        self.entries = entries
        self.networks: list[tuple] = []
        for entry in entries:
            for value in entry.get("ips", []):
                try:
                    self.networks.append((ipaddress.ip_network(value, strict=False), entry))
                except ValueError:
                    continue

    def owners(self, ip: str) -> list[dict]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        return [entry for network, entry in self.networks if address.version == network.version and address in network]

    def by_marker(self, target: str) -> list[dict]:
        text = (target or "").lower()
        return [entry for entry in self.entries if any(marker_in(marker, text) for marker in entry.get("markers", []))]


def marker_in(marker: str, text: str) -> bool:
    """El identificador aparece como palabra completa (no dentro de otra palabra)."""
    if not marker:
        return False
    return re.search(r"(?<![a-z0-9])" + re.escape(marker) + r"(?![a-z0-9])", text) is not None


def sensitive_path(path: str) -> bool:
    """Login o dinero según los segmentos de la ruta (sin la cadena de consulta)."""
    words = [word for word in re.split(r"[^a-z0-9]+", (path or "").split("?", 1)[0].lower()) if word]
    joined = (a + b for a, b in zip(words, words[1:]))
    return any(word in SENSITIVE_WORDS for word in words) or any(word in SENSITIVE_WORDS for word in joined)


def effect(http: dict) -> str:
    """Qué le pasó a la petición: accepted (1xx-3xx), rejected (4xx), error (5xx: llegó al origen y pudo
    procesarse a medias, cuenta como aceptada), blocked (Cloudflare la detuvo) o unknown (sin código)."""
    if (http.get("security_action") or "").strip().lower() in BLOCKING_ACTIONS:
        return "blocked"
    for name in ("origin_status", "status"):
        raw = (http.get(name) or "").strip()
        if raw.isdigit() and int(raw) >= 100:
            code = int(raw)
            return "accepted" if code < 400 else "rejected" if code < 500 else "error"
    return "unknown"


class Deduper:
    """Primera aparición de una clave en la ventana; el estado vive en el estado del colector."""

    def __init__(self, seen: object, now: float, window: int = DEFAULT_DEDUP_SECONDS):
        self.window = window
        self.now = now
        items = seen.items() if isinstance(seen, dict) else ()
        self.seen = {
            key: stamp for key, stamp in items
            if isinstance(key, str) and isinstance(stamp, (int, float)) and 0 <= now - stamp < window
        }

    def first(self, key: str) -> bool:
        if key in self.seen:
            return False
        self.seen[key] = self.now
        return True

    def export(self) -> dict:
        if len(self.seen) <= MAX_DEDUP_KEYS:
            return dict(self.seen)
        return dict(sorted(self.seen.items(), key=lambda item: item[1])[-MAX_DEDUP_KEYS:])


def dedup_window() -> int:
    raw = os.environ.get("B89_CF_ALLOWLIST_DEDUP_SECONDS", "")
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_DEDUP_SECONDS


def parse(document: object) -> Allowlist | None:
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        return None
    entries = []
    for raw in document["entries"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            continue
        entries.append({
            "id": str(raw.get("id", "")),
            "name": raw["name"][:120],
            "status": str(raw.get("status", "")),
            "ips": [str(ip) for ip in raw.get("ips", []) if isinstance(ip, str)][:50],
            "markers": [str(m).lower() for m in raw.get("markers", []) if isinstance(m, str) and len(m) >= 3][:10],
        })
    revision = document.get("revision")
    return Allowlist(revision if isinstance(revision, int) else 0, entries)


def load(path: str | None = None) -> Allowlist | None:
    """Lee el archivo y lo cachea por fecha de modificación."""
    path = path or os.environ.get("B89_CF_ALLOWLIST_FILE", DEFAULT_FILE)
    try:
        mtime = pathlib.Path(path).stat().st_mtime_ns
    except OSError:
        return None
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["value"]
    try:
        value = parse(json.loads(pathlib.Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        value = None
    _cache.update({"path": path, "mtime": mtime, "value": value})
    return value


def hosts() -> tuple:
    raw = os.environ.get("B89_CF_ALLOWLIST_HOSTS")
    if not raw:
        return DEFAULT_HOSTS
    return tuple(host.strip().lower() for host in raw.split(",") if host.strip())


def classify(http: dict, allowlist: Allowlist | None, watched_hosts: tuple = DEFAULT_HOSTS,
             deduper: Deduper | None = None) -> dict | None:
    """Campos ``allowlist_*`` para ``cloudflare.http``, o None si la petición no se vigila."""
    if allowlist is None:
        return None
    if (http.get("host") or "").lower() not in watched_hosts:
        return None
    if (http.get("method") or "").upper() == "OPTIONS":
        return None
    target = http.get("request_target") or (http.get("path") or "")
    sensitive = sensitive_path(http.get("path") or target)
    result = effect(http)
    client_ip = http.get("client_ip") or ""
    owners = allowlist.owners(client_ip)
    marked = allowlist.by_marker(target)
    claimed_with_ip = [entry for entry in marked if entry["status"] == "with_ip" and entry["ips"]]
    foreign = [entry for entry in claimed_with_ip if entry not in owners]
    if foreign:
        verdict, client = "outside", foreign[0]["name"]
    elif owners:
        verdict, client = "allowed", owners[0]["name"]
    elif marked:
        verdict, client = "client_without_ip", marked[0]["name"]
    elif (http.get("verified_bot_category") or "").strip():
        verdict, client = "verified_bot", ""
    else:
        verdict, client = "unknown", ""
    fields = {
        "allowlist_verdict": verdict,
        "allowlist_sensitive": "true" if sensitive else "false",
        "allowlist_effect": result,
        "allowlist_revision": str(allowlist.revision),
    }
    if client:
        fields["allowlist_client"] = client
    if verdict in ("outside", "unknown"):
        # Una alerta por (veredicto, cliente, IP, tipo) y ventana; sin deduplicador, siempre primera.
        passed = result in ("accepted", "error", "unknown")
        kind = ("sensitive-" if sensitive else "other-") + ("passed" if passed else "stopped")
        key = "|".join((verdict, client, client_ip, kind))
        fields["allowlist_first"] = "true" if deduper is None or deduper.first(key) else "false"
    return fields
