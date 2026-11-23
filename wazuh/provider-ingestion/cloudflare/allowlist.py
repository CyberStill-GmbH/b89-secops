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
SENSITIVE = re.compile(
    r"(login|logout|signin|sign-in|auth|oauth|token|session|password|otp|2fa|mfa"
    r"|payment|payout|payin|pay-out|pay-in|transfer|withdraw|refund|disburse|charge|settlement|balance)",
    re.IGNORECASE,
)

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
        return [entry for entry in self.entries if any(marker and marker in text for marker in entry.get("markers", []))]


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


def classify(http: dict, allowlist: Allowlist | None, watched_hosts: tuple = DEFAULT_HOSTS) -> dict | None:
    """Campos ``allowlist_*`` para ``cloudflare.http``, o None si la petición no se vigila."""
    if allowlist is None:
        return None
    if (http.get("host") or "").lower() not in watched_hosts:
        return None
    if (http.get("method") or "").upper() == "OPTIONS":
        return None
    target = http.get("request_target") or (http.get("path") or "")
    sensitive = bool(SENSITIVE.search(target))
    owners = allowlist.owners(http.get("client_ip") or "")
    marked = allowlist.by_marker(target)
    claimed_with_ip = [entry for entry in marked if entry["status"] == "with_ip" and entry["ips"]]
    foreign = [entry for entry in claimed_with_ip if entry not in owners]
    if foreign:
        verdict, client = "outside", foreign[0]["name"]
    elif owners:
        verdict, client = "allowed", owners[0]["name"]
    elif marked:
        verdict, client = "client_without_ip", marked[0]["name"]
    else:
        verdict, client = "unknown", ""
    fields = {
        "allowlist_verdict": verdict,
        "allowlist_sensitive": "true" if sensitive else "false",
        "allowlist_revision": str(allowlist.revision),
    }
    if client:
        fields["allowlist_client"] = client
    return fields
