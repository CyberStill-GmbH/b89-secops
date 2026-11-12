#!/var/ossec/framework/python/bin/python3
"""Integración Wazuh → B89 (push de alertas, docs/07 «Ingesta: push más reconciliación»).

integratord la invoca por cada alerta que pasa el filtro de <integration>:
    custom-b89 <archivo-alerta> B89_SECRET_FILE_V1 <hook_url>

- Firma el cuerpo con HMAC-SHA256 usando un archivo protegido root:wazuh; la clave nunca pasa por
  argumentos de proceso ni se versiona. Incluye un timestamp para evitar replay.
- Es best-effort: integratord no reintenta. El poller de B89 reconcilia por cursor, así que
  una alerta perdida aquí llega igual, con más latencia. Por eso un fallo solo se registra.
- Solo envía los campos que B89 normaliza (minimización N2), no `full_log` completo.
Instalar en /var/ossec/integrations/custom-b89 con dueño root:wazuh y modo 750.
"""
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.request

try:
    import certifi
except ImportError:  # Wazuh ships it; the fallback keeps local packaging portable.
    certifi = None

LOG = "/var/ossec/logs/integrations.log"
SECRET_FILE = "/var/ossec/etc/b89-wazuh-push.secret"
SECRET_MARKER = "B89_SECRET_FILE_V1"
# A wake-up needs only the native alert ID, manager name and source timestamp. The alert itself
# is fetched through the Indexer, which remains the authoritative evidence and reconciliation path.


def trusted_tls_context() -> ssl.SSLContext:
    """Use an explicit public CA bundle; Wazuh's Python may have no compiled default cafile."""
    candidates = [
        certifi.where() if certifi is not None else None,
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return ssl.create_default_context(cafile=path)
    raise OSError("no trusted CA bundle available")


def log(message: str) -> None:
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-b89: {message}\n")


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        log("argumentos insuficientes")
        return 1
    alert_file, secret_marker, hook_url = argv[1], argv[2], argv[3]
    if secret_marker != SECRET_MARKER:
        log("marcador de secreto no valido")
        return 1
    try:
        with open(SECRET_FILE, encoding="ascii") as handle:
            secret = handle.read().strip()
    except OSError:
        log("archivo de secreto no disponible")
        return 1
    if len(secret) < 32 or len(secret) > 512:
        log("archivo de secreto no valido")
        return 1
    if not hook_url.startswith("https://"):
        log("hook_url debe ser https")
        return 1
    with open(alert_file, encoding="utf-8") as handle:
        alert = json.load(handle)
    manager = alert.get("manager")
    manager_name = manager.get("name") if isinstance(manager, dict) else None
    alert_id = alert.get("id")
    occurred_at = alert.get("timestamp")
    if (
        isinstance(alert_id, bool)
        or not isinstance(alert_id, (str, int))
        or not isinstance(manager_name, str)
        or not manager_name
        or not isinstance(occurred_at, str)
    ):
        log("alerta sin identificadores validos")
        return 1
    # The receiver verifies parsed canonical JSON. Keep this field order aligned with the API's
    # canonicalHint implementation while sending only a lookup hint.
    hint = {
        "alertId": str(alert_id),
        "managerName": manager_name,
        "occurredAt": occurred_at,
    }
    body = json.dumps(
        hint,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256
    ).hexdigest()
    request = urllib.request.Request(
        hook_url,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-b89-timestamp": timestamp,
            "x-b89-signature": f"sha256={signature}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5, context=trusted_tls_context()) as response:
            if response.status not in (200, 202, 204):
                log(f"respuesta {response.status} para alerta {alert.get('id')}")
    except Exception as error:  # noqa: BLE001 — best-effort; el pull reconcilia
        log(f"fallo para alerta {alert.get('id')}: {type(error).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
