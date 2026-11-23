#!/usr/bin/env python3
"""Descarga la lista blanca de la API de pagos para el colector de Cloudflare.

Lo ejecuta el timer ``b89-collector-cloudflare-allowlist`` (install-b89-collectors.sh):
    python3 -I sync_allowlist.py --url https://SOC_HOSTNAME --connect 172.30.89.11 \
        --token-file /opt/b89/secrets/collectors/allowlist-feed-token \
        --output /opt/b89/collectors/state/cloudflare-allowlist.json

``--connect`` abre la conexión a esa IP (el edge en la red de Docker, como hace el manager de Wazuh
con ``extra_hosts``) pero valida el certificado y envía el nombre de ``--url``. El token se lee de
un archivo, nunca de argumentos. Si la API no responde o la respuesta no es válida, se conserva el
último archivo bueno: el colector sigue con la versión anterior.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import socket
import ssl
import sys
import tempfile
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from allowlist import DEFAULT_FILE, parse  # noqa: E402

FEED_PATH = "/api/cloudflare/allowlist/feed"
MAX_BYTES = 2 * 1024 * 1024


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS a una IP fija con SNI y verificación del nombre del certificado."""

    def __init__(self, host: str, connect_ip: str, timeout: int):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self.connect_ip = connect_ip

    def connect(self):  # noqa: D401 - firma de http.client
        sock = socket.create_connection((self.connect_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url: str, token: str, connect_ip: str | None = None, timeout: int = 20) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("la URL debe ser HTTPS y sin credenciales")
    if connect_ip:
        connection = PinnedHTTPSConnection(parsed.hostname, connect_ip, timeout)
    else:
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout,
                                                 context=ssl.create_default_context())
    try:
        connection.request("GET", parsed.path.rstrip("/") + FEED_PATH,
                           headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_BYTES + 1)
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        if len(body) > MAX_BYTES:
            raise RuntimeError("respuesta demasiado grande")
        return json.loads(body.decode("utf-8"))
    finally:
        connection.close()


def write_atomic(path: pathlib.Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".allowlist-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o640)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sincroniza la lista blanca de la API de pagos")
    parser.add_argument("--url", default=os.environ.get("B89_API_URL", ""))
    parser.add_argument("--connect", default=os.environ.get("B89_API_CONNECT_IP") or None)
    parser.add_argument("--token-file", default=os.environ.get("B89_ALLOWLIST_FEED_TOKEN_FILE", ""))
    parser.add_argument("--output", default=os.environ.get("B89_CF_ALLOWLIST_FILE", DEFAULT_FILE))
    args = parser.parse_args(argv)
    try:
        token = pathlib.Path(args.token_file).read_text(encoding="utf-8").strip()
    except OSError:
        print("b89-allowlist: no se pudo leer el archivo del token.", file=sys.stderr)
        return 2
    if len(token) < 32:
        print("b89-allowlist: el token es demasiado corto.", file=sys.stderr)
        return 2
    try:
        document = fetch(args.url, token, args.connect)
    except Exception as error:  # noqa: BLE001 - se conserva el último archivo bueno
        print(f"b89-allowlist: no se pudo descargar la lista ({type(error).__name__}: {error}); se conserva la anterior.",
              file=sys.stderr)
        return 1
    if parse(document) is None:
        print("b89-allowlist: la respuesta no es una lista blanca válida; se conserva la anterior.", file=sys.stderr)
        return 1
    write_atomic(pathlib.Path(args.output), document)
    print(f"b89-allowlist: revisión {document.get('revision')} con {len(document['entries'])} entradas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
