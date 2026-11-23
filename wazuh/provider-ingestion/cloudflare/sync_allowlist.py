#!/usr/bin/env python3
"""Descarga la lista blanca de la API de pagos para el colector de Cloudflare.

Uso (timer cada 2 minutos, como root en el host de Wazuh):
    B89_API_URL=https://... B89_ALLOWLIST_FEED_TOKEN_FILE=/etc/b89/allowlist-feed.token \
        python3 sync_allowlist.py [--output /var/ossec/etc/b89/cloudflare-allowlist.json]

El token se lee de un archivo (nunca de argumentos). Si la API no responde o la respuesta no es
válida, se conserva el último archivo bueno: el colector sigue con la versión anterior.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from allowlist import DEFAULT_FILE, parse  # noqa: E402


def fetch(url: str, token: str, timeout: int = 20) -> dict:
    request = urllib.request.Request(
        url.rstrip("/") + "/api/cloudflare/allowlist/feed",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Sincroniza la lista blanca de la API de pagos")
    parser.add_argument("--output", default=os.environ.get("B89_CF_ALLOWLIST_FILE", DEFAULT_FILE))
    args = parser.parse_args()
    url = os.environ.get("B89_API_URL", "")
    token_file = os.environ.get("B89_ALLOWLIST_FEED_TOKEN_FILE", "")
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        print("B89_API_URL debe ser HTTPS (o localhost).", file=sys.stderr)
        return 2
    try:
        token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
    except OSError:
        print("No se pudo leer B89_ALLOWLIST_FEED_TOKEN_FILE.", file=sys.stderr)
        return 2
    try:
        document = fetch(url, token)
    except Exception as error:  # noqa: BLE001 - se conserva el último archivo bueno
        print(f"No se pudo descargar la lista blanca: {type(error).__name__}", file=sys.stderr)
        return 1
    if parse(document) is None:
        print("La respuesta de la API no es una lista blanca válida; se conserva la anterior.", file=sys.stderr)
        return 1
    write_atomic(pathlib.Path(args.output), document)
    print(f"Lista blanca revisión {document.get('revision')} con {len(document['entries'])} entradas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
