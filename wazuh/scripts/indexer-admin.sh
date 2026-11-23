#!/usr/bin/env bash
# Helper común: `indexer <método> <ruta> [archivo-json]` con la credencial admin del Indexer.
# Mismo criterio que access/apply-access.sh: la contraseña sale del paquete de instalación del
# all-in-one (o de B89_INDEXER_ADMIN_PASSWORD en pruebas locales) y viaja a curl por archivo,
# nunca por argumentos visibles en `ps`. Se carga con `source`.

INDEXER_TLS_NAME="${B89_INDEXER_TLS_NAME:-}"
INDEXER_URL="${B89_INDEXER_URL:-}"
if [[ -z "$INDEXER_URL" ]]; then
  if [[ -n "$INDEXER_TLS_NAME" ]]; then
    INDEXER_URL="https://${INDEXER_TLS_NAME}:9200"
  else
    INDEXER_URL='https://127.0.0.1:9200'
  fi
fi
INDEXER_CA="${B89_INDEXER_CA:-/etc/wazuh-indexer/certs/root-ca.pem}"
_b89_work="$(mktemp -d)"
trap 'rm -rf "$_b89_work"' EXIT

if [[ -z "${B89_INDEXER_ADMIN_PASSWORD:-}" ]]; then
  [[ -r /root/wazuh-install-files.tar ]] || { echo 'no se encuentra wazuh-install-files.tar' >&2; exit 1; }
  B89_INDEXER_ADMIN_PASSWORD="$(
    tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt |
      python3 -c '
import sys
lines = [l.strip() for l in sys.stdin]
for i, l in enumerate(lines):
    k, s, v = l.partition(":")
    if s and k.strip().lower() == "indexer_username" and v.strip().strip("\x27\"") == "admin":
        for f in lines[i + 1:i + 4]:
            k2, s2, v2 = f.partition(":")
            if s2 and k2.strip().lower() == "indexer_password":
                print(v2.strip().strip("\x27\""), end=""); sys.exit(0)
sys.exit(1)'
  )" || { echo 'no se pudo leer la credencial admin del Indexer' >&2; exit 1; }
fi
printf 'user = "admin:%s"\n' "$B89_INDEXER_ADMIN_PASSWORD" >"$_b89_work/curl.cfg"
unset B89_INDEXER_ADMIN_PASSWORD

_b89_tls=(--cacert "$INDEXER_CA")
[[ "$INDEXER_CA" == insecure ]] && _b89_tls=(-k)

# indexer GET /_cluster/health
# indexer PUT /_plugins/_ism/policies/x policy.json
indexer() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -o "$_b89_work/out.json" -w '%{http_code}' -K "$_b89_work/curl.cfg" "${_b89_tls[@]}"
    -X "$method" -H 'content-type: application/json' "$INDEXER_URL$path")
  if [[ -n "$INDEXER_TLS_NAME" ]]; then
    args+=(--resolve "$INDEXER_TLS_NAME:9200:127.0.0.1")
  fi
  [[ -n "$body" ]] && args+=(--data-binary "@$body")
  local code
  code="$(curl "${args[@]}")"
  INDEXER_STATUS="$code"
  INDEXER_BODY="$_b89_work/out.json"
}
