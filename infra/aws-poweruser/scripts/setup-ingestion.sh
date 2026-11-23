#!/usr/bin/env bash
# Ingesta Wazuh → B89 sin Entra en el nodo PowerUser (B89_WAZUH_GATEWAY_AUTH=static-token, ver
# docs/04 «Ingesta de Wazuh sin Entra»). Idempotente; EN el host como root, con el indexer arriba.
#   1. Rol b89_alerts_read y usuario interno b89_reader (como wazuh/access/apply-access.sh).
#   2. Token estático del gateway, credencial Basic del lector y certificado TLS del gateway
#      (nombre wazuh-gateway, firmado por la CA interna que el API ya confía).
#   3. Autoprueba del lector: puede buscar en wazuh-alerts-* y NO puede escribir.
# Los secretos quedan en /opt/b89/secrets (0600): gateway.env y la parte del API en api.env.
set -euo pipefail
umask 022
: "${INDEXER_ADMIN_PASSWORD:?}"
ROOT=/opt/b89
SECRETS=$ROOT/secrets
PKI=$ROOT/pki
CERTS=$ROOT/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs
log() { printf '[b89-ingestion] %s\n' "$*"; }

idx() { # método ruta [json]
  local args=(-sk -o /dev/null -w '%{http_code}' -u "admin:$INDEXER_ADMIN_PASSWORD" -X "$1"
    -H 'Content-Type: application/json' "https://127.0.0.1:9200$2")
  [[ $# -ge 3 ]] && args+=(--data-binary @-)
  if [[ $# -ge 3 ]]; then printf '%s' "$3" | curl "${args[@]}"; else curl "${args[@]}"; fi
}
expect() { [[ $1 =~ ^(200|201)$ ]] || { echo "$2 → HTTP $1" >&2; exit 1; }; }

# --- 1. secretos ---------------------------------------------------------------
if [[ ! -s $SECRETS/gateway.env ]]; then
  log 'generando token del gateway y contraseña de b89_reader'
  reader_pw="$(openssl rand -hex 24)Aa9."
  token="$(openssl rand -base64 48 | tr -d '\n')"
  {
    echo "B89_WAZUH_GATEWAY_ACCESS_TOKEN=$token"
    echo "WAZUH_INDEXER_BASIC_AUTH_B64=$(printf 'b89_reader:%s' "$reader_pw" | base64 -w0)"
    echo "B89_READER_PASSWORD=$reader_pw"
  } >"$SECRETS/gateway.env"
  chmod 600 "$SECRETS/gateway.env"
fi
set -a; . "$SECRETS/gateway.env"; set +a
if ! grep -q '^B89_WAZUH_GATEWAY_ACCESS_TOKEN=' "$SECRETS/api.env"; then
  echo "B89_WAZUH_GATEWAY_ACCESS_TOKEN=$B89_WAZUH_GATEWAY_ACCESS_TOKEN" >>"$SECRETS/api.env"
  chmod 600 "$SECRETS/api.env"
fi

# --- 2. rol y usuario del lector -------------------------------------------------
log 'rol b89_alerts_read y usuario b89_reader'
expect "$(idx PUT /_plugins/_security/api/roles/b89_alerts_read \
  '{"description":"B89: lectura de alertas, Cloudflare y resultados ML (solo lectura)","cluster_permissions":["cluster_monitor","cluster:admin/opendistro/ad/detector/info","cluster:admin/opendistro/ad/detectors/get","cluster:admin/opendistro/ad/detector/search"],"index_permissions":[{"index_patterns":["wazuh-alerts-*","b89-cloudflare-traffic-*",".opendistro-anomaly-results*"],"allowed_actions":["read"]}]}')" 'rol b89_alerts_read'
expect "$(python3 -c 'import json,os;print(json.dumps({"password":os.environ["B89_READER_PASSWORD"],"description":"B89: lector de alertas del gateway (solo lectura)"}))' \
  | curl -sk -o /dev/null -w '%{http_code}' -u "admin:$INDEXER_ADMIN_PASSWORD" -X PUT -H 'Content-Type: application/json' \
    --data-binary @- https://127.0.0.1:9200/_plugins/_security/api/internalusers/b89_reader)" 'usuario b89_reader'
expect "$(idx PUT /_plugins/_security/api/rolesmapping/b89_alerts_read '{"users":["b89_reader"]}')" 'mapeo b89_alerts_read'

# --- 3. TLS del gateway -----------------------------------------------------------
install -d -m 0755 "$PKI/gateway"
if [[ ! -s $PKI/gateway/cert.pem ]]; then
  log 'certificado del gateway (wazuh-gateway)'
  openssl req -new -nodes -newkey rsa:2048 -subj '/CN=wazuh-gateway' \
    -keyout "$PKI/gateway/key.pem" -out /tmp/gw.csr 2>/dev/null
  openssl x509 -req -in /tmp/gw.csr -CA "$PKI/ca.pem" -CAkey "$SECRETS/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:wazuh-gateway\nextendedKeyUsage=serverAuth\n') -out "$PKI/gateway/cert.pem" 2>/dev/null
  rm -f /tmp/gw.csr
  chmod 0644 "$PKI/gateway/cert.pem"; chmod 0600 "$PKI/gateway/key.pem"
fi
install -m 0644 "$CERTS/root-ca.pem" "$PKI/gateway/indexer-ca.pem"

# --- 4. autoprueba del lector -------------------------------------------------------
r="$(curl -sk -o /dev/null -w '%{http_code}' -u "b89_reader:$B89_READER_PASSWORD" -H 'Content-Type: application/json' \
  --data '{"size":0}' 'https://127.0.0.1:9200/wazuh-alerts-*/_search')"
w="$(curl -sk -o /dev/null -w '%{http_code}' -u "b89_reader:$B89_READER_PASSWORD" -H 'Content-Type: application/json' \
  -X POST --data '{"x":1}' 'https://127.0.0.1:9200/wazuh-alerts-4.x-selftest/_doc')"
[[ $r == 200 && $w == 403 ]] || { echo "autoprueba del lector: search $r, write $w" >&2; exit 1; }
log "autoprueba: b89_reader search $r, write $w"
