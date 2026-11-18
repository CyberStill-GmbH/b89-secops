#!/usr/bin/env bash
# Prepara en el indexer el índice de tráfico de Cloudflare (idempotente, root en el host):
#   - plantilla b89-cloudflare-traffic-* (mapeo del contrato: @timestamp = hora REAL del evento);
#   - rol b89_cloudflare_traffic_writer (solo escribir en ese patrón) y usuario interno
#     b89_traffic_writer, con la contraseña en /opt/b89/secrets/collectors/indexer-traffic-writer-password;
#   - mapeo rol ↔ usuario. La lectura para los roles B89 está en wazuh/indexer/security/roles.b89.yml.
# Usa el certificado admin del propio contenedor del indexer (nunca sale de él).
set -Eeuo pipefail
SECRET=/opt/b89/secrets/collectors/indexer-traffic-writer-password
log() { printf '[b89-cf-index] %s\n' "$*"; }
[[ $(id -u) -eq 0 ]] || { log 'ERROR: ejecutar como root' >&2; exit 1; }
I="$(docker ps --format '{{.Names}}' | grep -m1 'wazuh.indexer')"
[[ -n $I ]] || { log 'ERROR: no hay contenedor del indexer' >&2; exit 1; }

install -d -m 0700 /opt/b89/secrets/collectors
if [[ ! -s $SECRET ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' >"$SECRET.tmp" && mv "$SECRET.tmp" "$SECRET"
  log 'contraseña del escritor generada'
fi
chmod 0600 "$SECRET"

api() { # método ruta (cuerpo por stdin)
  docker exec -i "$I" sh -c 'c=/usr/share/wazuh-indexer/config/certs; curl -sS -o /dev/null -w "%{http_code}" \
    --cacert $c/root-ca.pem --cert $c/admin.pem --key $c/admin-key.pem \
    --resolve wazuh.indexer:9200:127.0.0.1 -X "$0" -H "content-type: application/json" \
    --data-binary @- "https://wazuh.indexer:9200$1"' "$1" "$2"
}
expect() { local code; code="$(api "$1" "$2")"; [[ $code =~ ^20[01]$ ]] || { log "ERROR: $1 $2 → $code" >&2; exit 1; }; log "$1 $2 → $code"; }

kw() { printf '{"type":"keyword","ignore_above":2048}'; }
expect PUT /_index_template/b89-cloudflare-traffic <<EOF
{"index_patterns":["b89-cloudflare-traffic-*"],"priority":200,
 "template":{"settings":{"number_of_shards":1,"number_of_replicas":0,"refresh_interval":"10s"},
  "mappings":{"dynamic":false,"properties":{
   "@timestamp":{"type":"date"},"ingested_at":{"type":"date"},
   "event":{"properties":{"dataset":$(kw),"source":$(kw),"sampled":{"type":"boolean"},"history":{"type":"boolean"},"sample_interval":{"type":"float"}}},
   "zone":{"properties":{"name":$(kw),"id":$(kw)}},
   "client":{"properties":{"ip":{"type":"ip","ignore_malformed":true},"country":$(kw),"asn":{"type":"long"},"asn_name":$(kw)}},
   "http":{"properties":{"host":$(kw),"method":$(kw),
     "path":{"type":"keyword","ignore_above":2048,"fields":{"text":{"type":"text"}}},
     "query":$(kw),"uri":$(kw),"status":{"type":"integer"},"origin_status":{"type":"integer"},
     "user_agent":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}},
     "referer":$(kw),"ray":$(kw),"cache":$(kw),"protocol":$(kw),"tls":$(kw),
     "security_action":$(kw),"security_source":$(kw),"bytes":{"type":"long"}}},
   "dns":{"properties":{"query":$(kw),"type":$(kw),"rcode":$(kw),"colo":$(kw),"cached":{"type":"boolean"},"protocol":$(kw)}},
   "firewall":{"properties":{"action":$(kw),"source":$(kw),"rule_id":$(kw),"description":$(kw),"ray":$(kw)}},
   "audit":{"properties":{"action":$(kw),"result":$(kw),"actor_email":$(kw),"actor_ip":{"type":"ip","ignore_malformed":true},
     "resource_type":$(kw),"zone_name":$(kw),"id":$(kw)}}}}}}
EOF

expect PUT /_plugins/_security/api/roles/b89_cloudflare_traffic_writer <<'EOF'
{"cluster_permissions":["indices:data/write/bulk"],
 "index_permissions":[{"index_patterns":["b89-cloudflare-traffic-*"],
   "allowed_actions":["crud","create_index","indices:admin/mapping/put"]}]}
EOF
python3 -c 'import json,sys; print(json.dumps({"password": open(sys.argv[1]).read().strip(), "description": "B89 Cloudflare traffic indexer"}))' "$SECRET" |
  expect PUT /_plugins/_security/api/internalusers/b89_traffic_writer
expect PUT /_plugins/_security/api/rolesmapping/b89_cloudflare_traffic_writer <<'EOF'
{"users":["b89_traffic_writer"]}
EOF
log 'índice de tráfico listo'
