#!/usr/bin/env bash
# Precrea como administrador los index patterns que el chequeo de salud de la app de Wazuh crearía
# al primer acceso. Así un analista B89 (solo lectura) no necesita indices:data/write/index sobre
# .kibana y el chequeo pasa. Idempotente (409 = ya existe).
#
# Las peticiones salen DESDE el contenedor del dashboard (172.30.89.10, el único proxy en el que
# confía el indexer) con la identidad de servicio b89-bootstrap y el rol b89.platform.admin.
set -euo pipefail
C=b89-wazuh.dashboard-1
osd() {
  docker exec "$C" curl -s -o /dev/null -w '%{http_code}' -H 'osd-xsrf: true' \
    -H 'x-proxy-user: b89-bootstrap' -H 'x-proxy-roles: b89.platform.admin' \
    -H 'x-forwarded-for: 127.0.0.1' "$@"   # el proxy auth del indexer exige XFF resuelto
}

for _ in $(seq 1 60); do
  [[ $(osd http://127.0.0.1:5601/api/status) == 200 ]] && break
  sleep 5
done

for spec in 'wazuh-alerts-*|timestamp' 'wazuh-monitoring-*|timestamp' 'wazuh-statistics-*|timestamp'; do
  title="${spec%%|*}"; field="${spec##*|}"
  code="$(osd -H 'Content-Type: application/json' -X POST \
    --data "{\"attributes\":{\"title\":\"$title\",\"timeFieldName\":\"$field\"}}" \
    "http://127.0.0.1:5601/api/saved_objects/index-pattern/$title")"
  case "$code" in
    200|409) echo "[b89-deploy] index pattern $title: $([[ $code == 200 ]] && echo creado || echo existente)" ;;
    *) echo "index pattern $title → HTTP $code" >&2; exit 1 ;;
  esac
done
osd -H 'Content-Type: application/json' -X POST --data '{"changes":{"defaultIndex":"wazuh-alerts-*"}}' \
  http://127.0.0.1:5601/api/opensearch-dashboards/settings >/dev/null

# Dashboards B89 de los proveedores sin módulo nativo en la app de Wazuh (Bitdefender GravityZone,
# Snyk, Cloudflare) y de Microsoft 365 (wazuh/dashboard/saved-objects). Tenant global, misma
# identidad de servicio. Idempotente: IDs estables `b89-*` + overwrite.
NDJSON="${B89_PROVIDER_DASHBOARDS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/wazuh/dashboard/saved-objects/b89-provider-dashboards.ndjson}"
if [[ -f $NDJSON ]]; then
  result="$(docker exec -i "$C" curl -s -H 'osd-xsrf: true' \
    -H 'x-proxy-user: b89-bootstrap' -H 'x-proxy-roles: b89.platform.admin' \
    -H 'x-forwarded-for: 127.0.0.1' -F 'file=@-;filename=b89-provider-dashboards.ndjson' \
    'http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true' <"$NDJSON")"
  if [[ $result == *'"success":true'* ]]; then
    echo "[b89-deploy] dashboards de proveedores: $(grep -o '"successCount":[0-9]*' <<<"$result")"
  else
    echo "dashboards de proveedores: importación fallida: ${result:0:500}" >&2
    exit 1
  fi
fi
