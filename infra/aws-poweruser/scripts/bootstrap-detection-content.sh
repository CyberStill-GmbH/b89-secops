#!/usr/bin/env bash
# B89 SOC Â· importa las vistas de anÃ¡lisis del programa de detecciÃ³n (docs/17) en el tenant global.
#
#   sudo bash infra/aws-poweruser/scripts/bootstrap-detection-content.sh
#
# Igual que bootstrap-wazuh-app.sh: las peticiones salen DESDE el contenedor del dashboard (el Ãºnico
# proxy en el que confÃ­a el indexer) con la identidad de servicio b89-bootstrap y el rol
# b89.platform.admin. Nunca usa el login de una persona (sesiÃ³n Ãºnica N9). Idempotente: IDs estables
# `b89-det-*` + overwrite=true. Verifica al final que los seis dashboards existen.
#
# Variables: B89_DASHBOARD_CONTAINER (b89-wazuh.dashboard-1), B89_DETECTION_DASHBOARDS (ruta del NDJSON).
set -euo pipefail
C="${B89_DASHBOARD_CONTAINER:-b89-wazuh.dashboard-1}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NDJSON="${B89_DETECTION_DASHBOARDS:-$repo/wazuh/dashboard/saved-objects/detection/b89-detection-dashboards.ndjson}"
log() { printf '[b89-detection] %s\n' "$*"; }
osd() {
  docker exec -i "$C" curl -s -H 'osd-xsrf: true' \
    -H 'securitytenant: global' \
    -H 'x-proxy-user: b89-bootstrap' -H 'x-proxy-roles: b89.platform.admin' \
    -H 'x-forwarded-for: 127.0.0.1' "$@"   # el proxy auth del indexer exige XFF resuelto
}

[[ -f "$NDJSON" ]] || { log "no existe $NDJSON"; exit 1; }
for _ in $(seq 1 60); do
  [[ "$(osd -o /dev/null -w '%{http_code}' http://127.0.0.1:5601/api/status)" == 200 ]] && break
  sleep 5
done

# Los dashboards usan wazuh-alerts-* y wazuh-states-vulnerabilities-* (los crea bootstrap-wazuh-app.sh).
for ip in 'wazuh-alerts-*' 'wazuh-states-vulnerabilities-*'; do
  code="$(osd -o /dev/null -w '%{http_code}' "http://127.0.0.1:5601/api/saved_objects/index-pattern/$ip")"
  [[ $code == 200 ]] || { log "falta el index pattern $ip (HTTP $code): correr antes bootstrap-wazuh-app.sh"; exit 1; }
done

result="$(osd -F 'file=@-;filename=b89-detection-dashboards.ndjson' \
  'http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true' <"$NDJSON")"
if [[ $result != *'"success":true'* ]]; then
  log "importaciÃ³n fallida: ${result:0:600}"
  exit 1
fi
log "vistas de detecciÃ³n importadas: $(grep -o '"successCount":[0-9]*' <<<"$result")"

missing=0
for id in mitre vulnerabilities identity integrity hunting quality; do
  code="$(osd -o /dev/null -w '%{http_code}' "http://127.0.0.1:5601/api/saved_objects/dashboard/b89-det-dashboard-$id")"
  if [[ $code == 200 ]]; then log "dashboard b89-det-dashboard-$id: OK"; else log "dashboard b89-det-dashboard-$id: HTTP $code"; missing=1; fi
done
exit "$missing"
