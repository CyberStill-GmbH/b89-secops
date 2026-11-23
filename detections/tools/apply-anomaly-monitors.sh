#!/usr/bin/env bash
# B89 SOC · monitores de Alerting sobre los detectores de Anomaly Detection (docs/detection-engineering/07).
#
#   sudo bash wazuh/indexer/anomaly-detection/apply-detectors.sh     # crea y arranca los detectores b89-*
#   sudo bash detections/tools/apply-anomaly-monitors.sh             # crea/actualiza un monitor por detector
#
# Monitores de diagnostico: sin acciones ni entrega de avisos. El lector B89 API es el unico camino de notificacion.
set -euo pipefail
# Monitores tecnicos de referencia: sin acciones de entrega. El lector B89 API, cada 5 s,
# es el unico responsable de convertir hallazgos cualificados en alertas y notificaciones SOC.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../wazuh/manager/policy/lib.sh
source "$here/../../wazuh/manager/policy/lib.sh"
log() { printf '[b89-anomaly] %s\n' "$*"; }
AD=/_plugins/_anomaly_detection/detectors
AL=/_plugins/_alerting/monitors

for detector in ${B89_AD_MONITORS:-b89-agent-alert-volume b89-cf-backoffice-exports b89-cf-backoffice-per-ip b89-cf-money-movement b89-cf-payments-errors b89-logins-per-user b89-m365-file-downloads b89-m365-login-failures b89-provider-aws-activity b89-provider-bitdefender-activity b89-provider-snyk-activity b89-waf-blocks-per-zone}; do
  printf '{"query":{"term":{"name.keyword":"%s"}}}' "$detector" >"$B89_WORK/q.json"
  b89_indexer POST "$AD/_search" "$B89_WORK/q.json"
  id="$(b89_json "$INDEXER_BODY" "(d.get('hits',{}).get('hits') or [{}])[0].get('_id','')")"
  [[ -n "$id" ]] || { log "$detector: no existe (correr apply-detectors.sh primero)"; continue; }
  name="B89 · Anomalía · $detector"
  b89_python - "$name" "$id" >"$B89_WORK/monitor.json" <<'PY'
import json, sys
name, detector_id = sys.argv[1:3]
grade = "ctx.results[0].aggregations.max_grade.value"
conf = "ctx.results[0].aggregations.max_confidence.value"
print(json.dumps({
    "type": "monitor", "monitor_type": "query_level_monitor", "name": name, "enabled": True,
    "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
    "inputs": [{"search": {"indices": [".opendistro-anomaly-results*"], "query": {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"execution_end_time": {"from": "{{period_end}}||-5m", "to": "{{period_end}}",
                                              "include_lower": True, "include_upper": True}}},
            {"term": {"detector_id": {"value": detector_id}}},
            {"range": {"anomaly_grade": {"gte": 0.80}}},
            {"range": {"confidence": {"gte": 0.90}}}]}},
        "aggregations": {"max_grade": {"max": {"field": "anomaly_grade"}},
                         "max_confidence": {"max": {"field": "confidence"}}}}}}],
    "triggers": [{"name": "Hallazgo ML cualificado (grado >= 0.80; confianza >= 0.90)", "severity": "2", "actions": [],
                  "condition": {"script": {"lang": "painless", "source":
                      f"return ctx.results != null && ctx.results.length > 0 && {grade} != null && {grade} >= 0.80 "
                      f"&& {conf} != null && {conf} >= 0.90"}}}],
    "ui_metadata": {"monitor_type": "query_level_monitor", "search": {"searchType": "ad"}},
}))
PY
  printf '{"query":{"match_phrase":{"monitor.name":"%s"}}}' "$name" >"$B89_WORK/mq.json"
  b89_indexer POST "$AL/_search" "$B89_WORK/mq.json"
  mid="$(b89_json "$INDEXER_BODY" "(d.get('hits',{}).get('hits') or [{}])[0].get('_id','')")"
  if [[ -n "$mid" ]]; then
    b89_indexer PUT "$AL/$mid" "$B89_WORK/monitor.json"; log "$name actualizado ($mid) → HTTP $INDEXER_STATUS"
  else
    b89_indexer POST "$AL" "$B89_WORK/monitor.json"; log "$name creado → HTTP $INDEXER_STATUS"
  fi
done
