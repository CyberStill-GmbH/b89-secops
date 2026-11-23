#!/usr/bin/env bash
# B89 SecOps — detectores ML (OpenSearch Anomaly Detection, RCF) (docs/07). Idempotente.
#
# Crea cada detector `b89-*.json` si no existe y lo arranca. Si ya existe, no lo toca, salvo
# con B89_AD_UPDATE=true: en ese caso lo detiene, lo actualiza y lo vuelve a arrancar, porque
# AD no admite actualizar un detector en marcha. Los resultados quedan en
# `.opendistro-anomaly-results*`, que `modules/connectors` lee con `b89_reader`.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { printf 'b89-ad: ERROR %s\n' "$1" >&2; exit 1; }
info() { printf 'b89-ad: %s\n' "$1"; }
# shellcheck source=../../scripts/indexer-admin.sh
source "$here/../../scripts/indexer-admin.sh"
AD=/_plugins/_anomaly_detection/detectors
# B89 importa los resultados desde la API runtime/opensearch-anomaly-ingestion.ts.

# Valida el lote completo antes de detener o reemplazar un detector ya activo. La API de
# validación no cambia estado y evita dejar una mezcla de versiones ante un JSON incompatible.
for file in "$here"/b89-*.json; do
  name="$(jq -er '.name' "$file")" || fail "$(basename "$file") no es un detector válido"
  indexer POST "$AD/_validate" "$file"
  [[ "$INDEXER_STATUS" == 200 ]] || fail "$name: validación de configuración → HTTP $INDEXER_STATUS"
  jq -e '((.detector // {}) | length) == 0' "$INDEXER_BODY" >/dev/null \
    || fail "$name: OpenSearch rechazó la configuración del detector"
  info "$name configuración válida"
done

for file in "$here"/b89-*.json; do
  name="$(jq -er '.name' "$file")" || fail "$(basename "$file") no es un detector válido"
  query="$_b89_work/query.json"
  jq -n --arg name "$name" '{query: {term: {"name.keyword": $name}}}' >"$query"
  indexer POST "$AD/_search" "$query"
  id=""
  [[ "$INDEXER_STATUS" == 200 ]] && id="$(jq -r '.hits.hits[0]._id // empty' "$INDEXER_BODY")"

  if [[ -z "$id" ]]; then
    indexer POST "$AD" "$file"
    [[ "$INDEXER_STATUS" == 201 ]] || fail "$name: creación → HTTP $INDEXER_STATUS"
    id="$(jq -r '._id' "$INDEXER_BODY")"
    info "$name creado ($id)"
  elif [[ "${B89_AD_UPDATE:-false}" == true ]]; then
    indexer POST "$AD/$id/_stop"
    indexer PUT "$AD/$id" "$file"
    [[ "$INDEXER_STATUS" == 200 ]] || fail "$name: actualización → HTTP $INDEXER_STATUS"
    info "$name actualizado"
  else
    info "$name ya existe ($id); sin cambios"
  fi

  indexer POST "$AD/$id/_start"
  [[ "$INDEXER_STATUS" == 200 ]] && info "$name en marcha" \
    || info "$name: _start → HTTP $INDEXER_STATUS (ya en marcha o sin datos suficientes aún)"
done
