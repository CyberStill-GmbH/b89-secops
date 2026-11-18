#!/usr/bin/env bash
# B89 SOC — retención del Indexer en nodo único SIN repositorio de snapshots (EC2 PowerUser y
# local). Idempotente. Catálogo y motivos: docs/16-politicas.md.
#
#   b89-wazuh-alerts-90d        wazuh-alerts-*                         hot 90 d → delete
#   b89-wazuh-monitoring-15d    wazuh-monitoring-*, wazuh-statistics-*  15 d → delete
#   b89-wazuh-archives-7d       wazuh-archives-* (si se habilita logall_json)  7 d → delete
#
# Con S3 + rol IAM (infra/aws) se usa apply-ism.sh (b89-wazuh-retention con snapshot a b89-s3).
# Este script no crea repositorios ni borra snapshots. Corre en el host vía docker exec al
# contenedor del indexer (wazuh/manager/policy/lib.sh); credencial admin desde
# /opt/b89/secrets/compose.env o B89_INDEXER_ADMIN_PASSWORD.
#
# Variables: B89_ALERTS_RETENTION_DAYS (90), B89_MONITORING_RETENTION_DAYS (15),
#            B89_ISM_TAKEOVER (0): 1 = cambiar a estas políticas índices que ya tengan OTRA.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../manager/policy/lib.sh
source "$here/../../manager/policy/lib.sh"

alerts_days="${B89_ALERTS_RETENTION_DAYS:-90}"
mon_days="${B89_MONITORING_RETENTION_DAYS:-15}"
[[ "$alerts_days" =~ ^[0-9]+$ && "$alerts_days" -ge 7 ]] || b89_die 'B89_ALERTS_RETENTION_DAYS debe ser ≥ 7'
[[ "$mon_days" =~ ^[0-9]+$ && "$mon_days" -ge 1 ]] || b89_die 'B89_MONITORING_RETENTION_DAYS inválido'

b89_indexer GET /_cluster/health
[[ "$INDEXER_STATUS" == 200 ]] || b89_die "indexer no responde (HTTP $INDEXER_STATUS)"
b89_log "indexer: $(b89_indexer_container) ($(b89_json "$INDEXER_BODY" 'd["status"]'))"

# policy-id|archivo|días (vacío = tal cual)|patrón de índices existentes a adjuntar
specs=(
  "b89-wazuh-alerts-90d|$here/b89-wazuh-alerts-90d.json|$alerts_days|wazuh-alerts-*"
  "b89-wazuh-monitoring-15d|$here/b89-wazuh-monitoring-15d.json|$mon_days|wazuh-monitoring-*,wazuh-statistics-*"
  "b89-wazuh-archives-7d|$here/b89-wazuh-archives-7d.json||wazuh-archives-*"
)

for spec in "${specs[@]}"; do
  IFS='|' read -r id file days pattern <<<"$spec"
  want="$B89_WORK/$id.want.json"
  # Ajusta la edad de borrado (transición hacia el estado final) si se pidió otro plazo.
  b89_python - "$file" "$want" "$days" <<'PY'
import json, sys
src, dst, days = sys.argv[1], sys.argv[2], sys.argv[3]
p = json.load(open(src, encoding="utf-8"))
if days:
    for st in p["policy"]["states"]:
        for t in st.get("transitions", []):
            t["conditions"]["min_index_age"] = f"{days}d"
json.dump(p, open(dst, "w", encoding="utf-8"), ensure_ascii=False)
PY
  b89_indexer GET "/_plugins/_ism/policies/$id"
  if [[ "$INDEXER_STATUS" == 200 ]]; then
    same="$(b89_python - "$INDEXER_BODY" "$want" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1], encoding="utf-8"))["policy"]
want = json.load(open(sys.argv[2], encoding="utf-8"))["policy"]
def norm(p):
    keep = {k: p.get(k) for k in ("description", "default_state", "states")}
    keep["ism_template"] = [{"index_patterns": t["index_patterns"], "priority": t["priority"]}
                            for t in (p.get("ism_template") or [])]
    for st in keep["states"]:
        for a in st.get("actions", []):
            a.pop("retry", None)
    return json.dumps(keep, sort_keys=True)
print("yes" if norm(cur) == norm(want) else "no")
PY
)"
    if [[ "$same" == yes ]]; then
      b89_log "política $id: sin cambios"
    else
      seq="$(b89_json "$INDEXER_BODY" 'd["_seq_no"]')"; term="$(b89_json "$INDEXER_BODY" 'd["_primary_term"]')"
      b89_indexer PUT "/_plugins/_ism/policies/$id?if_seq_no=$seq&if_primary_term=$term" "$want"
      [[ "$INDEXER_STATUS" =~ ^20[01]$ ]] || { cat "$INDEXER_BODY" >&2; b89_die "política $id → HTTP $INDEXER_STATUS"; }
      b89_log "política $id: actualizada"
    fi
  else
    b89_indexer PUT "/_plugins/_ism/policies/$id" "$want"
    [[ "$INDEXER_STATUS" =~ ^20[01]$ ]] || { cat "$INDEXER_BODY" >&2; b89_die "política $id → HTTP $INDEXER_STATUS"; }
    b89_log "política $id: creada"
  fi

  # ism_template solo alcanza índices NUEVOS: adjuntar los existentes sin política.
  IFS=',' read -ra pats <<<"$pattern"
  for pat in "${pats[@]}"; do
    b89_indexer GET "/_plugins/_ism/explain/$pat"
    [[ "$INDEXER_STATUS" == 200 ]] || continue
    mapfile -t rows < <(b89_python - "$INDEXER_BODY" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for k, v in d.items():
    if isinstance(v, dict) and "index.plugins.index_state_management.policy_id" in v or isinstance(v, dict) and "index.opendistro.index_state_management.policy_id" in v:
        pid = v.get("index.plugins.index_state_management.policy_id") or v.get("index.opendistro.index_state_management.policy_id")
        print(f"{k} {pid or '-'}")
PY
)
    unmanaged=(); others=()
    for row in "${rows[@]}"; do
      idx="${row% *}"; pid="${row#* }"
      if [[ "$pid" == "-" || "$pid" == null || "$pid" == None ]]; then unmanaged+=("$idx")
      elif [[ "$pid" != "$id" ]]; then others+=("$idx:$pid"); fi
    done
    body="$B89_WORK/attach.json"; printf '{"policy_id":"%s"}' "$id" >"$body"
    for idx in "${unmanaged[@]}"; do
      b89_indexer POST "/_plugins/_ism/add/$idx" "$body"
      b89_log "adjuntada $id a $idx (HTTP $INDEXER_STATUS)"
    done
    for item in "${others[@]}"; do
      if [[ "${B89_ISM_TAKEOVER:-0}" == 1 ]]; then
        cbody="$B89_WORK/change.json"; printf '{"policy_id":"%s"}' "$id" >"$cbody"
        b89_indexer POST "/_plugins/_ism/change_policy/${item%%:*}" "$cbody"
        b89_log "cambiada a $id: $item (HTTP $INDEXER_STATUS)"
      else
        b89_log "AVISO: ${item%%:*} tiene la política ${item#*:}; no se cambia (B89_ISM_TAKEOVER=1 para tomarla)"
      fi
    done
  done
done

# Nodo único: el índice interno de ISM nace con 1 réplica y deja el clúster en amarillo. Es un
# índice de sistema (el usuario admin no puede tocarlo): se usa el certificado admin del propio
# contenedor, que nunca sale de él.
b89_indexer GET /_cluster/health
nodes="$(b89_json "$INDEXER_BODY" 'd["number_of_nodes"]')"
if [[ "$nodes" == 1 ]]; then
  c=/usr/share/wazuh-indexer/config/certs
  out="$(docker exec "$(b89_indexer_container)" curl -sS --cacert "$c/root-ca.pem" --cert "$c/admin.pem" \
    --key "$c/admin-key.pem" --resolve "${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200:127.0.0.1" \
    "https://${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200/.opendistro-ism-config/_settings/index.number_of_replicas?flat_settings=true" 2>&1 || true)"
  if [[ "$out" == *'"index.number_of_replicas":"0"'* ]]; then
    b89_log 'índice interno de ISM: 0 réplicas (nodo único)'
  elif [[ "$out" == *'number_of_replicas'* ]]; then
    docker exec "$(b89_indexer_container)" curl -sS --cacert "$c/root-ca.pem" --cert "$c/admin.pem" \
      --key "$c/admin-key.pem" --resolve "${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200:127.0.0.1" -X PUT \
      -H 'content-type: application/json' -d '{"index":{"number_of_replicas":0}}' \
      "https://${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200/.opendistro-ism-config/_settings" >/dev/null &&
      b89_log 'índice interno de ISM: réplicas → 0 (nodo único; evita el estado amarillo)'
  fi
  # El historial de ISM (.opendistro-ism-managed-index-history-*) rota a diario con 1 réplica por
  # defecto: se fija el ajuste del clúster para los futuros y se corrigen los existentes.
  for req in \
    "PUT /_cluster/settings {\"persistent\":{\"plugins.index_state_management.history.number_of_replicas\":0}}" \
    "PUT /.opendistro-ism-managed-index-history-*/_settings {\"index\":{\"number_of_replicas\":0}}" \
    "PUT /.opendistro-job-scheduler-lock/_settings {\"index\":{\"number_of_replicas\":0}}"; do
    read -r verb path body <<<"$req"
    docker exec "$(b89_indexer_container)" curl -sS -o /dev/null -w '%{http_code}' --cacert "$c/root-ca.pem" \
      --cert "$c/admin.pem" --key "$c/admin-key.pem" \
      --resolve "${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200:127.0.0.1" -X "$verb" \
      -H 'content-type: application/json' -d "$body" \
      "https://${B89_INDEXER_TLS_NAME:-wazuh.indexer}:9200$path" | grep -q '^200$' &&
      b89_log "historial de ISM: 0 réplicas ($verb $path)" || b89_log "AVISO: no se pudo ajustar $path"
  done
fi

b89_indexer GET /_snapshot
repos="$(b89_json "$INDEXER_BODY" 'sorted(d.keys()) if isinstance(d, dict) else []')"
b89_log "repositorios de snapshot registrados: $repos (sin S3/IAM: respaldo por snapshot EBS del volumen, ver docs/16)"
