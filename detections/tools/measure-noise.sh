#!/usr/bin/env bash
# B89 SOC · medición de ruido por regla (solo lectura). Doc: docs/detection-engineering/07-ajuste-falsos-positivos.md.
#
#   bash detections/tools/measure-noise.sh [días]        # por defecto 7
#
# Corre en el host del manager (mismo acceso al indexer que deploy-network.sh: contenedor del indexer y su
# contraseña de admin, nunca impresa). No cambia nada: solo consultas _search con size 0 y agregaciones.
# Salida: JSON por sección en stdout, para guardar como evidencia "antes" y "después" de un ajuste:
#   1. Top 40 reglas por volumen (rule.id, nivel, descripción) en la ventana.
#   2. MailItemsAccessed (91578 y overlay 100531-100535): por LogonType, top ClientAppId del dueño (para
#      completar detections/lists/b89-m365-mail-apps) y top buzones ajenos (b89-m365-shared-mailboxes).
#   3. Lista blanca de la API de pagos (101546-101549, 102020-102025): por regla, top IP/cliente/ruta/estado.
set -Eeuo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=../../wazuh/manager/policy/lib.sh
source "$repo/wazuh/manager/policy/lib.sh"
days="${1:-7}"
[[ "$days" =~ ^[0-9]{1,2}$ ]] || b89_die "uso: $0 [días 1-99]"

query() {
  local name="$1" body="$B89_WORK/$1.json"
  cat >"$body"
  b89_indexer POST '/wazuh-alerts-*/_search' "$body"
  [[ "$INDEXER_STATUS" == 200 ]] || b89_die "consulta $name: el indexer devolvió $INDEXER_STATUS"
  b89_python - "$name" "$INDEXER_BODY" <<'PY'
import json, sys
name, path = sys.argv[1:3]
data = json.load(open(path, encoding="utf-8"))
def flat(aggs):
    """terms → lista de {key, count, sub-agregaciones}; filter → {count, sub-agregaciones}."""
    out = {}
    for key, agg in (aggs or {}).items():
        if not isinstance(agg, dict):
            continue
        subs = {k: v for k, v in agg.items() if isinstance(v, dict) and ("buckets" in v or "doc_count" in v)}
        if "buckets" in agg:
            out[key] = [{"key": b.get("key"), "count": b.get("doc_count"),
                         **flat({k: v for k, v in b.items() if isinstance(v, dict)})} for b in agg["buckets"]]
        elif "doc_count" in agg:
            out[key] = {"count": agg["doc_count"], **flat(subs)}
    return out
print(json.dumps({"section": name, "total": data["hits"]["total"]["value"], **flat(data.get("aggregations"))},
                 ensure_ascii=False))
PY
}

range_filter="{\"range\":{\"timestamp\":{\"gte\":\"now-${days}d\"}}}"

query top_rules <<JSON
{"size":0,"track_total_hits":true,"query":{"bool":{"filter":[${range_filter}]}},
 "aggs":{"rules":{"terms":{"field":"rule.id","size":40},
   "aggs":{"level":{"terms":{"field":"rule.level","size":3}},"description":{"terms":{"field":"rule.description","size":1}}}}}}
JSON

query mail_items_accessed <<JSON
{"size":0,"track_total_hits":true,"query":{"bool":{"filter":[${range_filter},
   {"terms":{"rule.id":["91578","100531","100532","100533","100534","100535"]}}]}},
 "aggs":{"rule":{"terms":{"field":"rule.id","size":10}},
   "logon_type":{"terms":{"field":"data.office365.LogonType","size":5}},
   "owner_apps":{"filter":{"term":{"data.office365.LogonType":"0"}},
     "aggs":{"app":{"terms":{"field":"data.office365.ClientAppId","size":30,"missing":"(sin ClientAppId)"}}}},
   "foreign_mailboxes":{"filter":{"terms":{"data.office365.LogonType":["1","2"]}},
     "aggs":{"mailbox":{"terms":{"field":"data.office365.MailboxOwnerUPN","size":30}}}}}}
JSON

query payments_allowlist <<JSON
{"size":0,"track_total_hits":true,"query":{"bool":{"filter":[${range_filter},
   {"terms":{"rule.id":["101546","101547","101548","101549","102020","102021","102022","102023","102024","102025"]}}]}},
 "aggs":{"rule":{"terms":{"field":"rule.id","size":12}},
   "source":{"terms":{"field":"data.b89.source","size":5}},
   "client_ip":{"terms":{"field":"data.cloudflare.http.client_ip","size":30}},
   "client":{"terms":{"field":"data.cloudflare.http.allowlist_client","size":20}},
   "path":{"terms":{"field":"data.cloudflare.http.path","size":30}},
   "status":{"terms":{"field":"data.cloudflare.http.status","size":15}}}}
JSON
