#!/usr/bin/env bash
# B89 SOC · despliegue de la visibilidad de red en el manager (docs/18-visibilidad-de-red-y-capacidades-wazuh.md).
#
# Corre EN el host de los contenedores (EC2 PowerUser), como root, desde una copia del repo:
#   sudo bash infra/wazuh/network/deploy-network.sh manager   # decoders, reglas de red, listas, <localfile> del edge
#   sudo bash infra/wazuh/network/deploy-network.sh lists     # solo refresca las listas de reputación (timer diario)
#   sudo bash infra/wazuh/network/deploy-network.sh check     # muestra qué cambiaría, sin aplicar
#
# Instala en el manager:
#   - etc/decoders/b89_network_decoders.xml
#   - las reglas de los casos de uso con owner network-visibility (detections/<fuente>/<caso>/rule.xml →
#     etc/rules/b89_soc_<fuente>_<caso>.xml, mismo nombre que usa deploy-detections.sh)
#   - listas: b89-expected-listeners (versionada), b89-ti-blocklist, b89-ti-tor, b89-egress-known (fuentes
#     públicas, b89_threat_intel.py) y b89-cf-waf-attackers (consulta al indexer), con claves canario TEST-NET
#     para las pruebas de wazuh-logtest en productivo; y su <list> en <ruleset>
#   - <localfile> json del edge (b89-collectors/edge/access.json) y syslog del error.log, entre marcadores
# Seguridad: check_rule_ids.py contra lo instalado, respaldo en etc/b89-backup-<ts>-network/, wazuh-analysisd -t
# antes de reiniciar, verificación de analysisd/remoted y del agente 001 después; cualquier fallo restaura el
# respaldo y reinicia. Solo reinicia si algo cambió. Persiste el ossec.conf en el montaje del host.
# No usar deploy-host.sh ni ship.sh para esto.
set -Eeuo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
# shellcheck source=../../../wazuh/manager/policy/lib.sh
source "$repo/wazuh/manager/policy/lib.sh"
M="$(b89_manager)"
mode="${1:-manager}"
agent_id="${B89_VERIFY_AGENT:-001}"
cache="${B89_TI_CACHE:-/var/lib/b89-threat-intel}"
log() { printf '[b89-network] %s\n' "$*"; }
case "$mode" in manager | lists | check) ;; *) b89_die "uso: $0 manager|lists|check" ;; esac

stage="$B89_WORK/stage"
mkdir -p "$stage/rules" "$stage/decoders" "$stage/lists"

# ---------------------------------------------------------------- listas
b89_python "$here/threat-intel/b89_threat_intel.py" fetch --out "$stage/lists" --cache "$cache" \
  --egress-static "$here/lists/b89-egress-static" ${B89_TI_FIREHOL:+--firehol} >&2
# IPs del WAF de Cloudflare (bloqueo/desafío) con 5+ eventos en 7 días.
cat >"$B89_WORK/cf-query.json" <<'JSON'
{"size":0,"query":{"bool":{"filter":[{"terms":{"rule.id":["101510","101513","101740","101741","101742"]}},
 {"range":{"timestamp":{"gte":"now-7d"}}}]}},
 "aggs":{"ips":{"terms":{"field":"data.cloudflare.firewall.client_ip","size":5000,"min_doc_count":5}}}}
JSON
b89_indexer POST '/wazuh-alerts-*/_search' "$B89_WORK/cf-query.json"
if [[ "$INDEXER_STATUS" == 200 ]]; then
  b89_python "$here/threat-intel/b89_threat_intel.py" cloudflare --in "$INDEXER_BODY" --out "$stage/lists/b89-cf-waf-attackers" >&2
else
  log "AVISO: consulta de Cloudflare al indexer devolvió $INDEXER_STATUS; se conserva la lista instalada"
  b89_mexec cat /var/ossec/etc/lists/b89-cf-waf-attackers >"$stage/lists/b89-cf-waf-attackers" 2>/dev/null ||
    echo 'b89-sin-datos-b89-cf-waf-attackers.invalid:placeholder' >"$stage/lists/b89-cf-waf-attackers"
fi
# Canarios TEST-NET (RFC 5737): nunca aparecen en tráfico real; los usan los fixtures en productivo.
{
  echo '203.0.113.211:b89-canario-prueba'
  echo '203.0.113.212:b89-canario-prueba'
} >>"$stage/lists/b89-ti-blocklist"
echo '203.0.113.221:b89-canario-prueba' >>"$stage/lists/b89-ti-tor"
echo '203.0.113.231:b89-canario-prueba' >>"$stage/lists/b89-cf-waf-attackers"
echo '192.0.2.:b89-canario-prueba' >>"$stage/lists/b89-egress-known"
sed -i '/^b89-sin-datos-.*\.invalid:placeholder$/d' "$stage"/lists/b89-*
tr -d '\r' <"$here/lists/b89-expected-listeners" >"$stage/lists/b89-expected-listeners"
lists="b89-ti-blocklist b89-ti-tor b89-cf-waf-attackers b89-egress-known b89-expected-listeners"

# ---------------------------------------------------------------- reglas y decoders
if [[ "$mode" != lists ]]; then
  tr -d '\r' <"$here/decoders/b89_network_decoders.xml" >"$stage/decoders/b89_network_decoders.xml"
  # Copia del 0040 oficial del manager con el hermano B89 de auditd-syscall (IP del SOCKADDR) y exclusión
  # del original: los hermanos solo se encadenan dentro del mismo archivo (build_auditd_override.py).
  docker cp "$M:/var/ossec/ruleset/decoders/0040-auditd_decoders.xml" "$(b89_hp "$B89_WORK/0040-auditd_decoders.xml")"
  b89_python "$here/decoders/build_auditd_override.py" "$B89_WORK/0040-auditd_decoders.xml" \
    "$stage/decoders/b89_auditd_decoders.xml" >&2
  b89_python - "$repo" >"$B89_WORK/rules.tsv" <<'PY'
import sys, yaml, pathlib
root = pathlib.Path(sys.argv[1])
for meta in sorted((root / "detections").glob("*/*/metadata.yaml")):
    m = yaml.safe_load(meta.read_text(encoding="utf-8"))
    if m.get("owner") == "network-visibility" and (meta.parent / "rule.xml").exists():
        rel = meta.parent.relative_to(root / "detections")
        print(f"{(meta.parent / 'rule.xml').as_posix()}\tb89_soc_{'_'.join(p.replace('-', '_') for p in rel.parts)}.xml")
PY
  while IFS=$'\t' read -r src name; do tr -d '\r' <"$src" >"$stage/rules/$name"; done <"$B89_WORK/rules.tsv"
  names="$(cd "$stage/rules" && ls)"
  log "reglas de red: $(echo "$names" | wc -l) archivos"
  # shellcheck disable=SC2016
  b89_mexec bash -c '
    cd /var/ossec
    for f in ruleset/rules/*.xml etc/rules/*.xml; do
      case " $* " in *" $(basename "$f") "*) continue ;; esac
      grep -oE "<rule[^>]* id=\"[0-9]+\"" "$f" | grep -oE "[0-9]+\"$" | tr -d "\"" | sed "s#\$# $f#"
    done' _ $names >"$B89_WORK/installed-ids.txt"
  if ! b89_python "$repo/wazuh/manager/policy/check_rule_ids.py" --installed "$B89_WORK/installed-ids.txt" \
    "$stage"/rules/*.xml >"$B89_WORK/ids.log"; then
    cat "$B89_WORK/ids.log" >&2
    b89_die 'colisión de IDs de reglas: no se instala nada'
  fi
  tail -n 1 "$B89_WORK/ids.log" | sed 's/^/[b89-network] ids: /'
fi

# ---------------------------------------------------------------- bloque <localfile> del edge
BEGIN='<!-- B89:edge-logs:begin (infra/wazuh/network/deploy-network.sh) -->'
END='<!-- B89:edge-logs:end -->'
cat >"$stage/edge-localfile.xml" <<XML
$BEGIN
<ossec_config>
  <!-- Edge nginx de la consola del SOC (docs/18): JSON con la IP real del cliente. -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/b89-collectors/edge/access.json</location>
    <label key="b89.source">edge-nginx</label>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/b89-collectors/edge/error.log</location>
  </localfile>
</ossec_config>
$END
XML

docker exec -u 0 "$M" rm -rf /tmp/b89-network-stage
docker cp "$(b89_hp "$stage")" "$M:/tmp/b89-network-stage" >/dev/null
# shellcheck disable=SC2016
b89_mexec bash -euo pipefail -c '
  O=/var/ossec; S=/tmp/b89-network-stage; mode="$1"; agent="$2"; shift 2; lists="$*"; changed=0
  trap "rm -rf $S" EXIT
  same() { [ -f "$2" ] && [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }
  if [ "$mode" != lists ]; then
    for f in $S/rules/*.xml; do same "$f" "$O/etc/rules/$(basename "$f")" || { echo "[b89-network] cambia: etc/rules/$(basename "$f")"; changed=1; }; done
    for f in $S/decoders/*.xml; do same "$f" "$O/etc/decoders/$(basename "$f")" || { echo "[b89-network] cambia: etc/decoders/$(basename "$f")"; changed=1; }; done
    grep -q "<decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml</decoder_exclude>" $O/etc/ossec.conf || { echo "[b89-network] falta <decoder_exclude> de 0040-auditd"; changed=1; }
    grep -qF "B89:edge-logs:begin" $O/etc/ossec.conf || { echo "[b89-network] falta el <localfile> del edge"; changed=1; }
  fi
  for l in $lists; do
    same "$S/lists/$l" "$O/etc/lists/$l" || { echo "[b89-network] cambia: etc/lists/$l ($(wc -l <"$S/lists/$l") claves)"; changed=1; }
    grep -q "<list>etc/lists/$l</list>" $O/etc/ossec.conf || { echo "[b89-network] falta <list>etc/lists/$l</list>"; changed=1; }
  done
  if [ $changed = 0 ]; then echo "[b89-network] sin cambios: no se reinicia"; exit 0; fi
  if [ "$mode" = check ]; then echo "[b89-network] check: no se aplica nada"; exit 0; fi

  bak=$O/etc/b89-backup-$(date -u +%Y%m%dT%H%M%SZ)-network
  mkdir -p "$bak"; cp -a $O/etc/ossec.conf "$bak/"; cp -a $O/etc/rules "$bak/rules"; cp -a $O/etc/lists "$bak/lists"; cp -a $O/etc/decoders "$bak/decoders"
  echo "[b89-network] respaldo: $bak"
  restore() {
    for d in rules lists decoders; do rm -rf $O/etc/$d && cp -a "$bak/$d" $O/etc/$d; done
    cp -a "$bak/ossec.conf" $O/etc/ossec.conf
    $O/bin/wazuh-control restart >/dev/null 2>&1 || true
  }
  if [ "$mode" != lists ]; then
    install -o wazuh -g wazuh -m 0660 $S/rules/*.xml $O/etc/rules/
    install -o wazuh -g wazuh -m 0660 $S/decoders/*.xml $O/etc/decoders/
    grep -q "<decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml</decoder_exclude>" $O/etc/ossec.conf ||
      sed -i "0,/<\/ruleset>/s##  <decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml</decoder_exclude>\n  </ruleset>#" $O/etc/ossec.conf
    mkdir -p $O/logs/b89-collectors/edge && chown wazuh:wazuh $O/logs/b89-collectors/edge
    touch $O/logs/b89-collectors/edge/access.json $O/logs/b89-collectors/edge/error.log
    if ! grep -qF "B89:edge-logs:begin" $O/etc/ossec.conf; then
      { echo; cat $S/edge-localfile.xml; } >>$O/etc/ossec.conf
    fi
  fi
  for l in $lists; do
    install -o wazuh -g wazuh -m 0660 "$S/lists/$l" "$O/etc/lists/$l"
    grep -q "<list>etc/lists/$l</list>" $O/etc/ossec.conf || sed -i "0,/<\/ruleset>/s##  <list>etc/lists/$l</list>\n  </ruleset>#" $O/etc/ossec.conf
  done
  if ! $O/bin/wazuh-analysisd -t >/tmp/b89-network-test.log 2>&1; then
    tail -20 /tmp/b89-network-test.log >&2; restore
    echo "[b89-network] analysisd -t falló: restaurado $bak" >&2; exit 1
  fi
  echo "[b89-network] analysisd -t OK"
  $O/bin/wazuh-control restart >/dev/null 2>&1 || true
  for i in $(seq 1 45); do
    st="$($O/bin/wazuh-control status 2>&1 || true)"
    if echo "$st" | grep -q "wazuh-analysisd is running" && echo "$st" | grep -q "wazuh-remoted is running"; then
      for j in $(seq 1 30); do
        if $O/bin/agent_control -i "$agent" 2>/dev/null | grep -q "Status:.*Active"; then
          echo "[b89-network] manager reiniciado; agente $agent activo"; exit 0
        fi
        sleep 4
      done
      echo "[b89-network] el agente $agent no volvió a Active: restaurando" >&2; restore; exit 1
    fi
    sleep 2
  done
  echo "$st" >&2; restore
  echo "[b89-network] el manager no arrancó: restaurado $bak" >&2; exit 1
' _ "$mode" "$agent_id" $lists

# ---------------------------------------------------------------- persistencia del ossec.conf
[[ "$mode" == check ]] && exit 0
mount_src="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
if [[ -n "$mount_src" && -f "$mount_src" && -w "$mount_src" ]]; then
  [[ -e "$mount_src.b89-orig" ]] || cp -p "$mount_src" "$mount_src.b89-orig"
  for l in $lists; do
    grep -q "<list>etc/lists/$l</list>" "$mount_src" || sed -i "0,/<\/ruleset>/s##  <list>etc/lists/$l</list>\n  </ruleset>#" "$mount_src"
  done
  if [[ "$mode" == manager ]] && ! grep -q '<decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml' "$mount_src"; then
    sed -i "0,/<\/ruleset>/s##  <decoder_exclude>ruleset/decoders/0040-auditd_decoders.xml</decoder_exclude>\n  </ruleset>#" "$mount_src"
  fi
  if [[ "$mode" == manager ]] && ! grep -qF 'B89:edge-logs:begin' "$mount_src"; then
    { echo; cat "$stage/edge-localfile.xml"; } >>"$mount_src"
  fi
  log "ossec.conf persistido en el montaje del host ($mount_src)"
else
  log "AVISO: ossec.conf montado no accesible (${mount_src:-ninguno}); si se recrea el contenedor, reaplicar"
fi
