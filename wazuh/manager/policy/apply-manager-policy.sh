#!/usr/bin/env bash
# B89 SOC — política del manager: ossec.conf + reglas B89 (docs/16-politicas.md). Idempotente.
#
#   1. Reglas: comprueba que los IDs B89 no colisionan entre sí ni con lo instalado
#      (check_rule_ids.py) y prepara wazuh/office365/rules + infra/wazuh/*/rules.
#      La lista etc/lists/b89-break-glass se crea vacía si falta (nunca se pisa una existente).
#   2. ossec.conf: render_ossec_policy.py (VD + indexer, umbral de alertas, correo apagado,
#      lista B89 en <ruleset>, bloque B89:policy con Active Response opt-in).
#   3. Si algo cambió: respaldo en etc/b89-backup-<ts>-policy/, instala, valida con
#      wazuh-analysisd/modulesd/remoted/execd -t, reinicia y comprueba los daemons. Si falla,
#      restaura todo el respaldo y reinicia.
#   4. Persistencia: wazuh-docker copia /wazuh-config-mount/etc/ossec.conf sobre etc/ossec.conf en
#      cada arranque. Si ese origen existe y es escribible aquí (EC2:
#      /opt/b89/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf) se le aplica
#      la misma política. B89_PERSIST_MOUNT=0 lo omite. Reglas y listas viven en el volumen etc.
#
# Variables: B89_AR_AUTO_BLOCK (0), B89_AR_TIMEOUT (600), B89_AR_WHITELIST (""),
#            B89_LOG_ALERT_LEVEL (3), B89_VD_FEED_INTERVAL (60m), B89_PERSIST_MOUNT (auto).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"

M="$(b89_manager)"
tmpl="$here/../ossec.b89-policy.xml.tmpl"
render="$here/render_ossec_policy.py"
b89_log "manager: $M (auto-block=${B89_AR_AUTO_BLOCK:-0})"

# --- 1. Reglas B89 ---------------------------------------------------------------
mapfile -t rule_files < <(ls "$B89_REPO_ROOT"/wazuh/office365/rules/*.xml "$B89_REPO_ROOT"/infra/wazuh/*/rules/*.xml)
stage="$B89_WORK/stage"; mkdir -p "$stage/rules"
for f in "${rule_files[@]}"; do tr -d '\r' <"$f" >"$stage/rules/$(basename "$f")"; done
names="$(cd "$stage/rules" && ls)"
# IDs instalados fuera de los archivos B89 (ruleset oficial y reglas locales de otros dueños).
# shellcheck disable=SC2016
b89_mexec bash -c '
  cd /var/ossec
  for f in ruleset/rules/*.xml etc/rules/*.xml; do
    case " $* " in *" $(basename "$f") "*) continue ;; esac
    grep -oE "<rule[^>]* id=\"[0-9]+\"" "$f" | grep -oE "[0-9]+\"$" | tr -d "\"" | sed "s#\$# $f#"
  done' _ $names >"$B89_WORK/installed-ids.txt"
if ! b89_python "$here/check_rule_ids.py" --installed "$B89_WORK/installed-ids.txt" "$stage"/rules/*.xml \
  >"$B89_WORK/ids.log"; then
  cat "$B89_WORK/ids.log" >&2
  b89_die 'colisión de IDs de reglas: no se instala nada'
fi
sed 's/^/[b89-policy] reglas: /' "$B89_WORK/ids.log"

# --- 2. ossec.conf ------------------------------------------------------------------
conf="$stage/ossec.conf"
docker cp "$M:/var/ossec/etc/ossec.conf" "$(b89_hp "$conf")" >/dev/null
conf_result="$(b89_python "$render" "$conf" "$tmpl")"

# --- 3. Instalar con validación y rollback -------------------------------------------
docker exec -u 0 "$M" rm -rf /tmp/b89-policy-stage
docker cp "$(b89_hp "$stage")" "$M:/tmp/b89-policy-stage" >/dev/null
# shellcheck disable=SC2016
b89_mexec bash -euo pipefail -c '
  O=/var/ossec; S=/tmp/b89-policy-stage; changed=0
  trap "rm -rf $S" EXIT
  same() { [ -f "$2" ] && [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }
  for f in $S/rules/*.xml; do same "$f" "$O/etc/rules/$(basename "$f")" || changed=1; done
  [ -e $O/etc/lists/b89-break-glass ] || changed=1
  [ "$1" = changed ] && changed=1
  if [ $changed = 0 ]; then echo "[b89-policy] manager ya cumple la política: sin cambios ni reinicio"; exit 0; fi

  bak=$O/etc/b89-backup-$(date -u +%Y%m%dT%H%M%SZ)-policy
  mkdir -p "$bak"; cp -a $O/etc/ossec.conf "$bak/"; cp -a $O/etc/rules "$bak/rules"; cp -a $O/etc/lists "$bak/lists"
  restore() {
    rm -rf $O/etc/rules && cp -a "$bak/rules" $O/etc/rules
    rm -rf $O/etc/lists && cp -a "$bak/lists" $O/etc/lists
    cp -a "$bak/ossec.conf" $O/etc/ossec.conf
    $O/bin/wazuh-control restart >/dev/null 2>&1 || true
  }
  install -o wazuh -g wazuh -m 0660 $S/rules/*.xml $O/etc/rules/
  [ -e $O/etc/lists/b89-break-glass ] || install -o wazuh -g wazuh -m 0660 /dev/null $O/etc/lists/b89-break-glass
  install -o root -g wazuh -m 0660 $S/ossec.conf $O/etc/ossec.conf
  for t in wazuh-analysisd wazuh-modulesd wazuh-remoted wazuh-execd; do
    if ! $O/bin/$t -t >/tmp/b89-policy-test.log 2>&1; then
      tail -20 /tmp/b89-policy-test.log >&2; restore
      echo "configuración inválida ($t -t): restaurado $bak" >&2; exit 1
    fi
  done
  $O/bin/wazuh-control restart >/dev/null 2>&1 || true
  for i in $(seq 1 30); do
    st="$($O/bin/wazuh-control status 2>&1 || true)"
    if echo "$st" | grep -q "wazuh-analysisd is running" && echo "$st" | grep -q "wazuh-modulesd is running"; then
      echo "[b89-policy] manager reiniciado con la política (respaldo: $bak)"; exit 0
    fi
    sleep 2
  done
  echo "$st" >&2; restore
  echo "el manager no arrancó con la política: restaurado $bak" >&2; exit 1
' _ "$conf_result"

# --- 4. Persistencia frente a recreación/reinicio del contenedor ------------------------
mount_src="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
if [[ "${B89_PERSIST_MOUNT:-auto}" == 0 ]]; then
  b89_log 'persistencia omitida (B89_PERSIST_MOUNT=0)'
elif [[ -n "$mount_src" && -f "$mount_src" && -w "$mount_src" ]]; then
  [[ -e "$mount_src.b89-orig" ]] || cp -p "$mount_src" "$mount_src.b89-orig"
  r="$(b89_python "$render" "$mount_src" "$tmpl")"
  b89_log "origen montado $mount_src: $r (original en .b89-orig)"
else
  b89_log "AVISO: el origen montado de ossec.conf no es accesible desde este host (${mount_src:-ninguno}); si el contenedor se reinicia o recrea, reaplicar este script"
fi
