#!/usr/bin/env bash
# Contenido B89 del manager Wazuh en el nodo PowerUser: reglas, listas, grupos de agentes e
# integraciones INSTALADAS pero sin activar (quedan listas para configurar: necesitan URLs, claves
# o tenants que este nodo no tiene). Idempotente; EN el host como root.
#
#   Reglas      wazuh/office365/rules, infra/wazuh/{active-directory,endpoint,launch-detections}/rules
#   Listas      wazuh/office365/lists/b89-break-glass (vacía hasta cargar identidades reales)
#   Grupos      infra/wazuh/*/agent-groups/<grupo>.agent.conf → etc/shared/<grupo>/agent.conf
#   Integración wazuh/manager/integrations/custom-b89.py, infra/wazuh/shuffle/custom-b89-shuffle,
#               infra/wazuh/teams/custom-b89-teams → /var/ossec/integrations (sin <integration>)
#   Proveedores wazuh/provider-ingestion (Sophos, Cato) → /opt/b89/provider-ingestion (sin timers)
# Valida la configuración con `wazuh-analysisd -t` antes de reiniciar; si falla, revierte.
set -euo pipefail
SRC=/opt/b89/src
M=b89-wazuh.manager-1
log() { printf '[b89-wazuh] %s\n' "$*"; }
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/rules" "$stage/lists" "$stage/integrations" "$stage/groups"
cp "$SRC"/wazuh/office365/rules/*.xml "$SRC"/infra/wazuh/{active-directory,endpoint,launch-detections}/rules/*.xml "$stage/rules/"
# Estas reglas calibran la severidad Snyk (101732-101734), de la que dependen las reglas
# b89_watch_vulnprio_rules.xml instaladas por platform-monitoring. Sin ellas, Wazuh las ignora.
cp "$SRC/detections/snyk/severity-calibration/rule.xml" \
  "$stage/rules/b89_soc_snyk_severity_calibration.xml"
# La lista de break-glass se instala sin identidades (el ejemplo trae cuentas ficticias), con un
# centinela que nunca coincide (TLD .invalid): una lista CDB vacía rompe GET /lists de la API del
# manager («Bad format in CDB list») y la vista CDB lists de la app de Wazuh.
echo 'b89-sin-cuentas-break-glass@b89.invalid:placeholder' >"$stage/lists/b89-break-glass"
cp "$SRC/wazuh/manager/integrations/custom-b89.py" "$stage/integrations/custom-b89.py"
printf '%s\n' '#!/bin/sh' 'exec /var/ossec/framework/python/bin/python3 "$(dirname "$0")/custom-b89.py" "$@"' \
  >"$stage/integrations/custom-b89"
cp "$SRC/infra/wazuh/shuffle/custom-b89-shuffle" "$SRC/infra/wazuh/teams/custom-b89-teams" "$stage/integrations/"
for f in "$SRC"/infra/wazuh/*/agent-groups/*.agent.conf; do
  g="$(basename "$f" .agent.conf)"; mkdir -p "$stage/groups/$g"; cp "$f" "$stage/groups/$g/agent.conf"
done
find "$stage" -type f -exec sed -i 's/\r$//' {} +

# Enrolamiento de agentes con contraseña (authd use_password). Se genera una vez en el host.
if [[ ! -s /opt/b89/secrets/wazuh-authd.pass ]]; then
  (umask 077; openssl rand -hex 24 >/opt/b89/secrets/wazuh-authd.pass)
fi
cp /opt/b89/secrets/wazuh-authd.pass "$stage/authd.pass"

docker cp "$stage/." "$M:/tmp/b89-content"
docker exec -u 0 "$M" bash -euo pipefail -c '
  O=/var/ossec; S=/tmp/b89-content
  bak=$O/etc/b89-backup-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$bak"
  cp -a $O/etc/rules "$bak/rules"; cp -a $O/etc/lists "$bak/lists"; cp -a $O/etc/ossec.conf "$bak/"
  install -o wazuh -g wazuh -m 0660 $S/rules/*.xml $O/etc/rules/
  [ -s $O/etc/lists/b89-break-glass ] || install -o wazuh -g wazuh -m 0660 $S/lists/b89-break-glass $O/etc/lists/
  # Declarar la lista en <ruleset> si falta (las reglas de Office 365 la referencian).
  grep -q "etc/lists/b89-break-glass" $O/etc/ossec.conf || \
    sed -i "0,/<\/ruleset>/s##  <list>etc/lists/b89-break-glass</list>\n  </ruleset>#" $O/etc/ossec.conf
  install -o root -g wazuh -m 0640 $S/authd.pass $O/etc/authd.pass
  sed -i "/<auth>/,/<\/auth>/s#<use_password>no</use_password>#<use_password>yes</use_password>#" $O/etc/ossec.conf
  install -o root -g wazuh -m 0750 $S/integrations/* $O/integrations/
  for d in $S/groups/*/; do
    g=$(basename "$d")
    [ -d $O/etc/shared/$g ] || /var/ossec/bin/agent_groups -q -a -g "$g" >/dev/null
    install -o wazuh -g wazuh -m 0660 "$d/agent.conf" $O/etc/shared/$g/agent.conf
  done
  if ! $O/bin/wazuh-analysisd -t >/tmp/b89-analysisd.log 2>&1; then
    tail -20 /tmp/b89-analysisd.log >&2
    rm -rf $O/etc/rules && cp -a "$bak/rules" $O/etc/rules
    rm -rf $O/etc/lists && cp -a "$bak/lists" $O/etc/lists
    cp -a "$bak/ossec.conf" $O/etc/ossec.conf
    echo "configuración inválida: revertida a $bak" >&2; exit 1
  fi
  rm -rf $S
  $O/bin/wazuh-control restart >/dev/null
'
log "reglas: $(docker exec "$M" sh -c 'ls /var/ossec/etc/rules/b89_*.xml' | xargs -n1 basename | tr '\n' ' ')"
log "grupos: $(docker exec "$M" /var/ossec/bin/agent_groups -l 2>/dev/null | grep -o -E '(windows|linux)[a-z-]*' | tr '\n' ' ')"
log "integraciones instaladas (sin activar): $(docker exec "$M" sh -c 'ls /var/ossec/integrations' | grep -E 'custom-b89' | tr '\n' ' ')"

install -d -m 0755 /opt/b89/provider-ingestion
cp -a "$SRC/wazuh/provider-ingestion/." /opt/b89/provider-ingestion/
log 'proveedores Sophos/Cato copiados en /opt/b89/provider-ingestion (sin timers: faltan credenciales)'
