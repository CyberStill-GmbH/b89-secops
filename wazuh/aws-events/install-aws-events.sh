#!/usr/bin/env bash
# B89 SOC — instala en el manager Wazuh (nodo AWS PowerUser) la parte Wazuh del monitoreo de la
# cuenta AWS (EventBridge → SNS → receptor aws-events → JSONL):
#
#   sudo bash wazuh/aws-events/install-aws-events.sh
#
#   1. Crea <volumen de logs del manager>/b89-collectors/aws (uid 1000 = usuario del receptor) y el
#      JSONL vacío ANTES de reiniciar (si no existe al arrancar, logcollector lo abre desde el final).
#   2. Instala reglas 101600-101699 y un bloque <localfile> entre marcadores B89:aws-events en el
#      ossec.conf del contenedor; valida con wazuh-analysisd -t (revierte si falla); persiste el
#      ossec.conf en el montaje del host; reinicia SOLO el manager (B89_RESTART=false lo omite).
# Idempotente. No toca otros servicios ni bloques (B89:collectors, office365, …).
set -Eeuo pipefail
umask 027

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M="${B89_WAZUH_CONTAINER:-b89-wazuh.manager-1}"
RECEIVER_UID="${B89_AWS_EVENTS_UID:-1000}"
BEGIN='<!-- B89:aws-events:begin -->'
END='<!-- B89:aws-events:end -->'
log() { printf '[b89-aws-events] %s\n' "$*"; }
fail() { printf '[b89-aws-events] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail 'ejecutar como root'
docker inspect "$M" >/dev/null 2>&1 || fail "no existe el contenedor $M"

LOGVOL="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/var/ossec/logs"}}{{.Source}}{{end}}{{end}}')"
[[ -d $LOGVOL ]] || fail 'no se encontró el volumen de /var/ossec/logs del manager'
install -d -m 0750 -o root -g root "$LOGVOL/b89-collectors"
install -d -m 0750 -o "$RECEIVER_UID" -g root "$LOGVOL/b89-collectors/aws"
[[ -e $LOGVOL/b89-collectors/aws/aws-events.jsonl ]] ||
  install -m 0640 -o "$RECEIVER_UID" -g root /dev/null "$LOGVOL/b89-collectors/aws/aws-events.jsonl"
log "salida: $LOGVOL/b89-collectors/aws/aws-events.jsonl"

stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
cp "$HERE/rules/b89_aws_rules.xml" "$stage/"
sed -i 's/\r$//' "$stage/b89_aws_rules.xml"
docker cp "$M:/var/ossec/etc/ossec.conf" "$stage/ossec.conf"
python3 - "$stage/ossec.conf" "$BEGIN" "$END" <<'PY'
import re, sys
path, begin, end = sys.argv[1:4]
block = (
    "<ossec_config>\n  <localfile>\n"
    "    <location>/var/ossec/logs/b89-collectors/aws/aws-events.jsonl</location>\n"
    "    <log_format>json</log_format>\n"
    "    <label key=\"b89.channel\">aws-eventbridge</label>\n"
    "  </localfile>\n</ossec_config>"
)
text = open(path, encoding="utf-8").read()
text = re.sub(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "", text, flags=re.S)
text = text.rstrip("\n") + "\n" + begin + "\n" + block + "\n" + end + "\n"
open(path, "w", encoding="utf-8").write(text)
PY
docker cp "$stage/." "$M:/tmp/b89-aws-events"
docker exec -u 0 -e RESTART="${B89_RESTART:-true}" "$M" bash -euo pipefail -c '
  O=/var/ossec; S=/tmp/b89-aws-events
  bak=$O/etc/b89-backup-aws-events-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$bak"
  cp -a $O/etc/ossec.conf "$bak/"; [ -f $O/etc/rules/b89_aws_rules.xml ] && cp -a $O/etc/rules/b89_aws_rules.xml "$bak/" || true
  install -o wazuh -g wazuh -m 0660 $S/b89_aws_rules.xml $O/etc/rules/
  install -o root -g wazuh -m 0660 $S/ossec.conf $O/etc/ossec.conf
  if ! $O/bin/wazuh-analysisd -t >/tmp/b89-aws-events-analysisd.log 2>&1; then
    tail -20 /tmp/b89-aws-events-analysisd.log >&2
    cp -a "$bak/ossec.conf" $O/etc/ossec.conf
    if [ -f "$bak/b89_aws_rules.xml" ]; then cp -a "$bak/b89_aws_rules.xml" $O/etc/rules/; else rm -f $O/etc/rules/b89_aws_rules.xml; fi
    echo "configuración inválida: revertida a $bak" >&2; exit 1
  fi
  rm -rf $S
  if [ "$RESTART" = true ]; then $O/bin/wazuh-control restart >/dev/null 2>&1; fi
'
log 'reglas 101600-101699 y <localfile> instalados; wazuh-analysisd -t OK'
HOSTCONF="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}')"
if [[ -n $HOSTCONF && -f $HOSTCONF ]]; then
  cp -p "$HOSTCONF" "${HOSTCONF}.b89-bak-$(date -u +%Y%m%dT%H%M%SZ)"
  docker cp "$M:/var/ossec/etc/ossec.conf" "$stage/persist.conf"
  cat "$stage/persist.conf" >"$HOSTCONF"
  log 'ossec.conf persistido en el montaje del host'
fi
[[ ${B89_RESTART:-true} == true ]] && log 'manager reiniciado' || log 'manager NO reiniciado (B89_RESTART=false)'
