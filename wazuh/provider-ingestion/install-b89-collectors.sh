#!/usr/bin/env bash
# B89 SOC — instala en el host Docker (AWS PowerUser o local con systemd) los collectors de
# Bitdefender GravityZone, Snyk y Cloudflare y el servicio de correo de alertas críticas/altas.
#
#   sudo bash wazuh/provider-ingestion/install-b89-collectors.sh
#
# Qué hace (idempotente; nunca imprime secretos):
#   1. Separa /opt/b89/secrets/services.env (formato .env) en archivos 0600 bajo
#      /opt/b89/secrets/collectors/ (solo si faltan). También acepta esos archivos ya creados.
#   2. Copia el código a /opt/b89/collectors y escribe sus configs (0600) y estado.
#   3. Los JSONL se escriben DENTRO del volumen de logs del manager (resuelto con docker inspect),
#      en /var/ossec/logs/b89-collectors/: no hace falta cambiar el compose.
#   4. Instala reglas 101400-101549 y un bloque <localfile> entre marcadores B89:collectors en el
#      ossec.conf del contenedor, valida con wazuh-analysisd -t (revierte si falla), persiste el
#      ossec.conf en el archivo montado del host (/wazuh-config-mount) y reinicia SOLO el manager.
#   5. Instala units systemd b89-collector-<proveedor>.{service,timer} y b89-alert-mail.{service,timer};
#      ejecuta cada collector una vez y muestra estado y conteo de eventos.
#   6. El timer de correo solo se activa si el token de la app tiene Mail.Send (--check).
#
# Variables: B89_WAZUH_CONTAINER (b89-wazuh.manager-1), B89_SECRETS (/opt/b89/secrets),
#   B89_ENABLE_{BITDEFENDER,SNYK,CLOUDFLARE,ALERT_MAIL}=true|false (por defecto: según secretos).
set -Eeuo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_WAZUH="$(cd "${HERE}/.." && pwd)"
M="${B89_WAZUH_CONTAINER:-b89-wazuh.manager-1}"
SECRETS="${B89_SECRETS:-/opt/b89/secrets}"
CS="${SECRETS}/collectors"
ROOT=/opt/b89/collectors
ETC="${ROOT}/etc"
STATE="${ROOT}/state"
BEGIN='<!-- B89:collectors:begin -->'
END='<!-- B89:collectors:end -->'
log() { printf '[b89-collectors] %s\n' "$*"; }
fail() { printf '[b89-collectors] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail 'ejecutar como root'
command -v python3 >/dev/null || fail 'python3 requerido'
docker inspect "$M" >/dev/null 2>&1 || fail "no existe el contenedor $M"

# ------------------------------------------------------------------ 1. secretos
install -d -m 0700 "$CS"
if [[ -s ${SECRETS}/services.env ]]; then
  python3 - "${SECRETS}/services.env" "$CS" <<'PY'
import os, pathlib, re, sys
src, dest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
mapping = {
    "BITDEFENDER_API_KEY": "bitdefender-api-key", "BITDEFENDER_REGION": "bitdefender-region",
    "SNYK_TOKEN": "snyk-token", "SNYK_ORG_ID": "snyk-org-id", "SNYK_API_URL": "snyk-api-url",
    "CLOUDFLARE_API_TOKEN": "cloudflare-api-token",
    "TENANT_ID": "entra-tenant-id", "CLIENT_ID": "entra-client-id", "CLIENT_SECRET": "entra-client-secret",
    "ALERT_EMAIL_TO": "alert-email-to", "ALERT_EMAIL_FROM": "alert-email-from",
    "ALERT_INTERVAL_MIN": "alert-interval-min", "ALERT_MAIL_METHOD": "alert-mail-method",
}
for raw in src.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key, value = key.strip().removeprefix("export ").strip(), value.strip()
    if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) > 1:
        value = value[1:-1]
    else:
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    name = mapping.get(key)
    if not name or not value:
        continue
    target = dest / name
    if target.exists():
        continue
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(value + "\n")
PY
fi
has() { [[ -s ${CS}/$1 ]]; }
want() { local v="${!1:-}"; if [[ -n $v ]]; then [[ $v == true ]]; else shift; for f in "$@"; do has "$f" || return 1; done; fi; }
BD=false; SN=false; CF=false; AM=false
want B89_ENABLE_BITDEFENDER bitdefender-api-key && BD=true
want B89_ENABLE_SNYK snyk-token && SN=true
want B89_ENABLE_CLOUDFLARE cloudflare-api-token && CF=true
want B89_ENABLE_ALERT_MAIL entra-tenant-id entra-client-id entra-client-secret alert-email-to alert-email-from && AM=true
log "habilitados: bitdefender=$BD snyk=$SN cloudflare=$CF alert-mail=$AM"

# ------------------------------------------------------------------ 2. código y configs
LOGVOL="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/var/ossec/logs"}}{{.Source}}{{end}}{{end}}')"
[[ -d $LOGVOL ]] || fail 'no se encontró el volumen de /var/ossec/logs del manager'
OUT="${LOGVOL}/b89-collectors"
install -d -m 0750 "$ROOT" "$ROOT/provider-ingestion" "$ROOT/alert-mail" "$STATE" "$OUT"
install -d -m 0700 "$ETC"
for d in common bitdefender snyk cloudflare; do
  install -d -m 0750 "$ROOT/provider-ingestion/$d"
  install -m 0640 "${HERE}/$d"/*.py "$ROOT/provider-ingestion/$d/"
done
install -m 0640 "${REPO_WAZUH}/alert-mail/b89_alert_mail.py" "$ROOT/alert-mail/"
find "$ROOT" -name '*.py' -exec sed -i 's/\r$//' {} +
read_file() { if [[ -s ${CS}/$1 ]]; then tr -d '\r\n' <"${CS}/$1"; fi; }
# Crear los JSONL antes de reiniciar el manager: si no existen al arrancar, logcollector los abre
# más tarde desde el final y se pierde el primer lote.
for f in bitdefender-gz snyk-issues cloudflare-security; do
  [[ -e $OUT/$f.jsonl ]] || install -m 0640 /dev/null "$OUT/$f.jsonl"
done

python3 - "$ETC" "$CS" "$STATE" "$OUT" "$LOGVOL" "$(read_file bitdefender-region)" "$(read_file snyk-org-id)" \
  "$(read_file snyk-api-url)" "$(read_file alert-email-to)" "$(read_file alert-email-from)" <<'PY'
import json, os, sys
etc, cs, state, out, logvol, region, org, snyk_api, to, sender = sys.argv[1:11]
def write(name, data):
    path = os.path.join(etc, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, indent=1)
write("bitdefender.json", {"region": region or "us", "api_key_file": f"{cs}/bitdefender-api-key",
    "state_file": f"{state}/bitdefender.json", "output_file": f"{out}/bitdefender-gz.jsonl"})
snyk = {"api_url": snyk_api or "https://api.snyk.io", "token_file": f"{cs}/snyk-token",
    "state_file": f"{state}/snyk.json", "output_file": f"{out}/snyk-issues.jsonl", "initial_lookback_hours": 24}
if org:
    snyk["org_id"] = org
write("snyk.json", snyk)
write("cloudflare.json", {"token_file": f"{cs}/cloudflare-api-token", "state_file": f"{state}/cloudflare.json",
    "output_file": f"{out}/cloudflare-security.jsonl", "initial_lookback_hours": 1, "max_lookback_hours": 24})
write("alert-mail.json", {"tenant_id_file": f"{cs}/entra-tenant-id", "client_id_file": f"{cs}/entra-client-id",
    "client_secret_file": f"{cs}/entra-client-secret", "from": sender,
    "to": [a.strip() for a in to.replace(";", ",").split(",") if a.strip()],
    "alerts_file": f"{logvol}/alerts/alerts.json", "state_file": f"{state}/alert-mail.json",
    "min_level": 10, "max_per_email": 50, "max_emails_per_hour": 6,
    "console_url": "https://dev.security.b89.io/app/b89-alerts"})
PY

# ------------------------------------------------------------------ 3. reglas + ossec.conf
stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
cp "${HERE}"/rules/*.xml "$stage/"
sed -i 's/\r$//' "$stage"/*.xml
docker cp "$M:/var/ossec/etc/ossec.conf" "$stage/ossec.conf"
cp "$stage/ossec.conf" "$stage/ossec.conf.orig"
python3 - "$stage/ossec.conf" "$BEGIN" "$END" "$BD" "$SN" "$CF" <<'PY'
import re, sys
path, begin, end, bd, sn, cf = sys.argv[1:7]
files = [("bitdefender-gz", "bitdefender", bd), ("snyk-issues", "snyk", sn), ("cloudflare-security", "cloudflare", cf)]
blocks = [
    "<ossec_config>\n  <localfile>\n"
    f"    <location>/var/ossec/logs/b89-collectors/{name}.jsonl</location>\n"
    "    <log_format>json</log_format>\n"
    "    <label key=\"b89.channel\">provider-api</label>\n"
    "  </localfile>\n</ossec_config>"
    for name, _vendor, on in files if on == "true"
]
text = open(path, encoding="utf-8").read()
text = re.sub(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "", text, flags=re.S)
if blocks:
    text = text.rstrip("\n") + "\n" + begin + "\n" + "\n".join(blocks) + "\n" + end + "\n"
open(path, "w", encoding="utf-8").write(text)
PY
docker cp "$stage/." "$M:/tmp/b89-collectors"
docker exec -u 0 "$M" bash -euo pipefail -c '
  O=/var/ossec; S=/tmp/b89-collectors
  bak=$O/etc/b89-backup-collectors-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$bak"
  cp -a $O/etc/ossec.conf "$bak/"; cp -a $O/etc/rules "$bak/rules"
  install -o wazuh -g wazuh -m 0660 $S/b89_bitdefender_rules.xml $S/b89_snyk_rules.xml $S/b89_cloudflare_rules.xml $O/etc/rules/
  install -o root -g wazuh -m 0660 $S/ossec.conf $O/etc/ossec.conf
  if ! $O/bin/wazuh-analysisd -t >/tmp/b89-collectors-analysisd.log 2>&1; then
    tail -20 /tmp/b89-collectors-analysisd.log >&2
    cp -a "$bak/ossec.conf" $O/etc/ossec.conf; rm -rf $O/etc/rules; cp -a "$bak/rules" $O/etc/rules
    echo "configuración inválida: revertida a $bak" >&2; exit 1
  fi
  rm -rf $S
  $O/bin/wazuh-control restart >/dev/null 2>&1
'
log 'reglas 101400-101549 instaladas; wazuh-analysisd -t OK; manager reiniciado'
# Persistir: el contenedor copia /wazuh-config-mount/etc/ossec.conf sobre ossec.conf en cada arranque.
HOSTCONF="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}')"
if [[ -n $HOSTCONF && -f $HOSTCONF ]]; then
  cp -p "$HOSTCONF" "${HOSTCONF}.b89-bak-$(date -u +%Y%m%dT%H%M%SZ)"
  docker cp "$M:/var/ossec/etc/ossec.conf" "$stage/persist.conf"
  cat "$stage/persist.conf" >"$HOSTCONF"
  log "ossec.conf persistido en el montaje del host"
fi

# ------------------------------------------------------------------ 4. systemd
unit() { # nombre descripción comando intervalo
  cat >"/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=$2
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
User=root
UMask=0027
ExecStart=$3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectControlGroups=true
ReadOnlyPaths=${CS} ${ETC} ${ROOT}
ReadWritePaths=${STATE} ${OUT}
TimeoutStartSec=300
EOF
  cat >"/etc/systemd/system/$1.timer" <<EOF
[Unit]
Description=Programa $2

[Timer]
OnBootSec=90s
OnUnitActiveSec=$4
RandomizedDelaySec=20s
Persistent=true
Unit=$1.service

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "/etc/systemd/system/$1.service" "/etc/systemd/system/$1.timer"
}
PI="$ROOT/provider-ingestion"
unit b89-collector-bitdefender 'B89 Bitdefender GravityZone collector' "/usr/bin/python3 -I $PI/bitdefender/gravityzone.py --config $ETC/bitdefender.json" 10min
unit b89-collector-snyk 'B89 Snyk issues collector' "/usr/bin/python3 -I $PI/snyk/issues.py --config $ETC/snyk.json" 15min
unit b89-collector-cloudflare 'B89 Cloudflare security collector' "/usr/bin/python3 -I $PI/cloudflare/security.py --config $ETC/cloudflare.json" 5min
INTERVAL="$(read_file alert-interval-min)"; [[ $INTERVAL =~ ^[0-9]{1,3}$ ]] || INTERVAL=5
unit b89-alert-mail 'B89 alert mail (Graph sendMail)' "/usr/bin/python3 -I $ROOT/alert-mail/b89_alert_mail.py --config $ETC/alert-mail.json" "${INTERVAL}min"
systemctl daemon-reload

for p in bitdefender snyk cloudflare; do
  case $p in bitdefender) on=$BD ;; snyk) on=$SN ;; cloudflare) on=$CF ;; esac
  if [[ $on == true ]]; then
    systemctl start "b89-collector-$p.service" || true
    systemctl enable --now "b89-collector-$p.timer" >/dev/null
    rc="$(systemctl show -p ExecMainStatus --value "b89-collector-$p.service")"
    msg="$(journalctl -u "b89-collector-$p.service" --no-pager -o cat 2>/dev/null | grep -E "^b89-$p:" | tail -1)"
    log "$p: exit=$rc · $msg · líneas JSONL=$(wc -l <"$OUT/$(case $p in bitdefender) echo bitdefender-gz ;; snyk) echo snyk-issues ;; cloudflare) echo cloudflare-security ;; esac).jsonl" 2>/dev/null || echo 0)"
  else
    systemctl disable --now "b89-collector-$p.timer" >/dev/null 2>&1 || true
  fi
done

if [[ $AM == true ]]; then
  if /usr/bin/python3 -I "$ROOT/alert-mail/b89_alert_mail.py" --config "$ETC/alert-mail.json" --check; then
    systemctl enable --now b89-alert-mail.timer >/dev/null
    log "correo de alertas activo cada ${INTERVAL} min (nivel >= 10)"
    if [[ ${B89_ALERT_MAIL_TEST:-false} == true ]]; then
      /usr/bin/python3 -I "$ROOT/alert-mail/b89_alert_mail.py" --config "$ETC/alert-mail.json" --test
    fi
  else
    systemctl disable --now b89-alert-mail.timer >/dev/null 2>&1 || true
    log 'correo de alertas instalado pero APAGADO: la app Entra no tiene Mail.Send (Graph, aplicación, con consentimiento)'
  fi
fi
log 'listo'
