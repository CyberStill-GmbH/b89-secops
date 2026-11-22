#!/bin/sh
set -eu

ACTION="${1:-}"
[ "$ACTION" = install ] || [ "$ACTION" = remove ] || { echo "Uso: sudo $0 install --watch-root RUTA [--watch-root RUTA...] [--control-plane-url HTTPS_URL] | remove" >&2; exit 2; }
shift
case "$(uname -s)" in Darwin) OS=macos ;; Linux) OS=linux ;; *) echo "Solo se admiten macOS y Linux." >&2; exit 1 ;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; x86_64|amd64) ARCH=x64 ;; *) echo "Arquitectura no admitida: $(uname -m)." >&2; exit 1 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como administrador, por ejemplo con sudo." >&2; exit 1; }
PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || { echo "Se requiere Python 3 instalado." >&2; exit 1; }
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
DEST=/opt/b89/ferrispector
DATA=/var/lib/b89/ferrispector
CONFIG="$DATA/config.json"
MARK_BEGIN='<!-- B89:FERRISPECTOR:BEGIN -->'
MARK_END='<!-- B89:FERRISPECTOR:END -->'

wazuh_config() {
  if [ "$OS" = macos ]; then printf '%s' /Library/Ossec/etc/ossec.conf; else printf '%s' /var/ossec/etc/ossec.conf; fi
}

restart_wazuh() {
  if [ "$OS" = macos ]; then
    /Library/Ossec/bin/wazuh-control restart
  else
    systemctl restart wazuh-agent
  fi
}

remove_localfile() {
  cfg="$(wazuh_config)"
  [ -f "$cfg" ] || return 0
  "$PYTHON" - "$cfg" "$MARK_BEGIN" "$MARK_END" <<'PY'
import pathlib, re, sys, xml.etree.ElementTree as ET
path=pathlib.Path(sys.argv[1]); text=path.read_text(encoding='utf-8'); begin,end=sys.argv[2:]
updated=re.sub(re.escape(begin)+r".*?"+re.escape(end), "", text, flags=re.S)
if updated != text:
    ET.fromstring(updated)
    path.write_text(updated, encoding='utf-8')
PY
}

if [ "$ACTION" = remove ]; then
  if [ "$OS" = macos ]; then
    launchctl bootout system/io.b89.ferrispector >/dev/null 2>&1 || true
    rm -f /Library/LaunchDaemons/io.b89.ferrispector.plist
  else
    systemctl disable --now b89-ferrispector.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/b89-ferrispector.service
    systemctl daemon-reload
  fi
  remove_localfile
  restart_wazuh
  rm -rf -- "$DEST" "$DATA"
  echo "Ferrispector local fue eliminado. Revoca su credencial en Políticas de protección de datos; Wazuh y las carpetas vigiladas permanecen."
  exit 0
fi

[ -x "$SCRIPT_DIR/bin/yr" ] || { echo "Falta el motor YARA-X del paquete. Ejecuta el instalador desde el paquete extraído." >&2; exit 1; }
[ -f "$SCRIPT_DIR/policy/dlp-rules.yarc" ] || { echo "Faltan las reglas compiladas del paquete." >&2; exit 1; }
[ -f "$SCRIPT_DIR/manifest.json" ] || { echo "Falta manifest.json; verifica que el paquete sea oficial para esta plataforma." >&2; exit 1; }
"$PYTHON" - "$SCRIPT_DIR/manifest.json" "$OS" "$ARCH" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream: manifest=json.load(stream)
platform = "apple-darwin" if sys.argv[2] == "macos" else "unknown-linux-gnu"
if manifest.get("platform") != platform or manifest.get("architecture") != sys.argv[3]:
    raise SystemExit("El paquete no corresponde a esta plataforma y arquitectura.")
PY
[ -f "$(wazuh_config)" ] || { echo "Instala y conecta primero el agente Wazuh; no se modificó el equipo." >&2; exit 1; }
command -v "$PYTHON" >/dev/null
[ -f "$SCRIPT_DIR/ferrispector.py" ] || { echo "Falta ferrispector.py." >&2; exit 1; }

WATCH_ROOTS=""
CONTROL_URL=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --watch-root) [ "$#" -ge 2 ] || exit 2; WATCH_ROOTS="${WATCH_ROOTS}
$2"; shift 2 ;;
    --control-plane-url) [ "$#" -ge 2 ] || exit 2; CONTROL_URL="$2"; shift 2 ;;
    *) echo "Opción no reconocida: $1" >&2; exit 2 ;;
  esac
done
[ -n "$WATCH_ROOTS" ] || { echo "Indica al menos una carpeta aprobada con --watch-root." >&2; exit 2; }
[ ! -e "$CONFIG" ] || { echo "Ferrispector ya tiene configuración. Usa 'remove' antes de reinstalar." >&2; exit 1; }

install -d -o root -g wheel -m 0755 "$DEST" 2>/dev/null || install -d -o root -g root -m 0755 "$DEST"
install -d -o root -g wheel -m 0700 "$DATA" 2>/dev/null || install -d -o root -g root -m 0700 "$DATA"
install -d -o root -g wheel -m 0755 "$DEST/bin" "$DEST/policy" 2>/dev/null || install -d -o root -g root -m 0755 "$DEST/bin" "$DEST/policy"
install -m 0755 "$SCRIPT_DIR/bin/yr" "$DEST/bin/yr"
install -m 0644 "$SCRIPT_DIR/policy/dlp-rules.yarc" "$DEST/policy/dlp-rules.yarc"
install -m 0644 "$SCRIPT_DIR/policy/fingerprints.sha256" "$DEST/policy/fingerprints.sha256"
install -m 0644 "$SCRIPT_DIR/THIRD-PARTY-NOTICES.txt" "$DEST/THIRD-PARTY-NOTICES.txt"
install -m 0644 "$SCRIPT_DIR/manifest.json" "$DEST/manifest.json"
install -m 0755 "$SCRIPT_DIR/ferrispector.py" "$DEST/ferrispector.py"
install -m 0644 /dev/null "$DATA/events.jsonl"
set --
OLD_IFS="$IFS"; IFS='
'
for root in $WATCH_ROOTS; do [ -n "$root" ] && set -- "$@" --watch-root "$root"; done
IFS="$OLD_IFS"
[ -n "$CONTROL_URL" ] && set -- "$@" --control-plane-url "$CONTROL_URL"
"$PYTHON" "$DEST/ferrispector.py" init --config "$CONFIG" --release "$DEST" --data "$DATA" "$@"
chmod 0600 "$CONFIG" "$DATA/fingerprints.sha256" "$DATA/events.jsonl"

CFG="$(wazuh_config)"
"$PYTHON" - "$CFG" "$DATA/events.jsonl" "$MARK_BEGIN" "$MARK_END" <<'PY'
import pathlib, sys, xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
path=pathlib.Path(sys.argv[1]); text=path.read_text(encoding='utf-8'); begin,end=sys.argv[3:]
if begin not in text:
    block=f"\n  {begin}\n  <localfile><location>{escape(sys.argv[2])}</location><log_format>json</log_format></localfile>\n  {end}\n"
    if "</ossec_config>" not in text: raise SystemExit("Wazuh ossec.conf no contiene el cierre esperado.")
    text=text.replace("</ossec_config>", block+"</ossec_config>", 1)
ET.fromstring(text)
path.with_suffix(path.suffix+".b89-backup").write_text(path.read_text(encoding='utf-8'), encoding='utf-8')
path.write_text(text, encoding='utf-8')
PY

if [ "$OS" = macos ]; then
  cat > /Library/LaunchDaemons/io.b89.ferrispector.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.b89.ferrispector</string>
<key>ProgramArguments</key><array><string>$PYTHON</string><string>$DEST/ferrispector.py</string><string>run</string><string>--config</string><string>$CONFIG</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>30</integer>
<key>WorkingDirectory</key><string>$DATA</string>
<key>StandardOutPath</key><string>/var/log/b89-ferrispector.log</string>
<key>StandardErrorPath</key><string>/var/log/b89-ferrispector.log</string>
</dict></plist>
PLIST
  chmod 0644 /Library/LaunchDaemons/io.b89.ferrispector.plist
  launchctl bootstrap system /Library/LaunchDaemons/io.b89.ferrispector.plist
else
  cat > /etc/systemd/system/b89-ferrispector.service <<UNIT
[Unit]
Description=B89 Ferrispector local DLP detector
After=network-online.target wazuh-agent.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$PYTHON $DEST/ferrispector.py run --config $CONFIG
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DATA
ReadOnlyPaths=$DEST
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now b89-ferrispector.service
fi
restart_wazuh
echo "Ferrispector está instalado y vigila únicamente las carpetas aprobadas. El servicio opera como administrador para poder leerlas."
