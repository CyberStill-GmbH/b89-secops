#!/usr/bin/env bash
# Prepara lo que el receptor cloudflare-logpush necesita ANTES de arrancar (idempotente, root):
#   - spool /opt/b89/collectors/spool/cloudflare-logpush/{tmp,incoming} del usuario del receptor
#     (uid 1000) y {done,failed} de root (solo el consumidor los toca);
#   - secreto compartido /opt/b89/secrets/collectors/cloudflare-logpush-token (48 hex, 0600, uid
#     del receptor; root lo lee igual). Nunca se imprime ni se rota aquí: si existe se conserva.
# Sin esto, Docker crearía un directorio en lugar del archivo del secreto al montar el volumen.
set -Eeuo pipefail
RECEIVER_UID="${B89_LOGPUSH_UID:-1000}"
SPOOL=/opt/b89/collectors/spool/cloudflare-logpush
SECRET_DIR=/opt/b89/secrets/collectors
SECRET="$SECRET_DIR/cloudflare-logpush-token"
log() { printf '[b89-cf-logpush] %s\n' "$*"; }
[[ $(id -u) -eq 0 ]] || { log 'ERROR: ejecutar como root' >&2; exit 1; }

install -d -m 0750 -o root -g root /opt/b89/collectors /opt/b89/collectors/spool
install -d -m 0750 -o "$RECEIVER_UID" -g root "$SPOOL" "$SPOOL/tmp" "$SPOOL/incoming"
install -d -m 0750 -o root -g root "$SPOOL/done" "$SPOOL/failed"
# Objetos a medias de un receptor interrumpido: nunca se publicaron; se descartan.
find "$SPOOL/tmp" -type f -mmin +60 -delete 2>/dev/null || true

install -d -m 0700 -o root -g root "$SECRET_DIR"
if [[ -d $SECRET ]]; then
  rmdir "$SECRET" 2>/dev/null || { log "ERROR: $SECRET es un directorio no vacío" >&2; exit 1; }
fi
if [[ ! -s $SECRET ]]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_hex(24))' >"$SECRET.tmp"
  mv "$SECRET.tmp" "$SECRET"
  log 'secreto compartido de Logpush generado'
fi
chown "$RECEIVER_UID:root" "$SECRET"
chmod 0600 "$SECRET"
log "spool listo: $SPOOL"
