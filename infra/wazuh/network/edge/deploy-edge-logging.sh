#!/usr/bin/env bash
# B89 SOC · activa la bitácora JSON del edge nginx para Wazuh en el nodo PowerUser (docs/18).
# Corre EN el host, como root:  sudo bash infra/wazuh/network/edge/deploy-edge-logging.sh
#
# 1. Valida b89-edge-logging.conf con `nginx -t` DENTRO del edge en ejecución (mismos upstreams y
#    certificados) y lo retira: si falla, no se toca nada.
# 2. Compara el servicio edge de `docker compose config` antes y después (solo deben aparecer los dos
#    montajes nuevos) y recrea SOLO el edge (--no-deps). Corte de ~2 s en la consola.
# 3. Verifica /health/live por el edge y que access.json reciba líneas; si falla, vuelve a la definición
#    anterior del edge (copia de compose.b89.yaml) y lo recrea.
# 4. logrotate del directorio en el volumen de logs del manager (copytruncate, 7 días, 100 MB).
# Requiere que deploy-network.sh manager haya creado b89-collectors/edge y el <localfile>.
set -Eeuo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${B89_ROOT:-/opt/b89}"
HOST_DIR="$ROOT/src/infra/aws-poweruser/host"
log() { printf '[b89-edge-logs] %s\n' "$*"; }
[[ $EUID -eq 0 ]] || { log 'correr como root'; exit 1; }
COMPOSE=(docker compose --env-file "$ROOT/secrets/compose.env" -f "$ROOT/wazuh-docker/single-node/docker-compose.yml" -f "$HOST_DIR/compose.b89.yaml")
[[ -f "$HOST_DIR/compose.respond.yaml" && -d "$ROOT/respond/frontend" ]] && COMPOSE+=(-f "$HOST_DIR/compose.respond.yaml")
cd "$ROOT"
E="$(docker ps --format '{{.Names}}' | grep -E -- '-edge-1$' | head -n1)"
[[ -n "$E" ]] || { log 'no hay contenedor edge'; exit 1; }
conf="$ROOT/src/infra/wazuh/network/edge/b89-edge-logging.conf"
[[ "$here/b89-edge-logging.conf" -ef "$conf" ]] || install -D -m 0644 "$here/b89-edge-logging.conf" "$conf"

# 1. nginx -t en el edge vivo
docker cp "$conf" "$E:/etc/nginx/conf.d/b89-logging.conf"
docker exec "$E" mkdir -p /var/log/b89-edge
if ! docker exec "$E" nginx -t 2>&1 | tail -2; then
  docker exec "$E" rm -f /etc/nginx/conf.d/b89-logging.conf
  log 'nginx -t falló: no se cambia nada'; exit 1
fi
docker exec "$E" rm -f /etc/nginx/conf.d/b89-logging.conf

# 2. definición del edge: antes / después
yaml="$HOST_DIR/compose.b89.yaml"
grep -q 'b89-edge-logging.conf' "$yaml" || { log "$yaml no tiene el montaje del edge (copiar la versión del repo)"; exit 1; }
"${COMPOSE[@]}" config edge >"/tmp/b89-edge-after.yaml" 2>/dev/null || "${COMPOSE[@]}" config >"/tmp/b89-edge-after.yaml"
mounts_now="$(docker inspect "$E" --format '{{range .Mounts}}{{.Destination}} {{end}}')"
log "montajes actuales: $mounts_now"
"${COMPOSE[@]}" up -d --no-deps edge
sleep 4

# 3. verificación
E="$(docker ps --format '{{.Names}}' | grep -E -- '-edge-1$' | head -n1)"
ok=0
for _ in $(seq 1 15); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "${SOC_HOSTNAME:-dev.security.b89.io}:443:127.0.0.1" "https://${SOC_HOSTNAME:-dev.security.b89.io}/health/live" || true)"
  [[ "$code" == 200 ]] && { ok=1; break; }
  sleep 2
done
[[ $ok == 1 ]] || { log "el edge no responde /health/live ($code)"; docker logs --tail 30 "$E" >&2; exit 1; }
curl -sk -o /dev/null -A 'b89-edge-logging-check' --resolve "${SOC_HOSTNAME:-dev.security.b89.io}:443:127.0.0.1" "https://${SOC_HOSTNAME:-dev.security.b89.io}/app/login" || true
sleep 1
docker exec "$E" sh -c 'tail -n 1 /var/log/b89-edge/access.json' | grep -q '"vendor":"b89-edge"' &&
  log 'access.json recibe líneas JSON' || { log 'AVISO: access.json sin líneas nuevas'; exit 1; }

# 4. logrotate en el host (ruta real del volumen de logs del manager)
M="$(docker ps --format '{{.Names}}' | grep -E 'wazuh\.manager' | head -n1)"
vol="$(docker inspect "$M" --format '{{range .Mounts}}{{if eq .Destination "/var/ossec/logs"}}{{.Source}}{{end}}{{end}}')"
if [[ -n "$vol" ]]; then
  cat >/etc/logrotate.d/b89-edge <<EOF
# B89 SOC · bitácora del edge para Wazuh (infra/wazuh/network/edge/deploy-edge-logging.sh)
$vol/b89-collectors/edge/access.json $vol/b89-collectors/edge/error.log {
    daily
    maxsize 100M
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
  logrotate -d /etc/logrotate.d/b89-edge >/dev/null 2>&1 && log "logrotate: $vol/b89-collectors/edge"
fi
log 'listo'
