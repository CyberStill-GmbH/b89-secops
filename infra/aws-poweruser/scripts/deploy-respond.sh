#!/usr/bin/env bash
# B89 Respond en el nodo PowerUser: Shuffle v2.3.0 (backend, orborus, opensearch) y el frontend
# rebrandeado de b89-respond/. Se ejecuta EN el host como root, después de deploy-host.sh, con el
# fuente del frontend ya generado por `b89-respond/build.sh` en /opt/b89/respond/frontend-source.tar.gz.
set -euo pipefail
umask 022
ROOT=/opt/b89
R=$ROOT/respond
SECRETS=$ROOT/secrets
WD=$ROOT/wazuh-docker/single-node
HOST_DIR=$ROOT/src/infra/aws-poweruser/host
log() { printf '[b89-respond] %s\n' "$*"; }

[[ -s $R/frontend-source.tar.gz ]] || { echo "falta $R/frontend-source.tar.gz" >&2; exit 1; }

if ! grep -q '^SHUFFLE_OPENSEARCH_PASSWORD=' "$SECRETS/compose.env"; then
  log 'generando secretos de B89 Respond'
  {
    # OpenSearch exige mayúscula, minúscula, dígito y símbolo.
    echo "SHUFFLE_OPENSEARCH_PASSWORD=$(openssl rand -hex 16)Aa9!"
    echo "SHUFFLE_ADMIN_USERNAME=admin@b89.io"
    echo "SHUFFLE_ADMIN_PASSWORD=$(openssl rand -hex 12)Aa9."
    echo "SHUFFLE_ENCRYPTION_MODIFIER=$(openssl rand -hex 32)"
  } >>"$SECRETS/compose.env"
  chmod 600 "$SECRETS/compose.env"
fi

install -d -m 0755 "$R" "$R/apps" "$R/files"
install -d -m 0755 -o 1000 -g 1000 "$R/db"
cp "$HOST_DIR/shuffle.env" "$R/shuffle.env"
rm -rf "$R/frontend" "$R/src.tmp" && mkdir -p "$R/src.tmp"
tar -C "$R/src.tmp" -xzf "$R/frontend-source.tar.gz"
mv "$R/src.tmp/frontend" "$R/frontend" && rm -rf "$R/src.tmp"
# Si el fuente se generó en Windows (core.autocrlf), los scripts y plantillas traen CRLF y el
# entrypoint de nginx falla con `env: 'sh\r'`.
find "$R/frontend" -maxdepth 3 -type f \( -name '*.sh' -o -name '*.tpl' -o -name '*.conf' -o -name '*.tmpl' \) \
  -exec sed -i 's/\r$//' {} +

COMPOSE=(docker compose --env-file "$SECRETS/compose.env" -f "$WD/docker-compose.yml"
  -f "$HOST_DIR/compose.b89.yaml" -f "$HOST_DIR/compose.respond.yaml")
log 'construyendo el frontend de B89 Respond'
"${COMPOSE[@]}" build b89-respond-frontend
log 'arrancando B89 Respond'
"${COMPOSE[@]}" up -d shuffle-opensearch shuffle-backend shuffle-orborus b89-respond-frontend
"${COMPOSE[@]}" up -d --force-recreate edge
"${COMPOSE[@]}" ps --format 'table {{.Name}}\t{{.Status}}'
log 'listo'
