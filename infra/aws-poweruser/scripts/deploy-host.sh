#!/usr/bin/env bash
# B89 SOC (modo PowerUser) — instala o actualiza el runtime en el nodo. Se ejecuta EN el host,
# como root, con el árbol del repo ya copiado en /opt/b89/src (ver ship.sh). Idempotente:
# los secretos se generan una sola vez en /opt/b89/secrets (0700/0600) y nunca salen del host.
#
#   sudo SOC_HOSTNAME=dev.security.b89.io bash /opt/b89/src/infra/aws-poweruser/scripts/deploy-host.sh
set -euo pipefail
# 022: los contenedores (indexer uid 1000, dashboard) leen configs del clon de wazuh-docker. Los
# secretos quedan protegidos por /opt/b89/secrets (0700) y chmod 600 explícito.
umask 022

: "${SOC_HOSTNAME:?}"
WAZUH_DOCKER_TAG="${WAZUH_DOCKER_TAG:-v4.14.8}"
ROOT=/opt/b89
SRC=$ROOT/src
HOST_DIR=$SRC/infra/aws-poweruser/host
SECRETS=$ROOT/secrets
WD=$ROOT/wazuh-docker/single-node
log() { printf '[b89-deploy] %s\n' "$*"; }

export DEBIAN_FRONTEND=noninteractive
command -v envsubst >/dev/null || apt-get install -y gettext-base
python3 -c 'import bcrypt, yaml' 2>/dev/null || apt-get install -y python3-bcrypt python3-yaml
command -v certbot >/dev/null || apt-get install -y certbot
install -d -m 0700 "$SECRETS"
install -d -m 0755 "$ROOT/config" /var/www/certbot

# --- 1. Secretos (una sola vez) -------------------------------------------------
# Política de la API de Wazuh: mayúscula, minúscula, dígito y símbolo de .*+?-
wpass() { printf '%sAa9.' "$(openssl rand -hex 16)"; }
if [[ ! -s $SECRETS/compose.env ]]; then
  log 'generando secretos'
  {
    echo "INDEXER_ADMIN_PASSWORD=$(wpass)"
    echo "KIBANASERVER_PASSWORD=$(wpass)"
    echo "WAZUH_API_PASSWORD=$(wpass)"
    echo "POSTGRES_ADMIN_PASSWORD=$(openssl rand -hex 24)"
    echo "B89_MIGRATOR_PASSWORD=$(openssl rand -hex 24)"
    echo "B89_RUNTIME_PASSWORD=$(openssl rand -hex 24)"
  } >"$SECRETS/compose.env"
  openssl rand -base64 18 | tr -d '/+=' | head -c 20 | sed 's/^/B89-/' >"$SECRETS/demo-admin-password.txt"
  chmod 600 "$SECRETS"/*
fi
set -a; . "$SECRETS/compose.env"; set +a

# --- 2. PKI interna de PostgreSQL ------------------------------------------------
if [[ ! -s $ROOT/pki/ca.pem ]]; then
  log 'creando CA interna y certificado de postgres'
  install -d -m 0755 "$ROOT/pki" "$ROOT/pki/postgres"
  openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 1825 -subj '/CN=B89 SOC dev internal CA' \
    -keyout "$SECRETS/ca.key" -out "$ROOT/pki/ca.pem"
  openssl req -new -nodes -newkey rsa:2048 -subj '/CN=postgres' \
    -keyout "$ROOT/pki/postgres/postgres.key" -out /tmp/pg.csr
  openssl x509 -req -in /tmp/pg.csr -CA "$ROOT/pki/ca.pem" -CAkey "$SECRETS/ca.key" -CAcreateserial \
    -days 825 -sha256 -extfile <(printf 'subjectAltName=DNS:postgres\nextendedKeyUsage=serverAuth\n') \
    -out "$ROOT/pki/postgres/postgres.crt"
  rm -f /tmp/pg.csr
  chmod 0644 "$ROOT/pki/ca.pem" "$ROOT/pki/postgres/postgres.crt"
  chown 999:999 "$ROOT/pki/postgres/postgres.key"; chmod 0600 "$ROOT/pki/postgres/postgres.key"
fi

# --- 3. wazuh-docker fijado + certificados + usuarios internos ---------------------
if [[ ! -d $ROOT/wazuh-docker ]]; then
  log "clonando wazuh-docker $WAZUH_DOCKER_TAG"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$WAZUH_DOCKER_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$ROOT/wazuh-docker"
fi
cd "$WD"
if [[ ! -s config/wazuh_indexer_ssl_certs/root-ca.pem ]]; then
  log 'generando certificados de Wazuh'
  docker compose -f generate-indexer-certs.yml run --rm generator
fi
if [[ ! -f $SECRETS/.internal-users-applied ]]; then
  log 'aplicando hashes de admin y kibanaserver en internal_users.yml (antes del primer arranque)'
  python3 - config/wazuh_indexer/internal_users.yml <<'PY'
import os, sys, bcrypt, yaml
path = sys.argv[1]
data = yaml.safe_load(open(path))
for user, var in (("admin", "INDEXER_ADMIN_PASSWORD"), ("kibanaserver", "KIBANASERVER_PASSWORD")):
    data[user]["hash"] = bcrypt.hashpw(os.environ[var].encode(), bcrypt.gensalt(12)).decode()
yaml.safe_dump(data, open(path, "w"), sort_keys=False)
PY
  touch "$SECRETS/.internal-users-applied"
fi
# La app de Wazuh del dashboard lee la credencial de wazuh-wui de este archivo (el oficial trae
# la de ejemplo). Solo lo lee el uid 1000 del contenedor.
python3 - config/wazuh_dashboard/wazuh.yml <<'PY'
import os, sys, yaml
path = sys.argv[1]
data = yaml.safe_load(open(path))
for host in data["hosts"]:
    for entry in host.values():
        entry["password"] = os.environ["WAZUH_API_PASSWORD"]
yaml.safe_dump(data, open(path, "w"), sort_keys=False)
PY
chown 1000:1000 config/wazuh_dashboard/wazuh.yml; chmod 0600 config/wazuh_dashboard/wazuh.yml

# --- 4. Config del dashboard y del API ------------------------------------------
cp "$SRC/infra/local/wazuh-dashboard/opensearch_dashboards.local.yml" "$ROOT/config/opensearch_dashboards.yml"
if compgen -G "$SRC/infra/local/wazuh-dashboard/plugins-dist/*.zip" >/dev/null; then
  log 'plugins B89 presentes: se habilitan sus claves'
  { echo; cat "$SRC/infra/local/wazuh-dashboard/b89-plugins.local.yml"; } >>"$ROOT/config/opensearch_dashboards.yml"
fi
chmod 0644 "$ROOT/config/opensearch_dashboards.yml"

if [[ ! -s $SECRETS/api.env ]]; then
  log 'generando secretos del API'
  demo_hash="$(docker run --rm -i -v "$SRC/scripts/dev:/s:ro" node:24.21.0-trixie-slim \
    node /s/hash-demo-admin-password.mjs <"$SECRETS/demo-admin-password.txt")"
  vapid="$(openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0)"
  {
    echo "B89_POSTGRES_PASSWORD=$B89_RUNTIME_PASSWORD"
    echo "B89_ENTITY_REF_KEY=$(openssl rand 48 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    echo "B89_VAPID_PRIVATE_KEY=$vapid"
    echo "B89_ENTRA_CLIENT_SECRET=$(openssl rand -hex 24)"
    # Comillas simples: Compose interpola `$` en env_file y el hash scrypt los contiene.
    echo "B89_DEMO_ADMIN_PASSWORD_HASH='$demo_hash'"
  } >"$SECRETS/api.env"
  chmod 600 "$SECRETS/api.env"
fi
# La excepción demo vence como máximo a los 30 días del arranque: se renueva en cada despliegue.
DEMO_UNTIL="$(date -u -d '+29 days' +%Y-%m-%dT%H:%M:%SZ)" SOC_HOSTNAME="$SOC_HOSTNAME" \
  envsubst '${SOC_HOSTNAME} ${DEMO_UNTIL}' <"$HOST_DIR/api.env.template" >"$ROOT/config/api.env"
chmod 0644 "$ROOT/config/api.env"

COMPOSE=(docker compose --env-file "$SECRETS/compose.env" -f "$WD/docker-compose.yml" -f "$HOST_DIR/compose.b89.yaml")

# --- 5. Certificado público (HTTP-01 con webroot servido por un nginx temporal) ------
if [[ ! -s /etc/letsencrypt/live/$SOC_HOSTNAME/fullchain.pem ]]; then
  log "emitiendo certificado Let's Encrypt para $SOC_HOSTNAME"
  docker rm -f b89-acme >/dev/null 2>&1 || true
  docker run -d --name b89-acme -p 80:80 -v /var/www/certbot:/usr/share/nginx/html:ro nginx:1.29.3 >/dev/null
  certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --webroot --webroot-path /var/www/certbot -d "$SOC_HOSTNAME"
  docker rm -f b89-acme >/dev/null
fi
SOC_HOSTNAME="$SOC_HOSTNAME" envsubst '${SOC_HOSTNAME}' <"$HOST_DIR/edge.conf.template" >"$ROOT/config/edge.conf"
chmod 0644 "$ROOT/config/edge.conf"
cat >/etc/letsencrypt/renewal-hooks/deploy/b89-edge.sh <<'EOF'
#!/bin/sh
docker exec b89-edge-1 nginx -s reload || true
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/b89-edge.sh

# --- 6. Build y arranque -----------------------------------------------------
log 'construyendo imágenes (dashboard B89, API, migrador)'
"${COMPOSE[@]}" --profile tools build wazuh.dashboard api migrator
log 'arrancando Wazuh y PostgreSQL'
"${COMPOSE[@]}" up -d wazuh.indexer wazuh.manager postgres --wait

log 'roles de base de datos'
# Las contraseñas viajan por variables de entorno del exec (\getenv), no por argumentos.
{
  printf '%s\n' '\getenv mig B89_MIG' '\getenv run B89_RUN' 'BEGIN;' \
    "SELECT set_config('b89.migrator_password', :'mig', true), set_config('b89.runtime_password', :'run', true);"
  cat "$SRC/platform/database/bootstrap/roles.sql"
  echo 'COMMIT;'
} | B89_MIG="$B89_MIGRATOR_PASSWORD" B89_RUN="$B89_RUNTIME_PASSWORD" "${COMPOSE[@]}" exec -T \
  -e B89_MIG -e B89_RUN postgres psql -v ON_ERROR_STOP=1 -U b89_admin -d b89_secops -q -f - >/dev/null
log 'migraciones'
"${COMPOSE[@]}" --profile tools run --rm migrator migrate

log 'arrancando dashboard, API y edge'
"${COMPOSE[@]}" up -d wazuh.dashboard api edge
"${COMPOSE[@]}" ps --format 'table {{.Name}}\t{{.Status}}'
log 'listo'
