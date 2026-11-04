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
        # run_as: false (como infra/local/wazuh-dashboard/wazuh.local.yml): la app habla con la API
        # del manager como wazuh-wui; con run_as la API intentaría mapear cada usuario B89 y el
        # chequeo «API connection» se queda girando.
        entry["run_as"] = False
yaml.safe_dump(data, open(path, "w"), sort_keys=False)
PY
chown 1000:1000 config/wazuh_dashboard/wazuh.yml; chmod 0600 config/wazuh_dashboard/wazuh.yml

# --- 4. Config del dashboard y del API ------------------------------------------
# Sin los plugins B89 (login b89_ops) no hay proxy auth posible: se aborta en vez de exponer el
# formulario del Security plugin.
compgen -G "$SRC/infra/local/wazuh-dashboard/plugins-dist/b89Ops-*.zip" >/dev/null \
  || { echo 'faltan los plugins B89 en infra/local/wazuh-dashboard/plugins-dist (build-plugins.sh)' >&2; exit 1; }
cp "$HOST_DIR/opensearch_dashboards.yml" "$ROOT/config/opensearch_dashboards.yml"
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
# Cuentas demo por rol (B89_DEMO_ACCOUNTS, docs/04-identidad-y-acceso.md): la fuente es
# secrets/demo-accounts.txt (0600, una cuenta por línea: `usuario rol contraseña`; `#` comenta).
# Una línea B89_DEMO_ACCOUNTS ya presente en secrets/api.env se conserva tal cual; si falta (p. ej.
# api.env regenerado), se rehacen los hashes scrypt desde el .txt. Guarda: si el código aún no
# admite la variable (KNOWN_B89_VARIABLES), definirla tumbaría el arranque del API.
if [[ -s $SECRETS/demo-accounts.txt ]] && ! grep -q '^B89_DEMO_ACCOUNTS=' "$SECRETS/api.env"; then
  if grep -q "'B89_DEMO_ACCOUNTS'" "$SRC/platform/configuration/src/schema/environment.schema.ts"; then
    log 'cuentas demo: regenerando B89_DEMO_ACCOUNTS desde secrets/demo-accounts.txt'
    demo_accounts=''
    while read -r demo_user demo_role demo_password; do
      [[ -z $demo_user || $demo_user == \#* ]] && continue
      [[ $demo_user =~ ^[a-z0-9][a-z0-9._@+-]{2,63}$ && $demo_role =~ ^b89\.(soc\.analyst|soc\.lead|auditor|platform\.admin)$ ]] \
        || { echo 'secrets/demo-accounts.txt: línea inválida' >&2; exit 1; }
      demo_account_hash="$(printf '%s' "$demo_password" | docker run --rm -i -v "$SRC/scripts/dev:/s:ro" \
        node:24.21.0-trixie-slim node /s/hash-demo-admin-password.mjs)"
      demo_accounts+="${demo_accounts:+,}{\"username\":\"$demo_user\",\"role\":\"$demo_role\",\"passwordHash\":\"$demo_account_hash\"}"
    done <"$SECRETS/demo-accounts.txt"
    # Comillas simples: Compose interpola `$` en env_file y los hashes scrypt los contienen.
    [[ -n $demo_accounts ]] && printf "B89_DEMO_ACCOUNTS='[%s]'\n" "$demo_accounts" >>"$SECRETS/api.env"
    chmod 600 "$SECRETS/api.env"
    unset demo_accounts demo_user demo_role demo_password demo_account_hash
  else
    log 'cuentas demo: el código aún no admite B89_DEMO_ACCOUNTS; solo la cuenta admin'
  fi
fi
# La excepción demo vence como máximo a los 30 días del arranque: se renueva en cada despliegue.
DEMO_UNTIL="$(date -u -d '+29 days' +%Y-%m-%dT%H:%M:%SZ)" SOC_HOSTNAME="$SOC_HOSTNAME" \
  envsubst '${SOC_HOSTNAME} ${DEMO_UNTIL}' <"$HOST_DIR/api.env.template" >"$ROOT/config/api.env"
chmod 0644 "$ROOT/config/api.env"

# Bunny (asistente IA): sin IAM no hay Bedrock, así que usa Claude por la API directa de Anthropic
# con la clave B89_CLAUDE_API de /opt/b89/secrets/services.env (nunca en el repo). Cada despliegue
# la vuelve a copiar a api.env (así una rotación se aplica). Sin clave queda apagado.
# Guarda: hasta que platform/configuration acepte las variables B89_BUNNY_* (KNOWN_B89_VARIABLES),
# activarlas tumba el arranque del API con CONFIG_VALUE_INVALID.
sed -i '/^B89_BUNNY_/d' "$SECRETS/api.env"
bunny_key="$(grep -s '^B89_CLAUDE_API=.\+' "$SECRETS/services.env" | cut -d= -f2- || true)"
if ! grep -q "'B89_BUNNY_API_KEY'" "$SRC/platform/configuration/src/schema/environment.schema.ts"; then
  log 'Bunny: el código aún no admite B89_BUNNY_* en la configuración; asistente apagado'
elif [[ -n $bunny_key ]]; then
  printf 'B89_BUNNY_API_KEY=%s\n' "$bunny_key" >>"$SECRETS/api.env"; chmod 600 "$SECRETS/api.env"
  log 'Bunny: clave de Anthropic presente, asistente activado (Claude)'
  printf '%s\n' 'B89_BUNNY_ENABLED=true' 'B89_BUNNY_PROVIDER=anthropic' 'B89_BUNNY_EFFORT=medium' \
    'B89_BUNNY_REDACT_PII=true' >>"$ROOT/config/api.env"
  sed -i "s/^b89_ops.bunny.enabled: .*/b89_ops.bunny.enabled: true/" "$ROOT/config/opensearch_dashboards.yml"
else
  log 'Bunny: sin B89_CLAUDE_API en secrets/services.env, asistente apagado'
fi
unset bunny_key

COMPOSE=(docker compose --env-file "$SECRETS/compose.env" -f "$WD/docker-compose.yml" -f "$HOST_DIR/compose.b89.yaml")
# Con B89 Respond ya desplegado (deploy-respond.sh), el proyecto incluye sus servicios.
[[ -d $ROOT/respond/frontend ]] && COMPOSE+=(-f "$HOST_DIR/compose.respond.yaml")

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
# SKIP_API_BUILD=1: conserva las imágenes vigentes del API y del migrador (p. ej. si apps/api
# tiene trabajo en curso que aún no compila).
if [[ ${SKIP_API_BUILD:-0} == 1 ]]; then
  log 'construyendo imagen del dashboard B89 (API y migrador sin cambios)'
  "${COMPOSE[@]}" build wazuh.dashboard
else
  log 'construyendo imágenes (dashboard B89, API, migrador)'
  "${COMPOSE[@]}" --profile tools build wazuh.dashboard api migrator
fi
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

log 'proxy auth B89 en el indexer (solo desde la IP del dashboard)'
INDEXER_ADMIN_PASSWORD="$INDEXER_ADMIN_PASSWORD" bash "$SRC/infra/aws-poweruser/scripts/apply-indexer-security.sh"

log 'ingesta sin Entra: lector, token y gateway'
INDEXER_ADMIN_PASSWORD="$INDEXER_ADMIN_PASSWORD" bash "$SRC/infra/aws-poweruser/scripts/setup-ingestion.sh"
"${COMPOSE[@]}" up -d --force-recreate wazuh-gateway

log 'contenido B89 del manager (reglas, grupos, integraciones sin activar)'
bash "$SRC/infra/aws-poweruser/scripts/setup-wazuh-content.sh"
log 'agente Wazuh del propio nodo'
bash "$SRC/infra/aws-poweruser/scripts/setup-host-agent.sh"

log 'arrancando dashboard, API y edge'
"${COMPOSE[@]}" up -d --force-recreate wazuh.dashboard api edge
bash "$SRC/infra/aws-poweruser/scripts/bootstrap-wazuh-app.sh"
"${COMPOSE[@]}" ps --format 'table {{.Name}}\t{{.Status}}'
log 'listo'
