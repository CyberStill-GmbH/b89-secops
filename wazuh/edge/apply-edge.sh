#!/usr/bin/env bash
# B89 SecOps — edge unificado y dashboard con proxy auth (docs/04, docs/08). Idempotente.
#
# Corre en la instancia Wazuh (all-in-one) por SSM. Orden y compuertas:
#   1. Exige el dashboard del fork con el plugin b89_ops instalado: sin él, /b89/login no
#      existe y el edge dejaría a todos sin entrada. No instala el paquete (lo hace el release
#      del fork).
#   2. Exige que la API responda por la red privada (B89_API) en /api/auth/introspect con 401
#      sin cookie. Si responde otra cosa, se detiene antes de cambiar nada.
#   3. Escribe el bloque B89:dashboard en opensearch_dashboards.yml. Las claves que el bloque
#      redefine se comentan fuera de él para no duplicarlas. Reinicia el dashboard.
#   4. Renderiza wazuh/edge/b89-edge.conf en el archivo del dominio (reemplaza el proxy simple
#      de configure-wazuh-domain.sh). Si `nginx -t` o el reload fallan, restaura todo.
#   5. Smoke: sin sesión, `/` → 302 /b89/login y /api/alerts → 401; /b89/login → 200.
#
# Requiere que el Security plugin ya tenga el dominio de proxy auth
# (wazuh/indexer/security/apply-security.sh). Si no, el dashboard no reconoce a nadie.
#
# Variables: SOC_HOSTNAME (dominio público; p. ej. wazuh.jappi.net.pe)
#            B89_API    (salida `b89_edge_api_origin` de Terraform; p. ej. http://api.demo.b89.internal:3000)
#            B89_RESPOND_UPSTREAM (opcional; host:puerto privado del frontend B89 Respond)
#            CERT_NAME    (opcional; certificado de Let's Encrypt, por defecto b89-wazuh-dashboard)
#            SOC_EXTRA_HOSTNAMES (opcional; p. ej. "app.jappi.net.pe": hostnames adicionales del mismo SIEM.
#                         Expande el certificado con certbot (HTTP-01; el DNS ya debe apuntar a este host).
set -euo pipefail
umask 022
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { printf 'b89-edge: ERROR %s\n' "$1" >&2; exit 1; }
info() { printf 'b89-edge: %s\n' "$1"; }

: "${SOC_HOSTNAME:?}" "${B89_API:?}"
export SOC_HOSTNAME B89_API CERT_NAME="${CERT_NAME:-b89-wazuh-dashboard}"
export SOC_SERVER_NAMES="$SOC_HOSTNAME ${SOC_EXTRA_HOSTNAMES:-}"
for host in ${SOC_EXTRA_HOSTNAMES:-}; do
  [[ "$host" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || fail "hostname extra inválido: $host"
done
[[ "$SOC_HOSTNAME" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || fail 'SOC_HOSTNAME inválido'
[[ "$B89_API" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail 'B89_API debe ser scheme://host[:puerto], sin ruta'
B89_RESPOND_LOCATION=""
if [[ -n "${B89_RESPOND_UPSTREAM:-}" ]]; then
  [[ "$B89_RESPOND_UPSTREAM" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || fail 'B89_RESPOND_UPSTREAM debe ser host:puerto privado, sin esquema ni ruta'
  b89_respond_host="${B89_RESPOND_UPSTREAM%:*}"
  b89_respond_port="${B89_RESPOND_UPSTREAM##*:}"
  (( 10#$b89_respond_port >= 1 && 10#$b89_respond_port <= 65535 )) || fail 'puerto B89_RESPOND_UPSTREAM fuera de rango'
  if [[ "$b89_respond_host" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    IFS=. read -r a b c d <<<"$b89_respond_host"
    for octet in "$a" "$b" "$c" "$d"; do
      [[ "$octet" =~ ^[0-9]{1,3}$ ]] && (( 10#$octet <= 255 )) || fail 'IPv4 B89_RESPOND_UPSTREAM inválida'
    done
    if ! (( a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) )); then
      fail 'B89_RESPOND_UPSTREAM IPv4 debe estar en una red RFC1918'
    fi
  else
    [[ "$b89_respond_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.internal$ ]] ||
      fail 'B89_RESPOND_UPSTREAM DNS debe usar el sufijo privado .internal'
  fi
  b89_respond_code="$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://$B89_RESPOND_UPSTREAM/" || true)"
  [[ "$b89_respond_code" == 200 ]] || fail "B89 Respond privado no responde HTTP 200 en $B89_RESPOND_UPSTREAM/ (HTTP $b89_respond_code); edge sin cambios"
  B89_RESPOND_LOCATION="$(envsubst '${B89_RESPOND_UPSTREAM}' <"$here/b89-b89-respond.location.conf")"
fi
export B89_RESPOND_LOCATION
[[ -r "/etc/letsencrypt/live/$CERT_NAME/fullchain.pem" ]] || fail "no existe el certificado $CERT_NAME"
if [[ -n "${SOC_EXTRA_HOSTNAMES:-}" ]]; then
  domains=(-d "$SOC_HOSTNAME"); for host in $SOC_EXTRA_HOSTNAMES; do domains+=(-d "$host"); done
  certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --webroot     --webroot-path /var/www/certbot --cert-name "$CERT_NAME" --expand --keep-until-expiring "${domains[@]}"     || fail "certbot no pudo expandir $CERT_NAME a: $SOC_EXTRA_HOSTNAMES (¿el DNS ya apunta a este host?)"
fi

DASHBOARD_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
PLUGIN_BIN=/usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin
NGINX_CONF=/etc/nginx/conf.d/b89-wazuh-dashboard.conf
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1 · plugin del fork
plugin_list="$("$PLUGIN_BIN" list --allow-root 2>/dev/null)" ||
  fail 'no se pudo listar los plugins del dashboard'
if ! grep -qi 'b89' <<<"$plugin_list"; then
  fail 'el dashboard no tiene el plugin b89_ops (instalar antes el build del fork b89_ops-dashboard)'
fi

# 2 · API por la red privada
code="$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 5 "$B89_API/api/auth/introspect" || true)"
[[ "$code" == 401 ]] || fail "la API no responde 401 en $B89_API/api/auth/introspect (HTTP $code): revisar security groups y Cloud Map"
info 'API privada alcanzable'

# 3 · bloque del dashboard
cp "$DASHBOARD_YML" "$work/dashboard.previous"
cp "$NGINX_CONF" "$work/nginx.previous" 2>/dev/null || true
restore() {
  cp "$work/dashboard.previous" "$DASHBOARD_YML"
  if [[ -f "$work/nginx.previous" ]]; then cp "$work/nginx.previous" "$NGINX_CONF"; else rm -f "$NGINX_CONF"; fi
  systemctl restart wazuh-dashboard || true
  nginx -t && systemctl reload nginx || true
}
python3 - "$DASHBOARD_YML" "$here/../dashboard/opensearch_dashboards.b89.yml" <<'PY'
import re, sys
target, block_file = sys.argv[1:3]
block = open(block_file, encoding='utf-8').read().strip('\n')
text = open(target, encoding='utf-8').read()
text = re.sub(r'\n?# B89:dashboard:begin.*?# B89:dashboard:end\n?', '\n', text, flags=re.S)
keys = {m.group(1) for m in re.finditer(r'^([A-Za-z_][\w.]*):', block, re.M)}
out = []
for line in text.splitlines():
    m = re.match(r'^([A-Za-z_][\w.]*):', line)
    out.append(f'# B89 (redefinido abajo): {line}' if m and m.group(1) in keys else line)
open(target, 'w', encoding='utf-8').write(
    '\n'.join(out).rstrip('\n') + '\n\n# B89:dashboard:begin\n' + block + '\n# B89:dashboard:end\n')
PY
systemctl restart wazuh-dashboard
login_code=000
for _ in $(seq 1 60); do
  login_code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:5601/b89/login || true)"
  [[ "$login_code" == 200 ]] && break
  sleep 5
done
[[ "$login_code" == 200 ]] || { restore; fail "el dashboard no sirve /b89/login (HTTP $login_code); restaurado"; }
info 'dashboard en 127.0.0.1:5601 con login B89'

# 4 · edge nginx
envsubst '${SOC_SERVER_NAMES} ${B89_API} ${CERT_NAME} ${B89_RESPOND_LOCATION}' <"$here/b89-edge.conf" >"$work/edge.conf"
mkdir -p /var/cache/nginx/b89_auth
install -m 0644 "$work/edge.conf" "$NGINX_CONF"
if ! nginx -t; then restore; fail 'nginx -t falló; restaurado'; fi
systemctl reload nginx || { restore; fail 'reload de nginx falló; restaurado'; }

# 5 · smoke sin sesión
probe() { curl --noproxy '*' -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 \
  --resolve "$SOC_HOSTNAME:443:127.0.0.1" -H "accept: $2" "https://$SOC_HOSTNAME$1"; }
sleep 2
root="$(probe / text/html)"
api="$(probe /api/alerts application/json)"
login="$(probe /b89/login text/html)"
[[ "$root" == "302 https://$SOC_HOSTNAME/b89/login?nextUrl=/" ]] || { restore; fail "/ sin sesión → '$root' (esperado 302 al login); restaurado"; }
[[ "$api" == 401* ]] || { restore; fail "/api/alerts sin sesión → '$api' (esperado 401); restaurado"; }
[[ "$login" == 200* ]] || { restore; fail "/b89/login → '$login' (esperado 200); restaurado"; }
if [[ -n "${B89_RESPOND_UPSTREAM:-}" ]]; then
  b89-respond="$(probe /b89-respond/ text/html)"
  [[ "$b89-respond" == "302 https://$SOC_HOSTNAME/b89/login?nextUrl=/b89-respond/" ]] || { restore; fail "/b89-respond/ anónimo → '$b89-respond' (esperado login B89); restaurado"; }
fi
info "edge activo en https://$SOC_HOSTNAME (login B89, proxy auth, API privada${B89_RESPOND_UPSTREAM:+, B89 Respond con sesión y rol})"
