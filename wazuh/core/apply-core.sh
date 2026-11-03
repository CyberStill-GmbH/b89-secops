#!/usr/bin/env bash
# B89 SecOps — instala o actualiza el núcleo B89 en el host del SIEM (docs/12, opción B). Idempotente.
#
#   1. Usuario de sistema `b89-core` (sin shell ni home).
#   2. Descarga el release (URL prefirmada), verifica su SHA256 y lo extrae en
#      /opt/b89-core/releases/<sha>. Conserva los 3 anteriores: rollback e histórico.
#   3. Renderiza /etc/b89-core/core.env (0640 root:b89-core) desde el parámetro SSM con el
#      entorno (generado por Terraform) y los secretos de Secrets Manager por el rol de la instancia.
#      Los valores no se imprimen, y NO se crea ni rota ningún secreto: solo se leen.
#   4. Cambia /opt/b89-core/current con un enlace atómico, reinicia la API y espera
#      /health/ready y que el worker quede activo. Si falla, vuelve al release anterior.
#
# Variables: B89_CORE_URL, B89_CORE_SHA256, B89_CORE_ENV_PARAM (p. ej.
#            /b89-secops/demo/core/environment) y B89_AWS_REGION.
set -euo pipefail
umask 077
fail() { printf 'b89-core: ERROR %s\n' "$1" >&2; exit 1; }
info() { printf 'b89-core: %s\n' "$1"; }
: "${B89_CORE_URL:?}" "${B89_CORE_SHA256:?}" "${B89_CORE_ENV_PARAM:?}" "${B89_AWS_REGION:?}"
[[ "$B89_CORE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'B89_CORE_SHA256 inválido'
command -v aws >/dev/null || fail 'falta aws cli en el host'
command -v jq >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq >/dev/null

BASE=/opt/b89-core
work="$(mktemp -d)"; link_tmp=''; trap 'rm -rf "$work"; [[ -z "$link_tmp" ]] || rm -f -- "$link_tmp"' EXIT

# 1 · usuario
id b89-core >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin b89-core

# The API and worker run as b89-core, so every parent directory in their
# WorkingDirectory path must be traversable by that group. Repair existing
# directories too; install -d applies the requested owner/mode when they exist.
install -d -m 0750 -o root -g b89-core "$BASE" "$BASE/releases"

# 2 · release verificado
curl -fsS --max-time 600 -o "$work/core.tar.gz" "$B89_CORE_URL"
echo "${B89_CORE_SHA256}  $work/core.tar.gz" | sha256sum -c - >/dev/null || fail 'checksum del release no coincide'
top="$(tar -tzf "$work/core.tar.gz" | sed -n '1{s,/.*,,;p;}')"
[[ "$top" =~ ^b89-core-[0-9a-f]{12}$ ]] || fail "release con estructura inesperada ($top)"
release="$BASE/releases/${top#b89-core-}"
if [[ ! -d "$release" ]]; then
  tar -C "$work" -xzf "$work/core.tar.gz"
  mv "$work/$top" "$release"
  chown -R root:b89-core "$release"; chmod -R g+rX,o-rwx "$release"
fi
info "release ${release##*/} listo"

# 3 · entorno y secretos (sin imprimir valores)
install -d -m 0750 -o root -g b89-core /etc/b89-core
aws ssm get-parameter --region "$B89_AWS_REGION" --name "$B89_CORE_ENV_PARAM" \
  --query Parameter.Value --output text >"$work/env.json"
jq -e '.environment and .secrets' "$work/env.json" >/dev/null || fail 'parámetro de entorno inválido'
envfile="$work/core.env"
# EnvironmentFile de systemd: KEY="valor" con \ y " escapados; sin saltos de línea.
emit() { python3 -c 'import sys;k,v=sys.argv[1],sys.stdin.read();assert "\n" not in v.rstrip("\n"),k;v=v.rstrip("\n").replace("\\","\\\\").replace("\"","\\\"");print(f"{k}=\"{v}\"")' "$1"; }
jq -r '.environment | to_entries[] | [.key, .value] | @tsv' "$work/env.json" |
  while IFS=$'\t' read -r key value; do printf '%s' "$value" | emit "$key"; done >"$envfile"
jq -r '.secrets | to_entries[] | [.key, .value] | @tsv' "$work/env.json" |
  while IFS=$'\t' read -r key ref; do
    # Igual que ECS: "arn" o "arn:clave-json::"
    arn="$ref"; jsonkey=''
    if [[ "$ref" =~ ^(arn:aws:secretsmanager:[^:]+:[0-9]+:secret:[^:]+):([^:]+)::$ ]]; then
      arn="${BASH_REMATCH[1]}"; jsonkey="${BASH_REMATCH[2]}"
    fi
    value="$(aws secretsmanager get-secret-value --region "$B89_AWS_REGION" --secret-id "$arn" \
      --query SecretString --output text)" || fail "no se pudo leer el secreto de $key"
    [[ -n "$jsonkey" ]] && value="$(printf '%s' "$value" | jq -r --arg k "$jsonkey" '.[$k]')"
    printf '%s' "$value" | emit "$key"
  done >>"$envfile"
install -m 0640 -o root -g b89-core "$envfile" /etc/b89-core/core.env
info "core.env renderizado ($(wc -l </etc/b89-core/core.env) variables; valores no impresos)"

# 4 · activación atómica con rollback
previous="$(readlink -f "$BASE/current" 2>/dev/null || true)"
install -m 0644 "$release"/systemd/b89-core-*.service /etc/systemd/system/
systemctl daemon-reload
link_tmp="$BASE/.current-${release##*/}.$$"
ln -s "$release" "$link_tmp"
# A failed earlier activation can leave `current` self-referential. readlink -f then
# returns empty; remove only that invalid symlink so the verified release can take over.
if [[ -L "$BASE/current" && -z "$previous" ]]; then rm -f -- "$BASE/current"; fi
mv -Tf "$link_tmp" "$BASE/current"
link_tmp=''
active="$(readlink -f "$BASE/current" 2>/dev/null || true)"
[[ "$active" == "$release" ]] || fail 'el enlace current no apunta al release verificado'
systemctl enable --quiet b89-core-api b89-core-worker
systemctl restart b89-core-api
ready=false
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:3000/health/ready; then ready=true; break; fi
  sleep 3
done
if [[ "$ready" != true ]]; then
  if [[ -n "$previous" && -d "$previous" ]]; then
    ln -sfn "$previous" "$BASE/current.new" && mv -T "$BASE/current.new" "$BASE/current"
    systemctl restart b89-core-api
    fail "el release ${release##*/} no quedó listo; se volvió a ${previous##*/}"
  fi
  fail "el release ${release##*/} no quedó listo y no hay anterior"
fi
systemctl restart b89-core-worker
worker_ready=false
for _ in $(seq 1 30); do
  if systemctl is-active --quiet b89-core-worker; then worker_ready=true; break; fi
  sleep 1
done
if [[ "$worker_ready" != true ]]; then
  if [[ -n "$previous" && -d "$previous" ]]; then
    ln -sfn "$previous" "$BASE/current.new" && mv -T "$BASE/current.new" "$BASE/current"
    systemctl restart b89-core-api
    systemctl restart b89-core-worker || true
    for _ in $(seq 1 10); do
      systemctl is-active --quiet b89-core-worker && break
      sleep 1
    done
    systemctl is-active --quiet b89-core-worker || systemctl stop b89-core-worker || true
    fail "el worker del release ${release##*/} no quedó activo; API revertida a ${previous##*/}"
  fi
  fail "el worker del release ${release##*/} no quedó activo y no hay anterior"
fi
info "núcleo B89 activo: release ${release##*/} (API 127.0.0.1:3000 y worker)"

# Histórico: conservar los 3 releases más recientes además del activo.
ls -1dt "$BASE"/releases/* | tail -n +5 | while read -r old; do
  [[ "$old" == "$(readlink -f "$BASE/current")" ]] || rm -rf "$old"
done
