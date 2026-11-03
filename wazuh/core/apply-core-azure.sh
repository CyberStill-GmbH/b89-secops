#!/usr/bin/env bash
# Instala un release b89-core Azure en el host SIEM usando el core.env que ya
# materializó el bootstrap desde Key Vault. No crea, rota ni obtiene secretos.
set -euo pipefail
umask 077

fail() { printf 'b89-core-azure: ERROR %s\n' "$1" >&2; exit 1; }
info() { printf 'b89-core-azure: %s\n' "$1"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verify_only=false
if [[ "${1:-}" == --verify-only ]]; then
  verify_only=true
  shift
fi
archive="${1:?uso: apply-core-azure.sh [--verify-only] <archive.tar.gz> <sha256> [env-file]}"
expected_sha="${2:?uso: apply-core-azure.sh [--verify-only] <archive.tar.gz> <sha256> [env-file]}"
env_file="${3:-/etc/b89-core/core.env}"
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'SHA-256 de release inválido'
[[ -f "$archive" && ! -L "$archive" ]] || fail 'el archive no es un archivo normal'
echo "$expected_sha  $archive" | sha256sum --check --status || fail 'checksum del archive no coincide'

for command in sha256sum python3; do
  command -v "$command" >/dev/null || fail "falta el comando requerido: $command"
done
python3 "$HERE/verify_core_archive.py" "$archive" >/dev/null || fail 'validación del archive no pasó'
if [[ "$verify_only" == true ]]; then
  info 'archive válido; no se realizó instalación'
  exit 0
fi

[[ -f "$env_file" && ! -L "$env_file" ]] || fail 'falta el EnvironmentFile materializado desde Key Vault'
[[ "$(stat -c '%u' "$env_file")" == 0 ]] || fail 'core.env no pertenece a root'
mode="$(stat -c '%a' "$env_file")"
# El bootstrap lo deja 0640 root:b89-core para el grupo del servicio; nunca para otros.
(( (8#$mode & 0027) == 0 )) || fail 'core.env permite escritura de grupo o acceso a otros usuarios'
for command in curl tar systemctl install useradd; do
  command -v "$command" >/dev/null || fail "falta el comando requerido: $command"
done

BASE=/opt/b89-core
work="$(mktemp -d)"
link_tmp=''
previous=''
switched=false
deployment_ok=false
rollback() {
  [[ "$switched" == true && "$deployment_ok" != true ]] || return 0
  if [[ -n "$previous" && -d "$previous" ]]; then
    local restore_tmp="$BASE/.rollback-$$"
    rm -f -- "$restore_tmp"
    ln -s -- "$previous" "$restore_tmp" && mv -Tf -- "$restore_tmp" "$BASE/current"
    systemctl restart b89-core-api || true
    systemctl restart b89-core-worker || true
    info 'se restauró el release anterior tras el fallo de activación'
  else
    rm -f -- "$BASE/current"
    systemctl stop b89-core-api b89-core-worker >/dev/null 2>&1 || true
    info 'se retiró el release fallido; no existía una versión anterior'
  fi
}
cleanup() {
  rollback
  rm -rf -- "$work"
  [[ -z "$link_tmp" ]] || rm -f -- "$link_tmp"
}
trap cleanup EXIT

top=''
while IFS= read -r member; do
  component="${member%%/*}"
  [[ "$component" =~ ^b89-core-[0-9a-f]{12}$ ]] || fail 'estructura del archive inesperada'
  if [[ -z "$top" ]]; then top="$component"; fi
  [[ "$component" == "$top" ]] || fail 'el archive contiene más de una raíz'
done < <(tar -tzf "$archive")
[[ -n "$top" ]] || fail 'el archive está vacío'
tar -xzf "$archive" -C "$work" --no-same-owner --no-same-permissions
release_source="$work/$top"
[[ -s "$release_source/RELEASE" && "$(cat "$release_source/RELEASE")" == "${top#b89-core-}" ]] || \
  fail 'el marcador RELEASE no coincide con el nombre del archive'
[[ -x "$release_source/node/bin/node" ]] || fail 'Node del release no es ejecutable'
[[ "$("$release_source/node/bin/node" --version)" == 'v24.21.0' ]] || fail 'versión Node distinta de 24.21.0'
[[ -d "$release_source/api" && -d "$release_source/worker" && -d "$release_source/systemd" ]] || \
  fail 'el release no contiene API, worker y unidades systemd'

id b89-core >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin b89-core
install -d -m 0750 -o root -g b89-core "$BASE" "$BASE/releases" /etc/b89-core
if [[ "$(readlink -f "$env_file")" == "$(readlink -f /etc/b89-core/core.env)" ]]; then
  chown root:b89-core /etc/b89-core/core.env
  chmod 0640 /etc/b89-core/core.env
else
  install -m 0640 -o root -g b89-core "$env_file" /etc/b89-core/core.env
fi

release="$BASE/releases/${top#b89-core-}"
if [[ -e "$release" ]]; then
  [[ -d "$release" && ! -L "$release" ]] || fail 'el destino de release existente no es un directorio normal'
  [[ -s "$release/RELEASE" && "$(cat "$release/RELEASE")" == "${top#b89-core-}" ]] || \
    fail 'ya existe el mismo commit con contenido distinto'
  diff -qr --no-dereference "$release_source" "$release" >/dev/null || \
    fail 'el release existente difiere del archive validado'
  source_modes="$(find "$release_source" -printf '%m %P\n' | sort)"
  installed_modes="$(find "$release" -printf '%m %P\n' | sort)"
  [[ "$source_modes" == "$installed_modes" ]] || fail 'los permisos del release existente difieren del archive'
else
  mv -- "$release_source" "$release"
  chown -R root:b89-core "$release"
  chmod -R g+rX,o-rwx "$release"
fi

previous="$(readlink -f "$BASE/current" 2>/dev/null || true)"
if [[ -n "$previous" ]]; then
  [[ "$previous" == "$BASE"/releases/* && -d "$previous" ]] || \
    fail 'el release actualmente activo apunta fuera del directorio administrado'
fi
install -m 0644 "$release"/systemd/b89-core-*.service /etc/systemd/system/
systemctl daemon-reload
link_tmp="$BASE/.current-${top#b89-core-}.$$"
ln -s -- "$release" "$link_tmp"
if [[ -L "$BASE/current" && -z "$previous" ]]; then rm -f -- "$BASE/current"; fi
mv -Tf -- "$link_tmp" "$BASE/current"
link_tmp=''
switched=true
[[ "$(readlink -f "$BASE/current")" == "$release" ]] || fail 'activación atómica del release falló'

systemctl enable --quiet b89-core-api b89-core-worker || fail 'no se pudieron habilitar los servicios systemd'
systemctl restart b89-core-api || fail 'no se pudo reiniciar la API'
ready=false
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:3000/health/ready; then ready=true; break; fi
  sleep 3
done
if [[ "$ready" != true ]]; then
  fail 'API no alcanzó health/ready; se revirtió la activación'
fi

systemctl restart b89-core-worker || fail 'no se pudo reiniciar el worker'
systemctl is-active --quiet b89-core-worker || {
  fail 'worker no quedó activo; se revirtió la activación'
}
deployment_ok=true

# Conserva el release activo y tres releases anteriores para rollback.
current="$(readlink -f "$BASE/current")"
find "$BASE/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | \
  awk 'NR > 4 { $1=""; sub(/^ /, ""); print }' | while IFS= read -r old; do
    [[ -n "$old" && "$old" != "$current" && "$old" == "$BASE"/releases/* ]] || continue
    rm -rf -- "$old"
  done

info "release ${top#b89-core-} activo; API lista y worker activo; secretos no impresos"
