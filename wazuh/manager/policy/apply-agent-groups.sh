#!/usr/bin/env bash
# B89 SOC — políticas de agente centralizadas (etc/shared/<grupo>/agent.conf). Idempotente.
#
#   1. Valida cada agent.conf con verify-agent-conf del propio manager antes de instalarlo.
#   2. Crea el grupo si falta (agent_groups -a) e instala el agent.conf solo si cambió.
#   3. No asigna agentes: la asignación es del enrolamiento (WAZUH_AGENT_GROUP) o del operador.
#
# El grupo windows-telemetry-extended se crea vacío: asignarlo exige aprobación de privacidad.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$here/lib.sh"

M="$(b89_manager)"
b89_log "manager: $M"
changed=0
for dir in "$here"/shared/*/; do
  group="$(basename "$dir")"
  src="$dir/agent.conf"
  stage="$B89_WORK/$group.conf"
  tr -d '\r' <"$src" >"$stage"
  docker cp "$(b89_hp "$stage")" "$M:/tmp/b89-$group.conf" >/dev/null
  if ! out="$(b89_mexec /var/ossec/bin/verify-agent-conf -f "/tmp/b89-$group.conf" 2>&1)" ||
    ! grep -q 'verify-agent-conf: OK' <<<"$out"; then
    b89_mexec rm -f "/tmp/b89-$group.conf"
    printf '%s\n' "$out" >&2
    b89_die "agent.conf inválido para $group"
  fi
  # shellcheck disable=SC2016
  result="$(b89_mexec bash -euo pipefail -c '
    g="$1"; S=/var/ossec/etc/shared/$g; new=/tmp/b89-$g.conf
    if [ ! -d "$S" ]; then /var/ossec/bin/agent_groups -q -a -g "$g" >/dev/null; fi
    if [ -f "$S/agent.conf" ] && [ "$(sha256sum <"$new")" = "$(sha256sum <"$S/agent.conf")" ]; then echo unchanged
    else install -o wazuh -g wazuh -m 0660 "$new" "$S/agent.conf"; echo updated; fi
    rm -f "$new"' _ "$group")"
  [[ "$result" == updated ]] && changed=$((changed + 1))
  b89_log "grupo $group: $result"
done
b89_log "agent.conf actualizados: $changed (los agentes los reciben en su próximo keepalive; sin reinicio del manager)"
