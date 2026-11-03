#!/usr/bin/env bash
# Copia el árbol de trabajo de b89-secops al nodo y ejecuta deploy-host.sh.
#   SSH_KEY=<clave privada> HOST=<ip> SOC_HOSTNAME=dev.security.b89.io bash infra/aws-poweruser/scripts/ship.sh
# Nunca envía .env* (credenciales locales), .git, node_modules ni salidas locales.
set -euo pipefail
: "${SSH_KEY:?}" "${HOST:?}" "${SOC_HOSTNAME:?}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@$HOST")

tar -C "$REPO" -czf - \
  --exclude='./.git' --exclude='./.env' --exclude='./.env.*' --exclude='*/.env' \
  --exclude='node_modules' --exclude='./.local' --exclude='./.claude' --exclude='./.agents' \
  --exclude='./output' --exclude='./artifacts' --exclude='./test-results' \
  --exclude='.terraform' --exclude='*.tfplan' --exclude='*.tfstate*' \
  . | "${SSH[@]}" 'sudo rm -rf /opt/b89/src.new && sudo mkdir -p /opt/b89/src.new && sudo tar -C /opt/b89/src.new -xzf - \
      && sudo rm -rf /opt/b89/src && sudo mv /opt/b89/src.new /opt/b89/src \
      && sudo find /opt/b89/src -type f \( -name "*.sh" -o -name "*.tsv" -o -name "*.yml" -o -name "*.yaml" -o -name "*.template" -o -name "*.conf" \) -exec sed -i "s/\r$//" {} +'
"${SSH[@]}" "sudo SKIP_API_BUILD=${SKIP_API_BUILD:-0} SOC_HOSTNAME='$SOC_HOSTNAME' bash /opt/b89/src/infra/aws-poweruser/scripts/deploy-host.sh"
