#!/usr/bin/env bash
# Aprendizaje SOC · verificación independiente del motor (fase 1, docs/soc-learning/22-verificacion-motor.md).
#
# Un solo comando, pensado para una máquina con Docker (la estación de desarrollo no lo soporta):
#
#   bash scripts/soc-learning/verify-engine.sh            # todo
#   STEPS="postgres suites" bash scripts/soc-learning/verify-engine.sh
#
# Pasos (STEPS, por defecto todos, en este orden):
#   postgres   PostgreSQL 18.6 desechable en Docker (o usa ADMIN_DATABASE_URL si ya existe) y el job
#              `soc-learning-postgres`: migraciones desde cero y desde el estado previo, rollbacks
#              con resguardo, specs de integración (stores Prisma, concurrencia, roles).
#   commits    cada commit de BASE..HEAD compila y pasa sus pruebas por separado (`git rebase --exec`
#              en un worktree temporal; no toca la rama).
#   suites     suite unitaria 3 veces e integración 3 veces en este checkout.
#
# Deja un registro por paso en $OUT (por defecto ./verify-engine-out) para adjuntarlo a doc 22.
# Sin secretos: la contraseña de la base desechable es fija y solo vale para el contenedor local.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
STEPS="${STEPS:-postgres commits suites}"
BASE="${BASE:-ebb572b}"
OUT="${OUT:-$root/verify-engine-out}"
mkdir -p "$OUT"
container=""

log() { printf '\n== %s\n' "$*" | tee -a "$OUT/summary.txt"; }
cleanup() {
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  if [ -n "${commit_wt:-}" ] && [ -d "$commit_wt" ]; then git worktree remove --force "$commit_wt" || true; fi
}
trap cleanup EXIT

log "Entorno: $(git rev-parse --short HEAD) · $(node --version) · pnpm $(pnpm --version)"
pnpm install --frozen-lockfile --ignore-scripts > "$OUT/install.log" 2>&1
pnpm --filter @b89/database generate > "$OUT/generate.log" 2>&1

if [ -z "${ADMIN_DATABASE_URL:-}" ] && [[ " $STEPS " == *" postgres "* || " $STEPS " == *" suites "* ]]; then
  log "PostgreSQL 18.6 desechable"
  container="b89-verify-pg-$$"
  docker run -d --rm --name "$container" -e POSTGRES_USER=b89 -e POSTGRES_PASSWORD=verify-only-not-a-secret \
    -e POSTGRES_DB=postgres -p 55432:5432 postgres:18.6 -c max_connections=200 >/dev/null
  for _ in $(seq 1 60); do docker exec "$container" pg_isready -U b89 >/dev/null 2>&1 && break; sleep 1; done
  export ADMIN_DATABASE_URL="postgresql://b89:verify-only-not-a-secret@localhost:55432/postgres"
fi

for step in $STEPS; do
  case "$step" in
    postgres)
      log "1. Migraciones, rollback y specs de integración (job soc-learning-postgres)"
      bash scripts/ci/soc-learning-postgres.sh 2>&1 | tee "$OUT/postgres.log"
      log "1b. Roles de mínimo privilegio (spec existente, con el endurecimiento nuevo)"
      DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec vitest run --config vitest.integration.config.ts \
        platform/database/test/postgres-roles.integration.spec.ts 2>&1 | tee "$OUT/roles.log"
      ;;
    commits)
      log "2. Cada commit de $BASE..HEAD compila y pasa sus pruebas por separado"
      commit_wt="$(mktemp -d)/b89-commits"
      git worktree add --detach "$commit_wt" HEAD >/dev/null
      (
        cd "$commit_wt"
        # Dependencias propias del worktree (el lockfile no cambia en BASE..HEAD; se comprueba).
        test -z "$(git diff --name-only "$BASE" HEAD -- pnpm-lock.yaml '**/package.json')" \
          || { echo 'El lockfile o un package.json cambian en el rango: instale por commit.' >&2; exit 3; }
        pnpm install --frozen-lockfile --ignore-scripts --prefer-offline >/dev/null
        # --force-rebase: reaplica cada commit aunque la base no cambie, para que corra --exec en todos.
        GIT_SEQUENCE_EDITOR=: git rebase --force-rebase --exec \
          "pnpm --filter @b89/database generate >/dev/null && pnpm typecheck && pnpm exec vitest run --config vitest.config.ts" \
          "$BASE"
      ) 2>&1 | tee "$OUT/commits.log"
      ;;
    suites)
      for run in 1 2 3; do
        log "3. Suite unitaria · corrida $run"
        pnpm exec vitest run --config vitest.config.ts 2>&1 | tail -6 | tee -a "$OUT/suites.log"
        log "3. Integración · corrida $run"
        DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec vitest run --config vitest.integration.config.ts 2>&1 \
          | tail -6 | tee -a "$OUT/suites.log"
      done
      ;;
    *) echo "Paso desconocido: $step" >&2; exit 2 ;;
  esac
done

log "Verificación terminada. Registros en $OUT"
