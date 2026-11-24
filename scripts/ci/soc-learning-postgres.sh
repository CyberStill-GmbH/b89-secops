#!/usr/bin/env bash
# Aprendizaje SOC · verificación real contra PostgreSQL (etapas A–C).
#
# Requiere ADMIN_DATABASE_URL (rol con CREATEDB, base administrativa, p. ej. .../postgres) y psql.
# Crea una base desechable y comprueba:
#   1. `prisma migrate deploy` aplica todas las migraciones, incluidas las de aprendizaje SOC.
#   2. El etiquetado retroactivo corre en simulación y aplicado, y es idempotente.
#   3. El rollback con resguardo se niega con datos y funciona sin datos.
#   4. Tras el rollback, las migraciones se vuelven a aplicar limpias.
#   5. Las specs de integración (concurrencia de 50 ingestas, inmutabilidad, cierres, huellas).
# Borra la base al terminar, también si falla.
set -euo pipefail

: "${ADMIN_DATABASE_URL:?ADMIN_DATABASE_URL es obligatorio}"
command -v psql >/dev/null || { echo 'psql no está instalado' >&2; exit 2; }

root="$(cd "$(dirname "$0")/../.." && pwd)"
name="b89_soc_learning_$$_$(date +%s)"
base="${ADMIN_DATABASE_URL%/*}"
db_url="${base}/${name}"

cleanup() { psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -qc "DROP DATABASE IF EXISTS \"${name}\" WITH (FORCE)" >/dev/null || true; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "Base desechable ${name}"
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -qc "CREATE DATABASE \"${name}\""

migrate() { (cd "$root/platform/database" && DATABASE_URL="$db_url" pnpm exec prisma migrate deploy --schema prisma/schema.prisma); }

step "1. Migraciones"
migrate
psql "$db_url" -v ON_ERROR_STOP=1 -tAc "SELECT count(*) FROM _prisma_migrations WHERE migration_name LIKE '%soc_learning%' AND finished_at IS NOT NULL" | grep -qx 3

step "2. Etiquetado retroactivo (simulación, aplicado e idempotente)"
psql "$db_url" -v ON_ERROR_STOP=1 -v apply=0 -f "$root/scripts/soc-learning/backfill-closure-origin.sql"
psql "$db_url" -v ON_ERROR_STOP=1 -v apply=1 -f "$root/scripts/soc-learning/backfill-closure-origin.sql"
psql "$db_url" -v ON_ERROR_STOP=1 -v apply=1 -f "$root/scripts/soc-learning/backfill-closure-origin.sql"

step "3. Rollback: sin confirmación no hace nada; sin datos revierte"
psql "$db_url" -v ON_ERROR_STOP=1 -f "$root/scripts/soc-learning/rollback-learning-schema.sql" | grep -q 'Falta -v confirm'
psql "$db_url" -v ON_ERROR_STOP=1 -v confirm=rollback-soc-learning -f "$root/scripts/soc-learning/rollback-learning-schema.sql"
test "$(psql "$db_url" -tAc "SELECT to_regclass('soc_alert_groups') IS NULL")" = t

step "4. Reaplicar migraciones tras el rollback"
migrate
test "$(psql "$db_url" -tAc "SELECT to_regclass('soc_alert_groups') IS NOT NULL")" = t

step "3b. Rollback se niega si hay datos (fila sintética en soc_alert_closures vía una alerta)"
# Una fila de cierre exige una alerta y su candidato: se insertan los mínimos con SQL.
psql "$db_url" -v ON_ERROR_STOP=1 -q <<'SQL'
INSERT INTO detection_candidates (id, tenant_id, event_record_id, event_uid, idempotency_key, priority, score, reasons, ruleset_id, ruleset_version, title, occurred_at)
VALUES ('0199c1a0-0000-7000-8000-000000000001', 't-rollback', '0199c1a0-0000-7000-8000-000000000002', 'evt', 'k', 'P4', 30, '[]', 'r', '1', 't', now());
INSERT INTO soc_alerts (id, tenant_id, candidate_id, event_record_id, title, priority, score, reasons, status, occurred_at, updated_at, revision, closure_origin)
VALUES ('0199c1a0-0000-7000-8000-000000000001', 't-rollback', '0199c1a0-0000-7000-8000-000000000001', '0199c1a0-0000-7000-8000-000000000002', 't', 'P4', 30, '[]', 'closed', now(), now(), 2, 'human');
SQL
if psql "$db_url" -v ON_ERROR_STOP=1 -v confirm=rollback-soc-learning -f "$root/scripts/soc-learning/rollback-learning-schema.sql" 2>"$root/.rollback-refusal.log"; then
  echo 'El rollback debió negarse con datos' >&2; exit 1
fi
grep -q 'Hay datos de aprendizaje SOC' "$root/.rollback-refusal.log"
rm -f "$root/.rollback-refusal.log"
test "$(psql "$db_url" -tAc "SELECT to_regclass('soc_alert_closures') IS NOT NULL")" = t

step "5. Specs de integración SOC y base de datos"
(cd "$root" && DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec vitest run --config vitest.integration.config.ts \
  modules/soc/test/postgres-soc.integration.spec.ts \
  platform/database/test/postgres-c19.integration.spec.ts --reporter=verbose)

step "Verificación de aprendizaje SOC completa"
