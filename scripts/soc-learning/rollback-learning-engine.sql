-- Aprendizaje SOC · etapas D y E — rollback del esquema SOLO para un despliegue abortado.
--
-- Rollback normal: las migraciones son aditivas y no se revierten. Se vuelve atrás con banderas:
--   B89_LEARNING_ENABLED=false   (sin refresco de patrones ni evaluación de alertas)
-- La API anterior ignora tablas nuevas.
--
-- Este script deja la base como tras la etapa C (estado previo) y TODAVÍA SIN DATOS de D/E: si
-- hay un solo patrón, firma, evento, decisión, revisión o reversión, aborta sin tocar nada.
-- Las etapas A–C no se tocan (para eso está `rollback-learning-schema.sql`).
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v confirm=rollback-soc-learning-engine -f rollback-learning-engine.sql

\if :{?confirm}
\else
  \echo 'Falta -v confirm=rollback-soc-learning-engine'
  \quit
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SELECT set_config('b89.rollback_confirm', :'confirm', true);

DO $$
DECLARE
    confirm text := current_setting('b89.rollback_confirm', true);
    populated text := '';
    name text;
    has_rows boolean;
BEGIN
    IF confirm IS DISTINCT FROM 'rollback-soc-learning-engine' THEN
        RAISE EXCEPTION 'Confirmación inválida: use -v confirm=rollback-soc-learning-engine';
    END IF;
    FOREACH name IN ARRAY ARRAY[
        'soc_learning_jobs', 'soc_learning_config_events',
        'soc_learning_reversals', 'soc_learning_reviews', 'soc_learning_decisions',
        'soc_learning_pattern_events', 'soc_learning_pattern_approvals', 'soc_learning_patterns']
    LOOP
        IF to_regclass(name) IS NOT NULL THEN
            EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I)', name) INTO STRICT has_rows;
            IF has_rows THEN populated := populated || ' ' || name; END IF;
        END IF;
    END LOOP;
    IF populated <> '' THEN
        RAISE EXCEPTION 'Hay datos de aprendizaje SOC (D/E) en:%. No se revierte: use las banderas.', populated;
    END IF;
END $$;

-- Fase 2 (cola, latidos, configuración)
DROP TABLE IF EXISTS soc_learning_config_events;
DROP TABLE IF EXISTS soc_learning_engine_state;
DROP TABLE IF EXISTS soc_learning_rule_enablements;
DROP TABLE IF EXISTS soc_learning_context_entries;
DROP FUNCTION IF EXISTS soc_learning_governance_no_delete();
DROP INDEX IF EXISTS soc_outbox_messages_learning_notice_idx;
DROP TABLE IF EXISTS soc_learning_worker_heartbeats;
DROP TABLE IF EXISTS soc_learning_jobs;
-- Etapa E
ALTER TABLE soc_alerts DROP CONSTRAINT IF EXISTS soc_alerts_learning_engine_p4;
ALTER TABLE soc_alerts DROP CONSTRAINT IF EXISTS soc_alerts_effective_priority_floor,
    DROP COLUMN IF EXISTS effective_priority, DROP COLUMN IF EXISTS demoted_by;
DROP TABLE IF EXISTS soc_learning_reversals;
DROP TABLE IF EXISTS soc_learning_reviews;
DROP FUNCTION IF EXISTS soc_learning_reviews_guard();
DROP TABLE IF EXISTS soc_learning_decisions;
-- Etapa D
DROP TABLE IF EXISTS soc_learning_pattern_events;
DROP TABLE IF EXISTS soc_learning_pattern_approvals;
DROP FUNCTION IF EXISTS soc_learning_append_only();
DROP TABLE IF EXISTS soc_learning_patterns;
DROP FUNCTION IF EXISTS soc_learning_patterns_no_delete();

DELETE FROM _prisma_migrations
 WHERE migration_name IN (
    '20261124150000_soc_learning_patterns',
    '20261124160000_soc_learning_engine',
    '20261124161000_soc_learning_engine_guards',
    '20261124162000_soc_learning_queue',
    '20261124163000_soc_learning_effective_priority',
    '20261124164000_soc_learning_engine_state',
    '20261124165000_soc_learning_governance',
    '20261124166000_soc_learning_sampling_key',
    '20261124167000_soc_learning_check_fixes'
 );

COMMIT;
\echo 'Esquema de aprendizaje SOC (D/E) revertido (sin datos).'
