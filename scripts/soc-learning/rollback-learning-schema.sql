-- Aprendizaje SOC · etapas A–C — rollback del esquema SOLO para un despliegue abortado.
--
-- Rollback normal (convención del repo, docs/06-operacion.md): las migraciones son aditivas y
-- no se revierten. Se vuelve atrás con banderas y la imagen anterior de la API:
--   B89_SOC_CLOSURE_REASON_REQUIRED=false   (el cierre sin motivo vuelve a aceptarse)
--   B89_SOC_GROUPING_ENABLED=false          (la ingesta deja de agrupar)
-- La API anterior ignora columnas nulas y tablas nuevas.
--
-- Este script existe para el caso en que hay que dejar la base exactamente como antes (p. ej.
-- una migración aplicada a un ambiente equivocado) y TODAVÍA NO HAY DATOS. Si encuentra una sola
-- fila de cierre, huella o grupo, o una alerta con columnas de cierre pobladas, aborta sin tocar
-- nada: esas filas son evidencia y no se borran por script.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v confirm=rollback-soc-learning -f rollback-learning-schema.sql

\if :{?confirm}
\else
  \echo 'Falta -v confirm=rollback-soc-learning'
  \quit
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
-- psql no interpola variables dentro de $$…$$: la confirmación entra por un parámetro de sesión.
SELECT set_config('b89.rollback_confirm', :'confirm', true);

DO $$
DECLARE
    confirm text := current_setting('b89.rollback_confirm', true);
    populated text := '';
BEGIN
    IF confirm IS DISTINCT FROM 'rollback-soc-learning' THEN
        RAISE EXCEPTION 'Confirmación inválida: use -v confirm=rollback-soc-learning';
    END IF;
    IF EXISTS (SELECT 1 FROM soc_alert_group_members) THEN populated := populated || ' soc_alert_group_members'; END IF;
    IF EXISTS (SELECT 1 FROM soc_alert_groups) THEN populated := populated || ' soc_alert_groups'; END IF;
    IF EXISTS (SELECT 1 FROM soc_alert_fingerprints) THEN populated := populated || ' soc_alert_fingerprints'; END IF;
    IF EXISTS (SELECT 1 FROM soc_alert_closures) THEN populated := populated || ' soc_alert_closures'; END IF;
    IF EXISTS (
        SELECT 1 FROM soc_alerts
         WHERE closure_reason IS NOT NULL OR closure_origin IS NOT NULL
            OR closed_by IS NOT NULL OR closed_at IS NOT NULL
    ) THEN populated := populated || ' soc_alerts(cierre)'; END IF;
    IF populated <> '' THEN
        RAISE EXCEPTION 'Hay datos de aprendizaje SOC en:%. No se revierte: use las banderas.', populated;
    END IF;
END $$;

-- Etapa C
DROP TABLE soc_alert_group_members;
DROP FUNCTION soc_alert_group_members_append_only();
DROP TABLE soc_alert_groups;
-- Etapa B
DROP TABLE soc_alert_fingerprints;
DROP FUNCTION soc_alert_fingerprints_append_only();
-- Etapa A
DROP TABLE soc_alert_closures;
DROP FUNCTION soc_alert_closures_append_only();
DROP INDEX soc_alerts_closure_idx;
ALTER TABLE soc_alerts
    DROP CONSTRAINT soc_alerts_closure_reason_catalog,
    DROP CONSTRAINT soc_alerts_closure_origin_catalog,
    DROP COLUMN closure_reason,
    DROP COLUMN closure_origin,
    DROP COLUMN closed_by,
    DROP COLUMN closed_at;

-- Prisma debe volver a considerarlas pendientes.
DELETE FROM _prisma_migrations
 WHERE migration_name IN (
    '20261124120000_soc_learning_closure',
    '20261124130000_soc_learning_fingerprint',
    '20261124140000_soc_learning_alert_groups'
 );

COMMIT;
\echo 'Esquema de aprendizaje SOC revertido (sin datos).'
