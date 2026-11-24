-- Aprendizaje SOC · etapa A — etiquetado retroactivo del origen de cierre
-- (docs/soc-learning/01-diseno.md §3.3).
--
-- Qué hace, para cada alerta cerrada SIN `closure_origin` (cerrada antes de la etapa A):
--   1. Toma el último `soc.alert.close` exitoso de `audit_events` y deriva el origen por actor:
--      svc:b89-ai-analyst → ai_analyst; svc:b89-detection-engineering o correlación close-fp-*
--      → bulk_script; svc:b89-soc-learning → learning_engine; otro svc: → service_other;
--      persona → human. Sin auditoría → legacy_unknown.
--   2. Completa SOLO columnas vacías de soc_alerts (closure_origin, closed_by, closed_at).
--      No toca veredicto, nota, estado ni `revision`. closure_reason queda NULL: un cierre
--      histórico no tiene motivo estructurado y NO cuenta para patrones hasta que un analista
--      lo reconfirme con motivo.
--   3. Agrega a soc_alert_closures una fila `close` por alerta, con correlation_id
--      `backfill:<original>` para distinguirla. Idempotente: no inserta si ya hay una fila de
--      cierre para esa alerta.
--
-- Cómo correrlo (lo ejecuta el dueño del ambiente, con la migración 20261124120000 aplicada):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v apply=0 -f backfill-closure-origin.sql   # simulación
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v apply=1 -f backfill-closure-origin.sql   # aplica
-- La simulación muestra los conteos por origen y termina en ROLLBACK.

\if :{?apply}
\else
  \set apply 0
\endif

BEGIN;

CREATE TEMP TABLE backfill_closure_plan ON COMMIT DROP AS
WITH last_close AS (
    SELECT DISTINCT ON (e."tenant_id", e."resource_id")
        e."tenant_id",
        e."resource_id"     AS alert_id,
        e."actor_id",
        e."actor_type",
        e."correlation_id",
        e."occurred_at"
    FROM "audit_events" e
    WHERE e."action" = 'soc.alert.close'
      AND e."outcome" = 'succeeded'
      AND e."resource_type" = 'alert'
    ORDER BY e."tenant_id", e."resource_id", e."sequence" DESC
)
SELECT
    a."id"        AS alert_id,
    a."tenant_id",
    a."verdict",
    lc."actor_id",
    lc."correlation_id",
    COALESCE(lc."occurred_at", a."updated_at") AS closed_at,
    CASE
        WHEN lc."actor_id" IS NULL THEN 'legacy_unknown'
        WHEN lc."actor_id" = 'svc:b89-ai-analyst' THEN 'ai_analyst'
        WHEN lc."actor_id" = 'svc:b89-detection-engineering'
          OR lc."correlation_id" LIKE 'close-fp-%' THEN 'bulk_script'
        WHEN lc."actor_id" = 'svc:b89-soc-learning' THEN 'learning_engine'
        WHEN lc."actor_id" LIKE 'svc:%' OR lc."actor_type" <> 'user' THEN 'service_other'
        ELSE 'human'
    END AS origin
FROM "soc_alerts" a
LEFT JOIN last_close lc
       ON lc."tenant_id" = a."tenant_id" AND lc.alert_id = a."id"::text
WHERE a."status" = 'closed'
  AND a."closure_origin" IS NULL;

SELECT origin, count(*) AS alerts
FROM backfill_closure_plan
GROUP BY origin
ORDER BY origin;

UPDATE "soc_alerts" a
SET "closure_origin" = p.origin,
    "closed_by"      = COALESCE(a."closed_by", p."actor_id"),
    "closed_at"      = COALESCE(a."closed_at", p.closed_at)
FROM backfill_closure_plan p
WHERE a."id" = p.alert_id
  AND a."closure_origin" IS NULL;

INSERT INTO "soc_alert_closures" (
    "id", "tenant_id", "alert_id", "kind", "verdict", "closure_reason", "origin",
    "actor_id", "justification", "evidence_refs", "decision_group_id", "correlation_id", "at"
)
SELECT
    gen_random_uuid(), p."tenant_id", p.alert_id, 'close', p."verdict", NULL, p.origin,
    COALESCE(p."actor_id", 'legacy:unknown'), NULL, '[]'::jsonb, NULL,
    left('backfill:' || COALESCE(p."correlation_id", 'sin-auditoria'), 256), p.closed_at
FROM backfill_closure_plan p
WHERE NOT EXISTS (
    SELECT 1 FROM "soc_alert_closures" c
    WHERE c."alert_id" = p.alert_id AND c."kind" = 'close'
);

\if :apply
  COMMIT;
  \echo 'Etiquetado aplicado.'
\else
  ROLLBACK;
  \echo 'Simulación: nada se guardó. Repite con -v apply=1 para aplicar.'
\endif
