BEGIN;

SET LOCAL lock_timeout = '5s';

-- Correcciones de CHECK (hallazgos de PGlite y revisión): PostgreSQL acepta una fila si el CHECK da
-- NULL. Tres condiciones podían dar NULL con columnas nulas y dejaban pasar filas inválidas.

-- 1. Motor en pausa sin motivo.
ALTER TABLE "soc_learning_engine_state" DROP CONSTRAINT "soc_learning_engine_state_reason";
ALTER TABLE "soc_learning_engine_state"
    ADD CONSTRAINT "soc_learning_engine_state_reason" CHECK (
        ("paused" AND "reason" IS NOT NULL AND "reason" IN ('NOTIFICATION_UNDELIVERED', 'OPERATOR'))
        OR (NOT "paused" AND "reason" IS NULL)) NOT VALID;
ALTER TABLE "soc_learning_engine_state" VALIDATE CONSTRAINT "soc_learning_engine_state_reason";

-- 2. Revisión resuelta sin comentario.
ALTER TABLE "soc_learning_reviews" DROP CONSTRAINT "soc_learning_reviews_resolution";
ALTER TABLE "soc_learning_reviews"
    ADD CONSTRAINT "soc_learning_reviews_resolution" CHECK (
        ("status" = 'pending' AND "resolved_at" IS NULL AND "reviewer_id" IS NULL)
        OR ("status" <> 'pending' AND "resolved_at" IS NOT NULL AND "reviewer_id" IS NOT NULL
            AND "reviewer_id" NOT LIKE 'svc:%' AND "comment" IS NOT NULL
            AND char_length("comment") BETWEEN 10 AND 2000)) NOT VALID;
ALTER TABLE "soc_learning_reviews" VALIDATE CONSTRAINT "soc_learning_reviews_resolution";

-- 3. `demoted_by` sin prioridad efectiva.
ALTER TABLE "soc_alerts" DROP CONSTRAINT "soc_alerts_effective_priority_floor";
ALTER TABLE "soc_alerts"
    ADD CONSTRAINT "soc_alerts_effective_priority_floor" CHECK (
        ("effective_priority" IS NULL AND "demoted_by" IS NULL)
        OR ("effective_priority" IS NOT NULL AND "effective_priority" = 'P4' AND "priority" = 'P3'
            AND "demoted_by" IS NOT NULL)) NOT VALID;
ALTER TABLE "soc_alerts" VALIDATE CONSTRAINT "soc_alerts_effective_priority_floor";

COMMIT;
