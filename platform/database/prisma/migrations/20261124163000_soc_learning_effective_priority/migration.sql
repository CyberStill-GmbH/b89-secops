BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · fase 3 — prioridad efectiva para DEMOTE (docs/soc-learning/01-diseno.md §7.2).
-- Aditivo: `priority` (la original) nunca cambia; la cola ordena por `coalesce(effective_priority,
-- priority)` y muestra la original. `demoted_by` es la decisión del motor que lo hizo (trazable y
-- reversible: revertir la decisión limpia ambas columnas).
ALTER TABLE "soc_alerts"
    ADD COLUMN "effective_priority" TEXT,
    ADD COLUMN "demoted_by" UUID;

-- Piso duro en la base: solo P3 → P4. Nunca sobre P1/P2 ni por debajo de P4, y siempre con su
-- decisión. NOT VALID + VALIDATE para no bloquear la cola mientras se valida.
ALTER TABLE "soc_alerts"
    ADD CONSTRAINT "soc_alerts_effective_priority_floor" CHECK (
        ("effective_priority" IS NULL AND "demoted_by" IS NULL)
        OR ("effective_priority" = 'P4' AND "priority" = 'P3' AND "demoted_by" IS NOT NULL)
    ) NOT VALID;

ALTER TABLE "soc_alerts" VALIDATE CONSTRAINT "soc_alerts_effective_priority_floor";

COMMIT;
