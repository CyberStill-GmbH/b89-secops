BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · etapa E — respaldo en base de una guarda dura del motor
-- (docs/soc-learning/22-verificacion-motor.md): un cierre del motor (`closure_origin =
-- 'learning_engine'`) solo existe sobre una alerta P4. Aunque el código tuviera un defecto, la
-- base rechaza un autocierre de P1, P2 o P3. Una reapertura limpia `closure_origin` y no choca.
--
-- NOT VALID + VALIDATE: la validación no bloquea escrituras de la cola mientras recorre la tabla.
ALTER TABLE "soc_alerts"
    ADD CONSTRAINT "soc_alerts_learning_engine_p4"
    CHECK ("closure_origin" IS DISTINCT FROM 'learning_engine' OR "priority" = 'P4') NOT VALID;

ALTER TABLE "soc_alerts" VALIDATE CONSTRAINT "soc_alerts_learning_engine_p4";

COMMIT;
