BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · fase 3 — cada decisión registra la versión de la clave de muestreo que usó
-- (identificador, nunca la clave). Permite auditar rotaciones y, ante una clave comprometida, saber
-- qué selecciones de muestra pudo predecir un atacante.
ALTER TABLE "soc_learning_decisions"
    ADD COLUMN "sampling_key_version" TEXT,
    ADD CONSTRAINT "soc_learning_decisions_key_version"
        CHECK ("sampling_key_version" IS NULL OR "sampling_key_version" ~ '^[A-Za-z0-9._-]{1,64}$');

COMMIT;
