BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · fase 2 de la sombra — el motor sale del camino de la ingesta.
-- (docs/soc-learning/24-despliegue-sombra.md). Cambio aditivo: tres tablas.

-- Cola durable: un trabajo por alerta, escrito en la MISMA transacción que la alerta. Si el proceso
-- cae después del commit, el trabajo sigue ahí (antes la alerta quedaba sin evaluar). El worker lo
-- reclama con lease y `SKIP LOCKED`; tras `max_attempts` queda `dead` y la alerta sigue con personas.
CREATE TABLE "soc_learning_jobs" (
    "alert_id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "fingerprint" JSONB NOT NULL,
    "signals" JSONB,
    "status" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "available_at" TIMESTAMPTZ(3) NOT NULL,
    "lease_until" TIMESTAMPTZ(3),
    "claim_id" UUID,
    "last_error" TEXT,
    "enqueued_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),
    CONSTRAINT "soc_learning_jobs_pkey" PRIMARY KEY ("alert_id"),
    CONSTRAINT "soc_learning_jobs_alert_fkey" FOREIGN KEY ("alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_jobs_status" CHECK ("status" IN ('pending', 'leased', 'done', 'dead')),
    CONSTRAINT "soc_learning_jobs_lease" CHECK (
        ("status" = 'leased') = ("lease_until" IS NOT NULL AND "claim_id" IS NOT NULL)),
    CONSTRAINT "soc_learning_jobs_finished" CHECK (("status" IN ('done', 'dead')) = ("finished_at" IS NOT NULL)),
    CONSTRAINT "soc_learning_jobs_attempts" CHECK ("attempts" BETWEEN 0 AND 100),
    -- Solo un código de error corto: nunca texto crudo con datos de la alerta.
    CONSTRAINT "soc_learning_jobs_error" CHECK ("last_error" IS NULL OR "last_error" ~ '^[A-Z0-9_:.-]{1,80}$'),
    CONSTRAINT "soc_learning_jobs_bounded" CHECK (char_length("tenant_id") BETWEEN 1 AND 128)
);

CREATE INDEX "soc_learning_jobs_ready_idx"
    ON "soc_learning_jobs" ("available_at")
    WHERE "status" IN ('pending', 'leased');
CREATE INDEX "soc_learning_jobs_recent_idx"
    ON "soc_learning_jobs" ("tenant_id", "enqueued_at" DESC);

-- Latido del worker (dead man's switch): una fila por worker, se actualiza en cada pasada.
CREATE TABLE "soc_learning_worker_heartbeats" (
    "worker_id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "beat_at" TIMESTAMPTZ(3) NOT NULL,
    "claimed" INTEGER NOT NULL,
    "failed" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_worker_heartbeats_pkey" PRIMARY KEY ("worker_id"),
    CONSTRAINT "soc_learning_worker_heartbeats_counts" CHECK ("claimed" >= 0 AND "failed" >= 0),
    CONSTRAINT "soc_learning_worker_heartbeats_bounded" CHECK (
        char_length("worker_id") BETWEEN 1 AND 128 AND char_length("tenant_id") BETWEEN 1 AND 128)
);

-- Configuración efectiva de cada arranque (append-only): detecta cambios del techo, de reglas
-- activas o de kill switch. Solo la huella y contadores: ninguna clave ni lista completa.
CREATE TABLE "soc_learning_config_events" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "config_hash" TEXT NOT NULL,
    "max_mode" TEXT NOT NULL,
    "active_rules" INTEGER NOT NULL,
    "kill_switch" BOOLEAN NOT NULL,
    "sampling_key_version" TEXT,
    "at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_learning_config_events_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_config_events_mode" CHECK ("max_mode" IN ('off', 'shadow', 'dry_run', 'active')),
    CONSTRAINT "soc_learning_config_events_hash" CHECK ("config_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "soc_learning_config_events_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128 AND "active_rules" >= 0)
);

CREATE INDEX "soc_learning_config_events_recent_idx"
    ON "soc_learning_config_events" ("tenant_id", "at" DESC);

CREATE TRIGGER "soc_learning_config_events_no_update"
    BEFORE UPDATE ON "soc_learning_config_events"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_config_events_no_delete"
    BEFORE DELETE ON "soc_learning_config_events"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_config_events_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_config_events"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_append_only"();

COMMIT;
