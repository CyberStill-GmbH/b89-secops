BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · fase 3 — estado del motor por tenant (auto-pausa si sus avisos no llegan).
-- Con `paused = true` el techo efectivo es la sombra. Reanudar exige una persona designada.
CREATE TABLE "soc_learning_engine_state" (
    "tenant_id" TEXT NOT NULL,
    "paused" BOOLEAN NOT NULL,
    "reason" TEXT,
    "since" TIMESTAMPTZ(3),
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_engine_state_pkey" PRIMARY KEY ("tenant_id"),
    CONSTRAINT "soc_learning_engine_state_reason" CHECK (
        ("paused" AND "reason" IN ('NOTIFICATION_UNDELIVERED', 'OPERATOR'))
        OR (NOT "paused" AND "reason" IS NULL)),
    CONSTRAINT "soc_learning_engine_state_revision" CHECK ("revision" >= 1),
    CONSTRAINT "soc_learning_engine_state_bounded" CHECK (char_length("tenant_id") BETWEEN 1 AND 128)
);

-- La comprobación de entrega busca avisos del motor sin publicar en el outbox.
CREATE INDEX "soc_outbox_messages_learning_notice_idx"
    ON "soc_outbox_messages" ("tenant_id", "available_at")
    WHERE "message_type" = 'soc.alert.review_requested' AND "status" <> 'published';

COMMIT;
