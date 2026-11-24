BEGIN;

-- Aprendizaje SOC · etapa A (docs/soc-learning/01-diseno.md §2.1, §3).
-- Cambio aditivo: columnas nulas en soc_alerts y una bitácora nueva. No reescribe filas; el
-- etiquetado del histórico lo hace un script idempotente aparte.

ALTER TABLE "soc_alerts"
    ADD COLUMN "closure_reason" TEXT,
    ADD COLUMN "closure_origin" TEXT,
    ADD COLUMN "closed_by" TEXT,
    ADD COLUMN "closed_at" TIMESTAMPTZ(3);

ALTER TABLE "soc_alerts"
    ADD CONSTRAINT "soc_alerts_closure_reason_catalog" CHECK (
        "closure_reason" IS NULL OR "closure_reason" IN (
            'FP_ACTIVIDAD_LEGITIMA_CONOCIDA', 'FP_REGLA_MAL_AFINADA', 'FP_DATOS_ERRONEOS',
            'TP_BENIGNO_PRUEBA_O_PENTEST', 'TP_RIESGO_ACEPTADO', 'DUPLICADA', 'TP_REAL'
        )
    ),
    ADD CONSTRAINT "soc_alerts_closure_origin_catalog" CHECK (
        "closure_origin" IS NULL OR "closure_origin" IN (
            'human', 'ai_analyst', 'bulk_script', 'learning_engine', 'service_other', 'legacy_unknown'
        )
    );

CREATE INDEX "soc_alerts_closure_idx"
    ON "soc_alerts" ("tenant_id", "closure_origin", "closure_reason", "closed_at");

CREATE TABLE "soc_alert_closures" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "alert_id" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "verdict" TEXT,
    "closure_reason" TEXT,
    "origin" TEXT NOT NULL,
    "actor_id" TEXT NOT NULL,
    "justification" JSONB,
    "evidence_refs" JSONB NOT NULL DEFAULT '[]',
    "decision_group_id" UUID,
    "correlation_id" TEXT NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL,
    "recorded_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "soc_alert_closures_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_alert_closures_alert_fkey" FOREIGN KEY ("alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_alert_closures_kind" CHECK ("kind" IN ('close', 'reopen')),
    CONSTRAINT "soc_alert_closures_verdict" CHECK (
        "verdict" IS NULL OR "verdict" IN ('true_positive', 'false_positive', 'benign', 'duplicate')
    ),
    CONSTRAINT "soc_alert_closures_reason_catalog" CHECK (
        "closure_reason" IS NULL OR "closure_reason" IN (
            'FP_ACTIVIDAD_LEGITIMA_CONOCIDA', 'FP_REGLA_MAL_AFINADA', 'FP_DATOS_ERRONEOS',
            'TP_BENIGNO_PRUEBA_O_PENTEST', 'TP_RIESGO_ACEPTADO', 'DUPLICADA', 'TP_REAL'
        )
    ),
    CONSTRAINT "soc_alert_closures_origin_catalog" CHECK (
        "origin" IN (
            'human', 'ai_analyst', 'bulk_script', 'learning_engine', 'service_other', 'legacy_unknown'
        )
    ),
    -- Un cierre con motivo lleva justificación; una reapertura no lleva ninguno de los dos.
    CONSTRAINT "soc_alert_closures_reason_has_justification" CHECK (
        "closure_reason" IS NULL OR "justification" IS NOT NULL
    ),
    CONSTRAINT "soc_alert_closures_reopen_shape" CHECK (
        "kind" = 'close' OR ("closure_reason" IS NULL AND "justification" IS NULL)
    ),
    CONSTRAINT "soc_alert_closures_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("actor_id") BETWEEN 1 AND 256
        AND char_length("correlation_id") BETWEEN 1 AND 256
        AND jsonb_typeof("evidence_refs") = 'array'
        AND jsonb_array_length("evidence_refs") <= 10
        AND ("justification" IS NULL OR pg_column_size("justification") <= 16384)
    )
);

CREATE INDEX "soc_alert_closures_alert_idx"
    ON "soc_alert_closures" ("tenant_id", "alert_id", "at");
CREATE INDEX "soc_alert_closures_learning_idx"
    ON "soc_alert_closures" ("tenant_id", "origin", "closure_reason", "at");

-- Bitácora append-only, igual que audit_events: una evidencia que se pudiera corregir dejaría
-- de serlo. Un cierre equivocado se corrige con una reapertura, que es otra fila.
CREATE FUNCTION "soc_alert_closures_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'soc_alert_closures es append-only: % no está permitido', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_alert_closures_no_update"
    BEFORE UPDATE ON "soc_alert_closures"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_closures_append_only"();

CREATE TRIGGER "soc_alert_closures_no_delete"
    BEFORE DELETE ON "soc_alert_closures"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_closures_append_only"();

CREATE TRIGGER "soc_alert_closures_no_truncate"
    BEFORE TRUNCATE ON "soc_alert_closures"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_alert_closures_append_only"();

COMMIT;
