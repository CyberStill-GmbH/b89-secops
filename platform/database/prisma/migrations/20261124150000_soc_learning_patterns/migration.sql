BEGIN;

-- Si alguna tabla referida está ocupada, abortar en vez de encolar escrituras detrás del DDL.
SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · etapa D (docs/soc-learning/01-diseno.md §2.4, §5). Cambio aditivo: tres tablas.
-- Un patrón aprobado solo pasa a 'active' si las compuertas de preparación no bloquean, y un patrón
-- activo no tiene efecto hasta que exista el motor (etapa E). Nada de esto modifica soc_alerts.
CREATE TABLE "soc_learning_patterns" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "rule_key" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "normalizer_version" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "max_action" TEXT NOT NULL,
    "closure_reason" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "proposed_by" TEXT NOT NULL,
    "owner_id" TEXT,
    "origin_alert_ids" TEXT[] NOT NULL,
    "origin_closers" TEXT[] NOT NULL,
    "confirmations" INTEGER NOT NULL,
    "distinct_alerts" INTEGER NOT NULL,
    "distinct_days" INTEGER NOT NULL,
    "distinct_analysts" INTEGER NOT NULL,
    "true_positive_seen" INTEGER NOT NULL,
    "priority_ceiling" TEXT NOT NULL,
    "readiness_blockers" TEXT[] NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "activated_at" TIMESTAMPTZ(3),
    "expires_at" TIMESTAMPTZ(3),
    "renewal_count" INTEGER NOT NULL,
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_patterns_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_patterns_status" CHECK ("status" IN (
        'candidate', 'pending_second_approval', 'approved', 'active',
        'paused', 'expired', 'revoked', 'superseded')),
    CONSTRAINT "soc_learning_patterns_level" CHECK ("level" IN ('fine', 'coarse')),
    CONSTRAINT "soc_learning_patterns_action" CHECK ("max_action" IN ('auto_close', 'demote')),
    -- Una huella gruesa nunca autocierra (diseño §4.4).
    CONSTRAINT "soc_learning_patterns_coarse_demote" CHECK ("level" = 'fine' OR "max_action" = 'demote'),
    -- Solo motivos de falso positivo que alimentan patrones (LEARNABLE_CLOSURE_REASONS).
    CONSTRAINT "soc_learning_patterns_reason" CHECK ("closure_reason" IN (
        'FP_ACTIVIDAD_LEGITIMA_CONOCIDA', 'FP_REGLA_MAL_AFINADA')),
    CONSTRAINT "soc_learning_patterns_priority" CHECK ("priority_ceiling" IN ('P1', 'P2', 'P3', 'P4')),
    CONSTRAINT "soc_learning_patterns_format" CHECK ("fingerprint" ~ '^fp[0-9]+_[0-9a-f]{64}$'),
    -- Un patrón activo siempre vence: no hay supresión indefinida.
    CONSTRAINT "soc_learning_patterns_active_expires" CHECK (
        "status" <> 'active' OR ("activated_at" IS NOT NULL AND "expires_at" IS NOT NULL
                                 AND "expires_at" > "activated_at")),
    CONSTRAINT "soc_learning_patterns_counts" CHECK (
        "confirmations" >= 0 AND "distinct_alerts" >= 0 AND "distinct_days" >= 0
        AND "distinct_analysts" >= 0 AND "true_positive_seen" >= 0
        AND "renewal_count" >= 0 AND "revision" >= 1),
    CONSTRAINT "soc_learning_patterns_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("rule_key") BETWEEN 3 AND 192
        AND cardinality("origin_alert_ids") <= 50
        AND cardinality("origin_closers") <= 50
    )
);

-- Como máximo un patrón abierto por huella (OPEN_PATTERN_STATUSES).
CREATE UNIQUE INDEX "soc_learning_patterns_open_fingerprint_key"
    ON "soc_learning_patterns" ("tenant_id", "fingerprint")
    WHERE "status" IN ('candidate', 'pending_second_approval', 'approved', 'active', 'paused');
CREATE INDEX "soc_learning_patterns_board_idx"
    ON "soc_learning_patterns" ("tenant_id", "status", "updated_at" DESC);

CREATE TABLE "soc_learning_pattern_approvals" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "pattern_id" UUID NOT NULL,
    "pattern_revision" INTEGER NOT NULL,
    "stage" TEXT NOT NULL,
    "approver_id" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "comment" TEXT NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_learning_pattern_approvals_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_pattern_approvals_pattern_fkey" FOREIGN KEY ("pattern_id")
        REFERENCES "soc_learning_patterns" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_pattern_approvals_stage" CHECK ("stage" IN ('first', 'second')),
    CONSTRAINT "soc_learning_pattern_approvals_decision" CHECK ("decision" IN ('approve', 'reject')),
    -- Nunca firma una identidad de servicio.
    CONSTRAINT "soc_learning_pattern_approvals_human" CHECK ("approver_id" NOT LIKE 'svc:%'),
    CONSTRAINT "soc_learning_pattern_approvals_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("comment") BETWEEN 10 AND 2000)
);

CREATE INDEX "soc_learning_pattern_approvals_pattern_idx"
    ON "soc_learning_pattern_approvals" ("tenant_id", "pattern_id", "at");

CREATE TABLE "soc_learning_pattern_events" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "pattern_id" UUID NOT NULL,
    "from_status" TEXT,
    "to_status" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "actor_id" TEXT NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_learning_pattern_events_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_pattern_events_pattern_fkey" FOREIGN KEY ("pattern_id")
        REFERENCES "soc_learning_patterns" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_pattern_events_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128 AND char_length("reason") BETWEEN 1 AND 500)
);

CREATE INDEX "soc_learning_pattern_events_pattern_idx"
    ON "soc_learning_pattern_events" ("tenant_id", "pattern_id", "at");

-- Firmas y transiciones son evidencia: no se editan ni se borran.
CREATE FUNCTION "soc_learning_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% es append-only: % no está permitido', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_learning_pattern_approvals_no_update"
    BEFORE UPDATE ON "soc_learning_pattern_approvals"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_pattern_approvals_no_delete"
    BEFORE DELETE ON "soc_learning_pattern_approvals"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_pattern_approvals_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_pattern_approvals"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_pattern_events_no_update"
    BEFORE UPDATE ON "soc_learning_pattern_events"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_pattern_events_no_delete"
    BEFORE DELETE ON "soc_learning_pattern_events"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_pattern_events_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_pattern_events"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_append_only"();

-- Los patrones no se borran: se revocan, vencen o se reemplazan.
CREATE FUNCTION "soc_learning_patterns_no_delete"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'soc_learning_patterns no admite %: revocar en su lugar', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_learning_patterns_no_delete"
    BEFORE DELETE ON "soc_learning_patterns"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_patterns_no_delete"();
CREATE TRIGGER "soc_learning_patterns_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_patterns"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_patterns_no_delete"();

COMMIT;
