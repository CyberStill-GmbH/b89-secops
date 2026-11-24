BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · etapa E (docs/soc-learning/01-diseno.md §2.5, §7). Cambio aditivo.

-- Componentes de la huella aprendida: el motor los compara para detectar colisión y deriva.
ALTER TABLE "soc_learning_patterns"
    ADD COLUMN "components" JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT "soc_learning_patterns_components" CHECK (jsonb_typeof("components") = 'object');

CREATE INDEX "soc_learning_patterns_rule_idx"
    ON "soc_learning_patterns" ("tenant_id", "rule_key")
    WHERE "status" = 'active';

-- Una decisión por alerta, append-only: es el registro explicable del motor.
CREATE TABLE "soc_learning_decisions" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "alert_id" UUID NOT NULL,
    "mode" TEXT NOT NULL,
    "engine_version" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "rule_key" TEXT,
    "pattern_id" UUID,
    "proposed_action" TEXT NOT NULL,
    "applied_action" TEXT NOT NULL,
    "escalate_reason" TEXT,
    "confidence" TEXT NOT NULL,
    "checks" JSONB NOT NULL,
    "drift" JSONB,
    "sampled" BOOLEAN NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_learning_decisions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_decisions_alert_key" UNIQUE ("alert_id"),
    CONSTRAINT "soc_learning_decisions_alert_fkey" FOREIGN KEY ("alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_decisions_pattern_fkey" FOREIGN KEY ("pattern_id")
        REFERENCES "soc_learning_patterns" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_decisions_mode" CHECK ("mode" IN ('shadow', 'dry_run', 'active')),
    CONSTRAINT "soc_learning_decisions_actions" CHECK (
        "proposed_action" IN ('AUTO_CLOSE', 'DEMOTE', 'ESCALATE', 'NONE')
        AND "applied_action" IN ('AUTO_CLOSE', 'DEMOTE', 'ESCALATE', 'NONE')),
    -- En sombra nunca hay efecto; solo el modo activo autocierra.
    CONSTRAINT "soc_learning_decisions_shadow_inert" CHECK ("mode" <> 'shadow' OR "applied_action" = 'NONE'),
    CONSTRAINT "soc_learning_decisions_close_active" CHECK (
        "applied_action" <> 'AUTO_CLOSE' OR ("mode" = 'active' AND "level" = 'fine' AND "pattern_id" IS NOT NULL)),
    CONSTRAINT "soc_learning_decisions_level" CHECK ("level" IN ('fine', 'coarse')),
    CONSTRAINT "soc_learning_decisions_confidence" CHECK ("confidence" IN ('high', 'medium', 'low')),
    CONSTRAINT "soc_learning_decisions_checks" CHECK (jsonb_typeof("checks") = 'array'),
    CONSTRAINT "soc_learning_decisions_bounded" CHECK (char_length("tenant_id") BETWEEN 1 AND 128)
);

CREATE INDEX "soc_learning_decisions_pattern_idx"
    ON "soc_learning_decisions" ("tenant_id", "pattern_id", "at" DESC);
CREATE INDEX "soc_learning_decisions_recent_idx"
    ON "soc_learning_decisions" ("tenant_id", "at" DESC);

CREATE TABLE "soc_learning_reviews" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "decision_id" UUID NOT NULL,
    "alert_id" UUID NOT NULL,
    "pattern_id" UUID,
    "kind" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "reviewer_id" TEXT,
    "true_positive" BOOLEAN,
    "comment" TEXT,
    "at" TIMESTAMPTZ(3) NOT NULL,
    "resolved_at" TIMESTAMPTZ(3),
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_reviews_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_reviews_decision_fkey" FOREIGN KEY ("decision_id")
        REFERENCES "soc_learning_decisions" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_reviews_kind" CHECK ("kind" IN ('quality_sample', 'dry_run_approval', 'forced_review')),
    CONSTRAINT "soc_learning_reviews_status" CHECK ("status" IN ('pending', 'agreed', 'disagreed', 'expired')),
    -- Resuelta ⇔ tiene persona, fecha y comentario; nunca la resuelve un servicio.
    CONSTRAINT "soc_learning_reviews_resolution" CHECK (
        ("status" = 'pending' AND "resolved_at" IS NULL AND "reviewer_id" IS NULL)
        OR ("status" <> 'pending' AND "resolved_at" IS NOT NULL AND "reviewer_id" IS NOT NULL
            AND "reviewer_id" NOT LIKE 'svc:%' AND char_length("comment") BETWEEN 10 AND 2000)),
    CONSTRAINT "soc_learning_reviews_revision" CHECK ("revision" >= 1),
    CONSTRAINT "soc_learning_reviews_bounded" CHECK (char_length("tenant_id") BETWEEN 1 AND 128)
);

CREATE INDEX "soc_learning_reviews_queue_idx"
    ON "soc_learning_reviews" ("tenant_id", "status", "at" DESC);
CREATE INDEX "soc_learning_reviews_pattern_idx"
    ON "soc_learning_reviews" ("tenant_id", "pattern_id", "resolved_at");

CREATE TABLE "soc_learning_reversals" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "decision_id" UUID NOT NULL,
    "alert_id" UUID NOT NULL,
    "pattern_id" UUID,
    "actor_id" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "reopened" BOOLEAN NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_learning_reversals_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_reversals_decision_fkey" FOREIGN KEY ("decision_id")
        REFERENCES "soc_learning_decisions" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_learning_reversals_human" CHECK ("actor_id" NOT LIKE 'svc:%'),
    CONSTRAINT "soc_learning_reversals_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128 AND char_length("reason") BETWEEN 1 AND 500)
);

CREATE INDEX "soc_learning_reversals_pattern_idx"
    ON "soc_learning_reversals" ("tenant_id", "pattern_id", "at");

-- Decisiones y reversiones son evidencia: no se editan ni se borran (función de la etapa D).
CREATE TRIGGER "soc_learning_decisions_no_update"
    BEFORE UPDATE ON "soc_learning_decisions"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_decisions_no_delete"
    BEFORE DELETE ON "soc_learning_decisions"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_decisions_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_decisions"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_reversals_no_update"
    BEFORE UPDATE ON "soc_learning_reversals"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_reversals_no_delete"
    BEFORE DELETE ON "soc_learning_reversals"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_append_only"();
CREATE TRIGGER "soc_learning_reversals_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_reversals"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_append_only"();

-- Una revisión resuelta no se reabre ni se borra.
CREATE FUNCTION "soc_learning_reviews_guard"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'soc_learning_reviews no admite %', TG_OP USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD."status" <> 'pending' THEN
        RAISE EXCEPTION 'soc_learning_reviews: una revisión resuelta no cambia' USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."decision_id" <> OLD."decision_id" OR NEW."alert_id" <> OLD."alert_id"
       OR NEW."kind" <> OLD."kind" OR NEW."at" <> OLD."at" THEN
        RAISE EXCEPTION 'soc_learning_reviews: solo cambia la resolución' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER "soc_learning_reviews_guard_update"
    BEFORE UPDATE ON "soc_learning_reviews"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_reviews_guard"();
CREATE TRIGGER "soc_learning_reviews_guard_delete"
    BEFORE DELETE ON "soc_learning_reviews"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_reviews_guard"();
CREATE TRIGGER "soc_learning_reviews_guard_truncate"
    BEFORE TRUNCATE ON "soc_learning_reviews"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_reviews_guard"();

COMMIT;
