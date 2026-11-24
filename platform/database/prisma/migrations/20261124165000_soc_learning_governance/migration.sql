BEGIN;

SET LOCAL lock_timeout = '5s';

-- Aprendizaje SOC · fase 3 — habilitación en dos capas y contexto en base.
--
-- Capa 1: techo por entorno (variables, con registro de cambio; su cambio genera alerta de salud).
-- Capa 2: habilitación por regla y tenant en base, con aprobación de DOS personas distintas y
-- vencimiento obligatorio. Modo efectivo = mínimo de ambas; sin la fila aprobada, la regla queda en
-- sombra. Nada se borra: se revoca o vence.
CREATE TABLE "soc_learning_rule_enablements" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "rule_key" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "requested_by" TEXT NOT NULL,
    "requested_at" TIMESTAMPTZ(3) NOT NULL,
    "approved_by" TEXT,
    "approved_at" TIMESTAMPTZ(3),
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_by" TEXT,
    "revoked_at" TIMESTAMPTZ(3),
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_rule_enablements_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_rule_enablements_mode" CHECK ("mode" IN ('dry_run', 'active')),
    CONSTRAINT "soc_learning_rule_enablements_status" CHECK ("status" IN ('pending', 'approved', 'revoked')),
    -- Dos personas distintas, nunca un servicio.
    CONSTRAINT "soc_learning_rule_enablements_people" CHECK (
        "requested_by" NOT LIKE 'svc:%'
        AND ("approved_by" IS NULL OR ("approved_by" NOT LIKE 'svc:%' AND "approved_by" <> "requested_by"))),
    CONSTRAINT "soc_learning_rule_enablements_approved" CHECK (
        "status" <> 'approved' OR ("approved_by" IS NOT NULL AND "approved_at" IS NOT NULL)),
    CONSTRAINT "soc_learning_rule_enablements_revoked" CHECK (
        ("status" = 'revoked') = ("revoked_by" IS NOT NULL AND "revoked_at" IS NOT NULL)),
    -- Vencimiento obligatorio y acotado: nadie habilita para siempre.
    CONSTRAINT "soc_learning_rule_enablements_expiry" CHECK (
        "expires_at" > "requested_at" AND "expires_at" <= "requested_at" + interval '90 days'),
    CONSTRAINT "soc_learning_rule_enablements_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128 AND char_length("rule_key") BETWEEN 3 AND 192
        AND char_length("reason") BETWEEN 10 AND 2000),
    CONSTRAINT "soc_learning_rule_enablements_revision" CHECK ("revision" >= 1)
);

-- Como máximo una habilitación abierta (pendiente o aprobada) por regla y tenant.
CREATE UNIQUE INDEX "soc_learning_rule_enablements_open_key"
    ON "soc_learning_rule_enablements" ("tenant_id", "rule_key")
    WHERE "status" IN ('pending', 'approved');

-- Contexto (§2.6 del diseño): se suma a las listas del entorno (unión, nunca reemplazo).
CREATE TABLE "soc_learning_context_entries" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "created_by" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_by" TEXT,
    "revoked_at" TIMESTAMPTZ(3),
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_learning_context_entries_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_learning_context_entries_kind" CHECK ("kind" IN (
        'critical_asset', 'privileged_identity', 'break_glass', 'change_calendar_ack', 'never_suppress_rule')),
    CONSTRAINT "soc_learning_context_entries_people" CHECK (
        "created_by" NOT LIKE 'svc:%' AND ("revoked_by" IS NULL OR "revoked_by" NOT LIKE 'svc:%')),
    CONSTRAINT "soc_learning_context_entries_revoked" CHECK (("revoked_by" IS NULL) = ("revoked_at" IS NULL)),
    -- La confirmación del calendario vence en ≤ 30 días; el resto, en ≤ 90 (obliga a revisarlas).
    CONSTRAINT "soc_learning_context_entries_expiry" CHECK (
        "expires_at" > "created_at"
        AND "expires_at" <= "created_at" + CASE WHEN "kind" = 'change_calendar_ack'
                                               THEN interval '30 days' ELSE interval '90 days' END),
    CONSTRAINT "soc_learning_context_entries_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128 AND char_length("value") BETWEEN 1 AND 256
        AND char_length("reason") BETWEEN 10 AND 500),
    CONSTRAINT "soc_learning_context_entries_revision" CHECK ("revision" >= 1)
);

CREATE INDEX "soc_learning_context_entries_live_idx"
    ON "soc_learning_context_entries" ("tenant_id", "kind", "expires_at")
    WHERE "revoked_at" IS NULL;

-- Ni habilitaciones ni contexto se borran: se revocan o vencen.
CREATE FUNCTION "soc_learning_governance_no_delete"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% no admite %: revocar en su lugar', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_learning_rule_enablements_no_delete"
    BEFORE DELETE ON "soc_learning_rule_enablements"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_governance_no_delete"();
CREATE TRIGGER "soc_learning_rule_enablements_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_rule_enablements"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_governance_no_delete"();
CREATE TRIGGER "soc_learning_context_entries_no_delete"
    BEFORE DELETE ON "soc_learning_context_entries"
    FOR EACH ROW EXECUTE FUNCTION "soc_learning_governance_no_delete"();
CREATE TRIGGER "soc_learning_context_entries_no_truncate"
    BEFORE TRUNCATE ON "soc_learning_context_entries"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_learning_governance_no_delete"();

COMMIT;
