BEGIN;

-- Aprendizaje SOC · etapa C (docs/soc-learning/01-diseno.md §2.3). Cambio aditivo: dos tablas.
-- Agrupar no modifica soc_alerts: cada alerta conserva estado, prioridad y revisión.
CREATE TABLE "soc_alert_groups" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "rule_key" TEXT,
    "level" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "alert_count" INTEGER NOT NULL,
    "primary_alert_id" UUID NOT NULL,
    "highest_priority" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    CONSTRAINT "soc_alert_groups_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "soc_alert_groups_primary_alert_fkey" FOREIGN KEY ("primary_alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_alert_groups_status" CHECK ("status" IN ('open', 'closed')),
    CONSTRAINT "soc_alert_groups_level" CHECK ("level" IN ('fine', 'coarse')),
    CONSTRAINT "soc_alert_groups_priority" CHECK ("highest_priority" IN ('P1', 'P2', 'P3', 'P4')),
    CONSTRAINT "soc_alert_groups_format" CHECK ("fingerprint" ~ '^fp[0-9]+_[0-9a-f]{64}$'),
    CONSTRAINT "soc_alert_groups_counts" CHECK ("alert_count" >= 1 AND "revision" >= 1),
    CONSTRAINT "soc_alert_groups_span" CHECK ("first_seen_at" <= "last_seen_at"),
    CONSTRAINT "soc_alert_groups_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND ("rule_key" IS NULL OR char_length("rule_key") BETWEEN 3 AND 192)
    )
);

-- Un solo grupo abierto por huella: dos ingestas concurrentes no abren dos grupos.
CREATE UNIQUE INDEX "soc_alert_groups_open_fingerprint_key"
    ON "soc_alert_groups" ("tenant_id", "fingerprint")
    WHERE "status" = 'open';
CREATE INDEX "soc_alert_groups_board_idx"
    ON "soc_alert_groups" ("tenant_id", "status", "last_seen_at" DESC);

CREATE TABLE "soc_alert_group_members" (
    "alert_id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "group_id" UUID NOT NULL,
    "joined_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_alert_group_members_pkey" PRIMARY KEY ("alert_id"),
    CONSTRAINT "soc_alert_group_members_alert_fkey" FOREIGN KEY ("alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_alert_group_members_group_fkey" FOREIGN KEY ("group_id")
        REFERENCES "soc_alert_groups" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_alert_group_members_bounded" CHECK (char_length("tenant_id") BETWEEN 1 AND 128)
);

CREATE INDEX "soc_alert_group_members_group_idx"
    ON "soc_alert_group_members" ("tenant_id", "group_id", "joined_at" DESC);

-- La pertenencia es evidencia de cómo se agrupó: no se edita ni se borra.
CREATE FUNCTION "soc_alert_group_members_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'soc_alert_group_members es append-only: % no está permitido', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_alert_group_members_no_update"
    BEFORE UPDATE ON "soc_alert_group_members"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_group_members_append_only"();

CREATE TRIGGER "soc_alert_group_members_no_delete"
    BEFORE DELETE ON "soc_alert_group_members"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_group_members_append_only"();

CREATE TRIGGER "soc_alert_group_members_no_truncate"
    BEFORE TRUNCATE ON "soc_alert_group_members"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_alert_group_members_append_only"();

COMMIT;
