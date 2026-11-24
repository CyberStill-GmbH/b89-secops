BEGIN;

-- Aprendizaje SOC · etapa B (docs/soc-learning/01-diseno.md §2.2, §4).
-- Cambio aditivo: una tabla nueva, una fila por alerta, escrita en la misma transacción que la
-- crea. Los componentes ya vienen normalizados y redactados; la línea de comando original no se
-- guarda en ninguna tabla.
CREATE TABLE "soc_alert_fingerprints" (
    "alert_id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "rule_key" TEXT,
    "fingerprint" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "normalizer_version" TEXT NOT NULL,
    "components" JSONB NOT NULL,
    "computed_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "soc_alert_fingerprints_pkey" PRIMARY KEY ("alert_id"),
    CONSTRAINT "soc_alert_fingerprints_alert_fkey" FOREIGN KEY ("alert_id")
        REFERENCES "soc_alerts" ("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "soc_alert_fingerprints_level" CHECK ("level" IN ('fine', 'coarse')),
    CONSTRAINT "soc_alert_fingerprints_format" CHECK ("fingerprint" ~ '^fp[0-9]+_[0-9a-f]{64}$'),
    -- Una huella fina exige regla: sin regla no hay patrón posible.
    CONSTRAINT "soc_alert_fingerprints_fine_has_rule" CHECK ("level" = 'coarse' OR "rule_key" IS NOT NULL),
    CONSTRAINT "soc_alert_fingerprints_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND ("rule_key" IS NULL OR char_length("rule_key") BETWEEN 3 AND 192)
        AND char_length("version") BETWEEN 1 AND 16
        AND char_length("normalizer_version") BETWEEN 1 AND 16
        AND jsonb_typeof("components") = 'object'
        AND pg_column_size("components") <= 16384
    )
);

CREATE INDEX "soc_alert_fingerprints_lookup_idx"
    ON "soc_alert_fingerprints" ("tenant_id", "fingerprint", "computed_at");
CREATE INDEX "soc_alert_fingerprints_rule_idx"
    ON "soc_alert_fingerprints" ("tenant_id", "rule_key", "level");

-- La huella es evidencia de cómo se vio la alerta al promoverla: no se edita ni se borra. Una
-- versión nueva del normalizador produce huellas nuevas para alertas nuevas.
CREATE FUNCTION "soc_alert_fingerprints_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'soc_alert_fingerprints es append-only: % no está permitido', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "soc_alert_fingerprints_no_update"
    BEFORE UPDATE ON "soc_alert_fingerprints"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_fingerprints_append_only"();

CREATE TRIGGER "soc_alert_fingerprints_no_delete"
    BEFORE DELETE ON "soc_alert_fingerprints"
    FOR EACH ROW EXECUTE FUNCTION "soc_alert_fingerprints_append_only"();

CREATE TRIGGER "soc_alert_fingerprints_no_truncate"
    BEFORE TRUNCATE ON "soc_alert_fingerprints"
    FOR EACH STATEMENT EXECUTE FUNCTION "soc_alert_fingerprints_append_only"();

COMMIT;
