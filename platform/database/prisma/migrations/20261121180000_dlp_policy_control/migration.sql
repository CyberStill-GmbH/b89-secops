BEGIN;

CREATE TABLE "dlp_policies" (
    "tenant_id" TEXT NOT NULL,
    "document" JSONB NOT NULL,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_by" TEXT NOT NULL,
    CONSTRAINT "dlp_policies_pkey" PRIMARY KEY ("tenant_id"),
    CONSTRAINT "dlp_policies_revision_positive" CHECK ("revision" >= 1),
    CONSTRAINT "dlp_policies_document_bounded" CHECK (
        jsonb_typeof("document") = 'object' AND pg_column_size("document") <= 900000
    ),
    CONSTRAINT "dlp_policies_fields_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("updated_by") BETWEEN 1 AND 256
    )
);

CREATE TABLE "dlp_endpoints" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "enrollment_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "hostname" TEXT,
    "agent_id" TEXT,
    "enrolled_at" TIMESTAMPTZ(3),
    "last_seen_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "applied_revision" INTEGER NOT NULL DEFAULT 0,
    "policy_version" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "dlp_endpoints_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "dlp_endpoints_token_hash_unique" UNIQUE ("token_hash"),
    CONSTRAINT "dlp_endpoints_revision_nonnegative" CHECK ("applied_revision" >= 0),
    CONSTRAINT "dlp_endpoints_token_hash_format" CHECK ("token_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "dlp_endpoints_fields_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("hostname") <= 128
        AND char_length("agent_id") <= 16
        AND ("policy_version" IS NULL OR char_length("policy_version") <= 32)
    ),
    CONSTRAINT "dlp_endpoints_enrollment_state_coherent" CHECK (
        ("enrolled_at" IS NULL AND "hostname" IS NULL AND "agent_id" IS NULL AND "revoked_at" IS NULL)
        OR ("enrolled_at" IS NOT NULL AND "hostname" IS NOT NULL AND "agent_id" IS NOT NULL)
    )
);

CREATE INDEX "dlp_endpoints_tenant_seen_idx" ON "dlp_endpoints" ("tenant_id", "last_seen_at" DESC);

COMMIT;
