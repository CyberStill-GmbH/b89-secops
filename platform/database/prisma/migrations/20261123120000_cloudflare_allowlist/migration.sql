BEGIN;

-- Lista blanca de la API de pagos (clientes, proveedores e infraestructura con sus IPs).
-- Un documento por tenant con revisión: escritura compare-and-set, como la política DLP.
CREATE TABLE "cloudflare_allowlists" (
    "tenant_id" TEXT NOT NULL,
    "document" JSONB NOT NULL,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_by" TEXT NOT NULL,
    CONSTRAINT "cloudflare_allowlists_pkey" PRIMARY KEY ("tenant_id"),
    CONSTRAINT "cloudflare_allowlists_revision_positive" CHECK ("revision" >= 1),
    CONSTRAINT "cloudflare_allowlists_document_bounded" CHECK (
        jsonb_typeof("document") = 'object' AND pg_column_size("document") <= 900000
    ),
    CONSTRAINT "cloudflare_allowlists_fields_bounded" CHECK (
        char_length("tenant_id") BETWEEN 1 AND 128
        AND char_length("updated_by") BETWEEN 1 AND 256
    )
);

COMMIT;
