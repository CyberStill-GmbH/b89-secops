BEGIN;

-- Previously enrolled endpoints default to v0 and must be re-enrolled to receive a unique secret.
ALTER TABLE "dlp_endpoints"
  ADD COLUMN "credential_version" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "dlp_endpoints"
  ADD CONSTRAINT "dlp_endpoints_credential_version_valid"
  CHECK ("credential_version" IN (0, 1));

COMMIT;