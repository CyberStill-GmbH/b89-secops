import type { PrismaClient } from '../generated/client/client.js';
import { createDatabaseClient, type DatabaseConnectionOptions } from './client.js';

export interface DlpPolicyRow {
  readonly tenantId: string;
  readonly document: unknown;
  readonly revision: number;
  readonly updatedAt: Date;
  readonly updatedBy: string;
}

export interface DlpEndpointRow {
  readonly id: string;
  readonly tenantId: string;
  readonly hostname: string | null;
  readonly agentId: string | null;
  readonly enrolledAt: Date | null;
  readonly lastSeenAt: Date | null;
  readonly revokedAt: Date | null;
  readonly appliedRevision: number;
  readonly policyVersion: string | null;
  readonly enrollmentExpiresAt: Date;
}

/** PostgreSQL state for the active DLP policy and endpoint credentials. Tokens are stored hashed. */
export class PrismaDlpPolicyStore {
  private constructor(private readonly client: PrismaClient) {}

  public static connect(options: DatabaseConnectionOptions): PrismaDlpPolicyStore {
    return new PrismaDlpPolicyStore(createDatabaseClient(options));
  }

  public async ready(): Promise<void> {
    await this.client.$queryRaw`SELECT 1`;
    await this.client.$queryRaw`SELECT "tenant_id" FROM "dlp_policies" LIMIT 0`;
    await this.client.$queryRaw`SELECT "token_hash" FROM "dlp_endpoints" LIMIT 0`;
  }

  public close(): Promise<void> {
    return this.client.$disconnect();
  }

  public async policy(tenantId: string): Promise<DlpPolicyRow | undefined> {
    const rows = await this.client.$queryRaw<DlpPolicyRow[]>`
      SELECT "tenant_id" AS "tenantId", "document", "revision",
             "updated_at" AS "updatedAt", "updated_by" AS "updatedBy"
        FROM "dlp_policies" WHERE "tenant_id" = ${tenantId}`;
    return rows[0];
  }

  /** Compare-and-set: expected revision 0 creates the first policy; any stale update is rejected. */
  public async putPolicy(
    tenantId: string,
    document: unknown,
    expectedRevision: number,
    updatedBy: string,
    updatedAt: Date,
  ): Promise<boolean> {
    const encoded = JSON.stringify(document);
    const count = expectedRevision === 0
      ? await this.client.$executeRaw`
          INSERT INTO "dlp_policies" ("tenant_id", "document", "revision", "updated_at", "updated_by")
          VALUES (${tenantId}, ${encoded}::jsonb, 1, ${updatedAt}, ${updatedBy})
          ON CONFLICT ("tenant_id") DO NOTHING`
      : await this.client.$executeRaw`
          UPDATE "dlp_policies"
             SET "document" = ${encoded}::jsonb, "revision" = "revision" + 1,
                 "updated_at" = ${updatedAt}, "updated_by" = ${updatedBy}
           WHERE "tenant_id" = ${tenantId} AND "revision" = ${expectedRevision}::int`;
    return count === 1;
  }

  public async issueEnrollmentToken(input: {
    readonly id: string;
    readonly tenantId: string;
    readonly tokenHash: string;
    readonly expiresAt: Date;
    readonly now: Date;
  }): Promise<boolean> {
    await this.client.$executeRaw`
      DELETE FROM "dlp_endpoints"
       WHERE "tenant_id" = ${input.tenantId} AND "enrolled_at" IS NULL
         AND "enrollment_expires_at" <= ${input.now}`;
    const inserted = await this.client.$queryRaw<{ id: string }[]>`
      INSERT INTO "dlp_endpoints" ("id", "tenant_id", "token_hash", "enrollment_expires_at")
      SELECT ${input.id}, ${input.tenantId}, ${input.tokenHash}, ${input.expiresAt}
       WHERE (SELECT COUNT(*) FROM "dlp_endpoints" WHERE "tenant_id" = ${input.tenantId}) < 5000
      RETURNING "id"`;
    return inserted.length === 1;
  }

  public async enrollEndpoint(input: {
    readonly tenantId: string;
    readonly tokenHash: string;
    readonly hostname: string;
    readonly agentId: string;
    readonly at: Date;
  }): Promise<DlpEndpointRow | undefined> {
    const rows = await this.client.$queryRaw<DlpEndpointRow[]>`
      UPDATE "dlp_endpoints"
         SET "hostname" = ${input.hostname}, "agent_id" = ${input.agentId},
             "enrolled_at" = ${input.at}, "last_seen_at" = ${input.at},
             "enrollment_expires_at" = ${input.at}
       WHERE "tenant_id" = ${input.tenantId} AND "token_hash" = ${input.tokenHash}
         AND "enrolled_at" IS NULL AND "enrollment_expires_at" > ${input.at}
      RETURNING "id", "tenant_id" AS "tenantId", "hostname", "agent_id" AS "agentId",
                 "enrolled_at" AS "enrolledAt", "last_seen_at" AS "lastSeenAt",
                 "revoked_at" AS "revokedAt",
                 "applied_revision" AS "appliedRevision", "policy_version" AS "policyVersion",
                 "enrollment_expires_at" AS "enrollmentExpiresAt"`;
    return rows[0];
  }

  public async endpointByToken(input: {
    readonly tenantId: string;
    readonly tokenHash: string;
    readonly at: Date;
  }): Promise<DlpEndpointRow | undefined> {
    const rows = await this.client.$queryRaw<DlpEndpointRow[]>`
      UPDATE "dlp_endpoints" SET "last_seen_at" = ${input.at}
       WHERE "tenant_id" = ${input.tenantId} AND "token_hash" = ${input.tokenHash}
         AND "enrolled_at" IS NOT NULL AND "revoked_at" IS NULL
       RETURNING "id", "tenant_id" AS "tenantId", "hostname", "agent_id" AS "agentId",
                 "enrolled_at" AS "enrolledAt", "last_seen_at" AS "lastSeenAt",
                 "revoked_at" AS "revokedAt",
                 "applied_revision" AS "appliedRevision", "policy_version" AS "policyVersion",
                 "enrollment_expires_at" AS "enrollmentExpiresAt"`;
    return rows[0];
  }

  public async revokeEndpoint(input: {
    readonly tenantId: string;
    readonly id: string;
    readonly at: Date;
  }): Promise<boolean> {
    const count = await this.client.$executeRaw`
      UPDATE "dlp_endpoints" SET "revoked_at" = ${input.at}
       WHERE "tenant_id" = ${input.tenantId} AND "id" = ${input.id}
         AND "enrolled_at" IS NOT NULL AND "revoked_at" IS NULL`;
    return count === 1;
  }

  public async acknowledgePolicy(input: {
    readonly endpointId: string;
    readonly tenantId: string;
    readonly revision: number;
    readonly policyVersion: string;
    readonly at: Date;
  }): Promise<boolean> {
    const count = await this.client.$executeRaw`
      UPDATE "dlp_endpoints"
         SET "applied_revision" = ${input.revision}, "policy_version" = ${input.policyVersion},
             "last_seen_at" = ${input.at}
       WHERE "id" = ${input.endpointId} AND "tenant_id" = ${input.tenantId}
         AND "revoked_at" IS NULL`;
    return count === 1;
  }

  public async endpoints(tenantId: string): Promise<readonly DlpEndpointRow[]> {
    return this.client.$queryRaw<DlpEndpointRow[]>`
      SELECT "id", "tenant_id" AS "tenantId", "hostname", "agent_id" AS "agentId",
             "enrolled_at" AS "enrolledAt", "last_seen_at" AS "lastSeenAt",
             "revoked_at" AS "revokedAt",
             "applied_revision" AS "appliedRevision", "policy_version" AS "policyVersion",
             "enrollment_expires_at" AS "enrollmentExpiresAt"
        FROM "dlp_endpoints" WHERE "tenant_id" = ${tenantId} AND "enrolled_at" IS NOT NULL
       ORDER BY "hostname" ASC LIMIT 5000`;
  }
}
