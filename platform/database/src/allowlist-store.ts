import type { PrismaClient } from '../generated/client/client.js';
import { createDatabaseClient, type DatabaseConnectionOptions } from './client.js';

export interface AllowlistRow {
  readonly tenantId: string;
  readonly document: unknown;
  readonly revision: number;
  readonly updatedAt: Date;
  readonly updatedBy: string;
}

/** Lista blanca de la API de pagos: un documento por tenant con revisión (compare-and-set). */
export class PrismaAllowlistStore {
  private constructor(private readonly client: PrismaClient) {}

  public static connect(options: DatabaseConnectionOptions): PrismaAllowlistStore {
    return new PrismaAllowlistStore(createDatabaseClient(options));
  }

  public async ready(): Promise<void> {
    await this.client.$queryRaw`SELECT "tenant_id" FROM "cloudflare_allowlists" LIMIT 0`;
  }

  public close(): Promise<void> {
    return this.client.$disconnect();
  }

  public async get(tenantId: string): Promise<AllowlistRow | undefined> {
    const rows = await this.client.$queryRaw<AllowlistRow[]>`
      SELECT "tenant_id" AS "tenantId", "document", "revision",
             "updated_at" AS "updatedAt", "updated_by" AS "updatedBy"
        FROM "cloudflare_allowlists" WHERE "tenant_id" = ${tenantId}`;
    return rows[0];
  }

  /** Revisión esperada 0 crea la primera versión; una revisión vieja se rechaza. */
  public async put(
    tenantId: string,
    document: unknown,
    expectedRevision: number,
    updatedBy: string,
    updatedAt: Date,
  ): Promise<boolean> {
    const encoded = JSON.stringify(document);
    const count = expectedRevision === 0
      ? await this.client.$executeRaw`
          INSERT INTO "cloudflare_allowlists" ("tenant_id", "document", "revision", "updated_at", "updated_by")
          VALUES (${tenantId}, ${encoded}::jsonb, 1, ${updatedAt}, ${updatedBy})
          ON CONFLICT ("tenant_id") DO NOTHING`
      : await this.client.$executeRaw`
          UPDATE "cloudflare_allowlists"
             SET "document" = ${encoded}::jsonb, "revision" = "revision" + 1,
                 "updated_at" = ${updatedAt}, "updated_by" = ${updatedBy}
           WHERE "tenant_id" = ${tenantId} AND "revision" = ${expectedRevision}::int`;
    return count === 1;
  }
}
