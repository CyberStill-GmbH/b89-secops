/** Lista blanca de la API de pagos: un documento por tenant con revisión (compare-and-set). */
export interface AllowlistRecord {
  readonly tenantId: string;
  readonly document: unknown;
  readonly revision: number;
  readonly updatedAt: Date;
  readonly updatedBy: string;
}

export interface AllowlistStore {
  get(tenantId: string): Promise<AllowlistRecord | undefined>;
  put(tenantId: string, document: unknown, expectedRevision: number, updatedBy: string, updatedAt: Date): Promise<boolean>;
}

/** Para perfiles sin PostgreSQL (desarrollo y pruebas): mismas reglas, sin persistencia. */
export class InMemoryAllowlistStore implements AllowlistStore {
  private readonly rows = new Map<string, AllowlistRecord>();

  public async get(tenantId: string) {
    return this.rows.get(tenantId);
  }

  public async put(tenantId: string, document: unknown, expectedRevision: number, updatedBy: string, updatedAt: Date) {
    const current = this.rows.get(tenantId)?.revision ?? 0;
    if (current !== expectedRevision) return false;
    this.rows.set(tenantId, { tenantId, document, revision: current + 1, updatedAt, updatedBy });
    return true;
  }
}
