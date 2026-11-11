/**
 * C-20 — almacenamiento PostgreSQL de intentos SOAR.
 *
 * La capa de persistencia devuelve filas planas: el dominio y sus catálogos siguen en
 * `modules/soar`. La clave compuesta del esquema hace idempotente la creación frente a
 * reentregas del mismo mensaje.
 */

import { Prisma, type PrismaClient } from '../generated/client/client.js';

export interface NotificationAttemptRow {
  readonly id: string;
  readonly tenantId: string;
  readonly messageId: string;
  readonly idempotencyKey: string;
  readonly clientRequestId: string;
  readonly channel: string;
  readonly status: string;
  readonly attemptCount: number;
  readonly availableAt: Date;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly lastFailureCode: string | null;
  readonly lastFailureClass: string | null;
  readonly sentAt: Date | null;
  readonly acknowledgedAt: Date | null;
  readonly acknowledgedBy: string | null;
  readonly groupKey?: string | null;
  readonly context?: unknown;
  readonly delivery?: unknown;
  readonly suppressionReason?: string | null;
  readonly supersededBy?: string | null;
  readonly digestId?: string | null;
}

/** Estados en que el aviso se publicó (tiene `sentAt`). */
const NOTIFIED_STATUSES = ['sent', 'fallback', 'acknowledged', 'superseded'];



/** Store de una fila actual por (tenant, clave idempotente). */
export class PrismaNotificationAttemptStore {
  public constructor(private readonly client: PrismaClient) {}

  private assertIdentity(existing: NotificationAttemptRow, attempt: NotificationAttemptRow): void {
    if (
      existing.id !== attempt.id ||
      existing.messageId !== attempt.messageId ||
      existing.clientRequestId !== attempt.clientRequestId
    ) {
      throw new Error('SOAR_ATTEMPT_IDENTITY_MISMATCH');
    }
  }

  public async byIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<NotificationAttemptRow | undefined> {
    const row = await this.client.notificationAttempt.findUnique({
      where: { tenantId_idempotencyKey: { tenantId, idempotencyKey } },
    });
    return row ?? undefined;
  }

  public async byId(
    tenantId: string,
    attemptId: string,
  ): Promise<NotificationAttemptRow | undefined> {
    const row = await this.client.notificationAttempt.findFirst({
      where: { id: attemptId, tenantId },
    });
    return row ?? undefined;
  }

  /** Conteo por estado en la ventana `[since, ahora]`, agregado en la base. */
  public async countByStatusSince(
    tenantId: string,
    since: Date,
  ): Promise<Readonly<Record<string, number>>> {
    const groups = await this.client.notificationAttempt.groupBy({
      by: ['status'],
      where: { tenantId, createdAt: { gte: since } },
      _count: { _all: true },
    });
    return Object.fromEntries(groups.map((group) => [group.status, group._count._all]));
  }

  /** Bandeja de la consola: más recientes primero, acotada. */
  public async listByTenant(
    tenantId: string,
    limit: number,
  ): Promise<readonly NotificationAttemptRow[]> {
    return this.client.notificationAttempt.findMany({
      where: { tenantId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: Math.min(Math.max(limit, 1), 2_000),
    });
  }

  /** Último aviso publicado del grupo desde `since`. */
  public async lastNotifiedInGroup(
    tenantId: string,
    groupKey: string,
    since: Date,
  ): Promise<NotificationAttemptRow | undefined> {
    const row = await this.client.notificationAttempt.findFirst({
      where: { tenantId, groupKey, sentAt: { gte: since }, status: { in: NOTIFIED_STATUSES } },
      orderBy: [{ sentAt: 'desc' }, { id: 'desc' }],
    });
    return row ?? undefined;
  }

  public listSuppressedInGroup(
    tenantId: string,
    groupKey: string,
    after: Date,
    limit: number,
  ): Promise<readonly NotificationAttemptRow[]> {
    return this.client.notificationAttempt.findMany({
      where: { tenantId, groupKey, status: 'suppressed', createdAt: { gt: after } },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: Math.min(Math.max(limit, 1), 2_000),
    });
  }

  /** Avisos inmediatos publicados desde `since` (los resúmenes no cuentan para el tope). */
  public countNotifiedSince(tenantId: string, since: Date): Promise<number> {
    return this.client.notificationAttempt.count({
      where: {
        tenantId,
        sentAt: { gte: since },
        status: { in: NOTIFIED_STATUSES },
        OR: [{ groupKey: null }, { NOT: { groupKey: { startsWith: 'digest:' } } }],
      },
    });
  }

  public listUndigested(tenantId: string, limit: number): Promise<readonly NotificationAttemptRow[]> {
    return this.client.notificationAttempt.findMany({
      where: { tenantId, status: 'suppressed', digestId: null },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: Math.min(Math.max(limit, 1), 2_000),
    });
  }

  /**
   * Inserta el primer intento o guarda su estado más reciente. La identidad del intento,
   * mensaje e idempotency key no cambia al pasar por retries o acknowledgements.
   */
  public async save(attempt: NotificationAttemptRow): Promise<void> {
    const existing = await this.byIdempotencyKey(attempt.tenantId, attempt.idempotencyKey);
    const { tenantId, idempotencyKey } = attempt;
    const mutable = {
      messageId: attempt.messageId,
      clientRequestId: attempt.clientRequestId,
      channel: attempt.channel,
      status: attempt.status,
      attemptCount: attempt.attemptCount,
      availableAt: attempt.availableAt,
      createdAt: attempt.createdAt,
      updatedAt: attempt.updatedAt,
      lastFailureCode: attempt.lastFailureCode,
      lastFailureClass: attempt.lastFailureClass,
      sentAt: attempt.sentAt,
      acknowledgedAt: attempt.acknowledgedAt,
      acknowledgedBy: attempt.acknowledgedBy,
      groupKey: attempt.groupKey ?? null,
      context:
        attempt.context === undefined || attempt.context === null
          ? Prisma.DbNull
          : (attempt.context as Prisma.InputJsonValue),
      delivery: (attempt.delivery ?? []) as Prisma.InputJsonValue,
      suppressionReason: attempt.suppressionReason ?? null,
      supersededBy: attempt.supersededBy ?? null,
      digestId: attempt.digestId ?? null,
    };
    const where = { tenantId_idempotencyKey: { tenantId, idempotencyKey } };
    if (existing) {
      this.assertIdentity(existing, attempt);
      await this.client.notificationAttempt.update({ where, data: mutable });
      return;
    }

    try {
      await this.client.notificationAttempt.create({
        data: { ...mutable, id: attempt.id, tenantId, idempotencyKey },
      });
    } catch (error) {
      // Dos réplicas pueden crear el primer estado simultáneamente. La unicidad de
      // PostgreSQL decide al ganador; el perdedor solo puede continuar si era el mismo
      // mensaje/intento y entonces actualiza esa fila.
      if (
        typeof error !== 'object' ||
        error === null ||
        !('code' in error) ||
        error.code !== 'P2002'
      )
        throw error;
      const raced = await this.byIdempotencyKey(tenantId, idempotencyKey);
      if (!raced) throw error;
      this.assertIdentity(raced, attempt);
      await this.client.notificationAttempt.update({ where, data: mutable });
    }
  }
}

export interface NotificationChannelRow {
  readonly tenantId: string;
  readonly channelId: string;
  readonly enabled: boolean;
  readonly secretCiphertext: string | null;
  readonly secretHint: string | null;
  readonly updatedAt: Date;
  readonly updatedBy: string | null;
  readonly lastSuccessAt: Date | null;
  readonly lastFailureAt: Date | null;
  readonly lastHttpStatus: number | null;
  readonly lastFailureReason: string | null;
  readonly lastTestAt: Date | null;
  readonly lastTestOutcome: string | null;
  readonly lastTestHttpStatus: number | null;
  readonly lastTestProviderId: string | null;
}

/** Canales de aviso administrables: una fila por (tenant, canal). */
export class PrismaNotificationChannelStore {
  public constructor(private readonly client: PrismaClient) {}

  public list(tenantId: string): Promise<readonly NotificationChannelRow[]> {
    return this.client.notificationChannel.findMany({
      where: { tenantId },
      orderBy: { channelId: 'asc' },
    });
  }

  public async get(tenantId: string, channelId: string): Promise<NotificationChannelRow | undefined> {
    const row = await this.client.notificationChannel.findUnique({
      where: { tenantId_channelId: { tenantId, channelId } },
    });
    return row ?? undefined;
  }

  public async save(row: NotificationChannelRow): Promise<void> {
    const { tenantId, channelId, ...data } = row;
    await this.client.notificationChannel.upsert({
      where: { tenantId_channelId: { tenantId, channelId } },
      create: row,
      update: data,
    });
  }
}
