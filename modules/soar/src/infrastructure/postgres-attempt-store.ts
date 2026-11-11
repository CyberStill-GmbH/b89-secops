/** PostgreSQL adapter de C-20, publicado aparte para que el modo memoria no cargue Prisma. */

import {
  closeDatabaseClient,
  createDatabaseClient,
  type DatabaseConnectionOptions,
} from '@b89/database';
import {
  PrismaNotificationAttemptStore,
  PrismaNotificationChannelStore,
} from '@b89/database/notification-stores';

import {
  NOTIFICATION_CHANNELS,
  NOTIFICATION_STATUSES,
  SUPPRESSION_REASONS,
  type DeliveryEvidence,
  type NotificationAttempt,
} from '../notification.js';
import type { AttemptStore } from '../ports.js';
import { CHANNEL_IDS, type ChannelRecord, type ChannelStore } from '../notification-channels.js';

function toAttempt(
  row: Awaited<ReturnType<PrismaNotificationAttemptStore['byId']>>,
): NotificationAttempt | undefined {
  if (!row) return undefined;
  const channel = NOTIFICATION_CHANNELS.find((candidate) => candidate === row.channel);
  const status = NOTIFICATION_STATUSES.find((candidate) => candidate === row.status);
  if (!channel || !status) throw new Error('SOAR_STORAGE_CATALOG_INVALID');
  const context =
    row.context && typeof row.context === 'object' && !Array.isArray(row.context)
      ? (row.context as Readonly<Record<string, unknown>>)
      : null;
  return {
    ...row,
    channel,
    status,
    groupKey: row.groupKey ?? null,
    context,
    delivery: Array.isArray(row.delivery) ? (row.delivery as DeliveryEvidence[]) : [],
    suppressionReason:
      SUPPRESSION_REASONS.find((reason) => reason === row.suppressionReason) ?? null,
    supersededBy: row.supersededBy ?? null,
    digestId: row.digestId ?? null,
  };
}

/** Adapter de dominio y dueño del pool Prisma usado por el dispatcher. */
export class PostgresNotificationAttemptStore implements AttemptStore {
  /** Canales administrables, en el mismo pool (pocas lecturas y escrituras). */
  public readonly channels: ChannelStore;

  private constructor(
    private readonly store: PrismaNotificationAttemptStore,
    channelStore: PrismaNotificationChannelStore,
    private readonly closeClient: () => Promise<void>,
  ) {
    const toRecord = (row: Awaited<ReturnType<PrismaNotificationChannelStore['get']>>) => {
      if (!row) return undefined;
      const channelId = CHANNEL_IDS.find((id) => id === row.channelId);
      if (!channelId) return undefined;
      const outcome = row.lastTestOutcome === 'accepted' || row.lastTestOutcome === 'failed' ? row.lastTestOutcome : null;
      return { ...row, channelId, lastTestOutcome: outcome } satisfies ChannelRecord;
    };
    this.channels = {
      list: async (tenantId) =>
        (await channelStore.list(tenantId)).flatMap((row) => {
          const record = toRecord(row);
          return record ? [record] : [];
        }),
      get: async (tenantId, channelId) => toRecord(await channelStore.get(tenantId, channelId)),
      save: (record) => channelStore.save(record),
    };
  }

  public static connect(options: DatabaseConnectionOptions): PostgresNotificationAttemptStore {
    const client = createDatabaseClient(options);
    return new PostgresNotificationAttemptStore(
      new PrismaNotificationAttemptStore(client),
      new PrismaNotificationChannelStore(client),
      () => closeDatabaseClient(client),
    );
  }

  public async byIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<NotificationAttempt | undefined> {
    return toAttempt(await this.store.byIdempotencyKey(tenantId, idempotencyKey));
  }

  public async byId(tenantId: string, attemptId: string): Promise<NotificationAttempt | undefined> {
    return toAttempt(await this.store.byId(tenantId, attemptId));
  }

  public save(attempt: NotificationAttempt): Promise<void> {
    return this.store.save(attempt);
  }

  public countByStatusSince(
    tenantId: string,
    since: Date,
  ): Promise<Readonly<Record<string, number>>> {
    return this.store.countByStatusSince(tenantId, since);
  }

  public async lastNotifiedInGroup(
    tenantId: string,
    groupKey: string,
    since: Date,
  ): Promise<NotificationAttempt | undefined> {
    return toAttempt(await this.store.lastNotifiedInGroup(tenantId, groupKey, since));
  }

  public async listSuppressedInGroup(
    tenantId: string,
    groupKey: string,
    after: Date,
    limit: number,
  ): Promise<readonly NotificationAttempt[]> {
    const rows = await this.store.listSuppressedInGroup(tenantId, groupKey, after, limit);
    return rows.map((row) => toAttempt(row)!);
  }

  public countNotifiedSince(tenantId: string, since: Date): Promise<number> {
    return this.store.countNotifiedSince(tenantId, since);
  }

  public async listUndigested(
    tenantId: string,
    limit: number,
  ): Promise<readonly NotificationAttempt[]> {
    const rows = await this.store.listUndigested(tenantId, limit);
    return rows.map((row) => toAttempt(row)!);
  }

  public async listByTenant(
    tenantId: string,
    limit: number,
  ): Promise<readonly NotificationAttempt[]> {
    const rows = await this.store.listByTenant(tenantId, limit);
    return rows.map((row) => toAttempt(row)!);
  }

  public close(): Promise<void> {
    return this.closeClient();
  }
}

// Sprint 5: dispositivos Web Push en el mismo subpath `@b89/soar/postgres`.
export { PostgresPushSubscriptionStore } from './postgres-push-store.js';
