/**
 * Stores en memoria de C-20, para unit specs y para el harness E2E.
 *
 * `InMemoryOutbox` reproduce el lease y el reintento diferido; sin eso, una spec de
 * drenaje mediría algo distinto de lo que hará el adapter sobre PostgreSQL.
 */

import type { OutboxMessageDraft } from '@b89/soc';

import type {
  DeliveryEvidence,
  NotificationAttempt,
  NotificationChannel,
} from './notification.js';
import type { AttemptStore, FallbackChannel, FallbackNotification, OutboxReader } from './ports.js';

interface OutboxRow {
  readonly message: OutboxMessageDraft;
  status: 'pending' | 'processing' | 'published';
  availableAt: Date;
  attemptCount: number;
  lastErrorCode: string | null;
  publishedAt: Date | null;
}

export class InMemoryOutbox implements OutboxReader {
  public readonly rows = new Map<string, OutboxRow>();

  public enqueue(message: OutboxMessageDraft): void {
    if (this.rows.has(message.messageId)) return;
    this.rows.set(message.messageId, {
      message,
      status: 'pending',
      availableAt: message.availableAt,
      attemptCount: 0,
      lastErrorCode: null,
      publishedAt: null,
    });
  }

  public claimPending(limit: number, now: Date): Promise<readonly OutboxMessageDraft[]> {
    const claimed: OutboxMessageDraft[] = [];
    for (const row of this.rows.values()) {
      if (claimed.length >= limit) break;
      if (row.status !== 'pending' || row.availableAt.getTime() > now.getTime()) continue;
      row.status = 'processing';
      row.attemptCount += 1;
      claimed.push(row.message);
    }
    return Promise.resolve(claimed);
  }

  public markPublished(messageId: string, at: Date): Promise<void> {
    const row = this.rows.get(messageId);
    if (row) {
      row.status = 'published';
      row.publishedAt = at;
    }
    return Promise.resolve();
  }

  public scheduleRetry(messageId: string, availableAt: Date, errorCode: string): Promise<void> {
    const row = this.rows.get(messageId);
    if (row) {
      row.status = 'pending';
      row.availableAt = availableAt;
      row.lastErrorCode = errorCode;
    }
    return Promise.resolve();
  }
}

export class InMemoryAttemptStore implements AttemptStore {
  public readonly rows = new Map<string, NotificationAttempt>();

  public byIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<NotificationAttempt | undefined> {
    return Promise.resolve(this.rows.get(`${tenantId}|${idempotencyKey}`));
  }

  public byId(tenantId: string, attemptId: string): Promise<NotificationAttempt | undefined> {
    return Promise.resolve(
      [...this.rows.values()].find(
        (attempt) => attempt.tenantId === tenantId && attempt.id === attemptId,
      ),
    );
  }

  public save(attempt: NotificationAttempt): Promise<void> {
    this.rows.set(`${attempt.tenantId}|${attempt.idempotencyKey}`, attempt);
    return Promise.resolve();
  }

  public countByStatusSince(
    tenantId: string,
    since: Date,
  ): Promise<Readonly<Record<string, number>>> {
    const counts: Record<string, number> = {};
    for (const attempt of this.rows.values()) {
      if (attempt.tenantId !== tenantId || attempt.createdAt.getTime() < since.getTime()) continue;
      counts[attempt.status] = (counts[attempt.status] ?? 0) + 1;
    }
    return Promise.resolve(counts);
  }

  public lastNotifiedInGroup(
    tenantId: string,
    groupKey: string,
    since: Date,
  ): Promise<NotificationAttempt | undefined> {
    const notified = [...this.rows.values()]
      .filter(
        (attempt) =>
          attempt.tenantId === tenantId &&
          attempt.groupKey === groupKey &&
          attempt.sentAt !== null &&
          attempt.sentAt.getTime() >= since.getTime(),
      )
      .sort((left, right) => right.sentAt!.getTime() - left.sentAt!.getTime());
    return Promise.resolve(notified[0]);
  }

  public listSuppressedInGroup(
    tenantId: string,
    groupKey: string,
    after: Date,
    limit: number,
  ): Promise<readonly NotificationAttempt[]> {
    return Promise.resolve(
      [...this.rows.values()]
        .filter(
          (attempt) =>
            attempt.tenantId === tenantId &&
            attempt.groupKey === groupKey &&
            attempt.status === 'suppressed' &&
            attempt.createdAt.getTime() > after.getTime(),
        )
        .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime())
        .slice(0, limit),
    );
  }

  public countNotifiedSince(tenantId: string, since: Date): Promise<number> {
    return Promise.resolve(
      [...this.rows.values()].filter(
        (attempt) =>
          attempt.tenantId === tenantId &&
          attempt.sentAt !== null &&
          !(attempt.groupKey ?? '').startsWith('digest:') &&
          attempt.sentAt.getTime() >= since.getTime(),
      ).length,
    );
  }

  public listUndigested(tenantId: string, limit: number): Promise<readonly NotificationAttempt[]> {
    return Promise.resolve(
      [...this.rows.values()]
        .filter(
          (attempt) =>
            attempt.tenantId === tenantId &&
            attempt.status === 'suppressed' &&
            (attempt.digestId ?? null) === null,
        )
        .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime())
        .slice(0, limit),
    );
  }

  public listByTenant(tenantId: string, limit: number): Promise<readonly NotificationAttempt[]> {
    return Promise.resolve(
      [...this.rows.values()]
        .filter((attempt) => attempt.tenantId === tenantId)
        .sort(
          (left, right) =>
            right.createdAt.getTime() - left.createdAt.getTime() || right.id.localeCompare(left.id),
        )
        .slice(0, Math.max(limit, 1)),
    );
  }
}

/**
 * Fallback de registro: deja el crítico en una bandeja que la consola muestra y que
 * sigue exigiendo acuse. No pretende ser un segundo canal de mensajería.
 */
export class ConsoleFallbackChannel implements FallbackChannel {
  public readonly delivered: FallbackNotification[] = [];

  public notify(
    notification: FallbackNotification,
  ): Promise<{
    readonly channel: NotificationChannel;
    readonly reference: string;
    readonly evidence: readonly DeliveryEvidence[];
  }> {
    this.delivered.push(notification);
    return Promise.resolve({
      channel: 'manual_console',
      reference: `fallback:${notification.tenantId}:${notification.aggregateId}`,
      evidence: [
        {
          channel: 'console',
          outcome: 'accepted',
          at: notification.at.toISOString(),
          httpStatus: null,
          providerMessageId: null,
          providerLink: null,
          reason: notification.reason,
        },
      ],
    });
  }
}
