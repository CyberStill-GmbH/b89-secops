/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */

import type {
  NotificationChannelState,
  NotificationChannelTest,
  NotificationChannelView,
  NotificationChannelsResponse,
} from '../../common';

/** Adapts the registry DTO and the stable UI DTO without exposing webhook secrets. */
export function normalizeChannelsResponse(value: unknown): NotificationChannelsResponse {
  if (!isRecord(value)) return { channels: [] };
  const rows = Array.isArray(value.channels) ? value.channels : Array.isArray(value.items) ? value.items : [];
  return {
    channels: rows.flatMap((row): NotificationChannelView[] => {
      if (!isRecord(row)) return [];
      const apiId = row.id;
      const id = apiId === 'email' ? 'fallback_email' : apiId === 'push' ? 'manual_console' : apiId;
      if (id !== 'teams' && id !== 'fallback_email' && id !== 'manual_console') return [];
      const health = isRecord(row.health) ? row.health : {};
      const status = row.status;
      const state: NotificationChannelState = isChannelState(row.state) ? row.state : status === 'ok' ? 'active'
        : status === 'failing' || status === 'degraded' ? 'failing'
          : status === 'disabled' ? 'inactive'
            : status === 'unknown' ? 'unknown' : 'unconfigured';
      const successAt = stringOrNull(health.lastSuccessAt);
      const failureAt = stringOrNull(health.lastFailureAt);
      const lastAt = successAt ?? failureAt;
      return [{
        id,
        apiId: isApiChannelId(apiId) ? apiId : undefined,
        enabled: row.enabled === true,
        configured: row.configured === true,
        state,
        target: stringOrNull(row.target) ?? stringOrNull(row.destination),
        lastDelivery: lastAt ? {
          ok: Boolean(successAt) && (!failureAt || Date.parse(successAt!) >= Date.parse(failureAt)),
          at: lastAt,
          reason: stringOrNull(health.lastFailureReason),
        } : null,
        ...(typeof row.updatedAt === 'string' ? { updatedAt: row.updatedAt } : {}),
        ...(typeof row.updatedBy === 'string' ? { updatedBy: row.updatedBy } : {}),
        ...(typeof row.revision === 'number' ? { revision: row.revision } : {}),
      }];
    }),
  };
}

export function normalizeChannelTest(value: unknown): NotificationChannelTest {
  const body = isRecord(value) ? value : {};
  const result = isRecord(body.result) ? body.result : body;
  const failure = isRecord(result.failure) ? result.failure : {};
  return {
    ok: result.ok === true || result.outcome === 'accepted',
    at: typeof result.at === 'string' ? result.at : new Date().toISOString(),
    ...(typeof result.reason === 'string' ? { reason: result.reason }
      : typeof failure.code === 'string' ? { reason: failure.code } : {}),
    ...(typeof result.latencyMs === 'number' ? { latencyMs: result.latencyMs } : {}),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function isApiChannelId(value: unknown): value is 'teams' | 'email' | 'push' {
  return value === 'teams' || value === 'email' || value === 'push';
}

function isChannelState(value: unknown): value is NotificationChannelState {
  return value === 'active' || value === 'inactive' || value === 'failing' ||
    value === 'unconfigured' || value === 'unknown';
}
