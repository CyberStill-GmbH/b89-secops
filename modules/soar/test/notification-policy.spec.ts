import { beforeEach, describe, expect, it } from 'vitest';

import { InMemoryAuditStore } from '@b89/audit';
import type { OutboxMessageDraft } from '@b89/soc';

import { dispatchMessage, type DispatchDependencies } from '../src/dispatcher.js';
import { ConsoleFallbackChannel, InMemoryAttemptStore, InMemoryOutbox } from '../src/memory-stores.js';
import { groupKeyFor, type NotificationEnricher } from '../src/notification-context.js';
import { runSuppressedDigest } from '../src/notification-digest.js';
import { DEFAULT_NOTIFICATION_POLICY, decideNotification } from '../src/notification-policy.js';
import type { DeliveryOutcome, NotificationTransport } from '../src/teams-adapter.js';
import type { TeamsMessage } from '../src/teams-payload.js';

const NOW = new Date('2026-11-10T12:47:00.000Z');
const HISTORY = { lastNotified: null, suppressedSinceLast: 0, immediateLastHour: 0 };

describe('política de ruido · decisión', () => {
  it('P1/P2 frescos salen de inmediato; P3/P4 van al resumen', () => {
    for (const priority of ['P1', 'P2'] as const) {
      expect(
        decideNotification({ priority, incident: false, occurredAt: NOW, now: NOW, history: HISTORY }),
      ).toMatchObject({ kind: 'notify', occurrences: 1, late: false, reminderOf: null });
    }
    for (const priority of ['P3', 'P4'] as const) {
      expect(
        decideNotification({ priority, incident: false, occurredAt: NOW, now: NOW, history: HISTORY }),
      ).toEqual({ kind: 'suppress', reason: 'digest', coveredBy: null });
    }
  });

  it('agrupa dentro de la ventana silenciosa y re-avisa al vencer con el conteo', () => {
    const last = { id: 'a1', at: new Date(NOW.getTime() - 10 * 60_000) };
    expect(
      decideNotification({
        priority: 'P2',
        incident: false,
        occurredAt: NOW,
        now: NOW,
        history: { ...HISTORY, lastNotified: last },
      }),
    ).toEqual({ kind: 'suppress', reason: 'grouped', coveredBy: 'a1' });
    const old = { id: 'a1', at: new Date(NOW.getTime() - DEFAULT_NOTIFICATION_POLICY.quietPeriodMs.P2 - 1) };
    expect(
      decideNotification({
        priority: 'P2',
        incident: false,
        occurredAt: NOW,
        now: NOW,
        history: { ...HISTORY, lastNotified: old, suppressedSinceLast: 7 },
      }),
    ).toMatchObject({ kind: 'notify', reminderOf: 'a1', occurrences: 8 });
  });

  it('una P2 atrasada (backlog tras una caída) va al resumen; una P1 sale rotulada tardía', () => {
    const occurredAt = new Date(NOW.getTime() - 8 * 3_600_000);
    expect(
      decideNotification({ priority: 'P2', incident: false, occurredAt, now: NOW, history: HISTORY }),
    ).toMatchObject({ kind: 'suppress', reason: 'stale_backlog' });
    expect(
      decideNotification({ priority: 'P1', incident: false, occurredAt, now: NOW, history: HISTORY }),
    ).toMatchObject({ kind: 'notify', late: true });
  });

  it('respeta el tope por hora para P2, no para P1', () => {
    const history = { ...HISTORY, immediateLastHour: DEFAULT_NOTIFICATION_POLICY.maxImmediatePerHour };
    expect(
      decideNotification({ priority: 'P2', incident: false, occurredAt: NOW, now: NOW, history }),
    ).toMatchObject({ kind: 'suppress', reason: 'rate_limited' });
    expect(
      decideNotification({ priority: 'P1', incident: false, occurredAt: NOW, now: NOW, history }),
    ).toMatchObject({ kind: 'notify' });
  });

  it('la clave de grupo no contiene la entidad en claro y separa la escalada', () => {
    const key = groupKeyFor({
      aggregateType: 'alert',
      aggregateId: 'x',
      ruleId: '100510',
      entityKeys: ['user:rodrigo@b89.io'],
    });
    expect(key).toMatch(/^g_[0-9a-f]{24}$/u);
    expect(key).not.toContain('rodrigo');
    expect(
      groupKeyFor({ messageType: 'soc.alert.escalated', aggregateType: 'alert', aggregateId: 'x', ruleId: '100510' }),
    ).not.toBe(groupKeyFor({ aggregateType: 'alert', aggregateId: 'x', ruleId: '100510' }));
  });
});

class RecordingTransport implements NotificationTransport {
  public readonly destinationRef = 'teams:canal-soc';
  public readonly calls: TeamsMessage[] = [];
  public send(message: TeamsMessage): Promise<DeliveryOutcome> {
    this.calls.push(message);
    return Promise.resolve({
      delivered: true,
      httpStatus: 202,
      providerMessageId: `x-ms-workflow-run-id:run-${this.calls.length}`,
    });
  }
}

describe('ráfaga tras una caída (incidente 2026-11-10)', () => {
  let attempts: InMemoryAttemptStore;
  let outbox: InMemoryOutbox;
  let transport: RecordingTransport;
  let now: Date;
  let sequence: number;

  // 20 alertas de la misma regla del monitor (101810, b89-api-1 caído), ocurridas durante 8 h y
  // procesadas de golpe al volver la API, más una P2 fresca de otra regla.
  const occurredAt = (index: number) => new Date(NOW.getTime() - (8 * 60 - index * 20) * 60_000);
  const enricher: NotificationEnricher = {
    contextFor: (message) =>
      Promise.resolve({
        context: {
          kind: 'alert',
          alertId: message.aggregateId,
          incidentId: null,
          title: String(message.payload['title']),
          priority: 'P2',
          severity: null,
          source: { id: 'plataforma', vendor: 'Plataforma B89 (monitor)' },
          entity: null,
          ruleId: String(message.payload['ruleId']),
          summary: String(message.payload['title']),
          whyItMatters: null,
          mitre: [],
          correlation: null,
          score: 80,
          reasons: [],
          relatedAlertCount: 0,
          occurredAt: String(message.payload['occurredAt']),
          nextStep: null,
          runbook: null,
          test: false,
        },
        entityKeys: [],
        occurredAt: new Date(String(message.payload['occurredAt'])),
      }),
  };

  function message(index: number, ruleId: string, at: Date): OutboxMessageDraft {
    return {
      messageId: `00000000-0000-4000-8000-${index.toString().padStart(12, '0')}`,
      tenantId: 't1',
      aggregateType: 'alert',
      aggregateId: `alert-${index}`,
      messageType: 'soc.alert.created',
      schemaVersion: '1.0.0',
      idempotencyKey: `k-${index}`,
      payload: {
        title: `B89 Plataforma: servicio esencial caído b89-api-1 (${ruleId})`,
        priority: 'P2',
        ruleId,
        occurredAt: at.toISOString(),
      },
      availableAt: NOW,
    };
  }

  function dependencies(): DispatchDependencies {
    return {
      outbox,
      attempts,
      transport,
      fallback: new ConsoleFallbackChannel(),
      audit: new InMemoryAuditStore(),
      clock: { now: () => now },
      ids: {
        next: () => {
          sequence += 1;
          return `0199bf33-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
        },
      },
      consoleBaseUrl: 'https://dev.security.b89.io',
      enricher,
    };
  }

  beforeEach(() => {
    attempts = new InMemoryAttemptStore();
    outbox = new InMemoryOutbox();
    transport = new RecordingTransport();
    now = NOW;
    sequence = 0;
  });

  it('20 alertas atrasadas de la misma regla no abren 20 tarjetas: una sola sale como resumen', async () => {
    const codes = [];
    for (let index = 0; index < 20; index += 1) {
      codes.push((await dispatchMessage(dependencies(), message(index, '101810', occurredAt(index)))).code);
    }
    // La única fresca (ocurrida hace < 60 min) sale; el resto es atraso o queda agrupado con ella.
    expect(codes.filter((code) => code === 'delivered').length).toBeLessThanOrEqual(1);
    expect(codes.filter((code) => code === 'suppressed').length).toBeGreaterThanOrEqual(19);

    now = new Date(NOW.getTime() + DEFAULT_NOTIFICATION_POLICY.digestFlushMs + 1);
    const digest = await runSuppressedDigest({
      tenantId: 't1',
      attempts,
      transport,
      audit: new InMemoryAuditStore(),
      clock: { now: () => now },
      consoleBaseUrl: 'https://dev.security.b89.io',
    });
    expect(digest?.status).toBe('sent');
    expect(digest?.delivery?.[0]).toMatchObject({ channel: 'teams', outcome: 'accepted', httpStatus: 202 });
    // Total de tarjetas: ≤ 1 inmediata + 1 resumen (antes: 20).
    expect(transport.calls.length).toBeLessThanOrEqual(2);
    expect(await attempts.listUndigested('t1', 100)).toHaveLength(0);
    // Un segundo pase no repite el resumen.
    expect(
      await runSuppressedDigest({
        tenantId: 't1',
        attempts,
        transport,
        audit: new InMemoryAuditStore(),
        clock: { now: () => now },
        consoleBaseUrl: 'https://dev.security.b89.io',
      }),
    ).toBeUndefined();
  });

  it('guarda la evidencia de entrega (HTTP y run id del Workflow) en el intento', async () => {
    const result = await dispatchMessage(dependencies(), message(1, '100510', NOW));
    expect(result.code).toBe('delivered');
    expect(result.attempt?.delivery).toEqual([
      expect.objectContaining({
        channel: 'teams',
        outcome: 'accepted',
        httpStatus: 202,
        providerMessageId: 'x-ms-workflow-run-id:run-1',
      }),
    ]);
    expect(result.attempt?.groupKey).toMatch(/^g_/u);
    // Una segunda alerta del mismo grupo dentro de la ventana queda agrupada, no sale.
    const second = await dispatchMessage(dependencies(), message(2, '100510', NOW));
    expect(second.code).toBe('suppressed');
    expect(second.attempt).toMatchObject({ suppressionReason: 'grouped', supersededBy: result.attempt?.id });
    expect(transport.calls).toHaveLength(1);
  });
});
