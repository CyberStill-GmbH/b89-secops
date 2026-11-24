/**
 * Aprendizaje SOC · fase 2 — meta-monitoreo del motor: alertas, severidades y runbooks.
 */

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_LEARNING_HEALTH_POLICY,
  evaluateLearningHealth,
  LEARNING_SLOS,
  type LearningHealthMetrics,
} from '../src/learning-health.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';

const NOW = new Date('2026-11-24T15:00:00.000Z');
const MIN = 60_000;

function healthy(overrides: Partial<LearningHealthMetrics> = {}): LearningHealthMetrics {
  return {
    enabled: true,
    maxMode: 'shadow',
    killSwitch: false,
    heartbeatAt: new Date(NOW.getTime() - MIN),
    backlog: { pending: 0, expiredLeases: 0, oldestPendingAt: null },
    deadLast24h: 0,
    lastHour: {
      jobsFinished: 40,
      jobsRetried: 0,
      latencyP95Ms: 2_000,
      decisions: 40,
      byApplied: { NONE: 40 },
      byEscalateReason: { GUARD_CONTEXT: 4 },
      hypotheticalCloses: 20,
    },
    last24h: { pauses: 0, reversals: 0, disagreements: 0, configChanges: 0, modeRaised: false },
    sourceState: 'healthy',
    ...overrides,
  };
}

const ids = (metrics: LearningHealthMetrics) =>
  evaluateLearningHealth(metrics, NOW).alerts.map((alert) => `${alert.id}:${alert.severity}`);

describe('fase 2 · salud del motor', () => {
  it('todo en orden → OK sin alertas', () => {
    expect(evaluateLearningHealth(healthy(), NOW)).toEqual({ status: 'OK', alerts: [] });
  });

  it('dead man’s switch: sin latido (o nunca) → crítico', () => {
    expect(ids(healthy({ heartbeatAt: new Date(NOW.getTime() - 6 * MIN) }))).toEqual([
      'HEARTBEAT_STALE:critical',
    ]);
    expect(ids(healthy({ heartbeatAt: null }))).toEqual(['HEARTBEAT_STALE:critical']);
  });

  it('cola atrasada: aviso a los 5 min, crítico a los 30; leases vencidos y dead-letter', () => {
    expect(
      ids(
        healthy({
          backlog: {
            pending: 3,
            expiredLeases: 0,
            oldestPendingAt: new Date(NOW.getTime() - 6 * MIN),
          },
        }),
      ),
    ).toEqual(['BACKLOG_AGE:warning']);
    expect(
      ids(
        healthy({
          backlog: {
            pending: 3,
            expiredLeases: 2,
            oldestPendingAt: new Date(NOW.getTime() - 31 * MIN),
          },
        }),
      ),
    ).toEqual(['BACKLOG_AGE:critical', 'EXPIRED_LEASES:warning']);
    expect(ids(healthy({ deadLast24h: 1 }))).toEqual(['DEAD_LETTERS:warning']);
    expect(ids(healthy({ deadLast24h: DEFAULT_LEARNING_HEALTH_POLICY.deadCritical }))).toEqual([
      'DEAD_LETTERS:critical',
    ]);
  });

  it('latencia, errores y escaladas por encima de los umbrales', () => {
    const lastHour = healthy().lastHour;
    expect(ids(healthy({ lastHour: { ...lastHour, latencyP95Ms: 61_000 } }))).toEqual([
      'LATENCY_P95:warning',
    ]);
    expect(ids(healthy({ lastHour: { ...lastHour, jobsRetried: 5 } }))).toEqual([
      'ERROR_RATE:warning',
    ]);
    expect(
      ids(
        healthy({
          lastHour: {
            ...lastHour,
            byEscalateReason: { DRIFT: 30 },
            byApplied: { ESCALATE: 30, NONE: 10 },
          },
        }),
      ),
    ).toEqual(['ESCALATION_SPIKE:warning']);
  });

  it('pausas, reversiones, desacuerdos y fuente no sana avisan', () => {
    const day = healthy().last24h;
    expect(
      ids(
        healthy({
          last24h: { ...day, pauses: 1, reversals: 1, disagreements: 1 },
          sourceState: null,
        }),
      ),
    ).toEqual([
      'PATTERN_PAUSED:warning',
      'REVERSALS:warning',
      'DISAGREEMENT:warning',
      'SOURCE_NOT_HEALTHY:warning',
    ]);
  });

  it('un cambio de configuración avisa también con el motor apagado; subir el techo es crítico', () => {
    const day = healthy().last24h;
    const off = evaluateLearningHealth(
      healthy({
        enabled: false,
        maxMode: 'off',
        heartbeatAt: null,
        last24h: { ...day, configChanges: 1, modeRaised: true },
      }),
      NOW,
    );
    expect(off).toEqual({
      status: 'OFF',
      alerts: [expect.objectContaining({ id: 'CONFIG_CHANGED', severity: 'critical' })],
    });
  });

  it('cada alerta enlaza su runbook y los SLO están declarados', () => {
    const report = evaluateLearningHealth(healthy({ heartbeatAt: null, deadLast24h: 1 }), NOW);
    expect(
      report.alerts.every((alert) =>
        alert.runbook.startsWith('docs/soc-learning/25-runbooks-motor.md#'),
      ),
    ).toBe(true);
    expect(LEARNING_SLOS.map((slo) => slo.id)).toContain('decision_latency');
  });

  it('agregados en memoria: cola, latencia, decisiones y cambios de configuración', async () => {
    const soc = new InMemorySoc();
    const enqueued = new Date(NOW.getTime() - 10 * MIN);
    soc.jobRows.set('t|a1', {
      alertId: 'a1',
      tenantId: 't',
      fingerprint: {} as never,
      signals: null,
      status: 'done',
      attempts: 1,
      availableAt: enqueued,
      leaseUntil: null,
      claimId: null,
      lastError: null,
      enqueuedAt: enqueued,
      finishedAt: new Date(enqueued.getTime() + 3_000),
    });
    soc.jobRows.set('t|a2', {
      alertId: 'a2',
      tenantId: 't',
      fingerprint: {} as never,
      signals: null,
      status: 'pending',
      attempts: 1,
      availableAt: NOW,
      leaseUntil: null,
      claimId: null,
      lastError: 'LEARNING_TIMEOUT',
      enqueuedAt: enqueued,
      finishedAt: null,
    });
    soc.heartbeatRows.set('w1', { tenantId: 't', at: NOW, claimed: 1, failed: 1 });
    soc.configEventRows.push(
      {
        id: 'c1',
        tenantId: 't',
        configHash: 'a'.repeat(64),
        maxMode: 'shadow',
        activeRules: 0,
        killSwitch: false,
        samplingKeyVersion: null,
        at: new Date(NOW.getTime() - 48 * 60 * MIN),
      },
      {
        id: 'c2',
        tenantId: 't',
        configHash: 'b'.repeat(64),
        maxMode: 'active',
        activeRules: 1,
        killSwitch: false,
        samplingKeyVersion: null,
        at: new Date(NOW.getTime() - MIN),
      },
    );
    const counts = await soc.learningHealthCounts('t', NOW);
    expect(counts).toMatchObject({
      heartbeatAt: NOW,
      backlog: { pending: 1, oldestPendingAt: enqueued },
      lastHour: { jobsFinished: 1, jobsRetried: 1, latencyP95Ms: 3_000 },
      last24h: { configChanges: 1, modeRaised: true },
    });
  });
});

describe('fase 3 · rotación de la clave de muestreo', () => {
  it('avisa a los 90 días, crítico a los 120; sin fecha de emisión fuera de sombra, aviso', () => {
    expect(ids(healthy({ samplingKeyAgeDays: 30 }))).toEqual([]);
    expect(ids(healthy({ samplingKeyAgeDays: 91 }))).toEqual(['SAMPLING_KEY_ROTATION_DUE:warning']);
    expect(ids(healthy({ samplingKeyAgeDays: 121 }))).toEqual([
      'SAMPLING_KEY_ROTATION_DUE:critical',
    ]);
    expect(ids(healthy({ maxMode: 'active', samplingKeyAgeDays: null }))).toEqual([
      'SAMPLING_KEY_UNDATED:warning',
    ]);
    expect(ids(healthy({ samplingKeyAgeDays: null }))).toEqual([]);
  });
});
