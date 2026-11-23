import { describe, expect, it } from 'vitest';
import {
  CorrelatorFeedbackStatus,
  OperationsStatus,
  SocCorrelatorHealth,
} from '../../common/api_contract';
import {
  describeCorrelatorHealth,
  describeSourceCoverage,
  formatLatencySummary,
  formatOutboxQueueSummary,
} from './operations_view';

describe('operations correlator contract and copy', () => {
  const correlator = (
    feedbackStatus: CorrelatorFeedbackStatus,
    overrides: Partial<SocCorrelatorHealth> = {},
  ): SocCorrelatorHealth => ({
    status: 'OK' as OperationsStatus,
    ready: feedbackStatus === 'ready',
    feedbackStatus,
    feedbackAgeSeconds: null,
    lastFeedbackSuccess: null,
    ...overrides,
  });

  it.each([
    ['ready', 'Listo'],
    ['pending', 'Inicializando'],
    ['failed', 'Actualización fallida'],
    ['unavailable', 'Sin respuesta'],
    ['unconfigured', 'No configurado'],
  ] as const)('labels feedback status %s as %s', (feedbackStatus, label) => {
    expect(describeCorrelatorHealth(correlator(feedbackStatus)).label).toBe(label);
  });

  it('shows stale age and last successful refresh data without internal details', () => {
    const status = describeCorrelatorHealth(
      correlator('stale', {
        status: 'STALE',
        ready: false,
        feedbackAgeSeconds: 125,
        lastFeedbackSuccess: '2026-11-12T10:00:00.000Z',
      }),
    );
    expect(status.label).toBe('Atrasado · 2 min sin actualizar');
    expect(status.tone).toBe('warn');
  });

  it('reports a missing correlator response and degraded overall readiness clearly', () => {
    expect(describeCorrelatorHealth(undefined).label).toBe('Sin respuesta');
    expect(
      describeCorrelatorHealth(correlator('ready', { status: 'DEGRADED', ready: false })).label,
    ).toBe('Con problemas');
  });
});

describe('operations latency copy', () => {
  it('uses readable separators and Spanish labels for handler latency', () => {
    expect(formatLatencySummary(1.4, 2.6, 3.2, 8)).toBe(
      'p50 1 ms · p95 3 ms · p99 3 ms · 8 muestras',
    );
  });

  it('falls back to p95 when p50 or p99 is unavailable', () => {
    expect(formatLatencySummary(null, 12, null, 1)).toBe(
      'p50 0 ms · p95 12 ms · p99 12 ms · 1 muestra',
    );
  });
});

describe('operations outbox lease copy', () => {
  it('shows expired lease count and age without inventing age when there are none', () => {
    expect(
      formatOutboxQueueSummary({
        pending: 2,
        processing: 3,
        oldestPendingAgeSeconds: 61,
        expiredProcessing: 2,
        oldestExpiredLeaseAgeSeconds: 9,
      }),
    ).toBe(
      '2 pendientes · 3 en curso · más antigua 1 min · 2 atascados · el más antiguo atascado hace 9 s',
    );
    expect(
      formatOutboxQueueSummary({
        pending: 0,
        processing: 1,
        oldestPendingAgeSeconds: null,
        expiredProcessing: 0,
        oldestExpiredLeaseAgeSeconds: null,
      }),
    ).toBe('0 pendientes · 1 en curso · más antigua Sin dato · 0 atascados');
  });
});

describe('source coverage copy', () => {
  it('never presents missing heartbeats or lag as inactivity', () => {
    const state = describeSourceCoverage({
      complete: false,
      sources: [
        {
          source: 'aws',
          state: 'complete',
          reason: null,
          providerLagSeconds: 30,
          lastEventAgeSeconds: 5,
        },
        {
          source: 'm365',
          state: 'incomplete',
          reason: 'collector_behind_provider',
          providerLagSeconds: 3600,
          lastEventAgeSeconds: 120,
        },
        {
          source: 'wazuh',
          state: 'unknown',
          reason: 'no_collector_heartbeat',
          providerLagSeconds: null,
          lastEventAgeSeconds: null,
        },
      ],
    });
    expect(state.label).toBe('Cobertura incompleta');
    expect(state.tone).toBe('warn');
    expect(state.details).toEqual([
      'Microsoft 365: el colector va atrasado respecto del proveedor (1 h)',
      'wazuh: no verificada: el colector no reportó su estado',
    ]);
    expect(JSON.stringify(state)).not.toMatch(/sin actividad/i);
  });

  it('treats unknown-only coverage as incomplete but not as a warning', () => {
    const state = describeSourceCoverage({
      complete: false,
      sources: [
        {
          source: 'snyk',
          state: 'unknown',
          reason: null,
          providerLagSeconds: null,
          lastEventAgeSeconds: null,
        },
      ],
    });
    expect(state).toEqual({
      label: 'Cobertura incompleta',
      tone: 'neutral',
      details: ['Snyk: no verificada'],
    });
  });

  it('distinguishes complete, no sources and older correlators', () => {
    expect(describeSourceCoverage(undefined).label).toBe('Sin dato de cobertura');
    expect(describeSourceCoverage({ complete: true, sources: [] }).label).toBe(
      'Sin fuentes observadas',
    );
    expect(
      describeSourceCoverage({
        complete: true,
        sources: [
          {
            source: 'aws',
            state: 'complete',
            reason: null,
            providerLagSeconds: 1,
            lastEventAgeSeconds: 1,
          },
        ],
      }),
    ).toMatchObject({ label: 'Completa', tone: 'ok' });
  });
});
