/**
 * Aprendizaje SOC · fase 3 — la escalada llega a una persona; si no llega, el motor se pausa solo.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';
import {
  FINGERPRINT_COMPONENTS,
  type AlertFingerprint,
  type FingerprintComponents,
} from '@b89/detection';

import { createAlert, type Alert } from '../src/alert.js';
import {
  DEFAULT_ENGINE_SETTINGS,
  type EngineContext,
  type EngineSettings,
} from '../src/learning-engine.js';
import {
  capForEngineState,
  checkLearningNoticeDelivery,
  resumeLearningEngine,
} from '../src/learning-engine-state.js';
import {
  evaluateAlertWithLearning,
  revertLearningDecision,
} from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import { LEARNING_SERVICE_ACTOR } from '../src/learning-use-cases.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import type { SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const START = new Date('2026-11-24T15:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const RULE = 'linux-process:100200';
const PATTERN_ID = '0199d000-0000-7000-8000-00000000aaaa';

const COMPONENTS = {
  ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
    string,
    null
  >),
  ruleKey: RULE,
  user: 'svc-backup',
  host: 'agent:042',
} as FingerprintComponents;
const FP: AlertFingerprint = {
  fingerprint: `fp1_${'a'.repeat(64)}`,
  level: 'fine',
  version: '1',
  normalizerVersion: '2',
  ruleKey: RULE,
  components: COMPONENTS,
};
const CONTEXT: EngineContext = {
  criticalAssets: 4,
  privilegedIdentities: 3,
  changeCalendarAckUntil: new Date(START.getTime() + 20 * DAY),
  sourceState: 'healthy',
  samplingKey: Buffer.from('k'.repeat(48)),
};
const ACTIVE: EngineSettings = {
  ...DEFAULT_ENGINE_SETTINGS,
  maxMode: 'active',
  activeRules: new Set([RULE]),
};

let soc: InMemorySoc;
let now: Date;
let deps: SocDependencies;
let counter = 0;

function lead(subjectId: string): Actor {
  return {
    subjectId,
    tenantId: TENANT,
    sessionId: 's',
    roles: ['b89.soc.lead'],
    capabilities: capabilitiesForRoles(['b89.soc.lead']),
  };
}

beforeEach(() => {
  soc = new InMemorySoc();
  now = START;
  let ids = 0;
  deps = {
    unitOfWork: soc,
    clock: { now: () => now },
    ids: { next: () => `0199e700-0000-7000-8000-${(ids += 1).toString().padStart(12, '0')}` },
  };
  const pattern: LearningPattern = {
    id: PATTERN_ID,
    tenantId: TENANT,
    ruleKey: RULE,
    fingerprint: FP.fingerprint,
    normalizerVersion: '2',
    level: 'fine',
    components: COMPONENTS,
    maxAction: 'auto_close',
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    status: 'active',
    proposedBy: LEARNING_SERVICE_ACTOR,
    ownerId: 'lead-a',
    originAlertIds: ['0199d000-0000-7000-8000-0000000000o1'],
    originClosers: ['ana'],
    confirmations: 6,
    distinctAlerts: 6,
    distinctDays: 3,
    distinctAnalysts: 3,
    truePositiveSeen: 0,
    priorityCeiling: 'P4',
    readinessBlockers: [],
    createdAt: new Date(START.getTime() - 10 * DAY),
    updatedAt: new Date(START.getTime() - 5 * DAY),
    activatedAt: new Date(START.getTime() - 5 * DAY),
    expiresAt: new Date(START.getTime() + 25 * DAY),
    renewalCount: 0,
    revision: 4,
  };
  soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, pattern);
});

function newAlert(overrides: Partial<Alert> = {}): Alert {
  counter += 1;
  const id = `0199f700-0000-7000-8000-${counter.toString().padStart(12, '0')}`;
  const alert: Alert = {
    ...createAlert({
      id,
      tenantId: TENANT,
      candidateId: id,
      eventRecordId: id,
      title: 'Tarea programada',
      priority: 'P4',
      score: 20,
      reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }],
      occurredAt: START,
      createdAt: START,
      signal: 'other',
    }),
    ...overrides,
  };
  soc.alertRows.set(`${TENANT}|${alert.id}`, alert);
  return alert;
}

const evaluate = (alert: Alert, settings: EngineSettings = ACTIVE, fp: AlertFingerprint = FP) =>
  evaluateAlertWithLearning(
    deps,
    { settings, context: () => CONTEXT },
    {
      tenantId: TENANT,
      alertId: alert.id,
      fingerprint: fp,
      signals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
      correlationId: 'c',
    },
  );

const notices = () =>
  [...soc.outboxRows.values()].filter((message) =>
    String(message.payload['reasonCodes']).startsWith('LEARNING_'),
  );

describe('fase 3 · escalada que llega a una persona', () => {
  it('una escalada con efecto encola un pedido de revisión: WARM para guardas, HOT para deriva', async () => {
    await evaluate(newAlert({ priority: 'P2' }));
    await evaluate(newAlert(), ACTIVE, {
      ...FP,
      fingerprint: `fp1_${'b'.repeat(64)}`,
      components: { ...COMPONENTS, host: 'agent:099' },
    });
    expect(
      notices().map((message) => [
        message.messageType,
        message.payload['reasonCodes'],
        message.payload['urgency'],
      ]),
    ).toEqual([
      ['soc.alert.review_requested', 'LEARNING_GUARD_PRIORITY', 'digest'],
      ['soc.alert.review_requested', 'LEARNING_DRIFT', 'immediate'],
    ]);
  });

  it('en sombra no se avisa a nadie (no hay efecto)', async () => {
    await evaluate(newAlert({ priority: 'P2' }), { ...ACTIVE, activeRules: new Set() });
    expect(notices()).toEqual([]);
  });

  it('una ráfaga de la misma escalada en la misma hora comparte grupo (un aviso agrupado)', async () => {
    await evaluate(newAlert({ priority: 'P2' }));
    await evaluate(newAlert({ priority: 'P2' }));
    const groups = new Set(notices().map((message) => message.payload['groupKey']));
    expect(groups.size).toBe(1);
  });

  it('pausa por tope y reversión avisan en caliente', async () => {
    const first = newAlert();
    const evaluated = await evaluate(first);
    const decisionId = evaluated.ok && evaluated.value.recorded ? evaluated.value.decision.id : '';
    await revertLearningDecision(deps, {
      actor: {
        ...lead('beto'),
        roles: ['b89.soc.analyst'],
        capabilities: capabilitiesForRoles(['b89.soc.analyst']),
      },
      decisionId,
      reason: 'No correspondía cerrar esta alerta.',
      correlationId: 'c',
    });
    expect(notices().map((message) => message.payload['reasonCodes'])).toContain(
      'LEARNING_REVERSAL',
    );
    expect(
      notices().find((message) => message.payload['reasonCodes'] === 'LEARNING_REVERSAL')?.payload[
        'urgency'
      ],
    ).toBe('immediate');
  });

  it('si un aviso HOT no se entrega en 2 min, el motor se pausa solo y queda en sombra', async () => {
    await evaluate(newAlert(), ACTIVE, {
      ...FP,
      fingerprint: `fp1_${'c'.repeat(64)}`,
      components: { ...COMPONENTS, host: 'agent:099' },
    });
    now = new Date(START.getTime() + 60_000);
    expect(await checkLearningNoticeDelivery(deps, soc, TENANT)).toMatchObject({ paused: false });
    now = new Date(START.getTime() + 3 * 60_000);
    expect(await checkLearningNoticeDelivery(deps, soc, TENANT)).toMatchObject({
      paused: true,
      hot: 1,
    });
    const state = await soc.learningEngineState(TENANT);
    expect(state).toMatchObject({ paused: true, reason: 'NOTIFICATION_UNDELIVERED' });
    expect(capForEngineState(ACTIVE, state).maxMode).toBe('shadow');
    // Pausado, una alerta que antes se cerraba ahora solo se registra.
    const after = newAlert();
    await evaluate(after, capForEngineState(ACTIVE, state));
    expect(soc.alertRows.get(`${TENANT}|${after.id}`)?.status).toBe('new');
  });

  it('reanudar exige un aprobador designado con comentario; el servicio no puede', async () => {
    soc.engineStateRows.set(TENANT, {
      tenantId: TENANT,
      paused: true,
      reason: 'NOTIFICATION_UNDELIVERED',
      since: START,
      revision: 1,
    });
    const approvers = ['lead-a', 'lead-b'];
    expect(
      await resumeLearningEngine(deps, {
        actor: lead('intruso'),
        designatedApprovers: approvers,
        comment: 'Canal revisado y entregando.',
        correlationId: 'c',
      }),
    ).toMatchObject({ ok: false, reason: 'NOT_A_DESIGNATED_APPROVER' });
    expect(
      await resumeLearningEngine(deps, {
        actor: { ...lead(LEARNING_SERVICE_ACTOR) },
        designatedApprovers: [...approvers, LEARNING_SERVICE_ACTOR],
        comment: 'Me reanudo a mí mismo.',
        correlationId: 'c',
      }),
    ).toMatchObject({ ok: false, reason: 'SERVICE_IDENTITY' });
    expect(
      await resumeLearningEngine(deps, {
        actor: lead('lead-a'),
        designatedApprovers: approvers,
        comment: 'Canal revisado y entregando.',
        correlationId: 'c',
      }),
    ).toMatchObject({ ok: true, value: { paused: false } });
  });
});
