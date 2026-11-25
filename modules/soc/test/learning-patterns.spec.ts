/**
 * Aprendizaje SOC · etapa D — patrones de FP con aprobación A / A+B y compuertas de preparación.
 *
 * Lo que se fija aquí: la etapa D nunca activa un patrón por sí misma. Un patrón aprobado solo
 * pasa a `active` cuando todas las precondiciones verificables en ejecución se cumplen, y vuelve
 * a pausarse si alguna deja de cumplirse.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';
import { collidingRuleKeys } from '@b89/detection';

import { createAlert, type Alert } from '../src/alert.js';
import type { AlertClosureRecord, ClosureReason, ClosureOrigin } from '../src/closure.js';
import {
  checkApproval,
  DEFAULT_CANDIDATE_POLICY,
  evaluateEligibility,
  evaluateReadiness,
  nextAutomaticState,
  readinessSnapshotFrom,
  requiresSecondApprover,
  type ClosureEvidence,
  type LearningPattern,
  type ReadinessSnapshot,
} from '../src/learning-pattern.js';
import {
  approveLearningPattern,
  LEARNING_SERVICE_ACTOR,
  refreshLearningPatterns,
  rejectLearningPattern,
} from '../src/learning-use-cases.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import type { SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const NOW = new Date('2026-11-24T15:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const FP = `fp1_${'a'.repeat(64)}`;
const RULE = 'linux-process:100200';
const APPROVERS = ['lead-a', 'lead-b', 'lead-c'];

function daysAgo(days: number, hour = 15): Date {
  return new Date(NOW.getTime() - days * DAY + (hour - 15) * 60 * 60 * 1000);
}

function readySnapshot(overrides: Partial<ReadinessSnapshot> = {}): ReadinessSnapshot {
  return {
    closureReasonRequired: true,
    designatedApprovers: 3,
    closedAlertsWithoutOrigin: 0,
    sourceCoverage: new Map([['linux-process', { fine: 900, total: 1000 }]]),
    collidingRuleKeys: new Set(),
    currentNormalizerVersion: '2',
    ...overrides,
  };
}

function evidence(
  alertId: string,
  actorId: string,
  at: Date,
  extra: Partial<ClosureEvidence> = {},
): ClosureEvidence {
  return {
    alertId,
    actorId,
    at,
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    decisionGroupId: null,
    priority: 'P4',
    ruleKey: RULE,
    fingerprint: FP,
    level: 'fine',
    normalizerVersion: '2',
    ...extra,
  };
}

/** 6 cierres de 3 analistas en 3 días Lima: elegible con la política por defecto. */
const ELIGIBLE: readonly ClosureEvidence[] = [
  evidence('a1', 'ana', daysAgo(1)),
  evidence('a2', 'ana', daysAgo(2)),
  evidence('a3', 'beto', daysAgo(2)),
  evidence('a4', 'beto', daysAgo(3)),
  evidence('a5', 'caro', daysAgo(3)),
  evidence('a6', 'caro', daysAgo(1)),
];

function pattern(overrides: Partial<LearningPattern> = {}): LearningPattern {
  return {
    id: 'p-1',
    tenantId: TENANT,
    ruleKey: RULE,
    fingerprint: FP,
    normalizerVersion: '2',
    level: 'fine',
    maxAction: 'auto_close',
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    status: 'candidate',
    proposedBy: LEARNING_SERVICE_ACTOR,
    ownerId: null,
    originAlertIds: ['a1', 'a2'],
    originClosers: ['ana', 'beto'],
    confirmations: 6,
    distinctAlerts: 6,
    distinctDays: 3,
    distinctAnalysts: 3,
    truePositiveSeen: 0,
    priorityCeiling: 'P4',
    readinessBlockers: [],
    createdAt: NOW,
    updatedAt: NOW,
    activatedAt: null,
    expiresAt: null,
    renewalCount: 0,
    revision: 1,
    ...overrides,
  };
}

describe('etapa D · elegibilidad', () => {
  it('es elegible con evidencia humana suficiente y sin TP', () => {
    const result = evaluateEligibility(ELIGIBLE, 0, NOW, DEFAULT_CANDIDATE_POLICY);
    expect(result.missing).toEqual([]);
    expect(result.eligible).toBe(true);
    expect(result.distinctAnalysts).toBe(3);
  });

  it('un solo analista nunca basta, por muchas alertas que cierre', () => {
    const solo = Array.from({ length: 10 }, (_, index) =>
      evidence(`s${index}`, 'ana', daysAgo(index % 4)),
    );
    expect(evaluateEligibility(solo, 0, NOW, DEFAULT_CANDIDATE_POLICY).eligible).toBe(false);
  });

  it('un TP_REAL en la huella impide la elegibilidad', () => {
    expect(evaluateEligibility(ELIGIBLE, 1, NOW, DEFAULT_CANDIDATE_POLICY).eligible).toBe(false);
  });

  it('un cierre en bloque cuenta como una sola confirmación', () => {
    const bulk = ELIGIBLE.map((row) => ({ ...row, decisionGroupId: 'bulk-1' }));
    expect(evaluateEligibility(bulk, 0, NOW, DEFAULT_CANDIDATE_POLICY).eligible).toBe(false);
  });

  it('la evidencia fuera de la ventana no cuenta', () => {
    const old = ELIGIBLE.map((row) => ({ ...row, at: new Date(row.at.getTime() - 40 * DAY) }));
    expect(evaluateEligibility(old, 0, NOW, DEFAULT_CANDIDATE_POLICY).eligible).toBe(false);
  });
});

describe('etapa D · aprobación A / A+B y separación de funciones', () => {
  it('P4 con acción demote: basta una firma (A)', () => {
    const p = pattern({ maxAction: 'demote' });
    expect(requiresSecondApprover(p)).toBe(false);
    expect(checkApproval(p, 'lead-a', APPROVERS, null)).toEqual({
      ok: true,
      stage: 'first',
      next: 'approved',
    });
  });

  it('primera activación de autocierre o prioridad P1–P3: exige segunda firma (A+B)', () => {
    expect(requiresSecondApprover(pattern())).toBe(true);
    expect(requiresSecondApprover(pattern({ maxAction: 'demote', priorityCeiling: 'P3' }))).toBe(
      true,
    );
    expect(checkApproval(pattern(), 'lead-a', APPROVERS, null)).toMatchObject({
      next: 'pending_second_approval',
    });
  });

  it('rechaza servicio, no designado, quien cerró alertas de origen y la misma persona dos veces', () => {
    expect(
      checkApproval(pattern(), 'svc:b89-ai-analyst', [...APPROVERS, 'svc:b89-ai-analyst'], null),
    ).toEqual({
      ok: false,
      code: 'SERVICE_IDENTITY',
    });
    expect(checkApproval(pattern(), 'intruso', APPROVERS, null)).toEqual({
      ok: false,
      code: 'NOT_A_DESIGNATED_APPROVER',
    });
    expect(checkApproval(pattern(), 'ana', ['ana', ...APPROVERS], null)).toEqual({
      ok: false,
      code: 'APPROVER_CLOSED_ORIGIN_ALERTS',
    });
    const pending = pattern({ status: 'pending_second_approval' });
    expect(checkApproval(pending, 'lead-a', APPROVERS, 'lead-a')).toEqual({
      ok: false,
      code: 'SAME_APPROVER_TWICE',
    });
    expect(checkApproval(pending, 'lead-b', APPROVERS, 'lead-a')).toEqual({
      ok: true,
      stage: 'second',
      next: 'approved',
    });
  });
});

describe('etapa D · compuertas de preparación (precondiciones en ejecución)', () => {
  it('sin bloqueos cuando todo se cumple', () => {
    expect(evaluateReadiness(pattern(), readySnapshot())).toEqual([]);
  });

  it.each([
    ['CLOSURE_REASON_NOT_REQUIRED', { closureReasonRequired: false }],
    ['APPROVERS_NOT_CONFIGURED', { designatedApprovers: 1 }],
    ['BACKFILL_PENDING', { closedAlertsWithoutOrigin: 3 }],
    [
      'SOURCE_COVERAGE_UNMEASURED',
      { sourceCoverage: new Map([['linux-process', { fine: 50, total: 60 }]]) },
    ],
    [
      'SOURCE_COVERAGE_BELOW_THRESHOLD',
      { sourceCoverage: new Map([['linux-process', { fine: 100, total: 1000 }]]) },
    ],
    ['RULE_ID_COLLISION', { collidingRuleKeys: new Set([RULE]) }],
    ['NORMALIZER_OUTDATED', { currentNormalizerVersion: '3' }],
  ] as const)('%s bloquea', (blocker, overrides) => {
    expect(evaluateReadiness(pattern(), readySnapshot(overrides))).toContain(blocker);
  });

  it('la lista de colisiones de @b89/detection está vacía y ya no bloquea las reglas 1018xx', () => {
    // Hasta 2026-11-25 el monitor de plataforma reutilizaba 42 IDs 1018xx (renumerado a 1021xx).
    // El bloqueo en sí lo cubre el caso RULE_ID_COLLISION de arriba.
    const keys = collidingRuleKeys();
    expect([...keys]).toEqual([]);
    expect(
      evaluateReadiness(
        pattern({ ruleKey: 'network:101830' }),
        readySnapshot({ collidingRuleKeys: keys }),
      ),
    ).not.toContain('RULE_ID_COLLISION');
  });

  it('solo cuentan aprobadores humanos distintos', () => {
    const snapshot = readinessSnapshotFrom({
      closureReasonRequired: true,
      approvers: ['lead-a', ' lead-a ', 'svc:b89-soc-learning', ''],
      closedAlertsWithoutOrigin: 0,
      sourceCoverage: new Map(),
      collidingRuleKeys: new Set(),
      currentNormalizerVersion: '2',
    });
    expect(snapshot.designatedApprovers).toBe(1);
  });

  it('un aprobado con bloqueos no se activa; sin bloqueos sí', () => {
    const approved = pattern({ status: 'approved' });
    const context = { now: NOW, truePositives: 0, currentNormalizerVersion: '2' };
    expect(
      nextAutomaticState(approved, { ...context, blockers: ['BACKFILL_PENDING'] }),
    ).toBeUndefined();
    expect(nextAutomaticState(approved, { ...context, blockers: [] })).toEqual({
      status: 'active',
      reason: 'READINESS_PASSED',
    });
  });

  it('un candidato o pendiente nunca se activa solo, aunque no haya bloqueos', () => {
    const context = { now: NOW, truePositives: 0, blockers: [], currentNormalizerVersion: '2' };
    expect(nextAutomaticState(pattern(), context)).toBeUndefined();
    expect(
      nextAutomaticState(pattern({ status: 'pending_second_approval' }), context),
    ).toBeUndefined();
  });

  it('un activo se pausa si una precondición deja de cumplirse (fail-closed)', () => {
    const active = pattern({
      status: 'active',
      activatedAt: NOW,
      expiresAt: new Date(NOW.getTime() + DAY),
    });
    expect(
      nextAutomaticState(active, {
        now: NOW,
        truePositives: 0,
        blockers: ['APPROVERS_NOT_CONFIGURED'],
        currentNormalizerVersion: '2',
      }),
    ).toEqual({ status: 'paused', reason: 'READINESS_REGRESSED' });
  });

  it('TP pausa un activo y revoca uno no activo; vencido expira; normalizador nuevo reemplaza', () => {
    const base = { now: NOW, blockers: [], currentNormalizerVersion: '2' };
    const active = pattern({ status: 'active', activatedAt: daysAgo(31), expiresAt: daysAgo(1) });
    expect(nextAutomaticState(active, { ...base, truePositives: 1 })).toMatchObject({
      status: 'paused',
    });
    expect(nextAutomaticState(pattern(), { ...base, truePositives: 1 })).toMatchObject({
      status: 'revoked',
    });
    expect(nextAutomaticState(active, { ...base, truePositives: 0 })).toMatchObject({
      status: 'expired',
    });
    expect(
      nextAutomaticState(pattern(), { ...base, truePositives: 0, currentNormalizerVersion: '3' }),
    ).toMatchObject({
      status: 'superseded',
    });
  });
});

/* ------------------------------------------------------- Casos de uso en memoria */

function lead(subjectId: string): Actor {
  return {
    subjectId,
    tenantId: TENANT,
    sessionId: `sess-${subjectId}`,
    roles: ['b89.soc.lead'],
    capabilities: capabilitiesForRoles(['b89.soc.lead']),
  };
}

function seedClosure(
  soc: InMemorySoc,
  alertId: string,
  actorId: string,
  at: Date,
  reason: ClosureReason = 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
  origin: ClosureOrigin = 'human',
): void {
  const alert: Alert = {
    ...createAlert({
      id: alertId,
      tenantId: TENANT,
      candidateId: `cand-${alertId}`,
      eventRecordId: `rec-${alertId}`,
      title: 'Tarea programada',
      priority: 'P4',
      score: 20,
      reasons: [],
      occurredAt: at,
      createdAt: at,
    }),
    status: 'closed',
    closureReason: reason,
    closureOrigin: origin,
    closedBy: actorId,
    closedAt: at,
  };
  soc.alertRows.set(`${TENANT}|${alertId}`, alert);
  soc.fingerprintRows.set(`${TENANT}|${alertId}`, {
    alertId,
    tenantId: TENANT,
    fingerprint: FP,
    level: 'fine',
    version: '1',
    normalizerVersion: '2',
    ruleKey: RULE,
    components: {},
    computedAt: at,
  });
  const record: AlertClosureRecord = {
    id: `close-${alertId}`,
    tenantId: TENANT,
    alertId,
    kind: 'close',
    verdict: reason === 'TP_REAL' ? 'true_positive' : 'false_positive',
    closureReason: reason,
    origin,
    actorId,
    justification: null,
    evidenceRefs: [],
    decisionGroupId: null,
    correlationId: 'corr',
    at,
  };
  soc.closureRows.push(record);
}

describe('etapa D · ciclo completo en memoria', () => {
  let soc: InMemorySoc;
  let deps: SocDependencies;

  beforeEach(() => {
    soc = new InMemorySoc();
    let sequence = 0;
    deps = {
      unitOfWork: soc,
      clock: { now: () => NOW },
      ids: {
        next: () => {
          sequence += 1;
          return `0199bf22-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
        },
      },
    };
    for (const row of ELIGIBLE) seedClosure(soc, row.alertId, row.actorId, row.at);
  });

  async function refresh(snapshot: ReadinessSnapshot) {
    const result = await refreshLearningPatterns(deps, soc, {
      tenantId: TENANT,
      readiness: snapshot,
      correlationId: 'corr-refresh',
    });
    if (!result.ok) throw new Error(result.code);
    return result.value;
  }

  function only(): LearningPattern {
    const rows = [...soc.patternRows.values()];
    expect(rows).toHaveLength(1);
    return rows[0]!;
  }

  async function approve(subjectId: string) {
    const current = only();
    return approveLearningPattern(deps, {
      actor: lead(subjectId),
      patternId: current.id,
      expectedRevision: current.revision,
      comment: 'Revisado con el dueño del proceso de respaldo.',
      designatedApprovers: APPROVERS,
      correlationId: `corr-${subjectId}`,
    });
  }

  it('propone, exige A+B y solo activa cuando las compuertas pasan', async () => {
    const blocked = readySnapshot({ closureReasonRequired: false, designatedApprovers: 0 });
    expect((await refresh(blocked)).candidatesCreated).toBe(1);
    expect(only()).toMatchObject({ status: 'candidate', proposedBy: LEARNING_SERVICE_ACTOR });

    expect((await approve('lead-a')).ok).toBe(true);
    expect(only().status).toBe('pending_second_approval');
    const again = await approve('lead-a');
    expect(again).toMatchObject({ ok: false, code: 'FORBIDDEN', reason: 'SAME_APPROVER_TWICE' });
    expect((await approve('lead-b')).ok).toBe(true);
    expect(only().status).toBe('approved');

    // Aprobado pero con precondiciones sin cumplir: la etapa D no lo activa.
    const summary = await refresh(blocked);
    expect(only().status).toBe('approved');
    expect(only().readinessBlockers).toEqual([
      'CLOSURE_REASON_NOT_REQUIRED',
      'APPROVERS_NOT_CONFIGURED',
    ]);
    expect(summary.blockedApproved).toHaveLength(1);

    await refresh(readySnapshot());
    const active = only();
    expect(active.status).toBe('active');
    expect(active.readinessBlockers).toEqual([]);
    expect(active.expiresAt?.getTime()).toBe(NOW.getTime() + 30 * DAY);

    // Si una precondición retrocede, se pausa.
    await refresh(readySnapshot({ closedAlertsWithoutOrigin: 1 }));
    expect(only()).toMatchObject({ status: 'paused', readinessBlockers: ['BACKFILL_PENDING'] });

    const events = soc.patternEventRows.map((row) => `${row.from ?? '-'}>${row.to}`);
    expect(events).toEqual([
      '->candidate',
      'candidate>pending_second_approval',
      'pending_second_approval>approved',
      'approved>active',
      'active>paused',
    ]);
    expect(soc.approvalRows.map((row) => [row.stage, row.approverId])).toEqual([
      ['first', 'lead-a'],
      ['second', 'lead-b'],
    ]);
  });

  it('los cierres de IA o de scripts no proponen patrones', async () => {
    const other = new InMemorySoc();
    for (const row of ELIGIBLE)
      seedClosure(other, row.alertId, `svc:${row.actorId}`, row.at, undefined, 'ai_analyst');
    const result = await refreshLearningPatterns({ ...deps, unitOfWork: other }, other, {
      tenantId: TENANT,
      readiness: readySnapshot(),
      correlationId: 'corr',
    });
    expect(result).toMatchObject({ ok: true, value: { candidatesCreated: 0 } });
  });

  it('un TP_REAL posterior en la huella revoca el candidato', async () => {
    await refresh(readySnapshot());
    seedClosure(soc, 'tp-1', 'beto', daysAgo(0), 'TP_REAL');
    await refresh(readySnapshot());
    expect(only().status).toBe('revoked');
  });

  it('quien cerró alertas de origen no puede firmar; sin capability se deniega y audita', async () => {
    await refresh(readySnapshot());
    const current = only();
    const closer = await approveLearningPattern(deps, {
      actor: lead('ana'),
      patternId: current.id,
      expectedRevision: current.revision,
      comment: 'Lo conozco bien, es nuestro respaldo.',
      designatedApprovers: ['ana', ...APPROVERS],
      correlationId: 'corr',
    });
    expect(closer).toMatchObject({
      ok: false,
      code: 'FORBIDDEN',
      reason: 'APPROVER_CLOSED_ORIGIN_ALERTS',
    });

    const analyst: Actor = {
      ...lead('lead-a'),
      roles: ['b89.soc.analyst'],
      capabilities: capabilitiesForRoles(['b89.soc.analyst']),
    };
    const denied = await approveLearningPattern(deps, {
      actor: analyst,
      patternId: current.id,
      expectedRevision: current.revision,
      comment: 'Intento sin permiso suficiente.',
      designatedApprovers: APPROVERS,
      correlationId: 'corr',
    });
    expect(denied).toMatchObject({ ok: false, code: 'FORBIDDEN' });
    expect(only().status).toBe('candidate');
    expect(soc.approvalRows).toEqual([]);
  });

  it('un aprobador designado puede rechazar; queda revocado y la firma registrada', async () => {
    await refresh(readySnapshot());
    const current = only();
    const result = await rejectLearningPattern(deps, {
      actor: lead('lead-c'),
      patternId: current.id,
      expectedRevision: current.revision,
      comment: 'La legitimidad no está documentada todavía.',
      designatedApprovers: APPROVERS,
      correlationId: 'corr',
    });
    expect(result.ok).toBe(true);
    expect(only().status).toBe('revoked');
    expect(soc.approvalRows.map((row) => row.decision)).toEqual(['reject']);
  });
});
