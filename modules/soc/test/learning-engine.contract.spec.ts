/**
 * Aprendizaje SOC · etapa E — contrato de canarios contra el motor real (en memoria).
 * Casos de docs/soc-learning/16-contrato-canarios-motor.md. Cada caso cambia una sola cosa de la
 * fixture base y verifica decisión, efectos y registro.
 *
 * Invariante global: ningún caso «no autocierra» termina con la alerta `closed`.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';
import {
  FINGERPRINT_COMPONENTS,
  type AlertFingerprint,
  type FingerprintComponents,
  type GuardSignals,
  type Reason,
} from '@b89/detection';

import { createAlert, type Alert } from '../src/alert.js';
import {
  DEFAULT_ENGINE_SETTINGS,
  isSampled,
  type EngineContext,
  type EngineSettings,
} from '../src/learning-engine.js';
import {
  evaluateAlertWithLearning,
  resolveLearningReview,
  revertLearningDecision,
} from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import {
  LEARNING_SERVICE_ACTOR,
  refreshLearningPatterns,
  renewLearningPattern,
  resumeLearningPattern,
} from '../src/learning-use-cases.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import type { LearningDecisionRecord } from '../src/ports.js';
import type { SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const NOW = new Date('2026-11-24T15:00:00.000Z');
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const RULE = 'linux-process:100200';
const FP = `fp1_${'a'.repeat(64)}`;
const PATTERN_ID = '0199d000-0000-7000-8000-00000000aaaa';
const KEY = Buffer.from('k'.repeat(48));
const APPROVERS = ['lead-a', 'lead-b', 'lead-c'];

function components(overrides: Partial<Record<string, string | null>> = {}): FingerprintComponents {
  const base: Record<string, string | null> = Object.fromEntries(
    FINGERPRINT_COMPONENTS.map((name) => [name, null]),
  );
  return {
    ...base,
    ruleKey: RULE,
    ruleName: 'tarea programada',
    user: 'svc-backup',
    host: 'agent:042',
    processImage: 'c:\\program files\\veeam\\agent.exe',
    parentImage: 'c:\\windows\\system32\\svchost.exe',
    commandLine: 'agent.exe --job nightly',
    sha256: 'ab'.repeat(32),
    destination: 'backup.b89.io',
    destinationPort: '443',
    ...overrides,
  } as FingerprintComponents;
}

function fingerprint(overrides: Partial<AlertFingerprint> = {}): AlertFingerprint {
  return {
    fingerprint: FP,
    level: 'fine',
    version: '1',
    normalizerVersion: '2',
    ruleKey: RULE,
    components: components(),
    ...overrides,
  };
}

const SIGNALS: GuardSignals = {
  severity: 'low',
  mitreTactics: ['execution'],
  threatIntelHit: false,
};

const SETTINGS: EngineSettings = {
  ...DEFAULT_ENGINE_SETTINGS,
  maxMode: 'active',
  activeRules: new Set([RULE]),
  samplingPercent: 10,
  hourlyCap: 10,
  dailyCap: 30,
  forcedReviewAfter: 20,
};

const CONTEXT: EngineContext = {
  criticalAssets: 42,
  privilegedIdentities: 12,
  changeCalendarAckUntil: new Date(NOW.getTime() + 20 * DAY),
  sourceState: 'healthy',
  samplingKey: KEY,
};

function activePattern(overrides: Partial<LearningPattern> = {}): LearningPattern {
  return {
    id: PATTERN_ID,
    tenantId: TENANT,
    ruleKey: RULE,
    fingerprint: FP,
    normalizerVersion: '2',
    level: 'fine',
    components: components(),
    maxAction: 'auto_close',
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    status: 'active',
    proposedBy: LEARNING_SERVICE_ACTOR,
    ownerId: 'lead-a',
    originAlertIds: ['0199d000-0000-7000-8000-0000000000o1'],
    originClosers: ['ana', 'beto'],
    confirmations: 6,
    distinctAlerts: 6,
    distinctDays: 3,
    distinctAnalysts: 3,
    truePositiveSeen: 0,
    priorityCeiling: 'P4',
    readinessBlockers: [],
    createdAt: new Date(NOW.getTime() - 10 * DAY),
    updatedAt: new Date(NOW.getTime() - 5 * DAY),
    activatedAt: new Date(NOW.getTime() - 5 * DAY),
    expiresAt: new Date(NOW.getTime() + 25 * DAY),
    renewalCount: 0,
    revision: 4,
    ...overrides,
  };
}

function actor(subjectId: string, role = 'b89.soc.lead'): Actor {
  return {
    subjectId,
    tenantId: TENANT,
    sessionId: `sess-${subjectId}`,
    roles: [role],
    capabilities: capabilitiesForRoles([role]),
  };
}

let soc: InMemorySoc;
let deps: SocDependencies;
let sequence: number;

beforeEach(() => {
  soc = new InMemorySoc();
  sequence = 0;
  deps = {
    unitOfWork: soc,
    clock: { now: () => NOW },
    ids: {
      next: () => {
        sequence += 1;
        return `0199e000-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
      },
    },
  };
  soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, activePattern());
  for (const approver of ['lead-a', 'lead-b']) {
    soc.approvalRows.push({
      id: `ap-${approver}`,
      tenantId: TENANT,
      patternId: PATTERN_ID,
      patternRevision: approver === 'lead-a' ? 1 : 2,
      stage: approver === 'lead-a' ? 'first' : 'second',
      approverId: approver,
      decision: 'approve',
      comment: 'Revisado con el dueño del proceso.',
      at: new Date(NOW.getTime() - 6 * DAY),
    });
  }
});

let alertCounter = 0;
function newAlert(overrides: Partial<Alert> = {}, reasons: readonly Reason[] = []): Alert {
  alertCounter += 1;
  const id = `0199f000-0000-7000-8000-${alertCounter.toString().padStart(12, '0')}`;
  const alert: Alert = {
    ...createAlert({
      id,
      tenantId: TENANT,
      candidateId: id,
      eventRecordId: id,
      title: 'Tarea programada de respaldo',
      priority: 'P4',
      score: 25,
      reasons: [
        { code: 'BASE_SEVERITY', delta: 20, detail: 'Severidad normalizada low.' },
        ...reasons,
      ],
      occurredAt: new Date(NOW.getTime() - 60_000),
      createdAt: new Date(NOW.getTime() - 30_000),
      signal: 'other',
    }),
    ...overrides,
  };
  soc.alertRows.set(`${alert.tenantId}|${alert.id}`, alert);
  return alert;
}

interface Run {
  readonly decision: LearningDecisionRecord | undefined;
  readonly alert: Alert;
  readonly closed: boolean;
}

async function run(
  options: {
    readonly alert?: Partial<Alert>;
    readonly reasons?: readonly Reason[];
    readonly fp?: Partial<AlertFingerprint>;
    readonly signals?: GuardSignals | undefined;
    readonly settings?: Partial<EngineSettings>;
    readonly context?: Partial<EngineContext>;
  } = {},
): Promise<Run> {
  const alert = newAlert(options.alert, options.reasons);
  const result = await evaluateAlertWithLearning(
    deps,
    {
      settings: { ...SETTINGS, ...options.settings },
      context: () => ({ ...CONTEXT, ...options.context }),
    },
    {
      tenantId: alert.tenantId,
      alertId: alert.id,
      fingerprint: fingerprint(options.fp),
      signals: 'signals' in options ? options.signals : SIGNALS,
      correlationId: 'corr-engine',
    },
  );
  if (!result.ok) throw new Error(result.code);
  const after = soc.alertRows.get(`${alert.tenantId}|${alert.id}`)!;
  return {
    decision: result.value.recorded ? result.value.decision : undefined,
    alert: after,
    closed: result.value.recorded ? result.value.closed : false,
  };
}

function expectOpen(result: Run): void {
  expect(result.alert.status).not.toBe('closed');
}

describe('contrato E · base', () => {
  it('fixture base: AUTO_CLOSE como svc:b89-soc-learning con origen learning_engine (D5)', async () => {
    const result = await run();
    expect(result.decision).toMatchObject({
      mode: 'active',
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'AUTO_CLOSE',
    });
    expect(result.alert).toMatchObject({
      status: 'closed',
      closureOrigin: 'learning_engine',
      closedBy: LEARNING_SERVICE_ACTOR,
      closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
      verdict: 'false_positive',
    });
    expect(result.decision?.checks.map((check) => check.id)).toContain('CONTEXT');
    expect(soc.closureRows.at(-1)).toMatchObject({
      origin: 'learning_engine',
      actorId: LEARNING_SERVICE_ACTOR,
    });
    const audit = await soc.auditStore.range(TENANT, 0n, 1000);
    expect(audit.some((event) => event.action === 'learning.decision')).toBe(true);
  });
});

describe('contrato E · A. casi coincidencia (escala con DRIFT)', () => {
  const other = `fp1_${'b'.repeat(64)}`;
  it.each([
    ['A1', 'sha256', 'cd'.repeat(32)],
    ['A2', 'destination', 'evil.example'],
    ['A3', 'destinationPort', '4444'],
    ['A4', 'user', 'otra-cuenta'],
    ['A5', 'host', 'agent:099'],
    ['A6', 'parentImage', 'c:\\windows\\explorer.exe'],
    ['A7', 'commandLine', 'agent.exe --exfil all'],
  ] as const)('%s · otro %s → ESCALATE(DRIFT)', async (_case, component, value) => {
    const result = await run({
      fp: { fingerprint: other, components: components({ [component]: value }) },
    });
    expect(result.decision).toMatchObject({
      proposedAction: 'ESCALATE',
      escalateReason: 'DRIFT',
      patternId: PATTERN_ID,
    });
    expect(Object.keys(result.decision?.drift ?? {})).toEqual([component]);
    expectOpen(result);
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('active');
  });

  it('A8 · mismo temporal normalizado (misma huella) → AUTO_CLOSE', async () => {
    expect((await run()).alert.status).toBe('closed');
  });

  it('A9 · otro tenant → NONE (aislamiento)', async () => {
    const result = await run({ alert: { tenantId: 'tenant-2' } });
    expect(result.decision).toMatchObject({
      proposedAction: 'NONE',
      appliedAction: 'NONE',
      patternId: null,
    });
    expectOpen(result);
  });
});

describe('contrato E · B. guardas sobre la misma huella', () => {
  const reason = (code: Reason['code']): Reason => ({ code, delta: 10, detail: code });
  it.each([
    ['B1 P2', { alert: { priority: 'P2' } }, 'GUARD_PRIORITY'],
    ['B1 P1', { alert: { priority: 'P1' } }, 'GUARD_PRIORITY'],
    ['B3 severidad high', { signals: { ...SIGNALS, severity: 'high' } }, 'GUARD_SEVERITY'],
    ['B4 activo crítico', { reasons: [reason('CRITICAL_ASSET')] }, 'GUARD_CRITICAL_ASSET'],
    ['B5 privilegiada', { reasons: [reason('PRIVILEGED_IDENTITY')] }, 'GUARD_PRIVILEGED'],
    ['B5 break-glass', { reasons: [reason('BREAK_GLASS_IDENTITY')] }, 'GUARD_PRIVILEGED'],
    ['B6 táctica', { signals: { ...SIGNALS, mitreTactics: ['lateral-movement'] } }, 'GUARD_IMPACT'],
    ['B6 never_suppress', { settings: { neverSuppressRules: new Set([RULE]) } }, 'GUARD_IMPACT'],
    ['B6 señal excluida', { alert: { signal: 'credential_access' } }, 'GUARD_IMPACT'],
    ['B7 inteligencia', { signals: { ...SIGNALS, threatIntelHit: true } }, 'GUARD_THREAT_INTEL'],
    ['B8 cadena', { reasons: [reason('ATTACK_CHAIN')] }, 'GUARD_CORRELATION'],
    ['B8 relacionadas', { alert: { relatedAlertIds: ['r1', 'r2', 'r3'] } }, 'GUARD_CORRELATION'],
    [
      'B9 incidente',
      { alert: { incidentId: '0199d000-0000-7000-8000-0000000000c1' } },
      'GUARD_INCIDENT',
    ],
    ['B10 fuente degradada', { context: { sourceState: 'degraded' } }, 'GUARD_SOURCE'],
    ['B10 fuente desconocida', { context: { sourceState: null } }, 'GUARD_SOURCE'],
    ['B10 evidencia incompleta', { signals: undefined }, 'GUARD_SOURCE'],
    ['B11 ventana de cambio', { reasons: [reason('MAINTENANCE_WINDOW')] }, 'GUARD_CHANGE_WINDOW'],
    ['B12 lista vacía', { context: { criticalAssets: 0 } }, 'GUARD_CONTEXT'],
    [
      'B12 calendario vencido',
      { context: { changeCalendarAckUntil: new Date(NOW.getTime() - DAY) } },
      'GUARD_CONTEXT',
    ],
  ] as const)('%s → ESCALATE(%s)', async (_case, options, expected) => {
    const result = await run(options as Parameters<typeof run>[0]);
    expect(result.decision).toMatchObject({ proposedAction: 'ESCALATE', escalateReason: expected });
    expectOpen(result);
    expect(result.alert.priority).toBe(
      (options as { alert?: { priority?: string } }).alert?.priority ?? 'P4',
    );
  });

  it('B2 · P3 → como máximo DEMOTE, nunca AUTO_CLOSE', async () => {
    const result = await run({ alert: { priority: 'P3' } });
    expect(result.decision).toMatchObject({ proposedAction: 'DEMOTE', appliedAction: 'NONE' });
    expectOpen(result);
  });
});

describe('contrato E · C. estado del patrón y de la configuración', () => {
  it('C1 · vencido según el reloj del servidor, aunque la alerta ocurrió antes', async () => {
    soc.patternRows.set(
      `${TENANT}|${PATTERN_ID}`,
      activePattern({ expiresAt: new Date(NOW.getTime() - 1) }),
    );
    const result = await run({ alert: { occurredAt: new Date(NOW.getTime() - 2 * DAY) } });
    expect(result.decision?.checks.find((check) => check.id === 'PATTERN_EXPIRY')?.ok).toBe(false);
    expectOpen(result);
  });

  it.each(['paused', 'revoked'] as const)('C2 · patrón %s → no autocierra', async (status) => {
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, activePattern({ status }));
    expectOpen(await run());
  });

  it('C3 · kill switch global → NONE sin efectos', async () => {
    const result = await run({ settings: { killSwitch: true } });
    expect(result.decision).toMatchObject({ proposedAction: 'NONE', appliedAction: 'NONE' });
    expectOpen(result);
  });

  it('C4 · kill switch de la regla → NONE sin efectos', async () => {
    const result = await run({ settings: { killedRules: new Set([RULE]) } });
    expect(result.decision?.appliedAction).toBe('NONE');
    expectOpen(result);
  });

  it('C5 · regla en sombra → AUTO_CLOSE registrado sin cambio de estado', async () => {
    const result = await run({ settings: { activeRules: new Set() } });
    expect(result.decision).toMatchObject({
      mode: 'shadow',
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'NONE',
    });
    expect(result.alert.status).toBe('new');
  });

  it('modo off → no decide ni registra', async () => {
    const result = await run({ settings: { maxMode: 'off' } });
    expect(result.decision).toBeUndefined();
    expect(soc.decisionRows.size).toBe(0);
  });

  it('C6 · dry_run → revisión dry_run_approval; la alerta sigue abierta y aceptar la cierra', async () => {
    const result = await run({ settings: { maxMode: 'dry_run' } });
    expect(result.decision).toMatchObject({
      mode: 'dry_run',
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'NONE',
    });
    expect(result.alert.status).toBe('new');
    const review = [...soc.reviewRows.values()][0]!;
    expect(review).toMatchObject({ kind: 'dry_run_approval', status: 'pending' });
    const resolved = await resolveLearningReview(deps, {
      actor: actor('ana', 'b89.soc.analyst'),
      reviewId: review.id,
      expectedRevision: review.revision,
      outcome: 'agree',
      truePositive: false,
      comment: 'Coincide con el respaldo nocturno documentado.',
      correlationId: 'corr-review',
    });
    expect(resolved).toMatchObject({ ok: true, value: { status: 'agreed' } });
    expect(soc.alertRows.get(`${TENANT}|${result.alert.id}`)).toMatchObject({
      status: 'closed',
      closureOrigin: 'learning_engine',
    });
  });

  it('C7 · huella coarse idéntica → nunca AUTO_CLOSE', async () => {
    soc.patternRows.set(
      `${TENANT}|${PATTERN_ID}`,
      activePattern({ level: 'coarse', maxAction: 'demote' }),
    );
    const result = await run({ fp: { level: 'coarse' } });
    expect(result.decision?.proposedAction).not.toBe('AUTO_CLOSE');
    expectOpen(result);
  });

  it('C8 · patrón del normalizador v1 y alerta v2 → NONE', async () => {
    soc.patternRows.set(
      `${TENANT}|${PATTERN_ID}`,
      activePattern({ normalizerVersion: '1', fingerprint: `fp1_${'c'.repeat(64)}` }),
    );
    const result = await run();
    expect(result.decision).toMatchObject({ proposedAction: 'NONE', appliedAction: 'NONE' });
    expectOpen(result);
  });

  it('C9 · misma huella con componentes distintos → ESCALATE(FINGERPRINT_COLLISION)', async () => {
    const result = await run({
      fp: { components: components({ processImage: 'c:\\tmp\\x.exe' }) },
    });
    expect(result.decision).toMatchObject({ escalateReason: 'FINGERPRINT_COLLISION' });
    expectOpen(result);
  });

  it('C10 · patrón revocado antes del efecto → no cierra', async () => {
    const alert = newAlert();
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, activePattern({ status: 'revoked' }));
    await evaluateAlertWithLearning(
      deps,
      { settings: SETTINGS, context: () => CONTEXT },
      {
        tenantId: TENANT,
        alertId: alert.id,
        fingerprint: fingerprint(),
        signals: SIGNALS,
        correlationId: 'c',
      },
    );
    expect(soc.alertRows.get(`${TENANT}|${alert.id}`)?.status).toBe('new');
  });

  it('C10 · una persona tocó la alerta antes del efecto → no cierra y queda registrado', async () => {
    const result = await run({ alert: { status: 'acknowledged', assigneeId: 'ana' } });
    expect(result.decision).toMatchObject({
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'ESCALATE',
    });
    expect(result.decision?.checks.find((check) => check.id === 'EFFECT')?.ok).toBe(false);
    expectOpen(result);
  });

  it('una alerta se decide una sola vez', async () => {
    const alert = newAlert();
    const request = {
      tenantId: TENANT,
      alertId: alert.id,
      fingerprint: fingerprint(),
      signals: SIGNALS,
      correlationId: 'c',
    };
    const engine = { settings: SETTINGS, context: () => CONTEXT };
    await evaluateAlertWithLearning(deps, engine, request);
    const second = await evaluateAlertWithLearning(deps, engine, request);
    expect(second).toMatchObject({
      ok: true,
      value: { recorded: false, reason: 'ALREADY_DECIDED' },
    });
    expect(soc.decisionRows.size).toBe(1);
  });
});

describe('contrato E · D. radio de daño, muestreo y trazabilidad', () => {
  function seedCloses(count: number, minutesAgo: number): void {
    for (let index = 0; index < count; index += 1) {
      const id = `0199d900-0000-7000-8000-${(index + minutesAgo * 1000).toString().padStart(12, '0')}`;
      soc.decisionRows.set(`${TENANT}|${id}`, {
        id: `dec-${id}`,
        tenantId: TENANT,
        alertId: id,
        mode: 'active',
        engineVersion: '1.0.0',
        fingerprint: FP,
        level: 'fine',
        ruleKey: RULE,
        patternId: PATTERN_ID,
        proposedAction: 'AUTO_CLOSE',
        appliedAction: 'AUTO_CLOSE',
        escalateReason: null,
        confidence: 'medium',
        checks: [],
        drift: null,
        sampled: false,
        at: new Date(NOW.getTime() - minutesAgo * 60_000),
      });
    }
  }

  it('D1 · por encima del tope diario → a una persona, sin cierre', async () => {
    seedCloses(30, 180);
    const result = await run({ settings: { forcedReviewAfter: 1000 } });
    expect(result.decision?.escalateReason).toBe('DAILY_CAP');
    expectOpen(result);
  });

  it('D2 · N cierres seguidos sin revisión → revisión obligatoria; resolverla reinicia', async () => {
    seedCloses(20, 180);
    const first = await run({ settings: { dailyCap: 1000 } });
    expect(first.decision?.escalateReason).toBe('FORCED_REVIEW');
    expectOpen(first);
    const review = [...soc.reviewRows.values()].find((row) => row.kind === 'forced_review')!;
    await resolveLearningReview(deps, {
      actor: actor('ana', 'b89.soc.analyst'),
      reviewId: review.id,
      expectedRevision: review.revision,
      outcome: 'agree',
      truePositive: false,
      comment: 'Revisadas las últimas veinte: son el respaldo.',
      correlationId: 'c',
    });
    const after = await run({ settings: { dailyCap: 1000 } });
    expect(after.decision?.appliedAction).toBe('AUTO_CLOSE');
  });

  it('D3 · ráfaga por encima del tope por hora → RATE_LIMIT y patrón en pausa', async () => {
    seedCloses(10, 5);
    const result = await run();
    expect(result.decision?.escalateReason).toBe('RATE_LIMIT');
    expectOpen(result);
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('paused');
  });

  it('D4 · alerta seleccionada por la PRF: se cierra y entra a revisión; reproducible', async () => {
    let sampled: Alert | undefined;
    for (let attempt = 0; attempt < 200 && !sampled; attempt += 1) {
      const probe = `0199fa00-0000-7000-8000-${attempt.toString().padStart(12, '0')}`;
      if (isSampled(KEY, probe, 10)) sampled = { id: probe } as Alert;
    }
    expect(sampled).toBeDefined();
    expect(isSampled(KEY, sampled!.id, 10)).toBe(isSampled(KEY, sampled!.id, 10));
    const alert = newAlert({
      id: sampled!.id,
      candidateId: sampled!.id,
      eventRecordId: sampled!.id,
    });
    const result = await evaluateAlertWithLearning(
      deps,
      { settings: SETTINGS, context: () => CONTEXT },
      {
        tenantId: TENANT,
        alertId: alert.id,
        fingerprint: fingerprint(),
        signals: SIGNALS,
        correlationId: 'c',
      },
    );
    expect(result).toMatchObject({
      ok: true,
      value: { closed: true, decision: { sampled: true } },
    });
    expect([...soc.reviewRows.values()].map((row) => row.kind)).toEqual(['quality_sample']);
  });

  it('D5 · un cierre del motor no suma confirmaciones al patrón', async () => {
    await run();
    const evidence = await soc.learningEvidence(TENANT, new Date(NOW.getTime() - 90 * DAY));
    expect(evidence.closures).toEqual([]);
  });

  it('D6 · revisión de muestra con TP → reabre, registra la reversión y pausa el patrón', async () => {
    const result = await run();
    const decision = result.decision!;
    soc.reviewRows.set(`${TENANT}|rev-1`, {
      id: 'rev-1',
      tenantId: TENANT,
      decisionId: decision.id,
      alertId: decision.alertId,
      patternId: PATTERN_ID,
      kind: 'quality_sample',
      status: 'pending',
      reviewerId: null,
      truePositive: null,
      comment: null,
      at: NOW,
      resolvedAt: null,
      revision: 1,
    });
    const resolved = await resolveLearningReview(deps, {
      actor: actor('ana', 'b89.soc.analyst'),
      reviewId: 'rev-1',
      expectedRevision: 1,
      outcome: 'disagree',
      truePositive: true,
      comment: 'El destino no era el respaldo: exfiltración.',
      correlationId: 'c',
    });
    expect(resolved).toMatchObject({
      ok: true,
      value: { status: 'disagreed', truePositive: true },
    });
    expect(soc.alertRows.get(`${TENANT}|${decision.alertId}`)?.status).toBe('acknowledged');
    expect(soc.reversalRows).toHaveLength(1);
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('paused');
  });

  it('D7 · revert sobre un autocierre → acknowledged, reversión registrada, patrón en pausa', async () => {
    const result = await run();
    const reverted = await revertLearningDecision(deps, {
      actor: actor('beto', 'b89.soc.analyst'),
      decisionId: result.decision!.id,
      reason: 'El host cambió de rol esta semana.',
      correlationId: 'c',
    });
    expect(reverted).toMatchObject({ ok: true, value: { reopened: true } });
    expect(soc.alertRows.get(`${TENANT}|${result.alert.id}`)?.status).toBe('acknowledged');
    expect(soc.reversalRows[0]).toMatchObject({ actorId: 'beto', reopened: true });
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('paused');
  });

  it('revertir exige capability; una identidad de servicio no revisa', async () => {
    const result = await run();
    const auditor = await revertLearningDecision(deps, {
      actor: actor('aud', 'b89.auditor'),
      decisionId: result.decision!.id,
      reason: 'Intento sin permiso suficiente.',
      correlationId: 'c',
    });
    expect(auditor).toMatchObject({ ok: false, code: 'FORBIDDEN' });
    expect(soc.alertRows.get(`${TENANT}|${result.alert.id}`)?.status).toBe('closed');
  });
});

describe('etapa D · reanudar y renovar', () => {
  const request = (subjectId: string, pattern: LearningPattern) => ({
    actor: actor(subjectId),
    patternId: pattern.id,
    expectedRevision: pattern.revision,
    comment: 'Causa de la pausa revisada y resuelta.',
    designatedApprovers: APPROVERS,
    correlationId: 'c',
  });

  it('reanudar: paused → approved; las compuertas lo reactivan conservando el vencimiento', async () => {
    const paused = activePattern({ status: 'paused' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, paused);
    // «ana» es aprobadora designada, pero cerró alertas de origen: separación de funciones.
    expect(
      await resumeLearningPattern(deps, {
        ...request('ana', paused),
        designatedApprovers: ['ana', ...APPROVERS],
      }),
    ).toMatchObject({
      ok: false,
      reason: 'APPROVER_CLOSED_ORIGIN_ALERTS',
    });
    expect(await resumeLearningPattern(deps, request('lead-c', paused))).toMatchObject({
      ok: true,
      value: { status: 'approved' },
    });
    await refreshLearningPatterns(deps, soc, {
      tenantId: TENANT,
      correlationId: 'c',
      readiness: {
        closureReasonRequired: true,
        designatedApprovers: 3,
        closedAlertsWithoutOrigin: 0,
        sourceCoverage: new Map([['linux-process', { fine: 900, total: 1000 }]]),
        collidingRuleKeys: new Set(),
        currentNormalizerVersion: '2',
      },
    });
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)).toMatchObject({
      status: 'active',
      expiresAt: paused.expiresAt,
    });
  });

  it('no se reanuda un patrón vencido; un pausado vencido expira al refrescar', async () => {
    const stale = activePattern({ status: 'paused', expiresAt: new Date(NOW.getTime() - DAY) });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, stale);
    expect(await resumeLearningPattern(deps, request('lead-c', stale))).toMatchObject({
      ok: false,
      reason: 'PATTERN_EXPIRED',
    });
  });

  it('renovar: expired → nuevo ciclo A+B (autocierre) con 90 días al activarse', async () => {
    const expired = activePattern({ status: 'expired' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, expired);
    const first = await renewLearningPattern(deps, request('lead-c', expired));
    // P4 + autocierre en renovación: basta una firma (la regla A+B exige la segunda solo la 1.ª vez).
    expect(first).toMatchObject({
      ok: true,
      value: { status: 'approved', renewalCount: 1, expiresAt: null },
    });
    await refreshLearningPatterns(deps, soc, {
      tenantId: TENANT,
      correlationId: 'c',
      readiness: {
        closureReasonRequired: true,
        designatedApprovers: 3,
        closedAlertsWithoutOrigin: 0,
        sourceCoverage: new Map([['linux-process', { fine: 900, total: 1000 }]]),
        collidingRuleKeys: new Set(),
        currentNormalizerVersion: '2',
      },
    });
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.expiresAt?.getTime()).toBe(
      NOW.getTime() + 90 * DAY,
    );
  });

  it('renovar con P3 exige segunda firma', async () => {
    const expired = activePattern({ status: 'expired', priorityCeiling: 'P3' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, expired);
    expect(await renewLearningPattern(deps, request('lead-c', expired))).toMatchObject({
      ok: true,
      value: { status: 'pending_second_approval' },
    });
  });
});
