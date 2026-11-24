/**
 * Aprendizaje SOC · etapa E — revisión adversarial del motor (docs/soc-learning/22-verificacion-motor.md).
 *
 * Cada hallazgo de la revisión es una prueba: rutas donde un fallo, un dato ausente, el reloj o un
 * reintento podrían terminar en cierre, y lo que la cuenta `svc:b89-soc-learning` no puede hacer.
 * En memoria; la concurrencia real está en `learning-postgres.integration.spec.ts`.
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
  evaluateAlertWithLearning,
  resolveLearningReview,
  revertLearningDecision,
} from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import {
  approveLearningPattern,
  LEARNING_SERVICE_ACTOR,
  refreshLearningPatterns,
  rejectLearningPattern,
  renewLearningPattern,
  resumeLearningPattern,
  revokeLearningPattern,
} from '../src/learning-use-cases.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import type { SocTransactionContext, SocUnitOfWork } from '../src/ports.js';
import { executeAlertCommand, type SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const NOW = new Date('2026-11-24T15:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const RULE = 'linux-process:100200';
const FP = `fp1_${'a'.repeat(64)}`;
const PATTERN_ID = '0199d000-0000-7000-8000-00000000aaaa';
const APPROVERS = ['lead-a', 'lead-b', 'lead-c', LEARNING_SERVICE_ACTOR];
const ENTITY = 'ent_sintetico_0001';

function components(): FingerprintComponents {
  return {
    ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
      string,
      null
    >),
    ruleKey: RULE,
    user: 'svc-backup',
    host: 'agent:042',
    processImage: 'c:\\program files\\veeam\\agent.exe',
  } as FingerprintComponents;
}

const FINGERPRINT: AlertFingerprint = {
  fingerprint: FP,
  level: 'fine',
  version: '1',
  normalizerVersion: '2',
  ruleKey: RULE,
  components: components(),
};

const SETTINGS: EngineSettings = {
  ...DEFAULT_ENGINE_SETTINGS,
  maxMode: 'active',
  activeRules: new Set([RULE]),
};

const CONTEXT: EngineContext = {
  criticalAssets: 4,
  privilegedIdentities: 3,
  changeCalendarAckUntil: new Date(NOW.getTime() + 20 * DAY),
  sourceState: 'healthy',
  samplingKey: Buffer.from('k'.repeat(48)),
};

function pattern(overrides: Partial<LearningPattern> = {}): LearningPattern {
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
let counter = 0;

beforeEach(() => {
  soc = new InMemorySoc();
  let sequence = 0;
  deps = {
    unitOfWork: soc,
    clock: { now: () => NOW },
    ids: {
      next: () => {
        sequence += 1;
        return `0199e100-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
      },
    },
  };
  soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, pattern());
});

function newAlert(overrides: Partial<Alert> = {}): Alert {
  counter += 1;
  const id = `0199f100-0000-7000-8000-${counter.toString().padStart(12, '0')}`;
  const alert: Alert = {
    ...createAlert({
      id,
      tenantId: TENANT,
      candidateId: id,
      eventRecordId: id,
      title: 'Tarea programada',
      priority: 'P4',
      score: 25,
      reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }],
      occurredAt: new Date(NOW.getTime() - 60_000),
      createdAt: new Date(NOW.getTime() - 30_000),
      signal: 'other',
      entityKeys: ['user:svc-backup'],
      entityRefs: [ENTITY],
    }),
    ...overrides,
  };
  soc.alertRows.set(`${alert.tenantId}|${alert.id}`, alert);
  return alert;
}

function evaluate(alert: Alert, overrides: Partial<SocDependencies> = {}, fp = FINGERPRINT) {
  return evaluateAlertWithLearning(
    { ...deps, ...overrides },
    { settings: SETTINGS, context: () => CONTEXT },
    {
      tenantId: alert.tenantId,
      alertId: alert.id,
      fingerprint: fp,
      signals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
      correlationId: 'corr',
    },
  );
}

const statusOf = (alert: Alert) => soc.alertRows.get(`${alert.tenantId}|${alert.id}`)?.status;

describe('revisión adversarial · reloj, fallos y reintentos', () => {
  it('H1 · el reloj se lee tras el bloqueo: un patrón que vence durante la espera no cierra', async () => {
    // Patrón vigente hasta NOW + 1 s. La «espera del bloqueo» adelanta el reloj 5 s.
    soc.patternRows.set(
      `${TENANT}|${PATTERN_ID}`,
      pattern({ expiresAt: new Date(NOW.getTime() + 1_000) }),
    );
    let current = NOW;
    const slow: SocUnitOfWork = {
      run: <T>(work: (context: SocTransactionContext) => Promise<T>) => {
        current = new Date(NOW.getTime() + 5_000);
        return soc.run(work);
      },
    };
    const alert = newAlert();
    await evaluate(alert, { unitOfWork: slow, clock: { now: () => current } });
    expect(statusOf(alert)).toBe('new');
  });

  it('H2 · una excepción a mitad del efecto revierte todo: ni cierre ni decisión', async () => {
    const alert = newAlert();
    const original = soc.closureRows.push.bind(soc.closureRows);
    soc.closureRows.push = () => {
      throw new Error('fallo simulado de la base');
    };
    await expect(evaluate(alert)).rejects.toThrow(/fallo simulado/u);
    soc.closureRows.push = original;
    expect(statusOf(alert)).toBe('new');
    expect(soc.decisionRows.size).toBe(0);
  });

  it('H3 · la hora del evento (la controla el emisor) no cambia la decisión', async () => {
    const future = newAlert({ occurredAt: new Date(NOW.getTime() + 365 * DAY) });
    const past = newAlert({ occurredAt: new Date(NOW.getTime() - 365 * DAY) });
    await evaluate(future);
    await evaluate(past);
    const actions = [...soc.decisionRows.values()].map((row) => row.appliedAction);
    expect(actions).toEqual(['AUTO_CLOSE', 'AUTO_CLOSE']);
    // Lo que sí cuenta para vigencia y topes es el reloj del servidor.
    expect([...soc.decisionRows.values()].every((row) => row.at.getTime() === NOW.getTime())).toBe(
      true,
    );
  });

  it('H4 · sin rule_key el modo nunca supera la sombra', async () => {
    const alert = newAlert();
    const result = await evaluate(alert, {}, { ...FINGERPRINT, ruleKey: null });
    expect(result).toMatchObject({
      ok: true,
      value: { decision: { mode: 'shadow', appliedAction: 'NONE' } },
    });
    expect(statusOf(alert)).toBe('new');
  });

  it('H5 · reintento tras un cierre: segunda evaluación sin efectos', async () => {
    const alert = newAlert();
    await evaluate(alert);
    const closures = soc.closureRows.length;
    const again = await evaluate(alert);
    expect(again).toMatchObject({
      ok: true,
      value: { recorded: false, reason: 'ALREADY_DECIDED' },
    });
    expect(soc.closureRows.length).toBe(closures);
  });

  it('H6 · una persona reabre por la vía ordinaria un cierre del motor: reversión y pausa', async () => {
    const alert = newAlert();
    await evaluate(alert);
    expect(statusOf(alert)).toBe('closed');
    const closed = soc.alertRows.get(`${TENANT}|${alert.id}`)!;
    const reopened = await executeAlertCommand(deps, {
      actor: actor('ana', 'b89.soc.analyst'),
      alertId: alert.id,
      correlationId: 'corr-reopen',
      command: {
        name: 'reopen',
        expectedRevision: closed.revision,
        note: 'El host cambió de dueño.',
      },
    });
    expect(reopened.ok).toBe(true);
    expect(soc.reversalRows).toEqual([
      expect.objectContaining({ actorId: 'ana', reopened: true, patternId: PATTERN_ID }),
    ]);
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('paused');
  });

  it('H6 · reabrir un cierre humano no toca patrones ni reversiones', async () => {
    const alert = newAlert({
      status: 'closed',
      verdict: 'false_positive',
      closureOrigin: 'human',
      closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
      closedBy: 'ana',
      closedAt: NOW,
    });
    const reopened = await executeAlertCommand(deps, {
      actor: actor('beto', 'b89.soc.analyst'),
      alertId: alert.id,
      correlationId: 'c',
      command: { name: 'reopen', expectedRevision: alert.revision },
    });
    expect(reopened.ok).toBe(true);
    expect(soc.reversalRows).toEqual([]);
    expect(soc.patternRows.get(`${TENANT}|${PATTERN_ID}`)?.status).toBe('active');
  });
});

describe('cuenta svc:b89-soc-learning', () => {
  /** El servicio con las capabilities de un líder: las negativas vienen de la regla, no del rol. */
  const service: Actor = { ...actor(LEARNING_SERVICE_ACTOR), sessionId: 'system' };
  const request = (target: LearningPattern) => ({
    actor: service,
    patternId: target.id,
    expectedRevision: target.revision,
    comment: 'Intento del servicio de firmar.',
    designatedApprovers: APPROVERS,
    correlationId: 'c',
  });

  it('no aprueba, no rechaza, no revoca, no reanuda ni renueva patrones', async () => {
    const candidate = pattern({ status: 'candidate', proposedBy: 'lead-z' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, candidate);
    expect(await approveLearningPattern(deps, request(candidate))).toMatchObject({ ok: false });
    expect(await rejectLearningPattern(deps, request(candidate))).toMatchObject({ ok: false });
    expect(await revokeLearningPattern(deps, request(candidate))).toMatchObject({ ok: false });
    const paused = pattern({ status: 'paused' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, paused);
    expect(await resumeLearningPattern(deps, request(paused))).toMatchObject({
      ok: false,
      reason: 'SERVICE_IDENTITY',
    });
    const expired = pattern({ status: 'expired' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, expired);
    expect(await renewLearningPattern(deps, request(expired))).toMatchObject({
      ok: false,
      reason: 'SERVICE_IDENTITY',
    });
    expect(soc.approvalRows).toEqual([]);
  });

  it('sin capabilities (como corre de verdad) ni siquiera pasa la autorización', async () => {
    const candidate = pattern({ status: 'candidate', proposedBy: 'lead-z' });
    soc.patternRows.set(`${TENANT}|${PATTERN_ID}`, candidate);
    const bare: Actor = { ...service, roles: [], capabilities: new Set() };
    expect(
      await approveLearningPattern(deps, { ...request(candidate), actor: bare }),
    ).toMatchObject({ ok: false, code: 'FORBIDDEN' });
  });

  it('no resuelve revisiones ni revierte decisiones', async () => {
    const alert = newAlert();
    const evaluated = await evaluate(alert);
    const decisionId = evaluated.ok && evaluated.value.recorded ? evaluated.value.decision.id : '';
    expect(
      await revertLearningDecision(deps, {
        actor: service,
        decisionId,
        reason: 'reversión del servicio',
        correlationId: 'c',
      }),
    ).toMatchObject({ ok: false, reason: 'SERVICE_IDENTITY' });
    soc.reviewRows.set(`${TENANT}|rev-1`, {
      id: 'rev-1',
      tenantId: TENANT,
      decisionId,
      alertId: alert.id,
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
    expect(
      await resolveLearningReview(deps, {
        actor: service,
        reviewId: 'rev-1',
        expectedRevision: 1,
        outcome: 'agree',
        truePositive: false,
        comment: 'El servicio se revisa a sí mismo.',
        correlationId: 'c',
      }),
    ).toMatchObject({ ok: false, reason: 'SERVICE_IDENTITY' });
  });

  it('nunca cierra P1/P2 ni clases de alto impacto (ver también contrato B1/B6)', async () => {
    for (const overrides of [
      { priority: 'P1' as const },
      { priority: 'P2' as const },
      { signal: 'exfiltration' as const },
    ]) {
      const alert = newAlert(overrides);
      await evaluate(alert);
      expect(statusOf(alert)).not.toBe('closed');
    }
  });

  it('sus cierres no cuentan como evidencia por ninguna ruta de conteo', async () => {
    for (let index = 0; index < 8; index += 1) await evaluate(newAlert());
    expect(soc.closureRows.filter((row) => row.origin === 'learning_engine')).toHaveLength(8);
    // 1. Evidencia de patrones (etapa D).
    expect(
      (await soc.learningEvidence(TENANT, new Date(NOW.getTime() - 90 * DAY))).closures,
    ).toEqual([]);
    // 2. Conteo de falsos positivos por entidad (Analista IA, consola): solo orígenes humanos.
    const stats = await soc.alertStats({ tenantId: TENANT, entityRef: ENTITY });
    expect(stats).toMatchObject({ total: 8, falsePositive: 0 });
    // 3. El refresco no propone un candidato nuevo desde esos cierres.
    soc.patternRows.clear();
    const refreshed = await refreshLearningPatterns(deps, soc, {
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
    expect(refreshed).toMatchObject({ ok: true, value: { candidatesCreated: 0 } });
  });

  it('una reapertura hecha por un servicio no se registra como desacuerdo humano', async () => {
    const alert = newAlert();
    await evaluate(alert);
    const closed = soc.alertRows.get(`${TENANT}|${alert.id}`)!;
    await executeAlertCommand(deps, {
      actor: { ...service, capabilities: capabilitiesForRoles(['b89.soc.lead']) },
      alertId: alert.id,
      correlationId: 'c',
      command: { name: 'reopen', expectedRevision: closed.revision },
    });
    expect(soc.reversalRows).toEqual([]);
  });
});
