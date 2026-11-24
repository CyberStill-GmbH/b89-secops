/**
 * Aprendizaje SOC · fase 2 — el motor fuera del camino de la ingesta (cola durable + worker).
 * Contrato en memoria; la carrera real entre workers (`SKIP LOCKED`) está en la spec de PostgreSQL.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import {
  candidateId,
  FINGERPRINT_COMPONENTS,
  promotionKey,
  type AlertFingerprint,
  type DetectionCandidate,
  type FingerprintComponents,
} from '@b89/detection';

import { DEFAULT_ENGINE_SETTINGS, type EngineContext } from '../src/learning-engine.js';
import type { LearningEngineDependencies } from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import { LEARNING_SERVICE_ACTOR } from '../src/learning-use-cases.js';
import {
  DEFAULT_LEARNING_WORKER_POLICY,
  drainLearningQueue,
  errorCode,
} from '../src/learning-worker.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import { ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const RULE = 'linux-process:100200';
const DAY = 24 * 60 * 60 * 1000;
const START = new Date('2026-11-24T15:00:00.000Z');

const COMPONENTS = {
  ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
    string,
    null
  >),
  ruleKey: RULE,
  user: 'svc-backup',
  host: 'agent:042',
} as FingerprintComponents;

const FINGERPRINT: AlertFingerprint = {
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

const SHADOW: LearningEngineDependencies = {
  settings: { ...DEFAULT_ENGINE_SETTINGS, maxMode: 'shadow' },
  context: () => CONTEXT,
};

let soc: InMemorySoc;
let now: Date;
let deps: SocDependencies;
let sequence = 0;

beforeEach(() => {
  soc = new InMemorySoc();
  now = START;
  let ids = 0;
  deps = {
    unitOfWork: soc,
    clock: { now: () => now },
    ids: {
      next: () => {
        ids += 1;
        return `0199e900-0000-7000-8000-${ids.toString().padStart(12, '0')}`;
      },
    },
    learningEnqueue: true,
  };
  const pattern: LearningPattern = {
    id: '0199d000-0000-7000-8000-00000000aaaa',
    tenantId: TENANT,
    ruleKey: RULE,
    fingerprint: FINGERPRINT.fingerprint,
    normalizerVersion: '2',
    level: 'fine',
    components: COMPONENTS,
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
    createdAt: new Date(START.getTime() - 10 * DAY),
    updatedAt: new Date(START.getTime() - 5 * DAY),
    activatedAt: new Date(START.getTime() - 5 * DAY),
    expiresAt: new Date(START.getTime() + 25 * DAY),
    renewalCount: 0,
    revision: 4,
  };
  soc.patternRows.set(`${TENANT}|${pattern.id}`, pattern);
});

function candidate(overrides: Partial<DetectionCandidate> = {}): DetectionCandidate {
  sequence += 1;
  const eventRecordId = `0199e800-0000-7000-8000-${String(sequence).padStart(12, '0')}`;
  const key = promotionKey(TENANT, eventRecordId, '1.1.0');
  return {
    id: candidateId(key, START),
    tenantId: TENANT,
    eventRecordId,
    eventUid: `evt-${sequence}`,
    idempotencyKey: key,
    priority: 'P4',
    score: 20,
    reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }],
    rulesetId: 'b89.detection.prioritization',
    rulesetVersion: '1.1.0',
    occurredAt: START,
    createdAt: START,
    title: 'Tarea programada',
    entityKeys: [],
    signal: 'other',
    ruleId: '100200',
    relatedAlertIds: [],
    fingerprint: FINGERPRINT,
    guardSignals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
    ...overrides,
  };
}

const drain = (engine = SHADOW, policy = DEFAULT_LEARNING_WORKER_POLICY) =>
  drainLearningQueue({
    dependencies: deps,
    queue: soc.learningQueue,
    engine,
    policy,
    workerId: 'worker-1',
    tenantId: TENANT,
  });

describe('fase 2 · cola del motor', () => {
  it('la ingesta encola en la misma transacción; sin la bandera no encola', async () => {
    const created = await ingestCandidate(deps, candidate());
    expect(created.ok).toBe(true);
    expect([...soc.jobRows.values()]).toEqual([
      expect.objectContaining({
        status: 'pending',
        attempts: 0,
        signals: expect.objectContaining({ severity: 'low' }),
      }),
    ]);
    await ingestCandidate({ ...deps, learningEnqueue: false }, candidate());
    expect(soc.jobRows.size).toBe(1);
  });

  it('si la transacción de la ingesta falla, no queda ni alerta ni trabajo', async () => {
    // El outbox (último paso de la ingesta) falla dentro de la transacción.
    const failingOutbox: SocDependencies = {
      ...deps,
      unitOfWork: {
        run: (work) =>
          soc.run((context) =>
            work({
              ...context,
              outbox: {
                enqueueIfAbsent: () => Promise.reject(new Error('fallo simulado del outbox')),
              },
            }),
          ),
      },
    };
    await expect(ingestCandidate(failingOutbox, candidate())).rejects.toThrow(/fallo simulado/u);
    expect(soc.jobRows.size).toBe(0);
    expect(soc.alertRows.size).toBe(0);
  });

  it('una alerta duplicada no encola dos veces', async () => {
    const same = candidate();
    await ingestCandidate(deps, same);
    await ingestCandidate(deps, same);
    expect(soc.jobRows.size).toBe(1);
  });

  it('el worker decide en sombra, marca hecho y deja latido', async () => {
    await ingestCandidate(deps, candidate());
    const summary = await drain();
    expect(summary).toEqual({ claimed: 1, done: 1, retried: 0, dead: 0 });
    expect([...soc.jobRows.values()][0]).toMatchObject({ status: 'done', attempts: 1 });
    expect([...soc.decisionRows.values()][0]).toMatchObject({
      mode: 'shadow',
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'NONE',
    });
    expect(soc.heartbeatRows.get('worker-1')).toMatchObject({
      tenantId: TENANT,
      claimed: 1,
      failed: 0,
    });
  });

  it('un fallo reintenta con espera exponencial y tras el máximo queda en dead-letter', async () => {
    await ingestCandidate(deps, candidate());
    const failing = {
      ...SHADOW,
      context: () => {
        throw Object.assign(new Error('contexto caído'), { code: 'CONTEXT_DOWN' });
      },
    };
    const policy = { ...DEFAULT_LEARNING_WORKER_POLICY, maxAttempts: 3, backoffBaseMs: 1_000 };
    expect(await drain(failing, policy)).toMatchObject({ retried: 1, dead: 0 });
    const job = () => [...soc.jobRows.values()][0]!;
    expect(job()).toMatchObject({ status: 'pending', lastError: 'CONTEXT_DOWN' });
    expect(job().availableAt.getTime()).toBe(START.getTime() + 1_000);
    // Antes de la espera no se reclama.
    expect((await drain(failing, policy)).claimed).toBe(0);
    now = new Date(START.getTime() + 1_000);
    await drain(failing, policy);
    expect(job().availableAt.getTime()).toBe(now.getTime() + 2_000);
    now = new Date(now.getTime() + 2_000);
    expect(await drain(failing, policy)).toMatchObject({ dead: 1 });
    expect(job()).toMatchObject({ status: 'dead', attempts: 3 });
    // La alerta sigue abierta, para una persona.
    expect([...soc.alertRows.values()][0]?.status).toBe('new');
    expect(soc.decisionRows.size).toBe(0);
  });

  it('un tiempo agotado cuenta como fallo; el reintento ve la decisión y termina sin repetirla', async () => {
    await ingestCandidate(deps, candidate());
    const slowOnce = {
      ...SHADOW,
      context: () => CONTEXT,
    };
    const policy = { ...DEFAULT_LEARNING_WORKER_POLICY, timeoutMs: 1, backoffBaseMs: 0 };
    // Unidad de trabajo lenta: la decisión se guarda, pero después del tiempo máximo.
    const slowDeps: SocDependencies = {
      ...deps,
      unitOfWork: {
        run: async (work) => {
          const result = await soc.run(work);
          await new Promise((resolve) => setTimeout(resolve, 20));
          return result;
        },
      },
    };
    const first = await drainLearningQueue({
      dependencies: slowDeps,
      queue: soc.learningQueue,
      engine: slowOnce,
      policy,
      workerId: 'worker-1',
      tenantId: TENANT,
    });
    expect(first).toMatchObject({ retried: 1 });
    expect([...soc.jobRows.values()][0]).toMatchObject({ lastError: 'LEARNING_TIMEOUT' });
    await new Promise((resolve) => setTimeout(resolve, 30));
    const second = await drain(SHADOW, { ...policy, timeoutMs: 5_000 });
    expect(second).toMatchObject({ done: 1 });
    expect(soc.decisionRows.size).toBe(1);
  });

  it('un lease vencido se vuelve a reclamar; el dueño viejo ya no puede cerrar el trabajo', async () => {
    await ingestCandidate(deps, candidate());
    const [stale] = await soc.learningQueue.claim({
      limit: 10,
      leaseMs: 1_000,
      now,
      claimId: 'claim-viejo',
    });
    now = new Date(START.getTime() + 2_000);
    const [fresh] = await soc.learningQueue.claim({
      limit: 10,
      leaseMs: 1_000,
      now,
      claimId: 'claim-nuevo',
    });
    expect(fresh?.attempts).toBe(2);
    expect(await soc.learningQueue.complete(stale!.alertId, 'claim-viejo', now)).toBe(false);
    expect(await soc.learningQueue.complete(fresh!.alertId, 'claim-nuevo', now)).toBe(true);
  });

  it('concurrencia acotada: nunca más trabajos a la vez que el límite', async () => {
    for (let index = 0; index < 12; index += 1) await ingestCandidate(deps, candidate());
    let running = 0;
    let peak = 0;
    const counting: SocDependencies = {
      ...deps,
      unitOfWork: {
        run: async (work) => {
          running += 1;
          peak = Math.max(peak, running);
          await new Promise((resolve) => setTimeout(resolve, 5));
          try {
            return await soc.run(work);
          } finally {
            running -= 1;
          }
        },
      },
    };
    const summary = await drainLearningQueue({
      dependencies: counting,
      queue: soc.learningQueue,
      engine: SHADOW,
      policy: { ...DEFAULT_LEARNING_WORKER_POLICY, concurrency: 3 },
      workerId: 'worker-1',
      tenantId: TENANT,
    });
    expect(summary.done).toBe(12);
    expect(peak).toBeLessThanOrEqual(3);
  });

  it('el código de error guardado nunca lleva texto crudo', () => {
    expect(errorCode(new Error('usuario ana@b89 en host 10.0.0.1'))).toBe('ERROR');
    expect(errorCode(Object.assign(new Error('x'), { code: 'P2034' }))).toBe('P2034');
    expect(errorCode(Object.assign(new Error('x'), { code: 'a b/c' }))).toBe('A_B_C');
  });
});
