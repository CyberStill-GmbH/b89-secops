/**
 * Aprendizaje SOC · fase 2 de la sombra — worker del motor fuera del camino de la ingesta.
 *
 * La ingesta solo escribe un trabajo en su propia transacción (`soc_learning_jobs`); este worker los
 * reclama con lease, los evalúa con concurrencia acotada y un tiempo máximo por trabajo, y:
 *
 * - éxito (incluida «ya decidida» o «alerta inexistente») → `done`;
 * - excepción o tiempo agotado → reintento con espera exponencial;
 * - tras `maxAttempts` → `dead` (dead-letter): la alerta sigue abierta para una persona.
 *
 * Idempotente: una decisión por alerta (índice único). Si un trabajo agotó su tiempo pero su
 * transacción terminó, el reintento ve `ALREADY_DECIDED` y lo marca hecho. Cada pasada deja un
 * latido (dead man's switch que vigila el monitor de plataforma).
 */

import {
  evaluateAlertWithLearning,
  type LearningEngineDependencies,
} from './learning-engine-use-cases.js';
import type { LearningJob, LearningJobQueue } from './ports.js';
import type { SocDependencies } from './use-cases.js';

export interface LearningWorkerPolicy {
  readonly batchSize: number;
  readonly concurrency: number;
  readonly leaseMs: number;
  readonly timeoutMs: number;
  readonly maxAttempts: number;
  readonly backoffBaseMs: number;
}

export const DEFAULT_LEARNING_WORKER_POLICY: LearningWorkerPolicy = Object.freeze({
  batchSize: 50,
  concurrency: 4,
  leaseMs: 60_000,
  timeoutMs: 10_000,
  maxAttempts: 5,
  backoffBaseMs: 5_000,
});

export interface DrainSummary {
  readonly claimed: number;
  readonly done: number;
  readonly retried: number;
  readonly dead: number;
}

/** Código corto para `last_error` (la base solo admite `^[A-Z0-9_:.-]{1,80}$`). */
export function errorCode(error: unknown): string {
  const code = (error as { code?: unknown }).code;
  const raw =
    typeof code === 'string' && code.length > 0 ? code : (error as Error)?.name || 'ERROR';
  const cleaned = raw
    .toUpperCase()
    .replace(/[^A-Z0-9_:.-]/gu, '_')
    .slice(0, 80);
  return cleaned.length > 0 ? cleaned : 'ERROR';
}

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(Object.assign(new Error('timeout'), { code: 'LEARNING_TIMEOUT' })),
      ms,
    );
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/** Una pasada del worker. Nunca lanza por un trabajo: cada fallo queda en la cola. */
export async function drainLearningQueue(input: {
  readonly dependencies: SocDependencies;
  readonly queue: LearningJobQueue;
  readonly engine: LearningEngineDependencies;
  readonly policy?: LearningWorkerPolicy;
  readonly workerId: string;
  readonly tenantId: string;
}): Promise<DrainSummary> {
  const policy = input.policy ?? DEFAULT_LEARNING_WORKER_POLICY;
  const now = input.dependencies.clock.now();
  const claimId = input.dependencies.ids.next();
  const jobs = await input.queue.claim({
    limit: policy.batchSize,
    leaseMs: policy.leaseMs,
    now,
    claimId,
  });
  let done = 0;
  let retried = 0;
  let dead = 0;

  const process = async (job: LearningJob): Promise<void> => {
    try {
      await withTimeout(
        evaluateAlertWithLearning(input.dependencies, input.engine, {
          tenantId: job.tenantId,
          alertId: job.alertId,
          fingerprint: job.fingerprint,
          signals: job.signals ?? undefined,
          correlationId: `learning-job:${job.alertId}`,
        }),
        policy.timeoutMs,
      );
      if (await input.queue.complete(job.alertId, claimId, input.dependencies.clock.now()))
        done += 1;
    } catch (error) {
      const at = input.dependencies.clock.now();
      const exhausted = job.attempts >= policy.maxAttempts;
      const retryAt = exhausted
        ? null
        : new Date(at.getTime() + policy.backoffBaseMs * 2 ** Math.max(0, job.attempts - 1));
      if (await input.queue.fail(job.alertId, claimId, errorCode(error), at, retryAt)) {
        if (exhausted) dead += 1;
        else retried += 1;
      }
    }
  };

  // Concurrencia acotada: `concurrency` trabajos a la vez, nunca más.
  let next = 0;
  const lanes = Array.from({ length: Math.min(policy.concurrency, jobs.length) }, async () => {
    while (next < jobs.length) {
      const job = jobs[next];
      next += 1;
      if (job) await process(job);
    }
  });
  await Promise.all(lanes);

  await input.queue.heartbeat({
    workerId: input.workerId,
    tenantId: input.tenantId,
    at: input.dependencies.clock.now(),
    claimed: jobs.length,
    failed: retried + dead,
  });
  return { claimed: jobs.length, done, retried, dead };
}
