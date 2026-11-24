/**
 * Aprendizaje SOC · fase 3 — el motor se pausa solo si sus avisos no llegan.
 *
 * Invariante (AttentionPort): toda escalada con efecto produce un aviso a una persona en ≤ 2 min
 * (HOT) o ≤ 15 min (WARM, resumen). Si un aviso del motor sigue sin publicarse pasado su plazo,
 * nadie se está enterando de lo que el motor escala: el motor se pausa a sí mismo (vuelve a sombra,
 * sin efectos), lo audita y la salud lo marca crítico. Reanudar exige una persona designada.
 */

import { authorize, type Actor } from '@b89/access';
import { recordAudit } from '@b89/audit';

import type { EngineSettings } from './learning-engine.js';
import { LEARNING_SERVICE_ACTOR } from './learning-use-cases.js';
import type { SocReadModel } from './ports.js';
import { socAuditDraft, socFailure, type SocDependencies, type SocResult } from './use-cases.js';

export const ENGINE_PAUSE_REASONS = ['NOTIFICATION_UNDELIVERED', 'OPERATOR'] as const;
export type EnginePauseReason = (typeof ENGINE_PAUSE_REASONS)[number];

export interface LearningEngineState {
  readonly tenantId: string;
  readonly paused: boolean;
  readonly reason: EnginePauseReason | null;
  readonly since: Date | null;
  readonly revision: number;
}

/** Dentro de la unidad de trabajo: `save` es CAS (`expectedRevision = null` ⇒ primera fila). */
export interface LearningEngineStateStore {
  get(tenantId: string): Promise<LearningEngineState | undefined>;
  save(state: LearningEngineState, expectedRevision: number | null): Promise<boolean>;
}

const RANK = { off: 0, shadow: 1, dry_run: 2, active: 3 } as const;

/** Con el motor pausado, el techo efectivo es la sombra (decide y registra, sin efectos). */
export function capForEngineState(
  settings: EngineSettings,
  state: LearningEngineState | undefined,
): EngineSettings {
  if (!state?.paused || RANK[settings.maxMode] <= RANK.shadow) return settings;
  return { ...settings, maxMode: 'shadow' };
}

function serviceActor(tenantId: string): Actor {
  return {
    subjectId: LEARNING_SERVICE_ACTOR,
    tenantId,
    sessionId: 'system',
    capabilities: new Set(),
    roles: [],
  };
}

/** Comprueba la entrega de avisos y pausa el motor si alguno venció. Idempotente. */
export async function checkLearningNoticeDelivery(
  dependencies: SocDependencies,
  readModel: Pick<SocReadModel, 'learningUndeliveredNotices'>,
  tenantId: string,
): Promise<{ readonly paused: boolean; readonly hot: number; readonly warm: number }> {
  const now = dependencies.clock.now();
  const counts = (await readModel.learningUndeliveredNotices?.(tenantId, now)) ?? {
    hot: 0,
    warm: 0,
  };
  if (counts.hot === 0 && counts.warm === 0) return { paused: false, ...counts };
  const paused = await dependencies.unitOfWork.run(async (context) => {
    const current = await context.learningState.get(tenantId);
    if (current?.paused) return true;
    const next: LearningEngineState = {
      tenantId,
      paused: true,
      reason: 'NOTIFICATION_UNDELIVERED',
      since: now,
      revision: (current?.revision ?? 0) + 1,
    };
    if (!(await context.learningState.save(next, current?.revision ?? null))) return false;
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor: serviceActor(tenantId),
        action: 'learning.engine.paused',
        resource: { type: 'learning_engine', id: tenantId },
        outcome: 'succeeded',
        correlationId: `learning-delivery:${now.toISOString()}`,
        at: now,
        reason: 'NOTIFICATION_UNDELIVERED',
        metadata: { hot: counts.hot, warm: counts.warm },
      }),
    );
    return true;
  });
  return { paused, ...counts };
}

/** Reanuda el motor: una persona designada, con comentario. No reanuda patrones ni sube el techo. */
export async function resumeLearningEngine(
  dependencies: SocDependencies,
  request: {
    readonly actor: Actor;
    readonly designatedApprovers: readonly string[];
    readonly comment: string;
    readonly correlationId: string;
  },
): Promise<SocResult<LearningEngineState>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const decision = authorize({
      actor: request.actor,
      capability: 'learning.patterns.approve',
      resource: {
        type: 'learning_engine',
        id: request.actor.tenantId,
        tenantId: request.actor.tenantId,
      },
    });
    const subject = request.actor.subjectId;
    const problem = !decision.allowed
      ? decision.reason
      : subject.startsWith('svc:')
        ? 'SERVICE_IDENTITY'
        : !request.designatedApprovers.includes(subject)
          ? 'NOT_A_DESIGNATED_APPROVER'
          : request.comment.trim().length < 10
            ? 'COMMENT_REQUIRED'
            : undefined;
    const audit = (outcome: 'succeeded' | 'denied', reason?: string) =>
      recordAudit(
        context.audit,
        socAuditDraft({
          id: dependencies.ids.next(),
          actor: request.actor,
          action: 'learning.engine.resume',
          resource: { type: 'learning_engine', id: request.actor.tenantId },
          outcome,
          correlationId: request.correlationId,
          at: now,
          ...(reason ? { reason } : {}),
        }),
      );
    if (problem) {
      await audit('denied', problem);
      return socFailure(
        problem === 'COMMENT_REQUIRED' ? 'INVALID_COMMAND' : 'FORBIDDEN',
        problem,
        problem,
      );
    }
    const current = await context.learningState.get(request.actor.tenantId);
    if (!current?.paused) {
      return socFailure('INVALID_COMMAND', 'ENGINE_NOT_PAUSED', 'El motor no está en pausa.');
    }
    const next: LearningEngineState = {
      ...current,
      paused: false,
      reason: null,
      since: now,
      revision: current.revision + 1,
    };
    if (!(await context.learningState.save(next, current.revision))) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'El estado del motor cambió.');
    }
    await audit('succeeded');
    return { ok: true as const, value: next };
  });
}
