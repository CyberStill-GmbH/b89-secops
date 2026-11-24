/**
 * Aprendizaje SOC · etapa E — efectos del motor de decisión.
 *
 * - `evaluateAlertWithLearning`: corre DESPUÉS del commit de la ingesta, en su propia transacción.
 *   Si el motor falla, la alerta queda abierta para una persona (fail-safe) y la ingesta no se
 *   reintenta por su culpa. Relee la alerta y bloquea el patrón (`FOR UPDATE`) en la misma
 *   transacción que escribe el efecto: un patrón revocado entre la decisión y el efecto no cierra
 *   nada (contrato C10). Una decisión por alerta: repetir no duplica efectos.
 * - `resolveLearningReview`: una persona acepta o rechaza una muestra, una propuesta de dry-run o
 *   una revisión forzada. Un rechazo con TP pausa el patrón; un rechazo de una alerta ya cerrada
 *   la reabre.
 * - `revertLearningDecision`: reabre un autocierre, lo registra en `learning_reversals` y pausa el
 *   patrón (cuenta como desacuerdo).
 *
 * El cierre del motor usa los comandos ordinarios con `svc:b89-soc-learning`: su origen es
 * `learning_engine` y nunca suma evidencia a ningún patrón.
 */

import { authorize, type Actor } from '@b89/access';
import { recordAudit } from '@b89/audit';
import type { AlertFingerprint, GuardSignals } from '@b89/detection';

import { applyAlertCommand, type Alert } from './alert.js';
import { closureOriginFor } from './closure.js';
import { alertEvent } from './events.js';
import {
  decideLearningAction,
  LEARNING_ENGINE_VERSION,
  type EngineContext,
  type EngineDecision,
  type EngineSettings,
} from './learning-engine.js';
import type { LearningPattern } from './learning-pattern.js';
import { enqueueLearningNotice } from './learning-notices.js';
import { pauseLearningPattern } from './learning-reversal.js';
import { LEARNING_SERVICE_ACTOR } from './learning-use-cases.js';
import type {
  LearningDecisionRecord,
  LearningReviewRecord,
  SocTransactionContext,
} from './ports.js';
import {
  socAuditDraft,
  socFailure,
  socPublish,
  type SocDependencies,
  type SocResult,
} from './use-cases.js';

/** Configuración del motor que aporta el runtime en cada evaluación. */
export interface LearningEngineDependencies {
  readonly settings: EngineSettings;
  readonly context: () => EngineContext;
}

const REVIEW_CAPABILITY = 'learning.reviews.resolve' as const;
const COMMENT_MINIMUM = 10;

function serviceActor(tenantId: string): Actor {
  return {
    subjectId: LEARNING_SERVICE_ACTOR,
    tenantId,
    sessionId: 'system',
    capabilities: new Set(),
    roles: [],
  };
}

/** Patrón vigente según el reloj del servidor. */
function stillActive(pattern: LearningPattern | undefined, now: Date): pattern is LearningPattern {
  return (
    pattern !== undefined &&
    pattern.status === 'active' &&
    pattern.expiresAt !== null &&
    now.getTime() < pattern.expiresAt.getTime()
  );
}

async function pausePattern(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  pattern: LearningPattern,
  reason: string,
  actor: Actor,
  correlationId: string,
  at: Date,
): Promise<void> {
  await pauseLearningPattern(
    context,
    dependencies.ids,
    socAuditDraft,
    pattern,
    reason,
    actor,
    correlationId,
    at,
  );
}

/**
 * Acuse, triaje y cierre como el servicio de aprendizaje, en una sola escritura CAS. Solo sobre
 * una alerta `new` sin cambios desde la decisión: si alguien la tocó, el motor no la cierra.
 */
async function closeAsEngine(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  alert: Alert,
  pattern: LearningPattern,
  decisionId: string,
  correlationId: string,
  at: Date,
): Promise<boolean> {
  if (alert.status !== 'new' || alert.incidentId !== null) return false;
  const approvals = (await context.patterns.approvals(pattern.tenantId, pattern.id))
    .filter((row) => row.decision === 'approve')
    .map((row) => row.approverId);
  const signers = [...new Set(approvals)].slice(-2).join(' y ') || 'sin firmas';
  const actorId = LEARNING_SERVICE_ACTOR;
  const steps = [
    { name: 'acknowledge' as const },
    {
      name: 'triage' as const,
      verdict: 'false_positive' as const,
      note: `Patrón de FP aprendido ${pattern.id}: huella exacta y guardas en verde (decisión ${decisionId}).`,
    },
    {
      name: 'close' as const,
      closure: {
        reason: pattern.closureReason,
        justification: {
          evidenceType: 'log_correlation' as const,
          statement:
            `Cierre automático del motor de aprendizaje ${LEARNING_ENGINE_VERSION}: patrón ${pattern.id} ` +
            `(revisión ${pattern.revision}) aprobado por ${signers}; vence ${pattern.expiresAt?.toISOString() ?? '—'}.`,
          legitimacyField: 'fingerprint',
          legitimacyValue: pattern.fingerprint,
        },
        evidenceRefs: pattern.originAlertIds
          .slice(0, 5)
          .map((ref) => ({ kind: 'alert' as const, ref })),
      },
    },
  ];
  let current = alert;
  for (const step of steps) {
    const transition = applyAlertCommand(current, {
      ...step,
      actorId,
      at,
      expectedRevision: current.revision,
      closureReasonRequired: true,
    });
    if (!transition.ok) return false;
    current = transition.alert;
  }
  if (!(await context.alerts.update(current, alert.revision))) return false;
  const actor = serviceActor(alert.tenantId);
  await context.closures.append({
    id: dependencies.ids.next(),
    tenantId: alert.tenantId,
    alertId: alert.id,
    kind: 'close',
    verdict: current.verdict,
    closureReason: current.closureReason,
    origin: closureOriginFor(actorId),
    actorId,
    justification: steps[2]!.closure!.justification,
    evidenceRefs: steps[2]!.closure!.evidenceRefs,
    decisionGroupId: null,
    correlationId,
    at,
  });
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor,
      action: 'soc.alert.close',
      resource: { type: 'alert', id: alert.id },
      outcome: 'succeeded',
      correlationId,
      at,
      metadata: {
        from: alert.status,
        to: current.status,
        verdict: current.verdict,
        closureReason: current.closureReason,
        closureOrigin: current.closureOrigin,
        patternId: pattern.id,
        decisionId,
      },
    }),
  );
  await socPublish(
    context,
    [
      alertEvent({
        type: 'soc.alert.closed',
        tenantId: alert.tenantId,
        alertId: alert.id,
        actorId,
        at,
        priority: current.priority,
        status: current.status,
        title: current.title,
        score: current.score,
        signal: current.signal,
        ruleId: current.ruleId,
        reasonCodes: current.reasons.map((reason) => reason.code).join(', '),
        relatedAlertCount: current.relatedAlertIds.length,
        verdict: current.verdict,
        incidentId: current.incidentId,
      }),
    ],
    dependencies.ids,
  );
  return true;
}

/**
 * DEMOTE: prioridad efectiva P3 → P4 en una escritura CAS. `priority` (la original) no cambia y la
 * base rechaza cualquier otra combinación (CHECK `soc_alerts_effective_priority_floor`).
 */
async function demoteAsEngine(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  alert: Alert,
  decisionId: string,
  correlationId: string,
  at: Date,
): Promise<boolean> {
  if (
    alert.priority !== 'P3' ||
    alert.status === 'closed' ||
    (alert.effectivePriority ?? null) !== null
  ) {
    return false;
  }
  const next: Alert = {
    ...alert,
    effectivePriority: 'P4',
    demotedBy: decisionId,
    updatedAt: at,
    revision: alert.revision + 1,
  };
  if (!(await context.alerts.update(next, alert.revision))) return false;
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor: serviceActor(alert.tenantId),
      action: 'soc.alert.demote',
      resource: { type: 'alert', id: alert.id },
      outcome: 'succeeded',
      correlationId,
      at,
      metadata: { from: alert.priority, to: 'P4', decisionId },
    }),
  );
  return true;
}

/** Revierte un DEMOTE: la prioridad efectiva vuelve a la original. */
async function undemote(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  alertId: string,
  actor: Actor,
  correlationId: string,
  at: Date,
): Promise<boolean> {
  const alert = await context.alerts.byId(actor.tenantId, alertId);
  if (!alert || (alert.effectivePriority ?? null) === null) return false;
  const next: Alert = {
    ...alert,
    effectivePriority: null,
    demotedBy: null,
    updatedAt: at,
    revision: alert.revision + 1,
  };
  if (!(await context.alerts.update(next, alert.revision))) return false;
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor,
      action: 'soc.alert.undemote',
      resource: { type: 'alert', id: alert.id },
      outcome: 'succeeded',
      correlationId,
      at,
      metadata: { priority: alert.priority },
    }),
  );
  return true;
}

/* -------------------------------------------------------------- Evaluación */

export interface EvaluateRequest {
  readonly tenantId: string;
  readonly alertId: string;
  readonly fingerprint: AlertFingerprint;
  readonly signals: GuardSignals | undefined;
  readonly correlationId: string;
}

export type EvaluationOutcome =
  | { readonly recorded: false; readonly reason: 'OFF' | 'ALREADY_DECIDED' | 'ALERT_NOT_FOUND' }
  | {
      readonly recorded: true;
      readonly decision: LearningDecisionRecord;
      readonly closed: boolean;
    };

export async function evaluateAlertWithLearning(
  dependencies: SocDependencies,
  engine: LearningEngineDependencies,
  request: EvaluateRequest,
): Promise<SocResult<EvaluationOutcome>> {
  const engineContext = engine.context();
  return dependencies.unitOfWork
    .run(async (context) => {
      const alert = await context.alerts.byId(request.tenantId, request.alertId);
      if (!alert) {
        return {
          ok: true as const,
          value: { recorded: false as const, reason: 'ALERT_NOT_FOUND' as const },
        };
      }
      const fp = request.fingerprint;
      // El patrón exacto se lee bloqueando su fila: la decisión y el efecto ven el mismo estado.
      const exact = await context.patterns.openByFingerprint(request.tenantId, fp.fingerprint);
      // El reloj se lee DESPUÉS del bloqueo: una espera larga no puede dejar pasar un patrón que
      // venció mientras tanto, y los topes se cuentan sobre el estado ya serializado.
      const now = dependencies.clock.now();
      const sameRule = fp.ruleKey
        ? await context.patterns.activeByRule(request.tenantId, fp.ruleKey)
        : [];
      const counters =
        exact && exact.status === 'active'
          ? await context.learning.counters(
              request.tenantId,
              exact.id,
              now,
              exact.activatedAt ?? exact.updatedAt,
            )
          : undefined;
      const decided: EngineDecision = decideLearningAction({
        alert,
        fingerprint: fp,
        exact,
        sameRule,
        signals: request.signals,
        counters,
        settings: engine.settings,
        context: engineContext,
        now,
      });
      if (!decided.record) {
        return { ok: true as const, value: { recorded: false as const, reason: 'OFF' as const } };
      }
      const decisionId = dependencies.ids.next();
      let applied = decided.appliedAction;
      let closed = false;
      const checks = [...decided.checks];
      if (applied === 'DEMOTE') {
        const demoted = stillActive(exact, now)
          ? await demoteAsEngine(
              context,
              dependencies,
              alert,
              decisionId,
              request.correlationId,
              now,
            )
          : false;
        if (!demoted) {
          applied = 'ESCALATE';
          checks.push({
            id: 'EFFECT',
            ok: false,
            detail: 'la alerta o el patrón cambiaron antes de bajar la prioridad',
          });
        }
      }
      if (applied === 'AUTO_CLOSE') {
        closed = stillActive(exact, now)
          ? await closeAsEngine(
              context,
              dependencies,
              alert,
              exact,
              decisionId,
              request.correlationId,
              now,
            )
          : false;
        if (!closed) {
          applied = 'ESCALATE';
          checks.push({
            id: 'EFFECT',
            ok: false,
            detail: 'la alerta o el patrón cambiaron antes del cierre',
          });
        }
      }
      const record: LearningDecisionRecord = {
        id: decisionId,
        tenantId: request.tenantId,
        alertId: alert.id,
        mode: decided.mode,
        engineVersion: LEARNING_ENGINE_VERSION,
        fingerprint: fp.fingerprint,
        level: fp.level,
        ruleKey: fp.ruleKey,
        patternId: decided.patternId,
        proposedAction: decided.proposedAction,
        appliedAction: applied,
        escalateReason: decided.escalateReason,
        confidence: decided.confidence,
        checks,
        drift: decided.drift,
        sampled: decided.sampled,
        samplingKeyVersion: engineContext.samplingKeyVersion ?? null,
        at: now,
      };
      if (!(await context.learning.appendDecision(record))) {
        // Otra evaluación ya decidió esta alerta: abortar este intento sin efectos.
        throw Object.assign(new Error('LEARNING_DECISION_EXISTS'), {
          code: 'LEARNING_DECISION_EXISTS',
        });
      }
      const review = decided.review === 'quality_sample' && !closed ? null : decided.review;
      if (review) {
        await context.learning.insertReview({
          id: dependencies.ids.next(),
          tenantId: request.tenantId,
          decisionId,
          alertId: alert.id,
          patternId: decided.patternId,
          kind: review,
          status: 'pending',
          reviewerId: null,
          truePositive: null,
          comment: null,
          at: now,
          resolvedAt: null,
          revision: 1,
        });
      }
      // AttentionPort: una escalada con efecto llega a una persona (HOT inmediato o WARM en resumen).
      if (applied === 'ESCALATE') {
        await enqueueLearningNotice(context, dependencies.ids, {
          alert,
          kind: decided.escalateReason ?? 'EFFECT_FAILED',
          decisionId,
          ruleKey: fp.ruleKey,
          patternId: decided.patternId,
          actorId: LEARNING_SERVICE_ACTOR,
          at: now,
        });
      }
      if (decided.pausePattern && exact) {
        await enqueueLearningNotice(context, dependencies.ids, {
          alert,
          kind: 'PATTERN_PAUSED',
          decisionId,
          ruleKey: fp.ruleKey,
          patternId: exact.id,
          actorId: LEARNING_SERVICE_ACTOR,
          at: now,
        });
      }
      const actor = serviceActor(request.tenantId);
      if (decided.pausePattern && exact) {
        await pausePattern(
          context,
          dependencies,
          exact,
          'RATE_LIMIT',
          actor,
          request.correlationId,
          now,
        );
      }
      await recordAudit(
        context.audit,
        socAuditDraft({
          id: dependencies.ids.next(),
          actor,
          action: 'learning.decision',
          resource: { type: 'alert', id: alert.id },
          outcome: 'succeeded',
          correlationId: request.correlationId,
          at: now,
          metadata: {
            decisionId,
            mode: record.mode,
            proposed: record.proposedAction,
            applied: record.appliedAction,
            ...(record.escalateReason ? { escalateReason: record.escalateReason } : {}),
            ...(record.patternId ? { patternId: record.patternId } : {}),
          },
        }),
      );
      return { ok: true as const, value: { recorded: true as const, decision: record, closed } };
    })
    .catch((error: unknown) => {
      if ((error as { code?: string }).code === 'LEARNING_DECISION_EXISTS') {
        return {
          ok: true as const,
          value: { recorded: false as const, reason: 'ALREADY_DECIDED' as const },
        };
      }
      throw error;
    });
}

/* ------------------------------------------------------------- Revisiones */

export interface ReviewResolutionRequest {
  readonly actor: Actor;
  readonly reviewId: string;
  readonly expectedRevision: number;
  readonly outcome: 'agree' | 'disagree';
  /** Al discrepar: la persona considera la alerta un verdadero positivo. */
  readonly truePositive: boolean;
  readonly comment: string;
  readonly correlationId: string;
}

async function authorizeReviewer(
  dependencies: SocDependencies,
  context: SocTransactionContext,
  actor: Actor,
  resource: { readonly type: string; readonly id: string },
  action: string,
  correlationId: string,
  at: Date,
): Promise<SocResult<true>> {
  const decision = authorize({
    actor,
    capability: REVIEW_CAPABILITY,
    resource: { ...resource, tenantId: actor.tenantId },
  });
  if (decision.allowed && !actor.subjectId.startsWith('svc:')) return { ok: true, value: true };
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor,
      action,
      resource,
      outcome: 'denied',
      correlationId,
      at,
      reason: decision.allowed ? 'SERVICE_IDENTITY' : decision.reason,
    }),
  );
  return decision.allowed
    ? socFailure('FORBIDDEN', 'SERVICE_IDENTITY', 'Una identidad de servicio no revisa decisiones.')
    : socFailure('FORBIDDEN', decision.reason, decision.detail);
}

/** Reabre una alerta cerrada por el motor como la persona que discrepa. */
async function reopenAsReviewer(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  alertId: string,
  actor: Actor,
  correlationId: string,
  at: Date,
): Promise<boolean> {
  const alert = await context.alerts.byId(actor.tenantId, alertId);
  if (!alert || alert.status !== 'closed' || alert.closureOrigin !== 'learning_engine')
    return false;
  const transition = applyAlertCommand(alert, {
    name: 'reopen',
    actorId: actor.subjectId,
    at,
    expectedRevision: alert.revision,
  });
  if (!transition.ok || !(await context.alerts.update(transition.alert, alert.revision)))
    return false;
  await context.closures.append({
    id: dependencies.ids.next(),
    tenantId: alert.tenantId,
    alertId: alert.id,
    kind: 'reopen',
    verdict: transition.alert.verdict,
    closureReason: null,
    origin: closureOriginFor(actor.subjectId),
    actorId: actor.subjectId,
    justification: null,
    evidenceRefs: [],
    decisionGroupId: null,
    correlationId,
    at,
  });
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor,
      action: 'soc.alert.reopen',
      resource: { type: 'alert', id: alert.id },
      outcome: 'succeeded',
      correlationId,
      at,
      metadata: { from: 'closed', to: transition.alert.status, cause: 'learning_reversal' },
    }),
  );
  return true;
}

export async function resolveLearningReview(
  dependencies: SocDependencies,
  request: ReviewResolutionRequest,
): Promise<SocResult<LearningReviewRecord>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const auth = await authorizeReviewer(
      dependencies,
      context,
      request.actor,
      { type: 'learning_review', id: request.reviewId },
      'learning.review.resolve',
      request.correlationId,
      now,
    );
    if (!auth.ok) return auth;
    const review = await context.learning.reviewById(request.actor.tenantId, request.reviewId);
    if (!review) return socFailure('NOT_FOUND', 'REVIEW_NOT_FOUND', 'La revisión no existe.');
    if (review.revision !== request.expectedRevision) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'La revisión cambió; vuelva a cargarla.');
    }
    if (review.status !== 'pending') {
      return socFailure('INVALID_COMMAND', 'REVIEW_RESOLVED', 'La revisión ya fue resuelta.');
    }
    const comment = request.comment.trim();
    if (comment.length < COMMENT_MINIMUM) {
      return socFailure('INVALID_COMMAND', 'COMMENT_REQUIRED', 'La revisión exige un comentario.');
    }
    const pattern = review.patternId
      ? await context.patterns.byId(review.tenantId, review.patternId)
      : undefined;
    let status: LearningReviewRecord['status'] =
      request.outcome === 'agree' ? 'agreed' : 'disagreed';

    if (review.kind === 'dry_run_approval' && request.outcome === 'agree') {
      // Aceptar ejecuta el cierre, solo si el patrón sigue activo y vigente y la alerta intacta.
      const alert = await context.alerts.byId(review.tenantId, review.alertId);
      const closed =
        alert && stillActive(pattern, now)
          ? await closeAsEngine(
              context,
              dependencies,
              alert,
              pattern,
              review.decisionId,
              request.correlationId,
              now,
            )
          : false;
      if (!closed) status = 'expired';
    }
    let reopened = false;
    if (request.outcome === 'disagree') {
      reopened = await reopenAsReviewer(
        context,
        dependencies,
        review.alertId,
        request.actor,
        request.correlationId,
        now,
      );
      if (reopened || request.truePositive) {
        const target = await context.alerts.byId(review.tenantId, review.alertId);
        if (target) {
          await enqueueLearningNotice(context, dependencies.ids, {
            alert: target,
            kind: 'REVERSAL',
            decisionId: review.decisionId,
            ruleKey: pattern?.ruleKey ?? null,
            patternId: review.patternId,
            actorId: request.actor.subjectId,
            at: now,
          });
        }
      }
      if (reopened) {
        await context.learning.appendReversal({
          id: dependencies.ids.next(),
          tenantId: review.tenantId,
          decisionId: review.decisionId,
          alertId: review.alertId,
          patternId: review.patternId,
          actorId: request.actor.subjectId,
          reason: `review:${review.kind}: ${comment}`.slice(0, 500),
          reopened: true,
          at: now,
        });
      }
      if (pattern && (request.truePositive || reopened)) {
        await pausePattern(
          context,
          dependencies,
          pattern,
          request.truePositive ? 'REVIEW_TRUE_POSITIVE' : 'REVIEW_DISAGREEMENT',
          request.actor,
          request.correlationId,
          now,
        );
      }
    }
    const next: LearningReviewRecord = {
      ...review,
      status,
      reviewerId: request.actor.subjectId,
      truePositive: request.outcome === 'disagree' ? request.truePositive : false,
      comment,
      resolvedAt: now,
      revision: review.revision + 1,
    };
    if (!(await context.learning.updateReview(next, review.revision))) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó la revisión.');
    }
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor: request.actor,
        action: 'learning.review.resolve',
        resource: { type: 'learning_review', id: review.id },
        outcome: 'succeeded',
        correlationId: request.correlationId,
        at: now,
        metadata: {
          kind: review.kind,
          status,
          truePositive: next.truePositive,
          reopened,
          ...(review.patternId ? { patternId: review.patternId } : {}),
        },
      }),
    );
    return { ok: true as const, value: next };
  });
}

/* -------------------------------------------------------------- Reversión */

export interface RevertRequest {
  readonly actor: Actor;
  readonly decisionId: string;
  readonly reason: string;
  readonly correlationId: string;
}

export async function revertLearningDecision(
  dependencies: SocDependencies,
  request: RevertRequest,
): Promise<SocResult<{ readonly alertId: string; readonly reopened: boolean }>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const auth = await authorizeReviewer(
      dependencies,
      context,
      request.actor,
      { type: 'learning_decision', id: request.decisionId },
      'learning.decision.revert',
      request.correlationId,
      now,
    );
    if (!auth.ok) return auth;
    const reason = request.reason.trim();
    if (reason.length < COMMENT_MINIMUM) {
      return socFailure('INVALID_COMMAND', 'COMMENT_REQUIRED', 'La reversión exige un motivo.');
    }
    const decision = await context.learning.decisionById(
      request.actor.tenantId,
      request.decisionId,
    );
    if (!decision) return socFailure('NOT_FOUND', 'DECISION_NOT_FOUND', 'La decisión no existe.');
    // Un autocierre se revierte reabriendo; un DEMOTE, devolviendo la prioridad original.
    const reopened =
      decision.appliedAction === 'DEMOTE'
        ? await undemote(
            context,
            dependencies,
            decision.alertId,
            request.actor,
            request.correlationId,
            now,
          )
        : await reopenAsReviewer(
            context,
            dependencies,
            decision.alertId,
            request.actor,
            request.correlationId,
            now,
          );
    if (!reopened) {
      return socFailure(
        'INVALID_COMMAND',
        'NOT_ENGINE_CLOSED',
        'Solo se revierte una alerta que sigue cerrada (o con prioridad bajada) por el motor.',
      );
    }
    await context.learning.appendReversal({
      id: dependencies.ids.next(),
      tenantId: decision.tenantId,
      decisionId: decision.id,
      alertId: decision.alertId,
      patternId: decision.patternId,
      actorId: request.actor.subjectId,
      reason: reason.slice(0, 500),
      reopened: true,
      at: now,
    });
    const pattern = decision.patternId
      ? await context.patterns.byId(decision.tenantId, decision.patternId)
      : undefined;
    const reverted = await context.alerts.byId(decision.tenantId, decision.alertId);
    if (reverted) {
      await enqueueLearningNotice(context, dependencies.ids, {
        alert: reverted,
        kind: 'REVERSAL',
        decisionId: decision.id,
        ruleKey: decision.ruleKey,
        patternId: decision.patternId,
        actorId: request.actor.subjectId,
        at: now,
      });
    }
    if (pattern) {
      await pausePattern(
        context,
        dependencies,
        pattern,
        'REVERTED',
        request.actor,
        request.correlationId,
        now,
      );
    }
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor: request.actor,
        action: 'learning.decision.revert',
        resource: { type: 'learning_decision', id: decision.id },
        outcome: 'succeeded',
        correlationId: request.correlationId,
        at: now,
        reason,
        metadata: {
          alertId: decision.alertId,
          ...(decision.patternId ? { patternId: decision.patternId } : {}),
        },
      }),
    );
    return { ok: true as const, value: { alertId: decision.alertId, reopened } };
  });
}
