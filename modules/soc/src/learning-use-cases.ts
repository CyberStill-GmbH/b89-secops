/**
 * Aprendizaje SOC · etapa D — casos de uso de patrones de FP.
 *
 * - `refreshLearningPatterns`: propone candidatos desde cierres HUMANOS con motivo, actualiza su
 *   evidencia y aplica transiciones automáticas (TP visto, normalizador viejo, vencimiento y
 *   activación de un aprobado **solo si las compuertas de preparación no tienen bloqueos**).
 * - `approveLearningPattern` / `rejectLearningPattern` / `revokeLearningPattern`: firmas humanas
 *   con la regla A / A+B del diseño original y separación de funciones.
 *
 * La etapa D nunca cierra alertas: un patrón `active` solo tendrá efecto cuando exista el motor
 * (etapa E). Todo deja evento append-only y auditoría con cadena hash.
 */

import { authorize, type Actor } from '@b89/access';
import { recordAudit } from '@b89/audit';

import {
  checkApproval,
  DEFAULT_CANDIDATE_POLICY,
  DEFAULT_READINESS_POLICY,
  evaluateEligibility,
  evaluateReadiness,
  expiryFor,
  nextAutomaticState,
  OPEN_PATTERN_STATUSES,
  requiresSecondApprover,
  type CandidatePolicy,
  type ClosureEvidence,
  type LearningPattern,
  type PatternStatus,
  type ReadinessPolicy,
  type ReadinessSnapshot,
} from './learning-pattern.js';
import type { SocReadModel, SocTransactionContext } from './ports.js';
import { socAuditDraft, socFailure, type SocDependencies, type SocResult } from './use-cases.js';

export const LEARNING_SERVICE_ACTOR = 'svc:b89-soc-learning';
const DAY_MS = 24 * 60 * 60 * 1000;

function serviceActor(tenantId: string): Actor {
  return {
    subjectId: LEARNING_SERVICE_ACTOR,
    tenantId,
    sessionId: 'system',
    capabilities: new Set(),
    roles: [],
  };
}

async function transition(
  context: SocTransactionContext,
  dependencies: SocDependencies,
  pattern: LearningPattern,
  next: LearningPattern,
  reason: string,
  actor: Actor,
  correlationId: string,
): Promise<boolean> {
  if (!(await context.patterns.update(next, pattern.revision))) return false;
  if (next.status !== pattern.status) {
    await context.patterns.appendEvent({
      id: dependencies.ids.next(),
      tenantId: pattern.tenantId,
      patternId: pattern.id,
      from: pattern.status,
      to: next.status,
      reason,
      actorId: actor.subjectId,
      at: next.updatedAt,
    });
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor,
        action: `learning.pattern.${next.status}`,
        resource: { type: 'learning_pattern', id: pattern.id },
        outcome: 'succeeded',
        correlationId,
        at: next.updatedAt,
        reason,
        metadata: { from: pattern.status, to: next.status, ruleKey: pattern.ruleKey },
      }),
    );
  }
  return true;
}

/* ------------------------------------------------------------- Refresco */

export interface RefreshRequest {
  readonly tenantId: string;
  readonly readiness: ReadinessSnapshot;
  readonly candidatePolicy?: CandidatePolicy;
  readonly readinessPolicy?: ReadinessPolicy;
  readonly correlationId: string;
}

export interface RefreshSummary {
  readonly candidatesCreated: number;
  readonly transitions: Readonly<Partial<Record<PatternStatus, number>>>;
  /** Patrones aprobados que siguen sin activarse y por qué (precondiciones). */
  readonly blockedApproved: readonly {
    readonly patternId: string;
    readonly blockers: readonly string[];
  }[];
}

export async function refreshLearningPatterns(
  dependencies: SocDependencies,
  readModel: Pick<SocReadModel, 'learningEvidence'>,
  request: RefreshRequest,
): Promise<SocResult<RefreshSummary>> {
  const now = dependencies.clock.now();
  const policy = request.candidatePolicy ?? DEFAULT_CANDIDATE_POLICY;
  if (!readModel.learningEvidence) {
    return socFailure(
      'INVALID_COMMAND',
      'EVIDENCE_UNAVAILABLE',
      'El adapter no expone evidencia de aprendizaje.',
    );
  }
  const since = new Date(
    now.getTime() - Math.max(policy.evidenceWindowDays, policy.tpLookbackDays) * DAY_MS,
  );
  const evidence = await readModel.learningEvidence(request.tenantId, since);
  const byFingerprint = new Map<string, ClosureEvidence[]>();
  for (const closure of evidence.closures) {
    if (closure.ruleKey === null) continue;
    const list = byFingerprint.get(closure.fingerprint) ?? [];
    list.push(closure);
    byFingerprint.set(closure.fingerprint, list);
  }
  const actor = serviceActor(request.tenantId);

  return dependencies.unitOfWork.run(async (context) => {
    let candidatesCreated = 0;
    const transitions: Partial<Record<PatternStatus, number>> = {};
    const blockedApproved: { patternId: string; blockers: string[] }[] = [];

    // 1. Candidatos nuevos y evidencia al día de los abiertos.
    for (const [fingerprint, closures] of byFingerprint) {
      const truePositives = evidence.truePositivesByFingerprint.get(fingerprint) ?? 0;
      const eligibility = evaluateEligibility(closures, truePositives, now, policy);
      const existing = await context.patterns.openByFingerprint(request.tenantId, fingerprint);
      const sample = closures.at(-1)!;
      if (!existing) {
        if (!eligibility.eligible || eligibility.closureReason === null) continue;
        const pattern: LearningPattern = {
          id: dependencies.ids.next(),
          tenantId: request.tenantId,
          ruleKey: sample.ruleKey!,
          fingerprint,
          normalizerVersion: sample.normalizerVersion,
          level: sample.level,
          components: sample.components,
          maxAction: sample.level === 'fine' ? 'auto_close' : 'demote',
          closureReason: eligibility.closureReason,
          status: 'candidate',
          proposedBy: LEARNING_SERVICE_ACTOR,
          ownerId: null,
          originAlertIds: eligibility.originAlertIds,
          originClosers: eligibility.originClosers,
          confirmations: eligibility.confirmations,
          distinctAlerts: eligibility.distinctAlerts,
          distinctDays: eligibility.distinctDays,
          distinctAnalysts: eligibility.distinctAnalysts,
          truePositiveSeen: eligibility.truePositiveSeen,
          priorityCeiling: eligibility.priorityCeiling,
          readinessBlockers: [],
          createdAt: now,
          updatedAt: now,
          activatedAt: null,
          expiresAt: null,
          renewalCount: 0,
          revision: 1,
        };
        if (await context.patterns.insertIfAbsent(pattern)) {
          candidatesCreated += 1;
          await context.patterns.appendEvent({
            id: dependencies.ids.next(),
            tenantId: request.tenantId,
            patternId: pattern.id,
            from: null,
            to: 'candidate',
            reason: 'ELIGIBLE_HUMAN_EVIDENCE',
            actorId: LEARNING_SERVICE_ACTOR,
            at: now,
          });
          await recordAudit(
            context.audit,
            socAuditDraft({
              id: dependencies.ids.next(),
              actor,
              action: 'learning.pattern.candidate',
              resource: { type: 'learning_pattern', id: pattern.id },
              outcome: 'succeeded',
              correlationId: request.correlationId,
              at: now,
              metadata: {
                ruleKey: pattern.ruleKey,
                confirmations: pattern.confirmations,
                distinctAnalysts: pattern.distinctAnalysts,
                distinctDays: pattern.distinctDays,
              },
            }),
          );
        }
        continue;
      }
      // La evidencia de un patrón ya firmado se congela al aprobar (diseño §5.3): solo se
      // actualiza mientras es candidato.
      if (existing.status === 'candidate') {
        const updated: LearningPattern = {
          ...existing,
          originAlertIds: eligibility.originAlertIds,
          originClosers: eligibility.originClosers,
          confirmations: eligibility.confirmations,
          distinctAlerts: eligibility.distinctAlerts,
          distinctDays: eligibility.distinctDays,
          distinctAnalysts: eligibility.distinctAnalysts,
          truePositiveSeen: eligibility.truePositiveSeen,
          priorityCeiling: eligibility.priorityCeiling,
          updatedAt: now,
          revision: existing.revision + 1,
        };
        await context.patterns.update(updated, existing.revision);
      }
    }

    // 2. Transiciones automáticas de todos los abiertos (incluidos los sin evidencia nueva).
    for (const pattern of await context.patterns.listOpen(request.tenantId)) {
      const blockers = evaluateReadiness(
        pattern,
        request.readiness,
        request.readinessPolicy ?? DEFAULT_READINESS_POLICY,
      );
      const change = nextAutomaticState(pattern, {
        now,
        truePositives: evidence.truePositivesByFingerprint.get(pattern.fingerprint) ?? 0,
        blockers,
        currentNormalizerVersion: request.readiness.currentNormalizerVersion,
      });
      const recordedBlockers =
        pattern.status === 'approved' || pattern.status === 'active'
          ? blockers
          : pattern.readinessBlockers;
      if (!change) {
        if (pattern.status === 'approved')
          blockedApproved.push({ patternId: pattern.id, blockers });
        const changedBlockers = recordedBlockers.join(',') !== pattern.readinessBlockers.join(',');
        if (changedBlockers) {
          await context.patterns.update(
            {
              ...pattern,
              readinessBlockers: recordedBlockers,
              updatedAt: now,
              revision: pattern.revision + 1,
            },
            pattern.revision,
          );
        }
        continue;
      }
      const next: LearningPattern = {
        ...pattern,
        status: change.status,
        readinessBlockers: change.status === 'active' ? [] : recordedBlockers,
        updatedAt: now,
        revision: pattern.revision + 1,
        ...(change.status === 'active'
          ? {
              activatedAt: now,
              // Un patrón reanudado conserva su vencimiento; uno nuevo o renovado recibe el suyo.
              expiresAt:
                pattern.expiresAt && pattern.expiresAt.getTime() > now.getTime()
                  ? pattern.expiresAt
                  : expiryFor(pattern, now),
            }
          : {}),
      };
      if (
        await transition(
          context,
          dependencies,
          pattern,
          next,
          change.reason,
          actor,
          request.correlationId,
        )
      ) {
        transitions[change.status] = (transitions[change.status] ?? 0) + 1;
      }
    }
    return { ok: true as const, value: { candidatesCreated, transitions, blockedApproved } };
  });
}

/* -------------------------------------------------------------- Firmas */

export interface PatternDecisionRequest {
  readonly actor: Actor;
  readonly patternId: string;
  readonly expectedRevision: number;
  readonly comment: string;
  /** Aprobadores designados por persona (configuración). Vacío ⇒ nadie puede firmar. */
  readonly designatedApprovers: readonly string[];
  readonly correlationId: string;
}

const APPROVE_CAPABILITY = 'learning.patterns.approve' as const;

async function loadForDecision(
  dependencies: SocDependencies,
  context: SocTransactionContext,
  request: PatternDecisionRequest,
  action: string,
): Promise<SocResult<LearningPattern>> {
  const at = dependencies.clock.now();
  const pattern = await context.patterns.byId(request.actor.tenantId, request.patternId);
  const decision = authorize({
    actor: request.actor,
    capability: APPROVE_CAPABILITY,
    resource: {
      type: 'learning_pattern',
      id: request.patternId,
      tenantId: pattern?.tenantId ?? request.actor.tenantId,
    },
  });
  if (!decision.allowed) {
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor: request.actor,
        action,
        resource: { type: 'learning_pattern', id: request.patternId },
        outcome: 'denied',
        correlationId: request.correlationId,
        at,
        reason: decision.reason,
      }),
    );
    return socFailure('FORBIDDEN', decision.reason, decision.detail);
  }
  if (!pattern) return socFailure('NOT_FOUND', 'PATTERN_NOT_FOUND', 'El patrón no existe.');
  if (pattern.revision !== request.expectedRevision) {
    return socFailure('CONFLICT', 'REVISION_STALE', 'El patrón cambió; vuelva a cargarlo.');
  }
  if (request.comment.trim().length < 10) {
    return socFailure(
      'INVALID_COMMAND',
      'COMMENT_REQUIRED',
      'La firma exige un comentario de al menos 10 caracteres.',
    );
  }
  return { ok: true as const, value: pattern };
}

export async function approveLearningPattern(
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
): Promise<SocResult<LearningPattern>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const loaded = await loadForDecision(
      dependencies,
      context,
      request,
      'learning.pattern.approve',
    );
    if (!loaded.ok) return loaded;
    const pattern = loaded.value;
    const approvals = await context.patterns.approvals(pattern.tenantId, pattern.id);
    // La primera firma del ciclo vigente (una renovación abre un ciclo nuevo).
    const first = approvals.findLast((row) => row.decision === 'approve' && row.stage === 'first');
    const check = checkApproval(
      pattern,
      request.actor.subjectId,
      request.designatedApprovers,
      first?.approverId ?? null,
    );
    if (!check.ok) {
      await recordAudit(
        context.audit,
        socAuditDraft({
          id: dependencies.ids.next(),
          actor: request.actor,
          action: 'learning.pattern.approve',
          resource: { type: 'learning_pattern', id: pattern.id },
          outcome: 'denied',
          correlationId: request.correlationId,
          at: now,
          reason: check.code,
        }),
      );
      return socFailure(
        check.code === 'NOT_AWAITING_APPROVAL' ? 'INVALID_COMMAND' : 'FORBIDDEN',
        check.code,
        check.code,
      );
    }
    const next: LearningPattern = {
      ...pattern,
      status: check.next,
      ownerId: pattern.ownerId ?? request.actor.subjectId,
      updatedAt: now,
      revision: pattern.revision + 1,
    };
    // CAS primero: una firma solo queda registrada si el cambio de estado se aplicó.
    if (
      !(await transition(
        context,
        dependencies,
        pattern,
        next,
        `SIGNATURE_${check.stage.toUpperCase()}`,
        request.actor,
        request.correlationId,
      ))
    ) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó el patrón.');
    }
    await context.patterns.appendApproval({
      id: dependencies.ids.next(),
      tenantId: pattern.tenantId,
      patternId: pattern.id,
      patternRevision: pattern.revision,
      stage: check.stage,
      approverId: request.actor.subjectId,
      decision: 'approve',
      comment: request.comment.trim(),
      at: now,
    });
    return { ok: true as const, value: next };
  });
}

async function closePattern(
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
  action: 'reject' | 'revoke',
): Promise<SocResult<LearningPattern>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const loaded = await loadForDecision(
      dependencies,
      context,
      request,
      `learning.pattern.${action}`,
    );
    if (!loaded.ok) return loaded;
    const pattern = loaded.value;
    if (
      !request.designatedApprovers.includes(request.actor.subjectId) ||
      request.actor.subjectId.startsWith('svc:')
    ) {
      return socFailure(
        'FORBIDDEN',
        'NOT_A_DESIGNATED_APPROVER',
        'Solo un aprobador designado puede hacerlo.',
      );
    }
    const allowed: readonly PatternStatus[] =
      action === 'reject'
        ? ['candidate', 'pending_second_approval', 'approved']
        : OPEN_PATTERN_STATUSES;
    if (!allowed.includes(pattern.status)) {
      return socFailure(
        'INVALID_COMMAND',
        'INVALID_TRANSITION',
        `No se puede ${action} un patrón ${pattern.status}.`,
      );
    }
    const next: LearningPattern = {
      ...pattern,
      status: 'revoked',
      updatedAt: now,
      revision: pattern.revision + 1,
    };
    if (
      !(await transition(
        context,
        dependencies,
        pattern,
        next,
        action === 'reject' ? 'REJECTED' : 'REVOKED',
        request.actor,
        request.correlationId,
      ))
    ) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó el patrón.');
    }
    if (action === 'reject') {
      await context.patterns.appendApproval({
        id: dependencies.ids.next(),
        tenantId: pattern.tenantId,
        patternId: pattern.id,
        patternRevision: pattern.revision,
        stage: pattern.status === 'pending_second_approval' ? 'second' : 'first',
        approverId: request.actor.subjectId,
        decision: 'reject',
        comment: request.comment.trim(),
        at: now,
      });
    }
    return { ok: true as const, value: next };
  });
}

export const rejectLearningPattern = (
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
) => closePattern(dependencies, request, 'reject');
export const revokeLearningPattern = (
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
) => closePattern(dependencies, request, 'revoke');

/* ------------------------------------------------------ Reanudar y renovar */

/** Separación de funciones común a reanudar y renovar (como en `checkApproval`). */
function signerProblem(
  pattern: LearningPattern,
  request: PatternDecisionRequest,
): string | undefined {
  const subject = request.actor.subjectId;
  if (subject.startsWith('svc:')) return 'SERVICE_IDENTITY';
  if (!request.designatedApprovers.includes(subject)) return 'NOT_A_DESIGNATED_APPROVER';
  if (subject === pattern.proposedBy) return 'APPROVER_IS_PROPOSER';
  if (pattern.originClosers.includes(subject)) return 'APPROVER_CLOSED_ORIGIN_ALERTS';
  return undefined;
}

async function signAndMove(
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
  action: 'resume' | 'renew',
): Promise<SocResult<LearningPattern>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const loaded = await loadForDecision(
      dependencies,
      context,
      request,
      `learning.pattern.${action}`,
    );
    if (!loaded.ok) return loaded;
    const pattern = loaded.value;
    const problem = signerProblem(pattern, request);
    if (problem) {
      await recordAudit(
        context.audit,
        socAuditDraft({
          id: dependencies.ids.next(),
          actor: request.actor,
          action: `learning.pattern.${action}`,
          resource: { type: 'learning_pattern', id: pattern.id },
          outcome: 'denied',
          correlationId: request.correlationId,
          at: now,
          reason: problem,
        }),
      );
      return socFailure('FORBIDDEN', problem, problem);
    }
    let next: LearningPattern;
    if (action === 'resume') {
      // Reanudar vuelve a `approved`: las compuertas deciden la activación y el vencimiento se
      // conserva. Un patrón vencido no se reanuda: se renueva.
      if (pattern.status !== 'paused') {
        return socFailure(
          'INVALID_COMMAND',
          'INVALID_TRANSITION',
          'Solo se reanuda un patrón en pausa.',
        );
      }
      if (!pattern.expiresAt || pattern.expiresAt.getTime() <= now.getTime()) {
        return socFailure('INVALID_COMMAND', 'PATTERN_EXPIRED', 'El patrón venció; renuévelo.');
      }
      next = { ...pattern, status: 'approved', updatedAt: now, revision: pattern.revision + 1 };
    } else {
      // Renovar abre un ciclo de firmas nuevo (A o A+B) con vigencia de renovación (90 días).
      if (pattern.status !== 'expired') {
        return socFailure(
          'INVALID_COMMAND',
          'INVALID_TRANSITION',
          'Solo se renueva un patrón vencido.',
        );
      }
      if (await context.patterns.openByFingerprint(pattern.tenantId, pattern.fingerprint)) {
        return socFailure(
          'CONFLICT',
          'OPEN_PATTERN_EXISTS',
          'Ya hay otro patrón abierto para la misma huella.',
        );
      }
      const renewed: LearningPattern = { ...pattern, renewalCount: pattern.renewalCount + 1 };
      next = {
        ...renewed,
        status: requiresSecondApprover(renewed) ? 'pending_second_approval' : 'approved',
        activatedAt: null,
        expiresAt: null,
        readinessBlockers: [],
        updatedAt: now,
        revision: pattern.revision + 1,
      };
    }
    if (
      !(await transition(
        context,
        dependencies,
        pattern,
        next,
        action === 'resume' ? 'RESUMED' : 'RENEWAL_SIGNED',
        request.actor,
        request.correlationId,
      ))
    ) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó el patrón.');
    }
    await context.patterns.appendApproval({
      id: dependencies.ids.next(),
      tenantId: pattern.tenantId,
      patternId: pattern.id,
      patternRevision: pattern.revision,
      stage: 'first',
      approverId: request.actor.subjectId,
      decision: 'approve',
      comment: request.comment.trim(),
      at: now,
    });
    return { ok: true as const, value: next };
  });
}

/** Reanuda un patrón en pausa (una firma de un aprobador designado). */
export const resumeLearningPattern = (
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
) => signAndMove(dependencies, request, 'resume');

/** Renueva un patrón vencido: nuevo ciclo de firmas y vigencia de 90 días al activarse. */
export const renewLearningPattern = (
  dependencies: SocDependencies,
  request: PatternDecisionRequest,
) => signAndMove(dependencies, request, 'renew');
