/**
 * Aprendizaje SOC · etapa E — efectos compartidos de un desacuerdo humano con el motor.
 *
 * Lo usan el motor (topes, revisiones, reversión explícita) y el comando ordinario `reopen`: una
 * persona que reabre una alerta cerrada por el motor está en desacuerdo con él, use la ruta que
 * use. Sin esto, la señal de vuelta atrás se perdería si la reapertura no pasa por `revert`.
 *
 * Solo importa tipos de `use-cases.ts` (sin ciclo en ejecución): el constructor del borrador de
 * auditoría llega como parámetro.
 */

import type { Actor } from '@b89/access';
import { recordAudit } from '@b89/audit';

import type { LearningPattern } from './learning-pattern.js';
import type { SocTransactionContext } from './ports.js';
import type { IdFactory, socAuditDraft } from './use-cases.js';

/** Mismo constructor de borradores que los casos de uso (import solo de tipo: sin ciclo en ejecución). */
export type AuditDraftFactory = typeof socAuditDraft;

/** Pausa un patrón activo o aprobado (CAS), con evento y auditoría. Silencioso si ya no aplica. */
export async function pauseLearningPattern(
  context: SocTransactionContext,
  ids: IdFactory,
  draft: AuditDraftFactory,
  pattern: LearningPattern,
  reason: string,
  actor: Actor,
  correlationId: string,
  at: Date,
): Promise<boolean> {
  if (pattern.status !== 'active' && pattern.status !== 'approved') return false;
  const next: LearningPattern = {
    ...pattern,
    status: 'paused',
    updatedAt: at,
    revision: pattern.revision + 1,
  };
  if (!(await context.patterns.update(next, pattern.revision))) return false;
  await context.patterns.appendEvent({
    id: ids.next(),
    tenantId: pattern.tenantId,
    patternId: pattern.id,
    from: pattern.status,
    to: 'paused',
    reason,
    actorId: actor.subjectId,
    at,
  });
  await recordAudit(
    context.audit,
    draft({
      id: ids.next(),
      actor,
      action: 'learning.pattern.paused',
      resource: { type: 'learning_pattern', id: pattern.id },
      outcome: 'succeeded',
      correlationId,
      at,
      reason,
      metadata: { from: pattern.status, to: 'paused', ruleKey: pattern.ruleKey },
    }),
  );
  return true;
}

/**
 * Una persona reabrió por la vía ordinaria una alerta que había cerrado el motor: se registra la
 * reversión y se pausa el patrón, igual que con `revertLearningDecision`.
 */
export async function recordManualReopen(
  context: SocTransactionContext,
  ids: IdFactory,
  draft: AuditDraftFactory,
  input: {
    readonly tenantId: string;
    readonly alertId: string;
    readonly actor: Actor;
    readonly note: string | undefined;
    readonly correlationId: string;
    readonly at: Date;
  },
): Promise<void> {
  if (input.actor.subjectId.startsWith('svc:')) return;
  const decision = await context.learning.decisionByAlert(input.tenantId, input.alertId);
  if (!decision || decision.appliedAction !== 'AUTO_CLOSE') return;
  const note = input.note?.trim();
  await context.learning.appendReversal({
    id: ids.next(),
    tenantId: input.tenantId,
    decisionId: decision.id,
    alertId: input.alertId,
    patternId: decision.patternId,
    actorId: input.actor.subjectId,
    reason: `reopen: ${note && note.length > 0 ? note : 'reapertura manual'}`.slice(0, 500),
    reopened: true,
    at: input.at,
  });
  const pattern = decision.patternId
    ? await context.patterns.byId(input.tenantId, decision.patternId)
    : undefined;
  if (pattern) {
    await pauseLearningPattern(
      context,
      ids,
      draft,
      pattern,
      'MANUAL_REOPEN',
      input.actor,
      input.correlationId,
      input.at,
    );
  }
}
