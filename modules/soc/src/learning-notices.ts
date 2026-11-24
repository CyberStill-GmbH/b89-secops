/**
 * Aprendizaje SOC · fase 3 — la escalada llega a una persona (AttentionPort) y avisos inmediatos.
 *
 * Toda decisión con efecto `ESCALATE`, toda pausa de patrón y toda reversión encolan, EN LA MISMA
 * TRANSACCIÓN que la decisión, un pedido de revisión humana por la vía de notificación existente
 * (`soc.alert.review_requested`: ruteo a analista y líder, agrupación, ventanas, tope, resumen y
 * acuse). Router:
 *
 * - **HOT** (`immediate`): deriva, colisión, tope por hora, revisión forzada, pausa, reversión;
 * - **WARM** (`digest`): guardas, tope diario y demás escaladas (van al resumen).
 *
 * Deduplicación: `groupKey` agrupa por motivo, regla y hora; el outbox deduplica por contenido.
 * Si un aviso no se entrega a tiempo, el motor se pausa solo (`learning-engine-state.ts`).
 */

import type { Alert } from './alert.js';
import { toOutboxMessage, type SocDomainEvent } from './events.js';
import type { SocTransactionContext } from './ports.js';
import type { IdFactory } from './use-cases.js';

export const LEARNING_NOTICE_PREFIX = 'LEARNING_';

/** Motivos HOT: aviso propio inmediato. El resto va al resumen (WARM). */
export const HOT_LEARNING_NOTICES: ReadonlySet<string> = new Set([
  'DRIFT',
  'FINGERPRINT_COLLISION',
  'RATE_LIMIT',
  'FORCED_REVIEW',
  'PATTERN_PAUSED',
  'REVERSAL',
  'SAMPLING_UNAVAILABLE',
]);

/** Plazos de entrega (dead man's switch de la notificación). */
export const LEARNING_NOTICE_DEADLINES = Object.freeze({ hotMs: 2 * 60_000, warmMs: 15 * 60_000 });

export function urgencyOf(kind: string): 'immediate' | 'digest' {
  return HOT_LEARNING_NOTICES.has(kind) ? 'immediate' : 'digest';
}

/** Encola el aviso. Devuelve `false` si un aviso idéntico ya estaba en el outbox. */
export async function enqueueLearningNotice(
  context: SocTransactionContext,
  ids: IdFactory,
  input: {
    readonly alert: Alert;
    readonly kind: string;
    readonly decisionId: string;
    readonly ruleKey: string | null;
    readonly patternId: string | null;
    readonly actorId: string;
    readonly at: Date;
  },
): Promise<boolean> {
  const hour = input.at.toISOString().slice(0, 13);
  const urgency = urgencyOf(input.kind);
  const event: SocDomainEvent = {
    type: 'soc.alert.review_requested',
    tenantId: input.alert.tenantId,
    aggregateType: 'alert',
    aggregateId: input.alert.id,
    occurredAt: input.at,
    actorId: input.actorId,
    payload: {
      title: `Aprendizaje SOC · ${input.kind} · ${input.alert.title}`.slice(0, 300),
      priority: input.alert.effectivePriority ?? input.alert.priority,
      status: input.alert.status,
      score: input.alert.score,
      signal: input.alert.signal,
      ruleId: input.alert.ruleId,
      reasonCodes: `${LEARNING_NOTICE_PREFIX}${input.kind}`,
      relatedAlertCount: input.alert.relatedAlertIds.length,
      incidentId: input.alert.incidentId,
      urgency,
      // Agrupa por motivo, regla y hora: una ráfaga de escaladas iguales es un solo aviso.
      groupKey: `learning:${input.kind}:${input.ruleKey ?? 'sin-regla'}:${hour}`.slice(0, 200),
      investigationId: input.decisionId,
      patternId: input.patternId,
    },
  };
  return context.outbox.enqueueIfAbsent(toOutboxMessage(event, ids.next()));
}
