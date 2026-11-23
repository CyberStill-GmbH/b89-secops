/**
 * Explicación de una alerta para la consola, desde el catálogo de detección (`SocKnowledge`): el
 * caso de uso de la regla, cuándo suele ser un falso positivo, cuándo escalar, MITRE y el primer
 * paso de su runbook. Es la misma fuente que usa el aviso de Teams (`notification-enricher.ts`),
 * así la consola y la notificación dicen lo mismo. Solo datos del catálogo: nada del evento.
 */

import type { Alert } from '@b89/soc';

import { ruleForTitle, type SocKnowledge } from '../assistant/soc-knowledge.js';
import { runbookStep } from '../runtime/notification-enricher.js';

export interface AlertExplanation {
  /** Nombre del caso de uso («Rootcheck: anomalías del host…»). */
  readonly useCase: string | null;
  /** Nivel de la regla en el SIEM (0–15). */
  readonly level: number | null;
  /** Situaciones conocidas en que la regla salta sin que haya un ataque. */
  readonly falsePositives: readonly string[];
  /** Cuándo tratarla como real y escalar. */
  readonly escalateWhen: readonly string[];
  readonly mitre: ReadonlyArray<{ readonly id: string; readonly name: string | null }>;
  readonly runbook: { readonly title: string; readonly path: string; readonly firstStep: string | null } | null;
}

const LIMIT = 6;

export function explainAlertFromKnowledge(
  alert: Pick<Alert, 'ruleId' | 'title'>,
  knowledge: SocKnowledge,
): AlertExplanation | null {
  const rule =
    (alert.ruleId ? knowledge.rules[alert.ruleId] : undefined) ?? ruleForTitle(knowledge, alert.title);
  if (!rule) return null;
  const useCaseId = rule.useCases?.[0];
  const useCase = useCaseId ? knowledge.useCases.find((candidate) => candidate.id === useCaseId) : undefined;
  const runbookId = rule.runbooks?.[0];
  const runbook = runbookId ? knowledge.runbooks.find((candidate) => candidate.id === runbookId) : undefined;
  return {
    useCase: useCase?.title ?? null,
    level: Number.isInteger(rule.level) ? rule.level : null,
    falsePositives: (useCase?.falsePositives ?? []).slice(0, LIMIT),
    escalateWhen: (useCase?.escalateWhen ?? []).slice(0, LIMIT),
    mitre: rule.mitre.slice(0, 4).map((id) => ({ id, name: knowledge.techniques[id]?.name ?? null })),
    runbook: runbook
      ? { title: runbook.title, path: runbook.path, firstStep: runbookStep(runbook.markdown, rule.id) }
      : null,
  };
}
