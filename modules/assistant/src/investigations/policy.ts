/**
 * Analista IA — política determinista de triaje (pura y versionada).
 *
 * Decide, SIN modelo, si un trabajo se resuelve con reglas o si merece una inferencia y de qué
 * nivel. Solo lee campos estructurados (prioridad, conteos, fuentes, tácticas, historial,
 * cobertura): el título u otro texto de la alerta no puede cambiar el nivel ni el presupuesto.
 *
 * Nada aquí cierra, suprime ni rebaja una alerta: un patrón benigno conocido produce
 * `likely_false_positive` en `requires_review`, y nunca se aplica a P1.
 */

import type { Citation } from '../ports.js';
import type {
  EvidenceBundle,
  InferenceTier,
  InvestigationConfidence,
  InvestigationPriority,
  InvestigationResult,
  InvestigationSubject,
  InvestigationVerdict,
} from './types.js';

/** Cambiar umbrales, razones o el prompt exige una versión nueva. */
// 2026-11-14.1: el paquete incluye el contexto ampliado del SOC (`EvidenceBundle.context`).
export const POLICY_VERSION = 'b89-analyst-2026-11-14.1';

export interface TriageConfig {
  /** Cierres `false_positive` de la misma regla+entidad (30 d) para considerar el patrón benigno. */
  readonly knownBenignMinFalsePositives: number;
  /** Fuentes o tácticas distintas que vuelven ambiguo un P2. */
  readonly ambiguousMinSources: number;
  readonly ambiguousMinTactics: number;
  /** Estados de fuente que invalidan la cobertura (además de `fresh: false`). */
  readonly unhealthySourceStates: readonly string[];
  /** Tope de tokens de salida por nivel (el runner aplica además su límite global). */
  readonly maxOutputTokens: Readonly<Record<InferenceTier, number>>;
}

export const TRIAGE_CONFIG: TriageConfig = Object.freeze({
  knownBenignMinFalsePositives: 5,
  ambiguousMinSources: 2,
  ambiguousMinTactics: 2,
  unhealthySourceStates: Object.freeze(['failed', 'unknown']),
  maxOutputTokens: Object.freeze({ economy: 700, advanced: 1200 }),
});

export const TRIAGE_REASON_CODES = [
  'NOT_ELIGIBLE',
  'ISOLATED_LOW_SIGNAL',
  'DUPLICATE_OF_OPEN_INCIDENT',
  'EVIDENCE_INCOMPLETE',
  'KNOWN_BENIGN_PATTERN',
  'P1_ALWAYS_ANALYZED',
  'P2_ROUTINE',
  'P2_MULTI_SOURCE',
  'P2_MULTI_TACTIC',
  'P2_CONTRADICTORY_HISTORY',
  'P3_CORRELATED',
  'OUT_OF_SCOPE',
  'BELOW_INFERENCE_PRIORITY',
] as const;
export type TriageReasonCode = (typeof TRIAGE_REASON_CODES)[number];

/** Códigos que agrega el runner a `result.deterministic.reasons`. */
export const RUNNER_REASON_CODES = [
  'INFERENCE_DISABLED',
  'MODEL_UNAVAILABLE',
  'TIER_DOWNGRADED',
  'EVIDENCE_PACK_OVER_BUDGET',
  'REUSED_PRIOR_RESULT',
  'PRIOR_INFERENCE_SETTLED',
  'DAILY_CAP',
  'RUN_CAP',
  'USAGE_UNRECONCILED',
  'MODEL_REFUSED',
  'INVALID_MODEL_OUTPUT',
  'UNVERIFIED_OUTPUT',
  'ANALYST_DISABLED',
] as const;
export type RunnerReasonCode = (typeof RUNNER_REASON_CODES)[number];

export interface TriageInput {
  readonly priority: InvestigationPriority;
  readonly bundle: EvidenceBundle;
  /** Alcance fijado por el administrador (`AnalystSettings.scope`). Sin él, todo es elegible. */
  readonly scope?: {
    readonly priorities: readonly InvestigationPriority[];
    readonly inferenceMinPriority: InvestigationPriority;
  };
}

export interface TriageDecision {
  readonly decision: 'deterministic' | 'infer';
  /** Solo con `decision: 'infer'`. */
  readonly tier?: InferenceTier;
  readonly reasons: readonly TriageReasonCode[];
  /** 0 cuando no hay inferencia. */
  readonly maxOutputTokens: number;
  /** La evidencia está incompleta: el estado final no puede ser `completed`. */
  readonly partial: boolean;
  /** Estado final del expediente determinista (también el respaldo si la inferencia no ocurre). */
  readonly status: 'completed' | 'requires_review' | 'partial';
  readonly verdict: InvestigationVerdict;
  readonly confidence: InvestigationConfidence;
}

function distinct(values: readonly (string | null | undefined)[]): string[] {
  return [...new Set(values.filter((value): value is string => !!value))];
}

export function isCorrelatedEvidence(bundle: EvidenceBundle): boolean {
  return isCorrelated(bundle);
}

export function evidenceSources(bundle: EvidenceBundle): string[] {
  return distinct([
    ...bundle.alerts.map((alert) => alert.source),
    ...(bundle.candidate?.sources ?? []),
  ]);
}

export function unhealthySources(bundle: EvidenceBundle, config: TriageConfig = TRIAGE_CONFIG) {
  return bundle.sourceHealth.filter(
    (source) =>
      source.state !== 'disabled' &&
      (!source.fresh || config.unhealthySourceStates.includes(source.state)),
  );
}

function isCorrelated(bundle: EvidenceBundle): boolean {
  return (
    bundle.alerts.length > 1 ||
    bundle.relatedAlerts.length > 0 ||
    bundle.alerts.some((alert) => alert.relatedAlertIds.length > 0) ||
    (bundle.candidate?.memberCount ?? 0) > 1
  );
}

/** Decisión determinista. Pura: misma entrada estructurada ⇒ misma salida. */
export function triagePolicy(
  input: TriageInput,
  config: TriageConfig = TRIAGE_CONFIG,
): TriageDecision {
  const { priority, bundle } = input;
  const deterministic = (
    reasons: readonly TriageReasonCode[],
    status: TriageDecision['status'],
    verdict: InvestigationVerdict = 'inconclusive',
    confidence: InvestigationConfidence = 'low',
  ): TriageDecision => ({
    decision: 'deterministic',
    reasons,
    maxOutputTokens: 0,
    partial: status === 'partial',
    status,
    verdict,
    confidence,
  });

  if (input.scope && !input.scope.priorities.includes(priority)) {
    return deterministic(['OUT_OF_SCOPE'], 'completed');
  }

  const { history } = bundle;
  const incomplete =
    !bundle.completeness.complete ||
    bundle.completeness.truncated ||
    bundle.alerts.length === 0 ||
    unhealthySources(bundle, config).length > 0;
  const benignHistory =
    history.truePositive === 0 && history.falsePositive >= config.knownBenignMinFalsePositives;
  /** Baja prioridad sin modelo; si además el historial es benigno y completo, lo deja dicho. */
  const lowSignal = (reason: TriageReasonCode): TriageDecision =>
    benignHistory && !incomplete
      ? deterministic(
          [reason, 'KNOWN_BENIGN_PATTERN'],
          'completed',
          'likely_false_positive',
          'medium',
        )
      : deterministic([reason], 'completed');

  if (priority === 'P4') return lowSignal('NOT_ELIGIBLE');

  const sources = evidenceSources(bundle);
  const correlated = isCorrelated(bundle);
  if (priority === 'P3' && !correlated) {
    return lowSignal(sources.length <= 1 ? 'ISOLATED_LOW_SIGNAL' : 'NOT_ELIGIBLE');
  }

  // Ya hay personas trabajando el incidente: el expediente solo apunta a él.
  if (bundle.alerts.length > 0 && bundle.alerts.every((alert) => !!alert.incidentId)) {
    return deterministic(['DUPLICATE_OF_OPEN_INCIDENT'], 'completed');
  }

  if (incomplete && priority !== 'P1') return deterministic(['EVIDENCE_INCOMPLETE'], 'partial');

  if (priority !== 'P1' && benignHistory) {
    // Nunca autocierre: la recomendación queda para revisión humana.
    return deterministic(
      ['KNOWN_BENIGN_PATTERN'],
      'requires_review',
      'likely_false_positive',
      'medium',
    );
  }

  // 'P1' < 'P2' < 'P3' < 'P4' en orden lexicográfico: mayor cadena, menor prioridad.
  if (input.scope && priority > input.scope.inferenceMinPriority) {
    return deterministic(['BELOW_INFERENCE_PRIORITY'], incomplete ? 'partial' : 'completed');
  }

  const reasons: TriageReasonCode[] = [];
  let tier: InferenceTier = 'economy';
  if (priority === 'P1') {
    tier = 'advanced';
    reasons.push('P1_ALWAYS_ANALYZED');
    if (incomplete) reasons.push('EVIDENCE_INCOMPLETE');
  } else if (priority === 'P2') {
    if (sources.length >= config.ambiguousMinSources) reasons.push('P2_MULTI_SOURCE');
    if (distinct(bundle.candidate?.tactics ?? []).length >= config.ambiguousMinTactics) {
      reasons.push('P2_MULTI_TACTIC');
    }
    if (history.truePositive > 0 && history.falsePositive > 0) {
      reasons.push('P2_CONTRADICTORY_HISTORY');
    }
    if (reasons.length > 0) tier = 'advanced';
    else reasons.push('P2_ROUTINE');
  } else {
    reasons.push('P3_CORRELATED');
  }

  return {
    decision: 'infer',
    tier,
    reasons,
    maxOutputTokens: config.maxOutputTokens[tier],
    partial: incomplete,
    // Respaldo si la inferencia no llega a ocurrir: P1/P2/P3 correlado sin análisis ⇒ revisión.
    status: incomplete ? 'partial' : 'requires_review',
    verdict: 'inconclusive',
    confidence: 'low',
  };
}

const MAX_CITED = 12;

/**
 * Expediente determinista (sin modelo), armado solo con conteos e IDs de la evidencia. Es el
 * resultado final de la vía determinista y el respaldo cuando la inferencia no se hace.
 */
export function buildDeterministicResult(input: {
  readonly subject: InvestigationSubject;
  readonly priority: InvestigationPriority;
  readonly bundle: EvidenceBundle;
  readonly decision: TriageDecision;
  /** Códigos del runner que explican por qué no hubo inferencia. */
  readonly extraReasons?: readonly string[];
}): InvestigationResult {
  const { bundle, decision, priority } = input;
  const reasons = [...decision.reasons, ...(input.extraReasons ?? [])];
  const alertIds = bundle.alerts.slice(0, MAX_CITED).map((alert) => alert.id);
  const incidentIds = distinct(bundle.alerts.map((alert) => alert.incidentId));
  const unhealthy = unhealthySources(bundle);
  const citations: Citation[] = [
    ...bundle.alerts
      .slice(0, MAX_CITED)
      .map((alert): Citation => ({ kind: 'alert', id: alert.id, label: `Alerta ${alert.id}` })),
    ...incidentIds
      .slice(0, MAX_CITED)
      .map((id): Citation => ({ kind: 'incident', id, label: `Incidente ${id}` })),
    ...unhealthy
      .slice(0, MAX_CITED)
      .map((source): Citation => ({ kind: 'source', id: source.id, label: source.label })),
  ];

  const facts: { text: string; citations: string[] }[] = [];
  if (alertIds.length > 0) {
    facts.push({
      text: `El expediente agrupa ${bundle.alerts.length} alerta(s) de prioridad ${priority} y ${bundle.relatedAlerts.length} alerta(s) relacionada(s).`,
      citations: alertIds,
    });
    facts.push({
      text: `Historial de la misma regla y entidad en 30 días: ${bundle.history.total} en total, ${bundle.history.falsePositive} falso(s) positivo(s), ${bundle.history.truePositive} verdadero(s) positivo(s), ${bundle.history.open} abierta(s).`,
      citations: alertIds,
    });
  }
  if (incidentIds.length > 0) {
    facts.push({
      text: `Las alertas ya están unidas a incidente(s) abierto(s): ${incidentIds.join(', ')}.`,
      citations: incidentIds.slice(0, MAX_CITED),
    });
  }
  if (unhealthy.length > 0) {
    facts.push({
      text: `Fuentes sin datos frescos o con falla al leer: ${unhealthy.map((source) => source.id).join(', ')}.`,
      citations: unhealthy.slice(0, MAX_CITED).map((source) => source.id),
    });
  }

  const gaps = bundle.completeness.gaps.slice(0, 6);
  if (bundle.completeness.truncated) gaps.push('La lectura de evidencia quedó truncada.');
  if (!reasons.includes('NOT_ELIGIBLE') && decision.decision === 'infer') {
    gaps.push('No se ejecutó análisis con modelo para este expediente.');
  }

  const summary = reasons.includes('DUPLICATE_OF_OPEN_INCIDENT')
    ? `Expediente determinista: las alertas ya pertenecen al incidente ${incidentIds.join(', ')}; el trabajo continúa allí.`
    : reasons.includes('KNOWN_BENIGN_PATTERN')
      ? 'Expediente determinista: el historial de esta regla y entidad solo registra cierres como falso positivo. Probable falso positivo; requiere confirmación humana.'
      : reasons.includes('EVIDENCE_INCOMPLETE') && decision.decision === 'deterministic'
        ? 'Expediente determinista parcial: la evidencia está incompleta o hay fuentes sin datos frescos; no se emite conclusión.'
        : reasons.includes('ISOLATED_LOW_SIGNAL')
          ? 'Expediente determinista: alerta aislada de baja señal, sin correlación con otras alertas ni fuentes.'
          : reasons.includes('NOT_ELIGIBLE')
            ? 'Expediente determinista: la prioridad no es elegible para análisis con modelo.'
            : 'Expediente determinista (sin análisis de IA): se listan los datos estructurados disponibles; requiere revisión humana.';

  const nextSteps = reasons.includes('DUPLICATE_OF_OPEN_INCIDENT')
    ? ['Revisar el incidente abierto y agregar allí cualquier hallazgo nuevo.']
    : reasons.includes('KNOWN_BENIGN_PATTERN')
      ? [
          'Confirmar con una persona si corresponde a la actividad benigna ya conocida.',
          'Si el patrón se repite, proponer el ajuste de la regla por el proceso de ingeniería de detección.',
        ]
      : decision.status === 'completed'
        ? ['Atender la alerta en la cola humana según su prioridad.']
        : ['Revisar la alerta en la cola humana; el expediente no reemplaza el triaje.'];

  return {
    summary,
    verdict: decision.verdict,
    confidence: decision.confidence,
    recommendedPriority: null,
    facts,
    inferences: [],
    gaps,
    nextSteps,
    citations,
    verified: true,
    deterministic: { reasons },
  };
}
