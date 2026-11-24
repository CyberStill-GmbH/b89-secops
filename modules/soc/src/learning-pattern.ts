/**
 * Aprendizaje SOC · etapa D — patrones de falso positivo (docs/soc-learning/01-diseno.md §2.4, §5;
 * regla de aprobación A / A+B del diseño original, elegida por el dueño el 2026-11-24).
 *
 * Funciones puras. La etapa D **no activa patrones por sí misma**: un patrón aprobado solo pasa
 * a `active` si las compuertas de preparación (`evaluateReadiness`) no tienen bloqueos. Esas
 * compuertas son las precondiciones de la etapa D que se pueden comprobar en tiempo de
 * ejecución; mientras alguna falle, el patrón queda `approved` con el motivo registrado.
 * Además, un patrón activo no tiene efecto hasta que exista el motor (etapa E).
 */

import type { FingerprintComponents, Priority } from '@b89/detection';

import type { ClosureReason } from './closure.js';
import { LEARNABLE_CLOSURE_REASONS } from './closure.js';

export const PATTERN_STATUSES = [
  'candidate',
  'pending_second_approval',
  'approved',
  'active',
  'paused',
  'expired',
  'revoked',
  'superseded',
] as const;
export type PatternStatus = (typeof PATTERN_STATUSES)[number];

/** Estados que bloquean otra fila con la misma huella (índice único parcial en SQL). */
export const OPEN_PATTERN_STATUSES: readonly PatternStatus[] = Object.freeze([
  'candidate',
  'pending_second_approval',
  'approved',
  'active',
  'paused',
]);

export type PatternMaxAction = 'auto_close' | 'demote';

export interface LearningPattern {
  readonly id: string;
  readonly tenantId: string;
  readonly ruleKey: string;
  readonly fingerprint: string;
  readonly normalizerVersion: string;
  readonly level: 'fine' | 'coarse';
  /** Componentes de la huella aprendida: el motor los compara para detectar colisión y deriva. */
  readonly components: FingerprintComponents;
  /** Una huella gruesa nunca autocierra (diseño §4.4). */
  readonly maxAction: PatternMaxAction;
  readonly closureReason: ClosureReason;
  readonly status: PatternStatus;
  readonly proposedBy: string;
  readonly ownerId: string | null;
  /** Hasta 50 alertas de origen y quiénes las cerraron (separación de funciones). */
  readonly originAlertIds: readonly string[];
  readonly originClosers: readonly string[];
  readonly confirmations: number;
  readonly distinctAlerts: number;
  readonly distinctDays: number;
  readonly distinctAnalysts: number;
  readonly truePositiveSeen: number;
  readonly priorityCeiling: Priority;
  /** Bloqueos de preparación de la última evaluación (vacío si nunca se evaluó o pasó). */
  readonly readinessBlockers: readonly ReadinessBlocker[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly activatedAt: Date | null;
  readonly expiresAt: Date | null;
  readonly renewalCount: number;
  readonly revision: number;
}

/* -------------------------------------------------------------- Candidatos */

/** Un cierre humano con motivo, junto con la huella de su alerta. */
export interface ClosureEvidence {
  readonly alertId: string;
  readonly actorId: string;
  readonly at: Date;
  readonly closureReason: ClosureReason | null;
  readonly decisionGroupId: string | null;
  readonly priority: Priority;
  readonly ruleKey: string | null;
  readonly fingerprint: string;
  readonly level: 'fine' | 'coarse';
  readonly normalizerVersion: string;
  readonly components: FingerprintComponents;
}

export interface CandidatePolicy {
  readonly minConfirmations: number;
  readonly minDistinctAlerts: number;
  readonly minDistinctDays: number;
  readonly minDistinctAnalysts: number;
  /** Un mismo analista no suma más de esto (diseño §5.2). */
  readonly maxConfirmationsPerAnalyst: number;
  readonly evidenceWindowDays: number;
  readonly tpLookbackDays: number;
}

export const DEFAULT_CANDIDATE_POLICY: CandidatePolicy = Object.freeze({
  minConfirmations: 5,
  minDistinctAlerts: 5,
  minDistinctDays: 3,
  minDistinctAnalysts: 2,
  maxConfirmationsPerAnalyst: 2,
  evidenceWindowDays: 30,
  tpLookbackDays: 90,
});

export interface Eligibility {
  readonly eligible: boolean;
  readonly confirmations: number;
  readonly distinctAlerts: number;
  readonly distinctDays: number;
  readonly distinctAnalysts: number;
  readonly truePositiveSeen: number;
  readonly priorityCeiling: Priority;
  readonly closureReason: ClosureReason | null;
  readonly originAlertIds: readonly string[];
  readonly originClosers: readonly string[];
  /** Por qué no es elegible (vacío si lo es). */
  readonly missing: readonly string[];
}

const DAY_MS = 24 * 60 * 60 * 1000;
const PRIORITY_RANK: Readonly<Record<Priority, number>> = { P1: 1, P2: 2, P3: 3, P4: 4 };

/** Día calendario en America/Lima (UTC−5, sin horario de verano). */
function limaDay(at: Date): string {
  return new Date(at.getTime() - 5 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

/**
 * Evalúa la evidencia de UNA huella. Solo cuentan cierres humanos con motivo que alimenta
 * patrones, dentro de la ventana; cada `decisionGroupId` (cierre en bloque) es UNA confirmación
 * y un analista aporta como máximo `maxConfirmationsPerAnalyst`. `truePositives` son los cierres
 * TP_REAL de la misma huella en `tpLookbackDays`.
 */
export function evaluateEligibility(
  evidence: readonly ClosureEvidence[],
  truePositives: number,
  now: Date,
  policy: CandidatePolicy = DEFAULT_CANDIDATE_POLICY,
): Eligibility {
  const since = now.getTime() - policy.evidenceWindowDays * DAY_MS;
  const learnable = evidence.filter(
    (item) =>
      item.closureReason !== null &&
      LEARNABLE_CLOSURE_REASONS.includes(item.closureReason) &&
      item.at.getTime() >= since &&
      item.at.getTime() <= now.getTime(),
  );
  const decisions = new Map<string, ClosureEvidence>();
  for (const item of learnable) {
    const key = item.decisionGroupId ?? `alert:${item.alertId}`;
    if (!decisions.has(key)) decisions.set(key, item);
  }
  const perAnalyst = new Map<string, number>();
  let confirmations = 0;
  for (const item of [...decisions.values()].sort((a, b) => a.at.getTime() - b.at.getTime())) {
    const used = perAnalyst.get(item.actorId) ?? 0;
    if (used >= policy.maxConfirmationsPerAnalyst) continue;
    perAnalyst.set(item.actorId, used + 1);
    confirmations += 1;
  }
  const distinctAlerts = new Set(learnable.map((item) => item.alertId)).size;
  const distinctDays = new Set(learnable.map((item) => limaDay(item.at))).size;
  const distinctAnalysts = new Set(learnable.map((item) => item.actorId)).size;
  const priorityCeiling = learnable.reduce<Priority>(
    (highest, item) =>
      PRIORITY_RANK[item.priority] < PRIORITY_RANK[highest] ? item.priority : highest,
    'P4',
  );
  const reasons = new Map<ClosureReason, number>();
  for (const item of learnable)
    reasons.set(item.closureReason!, (reasons.get(item.closureReason!) ?? 0) + 1);
  const closureReason =
    [...reasons.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0]?.[0] ?? null;

  const missing: string[] = [];
  if (confirmations < policy.minConfirmations) missing.push('CONFIRMATIONS');
  if (distinctAlerts < policy.minDistinctAlerts) missing.push('DISTINCT_ALERTS');
  if (distinctDays < policy.minDistinctDays) missing.push('DISTINCT_DAYS');
  if (distinctAnalysts < policy.minDistinctAnalysts) missing.push('DISTINCT_ANALYSTS');
  if (truePositives > 0) missing.push('TRUE_POSITIVE_SEEN');
  return {
    eligible: missing.length === 0,
    confirmations,
    distinctAlerts,
    distinctDays,
    distinctAnalysts,
    truePositiveSeen: truePositives,
    priorityCeiling,
    closureReason,
    originAlertIds: [...new Set(learnable.map((item) => item.alertId))].slice(0, 50),
    originClosers: [...new Set(learnable.map((item) => item.actorId))].sort(),
    missing,
  };
}

/* -------------------------------------------------------------- Aprobación */

export interface ApprovalRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly patternId: string;
  readonly patternRevision: number;
  readonly stage: 'first' | 'second';
  readonly approverId: string;
  readonly decision: 'approve' | 'reject';
  readonly comment: string;
  readonly at: Date;
}

export const APPROVAL_ERROR_CODES = [
  'NOT_A_DESIGNATED_APPROVER',
  'SERVICE_IDENTITY',
  'APPROVER_IS_PROPOSER',
  'APPROVER_CLOSED_ORIGIN_ALERTS',
  'SAME_APPROVER_TWICE',
  'NOT_AWAITING_APPROVAL',
  'COMMENT_REQUIRED',
] as const;
export type ApprovalErrorCode = (typeof APPROVAL_ERROR_CODES)[number];

/**
 * ¿Hace falta un segundo aprobador? Diseño original §5.3: sí si la prioridad más alta vista es
 * P1–P3, si el alcance es amplio (no aplica: hoy los patrones son exactos) o si la acción máxima
 * es autocerrar en la PRIMERA activación (el primer autocierre de un patrón es el de mayor riesgo).
 */
export function requiresSecondApprover(pattern: LearningPattern): boolean {
  return (
    pattern.priorityCeiling !== 'P4' ||
    (pattern.maxAction === 'auto_close' && pattern.renewalCount === 0)
  );
}

export type ApprovalCheck =
  | { readonly ok: true; readonly stage: 'first' | 'second'; readonly next: PatternStatus }
  | { readonly ok: false; readonly code: ApprovalErrorCode };

/**
 * Valida una firma. `firstApproverId` es quien firmó la primera etapa (si la hubo). Nunca firma
 * una identidad de servicio, quien propuso ni quien cerró alguna alerta de origen.
 */
export function checkApproval(
  pattern: LearningPattern,
  approverId: string,
  designatedApprovers: readonly string[],
  firstApproverId: string | null,
): ApprovalCheck {
  if (approverId.startsWith('svc:')) return { ok: false, code: 'SERVICE_IDENTITY' };
  if (!designatedApprovers.includes(approverId))
    return { ok: false, code: 'NOT_A_DESIGNATED_APPROVER' };
  if (approverId === pattern.proposedBy) return { ok: false, code: 'APPROVER_IS_PROPOSER' };
  if (pattern.originClosers.includes(approverId))
    return { ok: false, code: 'APPROVER_CLOSED_ORIGIN_ALERTS' };
  if (pattern.status === 'candidate') {
    return {
      ok: true,
      stage: 'first',
      next: requiresSecondApprover(pattern) ? 'pending_second_approval' : 'approved',
    };
  }
  if (pattern.status === 'pending_second_approval') {
    if (firstApproverId === approverId) return { ok: false, code: 'SAME_APPROVER_TWICE' };
    return { ok: true, stage: 'second', next: 'approved' };
  }
  return { ok: false, code: 'NOT_AWAITING_APPROVAL' };
}

/* ------------------------------------------------- Compuertas de preparación */

export const READINESS_BLOCKERS = [
  'CLOSURE_REASON_NOT_REQUIRED',
  'APPROVERS_NOT_CONFIGURED',
  'BACKFILL_PENDING',
  'SOURCE_COVERAGE_UNMEASURED',
  'SOURCE_COVERAGE_BELOW_THRESHOLD',
  'RULE_ID_COLLISION',
  'NORMALIZER_OUTDATED',
] as const;
export type ReadinessBlocker = (typeof READINESS_BLOCKERS)[number];

/** Estado del entorno: lo aporta un puerto en cada evaluación (nada se guarda en caché). */
export interface ReadinessSnapshot {
  /** Precondición 3: `B89_SOC_CLOSURE_REASON_REQUIRED=true`. */
  readonly closureReasonRequired: boolean;
  /** Precondición 7: aprobadores designados por persona. */
  readonly designatedApprovers: number;
  /** Precondición 2: alertas cerradas sin `closure_origin` (etiquetado retroactivo pendiente). */
  readonly closedAlertsWithoutOrigin: number;
  /** Precondición 4: huellas finas / totales por fuente (prefijo de rule_key) en la ventana. */
  readonly sourceCoverage: ReadonlyMap<string, { readonly fine: number; readonly total: number }>;
  /** Precondición 8: claves de regla con IDs repetidos entre fuentes. */
  readonly collidingRuleKeys: ReadonlySet<string>;
  readonly currentNormalizerVersion: string;
}

export interface ReadinessPolicy {
  readonly minFineShare: number;
  /** Debajo de esta muestra la cobertura no se considera medida. */
  readonly minSourceSample: number;
}

export const DEFAULT_READINESS_POLICY: ReadinessPolicy = Object.freeze({
  minFineShare: 0.5,
  minSourceSample: 100,
});

export function sourceOf(ruleKey: string): string {
  const separator = ruleKey.indexOf(':');
  return separator > 0 ? ruleKey.slice(0, separator) : ruleKey;
}

/** Bloqueos que impiden activar este patrón ahora. Vacío = puede activarse. Fail-closed. */
export function evaluateReadiness(
  pattern: LearningPattern,
  snapshot: ReadinessSnapshot,
  policy: ReadinessPolicy = DEFAULT_READINESS_POLICY,
): ReadinessBlocker[] {
  const blockers: ReadinessBlocker[] = [];
  if (!snapshot.closureReasonRequired) blockers.push('CLOSURE_REASON_NOT_REQUIRED');
  if (snapshot.designatedApprovers < 2) blockers.push('APPROVERS_NOT_CONFIGURED');
  if (snapshot.closedAlertsWithoutOrigin > 0) blockers.push('BACKFILL_PENDING');
  const coverage = snapshot.sourceCoverage.get(sourceOf(pattern.ruleKey));
  if (!coverage || coverage.total < policy.minSourceSample)
    blockers.push('SOURCE_COVERAGE_UNMEASURED');
  else if (coverage.fine / coverage.total < policy.minFineShare) {
    blockers.push('SOURCE_COVERAGE_BELOW_THRESHOLD');
  }
  if (snapshot.collidingRuleKeys.has(pattern.ruleKey)) blockers.push('RULE_ID_COLLISION');
  if (pattern.normalizerVersion !== snapshot.currentNormalizerVersion)
    blockers.push('NORMALIZER_OUTDATED');
  return blockers;
}

/** Entradas del entorno con que se arma la foto de preparación en cada refresco. */
export interface ReadinessInputs {
  readonly closureReasonRequired: boolean;
  readonly approvers: readonly string[];
  readonly closedAlertsWithoutOrigin: number;
  readonly sourceCoverage: ReadonlyMap<string, { readonly fine: number; readonly total: number }>;
  readonly collidingRuleKeys: ReadonlySet<string>;
  readonly currentNormalizerVersion: string;
}

/** Solo cuentan personas distintas: una identidad de servicio nunca es aprobador. */
export function readinessSnapshotFrom(inputs: ReadinessInputs): ReadinessSnapshot {
  const people = new Set(
    inputs.approvers.map((id) => id.trim()).filter((id) => id.length > 0 && !id.startsWith('svc:')),
  );
  return {
    closureReasonRequired: inputs.closureReasonRequired,
    designatedApprovers: people.size,
    closedAlertsWithoutOrigin: inputs.closedAlertsWithoutOrigin,
    sourceCoverage: inputs.sourceCoverage,
    collidingRuleKeys: inputs.collidingRuleKeys,
    currentNormalizerVersion: inputs.currentNormalizerVersion,
  };
}

/* ------------------------------------------------------------ Ciclo de vida */

export const FIRST_ACTIVATION_DAYS = 30;
export const RENEWAL_DAYS = 90;

export function expiryFor(pattern: LearningPattern, now: Date): Date {
  const days = pattern.renewalCount === 0 ? FIRST_ACTIVATION_DAYS : RENEWAL_DAYS;
  return new Date(now.getTime() + days * DAY_MS);
}

/**
 * Transición automática de un patrón en cada refresco (sin firmas): TP visto, normalizador viejo,
 * vencimiento y activación de un aprobado cuando las compuertas pasan.
 */
export function nextAutomaticState(
  pattern: LearningPattern,
  context: {
    readonly now: Date;
    readonly truePositives: number;
    readonly blockers: readonly ReadinessBlocker[];
    readonly currentNormalizerVersion: string;
  },
): { readonly status: PatternStatus; readonly reason: string } | undefined {
  const open = OPEN_PATTERN_STATUSES.includes(pattern.status);
  if (!open) return undefined;
  if (pattern.normalizerVersion !== context.currentNormalizerVersion) {
    return { status: 'superseded', reason: 'NORMALIZER_CHANGED' };
  }
  if (context.truePositives > 0) {
    return pattern.status === 'active'
      ? { status: 'paused', reason: 'TRUE_POSITIVE_ON_FINGERPRINT' }
      : pattern.status === 'paused'
        ? undefined
        : { status: 'revoked', reason: 'TRUE_POSITIVE_ON_FINGERPRINT' };
  }
  // Vence por reloj del servidor, también en pausa: reanudar no puede extender la vigencia.
  if (
    (pattern.status === 'active' || pattern.status === 'paused') &&
    pattern.expiresAt &&
    context.now >= pattern.expiresAt
  ) {
    return { status: 'expired', reason: 'EXPIRED' };
  }
  // Fail-closed: si una precondición deja de cumplirse, un patrón activo se pausa.
  if (pattern.status === 'active' && context.blockers.length > 0) {
    return { status: 'paused', reason: 'READINESS_REGRESSED' };
  }
  if (pattern.status === 'approved' && context.blockers.length === 0) {
    return { status: 'active', reason: 'READINESS_PASSED' };
  }
  return undefined;
}
