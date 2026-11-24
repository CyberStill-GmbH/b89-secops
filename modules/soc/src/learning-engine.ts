/**
 * Aprendizaje SOC · etapa E — motor de decisión (docs/soc-learning/01-diseno.md §7, contrato de
 * canarios en docs/soc-learning/16-contrato-canarios-motor.md).
 *
 * Función pura: recibe la alerta recién creada, su huella, los patrones del tenant, las señales de
 * guarda y los contadores del patrón, y devuelve una decisión explicable (`checks`). No escribe nada:
 * los efectos los aplica `learning-engine-use-cases.ts` en la misma transacción que la alerta.
 *
 * Reglas de seguridad que no dependen de configuración:
 * - Solo autocierra P4, severidad low/informational, huella fina, patrón `active` y vigente según el
 *   reloj del servidor, con todas las guardas en verde y el contexto vigente. Cualquier guarda activa
 *   o indeterminada → `ESCALATE` (fail-closed).
 * - El modo efectivo nunca supera el techo global, y por encima de `shadow` solo para las `rule_key`
 *   listadas: la activación es por regla, nunca global.
 * - `DEMOTE` se decide y se registra, pero hoy no tiene efecto (falta `effective_priority`).
 */

import { createHmac } from 'node:crypto';

import {
  FINGERPRINT_BEHAVIOR_COMPONENTS,
  FINGERPRINT_SUBJECT_COMPONENTS,
  isHighImpactRuleKey,
  type FingerprintComponents,
  type GuardSignals,
  type Priority,
  type SignalClass,
} from '@b89/detection';

import type { Alert } from './alert.js';
import type { LearningPattern } from './learning-pattern.js';

export const LEARNING_ENGINE_VERSION = '1.0.0';

export const LEARNING_MODES = ['off', 'shadow', 'dry_run', 'active'] as const;
export type LearningMode = (typeof LEARNING_MODES)[number];

export const ENGINE_ACTIONS = ['AUTO_CLOSE', 'DEMOTE', 'ESCALATE', 'NONE'] as const;
export type EngineAction = (typeof ENGINE_ACTIONS)[number];

export const ESCALATE_REASONS = [
  'DRIFT',
  'FINGERPRINT_COLLISION',
  'GUARD_PRIORITY',
  'GUARD_SEVERITY',
  'GUARD_CRITICAL_ASSET',
  'GUARD_PRIVILEGED',
  'GUARD_IMPACT',
  'GUARD_THREAT_INTEL',
  'GUARD_CORRELATION',
  'GUARD_INCIDENT',
  'GUARD_SOURCE',
  'GUARD_CHANGE_WINDOW',
  'GUARD_CONTEXT',
  'RATE_LIMIT',
  'DAILY_CAP',
  'FORCED_REVIEW',
  'SAMPLING_UNAVAILABLE',
] as const;
export type EscalateReason = (typeof ESCALATE_REASONS)[number];

export type Confidence = 'high' | 'medium' | 'low';

export interface EngineCheck {
  readonly id: string;
  readonly ok: boolean;
  readonly detail: string;
}

/** Techo de configuración (variables de entorno; ver `learning-engine.schema.ts`). */
export interface EngineSettings {
  readonly maxMode: LearningMode;
  /** `rule_key` habilitadas por encima de `shadow`. Las demás quedan como máximo en sombra. */
  readonly activeRules: ReadonlySet<string>;
  /**
   * Capa 2 (base): modo aprobado por dos personas y vigente para cada regla. Si está presente, una
   * regla sin entrada aquí queda en sombra aunque figure en `activeRules` (capa 1, entorno).
   */
  readonly ruleModes?: ReadonlyMap<string, 'dry_run' | 'active'>;
  readonly killSwitch: boolean;
  readonly killedRules: ReadonlySet<string>;
  readonly samplingPercent: number;
  readonly hourlyCap: number;
  readonly dailyCap: number;
  readonly forcedReviewAfter: number;
  readonly neverSuppressRules: ReadonlySet<string>;
  readonly excludedSignals: ReadonlySet<string>;
  readonly excludedTactics: ReadonlySet<string>;
  readonly maxRelatedAlerts: number;
}

/** Guardas duras: la configuración solo puede endurecerlas (§6.1). */
export const LEARNING_HARD_GUARDS = Object.freeze({
  autoClosePriority: 'P4' as Priority,
  autoCloseSeverities: Object.freeze(['low', 'informational']),
  escalateSeverities: Object.freeze(['high', 'critical']),
  escalatePriorities: Object.freeze(['P1', 'P2'] as Priority[]),
  excludedSignals: Object.freeze([
    'credential_access',
    'privilege_escalation',
    'defense_evasion',
    'exfiltration',
    'persistence',
  ] as SignalClass[]),
  excludedTactics: Object.freeze([
    'lateral-movement',
    'exfiltration',
    'credential-access',
    'defense-evasion',
    'impact',
    'privilege-escalation',
    'persistence',
    'command-and-control',
  ]),
  maxRelatedAlerts: 2,
  /** Diferencias de componentes (sujeto + comportamiento) hasta las que una huella es «casi igual». */
  maxDriftComponents: 2,
  maxSamplingPercent: 100,
  minSamplingPercent: 1,
});

export const DEFAULT_ENGINE_SETTINGS: EngineSettings = Object.freeze({
  maxMode: 'off',
  activeRules: new Set<string>(),
  killSwitch: false,
  killedRules: new Set<string>(),
  samplingPercent: 10,
  hourlyCap: 10,
  dailyCap: 30,
  forcedReviewAfter: 20,
  neverSuppressRules: new Set<string>(),
  excludedSignals: new Set<string>(LEARNING_HARD_GUARDS.excludedSignals),
  excludedTactics: new Set<string>(LEARNING_HARD_GUARDS.excludedTactics),
  maxRelatedAlerts: LEARNING_HARD_GUARDS.maxRelatedAlerts,
});

/** Señales del evento que la alerta no conserva; las calcula la promoción. */
export type { GuardSignals };

/** Contexto vigente del tenant (§6.2): listas pobladas y calendario de cambios confirmado. */
export interface EngineContext {
  readonly criticalAssets: number;
  readonly privilegedIdentities: number;
  readonly changeCalendarAckUntil: Date | null;
  /** Estado de la fuente de ingesta; `null` = desconocido o vencido. */
  readonly sourceState: string | null;
  /** Clave de muestreo; sin ella no se autocierra en `dry_run`/`active`. */
  readonly samplingKey: Buffer | null;
  /** Identificador de la clave (nunca la clave): queda en cada decisión. */
  readonly samplingKeyVersion?: string | null;
}

export interface PatternCounters {
  readonly autoClosedLastHour: number;
  readonly autoClosedToday: number;
  readonly autoClosedSinceReview: number;
  readonly agreedSamplesLast30Days: number;
}

export interface EngineInput {
  readonly alert: Alert;
  readonly fingerprint: {
    readonly fingerprint: string;
    readonly level: 'fine' | 'coarse';
    readonly ruleKey: string | null;
    readonly normalizerVersion: string;
    readonly components: FingerprintComponents;
  };
  /** Patrón abierto con la misma huella exacta (si lo hay). */
  readonly exact: LearningPattern | undefined;
  /** Patrones `active` del tenant con la misma `rule_key` (para la deriva). */
  readonly sameRule: readonly LearningPattern[];
  readonly signals: GuardSignals | undefined;
  readonly counters: PatternCounters | undefined;
  readonly settings: EngineSettings;
  readonly context: EngineContext;
  readonly now: Date;
}

export interface EngineDecision {
  readonly mode: LearningMode;
  readonly patternId: string | null;
  readonly proposedAction: EngineAction;
  /** Lo que se aplica según el modo: en sombra siempre `NONE`. */
  readonly appliedAction: EngineAction;
  readonly escalateReason: EscalateReason | null;
  readonly confidence: Confidence;
  readonly checks: readonly EngineCheck[];
  readonly drift: Readonly<
    Record<string, { readonly from: string | null; readonly to: string | null }>
  > | null;
  readonly sampled: boolean;
  /** Si el motor debe pausar el patrón (ráfaga por encima del tope por hora). */
  readonly pausePattern: boolean;
  /** Si la alerta debe quedar en revisión humana obligatoria. */
  readonly review: 'quality_sample' | 'dry_run_approval' | 'forced_review' | null;
  /** `false` = no se registra (modo `off` o sin huella). */
  readonly record: boolean;
}

const MODE_RANK: Readonly<Record<LearningMode, number>> = {
  off: 0,
  shadow: 1,
  dry_run: 2,
  active: 3,
};
const ACTION_RANK: Readonly<Record<'AUTO_CLOSE' | 'DEMOTE' | 'NONE', number>> = {
  NONE: 0,
  DEMOTE: 1,
  AUTO_CLOSE: 2,
};
const SEVERITY_BY_BASE: Readonly<Record<number, string>> = {
  80: 'critical',
  60: 'high',
  40: 'medium',
  20: 'low',
  5: 'informational',
  15: 'unknown',
};

/**
 * Modo efectivo para una regla: mínimo de techo y habilitación por regla. Piso de impacto
 * inconfigurable: una regla de alto impacto nunca pasa de la sombra, diga lo que diga la configuración.
 */
export function effectiveMode(settings: EngineSettings, ruleKey: string | null): LearningMode {
  if (settings.maxMode === 'off') return 'off';
  if (isHighImpactRuleKey(ruleKey)) return 'shadow';
  const listed = ruleKey !== null && settings.activeRules.has(ruleKey);
  const perRule: LearningMode = !listed
    ? 'shadow'
    : settings.ruleModes
      ? (settings.ruleModes.get(ruleKey) ?? 'shadow')
      : 'active';
  return MODE_RANK[perRule] < MODE_RANK[settings.maxMode] ? perRule : settings.maxMode;
}

/** Severidad normalizada, deducida del ajuste `BASE_SEVERITY` cuando no llegan señales. */
export function severityOf(alert: Alert, signals: GuardSignals | undefined): string {
  if (signals) return signals.severity;
  const base = alert.reasons.find((reason) => reason.code === 'BASE_SEVERITY');
  return base ? (SEVERITY_BY_BASE[base.delta] ?? 'unknown') : 'unknown';
}

/** Selección de muestreo reproducible con la clave e imposible de predecir sin ella (D4). */
export function isSampled(key: Buffer, alertId: string, percent: number): boolean {
  const digest = createHmac('sha256', key).update(alertId, 'utf8').digest();
  return digest.readUInt32BE(0) % 100 < percent;
}

const LIMA_OFFSET_MS = 5 * 60 * 60 * 1000;
/** Inicio del día calendario de Lima que contiene `now` (para el tope diario). */
export function limaDayStart(now: Date): Date {
  const shifted = new Date(now.getTime() - LIMA_OFFSET_MS);
  shifted.setUTCHours(0, 0, 0, 0);
  return new Date(shifted.getTime() + LIMA_OFFSET_MS);
}

function decision(
  partial: Partial<EngineDecision> & Pick<EngineDecision, 'mode' | 'checks'>,
): EngineDecision {
  return {
    patternId: null,
    proposedAction: 'NONE',
    appliedAction: 'NONE',
    escalateReason: null,
    confidence: 'low',
    drift: null,
    sampled: false,
    pausePattern: false,
    review: null,
    record: true,
    ...partial,
  };
}

function escalate(
  mode: LearningMode,
  reason: EscalateReason,
  checks: readonly EngineCheck[],
  extra: Partial<EngineDecision> = {},
): EngineDecision {
  // En sombra se registra la escalada propuesta; no hay efecto que aplicar en ningún modo.
  return decision({
    mode,
    checks,
    proposedAction: 'ESCALATE',
    appliedAction: mode === 'shadow' ? 'NONE' : 'ESCALATE',
    escalateReason: reason,
    ...extra,
  });
}

function nearMatch(
  alert: FingerprintComponents,
  pattern: FingerprintComponents,
): Record<string, { from: string | null; to: string | null }> | null {
  const names = [...FINGERPRINT_SUBJECT_COMPONENTS, ...FINGERPRINT_BEHAVIOR_COMPONENTS];
  const differing = names.filter((name) => alert[name] !== pattern[name]);
  if (differing.length === 0 || differing.length > LEARNING_HARD_GUARDS.maxDriftComponents) {
    return null;
  }
  return Object.fromEntries(
    differing.map((name) => [name, { from: pattern[name], to: alert[name] }]),
  );
}

function sameComponents(left: FingerprintComponents, right: FingerprintComponents): boolean {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]) as Set<
    keyof FingerprintComponents
  >;
  return [...keys].every((key) => (left[key] ?? null) === (right[key] ?? null));
}

/** Decide qué hacer con una alerta recién creada. Ver el orden en §7.1. */
export function decideLearningAction(input: EngineInput): EngineDecision {
  const { alert, fingerprint, settings, context, now } = input;
  const ruleKey = fingerprint.ruleKey;
  const mode = effectiveMode(settings, ruleKey);
  const checks: EngineCheck[] = [];

  // 1. Modo y kill switch.
  if (mode === 'off') return decision({ mode, checks, record: false });
  if (settings.killSwitch || (ruleKey !== null && settings.killedRules.has(ruleKey))) {
    checks.push({
      id: 'KILL_SWITCH',
      ok: false,
      detail: settings.killSwitch ? 'global' : `regla ${ruleKey}`,
    });
    return decision({ mode, checks });
  }
  checks.push({ id: 'MODE', ok: true, detail: mode });

  // 2–4. Patrón exacto: activo, vigente según el reloj del servidor y con los mismos componentes.
  const exact = input.exact;
  if (!exact || exact.tenantId !== alert.tenantId) {
    // 5. Casi coincidencia: misma regla, uno o dos componentes distintos → deriva.
    for (const candidate of input.sameRule) {
      if (candidate.tenantId !== alert.tenantId || candidate.status !== 'active') continue;
      if (candidate.normalizerVersion !== fingerprint.normalizerVersion) continue;
      const drift = nearMatch(fingerprint.components, candidate.components);
      if (drift) {
        checks.push({
          id: 'DRIFT',
          ok: false,
          detail: `patrón ${candidate.id}: ${Object.keys(drift).join(', ')}`,
        });
        return escalate(mode, 'DRIFT', checks, { patternId: candidate.id, drift });
      }
    }
    checks.push({ id: 'PATTERN', ok: true, detail: 'sin patrón' });
    return decision({ mode, checks });
  }
  if (exact.status !== 'active') {
    checks.push({ id: 'PATTERN_STATUS', ok: false, detail: exact.status });
    return decision({ mode, checks, patternId: exact.id });
  }
  if (!exact.expiresAt || now.getTime() >= exact.expiresAt.getTime()) {
    checks.push({
      id: 'PATTERN_EXPIRY',
      ok: false,
      detail: `vencido ${exact.expiresAt?.toISOString() ?? '—'}`,
    });
    return decision({ mode, checks, patternId: exact.id });
  }
  if (!sameComponents(exact.components, fingerprint.components)) {
    checks.push({
      id: 'FINGERPRINT_COLLISION',
      ok: false,
      detail: 'misma huella con componentes distintos',
    });
    return escalate(mode, 'FINGERPRINT_COLLISION', checks, { patternId: exact.id });
  }
  checks.push({
    id: 'PATTERN',
    ok: true,
    detail: `${exact.id} vence ${exact.expiresAt.toISOString()}`,
  });
  const base = { patternId: exact.id };

  // 6. Guardas. La primera que corta escala; las que solo limitan bajan el techo.
  let ceiling: 'AUTO_CLOSE' | 'DEMOTE' | 'NONE' = 'AUTO_CLOSE';
  const lower = (to: 'DEMOTE' | 'NONE') => {
    if (ACTION_RANK[to] < ACTION_RANK[ceiling]) ceiling = to;
  };
  const codes = new Set(alert.reasons.map((reason) => reason.code));
  const guard = (id: string, ok: boolean, detail: string, reason: EscalateReason) => {
    checks.push({ id, ok, detail });
    return ok ? undefined : escalate(mode, reason, checks, base);
  };

  if (LEARNING_HARD_GUARDS.escalatePriorities.includes(alert.priority)) {
    return guard('PRIORITY', false, alert.priority, 'GUARD_PRIORITY')!;
  }
  checks.push({ id: 'PRIORITY', ok: true, detail: alert.priority });
  if (alert.priority !== LEARNING_HARD_GUARDS.autoClosePriority) lower('DEMOTE');

  if (!input.signals) {
    return guard(
      'EVIDENCE',
      false,
      'sin señales del evento (severidad, MITRE, inteligencia)',
      'GUARD_SOURCE',
    )!;
  }
  const severity = severityOf(alert, input.signals);
  if (LEARNING_HARD_GUARDS.escalateSeverities.includes(severity)) {
    return guard('SEVERITY', false, severity, 'GUARD_SEVERITY')!;
  }
  checks.push({ id: 'SEVERITY', ok: true, detail: severity });
  if (!LEARNING_HARD_GUARDS.autoCloseSeverities.includes(severity)) lower('DEMOTE');

  const stops: readonly [string, boolean, string, EscalateReason][] = [
    [
      'CRITICAL_ASSET',
      !codes.has('CRITICAL_ASSET'),
      'activo crítico (contexto vigente)',
      'GUARD_CRITICAL_ASSET',
    ],
    [
      'PRIVILEGED',
      !codes.has('PRIVILEGED_IDENTITY') && !codes.has('BREAK_GLASS_IDENTITY'),
      'identidad privilegiada o break-glass',
      'GUARD_PRIVILEGED',
    ],
    [
      'IMPACT',
      !codes.has('SUCCESSFUL_INTRUSION') &&
        !(alert.signal !== null && settings.excludedSignals.has(alert.signal)) &&
        !input.signals.mitreTactics.some((tactic) => settings.excludedTactics.has(tactic)) &&
        !(ruleKey !== null && settings.neverSuppressRules.has(ruleKey)) &&
        !isHighImpactRuleKey(ruleKey),
      `señal ${alert.signal ?? '—'}, tácticas ${input.signals.mitreTactics.join(',') || '—'}`,
      'GUARD_IMPACT',
    ],
    [
      'THREAT_INTEL',
      !input.signals.threatIntelHit,
      'IP en listas de inteligencia',
      'GUARD_THREAT_INTEL',
    ],
    [
      'CORRELATION',
      !codes.has('ATTACK_CHAIN') && alert.relatedAlertIds.length <= settings.maxRelatedAlerts,
      `${alert.relatedAlertIds.length} relacionadas${codes.has('ATTACK_CHAIN') ? ', cadena de compromiso' : ''}`,
      'GUARD_CORRELATION',
    ],
    ['INCIDENT', alert.incidentId === null, alert.incidentId ?? 'sin incidente', 'GUARD_INCIDENT'],
    [
      'SOURCE',
      context.sourceState === 'healthy',
      `fuente ${context.sourceState ?? 'desconocida'}`,
      'GUARD_SOURCE',
    ],
    ['CHANGE_WINDOW', !codes.has('MAINTENANCE_WINDOW'), 'ventana de cambio', 'GUARD_CHANGE_WINDOW'],
    [
      'CONTEXT',
      context.criticalAssets > 0 &&
        context.privilegedIdentities > 0 &&
        context.changeCalendarAckUntil !== null &&
        context.changeCalendarAckUntil.getTime() > now.getTime(),
      `activos ${context.criticalAssets}, privilegiadas ${context.privilegedIdentities}, calendario ${
        context.changeCalendarAckUntil?.toISOString() ?? 'sin confirmar'
      }`,
      'GUARD_CONTEXT',
    ],
  ];
  for (const [id, ok, detail, reason] of stops) {
    const stopped = guard(id, ok, detail, reason);
    if (stopped) return stopped;
  }

  // 7. Radio de daño.
  const counters = input.counters ?? {
    autoClosedLastHour: 0,
    autoClosedToday: 0,
    autoClosedSinceReview: 0,
    agreedSamplesLast30Days: 0,
  };
  if (counters.autoClosedLastHour >= settings.hourlyCap) {
    checks.push({
      id: 'RATE_LIMIT',
      ok: false,
      detail: `${counters.autoClosedLastHour}/h de ${settings.hourlyCap}`,
    });
    return escalate(mode, 'RATE_LIMIT', checks, { ...base, pausePattern: mode !== 'shadow' });
  }
  checks.push({
    id: 'RATE_LIMIT',
    ok: true,
    detail: `${counters.autoClosedLastHour}/h de ${settings.hourlyCap}`,
  });
  if (counters.autoClosedToday >= settings.dailyCap) {
    checks.push({
      id: 'DAILY_CAP',
      ok: false,
      detail: `${counters.autoClosedToday} hoy de ${settings.dailyCap}`,
    });
    return escalate(mode, 'DAILY_CAP', checks, base);
  }
  if (counters.autoClosedSinceReview >= settings.forcedReviewAfter) {
    checks.push({
      id: 'FORCED_REVIEW',
      ok: false,
      detail: `${counters.autoClosedSinceReview} cierres sin revisión humana`,
    });
    return escalate(mode, 'FORCED_REVIEW', checks, {
      ...base,
      review: mode === 'shadow' ? null : 'forced_review',
    });
  }

  // 8. Acción = mínimo entre el patrón, el nivel de la huella y el techo de las guardas.
  if (exact.maxAction === 'demote' || fingerprint.level === 'coarse') lower('DEMOTE');
  // `ceiling` cambia dentro de `lower`: TypeScript no sigue esa asignación.
  const action = ceiling as 'AUTO_CLOSE' | 'DEMOTE' | 'NONE';
  if (action === 'DEMOTE') {
    // Solo P3 → P4 (piso; P1/P2 ya escalaron arriba). En sombra se registra sin efecto; en dry-run
    // y activo se aplica (DEMOTE no oculta nada: la alerta sigue en la cola con su prioridad original).
    const applies = mode !== 'shadow' && alert.priority === 'P3';
    checks.push({
      id: 'ACTION',
      ok: true,
      detail: applies
        ? 'DEMOTE P3 → P4 (prioridad efectiva)'
        : `DEMOTE sin efecto (${mode}, ${alert.priority})`,
    });
    return decision({
      mode,
      checks,
      ...base,
      proposedAction: 'DEMOTE',
      appliedAction: applies ? 'DEMOTE' : 'NONE',
      confidence: 'low',
    });
  }

  // 9. Muestreo y efecto según el modo.
  const confidence: Confidence = counters.agreedSamplesLast30Days > 0 ? 'high' : 'medium';
  if (mode === 'shadow') {
    const sampled = context.samplingKey
      ? isSampled(context.samplingKey, alert.id, settings.samplingPercent)
      : false;
    return decision({
      mode,
      checks,
      ...base,
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'NONE',
      confidence,
      sampled,
    });
  }
  if (!context.samplingKey) {
    checks.push({ id: 'SAMPLING', ok: false, detail: 'sin clave de muestreo' });
    return escalate(mode, 'SAMPLING_UNAVAILABLE', checks, base);
  }
  const sampled = isSampled(context.samplingKey, alert.id, settings.samplingPercent);
  checks.push({ id: 'SAMPLING', ok: true, detail: sampled ? 'seleccionada' : 'no seleccionada' });
  if (mode === 'dry_run') {
    return decision({
      mode,
      checks,
      ...base,
      proposedAction: 'AUTO_CLOSE',
      appliedAction: 'NONE',
      confidence,
      sampled,
      review: 'dry_run_approval',
    });
  }
  return decision({
    mode,
    checks,
    ...base,
    proposedAction: 'AUTO_CLOSE',
    appliedAction: 'AUTO_CLOSE',
    confidence,
    sampled,
    review: sampled ? 'quality_sample' : null,
  });
}
