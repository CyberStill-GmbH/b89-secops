/**
 * Aprendizaje SOC · fase 2 — salud del propio motor (meta-monitoreo).
 *
 * Función pura: a partir de métricas agregadas (sin PII) decide el estado y las alertas, cada una
 * con severidad y enlace a su runbook (docs/soc-learning/25-runbooks-motor.md). El mismo criterio
 * lo aplica el monitor de plataforma leyendo la base, para que el latido se vigile aunque el API
 * esté caído (dead man's switch).
 */

import type { EngineAction } from './learning-engine.js';

export interface LearningHealthMetrics {
  readonly enabled: boolean;
  readonly maxMode: 'off' | 'shadow' | 'dry_run' | 'active';
  readonly killSwitch: boolean;
  readonly heartbeatAt: Date | null;
  readonly backlog: {
    readonly pending: number;
    readonly expiredLeases: number;
    readonly oldestPendingAt: Date | null;
  };
  readonly deadLast24h: number;
  readonly lastHour: {
    readonly jobsFinished: number;
    readonly jobsRetried: number;
    /** Encolado → decisión, p95 en ms; `null` sin trabajos terminados. */
    readonly latencyP95Ms: number | null;
    readonly decisions: number;
    readonly byApplied: Readonly<Partial<Record<EngineAction, number>>>;
    readonly byEscalateReason: Readonly<Record<string, number>>;
    /** Cierres que el motor habría hecho (sombra o dry-run). */
    readonly hypotheticalCloses: number;
  };
  readonly last24h: {
    readonly pauses: number;
    readonly reversals: number;
    readonly disagreements: number;
    readonly configChanges: number;
    readonly modeRaised: boolean;
  };
  readonly sourceState: string | null;
  /** Fase 3: el motor se pausó solo (avisos sin entregar) y está en sombra. */
  readonly enginePaused?: boolean;
  /** Fase 3: se pidió dry_run/activo sin canal de notificación: quedó en sombra. */
  readonly channelMissing?: boolean;
  /** Fase 3: días desde la emisión de la clave de muestreo; `null` = fecha desconocida. */
  readonly samplingKeyAgeDays?: number | null;
}

export type HealthSeverity = 'critical' | 'warning' | 'info';

export interface LearningHealthAlert {
  readonly id: string;
  readonly severity: HealthSeverity;
  readonly summary: string;
  readonly runbook: string;
}

export interface LearningHealthPolicy {
  /** Sin latido en este tiempo: el worker está caído. */
  readonly heartbeatMaxAgeMs: number;
  readonly backlogWarnMs: number;
  readonly backlogCriticalMs: number;
  readonly latencyP95WarnMs: number;
  readonly retryRateWarn: number;
  readonly escalationRateWarn: number;
  readonly minDecisionsForRates: number;
  readonly deadCritical: number;
}

export const DEFAULT_LEARNING_HEALTH_POLICY: LearningHealthPolicy = Object.freeze({
  heartbeatMaxAgeMs: 5 * 60_000,
  backlogWarnMs: 5 * 60_000,
  backlogCriticalMs: 30 * 60_000,
  latencyP95WarnMs: 60_000,
  retryRateWarn: 0.05,
  escalationRateWarn: 0.5,
  minDecisionsForRates: 20,
  deadCritical: 10,
});

/** SLOs propuestos para la sombra (docs/soc-learning/24-despliegue-sombra.md §4). */
export const LEARNING_SLOS = Object.freeze([
  { id: 'decision_latency', objective: 'p95 encolado → decisión ≤ 60 s', window: '1 h' },
  {
    id: 'decision_completeness',
    objective: '≥ 99 % de trabajos decididos en ≤ 5 min',
    window: '24 h',
  },
  { id: 'dead_letters', objective: '0 trabajos en dead-letter', window: '24 h' },
  { id: 'heartbeat', objective: 'latido ≤ 5 min el 99,9 % del tiempo', window: '30 d' },
  {
    id: 'ingest_isolation',
    objective: 'p95 de la ingesta sin cambio significativo con el motor encendido',
    window: '24 h',
  },
]);

const RUNBOOK = 'docs/soc-learning/25-runbooks-motor.md';

export interface LearningHealthReport {
  readonly status: 'OK' | 'DEGRADED' | 'CRITICAL' | 'OFF';
  readonly alerts: readonly LearningHealthAlert[];
}

export function evaluateLearningHealth(
  metrics: LearningHealthMetrics,
  now: Date,
  policy: LearningHealthPolicy = DEFAULT_LEARNING_HEALTH_POLICY,
): LearningHealthReport {
  const alerts: LearningHealthAlert[] = [];
  const add = (id: string, severity: HealthSeverity, summary: string, anchor: string) =>
    alerts.push({ id, severity, summary, runbook: `${RUNBOOK}#${anchor}` });

  // La configuración se vigila también con el motor apagado: subir el techo es un evento.
  if (metrics.last24h.configChanges > 0) {
    add(
      'CONFIG_CHANGED',
      metrics.last24h.modeRaised ? 'critical' : 'warning',
      `${metrics.last24h.configChanges} cambio(s) de configuración del motor en 24 h${
        metrics.last24h.modeRaised ? ', con subida del techo de modo' : ''
      }.`,
      'configuracion-cambiada',
    );
  }
  if (metrics.killSwitch) add('KILL_SWITCH', 'info', 'Kill switch global activo.', 'kill-switch');
  if (metrics.channelMissing) {
    add(
      'NOTIFICATION_CHANNEL_MISSING',
      'critical',
      'Se pidió dry_run/activo sin canal de notificación: el motor quedó en sombra.',
      'escalacion-sin-entrega',
    );
  }
  if (
    metrics.samplingKeyAgeDays === null &&
    metrics.maxMode !== 'shadow' &&
    metrics.maxMode !== 'off'
  ) {
    add(
      'SAMPLING_KEY_UNDATED',
      'warning',
      'Clave de muestreo sin fecha de emisión: no se puede vigilar su rotación.',
      'clave-comprometida',
    );
  }
  if (typeof metrics.samplingKeyAgeDays === 'number' && metrics.samplingKeyAgeDays > 90) {
    add(
      'SAMPLING_KEY_ROTATION_DUE',
      metrics.samplingKeyAgeDays > 120 ? 'critical' : 'warning',
      `Clave de muestreo emitida hace ${metrics.samplingKeyAgeDays} días: rotar (≤ 90).`,
      'clave-comprometida',
    );
  }
  if (metrics.enginePaused) {
    add(
      'ENGINE_SELF_PAUSED',
      'critical',
      'El motor se pausó solo: avisos de escalada sin entregar a tiempo. Está en sombra.',
      'escalacion-sin-entrega',
    );
  }
  if (!metrics.enabled || metrics.maxMode === 'off') {
    return { status: 'OFF', alerts };
  }

  const age = (at: Date | null) =>
    at === null ? Number.POSITIVE_INFINITY : now.getTime() - at.getTime();
  const heartbeatAge = age(metrics.heartbeatAt);
  if (heartbeatAge > policy.heartbeatMaxAgeMs) {
    add(
      'HEARTBEAT_STALE',
      'critical',
      metrics.heartbeatAt === null
        ? 'El worker del motor nunca registró un latido.'
        : `Sin latido del worker hace ${Math.round(heartbeatAge / 60_000)} min.`,
      'motor-caido',
    );
  }
  const backlogAge = age(metrics.backlog.oldestPendingAt);
  if (metrics.backlog.pending > 0 && backlogAge > policy.backlogWarnMs) {
    add(
      'BACKLOG_AGE',
      backlogAge > policy.backlogCriticalMs ? 'critical' : 'warning',
      `${metrics.backlog.pending} trabajo(s) pendiente(s); el más viejo espera ${Math.round(backlogAge / 60_000)} min.`,
      'cola-atrasada',
    );
  }
  if (metrics.backlog.expiredLeases > 0) {
    add(
      'EXPIRED_LEASES',
      'warning',
      `${metrics.backlog.expiredLeases} trabajo(s) con lease vencido.`,
      'cola-atrasada',
    );
  }
  if (metrics.deadLast24h > 0) {
    add(
      'DEAD_LETTERS',
      metrics.deadLast24h >= policy.deadCritical ? 'critical' : 'warning',
      `${metrics.deadLast24h} trabajo(s) en dead-letter en 24 h (esas alertas quedaron con personas).`,
      'dead-letter',
    );
  }
  const hour = metrics.lastHour;
  if (hour.latencyP95Ms !== null && hour.latencyP95Ms > policy.latencyP95WarnMs) {
    add(
      'LATENCY_P95',
      'warning',
      `p95 encolado → decisión ${Math.round(hour.latencyP95Ms / 1000)} s.`,
      'latencia',
    );
  }
  const attempts = hour.jobsFinished + hour.jobsRetried;
  if (
    attempts >= policy.minDecisionsForRates &&
    hour.jobsRetried / attempts > policy.retryRateWarn
  ) {
    add(
      'ERROR_RATE',
      'warning',
      `${hour.jobsRetried}/${attempts} intentos fallidos en 1 h.`,
      'errores',
    );
  }
  const escalations = hour.byApplied.ESCALATE ?? 0;
  const proposedEscalations = Object.values(hour.byEscalateReason).reduce(
    (sum, value) => sum + value,
    0,
  );
  const escalationShare =
    hour.decisions > 0 ? Math.max(escalations, proposedEscalations) / hour.decisions : 0;
  if (
    hour.decisions >= policy.minDecisionsForRates &&
    escalationShare > policy.escalationRateWarn
  ) {
    const top = Object.entries(hour.byEscalateReason).sort((left, right) => right[1] - left[1])[0];
    add(
      'ESCALATION_SPIKE',
      'warning',
      `${Math.round(escalationShare * 100)} % de decisiones escalan (principal: ${top?.[0] ?? '—'}).`,
      'escalaciones',
    );
  }
  if (metrics.last24h.pauses > 0) {
    add(
      'PATTERN_PAUSED',
      'warning',
      `${metrics.last24h.pauses} patrón(es) en pausa en 24 h.`,
      'pausa-de-patron',
    );
  }
  if (metrics.last24h.reversals > 0) {
    add('REVERSALS', 'warning', `${metrics.last24h.reversals} reversión(es) en 24 h.`, 'reversion');
  }
  if (metrics.last24h.disagreements > 0) {
    add(
      'DISAGREEMENT',
      'warning',
      `${metrics.last24h.disagreements} desacuerdo(s) de revisión en 24 h.`,
      'reversion',
    );
  }
  if (metrics.sourceState !== 'healthy') {
    add(
      'SOURCE_NOT_HEALTHY',
      'warning',
      `Fuente de ingesta ${metrics.sourceState ?? 'sin medir'}: el motor escala todo (GUARD_SOURCE).`,
      'salud-de-fuente',
    );
  }
  const status = alerts.some((alert) => alert.severity === 'critical')
    ? 'CRITICAL'
    : alerts.some((alert) => alert.severity === 'warning')
      ? 'DEGRADED'
      : 'OK';
  return { status, alerts };
}
