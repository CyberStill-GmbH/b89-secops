/**
 * Puertos de C-17.
 *
 * `SocUnitOfWork.run` recibe el trabajo completo y lo ejecuta en una sola transacción.
 * Es el punto donde se cumple el contrato con C-19 y C-20: estado, AuditEvent y mensaje
 * de outbox entran juntos o no entra ninguno. Un adapter que abra tres transacciones
 * distintas incumple aunque los tres escriban.
 *
 * `SocReadModel`, `SocOutboxQueue` y `CorrelationWindowQuery` son lecturas o marcas
 * idempotentes fuera de la transacción de negocio. `SocPersistence` agrupa todo lo que un
 * runtime necesita de un adapter (memoria para specs y desarrollo, PostgreSQL para
 * cualquier ambiente donde el estado deba sobrevivir a un reinicio).
 */

import type { AuditStore } from '@b89/audit';
import type {
  AlertFingerprint,
  CorrelationWindowQuery,
  GuardSignals,
  DetectionCandidateStore,
} from '@b89/detection';

import type { Alert, AlertStatus } from './alert.js';
import type { AlertGroup, AlertGroupStatus } from './alert-group.js';
import type { AlertClosureRecord, ClosureOrigin } from './closure.js';
import type {
  ApprovalRecord,
  ClosureEvidence,
  LearningPattern,
  PatternStatus,
} from './learning-pattern.js';
import type {
  Confidence,
  EngineAction,
  EngineCheck,
  EscalateReason,
  LearningMode,
  PatternCounters,
} from './learning-engine.js';
import type { Incident, IncidentStatus } from './incident.js';
import type { IncidentNote, IncidentTask } from './incident-work.js';
import type { OutboxMessageDraft } from './events.js';
import type { IngestionStateStore } from './ingestion.js';

export interface AlertStore {
  byId(tenantId: string, alertId: string): Promise<Alert | undefined>;
  insertIfAbsent(alert: Alert): Promise<boolean>;
  /** Compare-and-set sobre `revision`; `false` si otra escritura se adelantó. */
  update(alert: Alert, expectedRevision: number): Promise<boolean>;
  byIncident(tenantId: string, incidentId: string): Promise<readonly Alert[]>;
}

/**
 * Bitácora append-only de cierres y reaperturas (`soc_alert_closures`). Sin `update` ni
 * borrado por contrato: es la evidencia de la que aprende el SOC.
 */
export interface AlertClosureStore {
  append(record: AlertClosureRecord): Promise<void>;
}

/** Aprendizaje SOC · etapa B — huella de la alerta tal como se calculó al promoverla. */
export interface AlertFingerprintRecord extends AlertFingerprint {
  readonly alertId: string;
  readonly tenantId: string;
  readonly computedAt: Date;
}

/** Una huella por alerta; repetir la ingesta no la reescribe. */
export interface AlertFingerprintStore {
  insertIfAbsent(record: AlertFingerprintRecord): Promise<boolean>;
}

/** Etapa D · transición de estado de un patrón (bitácora append-only). */
export interface PatternEventRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly patternId: string;
  readonly from: PatternStatus | null;
  readonly to: PatternStatus;
  readonly reason: string;
  readonly actorId: string;
  readonly at: Date;
}

/**
 * Etapa D · patrones. Como máximo un patrón abierto por (tenant, huella); `update` es CAS.
 * Firmas y eventos son append-only.
 */
export interface LearningPatternStore {
  byId(tenantId: string, patternId: string): Promise<LearningPattern | undefined>;
  openByFingerprint(tenantId: string, fingerprint: string): Promise<LearningPattern | undefined>;
  listOpen(tenantId: string): Promise<readonly LearningPattern[]>;
  /** Patrones `active` del tenant con la misma `rule_key` (deriva). */
  activeByRule(tenantId: string, ruleKey: string): Promise<readonly LearningPattern[]>;
  insertIfAbsent(pattern: LearningPattern): Promise<boolean>;
  update(pattern: LearningPattern, expectedRevision: number): Promise<boolean>;
  approvals(tenantId: string, patternId: string): Promise<readonly ApprovalRecord[]>;
  appendApproval(record: ApprovalRecord): Promise<void>;
  appendEvent(record: PatternEventRecord): Promise<void>;
}

/** Etapa E · decisión del motor (append-only, una por alerta). */
export interface LearningDecisionRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly alertId: string;
  readonly mode: LearningMode;
  readonly engineVersion: string;
  readonly fingerprint: string;
  readonly level: 'fine' | 'coarse';
  readonly ruleKey: string | null;
  readonly patternId: string | null;
  readonly proposedAction: EngineAction;
  readonly appliedAction: EngineAction;
  readonly escalateReason: EscalateReason | null;
  readonly confidence: Confidence;
  readonly checks: readonly EngineCheck[];
  readonly drift: Readonly<
    Record<string, { readonly from: string | null; readonly to: string | null }>
  > | null;
  readonly sampled: boolean;
  readonly at: Date;
}

export const LEARNING_REVIEW_KINDS = [
  'quality_sample',
  'dry_run_approval',
  'forced_review',
] as const;
export type LearningReviewKind = (typeof LEARNING_REVIEW_KINDS)[number];
export const LEARNING_REVIEW_STATUSES = ['pending', 'agreed', 'disagreed', 'expired'] as const;
export type LearningReviewStatus = (typeof LEARNING_REVIEW_STATUSES)[number];

/** Etapa E · revisión humana de una decisión (muestra, propuesta en dry-run o revisión forzada). */
export interface LearningReviewRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly decisionId: string;
  readonly alertId: string;
  readonly patternId: string | null;
  readonly kind: LearningReviewKind;
  readonly status: LearningReviewStatus;
  readonly reviewerId: string | null;
  readonly truePositive: boolean | null;
  readonly comment: string | null;
  readonly at: Date;
  readonly resolvedAt: Date | null;
  readonly revision: number;
}

/** Etapa E · reversión de un autocierre (append-only). */
export interface LearningReversalRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly decisionId: string;
  readonly alertId: string;
  readonly patternId: string | null;
  readonly actorId: string;
  readonly reason: string;
  readonly reopened: boolean;
  readonly at: Date;
}

/** Etapa E · registro del motor. `appendDecision` es `false` si la alerta ya tenía decisión. */
export interface LearningRecordStore {
  appendDecision(record: LearningDecisionRecord): Promise<boolean>;
  decisionById(tenantId: string, decisionId: string): Promise<LearningDecisionRecord | undefined>;
  decisionByAlert(tenantId: string, alertId: string): Promise<LearningDecisionRecord | undefined>;
  /** Contadores del patrón: cierres (propuestos en dry-run/activo) desde `since` y muestras. */
  counters(tenantId: string, patternId: string, now: Date, since: Date): Promise<PatternCounters>;
  insertReview(record: LearningReviewRecord): Promise<void>;
  reviewById(tenantId: string, reviewId: string): Promise<LearningReviewRecord | undefined>;
  updateReview(record: LearningReviewRecord, expectedRevision: number): Promise<boolean>;
  appendReversal(record: LearningReversalRecord): Promise<void>;
}

/* --------------------------------------------- Cola del motor (fase 2 de la sombra) */

export const LEARNING_JOB_STATUSES = ['pending', 'leased', 'done', 'dead'] as const;
export type LearningJobStatus = (typeof LEARNING_JOB_STATUSES)[number];

/**
 * Trabajo del motor para una alerta. Se escribe en la transacción de la ingesta; lo consume el
 * worker fuera del camino crítico. `signals` viaja aquí porque la alerta no las conserva.
 */
export interface LearningJob {
  readonly alertId: string;
  readonly tenantId: string;
  readonly fingerprint: AlertFingerprint;
  readonly signals: GuardSignals | null;
  readonly status: LearningJobStatus;
  readonly attempts: number;
  readonly availableAt: Date;
  readonly leaseUntil: Date | null;
  readonly claimId: string | null;
  readonly lastError: string | null;
  readonly enqueuedAt: Date;
  readonly finishedAt: Date | null;
}

/** Dentro de la transacción de la ingesta: `false` si la alerta ya tenía trabajo. */
export interface LearningJobStore {
  enqueue(job: LearningJob): Promise<boolean>;
}

/** Fuera de transacción: lo usa el worker. */
export interface LearningJobQueue {
  /** Reclama pendientes vencidos y leases caducados (`SKIP LOCKED`); suma un intento a cada uno. */
  claim(input: {
    readonly limit: number;
    readonly leaseMs: number;
    readonly now: Date;
    readonly claimId: string;
  }): Promise<readonly LearningJob[]>;
  complete(alertId: string, claimId: string, now: Date): Promise<boolean>;
  /** `retryAt = null` ⇒ `dead` (dead-letter): la alerta sigue con personas. */
  fail(
    alertId: string,
    claimId: string,
    error: string,
    now: Date,
    retryAt: Date | null,
  ): Promise<boolean>;
  heartbeat(beat: {
    readonly workerId: string;
    readonly tenantId: string;
    readonly at: Date;
    readonly claimed: number;
    readonly failed: number;
  }): Promise<void>;
  recordConfig(event: LearningConfigEvent): Promise<void>;
}

/** Configuración efectiva de un arranque: solo huella y contadores (sin claves ni listas). */
export interface LearningConfigEvent {
  readonly id: string;
  readonly tenantId: string;
  readonly configHash: string;
  readonly maxMode: 'off' | 'shadow' | 'dry_run' | 'active';
  readonly activeRules: number;
  readonly killSwitch: boolean;
  readonly samplingKeyVersion: string | null;
  readonly at: Date;
}

/** Evidencia para refrescar patrones: último cierre humano vigente por alerta, con su huella. */
export interface LearningEvidence {
  readonly closures: readonly ClosureEvidence[];
  /** Cierres TP_REAL vigentes por huella (cualquier origen: un TP siempre cuenta en contra). */
  readonly truePositivesByFingerprint: ReadonlyMap<string, number>;
}

/** Métricas para las compuertas de preparación. */
export interface ReadinessMetrics {
  readonly closedAlertsWithoutOrigin: number;
  readonly sourceCoverage: ReadonlyMap<string, { readonly fine: number; readonly total: number }>;
}

/**
 * Aprendizaje SOC · etapa C — grupos por huella. Como máximo uno abierto por (tenant, huella):
 * `insertIfAbsent` devuelve `false` si otro proceso lo abrió antes; `update` es compare-and-set.
 * La pertenencia es append-only: una alerta entra a un grupo una sola vez.
 */
export interface AlertGroupStore {
  /**
   * Grupo abierto de la huella. Un adapter durable **debe bloquear la fila** hasta el fin de la
   * transacción (`FOR UPDATE`): así ingestas concurrentes se suman en orden en vez de perder el CAS.
   */
  openByFingerprint(tenantId: string, fingerprint: string): Promise<AlertGroup | undefined>;
  insertIfAbsent(group: AlertGroup): Promise<boolean>;
  update(group: AlertGroup, expectedRevision: number): Promise<boolean>;
  addMember(member: {
    readonly tenantId: string;
    readonly groupId: string;
    readonly alertId: string;
    readonly joinedAt: Date;
  }): Promise<void>;
}

export interface IncidentStore {
  byId(tenantId: string, incidentId: string): Promise<Incident | undefined>;
  insert(incident: Incident): Promise<void>;
  update(incident: Incident, expectedRevision: number): Promise<boolean>;
}

/** Tareas del incidente (S5-D8). `update` es compare-and-set sobre `revision`. */
export interface IncidentTaskStore {
  byId(tenantId: string, taskId: string): Promise<IncidentTask | undefined>;
  byIncident(tenantId: string, incidentId: string): Promise<readonly IncidentTask[]>;
  insert(task: IncidentTask): Promise<void>;
  update(task: IncidentTask, expectedRevision: number): Promise<boolean>;
}

/** Bitácora append-only: no hay `update` ni borrado por contrato. */
export interface IncidentNoteStore {
  byId(tenantId: string, noteId: string): Promise<IncidentNote | undefined>;
  insert(note: IncidentNote): Promise<void>;
}

export interface OutboxStore {
  /** `false` si la `idempotencyKey` ya existía: el hecho ya se publicó una vez. */
  enqueueIfAbsent(message: OutboxMessageDraft): Promise<boolean>;
}

export interface SocTransactionContext {
  readonly alerts: AlertStore;
  readonly closures: AlertClosureStore;
  readonly fingerprints: AlertFingerprintStore;
  readonly groups: AlertGroupStore;
  readonly patterns: LearningPatternStore;
  readonly learning: LearningRecordStore;
  readonly learningJobs: LearningJobStore;
  readonly incidents: IncidentStore;
  readonly tasks: IncidentTaskStore;
  readonly notes: IncidentNoteStore;
  readonly outbox: OutboxStore;
  readonly audit: AuditStore;
  /**
   * Candidatos de C-16. La alerta referencia a su candidato por FK en PostgreSQL, así que
   * ambos se escriben en la misma transacción.
   */
  readonly candidates: DetectionCandidateStore;
}

export interface SocUnitOfWork {
  run<T>(work: (context: SocTransactionContext) => Promise<T>): Promise<T>;
}

/* ------------------------------------------------------------------ Lecturas */

export interface AlertQuery {
  readonly tenantId: string;
  /** `open` = todo lo no cerrado. */
  readonly status?: AlertStatus | 'open';
  readonly priority?: Alert['priority'];
  /** Texto en minúsculas; busca en título, asignado e id. */
  readonly search?: string;
  /** Referencia opaca de entidad (`ent_…`, D-10b) para agrupar por usuario o IP. */
  readonly entityRef?: string;
}

export interface IncidentQuery {
  readonly tenantId: string;
  readonly statuses?: readonly IncidentStatus[];
  readonly search?: string;
}

/**
 * Resultado de un listado: filas ya filtradas por tenant (como máximo el tope del adapter)
 * y total exacto. La paginación por cursor ocurre en el BFF sobre estas filas.
 */
export interface QueryResult<T> {
  readonly items: readonly T[];
  readonly total: number;
}

/** Conteo exacto (sin tope de filas) de las alertas de una entidad para el Analista IA. */
export interface AlertStatsQuery {
  readonly tenantId: string;
  readonly entityRef: string;
  /** Solo alertas de esta regla; sin el campo, todas las reglas. */
  readonly ruleId?: string;
  /** Creadas desde este instante (incluido). */
  readonly since?: Date;
  /** Alertas que no cuentan (las del propio trabajo). */
  readonly excludeIds?: readonly string[];
  /**
   * Orígenes de cierre que cuentan como falso positivo (aprendizaje SOC · etapa A). Por defecto
   * solo `human`: los cierres del Analista IA, de scripts o del motor no se refuerzan a sí mismos.
   */
  readonly falsePositiveOrigins?: readonly ClosureOrigin[];
}

/** Por defecto solo cuentan los cierres humanos como historial de falso positivo. */
export const DEFAULT_FALSE_POSITIVE_ORIGINS: readonly ClosureOrigin[] = Object.freeze(['human']);

export interface AlertStats {
  readonly total: number;
  readonly falsePositive: number;
  readonly truePositive: number;
  /** No cerradas. */
  readonly open: number;
  /** IDs de incidentes vinculados (distintos), sin tope del listado. */
  readonly incidentIds: readonly string[];
}

export interface AlertGroupQuery {
  readonly tenantId: string;
  readonly status?: AlertGroupStatus;
  /** Máximo de grupos, por `lastSeenAt` descendente. */
  readonly limit: number;
}

export interface SocReadModel {
  alertById(tenantId: string, alertId: string): Promise<Alert | undefined>;
  /** Aprendizaje SOC · etapa C. Opcionales: un adapter sin grupos devuelve `undefined`/vacío. */
  alertGroupById?(tenantId: string, groupId: string): Promise<AlertGroup | undefined>;
  alertGroupOf?(tenantId: string, alertId: string): Promise<AlertGroup | undefined>;
  /** Grupo de cada alerta (las que no tienen grupo no aparecen en el mapa). */
  alertGroupsOf?(
    tenantId: string,
    alertIds: readonly string[],
  ): Promise<ReadonlyMap<string, AlertGroup>>;
  listAlertGroups?(query: AlertGroupQuery): Promise<QueryResult<AlertGroup>>;
  /** IDs de las alertas del grupo, más recientes primero, como máximo `limit`. */
  alertGroupMembers?(tenantId: string, groupId: string, limit: number): Promise<readonly string[]>;
  /** Etapa D. Cierres desde `since` (último vigente por alerta) y TP por huella. */
  learningEvidence?(tenantId: string, since: Date): Promise<LearningEvidence>;
  /** Etapa D. Alertas cerradas sin origen y cobertura de huella fina por fuente desde `since`. */
  readinessMetrics?(tenantId: string, since: Date): Promise<ReadinessMetrics>;
  /** Etapa D/E · lecturas de la consola. */
  listLearningPatterns?(query: {
    readonly tenantId: string;
    readonly status?: PatternStatus;
    readonly limit: number;
  }): Promise<QueryResult<LearningPattern>>;
  learningPatternById?(tenantId: string, patternId: string): Promise<LearningPattern | undefined>;
  learningPatternHistory?(
    tenantId: string,
    patternId: string,
  ): Promise<{
    readonly approvals: readonly ApprovalRecord[];
    readonly events: readonly PatternEventRecord[];
  }>;
  listLearningDecisions?(query: {
    readonly tenantId: string;
    readonly alertId?: string;
    readonly patternId?: string;
    readonly limit: number;
  }): Promise<QueryResult<LearningDecisionRecord>>;
  listLearningReviews?(query: {
    readonly tenantId: string;
    readonly status?: LearningReviewStatus;
    readonly limit: number;
  }): Promise<QueryResult<LearningReviewRecord>>;
  /**
   * Conteos exactos por veredicto y estado; opcional (los adapters que no lo implementan
   * obligan a quien llama a usar `listAlerts` y declarar el tope).
   */
  alertStats?(query: AlertStatsQuery): Promise<AlertStats>;
  /** Una alerta por evento: base de la idempotencia de la promoción en el runtime. */
  alertByEventRecordId(tenantId: string, eventRecordId: string): Promise<Alert | undefined>;
  listAlerts(query: AlertQuery): Promise<QueryResult<Alert>>;
  /** Alertas de un incidente: las `limit` más recientes y el total real de vínculos. */
  listIncidentAlerts(
    tenantId: string,
    incidentId: string,
    limit: number,
  ): Promise<QueryResult<Alert>>;
  incidentById(tenantId: string, incidentId: string): Promise<Incident | undefined>;
  listIncidents(query: IncidentQuery): Promise<QueryResult<Incident>>;
  /** Tareas de un incidente, más recientes primero; como máximo el tope del adapter. */
  listIncidentTasks(tenantId: string, incidentId: string): Promise<readonly IncidentTask[]>;
  /** Notas de un incidente, más recientes primero; como máximo el tope del adapter. */
  listIncidentNotes(tenantId: string, incidentId: string): Promise<readonly IncidentNote[]>;
}

/* -------------------------------------------------------------------- Outbox */

/**
 * Cola durable del outbox SOC que consume el despacho de C-20, sin copias intermedias.
 *
 * `claimOutbox` reclama con lease: el mensaje queda `processing` hasta `at + leaseMs`. Si
 * el despachador muere, el lease vence y otro lo reclama; por eso la entrega es "al menos
 * una vez" y la idempotencia del intento de notificación evita el duplicado. Publicar o
 * reprogramar solo actúa sobre mensajes en `processing`.
 */
export interface SocOutboxQueue {
  claimOutbox(
    at: Date,
    limit: number,
    leaseMs: number,
    lane?: OutboxLane,
  ): Promise<readonly ClaimedOutboxMessage[]>;
  /** `false` si el claim ya no es el vigente (lease vencido y reclamado por otro). */
  markOutboxPublished(messageId: string, claimToken: string, at: Date): Promise<boolean>;
  scheduleOutboxRetry(
    messageId: string,
    claimToken: string,
    availableAt: Date,
    errorCode: string,
  ): Promise<boolean>;
}

/** Carril SQL del outbox. `all` conserva el contrato para consumidores/manual drain antiguos. */
export type OutboxLane = 'all' | 'urgent' | 'normal';

/**
 * Mensaje reclamado. `claimToken` es el fencing token del claim: solo quien lo tiene puede
 * publicar o reprogramar, así un despachador que perdió su lease no pisa al nuevo dueño.
 */
export interface ClaimedOutboxMessage extends OutboxMessageDraft {
  readonly claimToken: string;
}

/* ------------------------------------------------------------------- Salud */

/** Estado agregado de la cola del outbox de un tenant, para `GET /api/operations/health`. */
export interface OutboxHealth {
  readonly pending: number;
  readonly processing: number;
  /** Disponibilidad del pendiente más antiguo; `null` si no hay pendientes. */
  readonly oldestPendingAt: Date | null;
  /** Claims en proceso cuyo lease ya venció al instante de la consulta. */
  readonly expiredProcessing: number;
  /** Vencimiento más antiguo entre leases expirados; `null` si todos siguen vigentes. */
  readonly oldestExpiredProcessingLeaseUntil: Date | null;
}

export interface SocHealthQuery {
  /** Instante de la alerta más reciente del tenant; `null` si nunca hubo. */
  lastAlertAt(tenantId: string): Promise<Date | null>;
  outboxHealth(tenantId: string, at: Date): Promise<OutboxHealth>;
}

/* ---------------------------------------------------------------- Agregado */

export interface SocPersistence
  extends SocUnitOfWork, SocReadModel, SocOutboxQueue, CorrelationWindowQuery, SocHealthQuery {
  /** Nombre estable del adapter para health y logs: `memory` o `postgres`. */
  readonly kind: 'memory' | 'postgres';
  /**
   * Auditoría para escritores fuera de una unidad de trabajo SOC (inicio de sesión,
   * despacho) y para la consulta de C-19. Es la misma cadena que escribe `run`.
   */
  readonly audit: AuditStore;
  /** Cursor y observaciones de la ingesta de fuentes (Sprint 5 · fase 0). */
  readonly ingestion: IngestionStateStore;
  /** Cola del motor de aprendizaje (fase 2): ausente en adapters que no la soportan. */
  readonly learningQueue?: LearningJobQueue;
  /** Comprueba conectividad y esquema; lanza si el adapter no puede atender. */
  ready(): Promise<void>;
  close(): Promise<void>;
}
