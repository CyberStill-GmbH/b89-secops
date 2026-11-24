/**
 * Adapter PostgreSQL de C-17: implementa `SocPersistence` sobre los stores Prisma de
 * `@b89/database`.
 *
 * Responsabilidades de este archivo, y solo estas:
 *
 * 1. Traducir filas planas a tipos de dominio y viceversa. Los stores de `platform` no
 *    conocen `Alert` ni `Incident`; aquí se valida que los catálogos leídos (estado,
 *    prioridad, señal) sigan siendo los del dominio. Una fila con un valor desconocido es
 *    un error de integridad y se reporta, no se adivina.
 * 2. Componer la unidad de trabajo: alertas, incidentes, candidatos, outbox y auditoría
 *    comparten la misma transacción (`PrismaSocUnitOfWork`).
 * 3. Exponer lecturas, ventana de correlación y relay del outbox fuera de transacción.
 *
 * Se publica como subpath (`@b89/soc/postgres`) para que un runtime en memoria no cargue
 * Prisma ni el driver de PostgreSQL.
 */

import type { AuditStore, SealedAuditEvent } from '@b89/audit';
import {
  closeDatabaseClient,
  createDatabaseClient,
  PrismaAuditStore,
  PrismaIncidentWorkQueries,
  PrismaIngestionStateStore,
  PrismaWazuhPushInboxStore,
  PrismaSocQueries,
  PrismaSocUnitOfWork,
  PrismaStandaloneAuditStore,
  type AlertGroupRow,
  type AlertRow,
  type CandidateRow,
  type DatabaseConnectionOptions,
  type IncidentNoteRow,
  type IncidentRow,
  type IncidentTaskRow,
  type IncidentWithAlertsRow,
  type LearningClosureRow,
  type LearningDecisionRow,
  type LearningPatternRow,
  type LearningReviewRow,
  type PatternApprovalRow,
  type SealedAuditRow,
} from '@b89/database';
import {
  FINGERPRINT_COMPONENTS,
  PRIORITIES,
  SIGNAL_CLASSES,
  type FingerprintComponents,
  type CorrelatableAlert,
  type DetectionCandidate,
  type DetectionCandidateStore,
  type Priority,
  type Reason,
  type SignalClass,
} from '@b89/detection';

import { ALERT_STATUSES, TRIAGE_VERDICTS, type Alert } from '../alert.js';
import { ALERT_GROUP_STATUSES, type AlertGroup } from '../alert-group.js';
import { CLOSURE_ORIGINS, CLOSURE_REASONS, LEARNABLE_CLOSURE_REASONS } from '../closure.js';
import {
  PATTERN_STATUSES,
  READINESS_BLOCKERS,
  type ApprovalRecord,
  type ClosureEvidence,
  type LearningPattern,
} from '../learning-pattern.js';
import {
  ENGINE_ACTIONS,
  ESCALATE_REASONS,
  LEARNING_MODES,
  limaDayStart,
  type EngineCheck,
} from '../learning-engine.js';
import type {
  ClaimedWazuhPushHint,
  WazuhPushHint,
  WazuhPushInboxMetrics,
  WazuhPushInboxStore,
} from '../wazuh-push-inbox.js';
import { INCIDENT_SEVERITIES, INCIDENT_STATUSES, type Incident } from '../incident.js';
import {
  POLL_OUTCOMES,
  type ClaimedIngestionCursor,
  type IngestionCursorKey,
  type IngestionStateStore,
  type SourcePollObservation,
} from '../ingestion.js';
import {
  SOURCE_HEALTH_REASONS,
  SOURCE_HEALTH_STATES,
  type SourceHealthTransition,
} from '../source-health.js';
import { TASK_STATUSES, type IncidentNote, type IncidentTask } from '../incident-work.js';
import type { OutboxMessageDraft, SocEventType } from '../events.js';
import type {
  AlertQuery,
  AlertStats,
  AlertStatsQuery,
  AlertClosureStore,
  AlertFingerprintStore,
  AlertGroupQuery,
  AlertGroupStore,
  AlertStore,
  ClaimedOutboxMessage,
  OutboxHealth,
  IncidentNoteStore,
  IncidentQuery,
  IncidentStore,
  IncidentTaskStore,
  LearningDecisionRecord,
  LearningEvidence,
  LearningPatternStore,
  LearningRecordStore,
  LearningReviewRecord,
  LearningReviewStatus,
  PatternEventRecord,
  OutboxLane,
  OutboxStore,
  QueryResult,
  ReadinessMetrics,
  SocPersistence,
  SocTransactionContext,
} from '../ports.js';
import { LEARNING_REVIEW_KINDS, LEARNING_REVIEW_STATUSES } from '../ports.js';

/** Fila con un valor fuera del catálogo del dominio: la base y el código divergieron. */
export class SocIntegrityError extends Error {
  public constructor(
    public readonly table: string,
    public readonly column: string,
  ) {
    super(`Valor fuera de catálogo en ${table}.${column}.`);
    this.name = 'SocIntegrityError';
  }
}

function oneOf<T extends string>(
  catalog: readonly T[],
  value: string,
  table: string,
  column: string,
): T {
  if (!(catalog as readonly string[]).includes(value)) throw new SocIntegrityError(table, column);
  return value as T;
}

function optionalOneOf<T extends string>(
  catalog: readonly T[],
  value: string | null,
  table: string,
  column: string,
): T | null {
  return value === null ? null : oneOf(catalog, value, table, column);
}

/* --------------------------------------------------------------- Traducción */

function toAlert(row: AlertRow): Alert {
  return {
    id: row.id,
    tenantId: row.tenantId,
    candidateId: row.candidateId,
    eventRecordId: row.eventRecordId,
    title: row.title,
    priority: oneOf(PRIORITIES, row.priority, 'soc_alerts', 'priority'),
    score: row.score,
    reasons: row.reasons as readonly Reason[],
    status: oneOf(ALERT_STATUSES, row.status, 'soc_alerts', 'status'),
    assigneeId: row.assigneeId,
    verdict: optionalOneOf(TRIAGE_VERDICTS, row.verdict, 'soc_alerts', 'verdict'),
    triageNote: row.triageNote,
    incidentId: row.incidentId,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    revision: row.revision,
    entityKeys: [...row.entityKeys],
    entityRefs: [...row.entityRefs],
    signal: optionalOneOf(SIGNAL_CLASSES, row.signal, 'soc_alerts', 'signal'),
    ruleId: row.ruleId,
    relatedAlertIds: [...row.relatedAlertIds],
    closureReason: optionalOneOf(
      CLOSURE_REASONS,
      row.closureReason,
      'soc_alerts',
      'closure_reason',
    ),
    closureOrigin: optionalOneOf(
      CLOSURE_ORIGINS,
      row.closureOrigin,
      'soc_alerts',
      'closure_origin',
    ),
    closedBy: row.closedBy,
    closedAt: row.closedAt,
  };
}

const FINGERPRINT_LEVELS = ['fine', 'coarse'] as const;

function toAlertGroup(row: AlertGroupRow): AlertGroup {
  return {
    ...row,
    level: oneOf(FINGERPRINT_LEVELS, row.level, 'soc_alert_groups', 'level'),
    status: oneOf(ALERT_GROUP_STATUSES, row.status, 'soc_alert_groups', 'status'),
    highestPriority: oneOf(PRIORITIES, row.highestPriority, 'soc_alert_groups', 'highest_priority'),
  };
}

const PATTERN_ACTIONS = ['auto_close', 'demote'] as const;
const APPROVAL_STAGES = ['first', 'second'] as const;
const APPROVAL_DECISIONS = ['approve', 'reject'] as const;

/** Componentes de huella leídos de JSONB: exactamente las claves del catálogo, texto o null. */
function toComponents(value: unknown, table: string): FingerprintComponents {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SocIntegrityError(table, 'components');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.some((key) => !(FINGERPRINT_COMPONENTS as readonly string[]).includes(key))) {
    throw new SocIntegrityError(table, 'components');
  }
  const result: Record<string, string | null> = {};
  for (const name of FINGERPRINT_COMPONENTS) {
    const item = record[name] ?? null;
    if (item !== null && typeof item !== 'string') throw new SocIntegrityError(table, 'components');
    result[name] = item;
  }
  return result as FingerprintComponents;
}

function toPattern(row: LearningPatternRow): LearningPattern {
  const table = 'soc_learning_patterns';
  return {
    ...row,
    components: toComponents(row.components, table),
    level: oneOf(FINGERPRINT_LEVELS, row.level, table, 'level'),
    maxAction: oneOf(PATTERN_ACTIONS, row.maxAction, table, 'max_action'),
    closureReason: oneOf(LEARNABLE_CLOSURE_REASONS, row.closureReason, table, 'closure_reason'),
    status: oneOf(PATTERN_STATUSES, row.status, table, 'status'),
    priorityCeiling: oneOf(PRIORITIES, row.priorityCeiling, table, 'priority_ceiling'),
    originAlertIds: [...row.originAlertIds],
    originClosers: [...row.originClosers],
    readinessBlockers: row.readinessBlockers.map((blocker) =>
      oneOf(READINESS_BLOCKERS, blocker, table, 'readiness_blockers'),
    ),
  };
}

function toApproval(row: PatternApprovalRow): ApprovalRecord {
  const table = 'soc_learning_pattern_approvals';
  return {
    ...row,
    stage: oneOf(APPROVAL_STAGES, row.stage, table, 'stage'),
    decision: oneOf(APPROVAL_DECISIONS, row.decision, table, 'decision'),
  };
}

const CONFIDENCES = ['high', 'medium', 'low'] as const;

function toChecks(value: unknown): readonly EngineCheck[] {
  if (!Array.isArray(value)) throw new SocIntegrityError('soc_learning_decisions', 'checks');
  return value.map((item) => {
    const entry = item as Record<string, unknown>;
    if (
      typeof entry['id'] !== 'string' ||
      typeof entry['ok'] !== 'boolean' ||
      typeof entry['detail'] !== 'string'
    ) {
      throw new SocIntegrityError('soc_learning_decisions', 'checks');
    }
    return { id: entry['id'], ok: entry['ok'], detail: entry['detail'] };
  });
}

function toDecision(row: LearningDecisionRow): LearningDecisionRecord {
  const table = 'soc_learning_decisions';
  const modes = LEARNING_MODES.filter((mode) => mode !== 'off');
  return {
    ...row,
    mode: oneOf(modes, row.mode, table, 'mode'),
    level: oneOf(FINGERPRINT_LEVELS, row.level, table, 'level'),
    proposedAction: oneOf(ENGINE_ACTIONS, row.proposedAction, table, 'proposed_action'),
    appliedAction: oneOf(ENGINE_ACTIONS, row.appliedAction, table, 'applied_action'),
    escalateReason: optionalOneOf(ESCALATE_REASONS, row.escalateReason, table, 'escalate_reason'),
    confidence: oneOf(CONFIDENCES, row.confidence, table, 'confidence'),
    checks: toChecks(row.checks),
    drift: (row.drift ?? null) as LearningDecisionRecord['drift'],
  };
}

function toReview(row: LearningReviewRow): LearningReviewRecord {
  const table = 'soc_learning_reviews';
  return {
    ...row,
    kind: oneOf(LEARNING_REVIEW_KINDS, row.kind, table, 'kind'),
    status: oneOf(LEARNING_REVIEW_STATUSES, row.status, table, 'status'),
  };
}

function toClosureEvidence(row: LearningClosureRow): ClosureEvidence {
  return {
    alertId: row.alertId,
    actorId: row.actorId,
    at: row.at,
    closureReason: optionalOneOf(
      CLOSURE_REASONS,
      row.closureReason,
      'soc_alert_closures',
      'closure_reason',
    ),
    decisionGroupId: row.decisionGroupId,
    priority: oneOf(PRIORITIES, row.priority, 'soc_alerts', 'priority'),
    ruleKey: row.ruleKey,
    fingerprint: row.fingerprint,
    level: oneOf(FINGERPRINT_LEVELS, row.level, 'soc_alert_fingerprints', 'level'),
    normalizerVersion: row.normalizerVersion,
    components: toComponents(row.components, 'soc_alert_fingerprints'),
  };
}

function fromAlert(alert: Alert): AlertRow {
  return { ...alert, reasons: alert.reasons };
}

function toTask(row: IncidentTaskRow): IncidentTask {
  return { ...row, status: oneOf(TASK_STATUSES, row.status, 'incident_tasks', 'status') };
}

function toNote(row: IncidentNoteRow): IncidentNote {
  return { ...row };
}

function toIncident(row: IncidentWithAlertsRow): Incident {
  return {
    id: row.id,
    tenantId: row.tenantId,
    title: row.title,
    severity: oneOf(INCIDENT_SEVERITIES, row.severity, 'soc_incidents', 'severity'),
    status: oneOf(INCIDENT_STATUSES, row.status, 'soc_incidents', 'status'),
    ownerId: row.ownerId,
    alertIds: [...row.alertIds],
    summary: row.summary,
    openedAt: row.openedAt,
    updatedAt: row.updatedAt,
    closedAt: row.closedAt,
    closureReason: row.closureReason,
    revision: row.revision,
  };
}

/** `alertIds` no es columna: la relación vive en `soc_alerts.incident_id`. */
function fromIncident(incident: Incident): IncidentRow {
  const { alertIds: _alertIds, ...row } = incident;
  return row;
}

function toCandidate(row: CandidateRow): DetectionCandidate {
  return {
    id: row.id,
    tenantId: row.tenantId,
    eventRecordId: row.eventRecordId,
    eventUid: row.eventUid,
    idempotencyKey: row.idempotencyKey,
    priority: oneOf(PRIORITIES, row.priority, 'detection_candidates', 'priority') as Priority,
    score: row.score,
    reasons: row.reasons as readonly Reason[],
    rulesetId: row.rulesetId,
    rulesetVersion: row.rulesetVersion,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
    title: row.title,
    entityKeys: [...row.entityKeys],
    signal: (optionalOneOf(SIGNAL_CLASSES, row.signal, 'detection_candidates', 'signal') ??
      'other') as SignalClass,
    ruleId: row.ruleId,
    relatedAlertIds: [...row.relatedAlertIds],
  };
}

function toOutboxDraft(row: {
  readonly messageId: string;
  readonly tenantId: string;
  readonly aggregateType: 'alert' | 'incident';
  readonly aggregateId: string;
  readonly messageType: string;
  readonly schemaVersion: string;
  readonly idempotencyKey: string;
  readonly payload: Readonly<Record<string, string | number | boolean | null>>;
  readonly availableAt: Date;
}): OutboxMessageDraft {
  return { ...row, messageType: row.messageType as SocEventType };
}

/**
 * La fila de auditoría y el evento sellado del puerto tienen la misma forma; solo difiere
 * el tipo de `metadata` (`unknown` en la fila, valor canónico en el puerto). Lo que la
 * base devuelve se escribió a través de este mismo puerto, por eso la conversión es segura
 * y queda concentrada aquí.
 */
function auditPort(store: PrismaAuditStore | PrismaStandaloneAuditStore): AuditStore {
  return {
    head: (tenantId) => store.head(tenantId),
    append: (event: SealedAuditEvent) => store.append(event as SealedAuditRow),
    read: async (query) => {
      const page = await store.read(query);
      return { events: page.events as readonly SealedAuditEvent[], nextCursor: page.nextCursor };
    },
    range: async (tenantId, fromSequence, limit) =>
      (await store.range(tenantId, fromSequence, limit)) as readonly SealedAuditEvent[],
  };
}

/* ---------------------------------------------------------------- Ingesta */

function ingestionPort(store: PrismaIngestionStateStore): IngestionStateStore {
  return {
    claimCursor: async (key: IngestionCursorKey, at: Date, leaseMs: number) => {
      const claim = await store.claimCursor(key, at, leaseMs);
      return claim
        ? {
            key,
            watermark: claim.watermark,
            continuation: claim.continuation,
            claimId: claim.claimId,
          }
        : undefined;
    },
    advanceCursor: (claim: ClaimedIngestionCursor, watermark: Date, at: Date) =>
      store.advanceCursor(claim.key, claim.claimId, watermark, at),
    saveContinuation: (claim: ClaimedIngestionCursor, continuation, at: Date) =>
      store.saveContinuation(claim.key, claim.claimId, continuation, at),
    releaseCursor: (claim: ClaimedIngestionCursor) => store.releaseCursor(claim.key, claim.claimId),
    recordObservation: (observation: SourcePollObservation) => store.recordObservation(observation),
    recentTransitions: async (key: IngestionCursorKey, limit: number) =>
      (await store.recentTransitions(key, limit)).map((row) => ({
        ...row,
        fromState:
          row.fromState === null
            ? null
            : oneOf(SOURCE_HEALTH_STATES, row.fromState, 'source_health_transitions', 'from_state'),
        toState: oneOf(SOURCE_HEALTH_STATES, row.toState, 'source_health_transitions', 'to_state'),
        reason: oneOf(SOURCE_HEALTH_REASONS, row.reason, 'source_health_transitions', 'reason'),
      })),
    appendTransition: (transition: SourceHealthTransition) => store.appendTransition(transition),
    saveActivity: (key: IngestionCursorKey, records) => store.saveActivity(key, records),
    activity: (key: IngestionCursorKey) => store.activity(key),
    recentObservations: async (key: IngestionCursorKey, limit: number) =>
      (await store.recentObservations(key, limit)).map((row) => ({
        ...row,
        outcome: oneOf(POLL_OUTCOMES, row.outcome, 'source_poll_observations', 'outcome'),
      })),
  };
}

/* ------------------------------------------------------------------ Adapter */

export class PostgresSocPersistence implements SocPersistence {
  public readonly kind = 'postgres' as const;
  public readonly audit: AuditStore;
  public readonly ingestion: IngestionStateStore;
  private readonly unitOfWork: PrismaSocUnitOfWork;
  private readonly queries: PrismaSocQueries;
  private readonly workQueries: PrismaIncidentWorkQueries;

  private constructor(private readonly client: ReturnType<typeof createDatabaseClient>) {
    this.unitOfWork = new PrismaSocUnitOfWork(client);
    this.queries = new PrismaSocQueries(client);
    this.workQueries = new PrismaIncidentWorkQueries(client);
    this.audit = auditPort(new PrismaStandaloneAuditStore(client));
    this.ingestion = ingestionPort(new PrismaIngestionStateStore(client));
  }

  public static connect(options: DatabaseConnectionOptions): PostgresSocPersistence {
    return new PostgresSocPersistence(createDatabaseClient(options));
  }

  public run<T>(work: (context: SocTransactionContext) => Promise<T>): Promise<T> {
    return this.unitOfWork.run((stores) => {
      const alerts: AlertStore = {
        byId: async (tenantId, alertId) => {
          const row = await stores.alerts.byId(tenantId, alertId);
          return row ? toAlert(row) : undefined;
        },
        insertIfAbsent: (alert) => stores.alerts.insertIfAbsent(fromAlert(alert)),
        update: (alert, expectedRevision) =>
          stores.alerts.update(fromAlert(alert), expectedRevision),
        byIncident: async (tenantId, incidentId) =>
          (await stores.alerts.byIncident(tenantId, incidentId)).map(toAlert),
      };
      const closures: AlertClosureStore = {
        append: (record) =>
          stores.closures.append({
            ...record,
            justification: record.justification,
            evidenceRefs: [...record.evidenceRefs],
          }),
      };
      const fingerprints: AlertFingerprintStore = {
        insertIfAbsent: (record) =>
          stores.fingerprints.insertIfAbsent({ ...record, components: { ...record.components } }),
      };
      const groups: AlertGroupStore = {
        openByFingerprint: async (tenantId, fingerprint) => {
          const row = await stores.groups.openByFingerprint(tenantId, fingerprint);
          return row ? toAlertGroup(row) : undefined;
        },
        insertIfAbsent: (group) => stores.groups.insertIfAbsent(group),
        update: (group, expectedRevision) => stores.groups.update(group, expectedRevision),
        addMember: (member) => stores.groups.addMember(member),
      };
      const patterns: LearningPatternStore = {
        byId: async (tenantId, patternId) => {
          const row = await stores.patterns.byId(tenantId, patternId);
          return row ? toPattern(row) : undefined;
        },
        openByFingerprint: async (tenantId, fingerprint) => {
          const row = await stores.patterns.openByFingerprint(tenantId, fingerprint);
          return row ? toPattern(row) : undefined;
        },
        listOpen: async (tenantId) => (await stores.patterns.listOpen(tenantId)).map(toPattern),
        activeByRule: async (tenantId, ruleKey) =>
          (await stores.patterns.activeByRule(tenantId, ruleKey)).map(toPattern),
        insertIfAbsent: (pattern) => stores.patterns.insertIfAbsent(pattern),
        update: (pattern, expectedRevision) => stores.patterns.update(pattern, expectedRevision),
        approvals: async (tenantId, patternId) =>
          (await stores.patterns.approvals(tenantId, patternId)).map(toApproval),
        appendApproval: (record) => stores.patterns.appendApproval(record),
        appendEvent: (record) =>
          stores.patterns.appendEvent({
            id: record.id,
            tenantId: record.tenantId,
            patternId: record.patternId,
            fromStatus: record.from,
            toStatus: record.to,
            reason: record.reason,
            actorId: record.actorId,
            at: record.at,
          }),
      };
      const incidents: IncidentStore = {
        byId: async (tenantId, incidentId) => {
          const row = await stores.incidents.byId(tenantId, incidentId);
          if (!row) return undefined;
          const linked = await stores.alerts.byIncident(tenantId, incidentId);
          return toIncident({ ...row, alertIds: linked.map((alert) => alert.id) });
        },
        insert: (incident) => stores.incidents.insert(fromIncident(incident)),
        update: (incident, expectedRevision) =>
          stores.incidents.update(fromIncident(incident), expectedRevision),
      };
      const tasks: IncidentTaskStore = {
        byId: async (tenantId, taskId) => {
          const row = await stores.tasks.byId(tenantId, taskId);
          return row ? toTask(row) : undefined;
        },
        byIncident: async (tenantId, incidentId) =>
          (await stores.tasks.byIncident(tenantId, incidentId)).map(toTask),
        insert: (task) => stores.tasks.insert(task),
        update: (task, expectedRevision) => stores.tasks.update(task, expectedRevision),
      };
      const notes: IncidentNoteStore = {
        byId: async (tenantId, noteId) => {
          const row = await stores.notes.byId(tenantId, noteId);
          return row ? toNote(row) : undefined;
        },
        insert: (note) => stores.notes.insert(note),
      };
      const outbox: OutboxStore = {
        enqueueIfAbsent: (message) => stores.outbox.enqueueIfAbsent(message),
      };
      const candidates: DetectionCandidateStore = {
        byIdempotencyKey: async (tenantId, key) => {
          const row = await stores.candidates.byIdempotencyKey(tenantId, key);
          return row ? toCandidate(row) : undefined;
        },
        insertIfAbsent: (candidate) => stores.candidates.insertIfAbsent(candidate),
      };
      const learning: LearningRecordStore = {
        appendDecision: (record) => stores.learning.appendDecision(record),
        decisionById: async (tenantId, decisionId) => {
          const row = await stores.learning.decisionById(tenantId, decisionId);
          return row ? toDecision(row) : undefined;
        },
        counters: (tenantId, patternId, now, since) =>
          stores.learning.counters(tenantId, patternId, now, since, limaDayStart(now)),
        insertReview: (record) => stores.learning.insertReview(record),
        reviewById: async (tenantId, reviewId) => {
          const row = await stores.learning.reviewById(tenantId, reviewId);
          return row ? toReview(row) : undefined;
        },
        updateReview: (record, expectedRevision) =>
          stores.learning.updateReview(record, expectedRevision),
        appendReversal: (record) => stores.learning.appendReversal(record),
      };
      return work({
        alerts,
        closures,
        fingerprints,
        groups,
        patterns,
        learning,
        incidents,
        tasks,
        notes,
        outbox,
        candidates,
        audit: auditPort(stores.audit),
      });
    });
  }

  public async alertById(tenantId: string, alertId: string): Promise<Alert | undefined> {
    const row = await this.queries.alertById(tenantId, alertId);
    return row ? toAlert(row) : undefined;
  }

  public async alertByEventRecordId(
    tenantId: string,
    eventRecordId: string,
  ): Promise<Alert | undefined> {
    const row = await this.queries.alertByEventRecordId(tenantId, eventRecordId);
    return row ? toAlert(row) : undefined;
  }

  public async listAlerts(query: AlertQuery): Promise<QueryResult<Alert>> {
    const result = await this.queries.listAlerts({
      tenantId: query.tenantId,
      ...(query.status ? { status: query.status } : {}),
      ...(query.priority ? { priority: query.priority } : {}),
      ...(query.search ? { search: query.search } : {}),
      ...(query.entityRef ? { entityRef: query.entityRef } : {}),
    });
    return { items: result.rows.map(toAlert), total: result.total };
  }

  public async alertGroupById(tenantId: string, groupId: string): Promise<AlertGroup | undefined> {
    const row = await this.queries.alertGroupById(tenantId, groupId);
    return row ? toAlertGroup(row) : undefined;
  }

  public async alertGroupOf(tenantId: string, alertId: string): Promise<AlertGroup | undefined> {
    const row = await this.queries.alertGroupOf(tenantId, alertId);
    return row ? toAlertGroup(row) : undefined;
  }

  public async alertGroupsOf(
    tenantId: string,
    alertIds: readonly string[],
  ): Promise<ReadonlyMap<string, AlertGroup>> {
    const rows = await this.queries.alertGroupsOf(tenantId, alertIds);
    return new Map([...rows].map(([alertId, row]) => [alertId, toAlertGroup(row)]));
  }

  public async listAlertGroups(query: AlertGroupQuery): Promise<QueryResult<AlertGroup>> {
    const result = await this.queries.listAlertGroups(query);
    return { items: result.items.map(toAlertGroup), total: result.total };
  }

  public async listLearningPatterns(query: {
    readonly tenantId: string;
    readonly status?: LearningPattern['status'];
    readonly limit: number;
  }): Promise<QueryResult<LearningPattern>> {
    const result = await this.queries.listLearningPatterns(query);
    return { items: result.items.map(toPattern), total: result.total };
  }

  public async learningPatternById(
    tenantId: string,
    patternId: string,
  ): Promise<LearningPattern | undefined> {
    const row = await this.queries.learningPatternById(tenantId, patternId);
    return row ? toPattern(row) : undefined;
  }

  public async learningPatternHistory(
    tenantId: string,
    patternId: string,
  ): Promise<{
    readonly approvals: readonly ApprovalRecord[];
    readonly events: readonly PatternEventRecord[];
  }> {
    const history = await this.queries.learningPatternHistory(tenantId, patternId);
    return {
      approvals: history.approvals.map(toApproval),
      events: history.events.map((row) => ({
        id: row.id,
        tenantId: row.tenantId,
        patternId: row.patternId,
        from:
          row.fromStatus === null
            ? null
            : oneOf(PATTERN_STATUSES, row.fromStatus, 'soc_learning_pattern_events', 'from_status'),
        to: oneOf(PATTERN_STATUSES, row.toStatus, 'soc_learning_pattern_events', 'to_status'),
        reason: row.reason,
        actorId: row.actorId,
        at: row.at,
      })),
    };
  }

  public async listLearningDecisions(query: {
    readonly tenantId: string;
    readonly alertId?: string;
    readonly patternId?: string;
    readonly limit: number;
  }): Promise<QueryResult<LearningDecisionRecord>> {
    const result = await this.queries.listLearningDecisions(query);
    return { items: result.items.map(toDecision), total: result.total };
  }

  public async listLearningReviews(query: {
    readonly tenantId: string;
    readonly status?: LearningReviewStatus;
    readonly limit: number;
  }): Promise<QueryResult<LearningReviewRecord>> {
    const result = await this.queries.listLearningReviews(query);
    return { items: result.items.map(toReview), total: result.total };
  }

  /** Etapa D. Último cierre vigente por alerta; TP_REAL de cualquier origen, el resto solo humano. */
  public async learningEvidence(tenantId: string, since: Date): Promise<LearningEvidence> {
    const rows = await this.queries.learningClosures(tenantId, since);
    const closures: ClosureEvidence[] = [];
    const truePositivesByFingerprint = new Map<string, number>();
    for (const row of rows) {
      if (row.closureReason === 'TP_REAL') {
        truePositivesByFingerprint.set(
          row.fingerprint,
          (truePositivesByFingerprint.get(row.fingerprint) ?? 0) + 1,
        );
      }
      if (row.origin === 'human') closures.push(toClosureEvidence(row));
    }
    return { closures, truePositivesByFingerprint };
  }

  public async readinessMetrics(tenantId: string, since: Date): Promise<ReadinessMetrics> {
    const [closedAlertsWithoutOrigin, coverage] = await Promise.all([
      this.queries.closedAlertsWithoutOrigin(tenantId),
      this.queries.sourceCoverage(tenantId, since),
    ]);
    return {
      closedAlertsWithoutOrigin,
      sourceCoverage: new Map(
        coverage.map((row) => [row.source, { fine: row.fine, total: row.total }]),
      ),
    };
  }

  public alertGroupMembers(
    tenantId: string,
    groupId: string,
    limit: number,
  ): Promise<readonly string[]> {
    return this.queries.alertGroupMembers(tenantId, groupId, limit);
  }

  public alertStats(query: AlertStatsQuery): Promise<AlertStats> {
    return this.queries.alertStats(query);
  }

  public async incidentById(tenantId: string, incidentId: string): Promise<Incident | undefined> {
    const row = await this.queries.incidentById(tenantId, incidentId);
    return row ? toIncident(row) : undefined;
  }

  public async listIncidentAlerts(
    tenantId: string,
    incidentId: string,
    limit: number,
  ): Promise<QueryResult<Alert>> {
    const result = await this.queries.alertsByIncident(tenantId, incidentId, limit);
    return { items: result.rows.map(toAlert), total: result.total };
  }

  public async listIncidentTasks(
    tenantId: string,
    incidentId: string,
  ): Promise<readonly IncidentTask[]> {
    return (await this.workQueries.tasksByIncident(tenantId, incidentId)).map(toTask);
  }

  public async listIncidentNotes(
    tenantId: string,
    incidentId: string,
  ): Promise<readonly IncidentNote[]> {
    return (await this.workQueries.notesByIncident(tenantId, incidentId)).map(toNote);
  }

  public async listIncidents(query: IncidentQuery): Promise<QueryResult<Incident>> {
    const result = await this.queries.listIncidents({
      tenantId: query.tenantId,
      ...(query.statuses ? { statuses: query.statuses } : {}),
      ...(query.search ? { search: query.search } : {}),
    });
    return { items: result.rows.map(toIncident), total: result.total };
  }

  public async recentByEntities(
    tenantId: string,
    entityKeys: readonly string[],
    since: Date,
    limit: number,
  ): Promise<readonly CorrelatableAlert[]> {
    const rows = await this.queries.recentByEntities(tenantId, entityKeys, since, limit);
    return rows.map((row) => ({
      id: row.id,
      occurredAt: row.occurredAt,
      entityKeys: [...row.entityKeys],
      signal: optionalOneOf(SIGNAL_CLASSES, row.signal, 'soc_alerts', 'signal'),
      ruleId: row.ruleId,
    }));
  }

  public async claimOutbox(
    at: Date,
    limit: number,
    leaseMs: number,
    lane: OutboxLane = 'all',
  ): Promise<readonly ClaimedOutboxMessage[]> {
    return (await this.queries.claimOutbox(at, limit, leaseMs, lane)).map((row) => ({
      ...toOutboxDraft(row),
      claimToken: row.claimToken,
    }));
  }

  public markOutboxPublished(messageId: string, claimToken: string, at: Date): Promise<boolean> {
    return this.queries.markOutboxPublished(messageId, claimToken, at);
  }

  public scheduleOutboxRetry(
    messageId: string,
    claimToken: string,
    availableAt: Date,
    errorCode: string,
  ): Promise<boolean> {
    return this.queries.scheduleOutboxRetry(messageId, claimToken, availableAt, errorCode);
  }

  public lastAlertAt(tenantId: string): Promise<Date | null> {
    return this.queries.lastAlertAt(tenantId);
  }

  public outboxHealth(tenantId: string, at: Date): Promise<OutboxHealth> {
    return this.queries.outboxHealth(tenantId, at);
  }

  /**
   * Readiness: conectividad y presencia de la última migración que este código necesita.
   * Arrancar contra un esquema viejo produciría errores en la primera alerta, no al inicio.
   */
  public async ready(): Promise<void> {
    // `lease_until` es la última columna que este código necesita: si existe, el esquema
    // está al día con la migración 20261011120000.
    const rows = await this.client.$queryRaw<{ readonly present: boolean }[]>`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'soc_outbox_messages'
           AND column_name = 'lease_until'
      ) AS present`;
    if (!rows[0]?.present) {
      throw new Error('SOC_SCHEMA_OUTDATED: falta la migración 20261011120000.');
    }
  }

  public close(): Promise<void> {
    return closeDatabaseClient(this.client);
  }
}

/** PostgreSQL adapter for the durable Wazuh push hint port. */
export class PostgresWazuhPushInboxStore implements WazuhPushInboxStore {
  private constructor(private readonly store: PrismaWazuhPushInboxStore) {}

  public static connect(options: DatabaseConnectionOptions): PostgresWazuhPushInboxStore {
    return new PostgresWazuhPushInboxStore(PrismaWazuhPushInboxStore.connect(options));
  }

  public ready(): Promise<void> {
    return this.store.ready();
  }

  public close(): Promise<void> {
    return this.store.close();
  }

  public enqueue(hint: WazuhPushHint): Promise<'inserted' | 'duplicate' | 'reopened-terminal'> {
    return this.store.enqueue(hint);
  }

  public claimBatch(
    at: Date,
    limit: number,
    leaseMs: number,
  ): Promise<readonly ClaimedWazuhPushHint[]> {
    return this.store.claimBatch(at, limit, leaseMs);
  }

  public complete(claim: ClaimedWazuhPushHint): Promise<boolean> {
    return this.store.complete(claim);
  }

  public scheduleRetry(
    claim: ClaimedWazuhPushHint,
    availableAt: Date,
    safeCode: string,
  ): Promise<boolean> {
    return this.store.scheduleRetry(claim, availableAt, safeCode);
  }

  public failTerminal(claim: ClaimedWazuhPushHint, safeCode: string): Promise<boolean> {
    return this.store.failTerminal(claim, safeCode);
  }

  public metrics(at?: Date): Promise<WazuhPushInboxMetrics> {
    return this.store.metrics(at);
  }
}
