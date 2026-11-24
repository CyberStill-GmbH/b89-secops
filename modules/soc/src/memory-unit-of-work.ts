/**
 * Adapter en memoria de C-17, para unit specs, desarrollo local y el harness E2E.
 *
 * Implementa la propiedad que las specs deben poder comprobar: si el trabajo lanza, no
 * queda nada escrito —ni estado, ni candidato, ni auditoría, ni outbox—. Se consigue con
 * copia previa y restauración, que es lo que una transacción real hace por nosotros.
 *
 * No sobrevive a un reinicio. Por eso el runtime lo rechaza en el perfil de producción
 * salvo declaración explícita, y la readiness informa el modo efectivo.
 */

import { randomUUID } from 'node:crypto';

import { InMemoryAuditStore } from '@b89/audit';
import type { AuditStore, SealedAuditEvent } from '@b89/audit';
import type {
  CorrelatableAlert,
  DetectionCandidate,
  DetectionCandidateStore,
} from '@b89/detection';

import type { Alert } from './alert.js';
import type { AlertGroup } from './alert-group.js';
import {
  OPEN_PATTERN_STATUSES,
  type ApprovalRecord,
  type ClosureEvidence,
  type LearningPattern,
} from './learning-pattern.js';
import type { AlertClosureRecord } from './closure.js';
import { limaDayStart, type PatternCounters } from './learning-engine.js';
import type { LearningEngineState, LearningEngineStateStore } from './learning-engine-state.js';
import type {
  ContextEntry,
  LearningGovernanceStore,
  RuleEnablement,
} from './learning-governance.js';
import { LEARNING_NOTICE_DEADLINES, LEARNING_NOTICE_PREFIX } from './learning-notices.js';
import type { Incident } from './incident.js';
import type { IncidentNote, IncidentTask } from './incident-work.js';
import { InMemoryIngestionState } from './memory-ingestion.js';
import type { OutboxMessageDraft } from './events.js';
import { DEFAULT_FALSE_POSITIVE_ORIGINS, type OutboxLane } from './ports.js';
import type {
  AlertQuery,
  AlertStats,
  AlertStatsQuery,
  AlertClosureStore,
  AlertFingerprintRecord,
  AlertFingerprintStore,
  AlertGroupQuery,
  AlertGroupStore,
  AlertStore,
  LearningConfigEvent,
  LearningHealthCounts,
  LearningDecisionRecord,
  LearningEvidence,
  LearningJob,
  LearningJobQueue,
  LearningJobStore,
  LearningPatternStore,
  LearningRecordStore,
  LearningReversalRecord,
  LearningReviewRecord,
  LearningReviewStatus,
  PatternEventRecord,
  ReadinessMetrics,
  ClaimedOutboxMessage,
  OutboxHealth,
  IncidentNoteStore,
  IncidentQuery,
  IncidentStore,
  IncidentTaskStore,
  OutboxStore,
  QueryResult,
  SocPersistence,
  SocTransactionContext,
} from './ports.js';

interface Snapshot {
  readonly alerts: ReadonlyMap<string, Alert>;
  readonly closures: readonly AlertClosureRecord[];
  readonly fingerprints: ReadonlyMap<string, AlertFingerprintRecord>;
  readonly groups: ReadonlyMap<string, AlertGroup>;
  readonly patterns: ReadonlyMap<string, LearningPattern>;
  readonly approvals: readonly ApprovalRecord[];
  readonly patternEvents: readonly PatternEventRecord[];
  readonly decisions: ReadonlyMap<string, LearningDecisionRecord>;
  readonly reviews: ReadonlyMap<string, LearningReviewRecord>;
  readonly reversals: readonly LearningReversalRecord[];
  readonly jobs: ReadonlyMap<string, LearningJob>;
  readonly engineStates: ReadonlyMap<string, LearningEngineState>;
  readonly enablements: ReadonlyMap<string, RuleEnablement>;
  readonly contextEntries: ReadonlyMap<string, ContextEntry>;
  readonly groupMembers: ReadonlyMap<string, GroupMember>;
  readonly incidents: ReadonlyMap<string, Incident>;
  readonly tasks: ReadonlyMap<string, IncidentTask>;
  readonly notes: ReadonlyMap<string, IncidentNote>;
  readonly outbox: ReadonlyMap<string, OutboxMessageDraft>;
  readonly candidates: ReadonlyMap<string, DetectionCandidate>;
}

interface GroupMember {
  readonly tenantId: string;
  readonly groupId: string;
  readonly alertId: string;
  readonly joinedAt: Date;
}

interface OutboxQueueState {
  status: 'pending' | 'processing' | 'published';
  availableAt: Date;
  attemptCount: number;
  leaseUntil: Date | null;
  claimToken: string | null;
  lastErrorCode: string | null;
  publishedAt: Date | null;
}

function newestFirst(left: { at: Date; id: string }, right: { at: Date; id: string }): number {
  const delta = right.at.getTime() - left.at.getTime();
  if (delta !== 0) return delta;
  return left.id < right.id ? 1 : left.id > right.id ? -1 : 0;
}

export class InMemorySoc implements SocPersistence {
  public readonly kind = 'memory' as const;
  public readonly alertRows = new Map<string, Alert>();
  /** Bitácora append-only de cierres (aprendizaje SOC · etapa A). */
  public readonly closureRows: AlertClosureRecord[] = [];
  /** Huellas por `tenant|alerta` (aprendizaje SOC · etapa B). */
  public readonly fingerprintRows = new Map<string, AlertFingerprintRecord>();
  /** Grupos por `tenant|grupo` y pertenencia por `tenant|alerta` (etapa C). */
  public readonly groupRows = new Map<string, AlertGroup>();
  public readonly groupMemberRows = new Map<string, GroupMember>();
  /** Etapa D: patrones por `tenant|id`; firmas y eventos append-only. */
  public readonly patternRows = new Map<string, LearningPattern>();
  public readonly approvalRows: ApprovalRecord[] = [];
  public readonly patternEventRows: PatternEventRecord[] = [];
  /** Etapa E: decisiones por `tenant|alertId` (una por alerta), revisiones y reversiones. */
  public readonly decisionRows = new Map<string, LearningDecisionRecord>();
  public readonly reviewRows = new Map<string, LearningReviewRecord>();
  public readonly reversalRows: LearningReversalRecord[] = [];
  /** Fase 2: cola del motor por `tenant|alertId`, latidos y configuración de cada arranque. */
  public readonly jobRows = new Map<string, LearningJob>();
  public readonly heartbeatRows = new Map<
    string,
    { tenantId: string; at: Date; claimed: number; failed: number }
  >();
  public readonly configEventRows: LearningConfigEvent[] = [];
  public readonly engineStateRows = new Map<string, LearningEngineState>();
  public readonly enablementRows = new Map<string, RuleEnablement>();
  public readonly contextEntryRows = new Map<string, ContextEntry>();

  private readonly learningGovernance: LearningGovernanceStore = {
    enablementById: (tenantId, id) => Promise.resolve(this.enablementRows.get(`${tenantId}|${id}`)),
    insertEnablement: (row) => {
      const open = [...this.enablementRows.values()].some(
        (other) =>
          other.tenantId === row.tenantId &&
          other.ruleKey === row.ruleKey &&
          other.status !== 'revoked',
      );
      if (open) return Promise.resolve(false);
      this.enablementRows.set(`${row.tenantId}|${row.id}`, row);
      return Promise.resolve(true);
    },
    updateEnablement: (row, expectedRevision) => {
      const key = `${row.tenantId}|${row.id}`;
      if (this.enablementRows.get(key)?.revision !== expectedRevision)
        return Promise.resolve(false);
      this.enablementRows.set(key, row);
      return Promise.resolve(true);
    },
    contextById: (tenantId, id) => Promise.resolve(this.contextEntryRows.get(`${tenantId}|${id}`)),
    insertContext: (row) => {
      this.contextEntryRows.set(`${row.tenantId}|${row.id}`, row);
      return Promise.resolve();
    },
    updateContext: (row, expectedRevision) => {
      const key = `${row.tenantId}|${row.id}`;
      if (this.contextEntryRows.get(key)?.revision !== expectedRevision)
        return Promise.resolve(false);
      this.contextEntryRows.set(key, row);
      return Promise.resolve(true);
    },
  };

  private readonly learningState: LearningEngineStateStore = {
    get: (tenantId) => Promise.resolve(this.engineStateRows.get(tenantId)),
    save: (state, expectedRevision) => {
      const current = this.engineStateRows.get(state.tenantId);
      if ((current?.revision ?? null) !== expectedRevision) return Promise.resolve(false);
      this.engineStateRows.set(state.tenantId, state);
      return Promise.resolve(true);
    },
  };

  private readonly learningJobs: LearningJobStore = {
    enqueue: (job) => {
      const key = `${job.tenantId}|${job.alertId}`;
      if (this.jobRows.has(key)) return Promise.resolve(false);
      this.jobRows.set(key, job);
      return Promise.resolve(true);
    },
  };

  /** Fuera de transacción, como en PostgreSQL. Sin concurrencia real: la prueba es de contrato. */
  public readonly learningQueue: LearningJobQueue = {
    claim: ({ limit, leaseMs, now, claimId }) => {
      const ready = [...this.jobRows.values()]
        .filter(
          (job) =>
            (job.status === 'pending' && job.availableAt.getTime() <= now.getTime()) ||
            (job.status === 'leased' &&
              job.leaseUntil !== null &&
              job.leaseUntil.getTime() < now.getTime()),
        )
        .sort((left, right) => left.availableAt.getTime() - right.availableAt.getTime())
        .slice(0, limit);
      const claimed = ready.map((job) => {
        const next: LearningJob = {
          ...job,
          status: 'leased',
          attempts: job.attempts + 1,
          leaseUntil: new Date(now.getTime() + leaseMs),
          claimId,
        };
        this.jobRows.set(`${job.tenantId}|${job.alertId}`, next);
        return next;
      });
      return Promise.resolve(claimed);
    },
    complete: (alertId, claimId, now) => this.finishJob(alertId, claimId, now, null, null),
    fail: (alertId, claimId, error, now, retryAt) =>
      this.finishJob(alertId, claimId, now, error, retryAt ?? undefined),
    heartbeat: (beat) => {
      this.heartbeatRows.set(beat.workerId, {
        tenantId: beat.tenantId,
        at: beat.at,
        claimed: beat.claimed,
        failed: beat.failed,
      });
      return Promise.resolve();
    },
    recordConfig: (event) => {
      this.configEventRows.push(event);
      return Promise.resolve();
    },
  };

  /** `error = null` ⇒ terminado; `retryAt` definido ⇒ vuelve a pendiente; `undefined` ⇒ `dead`. */
  private finishJob(
    alertId: string,
    claimId: string,
    now: Date,
    error: string | null,
    retryAt: Date | null | undefined,
  ): Promise<boolean> {
    const entry = [...this.jobRows.entries()].find(([, job]) => job.alertId === alertId);
    if (!entry || entry[1].status !== 'leased' || entry[1].claimId !== claimId)
      return Promise.resolve(false);
    const [key, job] = entry;
    const base = { ...job, leaseUntil: null, claimId: null, lastError: error };
    this.jobRows.set(
      key,
      error === null
        ? { ...base, status: 'done', finishedAt: now }
        : retryAt instanceof Date
          ? { ...base, status: 'pending', availableAt: retryAt }
          : { ...base, status: 'dead', finishedAt: now },
    );
    return Promise.resolve(true);
  }
  public readonly incidentRows = new Map<string, Incident>();
  public readonly taskRows = new Map<string, IncidentTask>();
  public readonly noteRows = new Map<string, IncidentNote>();
  public readonly outboxRows = new Map<string, OutboxMessageDraft>();
  public readonly candidateRows = new Map<string, DetectionCandidate>();
  /** Estado de cola por `messageId`: equivale a las columnas de lease de PostgreSQL. */
  public readonly outboxState = new Map<string, OutboxQueueState>();
  private auditStoreRef = new InMemoryAuditStore();
  /** Estado de ingesta; fuera de la unidad de trabajo, como en PostgreSQL. */
  public readonly ingestion = new InMemoryIngestionState();
  /** Fuerza el fallo del commit en la siguiente transacción, para specs de rollback. */
  public failNextCommit = false;

  private readonly alerts: AlertStore = {
    byId: (tenantId, alertId) => Promise.resolve(this.alertRows.get(`${tenantId}|${alertId}`)),
    insertIfAbsent: (alert) => {
      const key = `${alert.tenantId}|${alert.id}`;
      if (this.alertRows.has(key)) return Promise.resolve(false);
      this.alertRows.set(key, alert);
      return Promise.resolve(true);
    },
    update: (alert, expectedRevision) => {
      const key = `${alert.tenantId}|${alert.id}`;
      const current = this.alertRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.alertRows.set(key, alert);
      return Promise.resolve(true);
    },
    byIncident: (tenantId, incidentId) =>
      Promise.resolve(
        [...this.alertRows.values()].filter(
          (alert) => alert.tenantId === tenantId && alert.incidentId === incidentId,
        ),
      ),
  };

  private readonly closures: AlertClosureStore = {
    append: (record) => {
      this.closureRows.push(record);
      return Promise.resolve();
    },
  };

  private readonly fingerprints: AlertFingerprintStore = {
    insertIfAbsent: (record) => {
      const key = `${record.tenantId}|${record.alertId}`;
      if (this.fingerprintRows.has(key)) return Promise.resolve(false);
      this.fingerprintRows.set(key, record);
      return Promise.resolve(true);
    },
  };

  private readonly learning: LearningRecordStore = {
    appendDecision: (record) => {
      const key = `${record.tenantId}|${record.alertId}`;
      if (this.decisionRows.has(key)) return Promise.resolve(false);
      this.decisionRows.set(key, record);
      return Promise.resolve(true);
    },
    decisionById: (tenantId, decisionId) =>
      Promise.resolve(
        [...this.decisionRows.values()].find(
          (row) => row.tenantId === tenantId && row.id === decisionId,
        ),
      ),
    decisionByAlert: (tenantId, alertId) =>
      Promise.resolve(this.decisionRows.get(`${tenantId}|${alertId}`)),
    counters: (tenantId, patternId, now, since) =>
      Promise.resolve(this.patternCounters(tenantId, patternId, now, since)),
    insertReview: (record) => {
      this.reviewRows.set(`${record.tenantId}|${record.id}`, record);
      return Promise.resolve();
    },
    reviewById: (tenantId, reviewId) =>
      Promise.resolve(this.reviewRows.get(`${tenantId}|${reviewId}`)),
    updateReview: (record, expectedRevision) => {
      const key = `${record.tenantId}|${record.id}`;
      const current = this.reviewRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.reviewRows.set(key, record);
      return Promise.resolve(true);
    },
    appendReversal: (record) => {
      this.reversalRows.push(record);
      return Promise.resolve();
    },
  };

  /** Mismo cálculo que la consulta SQL de `PrismaLearningRecordStore.counters`. */
  private patternCounters(
    tenantId: string,
    patternId: string,
    now: Date,
    since: Date,
  ): PatternCounters {
    const closes = [...this.decisionRows.values()].filter(
      (row) =>
        row.tenantId === tenantId &&
        row.patternId === patternId &&
        row.proposedAction === 'AUTO_CLOSE' &&
        row.mode !== 'shadow' &&
        row.at >= since,
    );
    const resolved = [...this.reviewRows.values()].filter(
      (row) => row.tenantId === tenantId && row.patternId === patternId && row.resolvedAt !== null,
    );
    const lastReview = resolved.reduce<Date | null>(
      (latest, row) => (latest === null || row.resolvedAt! > latest ? row.resolvedAt : latest),
      null,
    );
    const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const dayStart = limaDayStart(now);
    return {
      autoClosedLastHour: closes.filter((row) => row.at > hourAgo).length,
      autoClosedToday: closes.filter((row) => row.at >= dayStart).length,
      autoClosedSinceReview: closes.filter((row) => lastReview === null || row.at > lastReview)
        .length,
      agreedSamplesLast30Days: resolved.filter(
        (row) =>
          row.kind === 'quality_sample' && row.status === 'agreed' && row.resolvedAt! > monthAgo,
      ).length,
    };
  }

  private readonly patterns: LearningPatternStore = {
    byId: (tenantId, patternId) =>
      Promise.resolve(this.patternRows.get(`${tenantId}|${patternId}`)),
    openByFingerprint: (tenantId, fingerprint) =>
      Promise.resolve(
        [...this.patternRows.values()].find(
          (pattern) =>
            pattern.tenantId === tenantId &&
            pattern.fingerprint === fingerprint &&
            OPEN_PATTERN_STATUSES.includes(pattern.status),
        ),
      ),
    activeByRule: (tenantId, ruleKey) =>
      Promise.resolve(
        [...this.patternRows.values()].filter(
          (pattern) =>
            pattern.tenantId === tenantId &&
            pattern.ruleKey === ruleKey &&
            pattern.status === 'active',
        ),
      ),
    listOpen: (tenantId) =>
      Promise.resolve(
        [...this.patternRows.values()].filter(
          (pattern) =>
            pattern.tenantId === tenantId && OPEN_PATTERN_STATUSES.includes(pattern.status),
        ),
      ),
    insertIfAbsent: (pattern) => {
      const clash = [...this.patternRows.values()].some(
        (row) =>
          row.id === pattern.id ||
          (row.tenantId === pattern.tenantId &&
            row.fingerprint === pattern.fingerprint &&
            OPEN_PATTERN_STATUSES.includes(row.status)),
      );
      if (clash) return Promise.resolve(false);
      this.patternRows.set(`${pattern.tenantId}|${pattern.id}`, pattern);
      return Promise.resolve(true);
    },
    update: (pattern, expectedRevision) => {
      const key = `${pattern.tenantId}|${pattern.id}`;
      const current = this.patternRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.patternRows.set(key, pattern);
      return Promise.resolve(true);
    },
    approvals: (tenantId, patternId) =>
      Promise.resolve(
        this.approvalRows.filter((row) => row.tenantId === tenantId && row.patternId === patternId),
      ),
    appendApproval: (record) => {
      this.approvalRows.push(record);
      return Promise.resolve();
    },
    appendEvent: (record) => {
      this.patternEventRows.push(record);
      return Promise.resolve();
    },
  };

  private readonly groups: AlertGroupStore = {
    openByFingerprint: (tenantId, fingerprint) =>
      Promise.resolve(
        [...this.groupRows.values()].find(
          (group) =>
            group.tenantId === tenantId &&
            group.fingerprint === fingerprint &&
            group.status === 'open',
        ),
      ),
    insertIfAbsent: (group) => {
      const clash = [...this.groupRows.values()].some(
        (row) =>
          row.id === group.id ||
          (group.status === 'open' &&
            row.status === 'open' &&
            row.tenantId === group.tenantId &&
            row.fingerprint === group.fingerprint),
      );
      if (clash) return Promise.resolve(false);
      this.groupRows.set(`${group.tenantId}|${group.id}`, group);
      return Promise.resolve(true);
    },
    update: (group, expectedRevision) => {
      const key = `${group.tenantId}|${group.id}`;
      const current = this.groupRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.groupRows.set(key, group);
      return Promise.resolve(true);
    },
    addMember: (member) => {
      const key = `${member.tenantId}|${member.alertId}`;
      if (!this.groupMemberRows.has(key)) this.groupMemberRows.set(key, member);
      return Promise.resolve();
    },
  };

  private readonly incidents: IncidentStore = {
    byId: (tenantId, incidentId) =>
      Promise.resolve(this.incidentRows.get(`${tenantId}|${incidentId}`)),
    insert: (incident) => {
      this.incidentRows.set(`${incident.tenantId}|${incident.id}`, incident);
      return Promise.resolve();
    },
    update: (incident, expectedRevision) => {
      const key = `${incident.tenantId}|${incident.id}`;
      const current = this.incidentRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.incidentRows.set(key, incident);
      return Promise.resolve(true);
    },
  };

  private readonly tasks: IncidentTaskStore = {
    byId: (tenantId, taskId) => Promise.resolve(this.taskRows.get(`${tenantId}|${taskId}`)),
    byIncident: (tenantId, incidentId) =>
      Promise.resolve(
        [...this.taskRows.values()].filter(
          (task) => task.tenantId === tenantId && task.incidentId === incidentId,
        ),
      ),
    insert: (task) => {
      this.taskRows.set(`${task.tenantId}|${task.id}`, task);
      return Promise.resolve();
    },
    update: (task, expectedRevision) => {
      const key = `${task.tenantId}|${task.id}`;
      const current = this.taskRows.get(key);
      if (!current || current.revision !== expectedRevision) return Promise.resolve(false);
      this.taskRows.set(key, task);
      return Promise.resolve(true);
    },
  };

  /** Append-only, igual que la tabla: sin update ni borrado. */
  private readonly notes: IncidentNoteStore = {
    byId: (tenantId, noteId) => Promise.resolve(this.noteRows.get(`${tenantId}|${noteId}`)),
    insert: (note) => {
      const key = `${note.tenantId}|${note.id}`;
      if (this.noteRows.has(key)) return Promise.reject(new Error('NOTE_ALREADY_EXISTS'));
      this.noteRows.set(key, note);
      return Promise.resolve();
    },
  };

  private readonly outbox: OutboxStore = {
    enqueueIfAbsent: (message) => {
      if (this.outboxRows.has(message.idempotencyKey)) return Promise.resolve(false);
      this.outboxRows.set(message.idempotencyKey, message);
      return Promise.resolve(true);
    },
  };

  private readonly candidates: DetectionCandidateStore = {
    byIdempotencyKey: (tenantId, key) =>
      Promise.resolve(this.candidateRows.get(`${tenantId}|${key}`)),
    insertIfAbsent: (candidate) => {
      const key = `${candidate.tenantId}|${candidate.idempotencyKey}`;
      if (this.candidateRows.has(key)) return Promise.resolve(false);
      this.candidateRows.set(key, candidate);
      return Promise.resolve(true);
    },
  };

  private snapshot(): Snapshot {
    return {
      alerts: new Map(this.alertRows),
      closures: [...this.closureRows],
      fingerprints: new Map(this.fingerprintRows),
      groups: new Map(this.groupRows),
      patterns: new Map(this.patternRows),
      approvals: [...this.approvalRows],
      patternEvents: [...this.patternEventRows],
      decisions: new Map(this.decisionRows),
      reviews: new Map(this.reviewRows),
      reversals: [...this.reversalRows],
      jobs: new Map(this.jobRows),
      engineStates: new Map(this.engineStateRows),
      enablements: new Map(this.enablementRows),
      contextEntries: new Map(this.contextEntryRows),
      groupMembers: new Map(this.groupMemberRows),
      incidents: new Map(this.incidentRows),
      tasks: new Map(this.taskRows),
      notes: new Map(this.noteRows),
      outbox: new Map(this.outboxRows),
      candidates: new Map(this.candidateRows),
    };
  }

  /** Siempre la instancia vigente: un rollback la reemplaza. */
  public get auditStore(): InMemoryAuditStore {
    return this.auditStoreRef;
  }

  public get audit(): AuditStore {
    return this.auditStoreRef;
  }

  private restore(snapshot: Snapshot, auditBefore: readonly SealedAuditEvent[]): void {
    const replace = <T>(target: Map<string, T>, source: ReadonlyMap<string, T>) => {
      target.clear();
      for (const [key, value] of source) target.set(key, value);
    };
    replace(this.alertRows, snapshot.alerts);
    this.closureRows.splice(0, this.closureRows.length, ...snapshot.closures);
    replace(this.fingerprintRows, snapshot.fingerprints);
    replace(this.groupRows, snapshot.groups);
    replace(this.patternRows, snapshot.patterns);
    this.approvalRows.splice(0, this.approvalRows.length, ...snapshot.approvals);
    this.patternEventRows.splice(0, this.patternEventRows.length, ...snapshot.patternEvents);
    replace(this.decisionRows, snapshot.decisions);
    replace(this.reviewRows, snapshot.reviews);
    this.reversalRows.splice(0, this.reversalRows.length, ...snapshot.reversals);
    replace(this.jobRows, snapshot.jobs);
    replace(this.engineStateRows, snapshot.engineStates);
    replace(this.enablementRows, snapshot.enablements);
    replace(this.contextEntryRows, snapshot.contextEntries);
    replace(this.groupMemberRows, snapshot.groupMembers);
    replace(this.incidentRows, snapshot.incidents);
    replace(this.taskRows, snapshot.tasks);
    replace(this.noteRows, snapshot.notes);
    replace(this.outboxRows, snapshot.outbox);
    replace(this.candidateRows, snapshot.candidates);
    this.auditRollback(auditBefore);
  }

  /**
   * La auditoría no admite borrado por contrato. Para restaurar el estado previo se
   * reconstruye el store completo, que es justo lo que hace un ROLLBACK: la fila nunca
   * llegó a existir.
   */
  private auditRollback(before: readonly SealedAuditEvent[]): void {
    const replacement = new InMemoryAuditStore();
    for (const event of before) void replacement.append(event);
    this.auditStoreRef = replacement;
  }

  public async run<T>(work: (context: SocTransactionContext) => Promise<T>): Promise<T> {
    const snapshot = this.snapshot();
    const auditBefore = await this.allAudit();
    try {
      const result = await work({
        alerts: this.alerts,
        closures: this.closures,
        fingerprints: this.fingerprints,
        groups: this.groups,
        patterns: this.patterns,
        learning: this.learning,
        learningJobs: this.learningJobs,
        learningState: this.learningState,
        learningGovernance: this.learningGovernance,
        incidents: this.incidents,
        tasks: this.tasks,
        notes: this.notes,
        outbox: this.outbox,
        audit: this.auditStoreRef as AuditStore,
        candidates: this.candidates,
      });
      if (this.failNextCommit) {
        this.failNextCommit = false;
        throw new Error('COMMIT_FAILED');
      }
      return result;
    } catch (error) {
      this.restore(snapshot, auditBefore);
      throw error;
    }
  }

  public async allAudit(): Promise<readonly SealedAuditEvent[]> {
    const events: SealedAuditEvent[] = [];
    for (const tenant of this.auditStoreRef.tenants()) {
      events.push(...(await this.auditStoreRef.range(tenant, 1n, 1_000)));
    }
    return events;
  }

  /* ---------------------------------------------------------------- Lecturas */

  public alertById(tenantId: string, alertId: string): Promise<Alert | undefined> {
    return Promise.resolve(this.alertRows.get(`${tenantId}|${alertId}`));
  }

  public alertGroupById(tenantId: string, groupId: string): Promise<AlertGroup | undefined> {
    return Promise.resolve(this.groupRows.get(`${tenantId}|${groupId}`));
  }

  public alertGroupOf(tenantId: string, alertId: string): Promise<AlertGroup | undefined> {
    const member = this.groupMemberRows.get(`${tenantId}|${alertId}`);
    return Promise.resolve(
      member ? this.groupRows.get(`${tenantId}|${member.groupId}`) : undefined,
    );
  }

  /** Último registro de cierre vigente por alerta (una reapertura posterior lo anula). */
  private latestClosures(tenantId: string, since: Date) {
    const latest = new Map<string, AlertClosureRecord>();
    for (const row of this.closureRows) {
      if (row.tenantId !== tenantId) continue;
      const current = latest.get(row.alertId);
      if (!current || row.at.getTime() >= current.at.getTime()) latest.set(row.alertId, row);
    }
    return [...latest.values()].filter((row) => row.kind === 'close' && row.at >= since);
  }

  public learningEvidence(tenantId: string, since: Date): Promise<LearningEvidence> {
    const closures: ClosureEvidence[] = [];
    const truePositivesByFingerprint = new Map<string, number>();
    for (const row of this.latestClosures(tenantId, since)) {
      const fingerprint = this.fingerprintRows.get(`${tenantId}|${row.alertId}`);
      const alert = this.alertRows.get(`${tenantId}|${row.alertId}`);
      if (!fingerprint || !alert) continue;
      if (row.closureReason === 'TP_REAL') {
        truePositivesByFingerprint.set(
          fingerprint.fingerprint,
          (truePositivesByFingerprint.get(fingerprint.fingerprint) ?? 0) + 1,
        );
      }
      if (row.origin !== 'human') continue;
      closures.push({
        alertId: row.alertId,
        actorId: row.actorId,
        at: row.at,
        closureReason: row.closureReason,
        decisionGroupId: row.decisionGroupId,
        priority: alert.priority,
        ruleKey: fingerprint.ruleKey,
        fingerprint: fingerprint.fingerprint,
        level: fingerprint.level,
        normalizerVersion: fingerprint.normalizerVersion,
        components: fingerprint.components,
      });
    }
    return Promise.resolve({ closures, truePositivesByFingerprint });
  }

  public listLearningPatterns(query: {
    readonly tenantId: string;
    readonly status?: LearningPattern['status'];
    readonly limit: number;
  }): Promise<QueryResult<LearningPattern>> {
    const items = [...this.patternRows.values()]
      .filter(
        (row) => row.tenantId === query.tenantId && (!query.status || row.status === query.status),
      )
      .sort((left, right) => right.updatedAt.getTime() - left.updatedAt.getTime());
    return Promise.resolve({ items: items.slice(0, query.limit), total: items.length });
  }

  public learningPatternById(
    tenantId: string,
    patternId: string,
  ): Promise<LearningPattern | undefined> {
    return Promise.resolve(this.patternRows.get(`${tenantId}|${patternId}`));
  }

  public learningPatternHistory(tenantId: string, patternId: string) {
    return Promise.resolve({
      approvals: this.approvalRows.filter(
        (row) => row.tenantId === tenantId && row.patternId === patternId,
      ),
      events: this.patternEventRows.filter(
        (row) => row.tenantId === tenantId && row.patternId === patternId,
      ),
    });
  }

  public listLearningDecisions(query: {
    readonly tenantId: string;
    readonly alertId?: string;
    readonly patternId?: string;
    readonly limit: number;
  }): Promise<QueryResult<LearningDecisionRecord>> {
    const items = [...this.decisionRows.values()]
      .filter(
        (row) =>
          row.tenantId === query.tenantId &&
          (!query.alertId || row.alertId === query.alertId) &&
          (!query.patternId || row.patternId === query.patternId),
      )
      .sort((left, right) => right.at.getTime() - left.at.getTime());
    return Promise.resolve({ items: items.slice(0, query.limit), total: items.length });
  }

  public listLearningReviews(query: {
    readonly tenantId: string;
    readonly status?: LearningReviewStatus;
    readonly limit: number;
  }): Promise<QueryResult<LearningReviewRecord>> {
    const items = [...this.reviewRows.values()]
      .filter(
        (row) => row.tenantId === query.tenantId && (!query.status || row.status === query.status),
      )
      .sort((left, right) => right.at.getTime() - left.at.getTime());
    return Promise.resolve({ items: items.slice(0, query.limit), total: items.length });
  }

  public listRuleEnablements(tenantId: string) {
    return Promise.resolve(
      [...this.enablementRows.values()].filter((row) => row.tenantId === tenantId),
    );
  }

  public listContextEntries(tenantId: string) {
    return Promise.resolve(
      [...this.contextEntryRows.values()].filter((row) => row.tenantId === tenantId),
    );
  }

  public learningEngineState(tenantId: string) {
    return Promise.resolve(this.engineStateRows.get(tenantId));
  }

  /** Mismo criterio que `PrismaSocQueries.learningUndeliveredNotices`. */
  public learningUndeliveredNotices(tenantId: string, now: Date) {
    let hot = 0;
    let warm = 0;
    for (const message of this.outboxRows.values()) {
      if (message.tenantId !== tenantId || message.messageType !== 'soc.alert.review_requested')
        continue;
      if (!String(message.payload['reasonCodes'] ?? '').startsWith(LEARNING_NOTICE_PREFIX))
        continue;
      if (this.outboxState.get(message.messageId)?.status === 'published') continue;
      const age = now.getTime() - message.availableAt.getTime();
      if (message.payload['urgency'] === 'immediate') {
        if (age > LEARNING_NOTICE_DEADLINES.hotMs) hot += 1;
      } else if (age > LEARNING_NOTICE_DEADLINES.warmMs) warm += 1;
    }
    return Promise.resolve({ hot, warm });
  }

  public learningShadowRows(tenantId: string, from: Date, to: Date) {
    return Promise.resolve(
      [...this.decisionRows.values()]
        .filter((row) => row.tenantId === tenantId && row.at >= from && row.at < to)
        .map((row) => {
          const alert = this.alertRows.get(`${tenantId}|${row.alertId}`);
          return {
            ruleKey: row.ruleKey,
            patternId: row.patternId,
            mode: row.mode,
            proposedAction: row.proposedAction,
            appliedAction: row.appliedAction,
            escalateReason: row.escalateReason,
            alertStatus: alert?.status ?? 'unknown',
            closureOrigin: alert?.closureOrigin ?? null,
            closureReason: alert?.closureReason ?? null,
            verdict: alert?.verdict ?? null,
            incidentLinked: (alert?.incidentId ?? null) !== null,
          };
        }),
    );
  }

  /** Mismo cálculo que `PrismaSocQueries.learningHealthCounts`. */
  public learningHealthCounts(tenantId: string, now: Date): Promise<LearningHealthCounts> {
    const hourAgo = now.getTime() - 60 * 60 * 1000;
    const dayAgo = now.getTime() - 24 * 60 * 60 * 1000;
    const jobs = [...this.jobRows.values()].filter((job) => job.tenantId === tenantId);
    const pending = jobs.filter((job) => job.status === 'pending');
    const finishedHour = jobs.filter(
      (job) =>
        job.status === 'done' && job.finishedAt !== null && job.finishedAt.getTime() > hourAgo,
    );
    const latencies = finishedHour
      .map((job) => job.finishedAt!.getTime() - job.enqueuedAt.getTime())
      .sort((left, right) => left - right);
    const decisions = [...this.decisionRows.values()].filter(
      (row) => row.tenantId === tenantId && row.at.getTime() > hourAgo,
    );
    const byApplied: Partial<Record<LearningDecisionRecord['appliedAction'], number>> = {};
    const byEscalateReason: Record<string, number> = {};
    for (const row of decisions) {
      byApplied[row.appliedAction] = (byApplied[row.appliedAction] ?? 0) + 1;
      if (row.escalateReason)
        byEscalateReason[row.escalateReason] = (byEscalateReason[row.escalateReason] ?? 0) + 1;
    }
    const heartbeats = [...this.heartbeatRows.values()].filter(
      (beat) => beat.tenantId === tenantId,
    );
    const configs = this.configEventRows
      .filter((event) => event.tenantId === tenantId)
      .sort((left, right) => left.at.getTime() - right.at.getTime());
    const rank = { off: 0, shadow: 1, dry_run: 2, active: 3 } as const;
    let configChanges = 0;
    let modeRaised = false;
    configs.forEach((event, index) => {
      const previous = configs[index - 1];
      if (!previous || event.at.getTime() <= dayAgo) return;
      if (event.configHash !== previous.configHash) configChanges += 1;
      if (rank[event.maxMode] > rank[previous.maxMode]) modeRaised = true;
    });
    return Promise.resolve({
      heartbeatAt: heartbeats.reduce<Date | null>(
        (latest, beat) => (latest === null || beat.at > latest ? beat.at : latest),
        null,
      ),
      backlog: {
        pending: pending.length,
        expiredLeases: jobs.filter(
          (job) =>
            job.status === 'leased' &&
            job.leaseUntil !== null &&
            job.leaseUntil.getTime() < now.getTime(),
        ).length,
        oldestPendingAt: pending.reduce<Date | null>(
          (oldest, job) => (oldest === null || job.enqueuedAt < oldest ? job.enqueuedAt : oldest),
          null,
        ),
      },
      deadLast24h: jobs.filter(
        (job) =>
          job.status === 'dead' && job.finishedAt !== null && job.finishedAt.getTime() > dayAgo,
      ).length,
      lastHour: {
        jobsFinished: finishedHour.length,
        jobsRetried:
          jobs.filter((job) => job.lastError !== null && job.status === 'pending').length +
          finishedHour.filter((job) => job.attempts > 1).length,
        latencyP95Ms:
          latencies.length === 0 ? null : latencies[Math.ceil(latencies.length * 0.95) - 1]!,
        decisions: decisions.length,
        byApplied,
        byEscalateReason,
        hypotheticalCloses: decisions.filter(
          (row) => row.proposedAction === 'AUTO_CLOSE' && row.appliedAction !== 'AUTO_CLOSE',
        ).length,
      },
      last24h: {
        pauses: this.patternEventRows.filter(
          (row) => row.tenantId === tenantId && row.to === 'paused' && row.at.getTime() > dayAgo,
        ).length,
        reversals: this.reversalRows.filter(
          (row) => row.tenantId === tenantId && row.at.getTime() > dayAgo,
        ).length,
        disagreements: [...this.reviewRows.values()].filter(
          (row) =>
            row.tenantId === tenantId &&
            row.status === 'disagreed' &&
            row.resolvedAt !== null &&
            row.resolvedAt.getTime() > dayAgo,
        ).length,
        configChanges,
        modeRaised,
      },
    });
  }

  public readinessMetrics(tenantId: string, since: Date): Promise<ReadinessMetrics> {
    const closedAlertsWithoutOrigin = [...this.alertRows.values()].filter(
      (alert) =>
        alert.tenantId === tenantId && alert.status === 'closed' && alert.closureOrigin === null,
    ).length;
    const sourceCoverage = new Map<string, { fine: number; total: number }>();
    for (const row of this.fingerprintRows.values()) {
      if (row.tenantId !== tenantId || row.computedAt < since || row.ruleKey === null) continue;
      const source = row.ruleKey.slice(0, Math.max(0, row.ruleKey.indexOf(':'))) || row.ruleKey;
      const entry = sourceCoverage.get(source) ?? { fine: 0, total: 0 };
      entry.total += 1;
      if (row.level === 'fine') entry.fine += 1;
      sourceCoverage.set(source, entry);
    }
    return Promise.resolve({ closedAlertsWithoutOrigin, sourceCoverage });
  }

  public alertGroupsOf(
    tenantId: string,
    alertIds: readonly string[],
  ): Promise<ReadonlyMap<string, AlertGroup>> {
    const result = new Map<string, AlertGroup>();
    for (const alertId of alertIds) {
      const member = this.groupMemberRows.get(`${tenantId}|${alertId}`);
      const group = member ? this.groupRows.get(`${tenantId}|${member.groupId}`) : undefined;
      if (group) result.set(alertId, group);
    }
    return Promise.resolve(result);
  }

  public listAlertGroups(query: AlertGroupQuery): Promise<QueryResult<AlertGroup>> {
    const rows = [...this.groupRows.values()]
      .filter(
        (group) =>
          group.tenantId === query.tenantId && (!query.status || group.status === query.status),
      )
      .sort(
        (left, right) =>
          right.lastSeenAt.getTime() - left.lastSeenAt.getTime() || (left.id < right.id ? -1 : 1),
      );
    return Promise.resolve({ items: rows.slice(0, query.limit), total: rows.length });
  }

  public alertGroupMembers(
    tenantId: string,
    groupId: string,
    limit: number,
  ): Promise<readonly string[]> {
    const ids = [...this.groupMemberRows.values()]
      .filter((member) => member.tenantId === tenantId && member.groupId === groupId)
      .sort(
        (left, right) =>
          right.joinedAt.getTime() - left.joinedAt.getTime() ||
          (left.alertId < right.alertId ? 1 : -1),
      )
      .map((member) => member.alertId);
    return Promise.resolve(ids.slice(0, limit));
  }

  public alertByEventRecordId(tenantId: string, eventRecordId: string): Promise<Alert | undefined> {
    return Promise.resolve(
      [...this.alertRows.values()].find(
        (alert) => alert.tenantId === tenantId && alert.eventRecordId === eventRecordId,
      ),
    );
  }

  public listAlerts(query: AlertQuery): Promise<QueryResult<Alert>> {
    const search = query.search?.trim();
    const items = [...this.alertRows.values()]
      .filter((alert) => alert.tenantId === query.tenantId)
      .filter((alert) =>
        query.status === 'open'
          ? alert.status !== 'closed'
          : !query.status || alert.status === query.status,
      )
      .filter((alert) => !query.priority || alert.priority === query.priority)
      .filter((alert) => !query.entityRef || alert.entityRefs.includes(query.entityRef))
      .filter(
        (alert) =>
          !search ||
          `${alert.title} ${alert.id} ${alert.assigneeId ?? ''}`
            .toLocaleLowerCase()
            .includes(search),
      )
      .sort((left, right) =>
        newestFirst({ at: left.occurredAt, id: left.id }, { at: right.occurredAt, id: right.id }),
      );
    return Promise.resolve({ items, total: items.length });
  }

  public alertStats(query: AlertStatsQuery): Promise<AlertStats> {
    const excluded = new Set(query.excludeIds ?? []);
    const origins = new Set<string>(query.falsePositiveOrigins ?? DEFAULT_FALSE_POSITIVE_ORIGINS);
    const rows = [...this.alertRows.values()].filter(
      (alert) =>
        alert.tenantId === query.tenantId &&
        alert.entityRefs.includes(query.entityRef) &&
        (!query.ruleId || alert.ruleId === query.ruleId) &&
        (!query.since || alert.createdAt.getTime() >= query.since.getTime()) &&
        !excluded.has(alert.id),
    );
    return Promise.resolve({
      total: rows.length,
      falsePositive: rows.filter(
        (alert) =>
          alert.verdict === 'false_positive' &&
          alert.closureOrigin !== null &&
          origins.has(alert.closureOrigin),
      ).length,
      truePositive: rows.filter((alert) => alert.verdict === 'true_positive').length,
      open: rows.filter((alert) => alert.status !== 'closed').length,
      incidentIds: [
        ...new Set(
          rows
            .map((alert) => alert.incidentId)
            .filter((id): id is string => typeof id === 'string'),
        ),
      ],
    });
  }

  public incidentById(tenantId: string, incidentId: string): Promise<Incident | undefined> {
    return Promise.resolve(this.incidentRows.get(`${tenantId}|${incidentId}`));
  }

  public listIncidentAlerts(
    tenantId: string,
    incidentId: string,
    limit: number,
  ): Promise<QueryResult<Alert>> {
    const linked = [...this.alertRows.values()]
      .filter((alert) => alert.tenantId === tenantId && alert.incidentId === incidentId)
      .sort((left, right) =>
        newestFirst({ at: left.occurredAt, id: left.id }, { at: right.occurredAt, id: right.id }),
      );
    return Promise.resolve({ items: linked.slice(0, limit), total: linked.length });
  }

  public listIncidentTasks(tenantId: string, incidentId: string): Promise<readonly IncidentTask[]> {
    return Promise.resolve(
      [...this.taskRows.values()]
        .filter((task) => task.tenantId === tenantId && task.incidentId === incidentId)
        .sort((left, right) =>
          newestFirst({ at: left.createdAt, id: left.id }, { at: right.createdAt, id: right.id }),
        ),
    );
  }

  public listIncidentNotes(tenantId: string, incidentId: string): Promise<readonly IncidentNote[]> {
    return Promise.resolve(
      [...this.noteRows.values()]
        .filter((note) => note.tenantId === tenantId && note.incidentId === incidentId)
        .sort((left, right) =>
          newestFirst({ at: left.createdAt, id: left.id }, { at: right.createdAt, id: right.id }),
        ),
    );
  }

  public listIncidents(query: IncidentQuery): Promise<QueryResult<Incident>> {
    const search = query.search?.trim();
    const items = [...this.incidentRows.values()]
      .filter((incident) => incident.tenantId === query.tenantId)
      .filter(
        (incident) =>
          !query.statuses ||
          query.statuses.length === 0 ||
          query.statuses.includes(incident.status),
      )
      .filter(
        (incident) =>
          !search ||
          `${incident.title} ${incident.id} ${incident.ownerId} ${incident.summary}`
            .toLocaleLowerCase()
            .includes(search),
      )
      .sort((left, right) =>
        newestFirst({ at: left.openedAt, id: left.id }, { at: right.openedAt, id: right.id }),
      );
    return Promise.resolve({ items, total: items.length });
  }

  /* ------------------------------------------------------------ Correlación */

  public recentByEntities(
    tenantId: string,
    entityKeys: readonly string[],
    since: Date,
    limit: number,
  ): Promise<readonly CorrelatableAlert[]> {
    const wanted = new Set(entityKeys);
    const rows = [...this.alertRows.values()]
      .filter(
        (alert) =>
          alert.tenantId === tenantId &&
          alert.occurredAt.getTime() >= since.getTime() &&
          alert.entityKeys.some((key) => wanted.has(key)),
      )
      .sort((left, right) =>
        newestFirst({ at: left.occurredAt, id: left.id }, { at: right.occurredAt, id: right.id }),
      )
      .slice(0, Math.max(limit, 1))
      .map((alert) => ({
        id: alert.id,
        occurredAt: alert.occurredAt,
        entityKeys: alert.entityKeys,
        signal: alert.signal,
        ruleId: alert.ruleId,
      }));
    return Promise.resolve(rows);
  }

  /* ------------------------------------------------------------------ Outbox */

  private stateOf(message: OutboxMessageDraft): OutboxQueueState {
    let state = this.outboxState.get(message.messageId);
    if (!state) {
      state = {
        status: 'pending',
        availableAt: message.availableAt,
        attemptCount: 0,
        leaseUntil: null,
        claimToken: null,
        lastErrorCode: null,
        publishedAt: null,
      };
      this.outboxState.set(message.messageId, state);
    }
    return state;
  }

  /** Misma semántica que el claim con lease y fencing de PostgreSQL, en un solo hilo. */
  public claimOutbox(
    at: Date,
    limit: number,
    leaseMs: number,
    lane: OutboxLane = 'all',
  ): Promise<readonly ClaimedOutboxMessage[]> {
    const now = at.getTime();
    const claimable = [...this.outboxRows.values()]
      .filter((message) => {
        const urgent = isUrgentOutboxMessage(message);
        if (lane === 'urgent' && !urgent) return false;
        if (lane === 'normal' && urgent) return false;
        const state = this.stateOf(message);
        if (state.status === 'pending') return state.availableAt.getTime() <= now;
        return state.status === 'processing' && (state.leaseUntil?.getTime() ?? 0) < now;
      })
      .sort(
        (left, right) =>
          this.stateOf(left).availableAt.getTime() - this.stateOf(right).availableAt.getTime() ||
          left.messageId.localeCompare(right.messageId),
      )
      .slice(0, Math.max(limit, 1));
    return Promise.resolve(
      claimable.map((message) => {
        const state = this.stateOf(message);
        state.status = 'processing';
        state.leaseUntil = new Date(now + Math.max(leaseMs, 1_000));
        state.claimToken = randomUUID();
        state.attemptCount += 1;
        return { ...message, claimToken: state.claimToken };
      }),
    );
  }

  /** Solo el claim vigente (estado y token) puede cerrar el mensaje. */
  private ownedClaim(messageId: string, claimToken: string): OutboxQueueState | undefined {
    const state = this.outboxState.get(messageId);
    return state?.status === 'processing' && state.claimToken === claimToken ? state : undefined;
  }

  public markOutboxPublished(messageId: string, claimToken: string, at: Date): Promise<boolean> {
    const state = this.ownedClaim(messageId, claimToken);
    if (state) {
      state.status = 'published';
      state.publishedAt = at;
      state.leaseUntil = null;
      state.claimToken = null;
    }
    return Promise.resolve(state !== undefined);
  }

  public scheduleOutboxRetry(
    messageId: string,
    claimToken: string,
    availableAt: Date,
    errorCode: string,
  ): Promise<boolean> {
    const state = this.ownedClaim(messageId, claimToken);
    if (state) {
      state.status = 'pending';
      state.availableAt = availableAt;
      state.leaseUntil = null;
      state.claimToken = null;
      state.lastErrorCode = errorCode;
    }
    return Promise.resolve(state !== undefined);
  }

  /* ------------------------------------------------------------------- Salud */

  public lastAlertAt(tenantId: string): Promise<Date | null> {
    let latest: Date | null = null;
    for (const alert of this.alertRows.values()) {
      if (alert.tenantId !== tenantId) continue;
      if (!latest || alert.occurredAt.getTime() > latest.getTime()) latest = alert.occurredAt;
    }
    return Promise.resolve(latest);
  }

  public outboxHealth(tenantId: string, at: Date): Promise<OutboxHealth> {
    let pending = 0;
    let processing = 0;
    let oldestPendingAt: Date | null = null;
    let expiredProcessing = 0;
    let oldestExpiredProcessingLeaseUntil: Date | null = null;
    for (const message of this.outboxRows.values()) {
      if (message.tenantId !== tenantId) continue;
      const state = this.stateOf(message);
      if (state.status === 'processing') {
        processing += 1;
        if (state.leaseUntil && state.leaseUntil.getTime() < at.getTime()) {
          expiredProcessing += 1;
          if (
            !oldestExpiredProcessingLeaseUntil ||
            state.leaseUntil.getTime() < oldestExpiredProcessingLeaseUntil.getTime()
          ) {
            oldestExpiredProcessingLeaseUntil = state.leaseUntil;
          }
        }
      }
      if (state.status !== 'pending') continue;
      pending += 1;
      if (!oldestPendingAt || state.availableAt.getTime() < oldestPendingAt.getTime()) {
        oldestPendingAt = state.availableAt;
      }
    }
    return Promise.resolve({
      pending,
      processing,
      oldestPendingAt,
      expiredProcessing,
      oldestExpiredProcessingLeaseUntil,
    });
  }

  public ready(): Promise<void> {
    return Promise.resolve();
  }

  public close(): Promise<void> {
    return Promise.resolve();
  }
}

function isUrgentOutboxMessage(message: OutboxMessageDraft): boolean {
  if (
    message.aggregateType === 'alert' &&
    (message.messageType === 'soc.alert.created' || message.messageType === 'soc.alert.escalated')
  ) {
    return message.payload['priority'] === 'P1';
  }
  return (
    message.aggregateType === 'incident' &&
    message.messageType === 'soc.incident.opened' &&
    message.payload['severity'] === 'critical'
  );
}
