/**
 * Aprendizaje SOC · etapas D/E contra PostgreSQL real (stores Prisma y concurrencia).
 *
 * Lo que la versión en memoria no puede demostrar:
 *
 * - los stores Prisma de patrones, firmas, eventos, decisiones, revisiones y reversiones
 *   (arreglos de texto, JSONB, CAS con `updateMany`, índices únicos parciales);
 * - la consulta de evidencia (último cierre vigente por alerta) y las métricas de preparación;
 * - concurrencia real con hasta 60 conexiones: dos firmantes a la vez, reanudar/renovar a la vez,
 *   topes por hora y por día que no se exceden bajo carrera (el bloqueo `FOR UPDATE` del patrón
 *   serializa las evaluaciones), pausa por tope, doble decisión sobre la misma alerta y
 *   reversiones concurrentes.
 *
 * Bajo carrera una evaluación puede fallar por `lock_timeout` (2 s): eso deja la alerta abierta y
 * sin decisión (fail-safe). Las aserciones lo admiten y verifican que NUNCA haya un cierre de más.
 *
 * Se ejecuta con `DATABASE_URL` (base administrativa); sin ella queda omitida.
 */

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';
import {
  candidateId,
  FINGERPRINT_COMPONENTS,
  promotionKey,
  type AlertFingerprint,
  type DetectionCandidate,
  type FingerprintComponents,
} from '@b89/detection';

import { PostgresSocPersistence } from '../src/infrastructure/postgres-soc.js';
import {
  DEFAULT_ENGINE_SETTINGS,
  type EngineContext,
  type EngineSettings,
} from '../src/learning-engine.js';
import {
  evaluateAlertWithLearning,
  resolveLearningReview,
  revertLearningDecision,
} from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import {
  approveLearningPattern,
  LEARNING_SERVICE_ACTOR,
  refreshLearningPatterns,
  renewLearningPattern,
  resumeLearningPattern,
} from '../src/learning-use-cases.js';
import { executeAlertCommand, ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const exec = promisify(execFile);
const databaseUrl = process.env['DATABASE_URL'];
const databaseRoot = fileURLToPath(new URL('../../../platform/database/', import.meta.url));

const TENANT = 'tenant-learning-pg';
const NOW = new Date('2026-11-24T15:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const RULE = 'linux-process:100200';
const APPROVERS = ['lead-a', 'lead-b', 'lead-c'];

async function provisionDatabase() {
  if (!databaseUrl) throw new Error('DATABASE_URL es obligatorio para esta spec.');
  const parsed = new URL(databaseUrl);
  const name = `b89_learning_${process.pid}_${Date.now()}`.toLowerCase();
  const adminUrl = new URL(parsed);
  adminUrl.pathname = '/postgres';
  const admin = new Client(adminUrl.toString());
  await admin.connect();
  await admin.query(`CREATE DATABASE "${name}"`);
  parsed.pathname = `/${name}`;
  const url = parsed.toString();
  try {
    await exec(
      process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm',
      ['exec', 'prisma', 'migrate', 'deploy', '--schema', 'prisma/schema.prisma'],
      {
        cwd: databaseRoot,
        env: { ...process.env, DATABASE_URL: url },
        shell: process.platform === 'win32',
      },
    );
    return { admin, name, url };
  } catch (error) {
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await admin.end();
    throw error;
  }
}

function hex(seed: string): string {
  return seed.repeat(64).slice(0, 64);
}

function components(user = 'svc-backup'): FingerprintComponents {
  return {
    ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
      string,
      null
    >),
    ruleKey: RULE,
    ruleName: 'tarea programada',
    user,
    host: 'agent:042',
    processImage: 'c:\\program files\\veeam\\agent.exe',
  } as FingerprintComponents;
}

function fingerprintOf(seed: string): AlertFingerprint {
  return {
    fingerprint: `fp1_${hex(seed)}`,
    level: 'fine',
    version: '1',
    normalizerVersion: '2',
    ruleKey: RULE,
    components: components(),
  };
}

let sequence = 0;
function candidate(
  fingerprint: AlertFingerprint,
  overrides: Partial<DetectionCandidate> = {},
): DetectionCandidate {
  sequence += 1;
  const eventRecordId = `0199d600-0000-7000-8000-${String(sequence).padStart(12, '0')}`;
  const occurredAt = new Date(NOW.getTime() - 60_000 + sequence);
  const key = promotionKey(TENANT, eventRecordId, '1.1.0');
  return {
    id: candidateId(key, occurredAt),
    tenantId: TENANT,
    eventRecordId,
    eventUid: `evt-${sequence}`,
    idempotencyKey: key,
    priority: 'P4',
    score: 20,
    reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'Severidad normalizada low.' }],
    rulesetId: 'b89.detection.prioritization',
    rulesetVersion: '1.1.0',
    occurredAt,
    createdAt: occurredAt,
    title: 'Tarea programada de respaldo',
    entityKeys: ['user:svc-backup'],
    signal: 'other',
    ruleId: '100200',
    relatedAlertIds: [],
    fingerprint,
    guardSignals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
    ...overrides,
  };
}

function actor(subjectId: string, role = 'b89.soc.lead'): Actor {
  return {
    subjectId,
    tenantId: TENANT,
    sessionId: `sess-${subjectId}`,
    roles: [role],
    capabilities: capabilitiesForRoles([role]),
  };
}

function pattern(
  fingerprint: AlertFingerprint,
  overrides: Partial<LearningPattern> = {},
): LearningPattern {
  return {
    id: randomUUID(),
    tenantId: TENANT,
    ruleKey: RULE,
    fingerprint: fingerprint.fingerprint,
    normalizerVersion: '2',
    level: 'fine',
    components: fingerprint.components,
    maxAction: 'auto_close',
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    status: 'active',
    proposedBy: LEARNING_SERVICE_ACTOR,
    ownerId: 'lead-a',
    originAlertIds: [randomUUID()],
    originClosers: ['ana', 'beto'],
    confirmations: 6,
    distinctAlerts: 6,
    distinctDays: 3,
    distinctAnalysts: 3,
    truePositiveSeen: 0,
    priorityCeiling: 'P4',
    readinessBlockers: [],
    createdAt: new Date(NOW.getTime() - 10 * DAY),
    updatedAt: new Date(NOW.getTime() - 5 * DAY),
    activatedAt: new Date(NOW.getTime() - 5 * DAY),
    expiresAt: new Date(NOW.getTime() + 25 * DAY),
    renewalCount: 0,
    revision: 4,
    ...overrides,
  };
}

const CONTEXT: EngineContext = {
  criticalAssets: 4,
  privilegedIdentities: 3,
  changeCalendarAckUntil: new Date(NOW.getTime() + 20 * DAY),
  sourceState: 'healthy',
  samplingKey: Buffer.from('k'.repeat(48)),
};

function settings(overrides: Partial<EngineSettings> = {}): EngineSettings {
  return {
    ...DEFAULT_ENGINE_SETTINGS,
    maxMode: 'active',
    activeRules: new Set([RULE]),
    samplingPercent: 1,
    hourlyCap: 1_000,
    dailyCap: 1_000,
    forcedReviewAfter: 1_000,
    ...overrides,
  };
}

describe.skipIf(!databaseUrl)('Aprendizaje SOC D/E · PostgreSQL real', () => {
  let database: Awaited<ReturnType<typeof provisionDatabase>> | undefined;
  let persistence: PostgresSocPersistence;
  let deps: SocDependencies;

  beforeAll(async () => {
    database = await provisionDatabase();
    persistence = PostgresSocPersistence.connect({
      connectionString: database.url,
      maxConnections: 60,
    });
    await persistence.ready();
    deps = {
      unitOfWork: persistence,
      clock: { now: () => NOW },
      ids: { next: () => randomUUID() },
    };
  });

  afterAll(async () => {
    if (!database) return;
    await persistence.close();
    await database.admin.query(`DROP DATABASE IF EXISTS "${database.name}" WITH (FORCE)`);
    await database.admin.end();
  });

  async function insertPattern(value: LearningPattern): Promise<LearningPattern> {
    const inserted = await persistence.run((context) => context.patterns.insertIfAbsent(value));
    expect(inserted).toBe(true);
    return value;
  }

  async function ingest(
    fingerprint: AlertFingerprint,
    overrides: Partial<DetectionCandidate> = {},
  ) {
    const result = await ingestCandidate(deps, candidate(fingerprint, overrides));
    if (!result.ok) throw new Error(result.code);
    return result.value.alert;
  }

  function evaluate(alertId: string, fingerprint: AlertFingerprint, engine = settings()) {
    return evaluateAlertWithLearning(
      deps,
      { settings: engine, context: () => CONTEXT },
      {
        tenantId: TENANT,
        alertId,
        fingerprint,
        signals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
        correlationId: `corr-${alertId}`,
      },
    );
  }

  async function count(sql: string, params: readonly unknown[]): Promise<number> {
    const result = await adminQuery(`SELECT count(*)::int AS n FROM (${sql}) q`, params);
    return result.rows[0].n as number;
  }

  async function adminQuery(sql: string, params: readonly unknown[]) {
    const client = new Client(database!.url);
    await client.connect();
    try {
      return await client.query(sql, [...params]);
    } finally {
      await client.end();
    }
  }

  it('store de patrones: inserción única por huella abierta, CAS, activos por regla y lecturas', async () => {
    const fp = fingerprintOf('a');
    const first = await insertPattern(
      pattern(fp, { status: 'candidate', activatedAt: null, expiresAt: null }),
    );
    const duplicate = await persistence.run((context) =>
      context.patterns.insertIfAbsent(
        pattern(fp, { status: 'candidate', activatedAt: null, expiresAt: null }),
      ),
    );
    expect(duplicate).toBe(false);
    const read = await persistence.run((context) =>
      context.patterns.openByFingerprint(TENANT, fp.fingerprint),
    );
    expect(read).toMatchObject({
      id: first.id,
      components: fp.components,
      originClosers: ['ana', 'beto'],
    });
    const stale = await persistence.run((context) =>
      context.patterns.update({ ...first, revision: 99 }, first.revision + 1),
    );
    expect(stale).toBe(false);
    const ok = await persistence.run((context) =>
      context.patterns.update(
        { ...first, revision: first.revision + 1, readinessBlockers: ['BACKFILL_PENDING'] },
        first.revision,
      ),
    );
    expect(ok).toBe(true);
    expect(await persistence.learningPatternById(TENANT, first.id)).toMatchObject({
      readinessBlockers: ['BACKFILL_PENDING'],
      revision: first.revision + 1,
    });
    const listed = await persistence.listLearningPatterns({
      tenantId: TENANT,
      status: 'candidate',
      limit: 10,
    });
    expect(listed.items.map((row) => row.id)).toContain(first.id);
  });

  it('evidencia y preparación: último cierre vigente por alerta; una reapertura lo anula', async () => {
    const fp = fingerprintOf('b');
    const alerts = await Promise.all([ingest(fp), ingest(fp)]);
    for (const alert of alerts) {
      const analyst = actor('ana', 'b89.soc.analyst');
      const assign = await executeAlertCommand(deps, {
        actor: analyst,
        alertId: alert.id,
        correlationId: 'c',
        command: { name: 'acknowledge', expectedRevision: alert.revision },
      });
      if (!assign.ok) throw new Error(assign.reason);
      const triage = await executeAlertCommand(deps, {
        actor: analyst,
        alertId: alert.id,
        correlationId: 'c',
        command: {
          name: 'triage',
          expectedRevision: assign.value.revision,
          verdict: 'false_positive',
          note: 'Respaldo nocturno documentado.',
        },
      });
      if (!triage.ok) throw new Error(triage.reason);
      const closed = await executeAlertCommand(deps, {
        actor: analyst,
        alertId: alert.id,
        correlationId: 'c',
        command: {
          name: 'close',
          expectedRevision: triage.value.revision,
          closure: {
            reason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
            justification: {
              evidenceType: 'scheduled_job',
              statement: 'Tarea programada de respaldo documentada en el runbook.',
              legitimacyField: 'process.image',
              legitimacyValue: 'c:\\program files\\veeam\\agent.exe',
            },
            evidenceRefs: [{ kind: 'ticket', ref: 'CHG-1042' }],
          },
        },
      });
      if (!closed.ok) throw new Error(closed.reason);
    }
    const second = (await persistence.alertById(TENANT, alerts[1]!.id))!;
    const reopened = await executeAlertCommand(deps, {
      actor: actor('beto', 'b89.soc.analyst'),
      alertId: second.id,
      correlationId: 'c',
      command: { name: 'reopen', expectedRevision: second.revision },
    });
    expect(reopened.ok).toBe(true);
    const evidence = await persistence.learningEvidence(TENANT, new Date(NOW.getTime() - 90 * DAY));
    const mine = evidence.closures.filter((row) => row.fingerprint === fp.fingerprint);
    expect(mine.map((row) => row.alertId)).toEqual([alerts[0]!.id]);
    expect(mine[0]).toMatchObject({ actorId: 'ana', ruleKey: RULE, components: fp.components });
    const metrics = await persistence.readinessMetrics(TENANT, new Date(NOW.getTime() - 90 * DAY));
    expect(metrics.sourceCoverage.get('linux-process')?.total).toBeGreaterThanOrEqual(2);
  });

  it('refresco de punta a punta: 6 cierres humanos de 3 analistas proponen un candidato', async () => {
    const fp = fingerprintOf('c');
    const closers = ['ana', 'ana', 'beto', 'beto', 'caro', 'caro'];
    for (const [index, closer] of closers.entries()) {
      const alert = await ingest(fp);
      const at = new Date(NOW.getTime() - (index % 3) * DAY - 60_000);
      // Cierres humanos con fechas de tres días Lima: se escriben como lo haría el comando.
      await adminQuery(
        `UPDATE soc_alerts SET status = 'closed', verdict = 'false_positive', closure_reason = 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
           closure_origin = 'human', closed_by = $2, closed_at = $3, revision = revision + 1 WHERE id = $1`,
        [alert.id, closer, at],
      );
      await adminQuery(
        `INSERT INTO soc_alert_closures (id, tenant_id, alert_id, kind, verdict, closure_reason, origin, actor_id, justification, evidence_refs, correlation_id, at)
         VALUES (gen_random_uuid(), $1, $2, 'close', 'false_positive', 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA', 'human', $3,
           '{"evidenceType":"scheduled_job","statement":"Tarea programada documentada en el runbook.","legitimacyField":"process.image","legitimacyValue":"x"}',
           '[{"kind":"ticket","ref":"CHG-1"}]', 'c', $4)`,
        [TENANT, alert.id, closer, at],
      );
    }
    const result = await refreshLearningPatterns(deps, persistence, {
      tenantId: TENANT,
      correlationId: 'c',
      readiness: {
        closureReasonRequired: true,
        designatedApprovers: 3,
        closedAlertsWithoutOrigin: 0,
        sourceCoverage: new Map([['linux-process', { fine: 900, total: 1000 }]]),
        collidingRuleKeys: new Set(),
        currentNormalizerVersion: '2',
      },
    });
    expect(result).toMatchObject({ ok: true });
    const created = await persistence.run((context) =>
      context.patterns.openByFingerprint(TENANT, fp.fingerprint),
    );
    expect(created).toMatchObject({
      status: 'candidate',
      distinctAnalysts: 3,
      components: fp.components,
    });
  });

  it('dos firmantes a la vez: una sola firma por etapa y un solo cambio de estado', async () => {
    const fp = fingerprintOf('d');
    const candidateRow = await insertPattern(
      pattern(fp, { status: 'candidate', activatedAt: null, expiresAt: null, revision: 1 }),
    );
    const sign = (subject: string, revision: number) =>
      approveLearningPattern(deps, {
        actor: actor(subject),
        patternId: candidateRow.id,
        expectedRevision: revision,
        comment: 'Revisado con el dueño del proceso.',
        designatedApprovers: APPROVERS,
        correlationId: `c-${subject}`,
      });
    const firsts = await Promise.allSettled([sign('lead-a', 1), sign('lead-b', 1)]);
    const okFirst = firsts.filter((row) => row.status === 'fulfilled' && row.value.ok);
    expect(okFirst).toHaveLength(1);
    const after = (await persistence.learningPatternById(TENANT, candidateRow.id))!;
    expect(after.status).toBe('pending_second_approval');
    const firstSigner = (await persistence.learningPatternHistory(TENANT, candidateRow.id))
      .approvals[0]!.approverId;
    const others = APPROVERS.filter((subject) => subject !== firstSigner);
    const seconds = await Promise.allSettled(
      others.map((subject) => sign(subject, after.revision)),
    );
    expect(seconds.filter((row) => row.status === 'fulfilled' && row.value.ok)).toHaveLength(1);
    const history = await persistence.learningPatternHistory(TENANT, candidateRow.id);
    expect(history.approvals.map((row) => row.stage)).toEqual(['first', 'second']);
    expect((await persistence.learningPatternById(TENANT, candidateRow.id))?.status).toBe(
      'approved',
    );
  });

  it('reanudar a la vez y renovar a la vez: un solo cambio cada uno', async () => {
    const paused = await insertPattern(pattern(fingerprintOf('e'), { status: 'paused' }));
    const resumes = await Promise.allSettled(
      ['lead-a', 'lead-b', 'lead-c'].map((subject) =>
        resumeLearningPattern(deps, {
          actor: actor(subject),
          patternId: paused.id,
          expectedRevision: paused.revision,
          comment: 'Causa de la pausa resuelta.',
          designatedApprovers: APPROVERS,
          correlationId: `r-${subject}`,
        }),
      ),
    );
    expect(resumes.filter((row) => row.status === 'fulfilled' && row.value.ok)).toHaveLength(1);
    expect(
      (await persistence.learningPatternHistory(TENANT, paused.id)).events.map((row) => row.to),
    ).toEqual(['approved']);

    const expired = await insertPattern(pattern(fingerprintOf('f'), { status: 'expired' }));
    const renewals = await Promise.allSettled(
      ['lead-a', 'lead-b', 'lead-c'].map((subject) =>
        renewLearningPattern(deps, {
          actor: actor(subject),
          patternId: expired.id,
          expectedRevision: expired.revision,
          comment: 'Renovación revisada.',
          designatedApprovers: APPROVERS,
          correlationId: `n-${subject}`,
        }),
      ),
    );
    expect(renewals.filter((row) => row.status === 'fulfilled' && row.value.ok)).toHaveLength(1);
    expect((await persistence.learningPatternById(TENANT, expired.id))?.renewalCount).toBe(1);
  });

  it.each([
    ['por hora', { hourlyCap: 10 }, 10, true],
    ['diario', { dailyCap: 5 }, 5, false],
  ] as const)(
    'tope %s bajo carrera de 50 evaluaciones: nunca se excede',
    async (_label, overrides, cap, pauses) => {
      const fp = fingerprintOf(pauses ? '1' : '2');
      const active = await insertPattern(pattern(fp));
      const alerts = await Promise.all(Array.from({ length: 50 }, () => ingest(fp)));
      const results = await Promise.allSettled(
        alerts.map((alert) => evaluate(alert.id, fp, settings(overrides))),
      );
      const closedAlerts = await count(
        `SELECT 1 FROM soc_alerts WHERE id = ANY($1::uuid[]) AND status = 'closed'`,
        [alerts.map((alert) => alert.id)],
      );
      const closingDecisions = await count(
        `SELECT 1 FROM soc_learning_decisions WHERE pattern_id = $1 AND applied_action = 'AUTO_CLOSE'`,
        [active.id],
      );
      expect(closedAlerts).toBeLessThanOrEqual(cap);
      expect(closedAlerts).toBe(closingDecisions);
      // Ninguna alerta cerrada sin decisión registrada; las que fallaron por bloqueo quedan abiertas.
      const failed = results.filter((row) => row.status === 'rejected').length;
      const decided = await count(`SELECT 1 FROM soc_learning_decisions WHERE pattern_id = $1`, [
        active.id,
      ]);
      expect(decided + failed).toBe(50);
      if (pauses && decided > cap) {
        expect((await persistence.learningPatternById(TENANT, active.id))?.status).toBe('paused');
      }
    },
  );

  it('doble decisión del motor sobre la misma alerta (20 a la vez): una decisión, un cierre', async () => {
    const fp = fingerprintOf('g');
    await insertPattern(pattern(fp));
    const alert = await ingest(fp);
    await Promise.allSettled(Array.from({ length: 20 }, () => evaluate(alert.id, fp)));
    expect(
      await count(`SELECT 1 FROM soc_learning_decisions WHERE alert_id = $1`, [alert.id]),
    ).toBe(1);
    expect(
      await count(
        `SELECT 1 FROM soc_alert_closures WHERE alert_id = $1 AND origin = 'learning_engine'`,
        [alert.id],
      ),
    ).toBeLessThanOrEqual(1);
  });

  it('reversiones concurrentes (10 revert + 1 reapertura manual): una sola gana', async () => {
    const fp = fingerprintOf('h');
    const active = await insertPattern(pattern(fp));
    const alert = await ingest(fp);
    const evaluated = await evaluate(alert.id, fp);
    if (!evaluated.ok || !evaluated.value.recorded) throw new Error('sin decisión');
    expect(evaluated.value.closed).toBe(true);
    const decisionId = evaluated.value.decision.id;
    const closed = (await persistence.alertById(TENANT, alert.id))!;
    const attempts = await Promise.allSettled([
      ...Array.from({ length: 10 }, (_, index) =>
        revertLearningDecision(deps, {
          actor: actor(`analista-${index}`, 'b89.soc.analyst'),
          decisionId,
          reason: 'El host cambió de rol esta semana.',
          correlationId: `rv-${index}`,
        }),
      ),
      executeAlertCommand(deps, {
        actor: actor('ana', 'b89.soc.analyst'),
        alertId: alert.id,
        correlationId: 'manual',
        command: { name: 'reopen', expectedRevision: closed.revision },
      }),
    ]);
    expect(attempts.filter((row) => row.status === 'fulfilled' && row.value.ok)).toHaveLength(1);
    expect(
      await count(`SELECT 1 FROM soc_learning_reversals WHERE alert_id = $1`, [alert.id]),
    ).toBe(1);
    expect((await persistence.alertById(TENANT, alert.id))?.status).toBe('acknowledged');
    expect((await persistence.learningPatternById(TENANT, active.id))?.status).toBe('paused');
  });

  it('revisión resuelta a la vez por dos personas: una sola resolución', async () => {
    const fp = fingerprintOf('i');
    await insertPattern(pattern(fp));
    const alert = await ingest(fp);
    const evaluated = await evaluate(alert.id, fp, settings({ maxMode: 'dry_run' }));
    if (!evaluated.ok || !evaluated.value.recorded) throw new Error('sin decisión');
    const reviews = await persistence.listLearningReviews({
      tenantId: TENANT,
      status: 'pending',
      limit: 50,
    });
    const review = reviews.items.find((row) => row.alertId === alert.id)!;
    const outcomes = await Promise.allSettled(
      ['ana', 'beto'].map((subject) =>
        resolveLearningReview(deps, {
          actor: actor(subject, 'b89.soc.analyst'),
          reviewId: review.id,
          expectedRevision: review.revision,
          outcome: 'agree',
          truePositive: false,
          comment: 'Coincide con el respaldo nocturno.',
          correlationId: `rs-${subject}`,
        }),
      ),
    );
    expect(outcomes.filter((row) => row.status === 'fulfilled' && row.value.ok)).toHaveLength(1);
    expect(
      await count(
        `SELECT 1 FROM soc_alert_closures WHERE alert_id = $1 AND origin = 'learning_engine'`,
        [alert.id],
      ),
    ).toBe(1);
  });

  it('la base solo admite DEMOTE P3 → P4 con su decisión (nunca P1/P2 ni sin trazabilidad)', async () => {
    const p2 = await ingest(fingerprintOf('k'), { priority: 'P2' });
    await expect(
      adminQuery(`UPDATE soc_alerts SET effective_priority = 'P4', demoted_by = $2 WHERE id = $1`, [
        p2.id,
        randomUUID(),
      ]),
    ).rejects.toThrow(/effective_priority_floor/u);
    const p3 = await ingest(fingerprintOf('l'), { priority: 'P3' });
    await expect(
      adminQuery(`UPDATE soc_alerts SET effective_priority = 'P4' WHERE id = $1`, [p3.id]),
    ).rejects.toThrow(/effective_priority_floor/u);
    await adminQuery(
      `UPDATE soc_alerts SET effective_priority = 'P4', demoted_by = $2 WHERE id = $1`,
      [p3.id, randomUUID()],
    );
  });

  it('CHECK con NULL: pausa sin motivo y demoted_by sin prioridad efectiva se rechazan', async () => {
    await expect(
      adminQuery(`INSERT INTO soc_learning_engine_state VALUES ($1, true, NULL, now(), 1)`, [
        `${TENANT}-null`,
      ]),
    ).rejects.toThrow(/engine_state_reason/u);
    const alert = await ingest(fingerprintOf('m'), { priority: 'P3' });
    await expect(
      adminQuery(`UPDATE soc_alerts SET demoted_by = $2 WHERE id = $1`, [alert.id, randomUUID()]),
    ).rejects.toThrow(/effective_priority_floor/u);
  });

  it('la base rechaza un cierre del motor fuera de P4 aunque el código lo intentara', async () => {
    const alert = await ingest(fingerprintOf('j'), { priority: 'P2' });
    await expect(
      adminQuery(
        `UPDATE soc_alerts SET status = 'closed', closure_origin = 'learning_engine', closed_by = $2, closed_at = now() WHERE id = $1`,
        [alert.id, LEARNING_SERVICE_ACTOR],
      ),
    ).rejects.toThrow(/learning_engine_p4/u);
  });
});
