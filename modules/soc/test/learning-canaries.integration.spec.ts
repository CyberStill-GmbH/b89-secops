/**
 * Aprendizaje SOC · canarios de docs/soc-learning/16-contrato-canarios-motor.md contra el MOTOR REAL
 * sobre PostgreSQL real (stores Prisma, bloqueos, CHECK de la base), no contra la memoria.
 *
 * En CI usa una base efímera; en staging se corre con `DATABASE_URL` apuntando al clúster de
 * staging (base administrativa): crea su propia base desechable, tenant sintético `canary-*` y
 * nunca toca datos reales. Cada caso cambia una sola cosa respecto de la fixture base.
 *
 * Invariante global: ningún caso «no autocierra» termina con la alerta `closed`.
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
  type GuardSignals,
  type Reason,
} from '@b89/detection';

import { PostgresSocPersistence } from '../src/infrastructure/postgres-soc.js';
import {
  DEFAULT_ENGINE_SETTINGS,
  isSampled,
  type EngineContext,
  type EngineSettings,
} from '../src/learning-engine.js';
import {
  evaluateAlertWithLearning,
  resolveLearningReview,
  revertLearningDecision,
} from '../src/learning-engine-use-cases.js';
import type { LearningPattern } from '../src/learning-pattern.js';
import { LEARNING_SERVICE_ACTOR } from '../src/learning-use-cases.js';
import { ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const exec = promisify(execFile);
const databaseUrl = process.env['DATABASE_URL'];
const databaseRoot = fileURLToPath(new URL('../../../platform/database/', import.meta.url));

const TENANT = `canary-${Date.now()}`;
const RULE = 'linux-process:100200';
const DAY = 24 * 60 * 60 * 1000;
const KEY = Buffer.from('canario-clave-de-muestreo-solo-pruebas-000');

function components(overrides: Partial<Record<string, string | null>> = {}): FingerprintComponents {
  return {
    ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
      string,
      null
    >),
    ruleKey: RULE,
    ruleName: 'tarea programada',
    user: 'svc-backup',
    host: 'agent:042',
    processImage: 'c:\\program files\\veeam\\agent.exe',
    parentImage: 'c:\\windows\\system32\\svchost.exe',
    commandLine: 'agent.exe --job nightly',
    sha256: 'ab'.repeat(32),
    destination: 'backup.b89.io',
    destinationPort: '443',
    ...overrides,
  } as FingerprintComponents;
}

const SIGNALS: GuardSignals = {
  severity: 'low',
  mitreTactics: ['execution'],
  threatIntelHit: false,
};

const CONTEXT: EngineContext = {
  criticalAssets: 42,
  privilegedIdentities: 12,
  changeCalendarAckUntil: new Date(Date.now() + 20 * DAY),
  sourceState: 'healthy',
  samplingKey: KEY,
};

const SETTINGS: EngineSettings = {
  ...DEFAULT_ENGINE_SETTINGS,
  maxMode: 'active',
  activeRules: new Set([RULE]),
  samplingPercent: 10,
  hourlyCap: 10_000,
  dailyCap: 10_000,
  forcedReviewAfter: 10_000,
};

interface Case {
  readonly id: string;
  /** Huella propia (cada caso aislado de los demás). */
  readonly seed: string;
  readonly alert?: Partial<DetectionCandidate>;
  readonly reasons?: readonly Reason[];
  readonly fp?: (base: AlertFingerprint) => AlertFingerprint;
  readonly signals?: GuardSignals | undefined;
  readonly settings?: Partial<EngineSettings>;
  readonly context?: Partial<EngineContext>;
  readonly pattern?: Partial<LearningPattern> | null;
  readonly expectReason?: string;
  readonly expectProposed?: string;
  readonly closes: boolean;
}

const reason = (code: Reason['code']): Reason => ({ code, delta: 10, detail: code });

const CASES: readonly Case[] = [
  { id: 'BASE', seed: '0', closes: true, expectProposed: 'AUTO_CLOSE' },
  // A · casi coincidencia → DRIFT
  ...(
    [
      'sha256',
      'destination',
      'destinationPort',
      'user',
      'host',
      'parentImage',
      'commandLine',
    ] as const
  ).map((component, index): Case => ({
    id: `A${index + 1}`,
    seed: `a${index}`,
    fp: (base) => ({
      ...base,
      fingerprint: `fp1_${'f'.repeat(63)}${index}`,
      components: { ...base.components, [component]: `otro-${component}` },
    }),
    expectReason: 'DRIFT',
    closes: false,
  })),
  { id: 'A8', seed: 'a8', closes: true, expectProposed: 'AUTO_CLOSE' },
  {
    id: 'A9',
    seed: 'a9',
    alert: { tenantId: `${TENANT}-otro` },
    closes: false,
    expectProposed: 'NONE',
  },
  // B · guardas
  {
    id: 'B1',
    seed: 'b1',
    alert: { priority: 'P2' },
    expectReason: 'GUARD_PRIORITY',
    closes: false,
  },
  { id: 'B2', seed: 'b2', alert: { priority: 'P3' }, expectProposed: 'DEMOTE', closes: false },
  {
    id: 'B3',
    seed: 'b3',
    signals: { ...SIGNALS, severity: 'high' },
    expectReason: 'GUARD_SEVERITY',
    closes: false,
  },
  {
    id: 'B4',
    seed: 'b4',
    reasons: [reason('CRITICAL_ASSET')],
    expectReason: 'GUARD_CRITICAL_ASSET',
    closes: false,
  },
  {
    id: 'B5',
    seed: 'b5',
    reasons: [reason('BREAK_GLASS_IDENTITY')],
    expectReason: 'GUARD_PRIVILEGED',
    closes: false,
  },
  {
    id: 'B6',
    seed: 'b6',
    signals: { ...SIGNALS, mitreTactics: ['lateral-movement'] },
    expectReason: 'GUARD_IMPACT',
    closes: false,
  },
  {
    id: 'B7',
    seed: 'b7',
    signals: { ...SIGNALS, threatIntelHit: true },
    expectReason: 'GUARD_THREAT_INTEL',
    closes: false,
  },
  {
    id: 'B8',
    seed: 'b8',
    reasons: [reason('ATTACK_CHAIN')],
    expectReason: 'GUARD_CORRELATION',
    closes: false,
  },
  {
    id: 'B10',
    seed: 'b10',
    context: { sourceState: 'degraded' },
    expectReason: 'GUARD_SOURCE',
    closes: false,
  },
  {
    id: 'B11',
    seed: 'b11',
    reasons: [reason('MAINTENANCE_WINDOW')],
    expectReason: 'GUARD_CHANGE_WINDOW',
    closes: false,
  },
  {
    id: 'B12',
    seed: 'b12',
    context: { criticalAssets: 0 },
    expectReason: 'GUARD_CONTEXT',
    closes: false,
  },
  // C · estado del patrón y configuración
  { id: 'C1', seed: 'c1', pattern: { expiresAt: new Date(Date.now() - 1_000) }, closes: false },
  { id: 'C2', seed: 'c2', pattern: { status: 'paused' }, closes: false },
  { id: 'C3', seed: 'c3', settings: { killSwitch: true }, expectProposed: 'NONE', closes: false },
  {
    id: 'C4',
    seed: 'c4',
    settings: { killedRules: new Set([RULE]) },
    expectProposed: 'NONE',
    closes: false,
  },
  {
    id: 'C5',
    seed: 'c5',
    settings: { activeRules: new Set() },
    expectProposed: 'AUTO_CLOSE',
    closes: false,
  },
  {
    id: 'C7',
    seed: 'c7',
    pattern: { level: 'coarse', maxAction: 'demote' },
    fp: (base) => ({ ...base, level: 'coarse' }),
    closes: false,
  },
  {
    id: 'C8',
    seed: 'c8',
    pattern: { normalizerVersion: '1', fingerprint: `fp1_${'c'.repeat(63)}8` },
    expectProposed: 'NONE',
    closes: false,
  },
  {
    id: 'C9',
    seed: 'c9',
    fp: (base) => ({ ...base, components: { ...base.components, processImage: 'c:\\tmp\\x.exe' } }),
    expectReason: 'FINGERPRINT_COLLISION',
    closes: false,
  },
];

describe.skipIf(!databaseUrl)('canarios del motor sobre PostgreSQL real (doc 16)', () => {
  let database: { admin: Client; name: string; url: string } | undefined;
  let persistence: PostgresSocPersistence;
  let deps: SocDependencies;
  let sequence = 0;

  beforeAll(async () => {
    const parsed = new URL(databaseUrl!);
    const name = `b89_canary_${process.pid}_${Date.now()}`.toLowerCase();
    const adminUrl = new URL(parsed);
    adminUrl.pathname = '/postgres';
    const admin = new Client(adminUrl.toString());
    await admin.connect();
    await admin.query(`CREATE DATABASE "${name}"`);
    parsed.pathname = `/${name}`;
    database = { admin, name, url: parsed.toString() };
    await exec(
      process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm',
      ['exec', 'prisma', 'migrate', 'deploy', '--schema', 'prisma/schema.prisma'],
      {
        cwd: databaseRoot,
        env: { ...process.env, DATABASE_URL: database.url },
        shell: process.platform === 'win32',
      },
    );
    persistence = PostgresSocPersistence.connect({
      connectionString: database.url,
      maxConnections: 8,
    });
    await persistence.ready();
    deps = {
      unitOfWork: persistence,
      clock: { now: () => new Date() },
      ids: { next: () => randomUUID() },
    };
  });

  afterAll(async () => {
    if (!database) return;
    await persistence.close();
    await database.admin.query(`DROP DATABASE IF EXISTS "${database.name}" WITH (FORCE)`);
    await database.admin.end();
  });

  async function sql(text: string, params: readonly unknown[] = []) {
    const client = new Client(database!.url);
    await client.connect();
    try {
      return await client.query(text, [...params]);
    } finally {
      await client.end();
    }
  }

  function fingerprintFor(seed: string): AlertFingerprint {
    return {
      fingerprint: `fp1_${seed
        .padEnd(64, 'e')
        .slice(0, 64)
        .replace(/[^0-9a-f]/gu, 'e')}`,
      level: 'fine',
      version: '1',
      normalizerVersion: '2',
      ruleKey: RULE,
      components: components(),
    };
  }

  async function arrange(seed: string, overrides: Partial<LearningPattern> | null = {}) {
    const fp = fingerprintFor(seed);
    if (overrides === null) return fp;
    const now = Date.now();
    const draft: LearningPattern = {
      id: randomUUID(),
      tenantId: TENANT,
      ruleKey: RULE,
      fingerprint: fp.fingerprint,
      normalizerVersion: '2',
      level: 'fine',
      components: fp.components,
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
      createdAt: new Date(now - 10 * DAY),
      updatedAt: new Date(now - 5 * DAY),
      activatedAt: new Date(now - 5 * DAY),
      expiresAt: new Date(now + 25 * DAY),
      renewalCount: 0,
      revision: 4,
      ...overrides,
    };
    // La base exige `expires_at > activated_at` en un activo; C1 (vencido por reloj) lo respeta.
    const pattern: LearningPattern =
      draft.status === 'active' &&
      draft.expiresAt &&
      draft.activatedAt &&
      draft.expiresAt <= draft.activatedAt
        ? { ...draft, activatedAt: new Date(draft.expiresAt.getTime() - DAY) }
        : draft;
    await persistence.run((context) => context.patterns.insertIfAbsent(pattern));
    return fp;
  }

  async function ingest(
    fp: AlertFingerprint,
    overrides: Partial<DetectionCandidate> = {},
    extra: readonly Reason[] = [],
  ) {
    sequence += 1;
    const eventRecordId = `0199eb00-0000-7000-8000-${String(sequence).padStart(12, '0')}`;
    const occurredAt = new Date();
    const tenantId = overrides.tenantId ?? TENANT;
    const key = promotionKey(tenantId, eventRecordId, '1.1.0');
    const created = await ingestCandidate(deps, {
      id: candidateId(key, occurredAt),
      tenantId,
      eventRecordId,
      eventUid: `canary-${sequence}`,
      idempotencyKey: key,
      priority: 'P4',
      score: 20,
      reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }, ...extra],
      rulesetId: 'b89.detection.prioritization',
      rulesetVersion: '1.1.0',
      occurredAt,
      createdAt: occurredAt,
      title: 'Canario sintético',
      entityKeys: [],
      signal: 'other',
      ruleId: '100200',
      relatedAlertIds: [],
      fingerprint: fp,
      ...overrides,
    });
    if (!created.ok) throw new Error(created.code);
    return created.value.alert;
  }

  async function evaluate(
    alertId: string,
    tenantId: string,
    fp: AlertFingerprint,
    options: {
      settings?: Partial<EngineSettings>;
      context?: Partial<EngineContext>;
      signals?: GuardSignals | undefined;
    } = {},
  ) {
    const result = await evaluateAlertWithLearning(
      deps,
      {
        settings: { ...SETTINGS, ...options.settings },
        context: () => ({ ...CONTEXT, ...options.context }),
      },
      {
        tenantId,
        alertId,
        fingerprint: fp,
        signals: 'signals' in options ? options.signals : SIGNALS,
        correlationId: `canary-${alertId}`,
      },
    );
    if (!result.ok) throw new Error(result.code);
    return result.value;
  }

  it.each(CASES)('$id', async (canary) => {
    const fpBase = await arrange(
      canary.seed,
      canary.pattern === null ? null : (canary.pattern ?? {}),
    );
    const fp = canary.fp ? canary.fp(fpBase) : fpBase;
    const alert = await ingest(fp, canary.alert ?? {}, canary.reasons ?? []);
    const outcome = await evaluate(alert.id, alert.tenantId, fp, {
      ...(canary.settings ? { settings: canary.settings } : {}),
      ...(canary.context ? { context: canary.context } : {}),
      ...('signals' in canary ? { signals: canary.signals } : {}),
    });
    const after = await persistence.alertById(alert.tenantId, alert.id);
    // Invariante global: un caso «no autocierra» nunca termina cerrado.
    expect(after?.status === 'closed').toBe(canary.closes);
    if (canary.closes) expect(after?.closureOrigin).toBe('learning_engine');
    if (outcome.recorded) {
      if (canary.expectReason) expect(outcome.decision.escalateReason).toBe(canary.expectReason);
      if (canary.expectProposed)
        expect(outcome.decision.proposedAction).toBe(canary.expectProposed);
      // Registro explicable: cada decisión lleva sus comprobaciones.
      expect(outcome.decision.checks.length).toBeGreaterThan(0);
    }
  });

  it('B9 · alerta vinculada a un incidente → ESCALATE(GUARD_INCIDENT), sin cierre', async () => {
    const fp = await arrange('b9');
    const alert = await ingest(fp);
    const incident = randomUUID();
    await sql(
      `INSERT INTO soc_incidents (id, tenant_id, title, severity, status, owner_id, summary, opened_at, updated_at, revision)
       VALUES ($1, $2, 'Canario', 'low', 'open', 'lead-a', 'Canario sintético', now(), now(), 1)`,
      [incident, TENANT],
    );
    await sql(`UPDATE soc_alerts SET incident_id = $1 WHERE id = $2`, [incident, alert.id]);
    const outcome = await evaluate(alert.id, TENANT, fp);
    expect(outcome.recorded && outcome.decision.escalateReason).toBe('GUARD_INCIDENT');
    expect((await persistence.alertById(TENANT, alert.id))?.status).not.toBe('closed');
  });

  it('C6 · dry_run → revisión pendiente; aceptar cierra como el motor', async () => {
    const fp = await arrange('c6');
    const alert = await ingest(fp);
    await evaluate(alert.id, TENANT, fp, { settings: { maxMode: 'dry_run' } });
    expect((await persistence.alertById(TENANT, alert.id))?.status).toBe('new');
    const pending = await persistence.listLearningReviews({
      tenantId: TENANT,
      status: 'pending',
      limit: 100,
    });
    const review = pending.items.find((row) => row.alertId === alert.id)!;
    expect(review.kind).toBe('dry_run_approval');
    const analyst: Actor = {
      subjectId: 'ana',
      tenantId: TENANT,
      sessionId: 's',
      roles: ['b89.soc.analyst'],
      capabilities: capabilitiesForRoles(['b89.soc.analyst']),
    };
    const resolved = await resolveLearningReview(deps, {
      actor: analyst,
      reviewId: review.id,
      expectedRevision: review.revision,
      outcome: 'agree',
      truePositive: false,
      comment: 'Canario: coincide con el respaldo.',
      correlationId: 'c6',
    });
    expect(resolved.ok).toBe(true);
    expect((await persistence.alertById(TENANT, alert.id))?.closureOrigin).toBe('learning_engine');
  });

  it('C10 · patrón revocado antes del efecto → no cierra', async () => {
    const fp = await arrange('c10', { status: 'revoked', activatedAt: null, expiresAt: null });
    const alert = await ingest(fp);
    await evaluate(alert.id, TENANT, fp);
    expect((await persistence.alertById(TENANT, alert.id))?.status).toBe('new');
  });

  it('D1/D3 · topes: el exceso va a una persona; la ráfaga pausa el patrón', async () => {
    const fp = await arrange('d1');
    const alerts = [];
    for (let index = 0; index < 4; index += 1) alerts.push(await ingest(fp));
    for (const alert of alerts)
      await evaluate(alert.id, TENANT, fp, { settings: { hourlyCap: 3 } });
    const closed = (
      await Promise.all(alerts.map((alert) => persistence.alertById(TENANT, alert.id)))
    ).filter((alert) => alert?.status === 'closed');
    expect(closed).toHaveLength(3);
    const open = await persistence.run((context) =>
      context.patterns.openByFingerprint(TENANT, fp.fingerprint),
    );
    expect(open?.status).toBe('paused');
  });

  it('D2 · N cierres seguidos sin revisión → revisión obligatoria', async () => {
    const fp = await arrange('d2');
    const alerts = [];
    for (let index = 0; index < 3; index += 1) alerts.push(await ingest(fp));
    for (const alert of alerts)
      await evaluate(alert.id, TENANT, fp, { settings: { forcedReviewAfter: 2 } });
    const last = await persistence.listLearningDecisions({
      tenantId: TENANT,
      alertId: alerts[2]!.id,
      limit: 1,
    });
    expect(last.items[0]?.escalateReason).toBe('FORCED_REVIEW');
  });

  it('D4 · muestreo con clave: se cierra y entra en revisión; reproducible', async () => {
    const fp = await arrange('d4');
    let sampled: Awaited<ReturnType<typeof ingest>> | undefined;
    for (let attempt = 0; attempt < 60 && !sampled; attempt += 1) {
      const alert = await ingest(fp);
      if (isSampled(KEY, alert.id, 10)) sampled = alert;
      else await evaluate(alert.id, TENANT, fp);
    }
    expect(sampled).toBeDefined();
    const outcome = await evaluate(sampled!.id, TENANT, fp);
    expect(outcome.recorded && outcome.decision.sampled).toBe(true);
    const reviews = await persistence.listLearningReviews({ tenantId: TENANT, limit: 500 });
    expect(
      reviews.items.some((row) => row.alertId === sampled!.id && row.kind === 'quality_sample'),
    ).toBe(true);
  });

  it('D5 · el cierre del motor no suma evidencia', async () => {
    const evidence = await persistence.learningEvidence(TENANT, new Date(Date.now() - 90 * DAY));
    expect(evidence.closures.filter((row) => row.actorId === LEARNING_SERVICE_ACTOR)).toEqual([]);
  });

  it('D7 · revert → reabre, registra la reversión y pausa el patrón', async () => {
    const fp = await arrange('d7');
    const alert = await ingest(fp);
    const outcome = await evaluate(alert.id, TENANT, fp);
    if (!outcome.recorded) throw new Error('sin decisión');
    const reverted = await revertLearningDecision(deps, {
      actor: {
        subjectId: 'beto',
        tenantId: TENANT,
        sessionId: 's',
        roles: ['b89.soc.analyst'],
        capabilities: capabilitiesForRoles(['b89.soc.analyst']),
      },
      decisionId: outcome.decision.id,
      reason: 'Canario: reversión de prueba.',
      correlationId: 'd7',
    });
    expect(reverted.ok).toBe(true);
    expect((await persistence.alertById(TENANT, alert.id))?.status).toBe('acknowledged');
  });
});
