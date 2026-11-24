/**
 * Aprendizaje SOC · prueba de carga: ¿el motor degrada la ingesta?
 *
 *   DATABASE_URL=postgresql://…/postgres pnpm --filter @b89/soc exec tsx --conditions=development \
 *     scripts/learning-load-test.ts --expected-per-day 2000 --factor 10 --minutes 5
 *
 * Crea una base desechable, migra y corre dos tramos con el MISMO tráfico (alertas sintéticas P4 de
 * una huella con patrón activo y otras sin patrón):
 *
 *   A · motor apagado: solo ingesta;
 *   B · motor en sombra: la ingesta encola y un worker drena en paralelo (como en producción).
 *
 * Mide la latencia de `ingestCandidate` (p50/p95/p99), el tiempo hasta vaciar la cola y el backlog
 * máximo. Criterio (docs/soc-learning/24-despliegue-sombra.md §3): p95(B) ≤ 1,2 × p95(A) + 20 ms y
 * ningún trabajo en dead-letter. Sale con código 1 si no se cumple. Datos sintéticos.
 */

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';

import { Client } from 'pg';

import {
  candidateId,
  FINGERPRINT_COMPONENTS,
  promotionKey,
  type FingerprintComponents,
} from '@b89/detection';
import { PostgresSocPersistence } from '../src/infrastructure/postgres-soc.js';
import { DEFAULT_ENGINE_SETTINGS } from '../src/learning-engine.js';
import { drainLearningQueue } from '../src/learning-worker.js';
import { ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const exec = promisify(execFile);

function argument(name: string, fallback: string): number {
  const index = process.argv.indexOf(`--${name}`);
  const value = Number(index >= 0 ? process.argv[index + 1] : fallback);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`--${name} inválido`);
  return value;
}

function percentile(values: readonly number[], p: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)] ?? 0;
}

const TENANT = 'load-test';
const COMPONENTS = {
  ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
    string,
    null
  >),
  ruleKey: 'linux-process:100200',
  user: 'svc-backup',
} as FingerprintComponents;

async function main(): Promise<void> {
  const admin = process.env['DATABASE_URL'];
  if (!admin) throw new Error('DATABASE_URL (base administrativa) es obligatorio.');
  const expectedPerDay = argument('expected-per-day', '2000');
  const factor = argument('factor', '10');
  const minutes = argument('minutes', '5');
  const concurrency = argument('concurrency', '16');
  const perSecond = (expectedPerDay * factor) / 86_400;
  const total = Math.max(200, Math.round(perSecond * minutes * 60));

  const parsed = new URL(admin);
  const name = `b89_load_${process.pid}_${Date.now()}`;
  parsed.pathname = '/postgres';
  const root = new Client(parsed.toString());
  await root.connect();
  await root.query(`CREATE DATABASE "${name}"`);
  parsed.pathname = `/${name}`;
  const url = parsed.toString();
  try {
    await exec(
      'pnpm',
      ['exec', 'prisma', 'migrate', 'deploy', '--schema', 'prisma/schema.prisma'],
      {
        cwd: new URL('../../../platform/database/', import.meta.url),
        env: { ...process.env, DATABASE_URL: url },
      },
    );
    const persistence = PostgresSocPersistence.connect({
      connectionString: url,
      maxConnections: concurrency + 8,
    });
    await persistence.ready();
    let sequence = 0;

    const run = async (label: string, engineOn: boolean) => {
      const deps: SocDependencies = {
        unitOfWork: persistence,
        clock: { now: () => new Date() },
        ids: { next: () => randomUUID() },
        ...(engineOn ? { learningEnqueue: true } : {}),
      };
      const latencies: number[] = [];
      let stopWorker = false;
      let maxBacklog = 0;
      const worker = engineOn
        ? (async () => {
            while (!stopWorker) {
              const summary = await drainLearningQueue({
                dependencies: deps,
                queue: persistence.learningQueue,
                engine: {
                  settings: { ...DEFAULT_ENGINE_SETTINGS, maxMode: 'shadow' },
                  context: () => ({
                    criticalAssets: 1,
                    privilegedIdentities: 1,
                    changeCalendarAckUntil: new Date(Date.now() + 86_400_000),
                    sourceState: 'healthy',
                    samplingKey: null,
                  }),
                },
                workerId: 'load-test',
                tenantId: TENANT,
              });
              if (summary.claimed === 0) await new Promise((resolve) => setTimeout(resolve, 200));
            }
          })()
        : Promise.resolve();
      const started = Date.now();
      let next = 0;
      const lanes = Array.from({ length: concurrency }, async () => {
        while (next < total) {
          next += 1;
          sequence += 1;
          const eventRecordId = `0199ec00-0000-7000-8000-${String(sequence).padStart(12, '0')}`;
          const at = new Date();
          const key = promotionKey(TENANT, eventRecordId, '1.1.0');
          // Ritmo objetivo: `perSecond` alertas por segundo en total.
          const due = started + (sequence % total) * (1000 / perSecond);
          const wait = due - Date.now();
          if (wait > 0 && perSecond < 50)
            await new Promise((resolve) => setTimeout(resolve, Math.min(wait, 1000)));
          const t0 = performance.now();
          const result = await ingestCandidate(deps, {
            id: candidateId(key, at),
            tenantId: TENANT,
            eventRecordId,
            eventUid: `load-${sequence}`,
            idempotencyKey: key,
            priority: 'P4',
            score: 20,
            reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }],
            rulesetId: 'b89.detection.prioritization',
            rulesetVersion: '1.1.0',
            occurredAt: at,
            createdAt: at,
            title: 'Carga sintética',
            entityKeys: [],
            signal: 'other',
            ruleId: '100200',
            relatedAlertIds: [],
            fingerprint: {
              fingerprint: `fp1_${(sequence % 50).toString(16).padStart(64, 'a')}`,
              level: 'fine',
              version: '1',
              normalizerVersion: '2',
              ruleKey: 'linux-process:100200',
              components: COMPONENTS,
            },
            guardSignals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
          });
          latencies.push(performance.now() - t0);
          if (!result.ok) throw new Error(`ingesta falló: ${result.code}`);
          if (engineOn && sequence % 100 === 0) {
            const counts = await persistence.learningHealthCounts(TENANT, new Date());
            maxBacklog = Math.max(maxBacklog, counts.backlog.pending);
          }
        }
      });
      await Promise.all(lanes);
      const ingestSeconds = (Date.now() - started) / 1000;
      let drainSeconds = 0;
      if (engineOn) {
        const drainStart = Date.now();
        for (;;) {
          const counts = await persistence.learningHealthCounts(TENANT, new Date());
          if (counts.backlog.pending === 0 && counts.backlog.expiredLeases === 0) break;
          if (Date.now() - drainStart > 10 * 60_000)
            throw new Error('la cola no se vació en 10 min');
          await new Promise((resolve) => setTimeout(resolve, 500));
        }
        drainSeconds = (Date.now() - drainStart) / 1000;
      }
      stopWorker = true;
      await worker;
      const dead = engineOn
        ? (await persistence.learningHealthCounts(TENANT, new Date())).deadLast24h
        : 0;
      return {
        label,
        alerts: latencies.length,
        ingestSeconds,
        p50: percentile(latencies, 0.5),
        p95: percentile(latencies, 0.95),
        p99: percentile(latencies, 0.99),
        drainSeconds,
        maxBacklog,
        dead,
      };
    };

    const off = await run('A · motor apagado', false);
    const on = await run('B · motor en sombra (cola + worker)', true);
    await persistence.close();
    const pass = on.p95 <= off.p95 * 1.2 + 20 && on.dead === 0;
    const row = (r: typeof off) =>
      `| ${r.label} | ${r.alerts} | ${r.ingestSeconds.toFixed(1)} | ${r.p50.toFixed(1)} | ${r.p95.toFixed(1)} | ${r.p99.toFixed(1)} | ${r.drainSeconds.toFixed(1)} | ${r.maxBacklog} | ${r.dead} |`;
    process.stdout.write(
      [
        `# Prueba de carga del motor (datos sintéticos)`,
        '',
        `Volumen esperado ${expectedPerDay}/día × ${factor} = ${(perSecond * 86_400).toFixed(0)}/día (${perSecond.toFixed(2)}/s), ${minutes} min, concurrencia ${concurrency}.`,
        '',
        '| Tramo | Alertas | Ingesta (s) | p50 ms | p95 ms | p99 ms | Vaciado cola (s) | Backlog máx. | Dead-letter |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
        row(off),
        row(on),
        '',
        `Criterio p95(B) ≤ 1,2 × p95(A) + 20 ms y 0 dead-letter: **${pass ? 'CUMPLE' : 'NO CUMPLE'}**.`,
        '',
      ].join('\n'),
    );
    if (!pass) process.exitCode = 1;
  } finally {
    await root.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await root.end();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`load-test: ${(error as Error).message}\n`);
  process.exitCode = 1;
});
