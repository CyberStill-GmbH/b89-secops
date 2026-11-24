/**
 * Aprendizaje SOC · etapas D/E — inmutabilidad y mínimo privilegio contra PostgreSQL real.
 *
 * Mismo orden que el rollout (roles → migración como `b89_migrator` → `post-migrate.sql`) y
 * tres identidades con conexiones reales:
 *
 * - `b89_soc_runtime` (API y motor, que hoy corre en el mismo proceso): sin UPDATE/DELETE/TRUNCATE
 *   en las tablas append-only y sin DELETE/TRUNCATE en patrones y revisiones;
 * - `b89_migrator` (dueño): los triggers rechazan igual UPDATE/DELETE/TRUNCATE en lo append-only;
 * - un rol de solo lectura creado por la spec: SELECT y nada más.
 *
 * No existe todavía un rol propio del motor (ver docs/soc-learning/22-verificacion-motor.md).
 * Usa roles globales del clúster: solo contra una base efímera de pruebas.
 */

import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const exec = promisify(execFile);
const databaseUrl = process.env['DATABASE_URL'];
const databaseRoot = fileURLToPath(new URL('../', import.meta.url));
const migratorPassword = randomBytes(32).toString('base64url');
const runtimePassword = randomBytes(32).toString('base64url');
const readerPassword = randomBytes(32).toString('base64url');
const READER = 'b89_learning_reader_test';

const T = 't-learning-roles';
const ALERT = '0199d500-0000-7000-8000-000000000001';
const PATTERN = '0199d500-0000-7000-8000-0000000000aa';
const DECISION = '0199d500-0000-7000-8000-0000000000dd';
const REVIEW = '0199d500-0000-7000-8000-0000000000ee';
const FP = `fp1_${'a'.repeat(64)}`;

function urlFor(base: string, database: string, user?: string, password?: string): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  if (user) url.username = user;
  if (password) url.password = password;
  return url.toString();
}

async function run(url: string, sql: string, params: readonly unknown[] = []) {
  const client = new Client(url);
  await client.connect();
  try {
    return await client.query(sql, [...params]);
  } finally {
    await client.end();
  }
}

async function bootstrap(url: string) {
  const sql = await readFile(new URL('../bootstrap/roles.sql', import.meta.url), 'utf8');
  const client = new Client(url);
  await client.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      "SELECT set_config('b89.migrator_password', $1, true), set_config('b89.runtime_password', $2, true)",
      [migratorPassword, runtimePassword],
    );
    await client.query(sql);
    await client.query('COMMIT');
  } finally {
    await client.end();
  }
}

const APPEND_ONLY = [
  'soc_learning_pattern_approvals',
  'soc_learning_pattern_events',
  'soc_learning_decisions',
  'soc_learning_reversals',
  'soc_learning_config_events',
] as const;

describe.skipIf(!databaseUrl)('Aprendizaje SOC D/E · roles e inmutabilidad', () => {
  const name = `b89_learning_roles_${process.pid}_${Date.now()}`.toLowerCase();
  let adminUrl: string;
  let migratorUrl: string;
  let runtimeUrl: string;
  let readerUrl: string;

  beforeAll(async () => {
    const admin = urlFor(databaseUrl!, 'postgres');
    await run(admin, `CREATE DATABASE "${name}"`);
    adminUrl = urlFor(databaseUrl!, name);
    migratorUrl = urlFor(databaseUrl!, name, 'b89_migrator', migratorPassword);
    runtimeUrl = urlFor(databaseUrl!, name, 'b89_soc_runtime', runtimePassword);
    readerUrl = urlFor(databaseUrl!, name, READER, readerPassword);

    await bootstrap(adminUrl);
    await exec(
      process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm',
      ['exec', 'prisma', 'migrate', 'deploy', '--schema', 'prisma/schema.prisma'],
      {
        cwd: databaseRoot,
        env: { ...process.env, DATABASE_URL: migratorUrl },
        shell: process.platform === 'win32',
      },
    );
    await run(
      migratorUrl,
      await readFile(new URL('../bootstrap/post-migrate.sql', import.meta.url), 'utf8'),
    );

    // Rol de solo lectura de la spec (la plataforma aún no define uno propio).
    await run(
      adminUrl,
      `DO $r$ BEGIN
         IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${READER}') THEN
           EXECUTE format('CREATE ROLE ${READER} LOGIN PASSWORD %L', '${readerPassword}');
         ELSE
           EXECUTE format('ALTER ROLE ${READER} WITH LOGIN PASSWORD %L', '${readerPassword}');
         END IF;
       END $r$`,
    );
    await run(adminUrl, `GRANT CONNECT ON DATABASE "${name}" TO ${READER}`);
    await run(migratorUrl, `GRANT USAGE ON SCHEMA public TO ${READER}`);
    await run(migratorUrl, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${READER}`);

    // Filas mínimas, como el runtime (las escribe la aplicación).
    await run(
      runtimeUrl,
      `INSERT INTO detection_candidates (id, tenant_id, event_record_id, event_uid, idempotency_key, priority, score, reasons, ruleset_id, ruleset_version, title, occurred_at)
       VALUES ($1, $2, $1, 'evt', 'k-roles', 'P4', 20, '[]', 'r', '1', 't', now())`,
      [ALERT, T],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_alerts (id, tenant_id, candidate_id, event_record_id, title, priority, score, reasons, status, occurred_at, updated_at, revision)
       VALUES ($1, $2, $1, $1, 't', 'P4', 20, '[]', 'new', now(), now(), 1)`,
      [ALERT, T],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_patterns (id, tenant_id, rule_key, fingerprint, normalizer_version, level, components, max_action,
         closure_reason, status, proposed_by, origin_alert_ids, origin_closers, confirmations, distinct_alerts, distinct_days,
         distinct_analysts, true_positive_seen, priority_ceiling, readiness_blockers, created_at, updated_at, renewal_count, revision)
       VALUES ($1, $2, 'linux-process:100200', $3, '2', 'fine', '{}', 'auto_close', 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
         'candidate', 'svc:b89-soc-learning', '{}', '{}', 6, 6, 3, 3, 0, 'P4', '{}', now(), now(), 0, 1)`,
      [PATTERN, T, FP],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_pattern_approvals VALUES (gen_random_uuid(), $1, $2, 1, 'first', 'lead-a', 'approve', 'Revisado con el dueño', now())`,
      [T, PATTERN],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_pattern_events VALUES (gen_random_uuid(), $1, $2, NULL, 'candidate', 'ELIGIBLE', 'svc:b89-soc-learning', now())`,
      [T, PATTERN],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_decisions (id, tenant_id, alert_id, mode, engine_version, fingerprint, level, rule_key, pattern_id,
         proposed_action, applied_action, confidence, checks, sampled, at)
       VALUES ($1, $2, $3, 'shadow', '1.0.0', $4, 'fine', 'linux-process:100200', $5, 'AUTO_CLOSE', 'NONE', 'medium', '[]', false, now())`,
      [DECISION, T, ALERT, FP, PATTERN],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_reviews (id, tenant_id, decision_id, alert_id, pattern_id, kind, status, at, revision)
       VALUES ($1, $2, $3, $4, $5, 'quality_sample', 'pending', now(), 1)`,
      [REVIEW, T, DECISION, ALERT, PATTERN],
    );
    await run(
      runtimeUrl,
      `INSERT INTO soc_learning_reversals VALUES (gen_random_uuid(), $1, $2, $3, $4, 'ana', 'motivo de prueba', true, now())`,
      [T, DECISION, ALERT, PATTERN],
    );
  });

  afterAll(async () => {
    await run(urlFor(databaseUrl!, 'postgres'), `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  });

  it.each(APPEND_ONLY)('runtime: %s sin UPDATE, DELETE ni TRUNCATE (permiso)', async (table) => {
    await expect(run(runtimeUrl, `UPDATE ${table} SET tenant_id = tenant_id`)).rejects.toThrow(
      /permission/iu,
    );
    await expect(run(runtimeUrl, `DELETE FROM ${table}`)).rejects.toThrow(/permission/iu);
    await expect(run(runtimeUrl, `TRUNCATE ${table}`)).rejects.toThrow(/permission/iu);
  });

  it.each(APPEND_ONLY)(
    'dueño de la tabla: %s rechaza UPDATE, DELETE y TRUNCATE (trigger)',
    async (table) => {
      await expect(run(migratorUrl, `UPDATE ${table} SET tenant_id = tenant_id`)).rejects.toThrow(
        /append-only/iu,
      );
      await expect(run(migratorUrl, `DELETE FROM ${table}`)).rejects.toThrow(/append-only/iu);
      // CASCADE alcanza revisiones y reversiones: falla con el primer trigger que se dispare.
      await expect(run(migratorUrl, `TRUNCATE ${table} CASCADE`)).rejects.toThrow(
        /append-only|no admite/iu,
      );
    },
  );

  it('patrones y revisiones: el runtime actualiza (CAS) pero no borra ni trunca', async () => {
    await expect(
      run(runtimeUrl, `UPDATE soc_learning_patterns SET revision = revision WHERE id = $1`, [
        PATTERN,
      ]),
    ).resolves.toBeDefined();
    for (const table of ['soc_learning_patterns', 'soc_learning_reviews']) {
      await expect(run(runtimeUrl, `DELETE FROM ${table}`)).rejects.toThrow(/permission/iu);
      await expect(run(runtimeUrl, `TRUNCATE ${table}`)).rejects.toThrow(/permission/iu);
    }
  });

  it('dueño: los patrones no se borran y una revisión resuelta no cambia', async () => {
    await expect(run(migratorUrl, `DELETE FROM soc_learning_patterns`)).rejects.toThrow(
      /revocar en su lugar/iu,
    );
    await run(
      migratorUrl,
      `UPDATE soc_learning_reviews SET status = 'agreed', reviewer_id = 'ana', comment = 'Coincide con el respaldo',
         resolved_at = now(), revision = 2 WHERE id = $1`,
      [REVIEW],
    );
    await expect(
      run(migratorUrl, `UPDATE soc_learning_reviews SET status = 'disagreed' WHERE id = $1`, [
        REVIEW,
      ]),
    ).rejects.toThrow(/resuelta no cambia/iu);
    await expect(run(migratorUrl, `DELETE FROM soc_learning_reviews`)).rejects.toThrow(
      /no admite/iu,
    );
  });

  it('solo lectura: lee todo y no escribe nada', async () => {
    await expect(
      run(readerUrl, `SELECT count(*) FROM soc_learning_decisions`),
    ).resolves.toBeDefined();
    await expect(
      run(readerUrl, `UPDATE soc_learning_patterns SET status = 'active' WHERE id = $1`, [PATTERN]),
    ).rejects.toThrow(/permission/iu);
    await expect(
      run(
        readerUrl,
        `INSERT INTO soc_learning_reversals VALUES (gen_random_uuid(), $1, $2, $3, NULL, 'ana', 'x', true, now())`,
        [T, DECISION, ALERT],
      ),
    ).rejects.toThrow(/permission/iu);
  });

  it('el runtime no puede DDL sobre las tablas de aprendizaje (ni desactivar triggers)', async () => {
    await expect(
      run(runtimeUrl, `ALTER TABLE soc_learning_decisions DISABLE TRIGGER ALL`),
    ).rejects.toThrow(/owner|permission/iu);
    await expect(run(runtimeUrl, `DROP TABLE soc_learning_reversals`)).rejects.toThrow(
      /owner|permission/iu,
    );
  });

  it('la base rechaza una firma o una reversión de una identidad de servicio', async () => {
    await expect(
      run(
        runtimeUrl,
        `INSERT INTO soc_learning_pattern_approvals VALUES (gen_random_uuid(), $1, $2, 1, 'first', 'svc:b89-soc-learning', 'approve', 'comentario largo', now())`,
        [T, PATTERN],
      ),
    ).rejects.toThrow(/approvals_human/iu);
    await expect(
      run(
        runtimeUrl,
        `INSERT INTO soc_learning_reversals VALUES (gen_random_uuid(), $1, $2, $3, NULL, 'svc:b89-soc-learning', 'x', true, now())`,
        [T, DECISION, ALERT],
      ),
    ).rejects.toThrow(/reversals_human/iu);
  });
});
