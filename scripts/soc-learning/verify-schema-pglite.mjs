// Aprendizaje SOC · verificación local PARCIAL del esquema sin Docker, con PGlite (Postgres 17
// compilado a WASM, una sola conexión). Aplica TODAS las migraciones reales del repo en orden y
// prueba invariantes de las etapas A–C, el etiquetado retroactivo y el rollback con resguardo.
//
// Lo que NO verifica: concurrencia real (PGlite serializa todo), el comportamiento exacto de la
// versión de producción (PG 18) ni los meta-comandos de psql. Eso lo cubre
// scripts/ci/soc-learning-postgres.sh contra un PostgreSQL de verdad.
//
//   node scripts/soc-learning/verify-schema-pglite.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));

/** PGlite llega como dependencia transitiva de `prisma` (@prisma/dev); no se instala aparte. */
async function loadPGlite() {
  const store = join(repo, 'node_modules/.pnpm');
  const folder = readdirSync(store)
    .filter((entry) => entry.startsWith('@electric-sql+pglite@'))
    .sort()
    .at(-1);
  if (!folder) {
    console.error('PGlite no está en node_modules/.pnpm; ejecute pnpm install.');
    process.exit(2);
  }
  const entry = join(store, folder, 'node_modules/@electric-sql/pglite/dist/index.js');
  return (await import(pathToFileURL(entry).href)).PGlite;
}
const PGlite = await loadPGlite();

const db = new PGlite();
const migrationsDir = join(repo, 'platform/database/prisma/migrations');
const migrations = readdirSync(migrationsDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

const results = [];
const check = async (name, fn) => {
  try {
    await fn();
    results.push(['OK', name]);
  } catch (error) {
    results.push(['FAIL', name, String(error.message ?? error).slice(0, 200)]);
  }
};
const expectError = async (sql, pattern) => {
  try {
    await db.exec(sql);
  } catch (error) {
    if (pattern && !pattern.test(String(error.message))) {
      throw new Error(`error inesperado: ${error.message}`);
    }
    return;
  }
  throw new Error(`se esperaba error: ${sql.slice(0, 80)}`);
};

const { rows: version } = await db.query('SELECT version()');
console.log(version[0].version);

for (const name of migrations) {
  const sql = readFileSync(join(migrationsDir, name, 'migration.sql'), 'utf8');
  try {
    await db.exec(sql);
  } catch (error) {
    console.log(`MIGRATION FAIL ${name}: ${error.message}`);
    process.exit(1);
  }
}
console.log(`migraciones aplicadas: ${migrations.length}`);

const T = "'t-verify'";
await db.exec(`
INSERT INTO detection_candidates (id, tenant_id, event_record_id, event_uid, idempotency_key, priority, score, reasons, ruleset_id, ruleset_version, title, occurred_at)
VALUES ('0199c1a0-0000-7000-8000-000000000001', ${T}, '0199c1a0-0000-7000-8000-000000000002', 'evt', 'k1', 'P4', 30, '[]', 'r', '1', 't', now()),
       ('0199c1a0-0000-7000-8000-000000000003', ${T}, '0199c1a0-0000-7000-8000-000000000004', 'evt2', 'k2', 'P4', 30, '[]', 'r', '1', 't', now());
INSERT INTO soc_alerts (id, tenant_id, candidate_id, event_record_id, title, priority, score, reasons, status, occurred_at, updated_at, revision)
VALUES ('0199c1a0-0000-7000-8000-000000000001', ${T}, '0199c1a0-0000-7000-8000-000000000001', '0199c1a0-0000-7000-8000-000000000002', 't', 'P4', 30, '[]', 'new', now(), now(), 1),
       ('0199c1a0-0000-7000-8000-000000000003', ${T}, '0199c1a0-0000-7000-8000-000000000003', '0199c1a0-0000-7000-8000-000000000004', 't', 'P4', 30, '[]', 'new', now(), now(), 1);
`);
const A1 = "'0199c1a0-0000-7000-8000-000000000001'";
const A2 = "'0199c1a0-0000-7000-8000-000000000003'";
const FP = `'fp1_${'a'.repeat(64)}'`;

await check('A · CHECK de catálogo de motivo y origen en soc_alerts', async () => {
  await expectError(
    `UPDATE soc_alerts SET closure_reason = 'FP_PORQUE_SI' WHERE id = ${A1}`,
    /closure_reason_catalog/,
  );
  await expectError(
    `UPDATE soc_alerts SET closure_origin = 'otro' WHERE id = ${A1}`,
    /closure_origin_catalog/,
  );
  await db.exec(`UPDATE soc_alerts SET closure_origin = 'human' WHERE id = ${A1}`);
});

await check(
  'A · soc_alert_closures: motivo exige justificación y reapertura sin motivo',
  async () => {
    await expectError(
      `INSERT INTO soc_alert_closures (id, tenant_id, alert_id, kind, closure_reason, origin, actor_id, correlation_id, at)
     VALUES (gen_random_uuid(), ${T}, ${A1}, 'close', 'TP_REAL', 'human', 'a', 'c', now())`,
      /reason_has_justification/,
    );
    await expectError(
      `INSERT INTO soc_alert_closures (id, tenant_id, alert_id, kind, closure_reason, origin, actor_id, justification, correlation_id, at)
     VALUES (gen_random_uuid(), ${T}, ${A1}, 'reopen', 'TP_REAL', 'human', 'a', '{}', 'c', now())`,
      /reopen_shape/,
    );
    await db.exec(
      `INSERT INTO soc_alert_closures (id, tenant_id, alert_id, kind, verdict, closure_reason, origin, actor_id, justification, evidence_refs, correlation_id, at)
     VALUES (gen_random_uuid(), ${T}, ${A1}, 'close', 'true_positive', 'TP_REAL', 'human', 'a', '{"statement":"x"}', '[{"kind":"ticket","ref":"X"}]', 'c', now())`,
    );
  },
);

await check('B · huella: formato, nivel y fina exige regla', async () => {
  await expectError(
    `INSERT INTO soc_alert_fingerprints (alert_id, tenant_id, rule_key, fingerprint, level, version, normalizer_version, components, computed_at)
     VALUES (${A1}, ${T}, 'w:1', 'fp1_xyz', 'fine', '1', '1', '{}', now())`,
    /format/,
  );
  await expectError(
    `INSERT INTO soc_alert_fingerprints (alert_id, tenant_id, rule_key, fingerprint, level, version, normalizer_version, components, computed_at)
     VALUES (${A1}, ${T}, NULL, ${FP}, 'fine', '1', '1', '{}', now())`,
    /fine_has_rule/,
  );
  await db.exec(
    `INSERT INTO soc_alert_fingerprints (alert_id, tenant_id, rule_key, fingerprint, level, version, normalizer_version, components, computed_at)
     VALUES (${A1}, ${T}, 'windows:101150', ${FP}, 'fine', '1', '1', '{}', now()),
            (${A2}, ${T}, 'windows:101150', ${FP}, 'fine', '1', '1', '{}', now())`,
  );
});

await check(
  'C · índice único parcial: un solo grupo abierto por huella; cerrado no cuenta',
  async () => {
    const insert = (id, status) =>
      `INSERT INTO soc_alert_groups (id, tenant_id, fingerprint, rule_key, level, status, first_seen_at, last_seen_at, alert_count, primary_alert_id, highest_priority, revision)
     VALUES ('${id}', ${T}, ${FP}, 'windows:101150', 'fine', '${status}', now(), now(), 1, ${A1}, 'P4', 1)`;
    await db.exec(insert('0199c1a0-0000-7000-8000-0000000000a1', 'open'));
    await expectError(
      insert('0199c1a0-0000-7000-8000-0000000000a2', 'open'),
      /open_fingerprint_key/,
    );
    await db.exec(insert('0199c1a0-0000-7000-8000-0000000000a3', 'closed'));
    const { rows } = await db.query(
      `INSERT INTO soc_alert_groups (id, tenant_id, fingerprint, rule_key, level, status, first_seen_at, last_seen_at, alert_count, primary_alert_id, highest_priority, revision)
     VALUES ('0199c1a0-0000-7000-8000-0000000000a4', ${T}, ${FP}, 'windows:101150', 'fine', 'open', now(), now(), 1, ${A1}, 'P4', 1)
     ON CONFLICT DO NOTHING RETURNING id`,
    );
    if (rows.length !== 0) throw new Error('ON CONFLICT DO NOTHING debió omitir la fila');
  },
);

await check(
  'C · SELECT … FOR UPDATE del grupo abierto (sintaxis y columnas del store)',
  async () => {
    const { rows } = await db.query(
      `SELECT id, tenant_id AS "tenantId", fingerprint, rule_key AS "ruleKey", level, status,
            first_seen_at AS "firstSeenAt", last_seen_at AS "lastSeenAt",
            alert_count AS "alertCount", primary_alert_id AS "primaryAlertId",
            highest_priority AS "highestPriority", revision
       FROM soc_alert_groups
      WHERE tenant_id = ${T} AND fingerprint = ${FP} AND status = 'open'
      FOR UPDATE`,
    );
    if (rows.length !== 1 || rows[0].alertCount !== 1) throw new Error(JSON.stringify(rows));
  },
);

await check('C · miembros: una alerta en un solo grupo', async () => {
  await db.exec(
    `INSERT INTO soc_alert_group_members (alert_id, tenant_id, group_id, joined_at)
     VALUES (${A1}, ${T}, '0199c1a0-0000-7000-8000-0000000000a1', now()),
            (${A2}, ${T}, '0199c1a0-0000-7000-8000-0000000000a1', now())`,
  );
  await expectError(
    `INSERT INTO soc_alert_group_members (alert_id, tenant_id, group_id, joined_at)
     VALUES (${A1}, ${T}, '0199c1a0-0000-7000-8000-0000000000a3', now())`,
    /pkey|duplicate/,
  );
});

for (const table of ['soc_alert_closures', 'soc_alert_fingerprints', 'soc_alert_group_members']) {
  await check(`Inmutabilidad · ${table}: UPDATE, DELETE y TRUNCATE rechazados`, async () => {
    await expectError(`UPDATE ${table} SET tenant_id = tenant_id`, /append-only/);
    await expectError(`DELETE FROM ${table}`, /append-only/);
    await expectError(`TRUNCATE ${table} CASCADE`, /append-only/);
  });
}

/** Extrae el SQL entre `BEGIN;` y el primer meta-comando de psql posterior (sin \if/\echo). */
function sqlBody(file, replacements = []) {
  let text = readFileSync(join(repo, file), 'utf8');
  for (const [from, to] of replacements) text = text.replaceAll(from, to);
  const start = text.indexOf('BEGIN;');
  const end = text.indexOf('\n\\', start);
  return text.slice(start, end === -1 ? undefined : end);
}

await check('A · etiquetado retroactivo: origen por actor, idempotente, sin motivo', async () => {
  await db.exec(
    `UPDATE soc_alerts SET status = 'closed', verdict = 'false_positive' WHERE id = ${A2}`,
  );
  await db.exec(`
    INSERT INTO audit_events (id, tenant_id, sequence, occurred_at, actor_id, actor_type, action, resource_type, resource_id, outcome, correlation_id, previous_hash, hash)
    VALUES (gen_random_uuid(), ${T}, 1, now(), 'svc:b89-ai-analyst', 'service', 'soc.alert.close', 'alert', ${A2}, 'succeeded', 'ai-investigation:x', '${'0'.repeat(64)}', '${'1'.repeat(64)}')`);
  const body = sqlBody('scripts/soc-learning/backfill-closure-origin.sql') + '\nCOMMIT;';
  await db.exec(body);
  await db.exec(body); // idempotente
  const { rows } = await db.query(
    `SELECT a.closure_origin, a.closure_reason, (SELECT count(*)::int FROM soc_alert_closures c WHERE c.alert_id = a.id AND c.correlation_id LIKE 'backfill:%') AS backfilled
       FROM soc_alerts a WHERE a.id = ${A2}`,
  );
  const row = rows[0];
  if (row.closure_origin !== 'ai_analyst' || row.closure_reason !== null || row.backfilled !== 1) {
    throw new Error(JSON.stringify(row));
  }
});

await check('Rollback · se niega con datos y no toca nada', async () => {
  const body = sqlBody('scripts/soc-learning/rollback-learning-schema.sql', [
    [":'confirm'", "'rollback-soc-learning'"],
  ]);
  await expectError(body + '\nCOMMIT;', /Hay datos de aprendizaje SOC/);
  await db.exec('ROLLBACK').catch(() => undefined);
  const { rows } = await db.query(`SELECT to_regclass('soc_alert_groups') IS NOT NULL AS present`);
  if (!rows[0].present) throw new Error('el rollback borró algo');
});

await check('Rollback · sin datos revierte y las migraciones se reaplican', async () => {
  const fresh = new PGlite();
  for (const name of migrations) {
    await fresh.exec(readFileSync(join(migrationsDir, name, 'migration.sql'), 'utf8'));
  }
  await fresh.exec(`CREATE TABLE IF NOT EXISTS _prisma_migrations (migration_name text)`);
  const body = sqlBody('scripts/soc-learning/rollback-learning-schema.sql', [
    [":'confirm'", "'rollback-soc-learning'"],
  ]);
  await fresh.exec(body);
  const gone = await fresh.query(
    `SELECT to_regclass('soc_alert_groups') IS NULL AND to_regclass('soc_alert_closures') IS NULL AS gone,
            NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'soc_alerts' AND column_name = 'closure_origin') AS column_gone`,
  );
  if (!gone.rows[0].gone || !gone.rows[0].column_gone)
    throw new Error(JSON.stringify(gone.rows[0]));
  for (const name of migrations.filter((entry) => entry.includes('soc_learning'))) {
    await fresh.exec(readFileSync(join(migrationsDir, name, 'migration.sql'), 'utf8'));
  }
  const back = await fresh.query(`SELECT to_regclass('soc_alert_groups') IS NOT NULL AS present`);
  if (!back.rows[0].present) throw new Error('no se reaplicó');
});

for (const [status, name, detail] of results) {
  console.log(`${status.padEnd(4)} ${name}${detail ? ` — ${detail}` : ''}`);
}
const failed = results.filter(([status]) => status !== 'OK').length;
console.log(`\n${results.length - failed}/${results.length} comprobaciones OK`);
process.exit(failed === 0 ? 0 : 1);
