/**
 * Aprendizaje SOC · informe de sombra en Markdown (diario o semanal), para cron.
 *
 *   DATABASE_URL=postgresql://…(rol de solo lectura)… pnpm exec tsx --conditions=development scripts/soc-learning/shadow-report.ts \
 *     --tenant <tenant> --period daily|weekly > informe.md
 *
 * Lee con la misma consulta que `GET /api/learning/shadow-report` y aplica `buildShadowReport`. Sin
 * PII: reglas, patrones y conteos. Datos reales, NO sintéticos: se rotula con el período y la fuente.
 */

import { PostgresSocPersistence } from '../../modules/soc/src/infrastructure/postgres-soc.js';
import {
  buildShadowReport,
  type ShadowStats,
} from '../../modules/soc/src/learning-shadow-report.js';

function argument(name: string, fallback?: string): string {
  const index = process.argv.indexOf(`--${name}`);
  const value = index >= 0 ? process.argv[index + 1] : fallback;
  if (!value) throw new Error(`Falta --${name}`);
  return value;
}

const pct = (value: number | null) => (value === null ? '—' : `${(value * 100).toFixed(1)} %`);

function line(label: string, stats: ShadowStats): string {
  return `| ${label} | ${stats.decisions} | ${stats.hypotheticalCloses} | ${stats.adjudicated} | ${stats.agreed} | ${stats.truePositivesSuppressed} | ${stats.pending} | ${pct(stats.precision)} | ${pct(stats.precisionLowerBound)} | ${pct(stats.coverageGain)} |`;
}

async function main(): Promise<void> {
  const url = process.env['DATABASE_URL'];
  if (!url) throw new Error('DATABASE_URL es obligatorio (rol de solo lectura).');
  const tenant = argument('tenant');
  const period = argument('period', 'daily');
  if (period !== 'daily' && period !== 'weekly')
    throw new Error('--period debe ser daily o weekly');
  const to = new Date();
  const from = new Date(to.getTime() - (period === 'weekly' ? 7 : 1) * 24 * 60 * 60 * 1000);
  const persistence = PostgresSocPersistence.connect({ connectionString: url, maxConnections: 2 });
  try {
    const rows = await persistence.learningShadowRows(tenant, from, to);
    const report = buildShadowReport(rows, { from, to });
    const header =
      '| | Decisiones | Cierres hipotéticos | Adjudicadas | Acuerdo | TP suprimidos | Pendientes | Precisión | Cota inf. CP 95 % | Cobertura |\n' +
      '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|';
    const out = [
      `# Informe de sombra (${period === 'weekly' ? 'semanal' : 'diario'})`,
      '',
      `Período: ${report.from} → ${report.to}. Fuente: decisiones del motor y estado actual de cada alerta.`,
      `Umbral: cota inferior ≥ ${report.threshold.precisionLowerBound} con ≥ ${report.threshold.minAdjudicated} adjudicadas. Gold set: ${report.goldSet}.`,
      '',
      header,
      line('**Total**', report.totals),
      ...report.byRule.map((rule) => line(`\`${rule.ruleKey}\``, rule)),
      '',
      '## Por patrón',
      '',
      header,
      ...report.byPattern.map((pattern) => line(`\`${pattern.patternId}\``, pattern)),
      '',
      '## Patrones inseguros',
      '',
      ...(report.unsafePatterns.length === 0
        ? ['Ninguno.']
        : report.unsafePatterns.map((item) => `- \`${item.patternId}\`: ${item.reason}`)),
      '',
      '## Razones de escalada',
      '',
      ...Object.entries(report.totals.escalations)
        .sort((left, right) => right[1] - left[1])
        .map(([reason, count]) => `- ${reason}: ${count}`),
      '',
    ];
    process.stdout.write(out.join('\n'));
  } finally {
    await persistence.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`shadow-report: ${(error as Error).message}\n`);
  process.exitCode = 1;
});
