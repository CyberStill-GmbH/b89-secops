/**
 * Corre todos los experimentos de F2 con semillas fijas y escribe research/soc-lab/RESULTS.md y
 * los CSV de las curvas en research/soc-lab/out/. Reproducible:
 *
 *   pnpm exec tsx --conditions=development research/soc-lab/run-all.ts
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { runCanaries } from './src/canary.js';
import { calibrateCusum, cusumDetector, evaluate, scenarios, staticDetector } from './src/drift.js';
import {
  clopperPearsonPolicy,
  countPolicy,
  hierarchicalPolicy,
  run,
  type ActivationPolicy,
  type RunOptions,
  type RunResult,
  type SamplingStrategy,
} from './src/sim.js';

const OUT = resolve(import.meta.dirname, 'out');
mkdirSync(OUT, { recursive: true });
const SEEDS = Array.from({ length: 30 }, (_, index) => 1000 + index);
const DAYS = 180;

const BASE: Omit<RunOptions, 'seed' | 'policy' | 'sampling'> = {
  days: DAYS,
  missRate: 0.02,
  falseAlarmRate: 0.005,
  samplingKey: 'clave-de-laboratorio',
  // Atacante sigiloso: copia exacta de los 3 patrones activos de más volumen, ~1 TP/día cada uno.
  attack: { startDay: 90, days: 30, targets: 3, ratePerDay: 1 },
};

const mean = (values: readonly number[]) => values.reduce((a, b) => a + b, 0) / values.length;
const sd = (values: readonly number[]) => {
  const m = mean(values);
  return Math.sqrt(values.reduce((a, b) => a + (b - m) ** 2, 0) / Math.max(1, values.length - 1));
};
const ci = (values: readonly number[]) => 1.96 * (sd(values) / Math.sqrt(values.length));
const fmt = (value: number, digits = 1) => (Number.isFinite(value) ? value.toFixed(digits) : '∞');
const pm = (values: readonly number[], digits = 1) =>
  `${fmt(mean(values), digits)} ± ${fmt(ci(values), digits)}`;

function runAll(
  policy: ActivationPolicy,
  sampling: SamplingStrategy,
  extra: Partial<RunOptions> = {},
) {
  return SEEDS.map((seed) => run({ ...BASE, ...extra, seed, policy, sampling }));
}

const lines: string[] = [];
const say = (...text: string[]) => lines.push(...text);
const started = Date.now();

say(
  '# Resultados F2 · laboratorio del SOC que aprende',
  '',
  `Generado por \`research/soc-lab/run-all.ts\` · ${SEEDS.length} semillas (${SEEDS[0]}–${SEEDS.at(-1)}) · ${DAYS} días por corrida · números aleatorios comunes entre políticas.`,
  'Intervalos: media ± IC 95 % (1,96·σ/√n) sobre las semillas. Todo es **sintético**: muestra órdenes de magnitud y comparaciones relativas, no cifras de producción.',
  '',
);

/* ------------------------------------------------ E1 · fichas 1 y 3: riesgo–cobertura */

const uniform10: SamplingStrategy = { kind: 'uniform', rate: 0.1 };
const policies: ActivationPolicy[] = [
  ...[3, 5, 10, 20, 40].map(countPolicy),
  ...[0.9, 0.95, 0.97, 0.99].map((q) => clopperPearsonPolicy(q)),
  ...[0.9, 0.95, 0.97, 0.99].map((q) => hierarchicalPolicy(q)),
];
const e1 = policies.map((policy) => ({ policy, results: runAll(policy, uniform10) }));
const csv1 = [
  'politica,semilla,cobertura,tp_suprimidos,tp_suprimidos_por_10k,ataque_suprimidos,patrones_inseguros_activos',
];
for (const { policy, results } of e1) {
  results.forEach((r, i) =>
    csv1.push(
      [
        policy.name,
        SEEDS[i],
        r.coverage.toFixed(5),
        r.tpSuppressed,
        r.tpSuppressedPer10k.toFixed(3),
        r.attackSuppressed,
        r.activePatternsUnsafe,
      ].join(','),
    ),
  );
}
writeFileSync(resolve(OUT, 'e1-riesgo-cobertura.csv'), `${csv1.join('\n')}\n`);

say(
  '## E1 · Fichas 1 y 3 — riesgo frente a cobertura de autocierre',
  '',
  'Muestreo uniforme del 10 % en todas. «TP suprimidos» = TP reales autocerrados y no detectados por la revisión (naturales + del atacante). «Inseguros activos» = patrones activos al final con θ_TP > 3 %.',
  '',
  '| Política | Cobertura (%) | TP suprimidos / corrida | TP suprimidos por 10 000 autocierres | Del atacante | Inseguros activos |',
  '|---|---:|---:|---:|---:|---:|',
);
for (const { policy, results } of e1) {
  say(
    `| ${policy.name} | ${pm(results.map((r) => 100 * r.coverage))} | ${pm(results.map((r) => r.tpSuppressed))} | ${pm(results.map((r) => r.tpSuppressedPer10k))} | ${pm(results.map((r) => r.attackSuppressed))} | ${pm(
      results.map((r) => r.activePatternsUnsafe),
      2,
    )} |`,
  );
}
say('');

/* ------------------------------------------------ E1b · envenenamiento de la evidencia */

const poison = { days: 60, share: 0.5 };
const poisonPolicies = [countPolicy(5), clopperPearsonPolicy(0.97), hierarchicalPolicy(0.97)];
say(
  '## E1b · Ficha 3 — robustez ante envenenamiento',
  '',
  `Una cuenta de analista comprometida etiqueta FP el ${100 * poison.share} % de lo que revisa en una regla **riesgosa** (θ ≈ 5 %) durante ${poison.days} días.`,
  '',
  '| Política | TP suprimidos sin veneno | TP suprimidos con veneno | Inseguros activos sin / con veneno |',
  '|---|---:|---:|---:|',
);
for (const policy of poisonPolicies) {
  const clean = runAll(policy, uniform10);
  const poisoned = runAll(policy, uniform10, { poison });
  say(
    `| ${policy.name} | ${pm(clean.map((r) => r.tpSuppressed))} | ${pm(poisoned.map((r) => r.tpSuppressed))} | ${fmt(mean(clean.map((r) => r.activePatternsUnsafe)), 2)} / ${fmt(mean(poisoned.map((r) => r.activePatternsUnsafe)), 2)} |`,
  );
}
say('');

/* ------------------------------------------------ E2 · ficha 2: muestreo */

const samplings: { name: string; strategy: SamplingStrategy }[] = [
  { name: 'sin muestreo', strategy: { kind: 'none' } },
  { name: 'uniforme 10 %', strategy: uniform10 },
  { name: 'adaptativo 10 % (piso 2 %)', strategy: { kind: 'adaptive', rate: 0.1, floor: 0.02 } },
];
say(
  '## E2 · Ficha 2 — muestreo de revisión con el mismo presupuesto',
  '',
  'Atacante: copia exacta de los 3 patrones activos de más volumen desde el día 90, ~1 TP/día cada uno, 30 días. «Días hasta pausar» = mediana sobre patrones atacados (∞ = nunca). Sesgo y RMSE de Horvitz–Thompson frente a la precisión real de lo autocerrado.',
  '',
  '| Política | Muestreo | Revisiones / corrida | Ataque suprimido | Días hasta pausar (mediana) | TP suprimidos totales | Sesgo HT (pp) | RMSE HT (pp) |',
  '|---|---|---:|---:|---:|---:|---:|---:|',
);
const csv2 = [
  'politica,muestreo,semilla,revisiones,ataque_suprimidos,tp_suprimidos,precision_real,precision_ht',
];
for (const policy of [countPolicy(5), clopperPearsonPolicy(0.97)]) {
  for (const { name, strategy } of samplings) {
    const results: RunResult[] = runAll(policy, strategy);
    results.forEach((r, i) =>
      csv2.push(
        [
          policy.name,
          name,
          SEEDS[i],
          r.reviews,
          r.attackSuppressed,
          r.tpSuppressed,
          r.truePrecision.toFixed(6),
          r.htPrecision?.toFixed(6) ?? '',
        ].join(','),
      ),
    );
    const pauses = results.flatMap((r) => r.attackDaysToPause).sort((a, b) => a - b);
    const medianPause = pauses.length ? pauses[Math.floor(pauses.length / 2)]! : Number.NaN;
    const errors = results
      .filter((r) => r.htPrecision !== null)
      .map((r) => 100 * (r.htPrecision! - r.truePrecision));
    say(
      `| ${policy.name} | ${name} | ${pm(
        results.map((r) => r.reviews),
        0,
      )} | ${pm(results.map((r) => r.attackSuppressed))} | ${fmt(medianPause, 0)} | ${pm(results.map((r) => r.tpSuppressed))} | ${errors.length ? fmt(mean(errors), 3) : '—'} | ${errors.length ? fmt(Math.sqrt(mean(errors.map((e) => e * e))), 3) : '—'} |`,
    );
  }
}
writeFileSync(resolve(OUT, 'e2-muestreo.csv'), `${csv2.join('\n')}\n`);
say('');

/* ------------------------------------------------ E3 · ficha 6: deriva */

const driftOptions = { base: 0.5, hours: 30 * 24, reps: 300, seed: 77 };
const changeAt = 15 * 24;
const all = scenarios(driftOptions.base, changeAt);
const noChange = all[0]!;
const staticNoChange = evaluate('estático', (b) => staticDetector(b), noChange, driftOptions);
const target = Math.max(staticNoChange.falseAlarmsPerMonth, 0.1);
const h = calibrateCusum(target, { ...driftOptions, seed: 991 });
say(
  '## E3 · Ficha 6 — deriva de la tasa de un patrón',
  '',
  `Tasa base 0,5 alertas/h con ciclo diario; cambio en la hora ${changeAt}; ${driftOptions.reps} series de 30 días por escenario. Estático = alarma si una hora supera max(10, 3 × p95 base). CUSUM de Poisson (λ₁ = 2λ₀) con h = ${fmt(h, 2)}, calibrado en semillas distintas para ≤ ${fmt(target, 2)} falsas alarmas/mes (el estático da ${fmt(staticNoChange.falseAlarmsPerMonth, 2)}).`,
  '',
  '| Escenario | Detector | Detecta (%) | Retraso mediano (h) | Falsas alarmas / mes |',
  '|---|---|---:|---:|---:|',
);
for (const scenario of all) {
  for (const [name, make] of [
    ['estático 3×p95', (b: readonly number[]) => staticDetector(b)],
    [`CUSUM h=${fmt(h, 2)}`, () => cusumDetector(h)],
  ] as const) {
    const result = evaluate(name, make, scenario, driftOptions);
    say(
      `| ${scenario.name} | ${name} | ${Number.isNaN(result.detectedShare) ? '—' : fmt(100 * result.detectedShare, 0)} | ${Number.isNaN(result.medianDelay) ? '—' : fmt(result.medianDelay, 0)} | ${fmt(result.falseAlarmsPerMonth, 2)} |`,
    );
  }
}
say('');

/* ------------------------------------------------ E4 · ficha 4: canarios */

const canaries = runCanaries(4242, 500);
say(
  '## E4 · Ficha 4 — canarios de casi-coincidencia (huella real, decisión modelada)',
  '',
  '500 patrones aprobados; por cada uno, una variante. La huella es la del repo (`modules/detection/src/fingerprint.ts`); la decisión es un **modelo** del diseño §7 (el motor no existe).',
  '',
  '| Variante | Inyectados | Autocerrados | Escalados |',
  '|---|---:|---:|---:|',
  ...canaries.map((c) => `| ${c.variant} | ${c.injected} | ${c.autoClosed} | ${c.escalated} |`),
  '',
  `Tiempo total: ${((Date.now() - started) / 1000).toFixed(0)} s.`,
);

writeFileSync(resolve(import.meta.dirname, 'RESULTS.md'), `${lines.join('\n')}\n`);
process.stdout.write(`${lines.join('\n')}\n`);
