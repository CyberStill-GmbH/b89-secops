/**
 * F3a — todos los experimentos con semillas fijas, en un solo comando:
 *
 *   pnpm exec tsx research/soc-lab/run-f3a.ts
 *
 * Escribe research/soc-lab/RESULTS-F3A.md y research/soc-lab/out/f3a-*.csv. Datos SINTÉTICOS.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { calibrateTable } from './src/cusum-table.js';
import {
  calibrate,
  cusumDetector,
  delay,
  ewmaDetector,
  falseAlarmsPerMonth,
  sprtDetector,
  staticDetector,
  type Change,
  type Detector,
  type Population,
} from './src/drift2.js';
import { mulberry32 } from './src/rng.js';
import {
  DEFAULT_WORLD,
  NO_DEFENSES,
  run,
  type AttackKind,
  type AttackSpec,
  type RunOptions,
  type RunResult,
} from './src/sim2.js';

const OUT = resolve(import.meta.dirname, 'out');
mkdirSync(OUT, { recursive: true });
const started = Date.now();
const seeds = (count: number, from = 5000) => Array.from({ length: count }, (_, i) => from + i);
const SEEDS_MAIN = seeds(100);
const SEEDS_GRID = seeds(60);
const SEEDS_POISON = seeds(40);

/* ------------------------------------------------------------ Utilidades */

const mean = (values: readonly number[]) => values.reduce((a, b) => a + b, 0) / values.length;
const fmt = (value: number, digits = 1) =>
  Number.isFinite(value) ? value.toFixed(digits).replace('.', ',') : '∞';

/** IC 95 % bootstrap (percentiles, 2000 remuestreos de semillas) de la media. */
function bootstrap(values: readonly number[], seed = 77, resamples = 2000): [number, number] {
  const rng = mulberry32(seed);
  const means: number[] = [];
  for (let b = 0; b < resamples; b += 1) {
    let sum = 0;
    for (let i = 0; i < values.length; i += 1) sum += values[Math.floor(rng.next() * values.length)]!;
    means.push(sum / values.length);
  }
  means.sort((a, b) => a - b);
  return [means[Math.floor(0.025 * resamples)]!, means[Math.floor(0.975 * resamples)]!];
}
const withCi = (values: readonly number[], digits = 1) => {
  const [low, high] = bootstrap(values);
  return `${fmt(mean(values), digits)} [${fmt(low, digits)}; ${fmt(high, digits)}]`;
};
/** Diferencia pareada A − B por semilla con IC bootstrap. */
const pairedDiff = (a: readonly RunResult[], b: readonly RunResult[], pick: (r: RunResult) => number, digits = 1) =>
  withCi(a.map((r, i) => pick(r) - pick(b[i]!)), digits);

const lines: string[] = [];
const say = (...text: string[]) => {
  for (const line of text) {
    if (line.startsWith('## ')) process.stderr.write(`[${((Date.now() - started) / 1000).toFixed(0)} s] ${line.slice(3)}\n`);
  }
  lines.push(...text);
};
const SYNTH = '_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._';

/* ---------------------------------------------------------- Configuración */

const table = calibrateTable(3600);
const ATTACK_TOP: AttackSpec = { kind: 'top', startDay: 90, days: 30, targets: 3, rate: 1 };
const BASE: Omit<RunOptions, 'seed' | 'policy'> = {
  days: 180,
  world: DEFAULT_WORLD,
  defenses: NO_DEFENSES,
  samplingRate: 0.1,
  weeklyReviewFloor: 0,
  capPerDay: Number.POSITIVE_INFINITY,
  forcedReviewAfter: Number.POSITIVE_INFINITY,
  impactGate: false,
  attack: ATTACK_TOP,
  insiderColluders: 1,
  analysts: 6,
  missRate: 0.02,
  falseAlarmRate: 0.005,
  samplingKey: 'clave-de-laboratorio',
};

type Config = Partial<RunOptions> & Pick<RunOptions, 'policy'>;
const POLICIES: Record<string, Config> = {
  'conteo N=5 (actual)': { policy: { kind: 'count', n: 5 } },
  'conteo N=10': { policy: { kind: 'count', n: 10 } },
  'jerárquica sola': { policy: { kind: 'hier', q: 0.97 } },
  combinada: {
    policy: { kind: 'hier', q: 0.97, cpFloor: 0.9 },
    defenses: { minAnalysts: 2, minDays: 3, twoPerson: true, sodScope: 'evidence' },
    cusum: table,
  },
};

const cache = new Map<string, RunResult[]>();
function runs(name: string, config: Config, seedList: readonly number[]): RunResult[] {
  const key = `${name}|${seedList.length}|${seedList[0]}`;
  if (!cache.has(key)) cache.set(key, seedList.map((seed) => run({ ...BASE, ...config, seed })));
  return cache.get(key)!;
}

say(
  '# Resultados F3a · laboratorio del SOC que aprende',
  '',
  'Generado por `pnpm exec tsx research/soc-lab/run-f3a.ts`. Semillas fijas; números aleatorios comunes entre políticas (mismo tráfico). Intervalos: **IC 95 % bootstrap** (2000 remuestreos de semillas, percentiles). Los valores son medias por corrida de 180 días (~170 alertas/día) salvo que se indique otra cosa.',
  '',
  SYNTH,
  '',
  `Tabla CUSUM (presupuesto global 1 falsa alarma/mes sobre ~120 patrones → ARL₀ = 3600 días por patrón): ${table.points.map((p) => `λ₀=${fmt(p.lambda, 2)}→h=${fmt(p.h, 2)}`).join(' · ')}.`,
  '',
  'Orden de llegada dentro del día: **aleatorio** (permutación con semilla). Una versión anterior procesaba las alertas del atacante siempre al final del día, lo que favorecía artificialmente al tope diario de E4; quedó corregido y todo se volvió a ejecutar.',
  '',
  '«Combinada» = jerárquica q = 0,97 + piso Clopper–Pearson 0,90 + ≥ 2 analistas distintos + ≥ 3 días distintos + aprobación de dos personas (separación respecto de quienes firmaron la evidencia presentada) + CUSUM con presupuesto global + muestreo uniforme con clave del 10 %.',
  '',
);

/* ------------------------------------------------- E1 · política combinada */

const e1 = Object.fromEntries(Object.entries(POLICIES).map(([name, config]) => [name, runs(name, config, SEEDS_MAIN)]));
const csv: string[] = ['experimento,politica,variante,semilla,alertas,autocierres,cobertura,tp_suprimidos,tp_ponderados,ataque_inyectado,ataque_suprimido,revisiones,inseguros_activos,falsas_alarmas_deriva'];
const toCsv = (experiment: string, policy: string, variant: string, results: readonly RunResult[], seedList: readonly number[]) =>
  results.forEach((r, i) =>
    csv.push([experiment, policy, variant, seedList[i], r.alerts, r.autoClosed, r.coverage.toFixed(5), r.tpSuppressed, r.tpSuppressedWeighted, r.attackInjected, r.attackSuppressed, r.reviews, r.unsafeActive, r.driftFalseAlarms].join(',')),
  );
for (const [name, results] of Object.entries(e1)) toCsv('E1', name, 'top', results, SEEDS_MAIN);

say(
  '## E1 · Política combinada frente a N=5, N=10 y jerárquica sola',
  '',
  `${SEEDS_MAIN.length} semillas. Atacante (a): copia exacta de los 3 patrones activos de más volumen, ~1 TP/día cada uno, días 90–119.`,
  '',
  SYNTH,
  '',
  '| Política | Alertas (denominador) | Autocierres | Cobertura % | TP suprimidos | …de ellos del atacante / inyectados | TP ponderados por impacto | Inseguros activos | Revisiones | Pausas CUSUM sin ataque |',
  '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|',
);
for (const [name, results] of Object.entries(e1)) {
  say(
    `| ${name} | ${fmt(mean(results.map((r) => r.alerts)), 0)} | ${fmt(mean(results.map((r) => r.autoClosed)), 0)} | ${withCi(results.map((r) => 100 * r.coverage))} | ${withCi(results.map((r) => r.tpSuppressed))} | ${fmt(mean(results.map((r) => r.attackSuppressed)))} / ${fmt(mean(results.map((r) => r.attackInjected)))} | ${withCi(results.map((r) => r.tpSuppressedWeighted))} | ${fmt(mean(results.map((r) => r.unsafeActive)), 2)} | ${fmt(mean(results.map((r) => r.reviews)), 0)} | ${fmt(mean(results.map((r) => r.driftFalseAlarms)), 2)} |`,
  );
}
say('', 'Diferencias pareadas (combinada − X), media [IC 95 % bootstrap]:', '', '| X | Δ cobertura (pp) | Δ TP suprimidos | Δ TP del atacante | Δ TP ponderados |', '|---|---:|---:|---:|---:|');
const combined = e1['combinada']!;
for (const name of ['conteo N=5 (actual)', 'conteo N=10', 'jerárquica sola']) {
  const other = e1[name]!;
  say(
    `| ${name} | ${pairedDiff(combined, other, (r) => 100 * r.coverage)} | ${pairedDiff(combined, other, (r) => r.tpSuppressed)} | ${pairedDiff(combined, other, (r) => r.attackSuppressed)} | ${pairedDiff(combined, other, (r) => r.tpSuppressedWeighted)} |`,
  );
}
say('');

/* --------------------------------------------- E1b · descomposición de la combinada */

const COMPONENTS: Record<string, Config> = {
  'jerárquica sola': POLICIES['jerárquica sola']!,
  '+ piso CP 0,90': { policy: { kind: 'hier', q: 0.97, cpFloor: 0.9 } },
  '+ ≥ 2 analistas': { policy: { kind: 'hier', q: 0.97 }, defenses: { ...NO_DEFENSES, minAnalysts: 2 } },
  '+ ≥ 3 días': { policy: { kind: 'hier', q: 0.97 }, defenses: { ...NO_DEFENSES, minDays: 3 } },
  '+ dos personas': { policy: { kind: 'hier', q: 0.97 }, defenses: { ...NO_DEFENSES, twoPerson: true, sodScope: 'evidence' } },
  '+ CUSUM': { policy: { kind: 'hier', q: 0.97 }, cusum: table },
  combinada: POLICIES['combinada']!,
};
say(
  '## E1b · Descomposición: qué pieza de la combinada cuesta cobertura',
  '',
  `${SEEDS_GRID.length} semillas. Cada fila añade UNA pieza a la jerárquica sola (salvo «combinada», que las suma todas). Δ = fila − jerárquica sola [IC 95 % bootstrap].`,
  '',
  SYNTH,
  '',
  '| Variante | Cobertura % | Δ cobertura (pp) | TP suprimidos | Δ TP suprimidos | TP del atacante / inyectados |',
  '|---|---:|---:|---:|---:|---:|',
);
const hierGrid = runs('E1b|jerárquica sola', COMPONENTS['jerárquica sola']!, SEEDS_GRID);
for (const [label, config] of Object.entries(COMPONENTS)) {
  const results = runs(`E1b|${label}`, config, SEEDS_GRID);
  say(`| ${label} | ${withCi(results.map((r) => 100 * r.coverage))} | ${pairedDiff(results, hierGrid, (r) => 100 * r.coverage)} | ${withCi(results.map((r) => r.tpSuppressed))} | ${pairedDiff(results, hierGrid, (r) => r.tpSuppressed)} | ${fmt(mean(results.map((r) => r.attackSuppressed)))} / ${fmt(mean(results.map((r) => r.attackInjected)))} |`);
}
say('');

/* --------------------------------------------------- E2 · atacantes múltiples */

const ATTACKERS: { label: string; attack: AttackSpec; extra?: Partial<RunOptions> }[] = [
  { label: '(a) mayor volumen', attack: ATTACK_TOP },
  { label: '(b) menor volumen', attack: { ...ATTACK_TOP, kind: 'low' } },
  { label: '(c) bajo y lento (sustituye 30 % del tráfico; tasa total igual)', attack: { ...ATTACK_TOP, kind: 'slow', rate: 0.3 } },
  { label: '(d) ráfagas: 7 TP juntos cada 7 días', attack: { ...ATTACK_TOP, kind: 'burst' } },
  { label: '(e) conoce p, no la clave: se detiene tras 6 por patrón', attack: { ...ATTACK_TOP, kind: 'budget', rate: 2 } },
  { label: '(f) cambia de patrón al ser pausado (3 TP/día)', attack: { ...ATTACK_TOP, kind: 'switch' } },
  { label: '(g1) insider solo planta un patrón (1 TP/día, 180 días)', attack: { ...ATTACK_TOP, kind: 'insider' }, extra: { insiderColluders: 1 } },
  { label: '(g2) colusión de 4 (2 etiquetan, 2 aprueban)', attack: { ...ATTACK_TOP, kind: 'insider' }, extra: { insiderColluders: 4 } },
];
const E2_POLICIES = ['conteo N=5 (actual)', 'jerárquica sola', 'combinada'];
say(
  '## E2 · Atacantes múltiples (peor caso por política)',
  '',
  `${SEEDS_GRID.length} semillas por celda. Cada celda: TP del atacante suprimidos / inyectados (media por corrida) y, para (g), % de corridas en que el patrón plantado llegó a activarse.`,
  '',
  SYNTH,
  '',
  `| Atacante | ${E2_POLICIES.join(' | ')} |`,
  `|---|${E2_POLICIES.map(() => '---:').join('|')}|`,
);
const worst: Record<string, { label: string; value: number; ratio: number }> = {};
for (const attacker of ATTACKERS) {
  const cells = E2_POLICIES.map((name) => {
    const results = runs(`${name}|${attacker.label}`, { ...POLICIES[name]!, attack: attacker.attack, ...(attacker.extra ?? {}) }, SEEDS_GRID);
    toCsv('E2', name, attacker.label, results, SEEDS_GRID);
    const suppressed = mean(results.map((r) => r.attackSuppressed));
    const injected = mean(results.map((r) => r.attackInjected));
    const ratio = injected === 0 ? 0 : suppressed / injected;
    if (!worst[name] || suppressed > worst[name]!.value) worst[name] = { label: attacker.label, value: suppressed, ratio };
    const activated = attacker.attack.kind === 'insider'
      ? ` · activado en ${fmt((100 * results.filter((r) => r.maliciousActivated).length) / results.length, 0)} %`
      : '';
    return `${fmt(suppressed)} / ${fmt(injected)} (${fmt(100 * ratio, 0)} %)${activated}`;
  });
  say(`| ${attacker.label} | ${cells.join(' | ')} |`);
}
say('', '**Peor caso** (atacante que más TP logra suprimir, media por corrida):', '');
for (const name of E2_POLICIES) {
  const w = worst[name]!;
  say(`- ${name}: ${w.label} — ${fmt(w.value)} TP suprimidos (${fmt(100 * w.ratio, 0)} % de lo inyectado).`);
}
say('');

/* ------------------------------------------------- E3 · clase de impacto */

say(
  '## E3 · Autocierre solo en clases de bajo impacto',
  '',
  `${SEEDS_GRID.length} semillas. 30 % de las reglas son de alto impacto (peso 10); el resto, peso 1. Con la compuerta, en alto impacto solo se agrupa o baja prioridad (no hay autocierre).`,
  '',
  SYNTH,
  '',
  '| Política | Compuerta | Cobertura % | TP suprimidos | TP ponderados por impacto | Del atacante (ponderado) |',
  '|---|---|---:|---:|---:|---:|',
);
for (const name of ['conteo N=5 (actual)', 'combinada']) {
  const off = runs(`${name}|E3off`, { ...POLICIES[name]! }, SEEDS_GRID);
  const on = runs(`${name}|E3on`, { ...POLICIES[name]!, impactGate: true }, SEEDS_GRID);
  toCsv('E3', name, 'sin compuerta', off, SEEDS_GRID);
  toCsv('E3', name, 'con compuerta', on, SEEDS_GRID);
  for (const [label, results] of [['no', off], ['sí', on]] as const) {
    say(`| ${name} | ${label} | ${withCi(results.map((r) => 100 * r.coverage))} | ${withCi(results.map((r) => r.tpSuppressed))} | ${withCi(results.map((r) => r.tpSuppressedWeighted))} | ${fmt(mean(results.map((r) => r.attackSuppressedWeighted)))} |`);
  }
  say(`| ${name} | Δ (sí − no) | ${pairedDiff(on, off, (r) => 100 * r.coverage)} | ${pairedDiff(on, off, (r) => r.tpSuppressed)} | ${pairedDiff(on, off, (r) => r.tpSuppressedWeighted)} | ${pairedDiff(on, off, (r) => r.attackSuppressedWeighted)} |`);
}
say('');

/* ------------------------------------------------ E4 · radio de daño */

say(
  '## E4 · Tope de radio de daño',
  '',
  `${SEEDS_GRID.length} semillas, política combinada. Tope = máximo de autocierres por patrón y día (el exceso va a una persona). Revisión forzada = tras N autocierres seguidos sin revisión humana, la siguiente alerta se revisa. Atacantes (a) y (f).`,
  '',
  SYNTH,
  '',
  '| Tope/día | Revisión forzada tras | Orden | Cobertura % | Revisiones | (a) TP del atacante | (f) TP del atacante | Δ cobertura vs sin topes (pp) |',
  '|---|---|---|---:|---:|---:|---:|---:|',
);
const noCaps = runs('combinada', POLICIES['combinada']!, SEEDS_GRID);
for (const cap of [Number.POSITIVE_INFINITY, 10, 5]) {
  for (const forced of [Number.POSITIVE_INFINITY, 20, 10]) {
    const config = { ...POLICIES['combinada']!, capPerDay: cap, forcedReviewAfter: forced };
    const top = runs(`E4|${cap}|${forced}|top`, config, SEEDS_GRID);
    const sw = runs(`E4|${cap}|${forced}|switch`, { ...config, attack: { ...ATTACK_TOP, kind: 'switch' } }, SEEDS_GRID);
    toCsv('E4', 'combinada', `tope=${cap};forzada=${forced}`, top, SEEDS_GRID);
    say(`| ${fmt(cap, 0)} | ${fmt(forced, 0)} | aleatorio | ${withCi(top.map((r) => 100 * r.coverage))} | ${fmt(mean(top.map((r) => r.reviews)), 0)} | ${withCi(top.map((r) => r.attackSuppressed))} | ${withCi(sw.map((r) => r.attackSuppressed))} | ${pairedDiff(top, noCaps, (r) => 100 * r.coverage)} |`);
  }
}
// Peor caso para el tope: el atacante lo conoce y entra antes que el tráfico legítimo del día.
for (const cap of [10, 5]) {
  const config = { ...POLICIES['combinada']!, capPerDay: cap, arrivalOrder: 'attacker-first' as const };
  const top = runs(`E4|${cap}|first|top`, config, SEEDS_GRID);
  const sw = runs(`E4|${cap}|first|switch`, { ...config, attack: { ...ATTACK_TOP, kind: 'switch' } }, SEEDS_GRID);
  say(`| ${fmt(cap, 0)} | ∞ | **atacante primero** | ${withCi(top.map((r) => 100 * r.coverage))} | ${fmt(mean(top.map((r) => r.reviews)), 0)} | ${withCi(top.map((r) => r.attackSuppressed))} | ${withCi(sw.map((r) => r.attackSuppressed))} | ${pairedDiff(top, noCaps, (r) => 100 * r.coverage)} |`);
}
say('');

/* ------------------------------------------------ E5 · envenenamiento */

const DEFENSE_SETS: { label: string; defenses: RunOptions['defenses'] }[] = [
  { label: 'ninguna', defenses: NO_DEFENSES },
  { label: '≥ 2 analistas', defenses: { ...NO_DEFENSES, minAnalysts: 2 } },
  { label: '≥ 3 días', defenses: { ...NO_DEFENSES, minDays: 3 } },
  { label: 'dos personas', defenses: { ...NO_DEFENSES, twoPerson: true, sodScope: 'evidence' } },
  { label: 'las tres', defenses: { minAnalysts: 2, minDays: 3, twoPerson: true, sodScope: 'evidence' } },
];
say(
  '## E5 · Envenenamiento reforzado',
  '',
  `${SEEDS_POISON.length} semillas por celda. Todas las reglas riesgosas (θ ≈ 5 %) atacadas: un % de sus cierres lo firman insiders que siempre marcan FP. Política base: jerárquica q = 0,97 + piso CP 0,90, sin ataque externo. Celda: TP naturales suprimidos en las reglas envenenadas (media) · patrones inseguros activos al final.`,
  '',
  SYNTH,
  '',
  `| Nivel · insiders | ${DEFENSE_SETS.map((d) => d.label).join(' | ')} | conteo N=5 sin defensas |`,
  `|---|${DEFENSE_SETS.map(() => '---:').join('|')}|---:|`,
);
for (const level of [0.01, 0.05, 0.2]) {
  for (const colluders of [1, 2]) {
    const poison = { rules: 99, level, colluders };
    const cells = DEFENSE_SETS.map(({ label, defenses }) => {
      const results = runs(`E5|${level}|${colluders}|${label}`, { policy: { kind: 'hier', q: 0.97, cpFloor: 0.9 }, defenses, poison, attack: { ...ATTACK_TOP, kind: 'none' } }, SEEDS_POISON);
      return `${fmt(mean(results.map((r) => r.poisonedRuleTpSuppressed)))} · ${fmt(mean(results.map((r) => r.unsafeActive)), 2)}`;
    });
    const reference = runs(`E5|${level}|${colluders}|N5`, { policy: { kind: 'count', n: 5 }, poison, attack: { ...ATTACK_TOP, kind: 'none' } }, SEEDS_POISON);
    say(`| ${fmt(100 * level, 0)} % · ${colluders} | ${cells.join(' | ')} | ${fmt(mean(reference.map((r) => r.poisonedRuleTpSuppressed)))} · ${fmt(mean(reference.map((r) => r.unsafeActive)), 2)} |`);
  }
}
say('');

/* ------------------------------------------------ E6 · detectores de deriva */

const population: Population = { patterns: 100, days: 180, medianRate: 1.2, sigma: 1 };
const BUDGET = 1;
const detectors: { name: string; detector: Detector; range: [number, number] }[] = [
  { name: 'CUSUM (h = c·tabla)', detector: cusumDetector(table), range: [0.2, 5] },
  { name: 'EWMA (r = 0,2)', detector: ewmaDetector, range: [0.5, 20] },
  { name: 'SPRT de Poisson', detector: sprtDetector, range: [0.5, 40] },
  { name: 'estático piso 3', detector: staticDetector(3), range: [0.5, 20] },
];
const calibrated = detectors.map((d) => ({ ...d, parameter: calibrate(d.detector, BUDGET, population, d.range[0], d.range[1], 300) }));
calibrated.push({ name: 'estático del diseño (piso 10, 3×p95; sin calibrar)', detector: staticDetector(10), range: [3, 3], parameter: 3 });
const CHANGES: { label: string; change: Change }[] = [
  { label: 'escalón ×2', change: { kind: 'step', factor: 2 } },
  { label: 'escalón ×3', change: { kind: 'step', factor: 3 } },
  { label: 'rampa a ×3 en 21 días', change: { kind: 'ramp', factor: 3, overDays: 21 } },
  { label: 'ráfaga +10 cada 7 días', change: { kind: 'burst', size: 10, everyDays: 7 } },
  { label: 'bajo y lento (sustitución, tasa igual)', change: { kind: 'slow' } },
];
say(
  '## E6 · Detectores de deriva con presupuesto global de falsas alarmas',
  '',
  `Falsas alarmas: se miden **en total** sobre P = ${population.patterns} patrones sin cambio (tasas lognormales, mediana 1,2/día) y se reportan también **por patrón**. Cada detector calibra UN parámetro para ≤ ${BUDGET} falsa alarma/mes **en total** (corrección por pruebas múltiples: por patrón ≤ ${BUDGET / population.patterns}/mes). Calibración en semillas 300+; medición en semillas 900+ (independientes). Retardo en días y **en alertas** del patrón desde el cambio hasta la alarma; 400 repeticiones por escenario.`,
  '',
  SYNTH,
  '',
  '| Detector | Parámetro | Falsas alarmas/mes total · por patrón | ' + CHANGES.map((c) => `${c.label}: detecta % · alertas mediana (p90) · días`).join(' | ') + ' |',
  '|---|---:|---:|' + CHANGES.map(() => '---').join('|') + '|',
);
for (const d of calibrated) {
  const fa = falseAlarmsPerMonth(d.detector, d.parameter, population, 900, 20);
  const cells = CHANGES.map(({ change }) => {
    const r = delay(d.detector, d.parameter, change, population, 1300, 400);
    return `${fmt(100 * r.detectedShare, 0)} % · ${fmt(r.medianDelayAlerts, 0)} (${fmt(r.p90DelayAlerts, 0)}) · ${fmt(r.medianDelayDays, 0)}`;
  });
  say(`| ${d.name} | ${fmt(d.parameter, 2)} | ${fmt(fa, 2)} · ${fmt(fa / population.patterns, 3)} | ${cells.join(' | ')} |`);
}
say('');

/* ---------------------------------------------- E7 · piso de muestreo */

say(
  '## E7 · Piso semanal de revisiones por patrón frente a uniforme puro',
  '',
  `${SEEDS_GRID.length} semillas, política combinada, clave fija. Piso = si un patrón activo lleva < k revisiones en la semana a partir del día 3 de la semana, se revisan sus alertas hasta cumplirlo.`,
  '',
  SYNTH,
  '',
  '| Muestreo | Revisiones/corrida | Cobertura % | (a) mayor volumen: TP atacante | (b) menor volumen: TP atacante |',
  '|---|---:|---:|---:|---:|',
);
for (const [label, rate, floor] of [['uniforme 10 %', 0.1, 0], ['uniforme 10 % + piso 2/semana', 0.1, 2], ['uniforme 8 % + piso 2/semana', 0.08, 2]] as const) {
  const config = { ...POLICIES['combinada']!, samplingRate: rate, weeklyReviewFloor: floor };
  const top = runs(`E7|${label}|top`, config, SEEDS_GRID);
  const low = runs(`E7|${label}|low`, { ...config, attack: { ...ATTACK_TOP, kind: 'low' } }, SEEDS_GRID);
  say(`| ${label} | ${fmt(mean(top.map((r) => r.reviews)), 0)} | ${withCi(top.map((r) => 100 * r.coverage))} | ${withCi(top.map((r) => r.attackSuppressed))} | ${withCi(low.map((r) => r.attackSuppressed))} |`);
}
say('');

/* ---------------------------------------------- E8 · sensibilidad */

say(
  '## E8 · Sensibilidad (un factor a la vez desde los valores por defecto)',
  '',
  `${SEEDS_GRID.length} semillas por celda. Celda: cobertura % · TP suprimidos · TP del atacante (media). Δ = combinada − N=5 en TP suprimidos [IC 95 %].`,
  '',
  SYNTH,
  '',
  '| Factor | Valor | N=5 | Combinada | Δ TP suprimidos |',
  '|---|---|---|---|---:|',
);
const SENS: { factor: string; value: string; config: Partial<RunOptions> }[] = [
  ...[0.25, 1, 4].map((rate) => ({ factor: 'prevalencia del atacante (TP/día por patrón)', value: fmt(rate, 2), config: { attack: { ...ATTACK_TOP, rate } } })),
  ...[0.5, 1, 2].map((scale) => ({ factor: 'escala de θ_TP (tasa de TP entre alertas)', value: `×${fmt(scale, 1)}`, config: { world: { ...DEFAULT_WORLD, thetaScale: scale } } })),
  ...[0.5, 1, 1.5].map((sigma) => ({ factor: 'asimetría de volúmenes (σ lognormal)', value: fmt(sigma, 1), config: { world: { ...DEFAULT_WORLD, rateSigma: sigma } } })),
];
for (const s of SENS) {
  const n5 = runs(`E8|${s.factor}|${s.value}|N5`, { ...POLICIES['conteo N=5 (actual)']!, ...s.config }, SEEDS_GRID);
  const comb = runs(`E8|${s.factor}|${s.value}|comb`, { ...POLICIES['combinada']!, ...s.config }, SEEDS_GRID);
  const cell = (results: RunResult[]) => `${fmt(mean(results.map((r) => 100 * r.coverage)))} · ${fmt(mean(results.map((r) => r.tpSuppressed)))} · ${fmt(mean(results.map((r) => r.attackSuppressed)))}`;
  say(`| ${s.factor} | ${s.value} | ${cell(n5)} | ${cell(comb)} | ${pairedDiff(comb, n5, (r) => r.tpSuppressed)} |`);
}

say('', `Tiempo total: ${((Date.now() - started) / 1000).toFixed(0)} s.`);
writeFileSync(resolve(OUT, 'f3a-corridas.csv'), `${csv.join('\n')}\n`);
writeFileSync(resolve(import.meta.dirname, 'RESULTS-F3A.md'), `${lines.join('\n')}\n`);
process.stdout.write(`${lines.join('\n')}\n`);
