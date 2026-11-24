/**
 * Ficha 6 — deriva de la tasa de un patrón: CUSUM de Poisson frente al multiplicador estático del
 * diseño (§7.3: alarma si la hora supera max(piso, 3 × p95 del periodo base)).
 *
 * Comparación justa: el umbral h de CUSUM se calibra para tener la MISMA tasa de falsas alarmas
 * que el estático en series sin cambio; después se mide el retraso de detección en escalón y en
 * rampa, y las alarmas ante una ráfaga legítima corta.
 */

import { mulberry32, poisson, type Rng } from './rng.js';

export interface DriftScenario {
  readonly name: string;
  /** Tasa por hora en la hora t (t = 0 … horas − 1). El cambio empieza en `changeAt`. */
  rate(t: number): number;
  readonly changeAt: number | null;
}

/** Tasa base con ciclo diario (más volumen de día). */
export function diurnal(base: number): (t: number) => number {
  return (t) => base * (1 + 0.6 * Math.sin((2 * Math.PI * ((t % 24) - 6)) / 24));
}

export function scenarios(base: number, changeAt: number): DriftScenario[] {
  const d = diurnal(base);
  return [
    { name: 'sin cambio', rate: d, changeAt: null },
    { name: 'escalón ×2', rate: (t) => d(t) * (t >= changeAt ? 2 : 1), changeAt },
    { name: 'escalón ×3', rate: (t) => d(t) * (t >= changeAt ? 3 : 1), changeAt },
    {
      name: 'rampa a ×3 en 72 h',
      rate: (t) => d(t) * (t < changeAt ? 1 : Math.min(3, 1 + (2 * (t - changeAt)) / 72)),
      changeAt,
    },
    {
      name: 'ráfaga legítima ×5 durante 2 h',
      rate: (t) => d(t) * (t >= changeAt && t < changeAt + 2 ? 5 : 1),
      changeAt: null,
    },
  ];
}

export function series(rng: Rng, scenario: DriftScenario, hours: number): number[] {
  return Array.from({ length: hours }, (_, t) => poisson(rng, scenario.rate(t)));
}

/** Detector: devuelve las horas con alarma. Se reinicia tras cada alarma (CUSUM a 0). */
export type Detector = (counts: readonly number[], baselineRate: (t: number) => number) => number[];

export function staticDetector(
  baselineHours: readonly number[],
  floor = 10,
  multiplier = 3,
): Detector {
  const sorted = [...baselineHours].sort((a, b) => a - b);
  const p95 = sorted[Math.floor(0.95 * (sorted.length - 1))] ?? 0;
  const limit = Math.max(floor, multiplier * p95);
  return (counts) => counts.flatMap((count, t) => (count > limit ? [t] : []));
}

/**
 * CUSUM de Poisson para detectar λ₁ = ratio·λ₀(t) (λ₀ con estacionalidad conocida del periodo
 * de aprobación): S_t = max(0, S_{t−1} + x_t·ln(ratio) − λ₀(t)·(ratio − 1)).
 */
export function cusumDetector(h: number, ratio = 2): Detector {
  return (counts, baselineRate) => {
    const alarms: number[] = [];
    let s = 0;
    counts.forEach((count, t) => {
      const lambda0 = baselineRate(t);
      s = Math.max(0, s + count * Math.log(ratio) - lambda0 * (ratio - 1));
      if (s > h) {
        alarms.push(t);
        s = 0;
      }
    });
    return alarms;
  };
}

export interface DriftResult {
  readonly scenario: string;
  readonly detector: string;
  /** Mediana del retraso (h) hasta la primera alarma posterior al cambio; ∞ si no detecta. */
  readonly medianDelay: number;
  readonly detectedShare: number;
  /** Alarmas por serie-mes ANTES del cambio (o en toda la serie si no hay cambio). */
  readonly falseAlarmsPerMonth: number;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

export function evaluate(
  detectorName: string,
  make: (baselineHours: readonly number[]) => Detector,
  scenario: DriftScenario,
  options: { base: number; hours: number; reps: number; seed: number },
): DriftResult {
  const delays: number[] = [];
  let falseAlarms = 0;
  let falseWindowHours = 0;
  for (let rep = 0; rep < options.reps; rep += 1) {
    const rng = mulberry32(options.seed + rep * 31);
    // Periodo de aprobación: 14 días sin cambio, para p95 y λ₀ por franja.
    const baselineHours = series(
      rng,
      { name: 'base', rate: diurnal(options.base), changeAt: null },
      14 * 24,
    );
    const counts = series(rng, scenario, options.hours);
    const alarms = make(baselineHours)(counts, diurnal(options.base));
    const changeAt = scenario.changeAt;
    const before = changeAt === null ? alarms : alarms.filter((t) => t < changeAt);
    falseAlarms += before.length;
    falseWindowHours += changeAt === null ? options.hours : changeAt;
    if (changeAt !== null) {
      const first = alarms.find((t) => t >= changeAt);
      delays.push(first === undefined ? Number.POSITIVE_INFINITY : first - changeAt);
    }
  }
  const detected = delays.filter(Number.isFinite);
  return {
    scenario: scenario.name,
    detector: detectorName,
    medianDelay: delays.length === 0 ? Number.NaN : median(delays),
    detectedShare: delays.length === 0 ? Number.NaN : detected.length / delays.length,
    falseAlarmsPerMonth: falseWindowHours === 0 ? 0 : (falseAlarms / falseWindowHours) * 24 * 30,
  };
}

/**
 * Calibra h para que la tasa de falsas alarmas de CUSUM en series sin cambio sea ≤ la objetivo
 * (por bisección sobre h; la tasa decrece con h).
 */
export function calibrateCusum(
  targetPerMonth: number,
  options: { base: number; hours: number; reps: number; seed: number; ratio?: number },
): number {
  const noChange = scenarios(options.base, 0)[0]!;
  let low = 0.5;
  let high = 40;
  for (let i = 0; i < 30; i += 1) {
    const mid = (low + high) / 2;
    const result = evaluate('cusum', () => cusumDetector(mid, options.ratio), noChange, options);
    if (result.falseAlarmsPerMonth > targetPerMonth) low = mid;
    else high = mid;
  }
  return high;
}
