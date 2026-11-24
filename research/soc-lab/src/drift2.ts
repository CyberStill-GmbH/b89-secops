/**
 * F3a · punto 6 — detectores de deriva con PRESUPUESTO GLOBAL de falsas alarmas.
 *
 * P patrones con tasas diarias lognormales (como el simulador). Cada detector tiene UN parámetro
 * escalar que se calibra por bisección, en semillas de calibración, para que la suma de falsas
 * alarmas de los P patrones sin cambio no supere B al mes (corrección por pruebas múltiples: el
 * presupuesto es total, no por patrón). Después se mide, en semillas distintas, el retardo de
 * detección en DÍAS y en NÚMERO DE ALERTAS del patrón que cambia.
 *
 * Detectores: CUSUM de Poisson (h = c·h_tabla(λ₀)), EWMA de Poisson (límite λ₀ + L·σ_EWMA),
 * SPRT de Poisson con reinicio (Wald; umbral log A) y estático (x > max(piso, m·p95)).
 */

import { mulberry32, poisson, lognormalRate, type Rng } from './rng.js';
import { cusumStep, thresholdFor, type CusumTable } from './cusum-table.js';

export interface PatternSeries {
  readonly lambda0: number;
  readonly baseline: readonly number[];
  readonly counts: readonly number[];
}

export type DetectorName = 'CUSUM' | 'EWMA' | 'SPRT' | 'estático';

/** Detector con parámetro escalar; devuelve los días con alarma (reinicia tras cada una). */
export type Detector = (series: PatternSeries, parameter: number) => number[];

export function cusumDetector(table: CusumTable): Detector {
  return (series, c) => {
    const h = c * thresholdFor(table, series.lambda0);
    const alarms: number[] = [];
    let s = 0;
    series.counts.forEach((count, day) => {
      s = cusumStep(s, count, series.lambda0, table.ratio);
      if (s > h) {
        alarms.push(day);
        s = 0;
      }
    });
    return alarms;
  };
}

export const ewmaDetector: Detector = (series, L) => {
  const r = 0.2;
  const sigma = Math.sqrt((r / (2 - r)) * series.lambda0);
  const limit = series.lambda0 + L * sigma;
  const alarms: number[] = [];
  let z = series.lambda0;
  series.counts.forEach((count, day) => {
    z = (1 - r) * z + r * count;
    if (z > limit) {
      alarms.push(day);
      z = series.lambda0;
    }
  });
  return alarms;
};

/** SPRT de Wald H0: λ₀ vs H1: 2λ₀; acepta H0 (reinicia) en log B = −2, alarma en log A. */
export const sprtDetector: Detector = (series, logA) => {
  const alarms: number[] = [];
  let llr = 0;
  series.counts.forEach((count, day) => {
    llr += count * Math.log(2) - series.lambda0;
    if (llr >= logA) {
      alarms.push(day);
      llr = 0;
    } else if (llr <= -2) llr = 0;
  });
  return alarms;
};

export function staticDetector(floor: number): Detector {
  return (series, multiplier) => {
    const sorted = [...series.baseline].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(0.95 * (sorted.length - 1))] ?? 0;
    const limit = Math.max(floor, multiplier * p95);
    return series.counts.flatMap((count, day) => (count > limit ? [day] : []));
  };
}

export interface Population {
  readonly patterns: number;
  readonly days: number;
  readonly medianRate: number;
  readonly sigma: number;
}

export type Change =
  | { readonly kind: 'none' }
  | { readonly kind: 'step'; readonly factor: number }
  | { readonly kind: 'ramp'; readonly factor: number; readonly overDays: number }
  | { readonly kind: 'burst'; readonly size: number; readonly everyDays: number }
  | { readonly kind: 'slow' };

function makeSeries(rng: Rng, lambda0: number, days: number, change: Change, changeAt: number): PatternSeries {
  const baseline = Array.from({ length: 28 }, () => poisson(rng, lambda0));
  const counts = Array.from({ length: days }, (_, day) => {
    const after = day >= changeAt;
    let rate = lambda0;
    if (after && change.kind === 'step') rate = lambda0 * change.factor;
    if (after && change.kind === 'ramp') {
      rate = lambda0 * Math.min(change.factor, 1 + ((change.factor - 1) * (day - changeAt)) / change.overDays);
    }
    let count = poisson(rng, rate);
    if (after && change.kind === 'burst' && (day - changeAt) % change.everyDays === 0) count += change.size;
    // `slow`: el atacante sustituye alertas legítimas; la tasa total no cambia (ciego por diseño).
    return count;
  });
  return { lambda0, baseline, counts };
}

/** Falsas alarmas TOTALES por mes sobre P patrones sin cambio. */
export function falseAlarmsPerMonth(detector: Detector, parameter: number, population: Population, seed: number, reps: number): number {
  let alarms = 0;
  for (let rep = 0; rep < reps; rep += 1) {
    const rng = mulberry32(seed + rep * 7);
    for (let p = 0; p < population.patterns; p += 1) {
      const lambda0 = lognormalRate(rng, population.medianRate, population.sigma);
      alarms += detector(makeSeries(rng, lambda0, population.days, { kind: 'none' }, population.days), parameter).length;
    }
  }
  return (alarms / reps) * (30 / population.days);
}

/** Bisección del parámetro (las falsas alarmas decrecen con él) para ≤ budget al mes en total. */
export function calibrate(detector: Detector, budget: number, population: Population, low: number, high: number, seed: number, reps = 20): number {
  for (let i = 0; i < 22; i += 1) {
    const mid = (low + high) / 2;
    if (falseAlarmsPerMonth(detector, mid, population, seed, reps) > budget) low = mid;
    else high = mid;
  }
  return high;
}

export interface DelayResult {
  readonly detectedShare: number;
  readonly medianDelayDays: number;
  readonly medianDelayAlerts: number;
  readonly p90DelayAlerts: number;
}

const quantile = (values: number[], q: number) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length === 0 ? Number.NaN : sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
};

/** Retardo para UN patrón que cambia en `changeAt`; λ₀ muestreado como en la población. */
export function delay(detector: Detector, parameter: number, change: Change, population: Population, seed: number, reps: number): DelayResult {
  const changeAt = 90;
  const days: number[] = [];
  const alertsUntil: number[] = [];
  let detected = 0;
  for (let rep = 0; rep < reps; rep += 1) {
    const rng = mulberry32(seed + rep * 13);
    const lambda0 = lognormalRate(rng, population.medianRate, population.sigma);
    const series = makeSeries(rng, lambda0, population.days, change, changeAt);
    const first = detector(series, parameter).find((day) => day >= changeAt);
    if (first === undefined) continue;
    detected += 1;
    days.push(first - changeAt);
    alertsUntil.push(series.counts.slice(changeAt, first + 1).reduce((a, b) => a + b, 0));
  }
  return {
    detectedShare: detected / reps,
    medianDelayDays: quantile(days, 0.5),
    medianDelayAlerts: quantile(alertsUntil, 0.5),
    p90DelayAlerts: quantile(alertsUntil, 0.9),
  };
}
