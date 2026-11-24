/**
 * Calibración de CUSUM diario de Poisson (λ₁ = ratio·λ₀) con PRESUPUESTO GLOBAL de falsas alarmas.
 *
 * Si hay P patrones vigilados y se admiten B falsas alarmas al mes EN TOTAL, cada patrón debe
 * tener una longitud media de corrida sin cambio (ARL₀) de P·30/B días (corrección tipo
 * Bonferroni sobre el número de pruebas). El umbral h que logra ese ARL₀ depende de λ₀, así que
 * se precalcula una tabla h(λ₀) por Monte Carlo y se interpola en escala logarítmica.
 */

import { mulberry32, poisson } from './rng.js';

export const CUSUM_GRID = [0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50] as const;

export interface CusumTable {
  readonly ratio: number;
  readonly targetArlDays: number;
  readonly points: readonly { readonly lambda: number; readonly h: number }[];
}

/** Un paso de CUSUM de Poisson. */
export function cusumStep(s: number, count: number, lambda0: number, ratio: number): number {
  return Math.max(0, s + count * Math.log(ratio) - lambda0 * (ratio - 1));
}

function averageRunLength(lambda0: number, h: number, ratio: number, reps: number, cap: number, seed: number) {
  const rng = mulberry32(seed);
  let total = 0;
  for (let rep = 0; rep < reps; rep += 1) {
    let s = 0;
    let day = 0;
    while (day < cap) {
      day += 1;
      s = cusumStep(s, poisson(rng, lambda0), lambda0, ratio);
      if (s > h) break;
    }
    total += day;
  }
  return total / reps;
}

export function calibrateTable(targetArlDays: number, ratio = 2, reps = 60, seed = 4049): CusumTable {
  const points = CUSUM_GRID.map((lambda, index) => {
    let low = 0.5;
    let high = 40;
    for (let i = 0; i < 14; i += 1) {
      const mid = (low + high) / 2;
      const arl = averageRunLength(lambda, mid, ratio, reps, 4 * targetArlDays, seed + index * 101 + i);
      if (arl < targetArlDays) low = mid;
      else high = mid;
    }
    return { lambda, h: high };
  });
  return { ratio, targetArlDays, points };
}

/** h interpolado en log(λ₀); fuera de la rejilla, el extremo más cercano. */
export function thresholdFor(table: CusumTable, lambda0: number): number {
  const points = table.points;
  if (lambda0 <= points[0]!.lambda) return points[0]!.h;
  for (let i = 1; i < points.length; i += 1) {
    const right = points[i]!;
    if (lambda0 <= right.lambda) {
      const left = points[i - 1]!;
      const t = (Math.log(lambda0) - Math.log(left.lambda)) / (Math.log(right.lambda) - Math.log(left.lambda));
      return left.h + t * (right.h - left.h);
    }
  }
  return points.at(-1)!.h;
}
