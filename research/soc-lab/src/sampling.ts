/**
 * Ficha 2 — muestreo de revisión con una función pseudoaleatoria con clave:
 * `u = HMAC-SHA256(clave, alertId)` → [0, 1). Reproducible para quien tiene la clave e
 * impredecible para quien no (no puede elegir alertas fuera de muestra). Y estimador de
 * Horvitz–Thompson (de razón) de la precisión de lo autocerrado.
 */

import { createHmac } from 'node:crypto';

export function keyedUniform(key: string, alertId: string): number {
  const digest = createHmac('sha256', key).update(alertId, 'utf8').digest();
  // 48 bits: resolución de 3,6e-15, de sobra para probabilidades de muestreo.
  return digest.readUIntBE(0, 6) / 2 ** 48;
}

export interface Reviewed {
  /** 1 si la revisión confirma FP (cierre correcto), 0 si es TP. */
  readonly y: 0 | 1;
  /** Probabilidad de inclusión con la que se muestreó. */
  readonly pi: number;
}

/** Estimador de razón de Horvitz–Thompson: Σ y/π ÷ Σ 1/π. */
export function horvitzThompsonRatio(sample: readonly Reviewed[]): number | null {
  let numerator = 0;
  let denominator = 0;
  for (const item of sample) {
    numerator += item.y / item.pi;
    denominator += 1 / item.pi;
  }
  return denominator === 0 ? null : numerator / denominator;
}
