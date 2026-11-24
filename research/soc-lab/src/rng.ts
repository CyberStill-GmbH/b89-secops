/**
 * Generador pseudoaleatorio con semilla (mulberry32) y distribuciones básicas. Todo el laboratorio
 * es reproducible: misma semilla, mismos números. No es criptográfico (para eso, HMAC en
 * `sampling.ts`).
 */

export interface Rng {
  next(): number;
}

export function mulberry32(seed: number): Rng {
  let state = seed >>> 0;
  return {
    next(): number {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    },
  };
}

export function bernoulli(rng: Rng, p: number): boolean {
  return rng.next() < p;
}

/** Poisson por inversión (λ pequeño) o aproximación normal redondeada (λ > 50). */
export function poisson(rng: Rng, lambda: number): number {
  if (lambda <= 0) return 0;
  if (lambda > 50) return Math.max(0, Math.round(lambda + Math.sqrt(lambda) * normal(rng)));
  const limit = Math.exp(-lambda);
  let k = 0;
  let product = rng.next();
  while (product > limit) {
    k += 1;
    product *= rng.next();
  }
  return k;
}

export function normal(rng: Rng): number {
  const u = Math.max(rng.next(), 1e-12);
  const v = rng.next();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/** Gamma(shape, 1) por Marsaglia–Tsang. */
export function gamma(rng: Rng, shape: number): number {
  if (shape < 1) return gamma(rng, shape + 1) * Math.pow(Math.max(rng.next(), 1e-12), 1 / shape);
  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (;;) {
    const x = normal(rng);
    const v = Math.pow(1 + c * x, 3);
    if (v <= 0) continue;
    const u = rng.next();
    if (Math.log(Math.max(u, 1e-300)) < 0.5 * x * x + d - d * v + d * Math.log(v)) return d * v;
  }
}

export function beta(rng: Rng, a: number, b: number): number {
  const x = gamma(rng, a);
  const y = gamma(rng, b);
  return x / (x + y);
}

export function pick<T>(rng: Rng, items: readonly T[]): T {
  return items[Math.floor(rng.next() * items.length)]!;
}

/** Tasa lognormal con mediana `median` y desviación `sigma` en escala logarítmica. */
export function lognormalRate(rng: Rng, median: number, sigma: number): number {
  return median * Math.exp(sigma * normal(rng));
}
