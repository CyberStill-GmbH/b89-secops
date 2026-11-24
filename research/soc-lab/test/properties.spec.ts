/**
 * Pruebas basadas en propiedades del laboratorio (semillas fijas, 1000 repeticiones cuando aplica).
 * Comprueban los invariantes en los que se apoyan las fichas: cobertura de la cota
 * Clopper–Pearson, insesgadez de Horvitz–Thompson, muestreo con PRF y determinismo de la huella.
 */

import { describe, expect, it } from 'vitest';

import {
  computeFingerprint,
  differingComponents,
} from '../../../modules/detection/src/fingerprint.js';
import { eventFor, randomBehavior } from '../src/canary.js';
import { bernoulli, mulberry32 } from '../src/rng.js';
import { horvitzThompsonRatio, keyedUniform } from '../src/sampling.js';
import { clopperPearsonPolicy, countPolicy, run } from '../src/sim.js';
import { clopperPearsonLower } from '../src/stats.js';

describe('Clopper–Pearson: la cota inferior al 95 % cubre la precisión real', () => {
  it.each([
    [0.9, 30],
    [0.97, 100],
    [0.99, 100],
    [0.999, 300],
  ])('p = %f, n = %i: P(p < cota) ≤ 5 % en 1000 repeticiones', (p, n) => {
    const rng = mulberry32(11);
    let misses = 0;
    const reps = 1000;
    for (let rep = 0; rep < reps; rep += 1) {
      let successes = 0;
      for (let i = 0; i < n; i += 1) if (bernoulli(rng, p)) successes += 1;
      if (p < clopperPearsonLower(successes, n)) misses += 1;
    }
    // Método exacto y conservador: ≤ 5 % salvo error de Monte Carlo (σ ≈ 0,7 % con 1000).
    expect(misses / reps).toBeLessThanOrEqual(0.05 + 3 * Math.sqrt((0.05 * 0.95) / reps));
  });

  it('con n sin errores la cota vale exactamente 0,05^(1/n)', () => {
    for (const n of [5, 30, 99, 299]) {
      expect(clopperPearsonLower(n, n)).toBeCloseTo(0.05 ** (1 / n), 10);
    }
  });
});

describe('Horvitz–Thompson: estimador de razón sin sesgo apreciable con π desiguales', () => {
  it('error medio < 0,3 puntos sobre 1000 repeticiones', () => {
    const rng = mulberry32(23);
    const population = Array.from({ length: 2000 }, (_, index) => ({
      // Unidades con baja probabilidad de inclusión concentran los errores: el caso difícil.
      pi: index % 10 === 0 ? 0.02 : 0.2,
      y: index % 10 === 0 ? (bernoulli(rng, 0.7) ? 1 : 0) : bernoulli(rng, 0.99) ? 1 : 0,
    }));
    const truth = population.reduce((sum, unit) => sum + unit.y, 0) / population.length;
    let errorSum = 0;
    const reps = 1000;
    for (let rep = 0; rep < reps; rep += 1) {
      const sample = population
        .filter((unit) => bernoulli(rng, unit.pi))
        .map((unit) => ({ y: unit.y as 0 | 1, pi: unit.pi }));
      errorSum += (horvitzThompsonRatio(sample) ?? 0) - truth;
    }
    expect(Math.abs(errorSum / reps)).toBeLessThan(0.003);
  });
});

describe('Muestreo con PRF con clave', () => {
  it('es determinista, respeta la tasa y cambia con la clave', () => {
    const ids = Array.from({ length: 20_000 }, (_, index) => `alert-${index}`);
    const pick = (key: string) => ids.filter((id) => keyedUniform(key, id) < 0.1);
    const first = pick('clave-a');
    expect(pick('clave-a')).toEqual(first);
    // Binomial(20000, 0,1): σ ≈ 42.
    expect(Math.abs(first.length - 2000)).toBeLessThan(5 * 42);
    const other = new Set(pick('clave-b'));
    const overlap = first.filter((id) => other.has(id)).length;
    // Independientes: solapamiento ≈ 10 % de 2000 = 200.
    expect(Math.abs(overlap - 200)).toBeLessThan(5 * 14);
  });
});

describe('Simulador: números aleatorios comunes y reproducibilidad', () => {
  const base = {
    days: 60,
    missRate: 0.02,
    falseAlarmRate: 0.005,
    samplingKey: 'k',
    sampling: { kind: 'uniform', rate: 0.1 } as const,
  };
  it('misma semilla, mismo resultado; distintas políticas ven el mismo tráfico natural', () => {
    const a = run({ ...base, seed: 3, policy: countPolicy(5) });
    expect(run({ ...base, seed: 3, policy: countPolicy(5) })).toEqual(a);
    const b = run({ ...base, seed: 3, policy: clopperPearsonPolicy(0.97) });
    expect(b.alerts).toBe(a.alerts);
    expect(b.tpTotal).toBe(a.tpTotal);
  });
});

describe('Huella real del repo (solo lectura)', () => {
  it('determinista ante partes variables: 1000 pares del mismo comportamiento dan la misma huella', () => {
    const rng = mulberry32(5);
    const mismatches: string[] = [];
    for (let i = 0; i < 1000; i += 1) {
      const behavior = randomBehavior(rng);
      const left = computeFingerprint(eventFor(behavior, rng));
      const right = computeFingerprint(eventFor(behavior, rng));
      if (left.fingerprint !== right.fingerprint) {
        const diff = differingComponents(left.components, right.components);
        mismatches.push(
          `${diff.join(',')}: ${left.components.commandLine} ≠ ${right.components.commandLine}`,
        );
      }
    }
    // Invariante verdadero. FALLA hoy por un defecto de normalización (archivos temporales con
    // nombre solo de letras hex, p. ej. `tmpcbbf.ps1`, no se normalizan). Ver RESULTS.md.
    expect(mismatches.slice(0, 3), `${mismatches.length} de 1000 pares difieren`).toEqual([]);
  });

  it('un componente de comportamiento o sujeto distinto cambia la huella (1000 casos)', () => {
    const rng = mulberry32(9);
    const fields = ['sha256', 'domain', 'port', 'user', 'agentId', 'parent', 'script'] as const;
    for (let i = 0; i < 1000; i += 1) {
      const behavior = randomBehavior(rng);
      const field = fields[i % fields.length]!;
      const changed = {
        ...behavior,
        [field]:
          field === 'port'
            ? behavior.port === 443
              ? 8443
              : 443
            : field === 'parent'
              ? behavior.parent.endsWith('explorer.exe')
                ? 'C:\\Windows\\System32\\services.exe'
                : 'C:\\Windows\\explorer.exe'
              : `${String(behavior[field])}x`,
      };
      const left = computeFingerprint(eventFor(behavior, rng));
      const right = computeFingerprint(eventFor(changed, rng));
      expect(right.fingerprint, field).not.toBe(left.fingerprint);
    }
  });
});
