/**
 * Simulador del SOC que aprende (fichas 1, 2 y 3 de docs/soc-learning/20-innovacion-tecnica.md).
 *
 * Mundo: reglas con «calidad» heterogénea; cada regla tiene varios patrones (huellas exactas) con
 * tasa verdadera de TP θ. Cada día llegan alertas Poisson por patrón. Lo que no se autocierra lo
 * etiqueta una persona con error; esas etiquetas son la única evidencia (los autocierres no
 * cuentan, como en la etapa A). Una política decide cada día qué patrones activa. Lo autocerrado
 * se muestrea para revisión; una revisión que encuentra un TP pausa el patrón.
 *
 * Atacante mimético: desde `attack.startDay` copia EXACTAMENTE la huella de los patrones activos
 * de más volumen (el peor caso: la huella no lo distingue) e inyecta TP durante `attack.days`.
 *
 * Envenenamiento (opcional): una cuenta de analista comprometida etiqueta FP todo lo que revisa
 * en una regla riesgosa durante `poison.days` días.
 */

import {
  beta as betaSample,
  bernoulli,
  lognormalRate,
  mulberry32,
  poisson,
  type Rng,
} from './rng.js';
import { betaCdf, clopperPearsonLower } from './stats.js';
import { keyedUniform } from './sampling.js';

export type RuleKind = 'clean' | 'low' | 'risky';

export interface Pattern {
  readonly id: number;
  readonly rule: number;
  readonly lambda: number;
  readonly theta: number;
  active: boolean;
  paused: boolean;
  /** Etiquetas humanas: FP (éxito) y TP. */
  fp: number;
  tp: number;
}

export interface World {
  readonly patterns: Pattern[];
  readonly ruleKind: readonly RuleKind[];
}

export interface WorldOptions {
  readonly rules: number;
  readonly meanPatternsPerRule: number;
  readonly medianRatePerDay: number;
}

export const DEFAULT_WORLD: WorldOptions = {
  rules: 30,
  meanPatternsPerRule: 4,
  medianRatePerDay: 1.2,
};

export function makeWorld(rng: Rng, options: WorldOptions = DEFAULT_WORLD): World {
  const patterns: Pattern[] = [];
  const ruleKind: RuleKind[] = [];
  for (let rule = 0; rule < options.rules; rule += 1) {
    const u = rng.next();
    const kind: RuleKind = u < 0.7 ? 'clean' : u < 0.9 ? 'low' : 'risky';
    ruleKind.push(kind);
    const count = 1 + poisson(rng, options.meanPatternsPerRule - 1);
    for (let i = 0; i < count; i += 1) {
      const theta =
        kind === 'clean'
          ? bernoulli(rng, 0.9)
            ? 0
            : betaSample(rng, 1, 999)
          : kind === 'low'
            ? betaSample(rng, 2, 398)
            : betaSample(rng, 2, 38);
      patterns.push({
        id: patterns.length,
        rule,
        lambda: lognormalRate(rng, options.medianRatePerDay, 1),
        theta,
        active: false,
        paused: false,
        fp: 0,
        tp: 0,
      });
    }
  }
  return { patterns, ruleKind };
}

/* ------------------------------------------------------------- Políticas */

export interface RuleEvidence {
  readonly fp: number;
  readonly tp: number;
}

export interface ActivationPolicy {
  readonly name: string;
  activate(pattern: Pattern, rule: RuleEvidence): boolean;
}

/** Línea base (estado actual): ≥ N etiquetas FP humanas y ninguna TP. */
export function countPolicy(minFp: number): ActivationPolicy {
  return {
    name: `conteo N=${minFp}`,
    activate: (pattern) => pattern.fp >= minFp && pattern.tp === 0,
  };
}

/** Ficha 1: cota inferior Clopper–Pearson de la precisión ≥ q (α = 0,05). */
export function clopperPearsonPolicy(q: number, alpha = 0.05): ActivationPolicy {
  return {
    name: `CP q=${q}`,
    activate: (pattern) => clopperPearsonLower(pattern.fp, pattern.fp + pattern.tp, alpha) >= q,
  };
}

/**
 * Ficha 3: Beta-Binomial jerárquico. Prior de la regla = evidencia de sus patrones encogida hacia
 * un prior global pesimista (1 % de TP); fuerza del prior acotada (κ ≤ kappaMax) y piso de
 * confirmaciones propias (`minOwn`) para que el prior nunca reemplace la evidencia del patrón.
 */
export function hierarchicalPolicy(
  q: number,
  options: { kappaMax?: number; minOwn?: number; confidence?: number } = {},
): ActivationPolicy {
  const kappaMax = options.kappaMax ?? 50;
  const minOwn = options.minOwn ?? 10;
  const confidence = options.confidence ?? 0.95;
  const globalA = 1;
  const globalB = 99;
  return {
    name: `jerárquica q=${q}`,
    activate: (pattern, rule) => {
      if (pattern.fp < minOwn) return false;
      const ruleN = rule.fp + rule.tp;
      const mean = (rule.tp + globalA) / (ruleN + globalA + globalB);
      const kappa = Math.min(kappaMax, ruleN + globalA + globalB);
      const a = mean * kappa + pattern.tp;
      const b = (1 - mean) * kappa + pattern.fp;
      // P(θ_TP ≤ 1 − q | datos) ≥ confidence
      return betaCdf(1 - q, a, b) >= confidence;
    },
  };
}

/* ------------------------------------------------------------- Muestreo */

export type SamplingStrategy =
  | { readonly kind: 'none' }
  | { readonly kind: 'uniform'; readonly rate: number }
  | { readonly kind: 'adaptive'; readonly rate: number; readonly floor: number };

/** Desviación típica de la posterior Beta(1 + tp, 1 + fp) de θ_TP. */
function posteriorSd(pattern: Pattern): number {
  const a = 1 + pattern.tp;
  const b = 1 + pattern.fp;
  return Math.sqrt((a * b) / ((a + b) ** 2 * (a + b + 1)));
}

/**
 * Probabilidad de revisión por patrón activo. `adaptive` reparte el MISMO presupuesto esperado
 * que `uniform` (Σ π·λ = rate·Σ λ) en proporción a la incertidumbre, con un piso por patrón.
 */
export function samplingProbabilities(
  active: readonly Pattern[],
  strategy: SamplingStrategy,
): Map<number, number> {
  const result = new Map<number, number>();
  if (strategy.kind === 'none') {
    for (const pattern of active) result.set(pattern.id, 0);
    return result;
  }
  if (strategy.kind === 'uniform') {
    for (const pattern of active) result.set(pattern.id, strategy.rate);
    return result;
  }
  const budget = strategy.rate * active.reduce((sum, pattern) => sum + pattern.lambda, 0);
  const weights = active.map((pattern) => posteriorSd(pattern));
  const spend = (c: number) =>
    active.reduce(
      (sum, pattern, index) =>
        sum + Math.min(1, Math.max(strategy.floor, c * weights[index]!)) * pattern.lambda,
      0,
    );
  let low = 0;
  let high = 1e6;
  for (let i = 0; i < 80; i += 1) {
    const mid = (low + high) / 2;
    if (spend(mid) < budget) low = mid;
    else high = mid;
  }
  active.forEach((pattern, index) =>
    result.set(pattern.id, Math.min(1, Math.max(strategy.floor, high * weights[index]!))),
  );
  return result;
}

/* ------------------------------------------------------------- Corrida */

export interface RunOptions {
  readonly seed: number;
  readonly days: number;
  readonly policy: ActivationPolicy;
  readonly sampling: SamplingStrategy;
  readonly world?: WorldOptions;
  /** Analista: P(etiquetar FP | TP real) y P(etiquetar TP | FP real). */
  readonly missRate: number;
  readonly falseAlarmRate: number;
  readonly attack?: {
    readonly startDay: number;
    readonly days: number;
    readonly targets: number;
    readonly ratePerDay: number;
  };
  readonly poison?: { readonly days: number; readonly share: number };
  /** Clave de la PRF de muestreo (en producción, secreto del gestor de secretos). */
  readonly samplingKey: string;
}

export interface RunResult {
  readonly alerts: number;
  readonly autoClosed: number;
  readonly coverage: number;
  readonly tpTotal: number;
  readonly tpSuppressed: number;
  readonly tpSuppressedPer10k: number;
  readonly attackAlerts: number;
  readonly attackSuppressed: number;
  readonly attackTargets: number;
  /** Días desde el inicio del ataque hasta pausar cada patrón atacado (∞ si nunca). */
  readonly attackDaysToPause: readonly number[];
  readonly reviews: number;
  /** Precisión real de lo autocerrado y estimación Horvitz–Thompson desde las revisiones. */
  readonly truePrecision: number;
  readonly htPrecision: number | null;
  readonly activePatternsUnsafe: number;
}

function ruleEvidence(world: World): RuleEvidence[] {
  const totals = world.ruleKind.map(() => ({ fp: 0, tp: 0 }));
  for (const pattern of world.patterns) {
    totals[pattern.rule]!.fp += pattern.fp;
    totals[pattern.rule]!.tp += pattern.tp;
  }
  return totals;
}

/**
 * Uniforme determinista por alerta y propósito: misma alerta, misma etiqueta humana en todas las
 * políticas (números aleatorios comunes). Hash FNV-1a → mulberry32; no criptográfico a propósito.
 */
function alertUniform(seed: number, alertId: string, purpose: string): number {
  let hash = 0x811c9dc5 ^ seed;
  const text = `${purpose}|${alertId}`;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return mulberry32(hash).next();
}

export function run(options: RunOptions): RunResult {
  // Flujos separados: mundo, llegadas naturales y ataque no dependen de lo que decida la política.
  const world = makeWorld(mulberry32(options.seed), options.world);
  const arrivals = mulberry32(options.seed * 7919 + 1);
  const attackRng = mulberry32(options.seed * 104729 + 3);
  const poisonRule = world.ruleKind.indexOf('risky');
  let alerts = 0;
  let autoClosed = 0;
  let tpTotal = 0;
  let tpSuppressed = 0;
  let attackAlerts = 0;
  let attackSuppressed = 0;
  let reviews = 0;
  let autoClosedTrueFp = 0;
  let htNumerator = 0;
  let htDenominator = 0;
  const attackTargets: Pattern[] = [];
  const pausedOn = new Map<number, number>();

  for (let day = 0; day < options.days; day += 1) {
    const evidence = ruleEvidence(world);
    for (const pattern of world.patterns) {
      if (
        !pattern.active &&
        !pattern.paused &&
        options.policy.activate(pattern, evidence[pattern.rule]!)
      ) {
        pattern.active = true;
      }
    }
    const active = world.patterns.filter((pattern) => pattern.active);
    const pi = samplingProbabilities(active, options.sampling);

    if (options.attack && day === options.attack.startDay) {
      attackTargets.push(
        ...[...active]
          .sort((left, right) => right.lambda - left.lambda)
          .slice(0, options.attack.targets),
      );
    }
    const attacking =
      options.attack !== undefined &&
      day >= options.attack.startDay &&
      day < options.attack.startDay + options.attack.days;

    for (const pattern of world.patterns) {
      const natural = poisson(arrivals, pattern.lambda);
      const naturalTruth = Array.from({ length: natural }, () =>
        bernoulli(arrivals, pattern.theta),
      );
      const injected =
        attacking && attackTargets.includes(pattern)
          ? poisson(attackRng, options.attack!.ratePerDay)
          : 0;
      for (let i = 0; i < natural + injected; i += 1) {
        const fromAttacker = i >= natural;
        const truthTp = fromAttacker || naturalTruth[i]!;
        const alertId = `${fromAttacker ? 'x' : 'n'}-${day}-${pattern.id}-${i}`;
        alerts += 1;
        if (truthTp) tpTotal += 1;
        if (fromAttacker) attackAlerts += 1;

        const poisoned =
          options.poison !== undefined &&
          pattern.rule === poisonRule &&
          day < options.poison.days &&
          alertUniform(options.seed, alertId, 'poison') < options.poison.share;
        const labelU = alertUniform(options.seed, alertId, 'label');
        const humanLabelFp = () =>
          poisoned ? true : truthTp ? labelU < options.missRate : labelU >= options.falseAlarmRate;

        if (pattern.active) {
          autoClosed += 1;
          if (!truthTp) autoClosedTrueFp += 1;
          const probability = pi.get(pattern.id) ?? 0;
          const sampled =
            probability > 0 && keyedUniform(options.samplingKey, alertId) < probability;
          let caught = false;
          if (sampled) {
            reviews += 1;
            const labelFp = humanLabelFp();
            htNumerator += (labelFp ? 1 : 0) / probability;
            htDenominator += 1 / probability;
            if (labelFp) pattern.fp += 1;
            else {
              pattern.tp += 1;
              caught = truthTp;
              // Una revisión que encuentra un TP pausa el patrón (vuelve a personas).
              pattern.active = false;
              pattern.paused = true;
              if (!pausedOn.has(pattern.id)) pausedOn.set(pattern.id, day);
            }
          }
          if (truthTp && !caught) {
            tpSuppressed += 1;
            if (fromAttacker) attackSuppressed += 1;
          }
        } else if (humanLabelFp()) pattern.fp += 1;
        else pattern.tp += 1;
      }
    }
  }

  const start = options.attack?.startDay ?? 0;
  return {
    alerts,
    autoClosed,
    coverage: alerts === 0 ? 0 : autoClosed / alerts,
    tpTotal,
    tpSuppressed,
    tpSuppressedPer10k: autoClosed === 0 ? 0 : (10_000 * tpSuppressed) / autoClosed,
    attackAlerts,
    attackSuppressed,
    attackTargets: attackTargets.length,
    attackDaysToPause: attackTargets.map((pattern) =>
      pausedOn.has(pattern.id) && pausedOn.get(pattern.id)! >= start
        ? pausedOn.get(pattern.id)! - start
        : Number.POSITIVE_INFINITY,
    ),
    reviews,
    truePrecision: autoClosed === 0 ? 1 : autoClosedTrueFp / autoClosed,
    htPrecision: htDenominator === 0 ? null : htNumerator / htDenominator,
    activePatternsUnsafe: world.patterns.filter((pattern) => pattern.active && pattern.theta > 0.03)
      .length,
  };
}
