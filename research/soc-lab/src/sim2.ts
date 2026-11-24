/**
 * Simulador F3a (extiende `sim.ts` sin cambiarlo: los resultados de F2 siguen reproducibles).
 *
 * Añade: equipo de analistas con identidad (insiders y colusión), clases de impacto por regla,
 * siete atacantes, CUSUM por patrón con presupuesto global, piso Clopper–Pearson, defensas de
 * activación (humanos distintos, días distintos, aprobación de dos personas), topes de radio de
 * daño y piso semanal de revisiones.
 *
 * Todo es SINTÉTICO. Números aleatorios comunes: mundo, llegadas y ataque usan flujos propios y
 * las etiquetas salen de un hash por alerta, así que las políticas ven el mismo tráfico.
 */

import { beta as betaSample, bernoulli, lognormalRate, mulberry32, poisson, type Rng } from './rng.js';
import { betaCdf, clopperPearsonLower } from './stats.js';
import { keyedUniform } from './sampling.js';
import { cusumStep, thresholdFor, type CusumTable } from './cusum-table.js';

/* ------------------------------------------------------------------ Mundo */

export type RuleKind = 'clean' | 'low' | 'risky';

export interface WorldOptions {
  readonly rules: number;
  readonly meanPatternsPerRule: number;
  readonly medianRatePerDay: number;
  /** Dispersión lognormal de volúmenes (asimetría). */
  readonly rateSigma: number;
  /** Multiplica θ_TP de todos los patrones (sensibilidad a la tasa de TP entre las alertas). */
  readonly thetaScale: number;
  /** Fracción de reglas de alto impacto (táctica MITRE / tipo de regla). */
  readonly highImpactShare: number;
}

export const DEFAULT_WORLD: WorldOptions = {
  rules: 30,
  meanPatternsPerRule: 4,
  medianRatePerDay: 1.2,
  rateSigma: 1,
  thetaScale: 1,
  highImpactShare: 0.3,
};

/** Peso de un TP suprimido según el impacto de su regla. */
export const IMPACT_WEIGHT = { low: 1, high: 10 } as const;

export interface Pattern {
  readonly id: number;
  readonly rule: number;
  readonly lambda: number;
  readonly theta: number;
  readonly malicious: boolean;
  active: boolean;
  /** Pausa definitiva: una revisión encontró un TP. */
  paused: boolean;
  /** Pausa temporal por deriva (CUSUM) o rechazo de aprobación: hasta este día. */
  holdUntil: number;
  fp: number;
  tp: number;
  readonly fpAnalysts: Set<number>;
  readonly fpDays: Set<number>;
  /** Quién firmó las últimas 10 confirmaciones FP: la evidencia que se presenta al aprobar. */
  readonly recentClosers: number[];
  /** Últimas 50 alertas etiquetadas: verdad (para el aprobador que inspecciona evidencia). */
  readonly evidence: boolean[];
  /** Base para CUSUM: alertas y días vistos antes de activarse. */
  seenAlerts: number;
  seenDays: number;
  cusum: number;
  lambda0: number;
  reviewsThisWeek: number;
  consecutiveAuto: number;
}

export interface World {
  readonly patterns: Pattern[];
  readonly ruleKind: readonly RuleKind[];
  readonly ruleHighImpact: readonly boolean[];
}

function newPattern(id: number, rule: number, lambda: number, theta: number, malicious = false): Pattern {
  return {
    id,
    rule,
    lambda,
    theta,
    malicious,
    active: false,
    paused: false,
    holdUntil: -1,
    fp: 0,
    tp: 0,
    fpAnalysts: new Set(),
    fpDays: new Set(),
    recentClosers: [],
    evidence: [],
    seenAlerts: 0,
    seenDays: 0,
    cusum: 0,
    lambda0: 0,
    reviewsThisWeek: 0,
    consecutiveAuto: 0,
  };
}

export function makeWorld(rng: Rng, options: WorldOptions): World {
  const patterns: Pattern[] = [];
  const ruleKind: RuleKind[] = [];
  const ruleHighImpact: boolean[] = [];
  for (let rule = 0; rule < options.rules; rule += 1) {
    const u = rng.next();
    const kind: RuleKind = u < 0.7 ? 'clean' : u < 0.9 ? 'low' : 'risky';
    ruleKind.push(kind);
    ruleHighImpact.push(rng.next() < options.highImpactShare);
    const count = 1 + poisson(rng, options.meanPatternsPerRule - 1);
    for (let i = 0; i < count; i += 1) {
      const base =
        kind === 'clean'
          ? bernoulli(rng, 0.9)
            ? 0
            : betaSample(rng, 1, 999)
          : kind === 'low'
            ? betaSample(rng, 2, 398)
            : betaSample(rng, 2, 38);
      patterns.push(
        newPattern(
          patterns.length,
          rule,
          lognormalRate(rng, options.medianRatePerDay, options.rateSigma),
          Math.min(1, base * options.thetaScale),
        ),
      );
    }
  }
  return { patterns, ruleKind, ruleHighImpact };
}

/* ------------------------------------------------------------- Opciones */

export type PolicySpec =
  | { readonly kind: 'count'; readonly n: number }
  | { readonly kind: 'hier'; readonly q: number; readonly cpFloor?: number };

export interface Defenses {
  readonly minAnalysts: number;
  readonly minDays: number;
  readonly twoPerson: boolean;
  /**
   * Alcance de la separación de funciones del aprobador: `evidence` = distinto de quienes firmaron
   * la evidencia presentada (últimas 10 confirmaciones); `all` = distinto de TODOS los que alguna
   * vez cerraron alertas del patrón (texto literal del diseño §5.3).
   */
  readonly sodScope?: 'evidence' | 'all';
}

export const NO_DEFENSES: Defenses = { minAnalysts: 1, minDays: 1, twoPerson: false };

export type AttackKind = 'none' | 'top' | 'low' | 'slow' | 'burst' | 'budget' | 'switch' | 'insider';

export interface AttackSpec {
  readonly kind: AttackKind;
  readonly startDay: number;
  readonly days: number;
  readonly targets: number;
  /** TP inyectados por día y patrón (para `slow`: fracción sustituida). */
  readonly rate: number;
}

export interface RunOptions {
  readonly seed: number;
  readonly days: number;
  readonly world: WorldOptions;
  readonly policy: PolicySpec;
  readonly defenses: Defenses;
  readonly samplingRate: number;
  /** Mínimo de revisiones por patrón activo y semana (0 = uniforme puro). */
  readonly weeklyReviewFloor: number;
  readonly cusum?: CusumTable;
  /** Máximo de autocierres por patrón y día (∞ sin tope). */
  readonly capPerDay: number;
  /** Tras N autocierres seguidos sin revisión humana, la siguiente alerta se revisa (∞ = nunca). */
  readonly forcedReviewAfter: number;
  /** Autocierre solo en reglas de bajo impacto; en las de alto impacto solo agrupar/bajar prioridad. */
  readonly impactGate: boolean;
  readonly attack: AttackSpec;
  /** Envenenamiento: reglas riesgosas atacadas, fracción de sus cierres en manos de insiders y colusión. */
  readonly poison?: { readonly rules: number; readonly level: number; readonly colluders: number };
  /** Ataque `insider`: cuántos analistas coluden (1 = insider solo). */
  readonly insiderColluders: number;
  readonly analysts: number;
  readonly missRate: number;
  readonly falseAlarmRate: number;
  readonly samplingKey: string;
  /** Orden de las alertas dentro del día de cada patrón (ver bucle de alertas). */
  readonly arrivalOrder?: 'random' | 'attacker-first';
}

export interface RunResult {
  readonly alerts: number;
  readonly autoClosed: number;
  readonly coverage: number;
  readonly tpSuppressed: number;
  readonly tpSuppressedWeighted: number;
  readonly naturalTpSuppressed: number;
  readonly attackInjected: number;
  readonly attackSuppressed: number;
  readonly attackSuppressedWeighted: number;
  readonly reviews: number;
  readonly unsafeActive: number;
  readonly maliciousActivated: boolean;
  /** Pausas por deriva en patrones sin ataque (falsas alarmas de CUSUM). */
  readonly driftFalseAlarms: number;
  readonly poisonedRuleTpSuppressed: number;
}

function hashUniform(seed: number, id: string, purpose: string): number {
  let hash = 0x811c9dc5 ^ seed;
  const text = `${purpose}|${id}`;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return mulberry32(hash).next();
}

const cpCache = new Map<string, number>();
function cpLower(fp: number, n: number): number {
  const key = `${fp}|${n}`;
  let value = cpCache.get(key);
  if (value === undefined) {
    value = clopperPearsonLower(fp, n);
    cpCache.set(key, value);
  }
  return value;
}

function policyAllows(spec: PolicySpec, pattern: Pattern, rule: { fp: number; tp: number }): boolean {
  if (spec.kind === 'count') return pattern.fp >= spec.n && pattern.tp === 0;
  if (pattern.fp < 10) return false;
  const ruleN = rule.fp + rule.tp;
  const mean = (rule.tp + 1) / (ruleN + 100);
  const kappa = Math.min(50, ruleN + 100);
  const ok = betaCdf(1 - spec.q, mean * kappa + pattern.tp, (1 - mean) * kappa + pattern.fp) >= 0.95;
  if (!ok) return false;
  return spec.cpFloor === undefined || cpLower(pattern.fp, pattern.fp + pattern.tp) >= spec.cpFloor;
}

/* ------------------------------------------------------------- Corrida */

export function run(options: RunOptions): RunResult {
  const world = makeWorld(mulberry32(options.seed), options.world);
  const arrivals = mulberry32(options.seed * 7919 + 1);
  const attackRng = mulberry32(options.seed * 104729 + 3);
  const A = options.analysts;
  const riskyRules = world.ruleKind.map((kind, rule) => (kind === 'risky' ? rule : -1)).filter((r) => r >= 0);
  const poisonedRules = new Set(riskyRules.slice(0, options.poison?.rules ?? 0));
  const colluders = options.attack.kind === 'insider' ? options.insiderColluders : (options.poison?.colluders ?? 0);
  // Los colusores se reparten: los primeros `labelers` etiquetan (los que exige minAnalysts); el
  // resto queda libre para aprobar (la separación de funciones excluye a quien cerró la evidencia).
  const labelers = Math.min(colluders, Math.max(1, options.defenses.minAnalysts));
  const activatedIds = new Set<number>();

  // Ataque insider: un patrón malicioso (todo TP) cuyas alertas etiquetan los colusores.
  if (options.attack.kind === 'insider') {
    const rule = Math.floor(attackRng.next() * world.ruleKind.length);
    world.patterns.push(newPattern(world.patterns.length, rule, 1, 1, true));
  }

  let alerts = 0;
  let autoClosed = 0;
  let tpSuppressed = 0;
  let tpSuppressedWeighted = 0;
  let naturalTpSuppressed = 0;
  let attackInjected = 0;
  let attackSuppressed = 0;
  let attackSuppressedWeighted = 0;
  let reviews = 0;
  let driftFalseAlarms = 0;
  let poisonedRuleTpSuppressed = 0;
  const targets: Pattern[] = [];
  const injectedByTarget = new Map<number, number>();
  let switchQueue: Pattern[] = [];
  let switchCurrent: Pattern | undefined;

  const weight = (pattern: Pattern) =>
    world.ruleHighImpact[pattern.rule] ? IMPACT_WEIGHT.high : IMPACT_WEIGHT.low;

  for (let day = 0; day < options.days; day += 1) {
    if (day % 7 === 0) for (const pattern of world.patterns) pattern.reviewsThisWeek = 0;

    // Evidencia por regla (solo etiquetas humanas).
    const ruleEvidence = world.ruleKind.map(() => ({ fp: 0, tp: 0 }));
    for (const pattern of world.patterns) {
      ruleEvidence[pattern.rule]!.fp += pattern.fp;
      ruleEvidence[pattern.rule]!.tp += pattern.tp;
    }

    // Activación.
    for (const pattern of world.patterns) {
      if (pattern.active || pattern.paused || day < pattern.holdUntil) continue;
      if (options.impactGate && world.ruleHighImpact[pattern.rule]) continue;
      if (!policyAllows(options.policy, pattern, ruleEvidence[pattern.rule]!)) continue;
      if (pattern.fpAnalysts.size < options.defenses.minAnalysts) continue;
      if (pattern.fpDays.size < options.defenses.minDays) continue;
      if (options.defenses.twoPerson && !approve(pattern, day)) {
        pattern.holdUntil = day + 14;
        continue;
      }
      pattern.active = true;
      activatedIds.add(pattern.id);
      pattern.lambda0 = Math.max(0.05, pattern.seenAlerts / Math.max(1, pattern.seenDays));
      pattern.cusum = 0;
    }

    function approve(pattern: Pattern, onDay: number): boolean {
      const excluded =
        options.defenses.sodScope === 'all' ? pattern.fpAnalysts : new Set(pattern.recentClosers);
      const pool = Array.from({ length: A }, (_, i) => i).filter((i) => !excluded.has(i));
      if (pool.length < 2) return false;
      const pickA = Math.floor(hashUniform(options.seed, `${pattern.id}-${onDay}`, 'appr-a') * pool.length);
      let pickB = Math.floor(hashUniform(options.seed, `${pattern.id}-${onDay}`, 'appr-b') * (pool.length - 1));
      if (pickB >= pickA) pickB += 1;
      for (const approver of [pool[pickA]!, pool[pickB]!]) {
        if (approver < colluders) continue; // un colusor aprueba sin mirar
        // Revisor honesto: inspecciona 5 evidencias al azar; detecta un TP con 98 %.
        for (let k = 0; k < 5 && pattern.evidence.length > 0; k += 1) {
          const index = Math.floor(
            hashUniform(options.seed, `${pattern.id}-${onDay}-${approver}-${k}`, 'appr-ev') *
              pattern.evidence.length,
          );
          if (pattern.evidence[index] && hashUniform(options.seed, `${pattern.id}-${onDay}-${approver}-${k}`, 'appr-det') < 0.98) {
            return false;
          }
        }
      }
      return true;
    }

    const active = world.patterns.filter((pattern) => pattern.active);

    // Selección de objetivos del atacante.
    const attack = options.attack;
    const attacking = attack.kind !== 'none' && attack.kind !== 'insider' && day >= attack.startDay && day < attack.startDay + attack.days;
    if (attack.kind !== 'none' && attack.kind !== 'insider' && day === attack.startDay) {
      const byVolume = [...active].sort((left, right) => right.lambda - left.lambda);
      if (attack.kind === 'low') targets.push(...byVolume.slice(-attack.targets));
      else if (attack.kind === 'switch') {
        switchQueue = byVolume;
        switchCurrent = switchQueue.shift();
      } else targets.push(...byVolume.slice(0, attack.targets));
    }
    if (attack.kind === 'switch' && switchCurrent && !switchCurrent.active) {
      // El patrón actual se pausó (o dejó de estar activo): pasa al siguiente activo.
      while (switchQueue.length > 0 && !(switchCurrent = switchQueue.shift())!.active) {
        /* avanza */
      }
      if (switchCurrent && !switchCurrent.active) switchCurrent = undefined;
    }

    const autoToday = new Map<number, number>();
    const countToday = new Map<number, number>();

    for (const pattern of world.patterns) {
      const natural = pattern.malicious ? 0 : poisson(arrivals, pattern.lambda);
      const naturalTruth = Array.from({ length: natural }, () => bernoulli(arrivals, pattern.theta));
      let injected = 0;
      let substitute = 0;
      if (pattern.malicious) injected = poisson(attackRng, pattern.lambda);
      else if (attacking) {
        const isTarget = attack.kind === 'switch' ? pattern === switchCurrent : targets.includes(pattern);
        if (isTarget) {
          if (attack.kind === 'slow') substitute = attack.rate;
          else if (attack.kind === 'burst') injected = (day - attack.startDay) % 7 === 0 ? Math.round(attack.rate * 7) : 0;
          else if (attack.kind === 'budget') {
            const done = injectedByTarget.get(pattern.id) ?? 0;
            const budget = Math.max(0, Math.floor(Math.log(0.5) / Math.log(1 - options.samplingRate * 0.98)));
            injected = Math.min(poisson(attackRng, attack.rate), Math.max(0, budget - done));
          } else injected = poisson(attackRng, attack.rate * (attack.kind === 'switch' ? attack.targets : 1));
        }
      }
      if (pattern.malicious || attacking) {
        injectedByTarget.set(pattern.id, (injectedByTarget.get(pattern.id) ?? 0) + injected);
      }
      countToday.set(pattern.id, natural + injected);
      if (!pattern.active) {
        pattern.seenAlerts += natural + injected;
        pattern.seenDays += 1;
      }

      // Orden de llegada dentro del día. `random` (por defecto): permutación determinista por
      // (semilla, día, patrón). `attacker-first`: el atacante conoce el tope diario y entra
      // antes que el tráfico legítimo (peor caso para el tope). Corrige el sesgo de F3a v1, donde
      // las alertas inyectadas iban siempre al final y caían en el exceso del tope.
      const order = Array.from({ length: natural + injected }, (_, index) => index);
      if (options.arrivalOrder === 'attacker-first') {
        order.sort((left, right) => Number(right >= natural) - Number(left >= natural));
      } else {
        const shuffle = mulberry32(Math.floor(hashUniform(options.seed, `${day}-${pattern.id}`, 'order') * 2 ** 32));
        for (let k = order.length - 1; k > 0; k -= 1) {
          const j = Math.floor(shuffle.next() * (k + 1));
          [order[k], order[j]] = [order[j]!, order[k]!];
        }
      }
      for (const i of order) {
        const fromAttacker =
          i >= natural ||
          (substitute > 0 && hashUniform(options.seed, `s-${day}-${pattern.id}-${i}`, 'subst') < substitute);
        const truthTp = fromAttacker || (i < natural && naturalTruth[i]!);
        const alertId = `${i >= natural ? 'x' : 'n'}-${day}-${pattern.id}-${i}`;
        alerts += 1;
        if (fromAttacker) attackInjected += 1;

        const labelU = hashUniform(options.seed, alertId, 'label');
        const analystU = hashUniform(options.seed, alertId, 'analyst');
        // Quién etiqueta si la alerta va a una persona.
        const insiderHandles =
          (pattern.malicious && colluders > 0) ||
          (poisonedRules.has(pattern.rule) && hashUniform(options.seed, alertId, 'poison') < (options.poison?.level ?? 0));
        const analyst = insiderHandles
          ? Math.floor(analystU * Math.max(1, labelers))
          : colluders + Math.floor(analystU * (A - colluders));
        const humanLabelFp = insiderHandles
          ? true
          : truthTp
            ? labelU < options.missRate
            : labelU >= options.falseAlarmRate;

        const recordHuman = (labelFp: boolean, who: number) => {
          if (labelFp) {
            pattern.fp += 1;
            pattern.fpAnalysts.add(who);
            pattern.fpDays.add(day);
            pattern.recentClosers.push(who);
            if (pattern.recentClosers.length > 10) pattern.recentClosers.shift();
          } else pattern.tp += 1;
          pattern.evidence.push(truthTp);
          if (pattern.evidence.length > 50) pattern.evidence.shift();
        };

        const capped = (autoToday.get(pattern.id) ?? 0) >= options.capPerDay;
        if (pattern.active && !capped) {
          autoClosed += 1;
          autoToday.set(pattern.id, (autoToday.get(pattern.id) ?? 0) + 1);
          // Muestreo: PRF con clave; piso semanal; revisión forzada tras N seguidos.
          const floorBoost =
            options.weeklyReviewFloor > 0 && pattern.reviewsThisWeek < options.weeklyReviewFloor && day % 7 >= 3;
          const forced = pattern.consecutiveAuto >= options.forcedReviewAfter;
          const sampled = forced || floorBoost || keyedUniform(options.samplingKey, alertId) < options.samplingRate;
          let caught = false;
          if (sampled) {
            reviews += 1;
            pattern.reviewsThisWeek += 1;
            pattern.consecutiveAuto = 0;
            // La revisión la hace una persona honesta (rotación separada de quien cerró).
            const labelFp = truthTp ? labelU < options.missRate : labelU >= options.falseAlarmRate;
            recordHuman(labelFp, colluders + Math.floor(analystU * (A - colluders)));
            if (!labelFp) {
              caught = truthTp;
              pattern.active = false;
              pattern.paused = true;
            }
          } else pattern.consecutiveAuto += 1;
          if (truthTp && !caught) {
            const w = weight(pattern);
            tpSuppressed += 1;
            tpSuppressedWeighted += w;
            if (fromAttacker) {
              attackSuppressed += 1;
              attackSuppressedWeighted += w;
            } else naturalTpSuppressed += 1;
            if (poisonedRules.has(pattern.rule) && !fromAttacker) poisonedRuleTpSuppressed += 1;
          }
        } else {
          recordHuman(humanLabelFp, analyst);
        }
      }
    }

    // CUSUM diario por patrón activo (sobre todo lo que llegó, natural + inyectado).
    if (options.cusum) {
      for (const pattern of world.patterns) {
        if (!pattern.active) continue;
        const count = countToday.get(pattern.id) ?? 0;
        pattern.cusum = cusumStep(pattern.cusum, count, pattern.lambda0, options.cusum.ratio);
        if (pattern.cusum > thresholdFor(options.cusum, pattern.lambda0)) {
          const underAttack = (injectedByTarget.get(pattern.id) ?? 0) > 0 || attack.kind === 'slow' && targets.includes(pattern);
          if (!underAttack) driftFalseAlarms += 1;
          pattern.active = false;
          pattern.holdUntil = day + 7;
          pattern.cusum = 0;
        }
      }
    }
  }

  const malicious = world.patterns.find((pattern) => pattern.malicious);
  return {
    alerts,
    autoClosed,
    coverage: alerts === 0 ? 0 : autoClosed / alerts,
    tpSuppressed,
    tpSuppressedWeighted,
    naturalTpSuppressed,
    attackInjected,
    attackSuppressed,
    attackSuppressedWeighted,
    reviews,
    unsafeActive: world.patterns.filter((pattern) => pattern.active && pattern.theta > 0.03).length,
    maliciousActivated: malicious ? activatedIds.has(malicious.id) : false,
    driftFalseAlarms,
    poisonedRuleTpSuppressed,
  };
}
