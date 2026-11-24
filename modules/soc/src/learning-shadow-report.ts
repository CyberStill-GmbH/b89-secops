/**
 * Aprendizaje SOC · fase 2 — informe automático de la sombra (diario y semanal).
 *
 * Por regla y por patrón: decisiones, cierres hipotéticos, concordancia con lo que hicieron las
 * personas, precisión con cota inferior Clopper–Pearson al 95 % (bilateral), TP que el motor habría
 * suprimido, cobertura que se ganaría, razones de escalada y patrones inseguros. Sin PII: solo
 * claves de regla, ids de patrón y conteos.
 *
 * Adjudicación de un cierre hipotético (la alerta que el motor habría cerrado):
 * - **acuerdo**: una persona la cerró como FP / benigna / duplicada (no `TP_REAL`);
 * - **TP suprimido**: una persona la cerró como `TP_REAL`, la escaló o la vinculó a un incidente;
 * - **pendiente**: sigue abierta, o la cerró una máquina (no cuenta como juicio humano).
 *
 * El gold set del diseño (§12) todavía no existe: el informe lo declara `NOT_AVAILABLE` en lugar
 * de suponerlo.
 */

/** Una decisión del período con el estado actual de su alerta. */
export interface ShadowRow {
  readonly ruleKey: string | null;
  readonly patternId: string | null;
  readonly mode: string;
  readonly proposedAction: string;
  readonly appliedAction: string;
  readonly escalateReason: string | null;
  readonly alertStatus: string;
  readonly closureOrigin: string | null;
  readonly closureReason: string | null;
  readonly verdict: string | null;
  readonly incidentLinked: boolean;
}

export interface ShadowStats {
  readonly decisions: number;
  readonly hypotheticalCloses: number;
  readonly adjudicated: number;
  readonly agreed: number;
  readonly truePositivesSuppressed: number;
  readonly pending: number;
  /** acuerdo / adjudicadas; `null` sin adjudicadas. */
  readonly precision: number | null;
  /** Cota inferior Clopper–Pearson 95 % bilateral; `null` sin adjudicadas. */
  readonly precisionLowerBound: number | null;
  /** Cierres hipotéticos / decisiones: carga que se quitaría a las personas. */
  readonly coverageGain: number | null;
  readonly escalations: Readonly<Record<string, number>>;
}

export interface ShadowReport {
  readonly from: string;
  readonly to: string;
  readonly threshold: { readonly precisionLowerBound: number; readonly minAdjudicated: number };
  readonly goldSet: 'NOT_AVAILABLE';
  readonly totals: ShadowStats;
  readonly byRule: readonly (ShadowStats & { readonly ruleKey: string })[];
  readonly byPattern: readonly (ShadowStats & {
    readonly patternId: string;
    readonly ruleKey: string | null;
  })[];
  /** Patrones con algún TP suprimido o con la cota inferior por debajo del umbral. */
  readonly unsafePatterns: readonly { readonly patternId: string; readonly reason: string }[];
}

/* ------------------------------------------------ Clopper–Pearson (exacto) */

function logGamma(x: number): number {
  // Lanczos (g = 7, n = 9): error relativo < 1e-13 en el rango que usamos.
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
    -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6,
    1.5056327351493116e-7,
  ];
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  const z = x - 1;
  let a = c[0]!;
  const t = z + 7.5;
  for (let index = 1; index < 9; index += 1) a += c[index]! / (z + index);
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(a);
}

/** Fracción continua de la beta incompleta (Lentz modificado). */
function betaContinuedFraction(a: number, b: number, x: number): number {
  const tiny = 1e-300;
  let c = 1;
  let d = 1 - ((a + b) * x) / (a + 1);
  if (Math.abs(d) < tiny) d = tiny;
  d = 1 / d;
  let h = d;
  for (let m = 1; m <= 300; m += 1) {
    const m2 = 2 * m;
    let aa = (m * (b - m) * x) / ((a + m2 - 1) * (a + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < tiny) d = tiny;
    c = 1 + aa / c;
    if (Math.abs(c) < tiny) c = tiny;
    d = 1 / d;
    h *= d * c;
    aa = (-(a + m) * (a + b + m) * x) / ((a + m2) * (a + m2 + 1));
    d = 1 + aa * d;
    if (Math.abs(d) < tiny) d = tiny;
    c = 1 + aa / c;
    if (Math.abs(c) < tiny) c = tiny;
    d = 1 / d;
    const delta = d * c;
    h *= delta;
    if (Math.abs(delta - 1) < 1e-14) break;
  }
  return h;
}

/** Beta incompleta regularizada I_x(a, b). */
export function regularizedBeta(x: number, a: number, b: number): number {
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const front = Math.exp(
    logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log(1 - x),
  );
  return x < (a + 1) / (a + b + 2)
    ? (front * betaContinuedFraction(a, b, x)) / a
    : 1 - (front * betaContinuedFraction(b, a, 1 - x)) / b;
}

/** Cota inferior Clopper–Pearson con confianza bilateral `1 − alpha`. */
export function clopperPearsonLower(successes: number, trials: number, alpha = 0.05): number {
  if (trials <= 0 || successes <= 0) return 0;
  // Cuantil alpha/2 de Beta(x, n − x + 1), por bisección.
  const target = alpha / 2;
  let low = 0;
  let high = 1;
  for (let iteration = 0; iteration < 80; iteration += 1) {
    const mid = (low + high) / 2;
    if (regularizedBeta(mid, successes, trials - successes + 1) < target) low = mid;
    else high = mid;
  }
  return (low + high) / 2;
}

/* ---------------------------------------------------------------- Informe */

const AGREE_VERDICTS = new Set(['false_positive', 'benign', 'duplicate']);

function stats(rows: readonly ShadowRow[]): ShadowStats {
  let hypothetical = 0;
  let agreed = 0;
  let suppressed = 0;
  let pending = 0;
  const escalations: Record<string, number> = {};
  for (const row of rows) {
    if (row.escalateReason)
      escalations[row.escalateReason] = (escalations[row.escalateReason] ?? 0) + 1;
    if (row.proposedAction !== 'AUTO_CLOSE' || row.appliedAction === 'AUTO_CLOSE') continue;
    hypothetical += 1;
    const humanTp =
      row.incidentLinked ||
      row.alertStatus === 'escalated' ||
      (row.closureOrigin === 'human' &&
        (row.closureReason === 'TP_REAL' || row.verdict === 'true_positive'));
    if (humanTp) suppressed += 1;
    else if (
      row.alertStatus === 'closed' &&
      row.closureOrigin === 'human' &&
      AGREE_VERDICTS.has(row.verdict ?? '')
    ) {
      agreed += 1;
    } else pending += 1;
  }
  const adjudicated = agreed + suppressed;
  return {
    decisions: rows.length,
    hypotheticalCloses: hypothetical,
    adjudicated,
    agreed,
    truePositivesSuppressed: suppressed,
    pending,
    precision: adjudicated === 0 ? null : agreed / adjudicated,
    precisionLowerBound: adjudicated === 0 ? null : clopperPearsonLower(agreed, adjudicated),
    coverageGain: rows.length === 0 ? null : hypothetical / rows.length,
    escalations,
  };
}

export function buildShadowReport(
  rows: readonly ShadowRow[],
  period: { readonly from: Date; readonly to: Date },
  threshold = { precisionLowerBound: 0.97, minAdjudicated: 30 },
): ShadowReport {
  const group = <K extends string>(key: (row: ShadowRow) => K | null) => {
    const groups = new Map<K, ShadowRow[]>();
    for (const row of rows) {
      const value = key(row);
      if (value === null) continue;
      groups.set(value, [...(groups.get(value) ?? []), row]);
    }
    return groups;
  };
  const byRule = [...group((row) => row.ruleKey)].map(([ruleKey, items]) => ({
    ruleKey,
    ...stats(items),
  }));
  const byPattern = [...group((row) => row.patternId)].map(([patternId, items]) => ({
    patternId,
    ruleKey: items[0]?.ruleKey ?? null,
    ...stats(items),
  }));
  const unsafePatterns = byPattern.flatMap((pattern) => {
    if (pattern.truePositivesSuppressed > 0) {
      return [
        {
          patternId: pattern.patternId,
          reason: `${pattern.truePositivesSuppressed} TP suprimido(s)`,
        },
      ];
    }
    if (
      pattern.adjudicated >= threshold.minAdjudicated &&
      pattern.precisionLowerBound !== null &&
      pattern.precisionLowerBound < threshold.precisionLowerBound
    ) {
      return [
        {
          patternId: pattern.patternId,
          reason: `cota inferior ${pattern.precisionLowerBound.toFixed(3)} < ${threshold.precisionLowerBound}`,
        },
      ];
    }
    return [];
  });
  const order = (left: { decisions: number }, right: { decisions: number }) =>
    right.decisions - left.decisions;
  return {
    from: period.from.toISOString(),
    to: period.to.toISOString(),
    threshold,
    goldSet: 'NOT_AVAILABLE',
    totals: stats(rows),
    byRule: byRule.sort(order),
    byPattern: byPattern.sort(order),
    unsafePatterns,
  };
}
