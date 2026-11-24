/**
 * Aprendizaje SOC · etapa B — clave única de regla `fuente:rule_id`
 * (docs/soc-learning/01-diseno.md §4.1, decisión D8).
 *
 * El ID de una regla no basta: el mismo número puede venir de fuentes distintas (p. ej. el rango
 * de red 1018xx agrupa conexiones Linux, SSH, Docker y edge). La fuente sale del rango declarado
 * en `detections/catalog.yaml#id_ranges`, generado a `rule-sources.generated.ts`.
 */

import type { SecurityEvent } from '@b89/contracts';

import { RULE_SOURCE_RANGES } from './rule-sources.generated.js';

export interface RuleSourceRange {
  readonly from: number;
  readonly to: number;
  readonly source: string;
}

/**
 * Rangos de `detections/catalog.yaml#id_ranges` (única fuente de verdad), generados por
 * `scripts/soc-learning/generate-rule-sources.mjs`. Una spec falla si el generado se desalinea.
 */
export { RULE_SOURCE_RANGES };

/** IDs reservados a las reglas de serie del SIEM; el overlay B89 usa 100000 en adelante. */
const STOCK_RULE_MAXIMUM = 99_999;

function slug(value: string): string {
  const result = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-|-$/gu, '');
  return result.length > 0 ? result.slice(0, 64) : 'unknown';
}

function hopProduct(event: SecurityEvent, kind: 'origin' | 'collector'): string | undefined {
  return event.provenance.ingestionPath.find((hop) => hop.kind === kind)?.product;
}

/**
 * Los rangos del catálogo son del overlay B89 sobre el SIEM colector: aplican cuando la regla la
 * evaluó ese mismo SIEM (proveedor de la regla = producto del salto `collector`). El dominio no
 * nombra al proveedor (C-23); lo deduce del linaje del evento.
 */
function evaluatedByCollector(event: SecurityEvent, provider: string): boolean {
  const collector = hopProduct(event, 'collector') ?? event.source.product;
  return slug(collector) === slug(provider);
}

/**
 * `fuente:rule_id`, o `undefined` si el evento no trae regla. Determinista: depende solo del
 * evento y de la tabla de rangos.
 */
export function ruleKeyOf(event: SecurityEvent): string | undefined {
  const rule = event.detection?.rule;
  if (!rule) return undefined;
  const id = rule.id.trim();
  if (id.length === 0) return undefined;
  // Reglas que ya traen su espacio de nombres (p. ej. `b89-correlator:edge-to-ssh`).
  if (/^[a-z][a-z0-9-]*:/u.test(id)) return id;
  const provider = slug(rule.provider);
  if (!evaluatedByCollector(event, rule.provider)) return `${provider}:${id}`;
  const numeric = /^\d+$/u.test(id) ? Number(id) : Number.NaN;
  if (Number.isSafeInteger(numeric)) {
    const range = RULE_SOURCE_RANGES.find((entry) => numeric >= entry.from && numeric <= entry.to);
    if (range) return `${range.source}:${id}`;
    if (numeric <= STOCK_RULE_MAXIMUM) return `${provider}:${id}`;
  }
  // Regla de overlay fuera de los rangos declarados: se identifica por el proveedor de origen.
  const origin = hopProduct(event, 'origin');
  return `${origin ? slug(origin) : `${provider}-custom`}:${id}`;
}
