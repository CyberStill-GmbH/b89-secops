/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { InvestigationEventSummary } from '../../common';
import { ENTITY_KIND_LABEL, EntityKind, VENDORS } from '../../common';

/** Eventos de una misma entidad cercanos en el tiempo (ayuda de lectura, no prueba de causa). */
export interface InvestigationActivityGroup {
  readonly entity: string;
  readonly firstAt: string;
  readonly lastAt: string;
  readonly events: readonly InvestigationEventSummary[];
}

export const DEFAULT_ACTIVITY_GAP_MS = 15 * 60 * 1000;
/** Nombre único de la vista agrupada en la UI, el CSV y el Excel. */
export const ACTIVITY_GROUPS_LABEL = 'Actividad agrupada';
export const INVESTIGATION_ACTIVITY_CSV_HEADER = Object.freeze([
  'Tipo',
  'Entidad coincidente',
  'Desde (UTC)',
  'Hasta (UTC)',
  'Eventos',
  'Fuentes',
  'Reglas',
  'IDs de eventos',
]);

/**
 * Group summaries that share a matched entity and are at most `gapMs` apart.
 * An event matching multiple queried entities appears in each matching entity group.
 */
export function groupInvestigationActivity(
  events: readonly InvestigationEventSummary[],
  gapMs = DEFAULT_ACTIVITY_GAP_MS,
): InvestigationActivityGroup[] {
  const allowedGap = Number.isFinite(gapMs) && gapMs > 0 ? gapMs : DEFAULT_ACTIVITY_GAP_MS;
  const byEntity = new Map<string, InvestigationEventSummary[]>();
  for (const event of events) {
    const timestamp = Date.parse(event.at);
    if (!Number.isFinite(timestamp)) continue;
    for (const entity of new Set(event.matched)) {
      const list = byEntity.get(entity) ?? [];
      list.push(event);
      byEntity.set(entity, list);
    }
  }

  const groups: InvestigationActivityGroup[] = [];
  for (const [entity, items] of byEntity) {
    const ordered = [...items].sort((left, right) => Date.parse(left.at) - Date.parse(right.at));
    let bucket: InvestigationEventSummary[] = [];
    const flush = () => {
      if (bucket.length === 0) return;
      groups.push({
        entity,
        firstAt: bucket[0]!.at,
        lastAt: bucket[bucket.length - 1]!.at,
        events: bucket,
      });
      bucket = [];
    };
    for (const event of ordered) {
      const previous = bucket[bucket.length - 1];
      if (previous && Date.parse(event.at) - Date.parse(previous.at) > allowedGap) flush();
      bucket.push(event);
    }
    flush();
  }
  return groups.sort((left, right) => Date.parse(right.lastAt) - Date.parse(left.lastAt));
}

/** Spreadsheet rows that can be appended to the investigation CSV export. */
export function investigationActivityCsvRows(
  groups: readonly InvestigationActivityGroup[],
): readonly (readonly string[])[] {
  return groups.map((group) => [
    ACTIVITY_GROUPS_LABEL,
    group.entity,
    group.firstAt,
    group.lastAt,
    String(group.events.length),
    [...new Set(group.events.map((event) => VENDORS[event.vendor]?.name ?? event.vendor))]
      .sort()
      .join(' | '),
    [...new Set(group.events.map((event) => event.ruleId))].sort().join(' | '),
    group.events.map((event) => event.id).join(' | '),
  ]);
}

// ------------------------------------------------------------------ Lectura de la línea de tiempo

export type TimelineOrder = 'asc' | 'desc';

/** «Usuario admin» a partir de la clave `user:admin` (sin perder el tipo de entidad). */
export function entityKeyLabel(key: string): string {
  const split = key.indexOf(':');
  if (split < 0) return key;
  const kind = key.slice(0, split) as EntityKind;
  const value = key.slice(split + 1);
  const label = ENTITY_KIND_LABEL[kind];
  return label ? `${label} ${value}` : value;
}

const CLOCK = new Intl.DateTimeFormat('es-PE', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});
const DAY = new Intl.DateTimeFormat('es-PE', { weekday: 'short', day: 'numeric', month: 'short' });
const DAY_KEY = new Intl.DateTimeFormat('en-CA', { year: 'numeric', month: '2-digit', day: '2-digit' });
const SHORT = new Intl.DateTimeFormat('es-PE', {
  day: 'numeric',
  month: 'short',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
});

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function cleanDate(text: string): string {
  // Intl añade puntos de abreviatura («sáb.», «nov.»): se quitan para una lectura limpia.
  return text.replace(/\./gu, '').replace(/,/gu, '').replace(/\s+/gu, ' ').trim();
}

/** Hora local «14:32:05». */
export function formatClock(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : CLOCK.format(date);
}

/** Separador de día «Sáb 21 nov». */
export function formatDay(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : capitalize(cleanDate(DAY.format(date)));
}

/** Fecha y hora breve «21 nov 14:35» para la cabecera. */
export function formatShortDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : cleanDate(SHORT.format(date));
}

function dayKey(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '' : DAY_KEY.format(date);
}

/** Distancia al momento de la alerta: «−3 min», «+12 min», «+2 h 5 min», «−1 d 3 h», «+40 s». */
export function formatOffset(iso: string, anchorIso: string): string {
  const delta = Date.parse(iso) - Date.parse(anchorIso);
  if (!Number.isFinite(delta)) return '';
  const sign = delta < 0 ? '−' : '+';
  const seconds = Math.round(Math.abs(delta) / 1000);
  if (seconds === 0) return 'mismo instante';
  if (seconds < 60) return `${sign}${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${sign}${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    const rest = minutes % 60;
    return rest ? `${sign}${hours} h ${rest} min` : `${sign}${hours} h`;
  }
  const days = Math.floor(hours / 24);
  const restHours = hours % 24;
  return restHours ? `${sign}${days} d ${restHours} h` : `${sign}${days} d`;
}

export type TimelineEntry =
  | { readonly type: 'day'; readonly key: string; readonly label: string }
  | { readonly type: 'anchor'; readonly key: string; readonly at: string }
  | { readonly type: 'event'; readonly key: string; readonly event: InvestigationEventSummary };

/**
 * Filas de la línea de tiempo en el orden elegido, con un separador cada vez que cambia el día
 * y la marca «Momento de la alerta» en su sitio. Si faltan páginas por cargar y el momento de la
 * alerta cae fuera de lo cargado, la marca no se dibuja (aún no se sabe qué hay en medio).
 */
export function buildTimelineEntries(
  events: readonly InvestigationEventSummary[],
  anchorIso: string,
  order: TimelineOrder,
  complete: boolean,
): TimelineEntry[] {
  const anchorMs = Date.parse(anchorIso);
  const sorted = [...events].sort((left, right) =>
    order === 'asc'
      ? Date.parse(left.at) - Date.parse(right.at)
      : Date.parse(right.at) - Date.parse(left.at),
  );
  type Item =
    | { kind: 'anchor'; at: string }
    | { kind: 'event'; at: string; event: InvestigationEventSummary };
  const items: Item[] = sorted.map((event) => ({ kind: 'event', at: event.at, event }));
  if (Number.isFinite(anchorMs)) {
    const oldestLoaded = sorted.length
      ? Math.min(...sorted.map((event) => Date.parse(event.at)))
      : Number.POSITIVE_INFINITY;
    // Las páginas llegan de la más reciente a la más antigua: lo que falta es siempre anterior.
    const known = complete || anchorMs >= oldestLoaded;
    if (known) {
      const index = items.findIndex((item) =>
        order === 'asc' ? Date.parse(item.at) > anchorMs : Date.parse(item.at) < anchorMs,
      );
      const anchor: Item = { kind: 'anchor', at: anchorIso };
      if (index < 0) items.push(anchor);
      else items.splice(index, 0, anchor);
    }
  }
  const out: TimelineEntry[] = [];
  let lastDay = '';
  for (const item of items) {
    const day = dayKey(item.at);
    if (day && day !== lastDay) {
      out.push({ type: 'day', key: `day:${day}`, label: formatDay(item.at) });
      lastDay = day;
    }
    out.push(
      item.kind === 'anchor'
        ? { type: 'anchor', key: 'anchor', at: item.at }
        : { type: 'event', key: item.event.id, event: item.event },
    );
  }
  return out;
}

/** Nivel de la regla de Wazuh en palabras propias (no reutiliza la escala de severidad). */
export function levelTone(level: number): 'very-high' | 'high' | 'medium' | 'low' {
  if (level >= 15) return 'very-high';
  if (level >= 12) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
}

const LEVEL_WORD: Record<ReturnType<typeof levelTone>, string> = {
  'very-high': 'muy alto',
  high: 'alto',
  medium: 'medio',
  low: 'bajo',
};

/** «Nivel 12 (alto)». */
export function levelText(level: number): string {
  return `Nivel ${level} (${LEVEL_WORD[levelTone(level)]})`;
}
