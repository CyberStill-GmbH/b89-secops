/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  limaTime,
  MAX_RANGE_MS,
  normalizeTrafficFilters,
  TRAFFIC_DATASET_LABEL,
  TRAFFIC_DATASETS,
  TrafficAggregations,
  TrafficDataset,
  TrafficEvent,
  TrafficFilters,
  UA_MAX,
  Validation,
} from '../../common';

/**
 * Modelo de la vista «Tráfico de Cloudflare». El estado vive en la URL (`?r=24h&ip=…`): un
 * filtro se comparte copiando el enlace y sobrevive a recargar. Funciones puras, sin React.
 */

export const RANGE_PRESETS = ['1h', '24h', '7d', '30d'] as const;
export type RangePreset = (typeof RANGE_PRESETS)[number];
export type RangeMode = RangePreset | 'custom';

export const RANGE_LABEL: Readonly<Record<RangeMode, string>> = {
  '1h': 'Última hora',
  '24h': '24 h',
  '7d': '7 días',
  '30d': '30 días',
  custom: 'Personalizado',
};

const PRESET_MS: Readonly<Record<RangePreset, number>> = {
  '1h': 3600 * 1000,
  '24h': 24 * 3600 * 1000,
  '7d': 7 * 24 * 3600 * 1000,
  '30d': 30 * 24 * 3600 * 1000,
};

/** Filtros de texto de la URL, en el orden en que se muestran. */
export const FILTER_KEYS = [
  'zone',
  'ip',
  'host',
  'path',
  'method',
  'status',
  'country',
  'asn',
  'ua',
  'q',
] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];

export const FILTER_LABEL: Readonly<Record<FilterKey, string>> = {
  zone: 'Zona',
  ip: 'IP',
  host: 'Host',
  path: 'Ruta contiene',
  method: 'Método',
  status: 'Estado',
  country: 'País',
  asn: 'ASN',
  ua: 'User-Agent',
  q: 'Texto',
};

export interface TrafficViewState {
  readonly range: RangeMode;
  /** Solo con `range: 'custom'` (ISO UTC). */
  readonly from?: string;
  readonly to?: string;
  readonly dataset: TrafficDataset | 'all';
  readonly filters: Readonly<Partial<Record<FilterKey, string>>>;
}

export const DEFAULT_STATE: TrafficViewState = { range: '24h', dataset: 'all', filters: {} };

function isoParam(value: string | null): string | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

/** Lee el estado de la query string. Un `from`/`to` sin `r` es un rango personalizado. */
export function parseViewState(search: string): TrafficViewState {
  const params = new URLSearchParams(search);
  const from = isoParam(params.get('from'));
  const to = isoParam(params.get('to'));
  const r = params.get('r');
  const range: RangeMode = (RANGE_PRESETS as readonly string[]).includes(r ?? '')
    ? (r as RangePreset)
    : from || to
      ? 'custom'
      : '24h';
  const ds = (params.get('ds') ?? params.get('dataset') ?? '').toLowerCase();
  const dataset = (TRAFFIC_DATASETS as readonly string[]).includes(ds)
    ? (ds as TrafficDataset)
    : 'all';
  const filters: Partial<Record<FilterKey, string>> = {};
  for (const key of FILTER_KEYS) {
    const value = params.get(key)?.trim();
    if (value) filters[key] = value.slice(0, UA_MAX);
  }
  return {
    range,
    ...(range === 'custom' && from ? { from } : {}),
    ...(range === 'custom' && to ? { to } : {}),
    dataset,
    filters,
  };
}

/** Query string del estado (sin `?`); vacía para el estado por defecto. */
export function viewStateSearch(state: TrafficViewState): string {
  const params = new URLSearchParams();
  if (state.range === 'custom') {
    if (state.from) params.set('from', state.from);
    if (state.to) params.set('to', state.to);
  } else if (state.range !== DEFAULT_STATE.range) {
    params.set('r', state.range);
  }
  if (state.dataset !== 'all') params.set('ds', state.dataset);
  for (const key of FILTER_KEYS) {
    const value = state.filters[key];
    if (value) params.set(key, value);
  }
  return params.toString();
}

/**
 * Rango absoluto. Los atajos cuentan hacia atrás desde `now`. Un rango personalizado sin fin
 * llega hasta ahora (máx. 31 días); sin inicio, 24 h antes del fin.
 */
export function resolveRange(state: TrafficViewState, now: number): { from: string; to: string } {
  if (state.range !== 'custom') {
    return {
      from: new Date(now - PRESET_MS[state.range]).toISOString(),
      to: new Date(now).toISOString(),
    };
  }
  const fromMs = state.from ? Date.parse(state.from) : Number.NaN;
  const toMs = state.to ? Date.parse(state.to) : Number.NaN;
  if (Number.isFinite(fromMs) && Number.isFinite(toMs)) {
    return { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() };
  }
  if (Number.isFinite(fromMs)) {
    const to = Math.max(fromMs + 60 * 1000, Math.min(now, fromMs + MAX_RANGE_MS));
    return { from: new Date(fromMs).toISOString(), to: new Date(to).toISOString() };
  }
  const end = Number.isFinite(toMs) ? toMs : now;
  return { from: new Date(end - PRESET_MS['24h']).toISOString(), to: new Date(end).toISOString() };
}

/** Filtros validados para la API (mismo validador que el servidor). */
export function viewFilters(state: TrafficViewState, now: number): Validation<TrafficFilters> {
  const range = resolveRange(state, now);
  return normalizeTrafficFilters({
    ...range,
    dataset: state.dataset === 'all' ? undefined : state.dataset,
    ...state.filters,
  });
}

export function withFilter(
  state: TrafficViewState,
  key: FilterKey,
  value: string | null | undefined,
): TrafficViewState {
  const filters = { ...state.filters };
  const trimmed = value?.trim();
  if (trimmed) filters[key] = trimmed;
  else delete filters[key];
  return { ...state, filters };
}

export function withFilters(
  state: TrafficViewState,
  values: Readonly<Partial<Record<FilterKey, string>>>,
): TrafficViewState {
  return FILTER_KEYS.reduce((next, key) => withFilter(next, key, values[key]), state);
}

export interface FilterChip {
  readonly key: FilterKey;
  readonly label: string;
  readonly value: string;
}

export function filterChips(state: TrafficViewState): FilterChip[] {
  return FILTER_KEYS.filter((key) => state.filters[key]).map((key) => ({
    key,
    label: FILTER_LABEL[key],
    value: state.filters[key] as string,
  }));
}

/** Lista «top» → filtro que aplica un clic. */
export const TOP_LISTS = [
  { id: 'topIps', title: 'IPs con más actividad', filter: 'ip' },
  { id: 'topHosts', title: 'Hosts', filter: 'host' },
  { id: 'topPaths', title: 'Rutas', filter: 'path' },
  { id: 'statusClasses', title: 'Estados HTTP', filter: 'status' },
  { id: 'topCountries', title: 'Países', filter: 'country' },
  { id: 'methods', title: 'Métodos', filter: 'method' },
] as const;

export type TopListId = (typeof TOP_LISTS)[number]['id'];

/** Clic en una lista: filtra por ese valor y vuelve a la primera página. */
export function applyTop(state: TrafficViewState, list: TopListId, key: string): TrafficViewState {
  const spec = TOP_LISTS.find((item) => item.id === list);
  return spec ? withFilter(state, spec.filter, key) : state;
}

/** «Ver toda la actividad de esta IP»: mismo rango, todos los tipos, solo esa IP. */
export function ipActivityState(
  state: TrafficViewState,
  event: TrafficEvent,
): TrafficViewState | null {
  if (!event.clientIp) return null;
  return { ...state, dataset: 'all', filters: { ip: event.clientIp } };
}

export const SESSION_WINDOW_MS = 60 * 60 * 1000;

/**
 * «Ver esta sesión de host»: la misma IP contra el mismo host (y el mismo User-Agent si lo
 * hay), una hora antes y después del evento.
 */
export function hostSessionState(event: TrafficEvent): TrafficViewState | null {
  const at = Date.parse(event.at);
  if (!event.clientIp || !event.host || event.dataset === 'dns' || !Number.isFinite(at)) {
    return null;
  }
  return {
    range: 'custom',
    from: new Date(at - SESSION_WINDOW_MS).toISOString(),
    to: new Date(at + SESSION_WINDOW_MS).toISOString(),
    dataset: 'all',
    filters: {
      ip: event.clientIp,
      host: event.host,
      ...(event.userAgent && event.userAgent.length <= UA_MAX ? { ua: event.userAgent } : {}),
    },
  };
}

/* -------------------------------------------------------------- Cifras */

const NUMBER = new Intl.NumberFormat('es-PE');
const PERCENT = new Intl.NumberFormat('es-PE', { maximumFractionDigits: 1 });

export interface StatTile {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly hint?: string;
  readonly tone?: 'warning' | 'danger';
}

export function statTiles(aggs: TrafficAggregations, dataset: TrafficDataset | 'all'): StatTile[] {
  const requests = aggs.datasets.http;
  const errors = aggs.errors4xx + aggs.errors5xx;
  const ratio = aggs.httpWithStatus > 0 ? (errors / aggs.httpWithStatus) * 100 : null;
  return [
    {
      id: 'requests',
      label: 'Peticiones HTTP',
      value: NUMBER.format(requests),
      hint:
        aggs.sampled > 0
          ? `${NUMBER.format(aggs.sampled)} registros muestreados: cada uno representa varias peticiones`
          : dataset !== 'all' && dataset !== 'http'
            ? 'Con los filtros actuales, en todos los tipos'
            : undefined,
    },
    { id: 'ips', label: 'IPs únicas', value: NUMBER.format(aggs.uniqueIps) },
    {
      id: 'errors',
      label: '% errores 4xx/5xx',
      value: ratio === null ? '—' : `${PERCENT.format(ratio)} %`,
      hint:
        ratio === null
          ? 'Sin respuestas HTTP en el rango'
          : `4xx ${NUMBER.format(aggs.errors4xx)} · 5xx ${NUMBER.format(aggs.errors5xx)}`,
      tone:
        ratio !== null && ratio >= 25
          ? 'danger'
          : ratio !== null && ratio >= 10
            ? 'warning'
            : undefined,
    },
    { id: 'countries', label: 'Países', value: NUMBER.format(aggs.countries) },
  ];
}

export function formatCount(value: number): string {
  return NUMBER.format(value);
}

export function totalLabel(total: { value: number; relation: 'eq' | 'gte' }): string {
  return `${total.relation === 'gte' ? 'más de ' : ''}${NUMBER.format(total.value)}`;
}

/** Colores por tipo (mismos en el histograma, las pestañas y las insignias). */
export const DATASET_COLOR: Readonly<Record<TrafficDataset, string>> = {
  http: '#3B82C4',
  dns: '#2FA37C',
  firewall: '#D9534F',
  audit: '#B07CC6',
};

export interface HistogramColumn {
  readonly at: string;
  readonly label: string;
  readonly total: number;
  /** Altura relativa 0–100. */
  readonly height: number;
  readonly segments: ReadonlyArray<{ dataset: TrafficDataset; count: number }>;
  readonly summary: string;
}

/** Columnas del histograma con la hora de Lima y el desglose por tipo. */
export function histogramColumns(aggs: TrafficAggregations): HistogramColumn[] {
  const max = Math.max(1, ...aggs.histogram.map((bucket) => bucket.total));
  const daily = /^\d+[dMy]$/u.test(aggs.interval ?? '');
  return aggs.histogram.map((bucket) => {
    const label = daily ? limaTime(bucket.at, false).slice(0, 10) : limaTime(bucket.at, false);
    const segments = TRAFFIC_DATASETS.map((dataset) => ({
      dataset,
      count: bucket.byDataset[dataset] ?? 0,
    })).filter((segment) => segment.count > 0);
    const detail = segments
      .map((segment) => `${TRAFFIC_DATASET_LABEL[segment.dataset]} ${NUMBER.format(segment.count)}`)
      .join(', ');
    return {
      at: bucket.at,
      label,
      total: bucket.total,
      height: (bucket.total / max) * 100,
      segments,
      summary: `${label} (Lima): ${NUMBER.format(bucket.total)} eventos${detail ? ` (${detail})` : ''}`,
    };
  });
}

/** Intervalo del histograma en español (`1h` → «1 hora»). */
export function intervalLabel(interval: string | null): string | null {
  const match = /^(\d+)([smhdMy])$/u.exec(interval ?? '');
  if (!match) return null;
  const count = Number(match[1]);
  const unit: Record<string, [string, string]> = {
    s: ['segundo', 'segundos'],
    m: ['minuto', 'minutos'],
    h: ['hora', 'horas'],
    d: ['día', 'días'],
    M: ['mes', 'meses'],
    y: ['año', 'años'],
  };
  const [one, other] = unit[match[2]];
  return `${count} ${count === 1 ? one : other}`;
}

/* ------------------------------------------------------------ Detalle */

/** Todos los campos del documento, aplanados (`http.status`) y ordenados. */
export function flattenSource(
  source: Readonly<Record<string, unknown>>,
  prefix = '',
): Array<readonly [string, string]> {
  const rows: Array<readonly [string, string]> = [];
  for (const [key, value] of Object.entries(source)) {
    const field = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      rows.push(...flattenSource(value as Record<string, unknown>, field));
    } else if (value !== undefined && value !== null && value !== '') {
      rows.push([field, Array.isArray(value) ? value.map(String).join(', ') : String(value)]);
    }
  }
  return prefix ? rows : rows.sort((a, b) => a[0].localeCompare(b[0]));
}

/** Texto acotado (User-Agent largo en la tabla). */
export function truncate(value: string | null, max = 60): string {
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/** «Ruta» visible: host + ruta para HTTP y firewall; el resumen para DNS y auditoría. */
export function targetOf(event: TrafficEvent): string {
  if (event.dataset === 'http' || event.dataset === 'firewall') {
    return `${event.host ?? ''}${event.path ?? ''}` || event.detail || '';
  }
  return event.detail ?? event.host ?? '';
}

/** Mensaje y tono del estado de una consulta fallida. */
export function errorMessage(error: unknown): { title: string; tone: 'warning' | 'danger' } {
  const status = (error as { status?: number })?.status;
  const message = error instanceof Error ? error.message : '';
  if (status === 403) {
    return {
      title: message || 'Tu rol no puede leer el tráfico de Cloudflare (b89-cloudflare-traffic-*).',
      tone: 'warning',
    };
  }
  if (status === 404) {
    return { title: message || 'Aún no hay índices de tráfico de Cloudflare.', tone: 'warning' };
  }
  if (status === 400) return { title: message || 'Revise los filtros.', tone: 'warning' };
  return {
    title: message && status ? message : 'No se pudo consultar el tráfico de Cloudflare.',
    tone: 'danger',
  };
}
