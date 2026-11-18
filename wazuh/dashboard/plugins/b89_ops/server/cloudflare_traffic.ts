/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { createHash } from 'crypto';
import {
  csvHeader,
  csvRow,
  CURSOR_MAX_LENGTH,
  DEFAULT_PAGE_SIZE,
  EXPORT_MAX_ROWS,
  fieldValue,
  HistogramBucket,
  MAX_PAGE_SIZE,
  TopBucket,
  TOTAL_HITS_CAP,
  TRAFFIC_DATASETS,
  TRAFFIC_INDEX,
  TrafficAggregations,
  TrafficDataset,
  TrafficEvent,
  TrafficFilters,
  TrafficResponse,
} from '../common/cloudflare_traffic';
import type { SearchClient } from './overview';

/**
 * `GET /api/b89_ops/cloudflare/traffic` y su exportación CSV: lectura de
 * `b89-cloudflare-traffic-*` con la identidad de quien mira (`asCurrentUser`).
 *
 * Seguridad de la consulta: el navegador solo envía filtros validados
 * (`normalizeTrafficFilters`); aquí se convierten en cláusulas `term`/`range`/`wildcard` con
 * valores escapados. El texto libre va en `simple_query_string` restringido a campos de texto
 * conocidos, sin comodines iniciales ni expresiones regulares.
 */

type Json = Record<string, unknown>;

/** Campos que puede tocar la búsqueda libre (nunca `*`). */
export const FREE_TEXT_FIELDS = [
  'http.path.text',
  'http.user_agent.text',
  'http.host',
  'http.uri',
  'http.ray',
  'dns.query',
  'firewall.description',
  'firewall.rule_id',
  'audit.action',
  'audit.actor_email',
  'audit.resource_type',
  'client.asn_name',
] as const;

/** Operadores admitidos en la búsqueda libre: sin FUZZY, NEAR, SLOP ni ESCAPE. */
const FREE_TEXT_FLAGS = 'AND|OR|NOT|PHRASE|PREFIX|PRECEDENCE|WHITESPACE';

/** Comodín de `wildcard`: escapa `*`, `?` y `\` del valor del usuario. */
export function wildcardLiteral(value: string): string {
  return value.replace(/[\\*?]/gu, (char) => `\\${char}`);
}

const STATUS_RANGE: Readonly<Record<string, { gte: number; lte: number }>> = {
  '2xx': { gte: 200, lte: 299 },
  '3xx': { gte: 300, lte: 399 },
  '4xx': { gte: 400, lte: 499 },
  '5xx': { gte: 500, lte: 599 },
};

/** Filtros salvo el de tipo (que va en `post_filter` para que las pestañas cuenten todo). */
export function trafficFilterClauses(filters: TrafficFilters): Json[] {
  const clauses: Json[] = [
    {
      range: {
        '@timestamp': { gte: filters.from, lte: filters.to, format: 'strict_date_optional_time' },
      },
    },
  ];
  if (filters.zones.length > 0) {
    clauses.push({
      bool: {
        should: [
          { terms: { 'zone.name': [...filters.zones] } },
          { terms: { 'audit.zone_name': [...filters.zones] } },
        ],
        minimum_should_match: 1,
      },
    });
  }
  if (filters.ip) {
    // Toda la actividad de la IP: como cliente (HTTP, DNS, firewall) o como actor (auditoría).
    clauses.push({
      bool: {
        should: [{ term: { 'client.ip': filters.ip } }, { term: { 'audit.actor_ip': filters.ip } }],
        minimum_should_match: 1,
      },
    });
  }
  if (filters.host) {
    clauses.push(
      filters.host.includes('*')
        ? {
            wildcard: {
              'http.host': {
                value: filters.host.replace(/[\\?]/gu, (char) => `\\${char}`),
                case_insensitive: true,
              },
            },
          }
        : { term: { 'http.host': filters.host } },
    );
  }
  if (filters.path) {
    clauses.push({
      wildcard: {
        'http.path': { value: `*${wildcardLiteral(filters.path)}*`, case_insensitive: true },
      },
    });
  }
  if (filters.method) clauses.push({ term: { 'http.method': filters.method } });
  if (filters.status) {
    const range = STATUS_RANGE[filters.status];
    clauses.push(
      range
        ? { range: { 'http.status': range } }
        : { term: { 'http.status': Number(filters.status) } },
    );
  }
  if (filters.country) clauses.push({ term: { 'client.country': filters.country } });
  if (filters.asn !== undefined) clauses.push({ term: { 'client.asn': filters.asn } });
  if (filters.ua) clauses.push({ term: { 'http.user_agent': filters.ua } });
  if (filters.q) {
    clauses.push({
      simple_query_string: {
        query: filters.q,
        fields: [...FREE_TEXT_FIELDS],
        flags: FREE_TEXT_FLAGS,
        default_operator: 'and',
        lenient: true,
        analyze_wildcard: false,
        auto_generate_synonyms_phrase_query: false,
      },
    });
  }
  return clauses;
}

function datasetFilter(filters: TrafficFilters): Json | null {
  return filters.datasets.length > 0 ? { terms: { 'event.dataset': [...filters.datasets] } } : null;
}

const top = (field: string, size: number): Json => ({ terms: { field, size } });

export function trafficAggregations(filters: TrafficFilters): Json {
  const scoped: Json = {
    histogram: {
      auto_date_histogram: {
        field: '@timestamp',
        buckets: 60,
        time_zone: 'America/Lima',
        minimum_interval: 'minute',
      },
      aggs: { datasets: top('event.dataset', TRAFFIC_DATASETS.length) },
    },
    unique_ips: { cardinality: { field: 'client.ip' } },
    countries: { cardinality: { field: 'client.country' } },
    with_status: { filter: { exists: { field: 'http.status' } } },
    errors_4xx: { filter: { range: { 'http.status': STATUS_RANGE['4xx'] } } },
    errors_5xx: { filter: { range: { 'http.status': STATUS_RANGE['5xx'] } } },
    sampled: { filter: { term: { 'event.sampled': true } } },
    top_ips: top('client.ip', 10),
    top_hosts: top('http.host', 10),
    top_paths: top('http.path', 10),
    top_countries: top('client.country', 10),
    methods: top('http.method', 10),
    zones: top('zone.name', 50),
    status_classes: {
      range: {
        field: 'http.status',
        ranges: [
          { key: '1xx', from: 100, to: 200 },
          { key: '2xx', from: 200, to: 300 },
          { key: '3xx', from: 300, to: 400 },
          { key: '4xx', from: 400, to: 500 },
          { key: '5xx', from: 500, to: 600 },
        ],
      },
    },
  };
  const dataset = datasetFilter(filters);
  return {
    // Conteo por tipo con todos los filtros salvo el tipo: las pestañas muestran cuánto hay.
    datasets: top('event.dataset', TRAFFIC_DATASETS.length),
    scoped: { filter: dataset ?? { match_all: {} }, aggs: scoped },
  };
}

/** Orden estable: hora del evento (desc) y orden interno del índice como desempate. */
const SORT: Json[] = [{ '@timestamp': { order: 'desc' } }, { _doc: { order: 'asc' } }];

export interface TrafficSearchParams {
  readonly filters: TrafficFilters;
  readonly size?: number;
  readonly searchAfter?: readonly [number, number];
  readonly withAggregations?: boolean;
  readonly trackTotal?: boolean;
}

export function trafficSearchBody(params: TrafficSearchParams): Json {
  const size = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(params.size ?? DEFAULT_PAGE_SIZE)));
  const dataset = datasetFilter(params.filters);
  return {
    size,
    track_total_hits: params.trackTotal === false ? false : TOTAL_HITS_CAP,
    timeout: '30s',
    query: { bool: { filter: trafficFilterClauses(params.filters) } },
    ...(dataset ? { post_filter: dataset } : {}),
    sort: SORT,
    ...(params.searchAfter ? { search_after: [...params.searchAfter] } : {}),
    ...(params.withAggregations ? { aggs: trafficAggregations(params.filters) } : {}),
  };
}

/* ------------------------------------------------------------------- Cursor */

export function filtersFingerprint(filters: TrafficFilters): string {
  return createHash('sha256').update(JSON.stringify(filters)).digest('hex').slice(0, 16);
}

interface Cursor {
  readonly f: string;
  readonly s: readonly [number, number];
}

function validSort(value: unknown): value is readonly [number, number] {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    value.every((item) => typeof item === 'number' && Number.isSafeInteger(item))
  );
}

export function encodeCursor(filters: TrafficFilters, sort: unknown): string | null {
  if (!validSort(sort)) return null;
  const cursor: Cursor = { f: filtersFingerprint(filters), s: [sort[0], sort[1]] };
  return Buffer.from(JSON.stringify(cursor)).toString('base64url');
}

/** Cursor de `search_after` atado a los filtros: otro filtro ⇒ error (400). */
export function decodeCursor(
  value: string | undefined,
  filters: TrafficFilters,
): readonly [number, number] | undefined {
  if (!value) return undefined;
  if (value.length > CURSOR_MAX_LENGTH || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error('Cursor no válido.');
  }
  let decoded: Partial<Cursor>;
  try {
    decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as Partial<Cursor>;
  } catch {
    throw new Error('Cursor no válido.');
  }
  if (decoded.f !== filtersFingerprint(filters) || !validSort(decoded.s)) {
    throw new Error('Cursor no válido para estos filtros.');
  }
  return decoded.s;
}

/* ------------------------------------------------------------------ Lectura */

function obj(value: unknown): Json {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : {};
}

function num(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string | null {
  if (typeof value === 'string') return value === '' ? null : value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

function numOrNull(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^-?\d+(\.\d+)?$/u.test(value)) return Number(value);
  return null;
}

function bool(value: unknown): boolean {
  return value === true || value === 'true';
}

function detailOf(source: Json, dataset: string): string | null {
  const get = (field: string) => str(fieldValue(source, field));
  const join = (...parts: Array<string | null>) =>
    parts.filter((part): part is string => !!part).join(' · ') || null;
  if (dataset === 'dns') {
    return join(get('dns.query'), get('dns.type'), get('dns.rcode'), get('dns.colo'));
  }
  if (dataset === 'firewall') {
    return join(get('firewall.description'), get('firewall.source'), get('firewall.rule_id'));
  }
  if (dataset === 'audit') {
    return join(
      get('audit.action'),
      get('audit.result'),
      get('audit.actor_email'),
      get('audit.resource_type'),
    );
  }
  return null;
}

export function parseTrafficEvent(hit: unknown): TrafficEvent {
  const item = obj(hit);
  const source = obj(item._source);
  const get = (field: string) => fieldValue(source, field);
  const dataset = str(get('event.dataset')) ?? 'desconocido';
  const at = str(get('@timestamp')) ?? '';
  const parsedAt = Date.parse(at);
  return {
    id: String(item._id ?? ''),
    index: String(item._index ?? ''),
    at: Number.isFinite(parsedAt) ? new Date(parsedAt).toISOString() : at,
    ingestedAt: str(get('ingested_at')),
    dataset,
    source: str(get('event.source')),
    sampled: bool(get('event.sampled')),
    sampleInterval: numOrNull(get('event.sample_interval')),
    history: bool(get('event.history')),
    zone: str(get('zone.name')) ?? str(get('audit.zone_name')),
    clientIp: str(get('client.ip')) ?? str(get('audit.actor_ip')),
    country: str(get('client.country')),
    asn: numOrNull(get('client.asn')),
    asnName: str(get('client.asn_name')),
    method: str(get('http.method')),
    host: str(get('http.host')) ?? (dataset === 'dns' ? str(get('dns.query')) : null),
    path: str(get('http.path')),
    status: numOrNull(get('http.status')),
    userAgent: str(get('http.user_agent')),
    action: str(get('http.security_action')) ?? str(get('firewall.action')),
    detail: detailOf(source, dataset),
    raw: source,
  };
}

function buckets(aggregation: unknown): TopBucket[] {
  return list(obj(aggregation).buckets)
    .map((bucket) => ({
      key: String(obj(bucket).key_as_string ?? obj(bucket).key ?? ''),
      count: num(obj(bucket).doc_count),
    }))
    .filter((bucket) => bucket.key !== '');
}

function datasetCounts(aggregation: unknown): Record<TrafficDataset, number> {
  const counts: Record<TrafficDataset, number> = { http: 0, dns: 0, firewall: 0, audit: 0 };
  for (const bucket of buckets(aggregation)) {
    if ((TRAFFIC_DATASETS as readonly string[]).includes(bucket.key)) {
      counts[bucket.key as TrafficDataset] = bucket.count;
    }
  }
  return counts;
}

export function parseTrafficAggregations(aggregations: unknown): TrafficAggregations {
  const root = obj(aggregations);
  const scoped = obj(root.scoped);
  const histogram: HistogramBucket[] = list(obj(scoped.histogram).buckets).map((bucket) => {
    const item = obj(bucket);
    const byDataset: Partial<Record<TrafficDataset, number>> = {};
    for (const entry of buckets(item.datasets)) {
      if ((TRAFFIC_DATASETS as readonly string[]).includes(entry.key)) {
        byDataset[entry.key as TrafficDataset] = entry.count;
      }
    }
    return { at: new Date(num(item.key)).toISOString(), total: num(item.doc_count), byDataset };
  });
  const interval = obj(scoped.histogram).interval;
  return {
    interval: typeof interval === 'string' ? interval : null,
    histogram,
    datasets: datasetCounts(root.datasets),
    uniqueIps: num(obj(scoped.unique_ips).value),
    countries: num(obj(scoped.countries).value),
    httpWithStatus: num(obj(scoped.with_status).doc_count),
    errors4xx: num(obj(scoped.errors_4xx).doc_count),
    errors5xx: num(obj(scoped.errors_5xx).doc_count),
    sampled: num(obj(scoped.sampled).doc_count),
    topIps: buckets(scoped.top_ips),
    topHosts: buckets(scoped.top_hosts),
    topPaths: buckets(scoped.top_paths),
    statusClasses: buckets(scoped.status_classes).filter((bucket) => bucket.count > 0),
    topCountries: buckets(scoped.top_countries),
    methods: buckets(scoped.methods),
    zones: buckets(scoped.zones),
  };
}

function isPartial(body: Json): boolean {
  return body.timed_out === true || num(obj(body._shards).failed) > 0;
}

function totalOf(body: Json): TrafficResponse['total'] {
  const total = obj(obj(body.hits).total);
  return {
    value: num(total.value),
    relation: total.relation === 'gte' ? 'gte' : 'eq',
  };
}

/* ---------------------------------------------------------------- Ejecución */

export async function searchTraffic(
  client: SearchClient,
  filters: TrafficFilters,
  options: { cursor?: string; size?: number } = {},
): Promise<TrafficResponse> {
  const searchAfter = decodeCursor(options.cursor, filters);
  const size = Math.max(1, Math.min(MAX_PAGE_SIZE, options.size ?? DEFAULT_PAGE_SIZE));
  const response = await client.search({
    index: TRAFFIC_INDEX,
    body: trafficSearchBody({ filters, size, searchAfter, withAggregations: !searchAfter }),
  });
  const body = obj(response.body);
  const hits = list(obj(body.hits).hits);
  const last = obj(hits[hits.length - 1]);
  return {
    filters,
    total: totalOf(body),
    events: hits.map(parseTrafficEvent),
    nextCursor: hits.length === size ? encodeCursor(filters, last.sort) : null,
    aggregations: searchAfter ? null : parseTrafficAggregations(body.aggregations),
    partial: isPartial(body),
  };
}

/** Filas por consulta de la exportación (search_after, sin agregaciones ni total). */
export const EXPORT_CHUNK = 1000;

/**
 * Exportación CSV por bloques de `search_after`: la primera página se pide antes de
 * responder (un 403 llega como error, no como CSV vacío) y el resto se genera mientras el
 * navegador descarga. Tope `EXPORT_MAX_ROWS` filas.
 */
export async function exportTrafficCsv(
  client: SearchClient,
  filters: TrafficFilters,
  maxRows: number = EXPORT_MAX_ROWS,
): Promise<AsyncGenerator<string, void, unknown>> {
  const page = async (searchAfter?: readonly [number, number]) => {
    const response = await client.search({
      index: TRAFFIC_INDEX,
      body: {
        ...trafficSearchBody({
          filters,
          size: Math.min(EXPORT_CHUNK, maxRows),
          searchAfter,
          trackTotal: false,
        }),
        size: Math.min(EXPORT_CHUNK, maxRows),
      },
    });
    return list(obj(obj(response.body).hits).hits).map(obj);
  };
  const firstPage = await page();
  async function* rows(): AsyncGenerator<string, void, unknown> {
    // BOM: Excel abre el CSV en UTF-8 (tildes y eñes de los textos).
    yield `﻿${csvHeader()}`;
    let hits = firstPage;
    let written = 0;
    while (hits.length > 0 && written < maxRows) {
      const lines: string[] = [];
      for (const hit of hits) {
        if (written >= maxRows) break;
        lines.push(csvRow(obj(hit._source)));
        written += 1;
      }
      yield lines.join('');
      const sort = list(hits[hits.length - 1].sort);
      if (hits.length < Math.min(EXPORT_CHUNK, maxRows) || !validSort(sort) || written >= maxRows) {
        break;
      }
      hits = await page([sort[0], sort[1]]);
    }
  }
  return rows();
}

export function exportFilename(filters: TrafficFilters): string {
  const compact = (iso: string) => iso.replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');
  return `b89-cloudflare-trafico_${compact(filters.from)}_${compact(filters.to)}.csv`;
}
