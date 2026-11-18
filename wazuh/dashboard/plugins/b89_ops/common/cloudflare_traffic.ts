/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * «Tráfico de Cloudflare»: contrato compartido entre la ruta del servidor del dashboard y la vista.
 *
 * Todo lo que Cloudflare registra (peticiones HTTP, consultas DNS, eventos de firewall/WAF y
 * auditoría de la cuenta) vive en `b89-cloudflare-traffic-YYYY.MM.DD` (un índice por día del
 * EVENTO) con la hora real del evento en `@timestamp` (UTC). La vista lo muestra tal cual, en
 * hora de Lima (UTC−5, sin horario de verano).
 *
 * Los filtros se validan aquí (lista blanca de valores y longitudes acotadas) y el servidor
 * arma la consulta: el navegador nunca envía DSL de OpenSearch.
 */

export const TRAFFIC_INDEX = 'b89-cloudflare-traffic-*';

export const TRAFFIC_ROUTES = {
  search: '/api/b89_ops/cloudflare/traffic',
  export: '/api/b89_ops/cloudflare/traffic/export',
} as const;

/** App de la vista (menú «Integraciones»). */
export const TRAFFIC_APP_PATH = '/app/b89-cloudflare-traffic';

export const TRAFFIC_DATASETS = ['http', 'dns', 'firewall', 'audit'] as const;
export type TrafficDataset = (typeof TRAFFIC_DATASETS)[number];

export const TRAFFIC_DATASET_LABEL: Readonly<Record<TrafficDataset, string>> = {
  http: 'HTTP',
  dns: 'DNS',
  firewall: 'Firewall',
  audit: 'Auditoría',
};

export const STATUS_CLASSES = ['2xx', '3xx', '4xx', '5xx'] as const;
export type StatusClass = (typeof STATUS_CLASSES)[number];

/** Rango máximo de una consulta (y de una exportación). */
export const MAX_RANGE_MS = 31 * 24 * 3600 * 1000;
export const MAX_PAGE_SIZE = 200;
export const DEFAULT_PAGE_SIZE = 100;
/** `track_total_hits`: el total exacto se cuenta hasta aquí; por encima es «más de». */
export const TOTAL_HITS_CAP = 100000;
export const EXPORT_MAX_ROWS = 50000;
export const MAX_ZONES = 20;
export const TEXT_MAX = 200;
/** Un User-Agent real puede superar 200 caracteres: se filtra por su valor exacto. */
export const UA_MAX = 512;
export const CURSOR_MAX_LENGTH = 512;

/** Lima no tiene horario de verano desde 1994: UTC−5 fijo. */
export const LIMA_OFFSET_MS = -5 * 3600 * 1000;
export const LIMA_LABEL = 'hora de Lima (UTC−5)';

/** Filtros normalizados (lo que el servidor convierte en consulta). */
export interface TrafficFilters {
  readonly from: string;
  readonly to: string;
  readonly datasets: readonly TrafficDataset[];
  readonly zones: readonly string[];
  readonly ip?: string;
  readonly host?: string;
  readonly path?: string;
  readonly method?: string;
  readonly status?: string;
  readonly country?: string;
  readonly asn?: number;
  readonly ua?: string;
  readonly q?: string;
}

/** Parámetros crudos de la query string (validados después). */
export type RawTrafficQuery = Readonly<Record<string, string | readonly string[] | undefined>>;

export type Validation<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: string };

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/u;
const IPV6 = /^[0-9A-Fa-f:.]{2,45}$/u;

/** IPv4/IPv6, con prefijo CIDR opcional (el campo `ip` de OpenSearch admite CIDR en `term`). */
export function validIp(value: string): boolean {
  const [address, prefix, extra] = value.split('/');
  if (extra !== undefined || !address) return false;
  const v4 = IPV4.test(address);
  const v6 =
    !v4 && address.includes(':') && IPV6.test(address) && (address.match(/::/gu) ?? []).length <= 1;
  if (!v4 && !v6) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/u.test(prefix)) return false;
  const bits = Number(prefix);
  return bits >= (v4 ? 8 : 16) && bits <= (v4 ? 32 : 128);
}

const HOST = /^[A-Za-z0-9*._-]{1,253}$/u;
const ZONE = /^[A-Za-z0-9._-]{1,253}$/u;
const METHOD = /^[A-Z]{3,16}$/u;
const COUNTRY = /^[A-Z]{2}$/u;
const STATUS_EXACT = /^[1-5]\d\d$/u;
// Sin caracteres de control; el resto se escapa al armar la consulta.
const CONTROL = /[\u0000-\u001f\u007f]/u;

function first(value: string | readonly string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : (value as string | undefined);
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  return trimmed === '' ? undefined : trimmed;
}

function many(value: string | readonly string[] | undefined): string[] {
  const values = Array.isArray(value) ? value : value === undefined ? [] : [value as string];
  const out: string[] = [];
  for (const item of values) {
    for (const part of item.split(',')) {
      const trimmed = part.trim();
      if (trimmed && !out.includes(trimmed)) out.push(trimmed);
    }
  }
  return out;
}

function isoOf(value: string | undefined): number | null {
  if (!value || value.length > 40) return null;
  // Solo instantes ISO 8601 completos (con zona): nada de expresiones `now-…` del navegador.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/u.test(value)) {
    return null;
  }
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function text(
  value: string | undefined,
  label: string,
  max: number = TEXT_MAX,
): Validation<string | undefined> {
  if (value === undefined) return { ok: true, value: undefined };
  if (value.length > max || CONTROL.test(value)) {
    return { ok: false, error: `${label} no válido.` };
  }
  return { ok: true, value };
}

/**
 * Valida y normaliza los filtros. `from` y `to` son obligatorios (ISO 8601 con zona) y el
 * rango no supera 31 días. Devuelve el primer error en español.
 */
export function normalizeTrafficFilters(raw: RawTrafficQuery): Validation<TrafficFilters> {
  const from = isoOf(first(raw.from));
  const to = isoOf(first(raw.to));
  if (from === null || to === null) {
    return { ok: false, error: 'Indique el rango con «from» y «to» en ISO 8601 (UTC).' };
  }
  if (to <= from) return { ok: false, error: 'El fin del rango debe ser posterior al inicio.' };
  if (to - from > MAX_RANGE_MS) return { ok: false, error: 'El rango máximo es de 31 días.' };

  const datasets: TrafficDataset[] = [];
  for (const value of many(raw.dataset)) {
    const lower = value.toLowerCase();
    if (!(TRAFFIC_DATASETS as readonly string[]).includes(lower)) {
      return { ok: false, error: `Tipo de dato desconocido: ${value.slice(0, 20)}.` };
    }
    if (!datasets.includes(lower as TrafficDataset)) datasets.push(lower as TrafficDataset);
  }

  const zones = many(raw.zone).map((zone) => zone.toLowerCase());
  if (zones.length > MAX_ZONES || zones.some((zone) => !ZONE.test(zone))) {
    return { ok: false, error: 'Zona no válida.' };
  }

  const ip = first(raw.ip);
  if (ip !== undefined && !validIp(ip)) return { ok: false, error: 'IP o rango CIDR no válido.' };

  const host = first(raw.host)?.toLowerCase();
  if (host !== undefined && !HOST.test(host.replace(/\*/gu, 'x'))) {
    return { ok: false, error: 'Host no válido.' };
  }

  const method = first(raw.method)?.toUpperCase();
  if (method !== undefined && !METHOD.test(method))
    return { ok: false, error: 'Método no válido.' };

  const status = first(raw.status)?.toLowerCase();
  if (
    status !== undefined &&
    !(STATUS_CLASSES as readonly string[]).includes(status) &&
    !STATUS_EXACT.test(status)
  ) {
    return { ok: false, error: 'Estado HTTP no válido (2xx…5xx o un código de 3 cifras).' };
  }

  const country = first(raw.country)?.toUpperCase();
  if (country !== undefined && !COUNTRY.test(country)) {
    return { ok: false, error: 'País no válido (código ISO de 2 letras).' };
  }

  const asnText = first(raw.asn)?.replace(/^AS/iu, '');
  if (asnText !== undefined && !/^\d{1,10}$/u.test(asnText)) {
    return { ok: false, error: 'ASN no válido.' };
  }
  const asn = asnText === undefined ? undefined : Number(asnText);
  if (asn !== undefined && asn > 4294967295) return { ok: false, error: 'ASN no válido.' };

  const path = text(first(raw.path), 'Ruta');
  if (!path.ok) return path;
  const ua = text(first(raw.ua), 'User-Agent', UA_MAX);
  if (!ua.ok) return ua;
  const q = text(first(raw.q), 'Texto de búsqueda');
  if (!q.ok) return q;

  return {
    ok: true,
    value: {
      from: new Date(from).toISOString(),
      to: new Date(to).toISOString(),
      datasets,
      zones,
      ...(ip !== undefined ? { ip } : {}),
      ...(host !== undefined ? { host } : {}),
      ...(path.value !== undefined ? { path: path.value } : {}),
      ...(method !== undefined ? { method } : {}),
      ...(status !== undefined ? { status } : {}),
      ...(country !== undefined ? { country } : {}),
      ...(asn !== undefined ? { asn } : {}),
      ...(ua.value !== undefined ? { ua: ua.value } : {}),
      ...(q.value !== undefined ? { q: q.value } : {}),
    },
  };
}

/** Query string de la API para unos filtros (la misma forma que valida el servidor). */
export function trafficQueryParams(filters: TrafficFilters): URLSearchParams {
  const params = new URLSearchParams();
  params.set('from', filters.from);
  params.set('to', filters.to);
  for (const dataset of filters.datasets) params.append('dataset', dataset);
  for (const zone of filters.zones) params.append('zone', zone);
  const optional: Array<keyof TrafficFilters> = [
    'ip',
    'host',
    'path',
    'method',
    'status',
    'country',
    'asn',
    'ua',
    'q',
  ];
  for (const key of optional) {
    const value = filters[key];
    if (value !== undefined && value !== '') params.set(key, String(value));
  }
  return params;
}

/* -------------------------------------------------------------- Respuesta */

export interface TrafficEvent {
  readonly id: string;
  readonly index: string;
  /** `@timestamp` del evento (ISO UTC). */
  readonly at: string;
  readonly ingestedAt: string | null;
  readonly dataset: string;
  readonly source: string | null;
  readonly sampled: boolean;
  readonly sampleInterval: number | null;
  readonly history: boolean;
  readonly zone: string | null;
  readonly clientIp: string | null;
  readonly country: string | null;
  readonly asn: number | null;
  readonly asnName: string | null;
  readonly method: string | null;
  readonly host: string | null;
  readonly path: string | null;
  readonly status: number | null;
  readonly userAgent: string | null;
  /** Acción de seguridad (HTTP) o acción del firewall. */
  readonly action: string | null;
  /** Resumen de una línea para DNS, firewall y auditoría. */
  readonly detail: string | null;
  /** Documento completo tal como está en el índice. */
  readonly raw: Readonly<Record<string, unknown>>;
}

export interface TopBucket {
  readonly key: string;
  readonly count: number;
}

export interface HistogramBucket {
  readonly at: string;
  readonly total: number;
  readonly byDataset: Readonly<Partial<Record<TrafficDataset, number>>>;
}

export interface TrafficAggregations {
  readonly interval: string | null;
  readonly histogram: readonly HistogramBucket[];
  /** Conteo por tipo SIN el filtro de tipo (para las pestañas). */
  readonly datasets: Readonly<Record<TrafficDataset, number>>;
  readonly uniqueIps: number;
  readonly countries: number;
  readonly httpWithStatus: number;
  readonly errors4xx: number;
  readonly errors5xx: number;
  readonly sampled: number;
  readonly topIps: readonly TopBucket[];
  readonly topHosts: readonly TopBucket[];
  readonly topPaths: readonly TopBucket[];
  readonly statusClasses: readonly TopBucket[];
  readonly topCountries: readonly TopBucket[];
  readonly methods: readonly TopBucket[];
  readonly zones: readonly TopBucket[];
}

export interface TrafficResponse {
  readonly filters: TrafficFilters;
  readonly total: { readonly value: number; readonly relation: 'eq' | 'gte' };
  readonly events: readonly TrafficEvent[];
  readonly nextCursor: string | null;
  /** Solo en la primera página. */
  readonly aggregations: TrafficAggregations | null;
  /** Algún shard falló o se agotó el tiempo: los datos pueden estar incompletos. */
  readonly partial: boolean;
}

/* ---------------------------------------------------------------- Hora de Lima */

const pad = (value: number, size = 2) => String(value).padStart(size, '0');

/** `2026-11-17 12:00:05` en hora de Lima (UTC−5). */
export function limaTime(iso: string | null | undefined, withSeconds = true): string {
  const ms = iso ? Date.parse(iso) : Number.NaN;
  if (!Number.isFinite(ms)) return '';
  const d = new Date(ms + LIMA_OFFSET_MS);
  const base = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(
    d.getUTCHours(),
  )}:${pad(d.getUTCMinutes())}`;
  return withSeconds ? `${base}:${pad(d.getUTCSeconds())}` : base;
}

/** Valor de un `<input type="datetime-local">` (hora de Lima) para un instante ISO. */
export function limaInputValue(iso: string): string {
  const text = limaTime(iso, false);
  return text ? text.replace(' ', 'T') : '';
}

/** `2026-11-17T12:00` interpretado en hora de Lima → instante ISO UTC (o `null`). */
export function limaInputToIso(value: string): string | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/u.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match;
  const utc = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s ?? 0));
  if (!Number.isFinite(utc)) return null;
  return new Date(utc - LIMA_OFFSET_MS).toISOString();
}

/* --------------------------------------------------------------------- CSV */

/** Columnas de la exportación: hora de Lima primero y `@timestamp` UTC tal cual. */
export const CSV_COLUMNS: ReadonlyArray<readonly [string, string]> = [
  ['hora_lima', ''],
  ['@timestamp', '@timestamp'],
  ['ingested_at', 'ingested_at'],
  ['dataset', 'event.dataset'],
  ['fuente', 'event.source'],
  ['muestreado', 'event.sampled'],
  ['intervalo_muestreo', 'event.sample_interval'],
  ['historico', 'event.history'],
  ['zona', 'zone.name'],
  ['ip_cliente', 'client.ip'],
  ['pais', 'client.country'],
  ['asn', 'client.asn'],
  ['asn_nombre', 'client.asn_name'],
  ['metodo', 'http.method'],
  ['host', 'http.host'],
  ['ruta', 'http.path'],
  ['query', 'http.query'],
  ['uri', 'http.uri'],
  ['estado', 'http.status'],
  ['estado_origen', 'http.origin_status'],
  ['accion_seguridad', 'http.security_action'],
  ['fuente_seguridad', 'http.security_source'],
  ['ray', 'http.ray'],
  ['cache', 'http.cache'],
  ['protocolo', 'http.protocol'],
  ['tls', 'http.tls'],
  ['bytes', 'http.bytes'],
  ['user_agent', 'http.user_agent'],
  ['referer', 'http.referer'],
  ['dns_consulta', 'dns.query'],
  ['dns_tipo', 'dns.type'],
  ['dns_rcode', 'dns.rcode'],
  ['dns_colo', 'dns.colo'],
  ['dns_cache', 'dns.cached'],
  ['dns_protocolo', 'dns.protocol'],
  ['firewall_accion', 'firewall.action'],
  ['firewall_fuente', 'firewall.source'],
  ['firewall_regla', 'firewall.rule_id'],
  ['firewall_descripcion', 'firewall.description'],
  ['firewall_ray', 'firewall.ray'],
  ['auditoria_accion', 'audit.action'],
  ['auditoria_resultado', 'audit.result'],
  ['auditoria_actor', 'audit.actor_email'],
  ['auditoria_ip_actor', 'audit.actor_ip'],
  ['auditoria_recurso', 'audit.resource_type'],
  ['auditoria_zona', 'audit.zone_name'],
  ['auditoria_id', 'audit.id'],
];

/** Valor de un campo con puntos, tanto anidado (`{http:{host}}`) como plano (`"http.host"`). */
export function fieldValue(source: Readonly<Record<string, unknown>>, dotted: string): unknown {
  if (Object.prototype.hasOwnProperty.call(source, dotted)) return source[dotted];
  const parts = dotted.split('.');
  let current: unknown = source;
  for (let index = 0; index < parts.length; index += 1) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return undefined;
    const record = current as Record<string, unknown>;
    // Prefijo plano restante (`{http: {"path.text": …}}` no aplica, pero sí `{"http.host": …}`).
    const rest = parts.slice(index).join('.');
    if (index > 0 && Object.prototype.hasOwnProperty.call(record, rest)) return record[rest];
    current = record[parts[index]];
  }
  return current;
}

/** Celda CSV (RFC 4180) a prueba de inyección de fórmulas en Excel/Sheets. */
export function csvCell(value: unknown): string {
  if (value === undefined || value === null) return '';
  let textValue =
    typeof value === 'object' ? JSON.stringify(value) : String(value as string | number | boolean);
  if (/^[=+\-@\t\r]/u.test(textValue)) textValue = `'${textValue}`;
  return /[",\r\n]/u.test(textValue) ? `"${textValue.replace(/"/gu, '""')}"` : textValue;
}

export function csvHeader(): string {
  return `${CSV_COLUMNS.map(([name]) => name).join(',')}\r\n`;
}

export function csvRow(source: Readonly<Record<string, unknown>>): string {
  return `${CSV_COLUMNS.map(([name, field]) => {
    if (name === 'hora_lima') {
      const at = fieldValue(source, '@timestamp');
      return csvCell(typeof at === 'string' ? limaTime(at) : '');
    }
    return csvCell(fieldValue(source, field));
  }).join(',')}\r\n`;
}
