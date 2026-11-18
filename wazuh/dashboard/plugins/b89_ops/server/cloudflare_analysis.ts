/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  ANOMALY_DETECTOR_PREFIX,
  ANOMALY_RESULTS_INDEX,
  AnalysisRequest,
  AnomalyRow,
  AnomalySection,
  AUTH_LOGIN_PATH,
  AUTH_REFRESH_PATH,
  BACKOFFICE_HOST_PATTERNS,
  Baseline,
  BASELINE_DAYS,
  buildFindings,
  buildSession,
  Caller,
  channelOfHost,
  CloudflareAnalysis,
  EndpointRule,
  hostingProvider,
  INTEGRATION_HOSTS,
  IpStats,
  MONEY_RULES,
  MoneyBucket,
  MoneyCaller,
  moneyInterval,
  OFF_HOURS_UTC,
  rankSessions,
  SENSITIVE_READ_RULES,
  STAFF_PATH,
  WRITE_METHODS,
} from '../common/cloudflare_analysis';
import { TopBucket, TRAFFIC_INDEX } from '../common/cloudflare_traffic';
import { trafficFilterClauses } from './cloudflare_traffic';
import { readabilityOf, SearchClient } from './overview';

/**
 * `GET /api/b89_ops/cloudflare/analysis`: análisis de `b89-cloudflare-traffic-*` (HTTP) con la
 * identidad de quien mira. Tres consultas acotadas (`size: 0`, `terms` con tamaño fijo) y la
 * lectura de OpenSearch Anomaly Detection; ninguna cláusula viene del navegador.
 */

type Json = Record<string, unknown>;

/** Cliente del usuario: `search` y, si existe, `transport` (API de detectores AD). */
export interface AnalysisClient extends SearchClient {
  search(params: {
    index?: string;
    body: Json;
    expand_wildcards?: string;
    ignore_unavailable?: boolean;
  }): Promise<{ body: unknown }>;
  readonly transport?: {
    request(params: { method: string; path: string; body?: Json }): Promise<{ body: unknown }>;
  };
}

export const SESSION_IPS = 150;
export const MONEY_CALLERS = 60;
export const SENSITIVE_CALLERS = 60;
export const BASELINE_IPS = 3000;
export const ANOMALY_ROWS = 200;

/* ------------------------------------------------------------ Cláusulas */

function pathClause(pattern: string): Json {
  return { wildcard: { 'http.path': { value: pattern, case_insensitive: true } } };
}

function hostPatternClause(pattern: string): Json {
  return { wildcard: { 'http.host': { value: pattern, case_insensitive: true } } };
}

const any = (clauses: Json[]): Json => ({ bool: { should: clauses, minimum_should_match: 1 } });
const all = (clauses: Json[]): Json => ({ bool: { filter: clauses } });

export const BACKOFFICE_HOSTS_CLAUSE = any(BACKOFFICE_HOST_PATTERNS.map(hostPatternClause));
const INTEGRATION_CLAUSE: Json = { terms: { 'http.host': [...INTEGRATION_HOSTS] } };
const WRITE_CLAUSE: Json = { terms: { 'http.method': [...WRITE_METHODS] } };

function methodClause(rule: EndpointRule): Json | null {
  if (rule.methods === 'write') return WRITE_CLAUSE;
  if (rule.methods === 'read') return { term: { 'http.method': 'GET' } };
  return null;
}

/** La misma regla que `moneyMovementRule`/`sensitiveReadRule`, como consulta. */
export function rulesClause(rules: readonly EndpointRule[]): Json {
  return any(
    rules.map((rule) => {
      const method = methodClause(rule);
      const paths = any(rule.paths.map(pathClause));
      return all(method ? [method, paths] : [paths]);
    }),
  );
}

export const MONEY_CLAUSE = rulesClause(MONEY_RULES);
export const SENSITIVE_CLAUSE = rulesClause(SENSITIVE_READ_RULES);
const STATUS_2XX: Json = { range: { 'http.status': { gte: 200, lte: 299 } } };
const LOGIN_OK = all([
  { term: { 'http.method': 'POST' } },
  pathClause(AUTH_LOGIN_PATH),
  STATUS_2XX,
]);
const LOGIN_FAILED = all([
  { term: { 'http.method': 'POST' } },
  pathClause(AUTH_LOGIN_PATH),
  { range: { 'http.status': { gte: 400, lte: 499 } } },
]);

/** 22:00–05:59 de Lima: horas UTC 03–10 (Lima no tiene horario de verano). */
export const OFF_HOURS_SCRIPT: Json = {
  script: {
    script: {
      lang: 'painless',
      source:
        "if (doc['@timestamp'].size() == 0) { return false; } int h = doc['@timestamp'].value.getHour(); return h >= params.from && h <= params.to;",
      params: { from: OFF_HOURS_UTC.from, to: OFF_HOURS_UTC.to },
    },
  },
};

function baseClauses(request: AnalysisRequest, from: string, to: string): Json[] {
  return [
    ...trafficFilterClauses({ from, to, zones: request.zones, datasets: [] }),
    { term: { 'event.dataset': 'http' } },
  ];
}

const terms = (field: string, size: number): Json => ({ terms: { field, size } });

/** Identidad de red de cada IP: país, ASN y su nombre, primera y última vez. */
const IDENTITY_AGGS: Json = {
  country: terms('client.country', 1),
  asn: terms('client.asn', 1),
  asn_name: terms('client.asn_name', 1),
  first: { min: { field: '@timestamp' } },
  last: { max: { field: '@timestamp' } },
};

function callerAggs(extra: Json = {}): Json {
  return {
    ...IDENTITY_AGGS,
    endpoints: terms('http.path', 5),
    statuses: terms('http.status', 6),
    user_agents: terms('http.user_agent', 3),
    hosts: terms('http.host', 4),
    ...extra,
  };
}

/** Consulta principal del rango: sesiones del backoffice, dinero y lecturas sensibles. */
export function analysisBody(request: AnalysisRequest): Json {
  return {
    size: 0,
    track_total_hits: true,
    timeout: '30s',
    query: { bool: { filter: baseClauses(request, request.from, request.to) } },
    aggs: {
      sampled: { filter: { term: { 'event.sampled': true } } },
      backoffice: {
        filter: BACKOFFICE_HOSTS_CLAUSE,
        aggs: {
          ips: {
            terms: { field: 'client.ip', size: SESSION_IPS },
            aggs: {
              ...IDENTITY_AGGS,
              logins: { filter: LOGIN_OK },
              logins_failed: { filter: LOGIN_FAILED },
              refreshes: { filter: pathClause(AUTH_REFRESH_PATH) },
              staff_ok: { filter: all([pathClause(STAFF_PATH), STATUS_2XX]) },
              staff_denied: {
                filter: all([pathClause(STAFF_PATH), { term: { 'http.status': 403 } }]),
              },
              writes: { filter: all([pathClause(STAFF_PATH), WRITE_CLAUSE]) },
              exports: { filter: pathClause('*export*') },
              money: { filter: MONEY_CLAUSE },
              ua_count: { cardinality: { field: 'http.user_agent' } },
              user_agents: terms('http.user_agent', 3),
              hosts: terms('http.host', 6),
            },
          },
        },
      },
      money: {
        filter: MONEY_CLAUSE,
        aggs: {
          histogram: {
            date_histogram: {
              field: '@timestamp',
              fixed_interval: moneyInterval(request.from, request.to),
              time_zone: 'America/Lima',
              min_doc_count: 0,
              extended_bounds: { min: request.from, max: request.to },
            },
            aggs: {
              backoffice: { filter: BACKOFFICE_HOSTS_CLAUSE },
              integration: { filter: INTEGRATION_CLAUSE },
            },
          },
          backoffice: { filter: BACKOFFICE_HOSTS_CLAUSE },
          integration: { filter: INTEGRATION_CLAUSE },
          callers: {
            terms: { field: 'client.ip', size: MONEY_CALLERS },
            aggs: callerAggs({ off_hours: { filter: OFF_HOURS_SCRIPT } }),
          },
        },
      },
      sensitive: {
        filter: SENSITIVE_CLAUSE,
        aggs: {
          callers: { terms: { field: 'client.ip', size: SENSITIVE_CALLERS }, aggs: callerAggs() },
        },
      },
    },
  };
}

/** Línea base: los 14 días anteriores al inicio del rango. */
export function baselineRange(request: AnalysisRequest): { from: string; to: string } {
  const start = Date.parse(request.from);
  return {
    from: new Date(start - BASELINE_DAYS * 24 * 3600 * 1000).toISOString(),
    to: new Date(start - 1).toISOString(),
  };
}

export function baselineBody(request: AnalysisRequest): Json {
  const range = baselineRange(request);
  return {
    size: 0,
    track_total_hits: false,
    timeout: '30s',
    query: { bool: { filter: baseClauses(request, range.from, range.to) } },
    aggs: {
      backoffice: {
        filter: BACKOFFICE_HOSTS_CLAUSE,
        aggs: {
          ips: terms('client.ip', BASELINE_IPS),
          login_countries: { filter: LOGIN_OK, aggs: { countries: terms('client.country', 250) } },
        },
      },
      money: { filter: MONEY_CLAUSE, aggs: { ips: terms('client.ip', BASELINE_IPS) } },
    },
  };
}

/* ------------------------------------------------------------- Lectura */

function obj(value: unknown): Json {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : {};
}
function num(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}
function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function topBuckets(aggregation: unknown): TopBucket[] {
  return list(obj(aggregation).buckets)
    .map((bucket) => ({
      key: String(obj(bucket).key_as_string ?? obj(bucket).key ?? ''),
      count: num(obj(bucket).doc_count),
    }))
    .filter((bucket) => bucket.key !== '');
}

function firstKey(aggregation: unknown): string | null {
  return topBuckets(aggregation)[0]?.key ?? null;
}

function isoOf(aggregation: unknown): string | null {
  const value = obj(aggregation).value;
  return typeof value === 'number' && Number.isFinite(value) ? new Date(value).toISOString() : null;
}

function identity(bucket: Json) {
  const asn = firstKey(bucket.asn);
  const asnName = firstKey(bucket.asn_name);
  return {
    ip: String(bucket.key ?? ''),
    country: firstKey(bucket.country),
    asn: asn !== null && /^\d+$/u.test(asn) ? Number(asn) : null,
    asnName,
    firstSeen: isoOf(bucket.first),
    lastSeen: isoOf(bucket.last),
  };
}

const docs = (bucket: Json, name: string) => num(obj(bucket[name]).doc_count);

export function parseIpStats(bucket: unknown): IpStats {
  const item = obj(bucket);
  return {
    ...identity(item),
    requests: num(item.doc_count),
    logins: docs(item, 'logins'),
    loginsFailed: docs(item, 'logins_failed'),
    refreshes: docs(item, 'refreshes'),
    staffOk: docs(item, 'staff_ok'),
    staffDenied: docs(item, 'staff_denied'),
    writes: docs(item, 'writes'),
    exports: docs(item, 'exports'),
    moneyCalls: docs(item, 'money'),
    userAgents: num(obj(item.ua_count).value),
    topUserAgents: topBuckets(item.user_agents).map((entry) => entry.key),
    hosts: topBuckets(item.hosts).map((entry) => entry.key),
  };
}

export function parseCaller(bucket: unknown): Caller {
  const item = obj(bucket);
  const base = identity(item);
  return {
    ...base,
    hosting: hostingProvider(base.asnName, base.asn),
    count: num(item.doc_count),
    endpoints: topBuckets(item.endpoints),
    statuses: topBuckets(item.statuses),
    userAgents: topBuckets(item.user_agents),
    hosts: topBuckets(item.hosts),
  };
}

function channelOfCaller(caller: Caller): MoneyCaller['channel'] {
  const channels = new Set(caller.hosts.map((host) => channelOfHost(host.key)));
  if (channels.size === 1) return Array.from(channels)[0];
  return channels.size === 0 ? 'other' : 'mixed';
}

export function parseBaseline(body: unknown): Baseline {
  const aggs = obj(obj(body).aggregations);
  const keys = (aggregation: unknown) =>
    new Set(topBuckets(aggregation).map((bucket) => bucket.key));
  const backoffice = obj(aggs.backoffice);
  return {
    available: true,
    backofficeIps: keys(backoffice.ips),
    moneyIps: keys(obj(aggs.money).ips),
    loginCountries: keys(obj(backoffice.login_countries).countries),
  };
}

export const NO_BASELINE: Baseline = {
  available: false,
  backofficeIps: new Set(),
  moneyIps: new Set(),
  loginCountries: new Set(),
};

function isPartial(body: Json): boolean {
  return body.timed_out === true || num(obj(body._shards).failed) > 0;
}

/** Une la respuesta principal y la línea base en el análisis (sin la sección de anomalías). */
export function assembleAnalysis(
  request: AnalysisRequest,
  mainBody: unknown,
  baseline: Baseline,
  anomalies: AnomalySection,
  now: Date = new Date(),
): CloudflareAnalysis {
  const body = obj(mainBody);
  const aggs = obj(body.aggregations);
  const sessions = rankSessions(
    list(obj(obj(aggs.backoffice).ips).buckets).map((bucket) =>
      buildSession(parseIpStats(bucket), baseline),
    ),
  );
  const money = obj(aggs.money);
  const histogram: MoneyBucket[] = list(obj(money.histogram).buckets).map((bucket) => {
    const item = obj(bucket);
    return {
      at: new Date(num(item.key)).toISOString(),
      backoffice: docs(item, 'backoffice'),
      integration: docs(item, 'integration'),
    };
  });
  const callers: MoneyCaller[] = list(obj(money.callers).buckets).map((bucket) => {
    const caller = parseCaller(bucket);
    return {
      ...caller,
      channel: channelOfCaller(caller),
      offHours: docs(obj(bucket), 'off_hours'),
      newCaller: baseline.available ? !baseline.moneyIps.has(caller.ip) : null,
    };
  });
  const sensitiveReads = list(obj(obj(aggs.sensitive).callers).buckets).map(parseCaller);
  const total = obj(obj(body.hits).total);
  return {
    generatedAt: now.toISOString(),
    from: request.from,
    to: request.to,
    zones: request.zones,
    httpRecords: num(total.value),
    sampledRecords: docs(aggs, 'sampled'),
    baseline: { ...baselineRange(request), available: baseline.available },
    findings: buildFindings({
      from: request.from,
      to: request.to,
      sessions,
      moneyCallers: callers,
      sensitiveReads,
    }),
    sessions,
    money: {
      interval: moneyInterval(request.from, request.to),
      histogram,
      totals: { backoffice: docs(money, 'backoffice'), integration: docs(money, 'integration') },
      callers,
    },
    sensitiveReads,
    anomalies,
    partial: isPartial(body),
  };
}

/* ------------------------------------------------------- Anomaly Detection */

export const DETECTORS_PATH = '/_plugins/_anomaly_detection/detectors/_search';

export function anomalyResultsBody(
  request: AnalysisRequest,
  detectorIds: readonly string[] | null,
): Json {
  const filters: Json[] = [
    { range: { anomaly_grade: { gt: 0 } } },
    {
      range: {
        data_end_time: {
          gte: Date.parse(request.from),
          lte: Date.parse(request.to),
          format: 'epoch_millis',
        },
      },
    },
  ];
  if (detectorIds) filters.push({ terms: { detector_id: [...detectorIds] } });
  return {
    size: ANOMALY_ROWS,
    timeout: '20s',
    query: { bool: { filter: filters } },
    sort: [{ anomaly_grade: { order: 'desc' } }, { data_end_time: { order: 'desc' } }],
    _source: [
      'detector_id',
      'data_start_time',
      'data_end_time',
      'anomaly_grade',
      'confidence',
      'feature_data',
      'entity',
    ],
  };
}

function epochIso(value: unknown): string {
  const ms = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : '';
}

export function parseAnomalyRow(hit: unknown, names: ReadonlyMap<string, string>): AnomalyRow {
  const item = obj(hit);
  const source = obj(item._source);
  const detectorId = String(source.detector_id ?? '');
  return {
    id: String(item._id ?? ''),
    start: epochIso(source.data_start_time),
    end: epochIso(source.data_end_time),
    detectorId,
    detectorName: names.get(detectorId) ?? null,
    entity: list(source.entity).map((entry) => ({
      name: String(obj(entry).name ?? ''),
      value: String(obj(entry).value ?? ''),
    })),
    grade: num(source.anomaly_grade),
    confidence: num(source.confidence),
    features: list(source.feature_data).map((entry) => {
      const value = obj(entry).data;
      return {
        name: String(obj(entry).feature_name ?? obj(entry).feature_id ?? ''),
        value: typeof value === 'number' && Number.isFinite(value) ? value : null,
      };
    }),
  };
}

const statusOf = (error: unknown) =>
  num(obj(error).statusCode) || num(obj(obj(error).meta).statusCode);

/**
 * Detectores `b89-cf-*` y sus resultados con anomaly_grade > 0 en el rango. Si el rol no puede
 * listar detectores, se leen igualmente los resultados (identificados por `detector_id`).
 */
export async function loadAnomalies(
  client: AnalysisClient,
  request: AnalysisRequest,
): Promise<AnomalySection> {
  let detectors: Array<{ id: string; name: string }> = [];
  let resolved = false;
  if (client.transport) {
    try {
      const response = await client.transport.request({
        method: 'POST',
        path: DETECTORS_PATH,
        body: { size: 200, query: { match_all: {} }, _source: ['name'] },
      });
      detectors = list(obj(obj(response.body).hits).hits)
        .map((hit) => ({
          id: String(obj(hit)._id ?? ''),
          name: String(obj(obj(hit)._source).name ?? ''),
        }))
        .filter((detector) => detector.id && detector.name.startsWith(ANOMALY_DETECTOR_PREFIX));
      resolved = true;
    } catch {
      // 403 (sin permiso sobre AD) o plugin ausente: se siguen leyendo los resultados.
    }
  }
  if (resolved && detectors.length === 0) {
    return {
      status: 'ok',
      detectors,
      detectorsResolved: true,
      rows: [],
      message: `Aún no hay detectores ${ANOMALY_DETECTOR_PREFIX}* creados.`,
    };
  }
  try {
    const response = await client.search({
      index: ANOMALY_RESULTS_INDEX,
      // Los históricos de resultados son índices ocultos detrás del alias.
      expand_wildcards: 'open,hidden',
      ignore_unavailable: true,
      body: anomalyResultsBody(request, resolved ? detectors.map((detector) => detector.id) : null),
    });
    const names = new Map(detectors.map((detector) => [detector.id, detector.name] as const));
    const rows = list(obj(obj(response.body).hits).hits).map((hit) => parseAnomalyRow(hit, names));
    return {
      status: 'ok',
      detectors,
      detectorsResolved: resolved,
      rows,
      message: rows.length === 0 ? 'Ninguna anomalía (grado > 0) en el rango.' : null,
    };
  } catch (error) {
    const status = statusOf(error);
    if (readabilityOf(error) === 'forbidden') {
      return {
        status: 'forbidden',
        detectors,
        detectorsResolved: resolved,
        rows: [],
        message:
          'Tu rol no puede leer los resultados de Anomaly Detection (.opendistro-anomaly-results*).',
      };
    }
    return {
      status: status === 404 ? 'unavailable' : 'error',
      detectors,
      detectorsResolved: resolved,
      rows: [],
      message:
        status === 404
          ? 'Todavía no hay resultados de Anomaly Detection: los detectores aún no han producido datos.'
          : 'No se pudieron leer los resultados de Anomaly Detection.',
    };
  }
}

/* ------------------------------------------------------------ Ejecución */

export async function analyzeTraffic(
  client: AnalysisClient,
  request: AnalysisRequest,
  now: Date = new Date(),
): Promise<CloudflareAnalysis> {
  // La principal decide el 403/404 de la ruta; la línea base y AD degradan sin tumbarla.
  const main = client.search({ index: TRAFFIC_INDEX, body: analysisBody(request) });
  const baseline = client
    .search({ index: TRAFFIC_INDEX, body: baselineBody(request) })
    .then((response) => parseBaseline(response.body))
    .catch(() => NO_BASELINE);
  const anomalies = loadAnomalies(client, request);
  const [mainResponse, baselineValue, anomalySection] = await Promise.all([
    main,
    baseline,
    anomalies,
  ]);
  return assembleAnalysis(request, mainResponse.body, baselineValue, anomalySection, now);
}
