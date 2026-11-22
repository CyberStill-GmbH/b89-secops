/**
 * Señales de salud por fuente sobre `wazuh-alerts-*` (docs/20 «Salud por fuente»): una sola
 * búsqueda `size: 0`, acotada por construcción.
 *
 * - Latidos (`rule.groups: b89_source_health`): `terms` por `data.b89.heartbeat.source_id` con
 *   `top_hits` de tamaño fijo (solo `timestamp` y `data.b89.heartbeat`) y la última hora con
 *   `auth: ok`.
 * - Datos por fuente: un `filter` por selector de la allowlist (sin latidos ni canarios), con el
 *   último `timestamp` y un `date_range` de la ventana actual y la misma ventana N semanas atrás.
 * - Retención: el mismo `date_range` sobre todo el índice; una ventana histórica sin ningún
 *   documento no es «cero eventos» sino «sin dato».
 * - Canarios: último `timestamp` por `rule.id` de la allowlist.
 */

import {
  SecurityEventProviderError,
  type HeartbeatSample,
  type SourceDataSelector,
  type SourceSignalReading,
  type SourceSignalsQuery,
  type SourceSignalsReport,
} from '../../application/security-event-provider.js';

export const SOURCE_HEALTH_GROUP = 'b89_source_health';
const CANARY_GROUP = 'b89_canary';
const MAX_SOURCES = 16;
const MAX_HEARTBEAT_IDS = 20;
const MAX_SAMPLES = 10;
const MAX_WEEKS = 4;
const WEEK_MS = 7 * 24 * 3_600_000;
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const RULE_ID = /^\d{3,6}$/u;
const SELECTOR_VALUE = /^[A-Za-z0-9._-]{1,64}$/u;
const FIELD: Readonly<Record<'office365.subscription' | 'b89.source', string>> = {
  'office365.subscription': 'data.office365.Subscription',
  'b89.source': 'data.b89.source',
};

type Json = Record<string, unknown>;

function reject(): never {
  throw new SecurityEventProviderError('PROVIDER_QUERY_REJECTED', 'readPage', false);
}

function invalid(): never {
  throw new SecurityEventProviderError('PROVIDER_RESPONSE_INVALID', 'readPage', false);
}

function selectorClause(selector: SourceDataSelector): Json {
  switch (selector.kind) {
    case 'rule_group':
      if (!SELECTOR_VALUE.test(selector.value)) reject();
      return { term: { 'rule.groups': selector.value } };
    case 'field': {
      const field = FIELD[selector.field];
      if (
        !field ||
        selector.values.length === 0 ||
        selector.values.length > 8 ||
        selector.values.some((value) => !SELECTOR_VALUE.test(value))
      )
        reject();
      return { terms: { [field]: [...selector.values] } };
    }
    case 'agents':
      // Los eventos de agentes: todo lo que no analiza el propio manager (agente 000).
      return { bool: { must: [{ exists: { field: 'agent.id' } }], must_not: [{ term: { 'agent.id': '000' } }] } };
    default:
      return reject();
  }
}

/** Ventanas `w0` (actual) y `w1..wN` (misma ventana N semanas atrás). */
export function signalWindows(
  now: number,
  windowMs: number,
  weeks: number,
): { key: string; from: string; to: string }[] {
  return Array.from({ length: weeks + 1 }, (_, index) => ({
    key: `w${index}`,
    from: new Date(now - index * WEEK_MS - windowMs).toISOString(),
    to: new Date(now - index * WEEK_MS).toISOString(),
  }));
}

export function buildSourceSignalsQuery(query: SourceSignalsQuery, maxRangeMs: number): Json {
  const now = Date.parse(query.now);
  const heartbeatIds = [...new Set(query.sources.flatMap((source) => source.heartbeatIds))];
  const canaries = [...new Set(query.sources.flatMap((source) => source.canaryRuleIds))];
  if (
    !Number.isFinite(now) ||
    query.sources.length === 0 ||
    query.sources.length > MAX_SOURCES ||
    query.sources.some((source) => !ID.test(source.id)) ||
    heartbeatIds.length > MAX_HEARTBEAT_IDS ||
    heartbeatIds.some((id) => !ID.test(id)) ||
    canaries.some((id) => !RULE_ID.test(id)) ||
    !Number.isInteger(query.heartbeatSamples) ||
    query.heartbeatSamples < 1 ||
    query.heartbeatSamples > MAX_SAMPLES ||
    !Number.isInteger(query.baselineWeeks) ||
    query.baselineWeeks < 1 ||
    query.baselineWeeks > MAX_WEEKS ||
    !(query.volumeWindowMs >= 60_000 && query.volumeWindowMs <= 24 * 3_600_000) ||
    !(query.heartbeatLookbackMs >= 60_000)
  )
    reject();
  const windows = signalWindows(now, query.volumeWindowMs, query.baselineWeeks);
  const oldest = Math.min(
    Date.parse(windows[windows.length - 1]!.from),
    now - query.heartbeatLookbackMs,
  );
  if (now - oldest > maxRangeMs) reject();
  const ranges = { date_range: { field: 'timestamp', ranges: windows } };
  const notHealth = [
    { term: { 'rule.groups': SOURCE_HEALTH_GROUP } },
    { term: { 'rule.groups': CANARY_GROUP } },
  ];
  const aggs: Json = {
    retention: ranges,
    ...(heartbeatIds.length > 0
      ? {
          heartbeats: {
            filter: {
              bool: {
                filter: [
                  { term: { 'rule.groups': SOURCE_HEALTH_GROUP } },
                  {
                    range: {
                      timestamp: {
                        gte: new Date(now - query.heartbeatLookbackMs).toISOString(),
                        lte: query.now,
                      },
                    },
                  },
                ],
              },
            },
            aggs: {
              ids: {
                terms: {
                  field: 'data.b89.heartbeat.source_id',
                  include: heartbeatIds,
                  size: heartbeatIds.length,
                },
                aggs: {
                  recent: {
                    top_hits: {
                      size: query.heartbeatSamples,
                      sort: [{ timestamp: { order: 'desc' } }],
                      _source: ['timestamp', 'data.b89.heartbeat'],
                    },
                  },
                  auth_ok: {
                    filter: { term: { 'data.b89.heartbeat.auth': 'ok' } },
                    aggs: { last: { max: { field: 'timestamp' } } },
                  },
                },
              },
            },
          },
        }
      : {}),
    ...(canaries.length > 0
      ? {
          canaries: {
            filter: { terms: { 'rule.id': canaries } },
            aggs: {
              ids: {
                terms: { field: 'rule.id', include: canaries, size: canaries.length },
                aggs: { last: { max: { field: 'timestamp' } } },
              },
            },
          },
        }
      : {}),
  };
  query.sources.forEach((source, index) => {
    aggs[`s${index}`] = {
      filter: { bool: { filter: [selectorClause(source.data)], must_not: notHealth } },
      aggs: { last: { max: { field: 'timestamp' } }, windows: ranges },
    };
  });
  return {
    size: 0,
    track_total_hits: false,
    query: {
      range: { timestamp: { gte: new Date(oldest).toISOString(), lte: query.now } },
    },
    aggs,
  };
}

function obj(value: unknown): Json {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Json)
    : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, max = 64): string | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  return value.slice(0, max);
}

function count(value: unknown): number | null {
  const number = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  return typeof number === 'number' && Number.isFinite(number) && number >= 0
    ? Math.floor(number)
    : null;
}

function flag(value: unknown): boolean | null {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false') return false;
  return null;
}

function isoText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value.replace(/([+-])(\d{2})(\d{2})$/u, '$1$2:$3'));
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function maxDate(aggregation: unknown): string | null {
  const value = obj(aggregation)['value'];
  return typeof value === 'number' && Number.isFinite(value) ? new Date(value).toISOString() : null;
}

function windowCounts(aggregation: unknown, size: number): (number | null)[] {
  const buckets = list(obj(aggregation)['buckets']);
  if (buckets.length !== size) invalid();
  const byKey = new Map(buckets.map((bucket) => [obj(bucket)['key'], count(obj(bucket)['doc_count'])]));
  return Array.from({ length: size }, (_, index) => byKey.get(`w${index}`) ?? null);
}

function heartbeatOf(hit: unknown): HeartbeatSample | null {
  const source = obj(obj(hit)['_source']);
  const beat = obj(obj(obj(source['data'])['b89'])['heartbeat']);
  const indexedAt = isoText(source['timestamp']);
  const sourceId = text(beat['source_id']);
  if (!indexedAt || !sourceId) return null;
  const rawContent = obj(beat['content']);
  const content: Record<string, { enabled: boolean | null; lastBlobAt: string | null }> = {};
  for (const [key, value] of Object.entries(rawContent).slice(0, 8)) {
    if (!/^[a-z]{1,16}$/u.test(key)) continue;
    content[key] = { enabled: flag(obj(value)['enabled']), lastBlobAt: isoText(obj(value)['last_blob_at']) };
  }
  return {
    indexedAt,
    sourceId,
    finishedAt: isoText(beat['finished_at']),
    outcome: text(beat['outcome'], 16),
    auth: text(beat['auth'], 16),
    httpStatusClass: text(beat['http_status_class'], 8),
    itemsFetched: count(beat['items_fetched']),
    cursorAdvanced: flag(beat['cursor_advanced']),
    cursorPosition: isoText(beat['cursor_position']),
    providerLagSeconds: count(beat['provider_lag_seconds']),
    errorCode: text(beat['error_code'], 32),
    collectorVersion: text(beat['collector_version'], 32),
    content: Object.keys(content).length > 0 ? content : null,
  };
}

export function parseSourceSignals(
  query: SourceSignalsQuery,
  body: unknown,
  measuredAt: string,
): SourceSignalsReport {
  const aggregations = obj(obj(body)['aggregations']);
  const size = query.baselineWeeks + 1;
  const retention = windowCounts(aggregations['retention'], size);
  const heartbeatsById = new Map<string, { samples: HeartbeatSample[]; authOk: string | null }>();
  for (const bucket of list(obj(obj(aggregations['heartbeats'])['ids'])['buckets'])) {
    const key = text(obj(bucket)['key']);
    if (!key) invalid();
    const hits = list(obj(obj(obj(bucket)['recent'])['hits'])['hits']);
    if (hits.length > query.heartbeatSamples) invalid();
    heartbeatsById.set(key, {
      samples: hits.map(heartbeatOf).filter((item): item is HeartbeatSample => item !== null),
      authOk: maxDate(obj(obj(bucket)['auth_ok'])['last']),
    });
  }
  const canaryById = new Map<string, string | null>();
  for (const bucket of list(obj(obj(aggregations['canaries'])['ids'])['buckets'])) {
    canaryById.set(String(obj(bucket)['key']), maxDate(obj(bucket)['last']));
  }
  const sources: SourceSignalReading[] = query.sources.map((source, index) => {
    const aggregation = aggregations[`s${index}`];
    if (aggregation === undefined) invalid();
    const counts = windowCounts(obj(aggregation)['windows'], size);
    const beats = source.heartbeatIds.flatMap((id) => heartbeatsById.get(id)?.samples ?? []);
    beats.sort((left, right) => (left.indexedAt < right.indexedAt ? 1 : -1));
    const authOk = source.heartbeatIds
      .map((id) => heartbeatsById.get(id)?.authOk ?? null)
      .filter((value): value is string => value !== null)
      .sort()
      .pop();
    const canary = source.canaryRuleIds
      .map((id) => canaryById.get(id) ?? null)
      .filter((value): value is string => value !== null)
      .sort()
      .pop();
    return {
      id: source.id,
      heartbeats: beats.slice(0, query.heartbeatSamples),
      lastAuthOkAt: authOk ?? null,
      lastEventAt: maxDate(obj(aggregation)['last']),
      currentCount: counts[0] ?? 0,
      // Sin documentos en todo el índice para esa ventana ⇒ no hay dato, no es un cero.
      baselineCounts: counts.slice(1).map((value, week) =>
        (retention[week + 1] ?? 0) > 0 ? (value ?? 0) : null,
      ),
      canaryAt: canary ?? null,
    };
  });
  return { measuredAt, sources };
}
