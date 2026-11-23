/** Lee hallazgos RCF recientes por el gateway allowlist y los entrega al pipeline idempotente SOC. */
import { createHash } from 'node:crypto';

import { validateSecurityEvent, type SecurityEvent } from '@b89/contracts';
import { deterministicUuid7 } from '@b89/telemetry';

import { NotificationDispatcher } from './notification-dispatcher.js';

const POLL_MS = 5_000;
const REQUEST_TIMEOUT_MS = 4_000;
const INITIAL_LOOKBACK_MS = 15 * 60_000;
const OVERLAP_MS = 2 * 60_000;
const PAGE_SIZE = 200;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MIN_GRADE = 0.8;
const MIN_CONFIDENCE = 0.9;
const DETECTOR_CACHE_MS = 5 * 60_000;

type DetectorPresentation = {
  readonly name: string;
  readonly title: string;
  readonly vendor: string;
  readonly product: string;
  readonly category: SecurityEvent['category'][number];
};

const PRESENTATION: Readonly<Record<string, Omit<DetectorPresentation, 'name'>>> = Object.freeze({
  'b89-cf-backoffice-exports': {
    title: 'Descarga inusual de datos del backoffice', vendor: 'Cloudflare', product: 'Cloudflare Logpush', category: 'file',
  },
  'b89-cf-backoffice-per-ip': {
    title: 'Actividad inusual desde una IP en el backoffice', vendor: 'Cloudflare', product: 'Cloudflare Logpush', category: 'network',
  },
  'b89-cf-money-movement': {
    title: 'Actividad inusual en operaciones de pagos', vendor: 'Cloudflare', product: 'Cloudflare Logpush', category: 'api',
  },
  'b89-cf-payments-errors': {
    title: 'Aumento inusual de errores en pagos', vendor: 'Cloudflare', product: 'Cloudflare Logpush', category: 'web',
  },
  'b89-m365-login-failures': {
    title: 'Aumento inusual de inicios de sesión fallidos', vendor: 'Microsoft', product: 'Microsoft 365', category: 'authentication',
  },
  'b89-m365-file-downloads': {
    title: 'Descarga inusual de archivos de SharePoint', vendor: 'Microsoft', product: 'Microsoft 365', category: 'file',
  },
  'b89-agent-alert-volume': {
    title: 'Aumento inusual de alertas en un equipo', vendor: 'Wazuh', product: 'Wazuh endpoint monitoring', category: 'host',
  },
  'b89-logins-per-user': {
    title: 'Aumento inusual de inicios de sesión de una cuenta', vendor: 'Wazuh', product: 'Wazuh authentication monitoring', category: 'authentication',
  },
  'b89-provider-aws-activity': {
    title: 'Aumento inusual de actividad de riesgo en AWS', vendor: 'Amazon Web Services', product: 'AWS', category: 'threat',
  },
  'b89-provider-bitdefender-activity': {
    title: 'Actividad inusual de protección de endpoint', vendor: 'Bitdefender', product: 'GravityZone', category: 'malware',
  },
  'b89-provider-snyk-activity': {
    title: 'Aumento inusual de hallazgos de vulnerabilidad', vendor: 'Snyk', product: 'Snyk', category: 'vulnerability',
  },
});

type JsonObject = Record<string, unknown>;
type SearchHit = { readonly _id?: unknown; readonly _source?: unknown; readonly sort?: readonly unknown[] };

function object(value: unknown): JsonObject | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function timestamp(value: unknown): Date | undefined {
  const millis = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isSafeInteger(millis) || millis < 0) return undefined;
  const date = new Date(millis);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function safeText(value: unknown, maximum = 256): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  return [...value].filter((char) => {
    const code = char.codePointAt(0);
    return code !== undefined && code >= 32 && code !== 127;
  }).join('').slice(0, maximum) || undefined;
}

function mappedPresentation(name: string): DetectorPresentation | undefined {
  const mapped = PRESENTATION[name];
  return mapped ? { name, ...mapped } : undefined;
}

function parseEntity(raw: unknown): {
  identities: SecurityEvent['entities']['identities'];
  resources: SecurityEvent['entities']['resources'];
} {
  const entities = Array.isArray(raw) ? raw.slice(0, 8).map(object).filter(Boolean) : [];
  const identities: SecurityEvent['entities']['identities'][number][] = [];
  const resources: SecurityEvent['entities']['resources'][number][] = [];
  for (const entity of entities) {
    const field = safeText(entity!.name, 128);
    const value = safeText(entity!.value);
    if (!field || !value) continue;
    const lower = field.toLowerCase();
    if (lower.includes('user') || lower.includes('principal') || lower.includes('upn')) {
      identities.push({ kind: 'user', name: value, ...(value.includes('@') ? { principal: value } : {}) });
    } else if (lower.endsWith('.ip') || lower === 'client.ip' || lower === 'source.ip') {
      resources.push({ kind: 'ip', id: value, name: value, type: 'ip' });
    } else {
      resources.push({ kind: lower.includes('host') || lower.includes('agent') ? 'host' : 'service', name: value, type: field });
    }
  }
  return { identities, resources };
}

function eventFromHit(input: {
  readonly hit: SearchHit;
  readonly tenantId: string;
  readonly sourceId: string;
  readonly now: Date;
  readonly presentation: DetectorPresentation;
}): SecurityEvent | undefined {
  const source = object(input.hit._source);
  const resultId = safeText(input.hit._id, 256);
  if (!source || !resultId) return undefined;
  const detectorId = safeText(source.detector_id, 256);
  const occurredAt = timestamp(source.approx_anomaly_start_time) ?? timestamp(source.data_end_time);
  const executionAt = timestamp(source.execution_end_time);
  const grade = typeof source.anomaly_grade === 'number' ? source.anomaly_grade : NaN;
  const confidence = typeof source.confidence === 'number' ? source.confidence : NaN;
  if (!detectorId || !occurredAt || !executionAt || !Number.isFinite(grade) || !Number.isFinite(confidence)) return undefined;
  const canonical = JSON.stringify(source);
  const identity = parseEntity(source.entity);
  const episodeWindowMs = 30 * 60_000;
  const episodeAt = new Date(Math.floor(occurredAt.getTime() / episodeWindowMs) * episodeWindowMs);
  const entityKey = JSON.stringify(identity);
  const episodeId = createHash('sha256').update(`${detectorId}\0${entityKey}\0${episodeAt.toISOString()}`).digest('hex');
  const recordId = deterministicUuid7(`b89-ad:${input.tenantId}`, episodeId, episodeAt);
  const featureData = Array.isArray(source.feature_data)
    ? source.feature_data.slice(0, 16).map(object).filter(Boolean).map((feature) => ({
        name: safeText(feature!.feature_name ?? feature!.feature_id, 128) ?? 'feature',
        value: typeof feature!.data === 'number' && Number.isFinite(feature!.data) ? feature!.data : null,
      }))
    : [];
  const event: SecurityEvent = {
    schemaVersion: '1.0.0',
    recordId,
    eventUid: `opensearch-ad:${episodeId}`,
    eventUidType: 'derived',
    kind: 'finding',
    occurredAt: occurredAt.toISOString(),
    observedAt: input.now.toISOString(),
    receivedAt: input.now.toISOString(),
    source: {
      kind: 'siem', vendor: input.presentation.vendor, product: input.presentation.product,
      dataset: 'anomaly-detection', instanceId: input.sourceId, nativeEventId: resultId,
    },
    tenant: { id: input.tenantId },
    severity: {
      normalized: 'medium', score: 50, originalValue: grade,
      originalLabel: `Desviación ${Math.round(grade * 100)} %, confianza ${Math.round(confidence * 100)} %`,
      originalScale: 'opensearch-anomaly-grade-0-1', mappingId: 'b89.opensearch-ad.severity', mappingVersion: '1.0.0',
    },
    category: [input.presentation.category],
    outcome: 'unknown', action: 'anomaly.detected',
    entities: identity,
    detection: { rule: {
      id: detectorId, name: input.presentation.title, provider: 'OpenSearch Anomaly Detection',
      version: '1', groups: ['anomaly_detection', input.presentation.vendor.toLowerCase().replaceAll(' ', '_')],
    } },
    raw: {
      ref: `raw:opensearch-ad/${encodeURIComponent(resultId)}`,
      sha256: createHash('sha256').update(canonical).digest('hex'),
      mediaType: 'application/json', sizeBytes: Buffer.byteLength(canonical, 'utf8'),
    },
    provenance: {
      connector: 'opensearch-anomaly-detection', connectorVersion: '1.0.0',
      parserVersion: '1.0.0', mappingVersion: '1.0.0', timestampQuality: 'source',
      ingestionPath: [
        { kind: 'origin', vendor: input.presentation.vendor, product: input.presentation.product },
        { kind: 'adapter', vendor: 'OpenSearch', product: 'Anomaly Detection' },
        { kind: 'adapter', vendor: 'B89', product: 'SOC' },
      ],
    },
    extensions: {
      'b89.opensearch-ad': {
        resultId, detectorId, grade, confidence,
        anomalyScore: typeof source.anomaly_score === 'number' ? source.anomaly_score : null,
        dataStartTime: timestamp(source.data_start_time)?.toISOString() ?? null,
        dataEndTime: timestamp(source.data_end_time)?.toISOString() ?? null,
        executionEndTime: executionAt.toISOString(), featureData,
      },
    },
  };
  const validated = validateSecurityEvent(event);
  return validated.valid ? validated.value : undefined;
}

export interface OpenSearchAnomalyIngestionOptions {
  readonly gatewayBaseUrl: string;
  readonly accessToken: () => Promise<string>;
  readonly tenantId: string;
  readonly sourceId: string;
  readonly now: () => Date;
  readonly promote: (event: SecurityEvent) => Promise<unknown>;
  readonly onError: (error: unknown) => void;
}

/**
 * Polls the OpenSearch result index with an overlap and stable search_after pagination.
 * Only the versioned B89 detector catalog is promoted; unknown detectors remain in OpenSearch.
 */
export function createOpenSearchAnomalyIngestion(options: OpenSearchAnomalyIngestionOptions): NotificationDispatcher {
  const baseUrl = options.gatewayBaseUrl.replace(/\/+$/u, '');
  let watermark = options.now().getTime() - INITIAL_LOOKBACK_MS;
  let searchAfter: readonly unknown[] | undefined;
  let detectorCache: { readonly at: number; readonly byId: ReadonlyMap<string, DetectorPresentation> } | undefined;

  const post = async (path: string, body: unknown): Promise<JsonObject> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const token = await options.accessToken();
      const response = await fetch(`${baseUrl}${path}`, {
        method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify(body), signal: controller.signal,
      });
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw Object.assign(new Error('ANOMALY_RESPONSE_TOO_LARGE'), { code: 'ANOMALY_RESPONSE_TOO_LARGE', retryable: true });
      if (!response.ok) throw Object.assign(new Error(`ANOMALY_GATEWAY_HTTP_${response.status}`), { code: `ANOMALY_GATEWAY_HTTP_${response.status}`, retryable: response.status >= 500 });
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { throw Object.assign(new Error('ANOMALY_RESPONSE_INVALID'), { code: 'ANOMALY_RESPONSE_INVALID', retryable: true }); }
      const result = object(parsed);
      if (!result) throw Object.assign(new Error('ANOMALY_RESPONSE_INVALID'), { code: 'ANOMALY_RESPONSE_INVALID', retryable: true });
      return result;
    } catch (error) {
      if (error instanceof Error && 'code' in error) throw error;
      throw Object.assign(new Error('ANOMALY_GATEWAY_UNAVAILABLE'), { code: 'ANOMALY_GATEWAY_UNAVAILABLE', retryable: true });
    } finally { clearTimeout(timeout); }
  };

  const detectors = async (): Promise<ReadonlyMap<string, DetectorPresentation>> => {
    const now = options.now().getTime();
    if (detectorCache && now - detectorCache.at < DETECTOR_CACHE_MS) return detectorCache.byId;
    const body = await post('/wazuh/anomaly-detectors/_search', {
      size: 1000, query: { prefix: { 'name.keyword': 'b89-' } },
      _source: ['name', 'enabled'], sort: [{ 'name.keyword': 'asc' }],
    });
    const hits = object(body.hits);
    const rows = Array.isArray(hits?.hits) ? hits!.hits as SearchHit[] : [];
    const byId = new Map<string, DetectorPresentation>();
    for (const hit of rows) {
      const id = safeText(hit._id, 256);
      const metadata = object(hit._source);
      const name = safeText(metadata?.name, 128);
      const enabled = metadata?.enabled;
      const presentation = name ? mappedPresentation(name) : undefined;
      if (id && presentation && enabled !== false) byId.set(id, presentation);
    }
    detectorCache = { at: now, byId };
    return byId;
  };

  const drain = async (): Promise<number> => {
    const knownDetectors = await detectors();
    const now = options.now();
    const from = Math.max(now.getTime() - INITIAL_LOOKBACK_MS, watermark - OVERLAP_MS);
    const body = await post('/wazuh/anomaly-results/_search', {
      size: PAGE_SIZE,
      track_total_hits: false,
      _source: [
        'detector_id', 'data_start_time', 'data_end_time', 'execution_start_time', 'execution_end_time',
        'approx_anomaly_start_time', 'anomaly_score', 'anomaly_grade', 'confidence', 'entity', 'model_id', 'feature_data',
      ],
      query: { bool: { filter: [
        { range: { execution_end_time: { gte: from, lte: now.getTime() } } },
        { range: { anomaly_grade: { gte: MIN_GRADE } } },
        { range: { confidence: { gte: MIN_CONFIDENCE } } },
      ] } },
      sort: [
        { execution_end_time: 'asc' }, { detector_id: 'asc' },
        { data_end_time: 'asc' }, { model_id: 'asc' },
      ],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    });
    const hits = Array.isArray(object(body.hits)?.hits) ? object(body.hits)!.hits as SearchHit[] : [];
    let newest = watermark;
    for (const hit of hits) {
      const executionAt = timestamp(object(hit._source)?.execution_end_time);
      if (executionAt) newest = Math.max(newest, executionAt.getTime());
      const detectorId = safeText(object(hit._source)?.detector_id, 256);
      const presentation = detectorId ? knownDetectors.get(detectorId) : undefined;
      if (!presentation) continue;
      const event = eventFromHit({ hit, tenantId: options.tenantId, sourceId: options.sourceId, now, presentation });
      if (event) await options.promote(event);
    }
    if (hits.length === PAGE_SIZE) {
      const tail = hits[hits.length - 1];
      if (!tail?.sort || tail.sort.length !== 4) throw Object.assign(new Error('ANOMALY_CURSOR_INVALID'), { code: 'ANOMALY_CURSOR_INVALID', retryable: true });
      searchAfter = tail.sort;
      return 1;
    }
    watermark = Math.max(watermark, newest, now.getTime());
    searchAfter = undefined;
    return 0;
  };

  return new NotificationDispatcher({ drain, intervalMs: POLL_MS, errorIntervalMs: 30_000, onError: options.onError });
}
