/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Hallazgos DLP (Ferrispector) leídos del SIEM: cuántos, de qué tipo, en qué equipos y los últimos,
 * más las fallas sostenidas del agente. Consulta y lectura puras; la ruta del servidor del plugin
 * las ejecuta con la identidad de quien mira (`asCurrentUser`).
 */

export const DLP_FINDINGS_ROUTE = '/api/b89_ops/dlp/findings';
export const DLP_FINDING_RULES = ['101110', '101111', '101112'] as const;
export const DLP_HEALTH_RULES = ['101114', '101116'] as const;
export const DLP_WINDOWS = ['24h', '7d', '30d'] as const;
export type DlpWindow = (typeof DLP_WINDOWS)[number];

const LATEST = 20;

export interface DlpFinding {
  readonly id: string;
  readonly at: string;
  readonly host: string;
  readonly ruleId: string;
  /** Regla de Ferrispector (`B89_CRED_GITHUB_TOKEN`, `B89_DLP_EXACT_FILE_FINGERPRINT`…). */
  readonly detector: string | null;
  readonly extension: string | null;
  readonly sizeBytes: number | null;
  readonly sha256: string | null;
}

export interface DlpFindings {
  readonly window: DlpWindow;
  readonly readable: 'ok' | 'forbidden' | 'error';
  readonly total: number;
  readonly byDetector: ReadonlyArray<{ readonly detector: string; readonly count: number }>;
  readonly byHost: ReadonlyArray<{ readonly host: string; readonly count: number }>;
  readonly latest: readonly DlpFinding[];
  /** Equipos con fallas sostenidas del agente (101114 sin política, 101116 sin poder revisar). */
  readonly agentIssues: ReadonlyArray<{ readonly host: string; readonly ruleId: string; readonly count: number; readonly last: string | null }>;
}

export function dlpWindow(value: unknown): DlpWindow {
  return (DLP_WINDOWS as readonly unknown[]).includes(value) ? (value as DlpWindow) : '7d';
}

type Json = Record<string, unknown>;

export function dlpFindingsQuery(window: DlpWindow): Json {
  const range = { range: { timestamp: { gte: `now-${window}`, lte: 'now' } } };
  return {
    size: LATEST,
    track_total_hits: true,
    sort: [{ timestamp: { order: 'desc' } }],
    _source: ['timestamp', 'agent.name', 'rule.id', 'data.endpoint', 'data.yara_rule_id', 'data.file_extension', 'data.file_size_bytes', 'data.file_sha256'],
    query: { bool: { filter: [range, { terms: { 'rule.id': [...DLP_FINDING_RULES] } }] } },
    aggs: {
      detectors: { terms: { field: 'data.yara_rule_id', size: 20 } },
      hosts: { terms: { field: 'agent.name', size: 20 } },
      health: {
        global: {},
        aggs: {
          scoped: {
            filter: { bool: { filter: [range, { terms: { 'rule.id': [...DLP_HEALTH_RULES] } }] } },
            aggs: {
              hosts: {
                terms: { field: 'agent.name', size: 20 },
                aggs: {
                  rules: { terms: { field: 'rule.id', size: 2 } },
                  last: { max: { field: 'timestamp' } },
                },
              },
            },
          },
        },
      },
    },
  };
}

const obj = (value: unknown): Json => (value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : {});
const arr = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const str = (value: unknown): string | null => (typeof value === 'string' && value.trim() ? value.slice(0, 256) : null);
const num = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) ? value : null);

function buckets(value: unknown): Array<{ key: string; count: number; raw: Json }> {
  return arr(obj(value).buckets)
    .map((bucket) => ({ key: String(obj(bucket).key ?? ''), count: num(obj(bucket).doc_count) ?? 0, raw: obj(bucket) }))
    .filter((bucket) => bucket.key);
}

export function parseDlpFindings(window: DlpWindow, response: unknown): DlpFindings {
  const body = obj(response);
  const hits = obj(body.hits);
  const totalRaw = hits.total;
  const total = typeof totalRaw === 'number' ? totalRaw : num(obj(totalRaw).value) ?? 0;
  const aggs = obj(body.aggregations);
  const latest = arr(hits.hits).map((hit): DlpFinding => {
    const source = obj(obj(hit)._source);
    const data = obj(source.data);
    return {
      id: str(obj(hit)._id) ?? '',
      at: str(source.timestamp) ?? '',
      host: str(obj(source.agent).name) ?? str(data.endpoint) ?? 'Equipo sin nombre',
      ruleId: str(obj(source.rule).id) ?? '',
      detector: str(data.yara_rule_id),
      extension: str(data.file_extension),
      sizeBytes: num(data.file_size_bytes) ?? (typeof data.file_size_bytes === 'string' ? Number(data.file_size_bytes) || null : null),
      sha256: str(data.file_sha256),
    };
  });
  const issues = buckets(obj(obj(obj(aggs.health).scoped).hosts)).map((bucket) => {
    const lastValue = obj(bucket.raw.last);
    return {
      host: bucket.key,
      ruleId: buckets(bucket.raw.rules)[0]?.key ?? DLP_HEALTH_RULES[0],
      count: bucket.count,
      last: str(lastValue.value_as_string) ?? (num(lastValue.value) ? new Date(num(lastValue.value)!).toISOString() : null),
    };
  });
  return {
    window,
    readable: 'ok',
    total,
    byDetector: buckets(aggs.detectors).map((bucket) => ({ detector: bucket.key, count: bucket.count })),
    byHost: buckets(aggs.hosts).map((bucket) => ({ host: bucket.key, count: bucket.count })),
    latest,
    agentIssues: issues,
  };
}

export function emptyDlpFindings(window: DlpWindow, readable: DlpFindings['readable']): DlpFindings {
  return { window, readable, total: 0, byDetector: [], byHost: [], latest: [], agentIssues: [] };
}
