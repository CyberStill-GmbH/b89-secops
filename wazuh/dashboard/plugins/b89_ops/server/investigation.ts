/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  entityClauses,
  entityKey,
  EntityKind,
  EventResponse,
  extractEntities,
  IndexerAccess,
  InvestigationEvent,
  InvestigationEventSummary,
  MAX_QUERY_ENTITIES,
  MitreInfo,
  RELATED_WINDOW_MS,
  RelatedResponse,
  RelatedWindow,
  SourceResponse,
} from '../common/investigation';
import { vendorOfGroups } from '../common/vendors';
import { ALERTS_INDEX, isoInstant, readabilityOf, SearchClient } from './overview';

/**
 * Rutas de investigación (`/api/b89_ops/investigation/*`). Todas las búsquedas van con
 * `asCurrentUser`: el Security plugin aplica el rol de quien mira (proxy auth B89). Un rol sin
 * lectura de `wazuh-alerts-*` recibe `access: forbidden`, nunca datos.
 */

type Json = Record<string, unknown>;

/** Tamaño máximo del `_source` que viaja al navegador (visor JSON). */
export const RAW_LIMIT_BYTES = 64 * 1024;
const RELATED_SIZE = 100;
/** Ventana para encontrar el documento de origen de una alerta B89 (regla + hora). */
const SOURCE_MATCH_MS = 5 * 60_000;

function obj(value: unknown): Json {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : {};
}

function list(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  return value === undefined || value === null ? [] : [value];
}

function strings(value: unknown): string[] {
  return list(value)
    .filter((item) => typeof item === 'string' || typeof item === 'number')
    .map(String);
}

function mitreOf(rule: Json): MitreInfo {
  const mitre = obj(rule.mitre);
  return {
    ids: strings(mitre.id).slice(0, 12),
    tactics: strings(mitre.tactic).slice(0, 12),
    techniques: strings(mitre.technique).slice(0, 12),
  };
}

function hitsOf(body: unknown): Json[] {
  return list(obj(obj(body).hits).hits).map(obj);
}

function totalOf(body: unknown): number {
  const total = obj(obj(body).hits).total;
  if (typeof total === 'number') return total;
  const value = obj(total).value;
  return typeof value === 'number' ? value : 0;
}

export function summaryOf(
  hit: Json,
  queried: ReadonlyArray<{ kind: EntityKind; value: string }> = [],
): InvestigationEventSummary {
  const source = obj(hit._source);
  const rule = obj(source.rule);
  const groups = strings(rule.groups);
  const entities = extractEntities(source);
  const present = new Set(entities.map(entityKey));
  return {
    id: String(hit._id ?? ''),
    index: String(hit._index ?? ''),
    at: isoInstant(source.timestamp),
    level: typeof rule.level === 'number' ? rule.level : Number(rule.level) || 0,
    ruleId: String(rule.id ?? ''),
    description: String(rule.description ?? '').slice(0, 300),
    groups,
    vendor: vendorOfGroups(groups, obj(obj(source.data).b89).vendor),
    agent: typeof obj(source.agent).name === 'string' ? String(obj(source.agent).name) : null,
    mitre: mitreOf(rule),
    matched: queried.map(entityKey).filter((key) => present.has(key)),
  };
}

export function eventOf(hit: Json): InvestigationEvent {
  const source = obj(hit._source);
  const serialized = JSON.stringify(source);
  const truncated = serialized.length > RAW_LIMIT_BYTES;
  return {
    ...summaryOf(hit),
    location: typeof source.location === 'string' ? source.location : null,
    entities: extractEntities(source),
    raw: truncated
      ? { aviso: 'Documento recortado: ábrelo completo en Discover.', rule: source.rule }
      : source,
    rawTruncated: truncated,
  };
}

/** Documento de origen: por id exacto o, si no, por regla y hora (±5 min, el más cercano). */
export function sourceQuery(params: {
  id?: string;
  ruleId?: string;
  at?: string;
  description?: string;
}): Json | null {
  if (params.id) return { size: 1, query: { ids: { values: [params.id] } } };
  const at = params.at ? Date.parse(params.at) : Number.NaN;
  if (!params.ruleId || !Number.isFinite(at)) return null;
  return {
    query: {
      bool: {
        filter: [
          { term: { 'rule.id': params.ruleId } },
          ...(params.description ? [{ term: { 'rule.description': params.description } }] : []),
          {
            range: {
              timestamp: {
                gte: new Date(at - SOURCE_MATCH_MS).toISOString(),
                lte: new Date(at + SOURCE_MATCH_MS).toISOString(),
              },
            },
          },
        ],
      },
    },
    size: 20,
    sort: [{ timestamp: { order: 'asc' } }],
  };
}

export function relatedQuery(params: {
  entities: ReadonlyArray<{ kind: EntityKind; value: string }>;
  at: number;
  window: RelatedWindow;
  excludeId?: string;
}): Json {
  const span = RELATED_WINDOW_MS[params.window];
  const perEntity: Json = {};
  for (const entity of params.entities) {
    perEntity[entityKey(entity)] = {
      bool: { should: entityClauses([entity]), minimum_should_match: 1 },
    };
  }
  return {
    size: RELATED_SIZE,
    track_total_hits: true,
    query: {
      bool: {
        filter: [
          {
            range: {
              timestamp: {
                gte: new Date(params.at - span).toISOString(),
                lte: new Date(params.at + span).toISOString(),
              },
            },
          },
        ],
        should: entityClauses(params.entities),
        minimum_should_match: 1,
        ...(params.excludeId ? { must_not: [{ ids: { values: [params.excludeId] } }] } : {}),
      },
    },
    sort: [{ timestamp: { order: 'desc' } }],
    _source: { excludes: ['full_log', 'data.office365.response', 'previous_output'] },
    aggs: { perEntity: { filters: { filters: perEntity } } },
  };
}

/** El documento más cercano a `at` (o el primero si no hay hora). */
export function nearest(hits: Json[], at?: string): Json | undefined {
  const target = at ? Date.parse(at) : Number.NaN;
  if (!Number.isFinite(target)) return hits[0];
  let best: Json | undefined;
  let distance = Number.POSITIVE_INFINITY;
  for (const hit of hits) {
    const when = Date.parse(isoInstant(obj(hit._source).timestamp));
    const gap = Math.abs(when - target);
    if (Number.isFinite(gap) && gap < distance) {
      best = hit;
      distance = gap;
    }
  }
  return best ?? hits[0];
}

async function guarded<T>(
  run: () => Promise<T>,
  fallback: (access: IndexerAccess) => T,
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    return fallback(readabilityOf(error));
  }
}

export function findSource(
  client: SearchClient,
  params: { id?: string; ruleId?: string; at?: string; description?: string },
): Promise<SourceResponse> {
  if (!sourceQuery(params)) return Promise.resolve({ access: 'ok', match: 'none', event: null });
  const attempt = async (query: typeof params) => {
    const body = sourceQuery(query);
    if (!body) return undefined;
    const result = await client.search({ index: ALERTS_INDEX, body });
    return nearest(hitsOf(result.body), query.at);
  };
  return guarded(
    async () => {
      // Con descripción (título de la alerta B89) primero: varias alertas comparten regla y hora.
      let hit = await attempt(params);
      if (!hit && params.description) hit = await attempt({ ...params, description: undefined });
      return {
        access: 'ok' as const,
        match: hit ? (params.id ? ('exact' as const) : ('matched' as const)) : ('none' as const),
        event: hit ? eventOf(hit) : null,
      };
    },
    (access) => ({ access, match: 'none', event: null }),
  );
}

export function findEvent(client: SearchClient, id: string): Promise<EventResponse> {
  return guarded(
    async () => {
      const result = await client.search({
        index: ALERTS_INDEX,
        body: { size: 1, query: { ids: { values: [id] } } },
      });
      const hit = hitsOf(result.body)[0];
      return { access: 'ok' as const, event: hit ? eventOf(hit) : null };
    },
    (access) => ({ access, event: null }),
  );
}

export function findRelated(
  client: SearchClient,
  params: {
    entities: ReadonlyArray<{ kind: EntityKind; value: string }>;
    at: number;
    window: RelatedWindow;
    excludeId?: string;
  },
): Promise<RelatedResponse> {
  const span = RELATED_WINDOW_MS[params.window];
  const from = new Date(params.at - span).toISOString();
  const to = new Date(params.at + span).toISOString();
  const entities = params.entities.slice(0, MAX_QUERY_ENTITIES);
  if (entities.length === 0) {
    return Promise.resolve({ access: 'ok', from, to, total: 0, events: [], perEntity: {} });
  }
  return guarded(
    async () => {
      const result = await client.search({
        index: ALERTS_INDEX,
        body: relatedQuery({ ...params, entities }),
      });
      const buckets = obj(obj(obj(obj(result.body).aggregations).perEntity).buckets);
      const perEntity: Record<string, number> = {};
      for (const [key, bucket] of Object.entries(buckets)) {
        const count = obj(bucket).doc_count;
        perEntity[key] = typeof count === 'number' ? count : 0;
      }
      return {
        access: 'ok' as const,
        from,
        to,
        total: totalOf(result.body),
        events: hitsOf(result.body).map((hit) => summaryOf(hit, entities)),
        perEntity,
      };
    },
    (access) => ({ access, from, to, total: 0, events: [], perEntity: {} }),
  );
}
