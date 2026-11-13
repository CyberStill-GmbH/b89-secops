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
import { createHash } from 'crypto';
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
export const RELATED_PAGE_SIZE = 100;
const RELATED_CURSOR_MAX_LENGTH = 2048;
const RELATED_PIT_KEEP_ALIVE = '2m';
/** Ventana para encontrar el documento de origen de una alerta B89 (regla + hora). */
const SOURCE_MATCH_MS = 5 * 60000;
const RAW_FIELDS_TO_OMIT = new Set(['full_log', 'previous_output']);
const OFFICE365_RAW_FIELDS_TO_OMIT = ['Parameters', 'ModifiedProperties', 'response'] as const;
const OFFICE365_MESSAGE_FIELDS_TO_OMIT = [
  'MailboxOwnerUPN',
  'recipientList',
  'InternetMessageId',
  'NetworkMessageId',
] as const;
const MAX_REPORT_RECIPIENTS = 50;

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

/** Recursively clone a source document while dropping log blobs from the investigation viewer. */
function omitRawFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(omitRawFields);
  if (!value || typeof value !== 'object') return value;
  const safe: Json = {};
  for (const [key, child] of Object.entries(value as Json)) {
    if (RAW_FIELDS_TO_OMIT.has(key)) continue;
    safe[key] = omitRawFields(child);
  }
  return safe;
}

/**
 * The expandable view is a convenience, not an unrestricted copy of `_source`. It removes raw
 * log blobs everywhere and preserves the existing Office365 field exclusions under data.office365.
 */
function investigationSource(source: Json): Json {
  const safeSource = omitRawFields(source) as Json;
  const data = obj(safeSource.data);
  const office365 = obj(data.office365);
  if (Object.keys(office365).length === 0) return safeSource;

  const safeOffice365 = { ...office365 };
  for (const field of OFFICE365_RAW_FIELDS_TO_OMIT) delete safeOffice365[field];
  for (const field of OFFICE365_MESSAGE_FIELDS_TO_OMIT) delete safeOffice365[field];
  return { ...safeSource, data: { ...data, office365: safeOffice365 } };
}

function emailMetadata(source: Json): InvestigationEventSummary['email'] {
  const office365 = obj(obj(source.data).office365);
  const mailbox = (value: unknown): string | undefined => {
    if (typeof value !== 'string') return undefined;
    const text = value.trim();
    const at = text.lastIndexOf('@');
    if (
      text.length > 320 ||
      /[\s<>\u0000-\u001f]/u.test(text) ||
      at <= 0 ||
      at === text.length - 1 ||
      text.indexOf('@') !== at
    )
      return undefined;
    return text.toLowerCase();
  };
  const internetMessageId =
    typeof office365.InternetMessageId === 'string' &&
    office365.InternetMessageId.length <= 512 &&
    !/[\u0000-\u001f\u007f]/u.test(office365.InternetMessageId)
      ? office365.InternetMessageId
      : undefined;
  const networkText =
    typeof office365.NetworkMessageId === 'string' ? office365.NetworkMessageId.trim() : '';
  const networkMessageId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(
    networkText,
  )
    ? networkText.toLowerCase()
    : undefined;
  const recipientList = Array.isArray(office365.recipientList) ? office365.recipientList : [];
  const recipients: string[] = [];
  const seenRecipients = new Set<string>();
  let uniqueRecipientCount = 0;
  for (const value of recipientList) {
    const address = mailbox(obj(value).Address);
    if (!address || seenRecipients.has(address)) continue;
    seenRecipients.add(address);
    uniqueRecipientCount += 1;
    if (recipients.length < MAX_REPORT_RECIPIENTS) recipients.push(address);
  }
  const rawRecipientCount = office365.recipientCount;
  const declaredRecipientCount =
    typeof rawRecipientCount === 'number' &&
    Number.isSafeInteger(rawRecipientCount) &&
    rawRecipientCount >= 0 &&
    rawRecipientCount <= 1_000_000
      ? rawRecipientCount
      : typeof rawRecipientCount === 'string' && /^\d{1,7}$/u.test(rawRecipientCount)
        ? Number(rawRecipientCount)
        : undefined;
  const recipientCount =
    declaredRecipientCount ?? (recipientList.length ? uniqueRecipientCount : undefined);
  const recipientsTruncated =
    recipientList.length > 0 &&
    (uniqueRecipientCount > MAX_REPORT_RECIPIENTS ||
      (declaredRecipientCount !== undefined && declaredRecipientCount > recipients.length));
  const operation =
    typeof office365.Operation === 'string' &&
    office365.Operation.length <= 128 &&
    !/[\u0000-\u001f\u007f]/u.test(office365.Operation)
      ? office365.Operation
      : undefined;
  const mailboxOwnerUpn = mailbox(office365.MailboxOwnerUPN);
  const email = {
    ...(internetMessageId ? { internetMessageId } : {}),
    ...(networkMessageId ? { networkMessageId } : {}),
    ...(mailboxOwnerUpn ? { mailboxOwnerUpn } : {}),
    ...(recipients.length ? { recipients } : {}),
    ...(recipientCount !== undefined ? { recipientCount } : {}),
    ...(recipientsTruncated ? { recipientsTruncated: true } : {}),
    ...(operation ? { operation } : {}),
  };
  return Object.keys(email).length ? email : undefined;
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
  const email = emailMetadata(source);
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
    ...(email ? { email } : {}),
    mitre: mitreOf(rule),
    matched: queried.map(entityKey).filter((key) => present.has(key)),
  };
}

export function eventOf(hit: Json): InvestigationEvent {
  const originalSource = obj(hit._source);
  const source = investigationSource(originalSource);
  const serialized = JSON.stringify(source);
  const truncated = Buffer.byteLength(serialized, 'utf8') > RAW_LIMIT_BYTES;
  return {
    ...summaryOf(hit),
    location: typeof source.location === 'string' ? source.location : null,
    entities: extractEntities(originalSource),
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
  searchAfter?: readonly [string, number];
  pitId?: string;
}): Json {
  const span = RELATED_WINDOW_MS[params.window];
  const perEntity: Json = {};
  for (const entity of params.entities) {
    perEntity[entityKey(entity)] = {
      bool: { should: entityClauses([entity]), minimum_should_match: 1 },
    };
  }
  return {
    size: RELATED_PAGE_SIZE,
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
    sort: [{ timestamp: { order: 'desc' } }, { _shard_doc: { order: 'asc' } }],
    ...(params.searchAfter ? { search_after: params.searchAfter } : {}),
    ...(params.pitId ? { pit: { id: params.pitId, keep_alive: RELATED_PIT_KEEP_ALIVE } } : {}),
    _source: {
      excludes: [
        'full_log',
        'data.office365.Parameters',
        'data.office365.ModifiedProperties',
        'data.office365.response',
        'previous_output',
      ],
    },
    aggs: { perEntity: { filters: { filters: perEntity } } },
  };
}

interface RelatedCursor {
  readonly filter: string;
  readonly pitId: string;
  readonly sort: readonly [string, number];
  readonly count: number;
}

function relatedFilterFingerprint(params: {
  entities: ReadonlyArray<{ kind: EntityKind; value: string }>;
  at: number;
  window: RelatedWindow;
  excludeId?: string;
}): string {
  const canonical = {
    entities: params.entities.map(entityKey).sort(),
    at: params.at,
    window: params.window,
    excludeId: params.excludeId ?? '',
  };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function cursorOf(value: string | undefined, filter: string): RelatedCursor | null {
  if (!value) return null;
  if (value.length > RELATED_CURSOR_MAX_LENGTH || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error('Cursor de investigacion no valido.');
  }
  try {
    const decoded = JSON.parse(
      Buffer.from(value, 'base64url').toString('utf8'),
    ) as Partial<RelatedCursor>;
    if (
      decoded.filter !== filter ||
      typeof decoded.pitId !== 'string' ||
      decoded.pitId.length === 0 ||
      decoded.pitId.length > 1024 ||
      !Array.isArray(decoded.sort) ||
      decoded.sort.length !== 2 ||
      typeof decoded.sort[0] !== 'string' ||
      !Number.isFinite(Date.parse(decoded.sort[0])) ||
      typeof decoded.sort[1] !== 'number' ||
      !Number.isSafeInteger(decoded.sort[1]) ||
      decoded.sort[1] < 0 ||
      !Number.isSafeInteger(decoded.count) ||
      (decoded.count ?? 0) < 1
    ) {
      throw new Error('Cursor de investigacion no valido.');
    }
    return decoded as RelatedCursor;
  } catch {
    throw new Error('Cursor de investigacion no valido.');
  }
}

function encodeRelatedCursor(
  filter: string,
  pitId: string,
  hit: Json,
  count: number,
): string | null {
  const sort = list(hit.sort);
  const timestamp = sort[0];
  const shardDoc = sort[1];
  if (pitId.length === 0 || pitId.length > 1024) return null;
  if (typeof timestamp !== 'string' || !Number.isFinite(Date.parse(timestamp))) return null;
  if (typeof shardDoc !== 'number' || !Number.isSafeInteger(shardDoc) || shardDoc < 0) return null;
  const cursor: RelatedCursor = {
    filter,
    pitId,
    sort: [timestamp, shardDoc],
    count,
  };
  return Buffer.from(JSON.stringify(cursor)).toString('base64url');
}

function supportsPit(client: SearchClient): boolean {
  return Boolean((client.createPit && client.deletePit) || client.transport);
}

async function createRelatedPit(client: SearchClient): Promise<{ body: unknown }> {
  if (client.createPit) {
    return client.createPit({ index: ALERTS_INDEX, keep_alive: RELATED_PIT_KEEP_ALIVE });
  }
  return client.transport!.request({
    method: 'POST',
    path: `/${ALERTS_INDEX}/_search/point_in_time`,
    querystring: { keep_alive: RELATED_PIT_KEEP_ALIVE },
  });
}

async function closeRelatedPit(client: SearchClient, pitId: string): Promise<void> {
  if (!pitId || !supportsPit(client)) return;
  try {
    if (client.deletePit) await client.deletePit({ body: { pit_id: [pitId] } });
    else {
      await client.transport!.request({
        method: 'DELETE',
        path: '/_search/point_in_time',
        body: { pit_id: [pitId] },
      });
    }
  } catch {
    // PIT tiene keep_alive corto; un fallo al cerrarlo no debe convertir una página correcta en error.
  }
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
  return guarded<SourceResponse>(
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
  return guarded<EventResponse>(
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
    cursor?: string;
  },
): Promise<RelatedResponse> {
  const span = RELATED_WINDOW_MS[params.window];
  const from = new Date(params.at - span).toISOString();
  const to = new Date(params.at + span).toISOString();
  const entities = params.entities.slice(0, MAX_QUERY_ENTITIES);
  const filter = relatedFilterFingerprint({ ...params, entities });
  const cursor = cursorOf(params.cursor, filter);
  if (
    cursor &&
    (Date.parse(cursor.sort[0]) < Date.parse(from) || Date.parse(cursor.sort[0]) > Date.parse(to))
  ) {
    throw new Error('Cursor de investigacion fuera de la ventana consultada.');
  }
  if (entities.length === 0) {
    return Promise.resolve({
      access: 'ok',
      from,
      to,
      total: 0,
      events: [],
      perEntity: {},
      nextCursor: null,
      pageSize: RELATED_PAGE_SIZE,
    });
  }
  return guarded<RelatedResponse>(
    async () => {
      if (!supportsPit(client)) {
        throw new Error('El cliente de Indexer no admite paginacion PIT.');
      }
      let pitId = cursor?.pitId;
      const createdHere = !pitId;
      if (!pitId) {
        const pit = await createRelatedPit(client);
        pitId = String(obj(pit.body).pit_id ?? '');
        if (!pitId || pitId.length > 1024) throw new Error('Indexer no devolvio un PIT valido.');
      }
      let result: { body: unknown };
      try {
        result = await client.search({
          body: relatedQuery({
            ...params,
            entities,
            pitId,
            searchAfter: cursor?.sort,
          }),
        });
      } catch (error) {
        if (createdHere) await closeRelatedPit(client, pitId);
        throw error;
      }
      const hits = hitsOf(result.body);
      const total = totalOf(result.body);
      const responsePitId = String(obj(result.body).pit_id ?? pitId);
      const nextCursor =
        cursor && total > cursor.count + hits.length
          ? encodeRelatedCursor(
              filter,
              responsePitId,
              hits[hits.length - 1] ?? {},
              cursor.count + hits.length,
            )
          : !cursor && total > hits.length
            ? encodeRelatedCursor(filter, responsePitId, hits[hits.length - 1] ?? {}, hits.length)
            : null;
      const buckets = obj(obj(obj(obj(result.body).aggregations).perEntity).buckets);
      const perEntity: Record<string, number> = {};
      for (const [key, bucket] of Object.entries(buckets)) {
        const count = obj(bucket).doc_count;
        perEntity[key] = typeof count === 'number' ? count : 0;
      }
      if (!nextCursor) await closeRelatedPit(client, responsePitId);
      return {
        access: 'ok' as const,
        from,
        to,
        total,
        events: hits.map((hit) => summaryOf(hit, entities)),
        nextCursor,
        pageSize: RELATED_PAGE_SIZE,
        perEntity,
      };
    },
    (access) => ({
      access,
      from,
      to,
      total: 0,
      events: [],
      perEntity: {},
      nextCursor: null,
      pageSize: RELATED_PAGE_SIZE,
    }),
  );
}
