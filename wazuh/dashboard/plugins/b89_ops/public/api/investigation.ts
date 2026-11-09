/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  entityKey,
  EntityKind,
  EventResponse,
  INVESTIGATION_ROUTES,
  RelatedResponse,
  RelatedWindow,
  SourceResponse,
} from '../../common';
import { B89ApiError } from './client';

/**
 * Rutas de investigación del propio plugin en OSD: el servidor del dashboard consulta
 * `wazuh-alerts-*` con la identidad de quien mira (proxy auth). Como `fetchOverview`.
 */
async function getJson<T>(
  basePath: string,
  path: string,
  params: URLSearchParams,
  fetchImpl: typeof fetch,
): Promise<T> {
  let response: Response;
  try {
    response = await fetchImpl(`${basePath}${path}?${params.toString()}`, {
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'osd-xsrf': 'true' },
      cache: 'no-store',
    });
  } catch {
    throw new B89ApiError('DEPENDENCY_DEGRADED', 0, null);
  }
  if (!response.ok) {
    throw new B89ApiError(
      response.status === 401
        ? 'AUTH_REQUIRED'
        : response.status === 400
          ? 'VALIDATION_FAILED'
          : 'DEPENDENCY_DEGRADED',
      response.status,
      null,
    );
  }
  return (await response.json()) as T;
}

const defaultFetch: typeof fetch = (...args) => window.fetch(...args);

export function fetchSource(
  basePath: string,
  query: { id?: string; ruleId?: string | null; at?: string; description?: string },
  fetchImpl: typeof fetch = defaultFetch,
): Promise<SourceResponse> {
  const params = new URLSearchParams();
  if (query.id) params.set('id', query.id);
  if (query.ruleId) params.set('ruleId', query.ruleId);
  if (query.at) params.set('at', query.at);
  if (query.description) params.set('description', query.description.slice(0, 400));
  return getJson(basePath, INVESTIGATION_ROUTES.source, params, fetchImpl);
}

export function fetchEvent(
  basePath: string,
  id: string,
  fetchImpl: typeof fetch = defaultFetch,
): Promise<EventResponse> {
  return getJson(basePath, INVESTIGATION_ROUTES.event, new URLSearchParams({ id }), fetchImpl);
}

export function fetchRelated(
  basePath: string,
  query: {
    entities: ReadonlyArray<{ kind: EntityKind; value: string }>;
    at: string;
    window: RelatedWindow;
    exclude?: string;
  },
  fetchImpl: typeof fetch = defaultFetch,
): Promise<RelatedResponse> {
  const params = new URLSearchParams();
  for (const entity of query.entities) params.append('e', entityKey(entity));
  params.set('at', query.at);
  params.set('window', query.window);
  if (query.exclude) params.set('exclude', query.exclude);
  return getJson(basePath, INVESTIGATION_ROUTES.related, params, fetchImpl);
}

/** Riesgo de entidad del motor de correlación (opcional). */
export interface EntityRisk {
  readonly score: number;
  readonly level?: string;
  readonly updatedAt?: string;
}

/**
 * `GET {apiPrefix}/risk/entities/{type}/{value}` del motor de riesgo. Es opcional: si la ruta no
 * existe, no responde JSON o falla, devuelve `null` y la UI no muestra el chip (sin redirigir
 * al login ni mostrar errores).
 */
export async function fetchEntityRisk(
  apiPrefix: string,
  kind: EntityKind,
  value: string,
  fetchImpl: typeof fetch = defaultFetch,
): Promise<EntityRisk | null> {
  try {
    const response = await fetchImpl(
      `${apiPrefix}/risk/entities/${encodeURIComponent(kind)}/${encodeURIComponent(value)}`,
      { credentials: 'same-origin', headers: { accept: 'application/json' }, cache: 'no-store' },
    );
    if (!response.ok) return null;
    if (!(response.headers.get('content-type') ?? '').includes('json')) return null;
    const body = (await response.json()) as Record<string, unknown>;
    const nested = (body.risk ?? body) as Record<string, unknown>;
    const score = Number(nested.score ?? nested.riskScore);
    if (!Number.isFinite(score)) return null;
    return {
      score,
      level: typeof nested.level === 'string' ? nested.level : undefined,
      updatedAt: typeof nested.updatedAt === 'string' ? nested.updatedAt : undefined,
    };
  } catch {
    return null;
  }
}
