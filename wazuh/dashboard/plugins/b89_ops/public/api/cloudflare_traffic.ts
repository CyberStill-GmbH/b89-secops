/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { TRAFFIC_ROUTES, TrafficFilters, trafficQueryParams, TrafficResponse } from '../../common';
import { B89ApiError } from './client';

/** Error de la ruta de tráfico con el mensaje en español que devuelve el servidor. */
export class TrafficRequestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'TrafficRequestError';
  }
}

const defaultFetch: typeof fetch = (...args) => window.fetch(...args);

/**
 * Ruta propia del plugin en OSD: el servidor del dashboard consulta
 * `b89-cloudflare-traffic-*` con la identidad de quien mira (como `fetchOverview`).
 */
export async function fetchTraffic(
  basePath: string,
  filters: TrafficFilters,
  options: { cursor?: string | null; size?: number; signal?: AbortSignal } = {},
  fetchImpl: typeof fetch = defaultFetch,
): Promise<TrafficResponse> {
  const params = trafficQueryParams(filters);
  if (options.cursor) params.set('cursor', options.cursor);
  if (options.size) params.set('size', String(options.size));
  let response: Response;
  try {
    response = await fetchImpl(`${basePath}${TRAFFIC_ROUTES.search}?${params.toString()}`, {
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'osd-xsrf': 'true' },
      cache: 'no-store',
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch {
    if (options.signal?.aborted) throw new DOMException('Solicitud cancelada', 'AbortError');
    throw new B89ApiError('DEPENDENCY_DEGRADED', 0, null);
  }
  if (response.status === 401) throw new B89ApiError('AUTH_REQUIRED', 401, null);
  if (!response.ok) {
    let message = 'No se pudo consultar el tráfico de Cloudflare.';
    try {
      const body = (await response.json()) as { message?: unknown };
      if (typeof body.message === 'string' && body.message) message = body.message;
    } catch {
      // Cuerpo no JSON: queda el mensaje genérico.
    }
    throw new TrafficRequestError(response.status, message);
  }
  return (await response.json()) as TrafficResponse;
}

/** Enlace de descarga del CSV para los filtros actuales (GET con la sesión del dashboard). */
export function trafficExportHref(basePath: string, filters: TrafficFilters): string {
  return `${basePath}${TRAFFIC_ROUTES.export}?${trafficQueryParams(filters).toString()}`;
}
