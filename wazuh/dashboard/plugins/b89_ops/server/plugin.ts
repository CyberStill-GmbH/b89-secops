/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { randomBytes } from 'crypto';
import { Readable } from 'stream';
import { schema } from '@osd/config-schema';
import { first } from 'rxjs/operators';
import type {
  CoreSetup,
  CoreStart,
  Logger,
  Plugin,
  PluginInitializerContext,
} from '../../../src/core/server';
import type { ConfigSchema } from './config';
import { LEGACY_LOGIN_PATHS, LOGIN_PATH, LOGOUT_PATH } from '../common';
import { OVERVIEW_ROUTE } from '../common/integrations';
import { buildOverview, SearchClient } from './overview';
import { findEvent, findRelated, findSource } from './investigation';
import { exportFilename, exportTrafficCsv, searchTraffic } from './cloudflare_traffic';
import {
  CURSOR_MAX_LENGTH,
  MAX_PAGE_SIZE,
  MAX_ZONES,
  normalizeTrafficFilters,
  RawTrafficQuery,
  TEXT_MAX,
  TRAFFIC_ROUTES,
  UA_MAX,
} from '../common/cloudflare_traffic';
import { readabilityOf } from './overview';
import {
  INVESTIGATION_ROUTES,
  MAX_QUERY_ENTITIES,
  parseEntityKey,
  RELATED_WINDOWS,
  RelatedWindow,
} from '../common/investigation';
import {
  loginContentSecurityPolicy,
  logoutContentSecurityPolicy,
  rawNextUrl,
  readSignInNotice,
  renderLoginPage,
  renderLogoutPage,
} from './login_page';

const NO_STORE_HEADERS = {
  'cache-control': 'no-store',
  // same-origin: con no-referrer Chrome envía Origin: null en el POST del login y la API lo rechaza.
  'referrer-policy': 'same-origin',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
};

interface SourceQuery {
  id?: string;
  ruleId?: string;
  at?: string;
  description?: string;
}

interface RelatedQuery {
  e: string | string[];
  at: string;
  window: string;
  exclude?: string;
  cursor?: string;
}

const idValidator = (value: string) =>
  /^[A-Za-z0-9_-]{1,128}$/u.test(value) ? undefined : 'identificador no válido';
const digitsValidator = (value: string) =>
  /^\d{1,10}$/u.test(value) ? undefined : 'regla no válida';

interface TrafficResponseFactory {
  customError(options: { statusCode: number; body: { message: string } }): unknown;
}

export class B89OpsServerPlugin implements Plugin<void, void> {
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public async setup(core: CoreSetup) {
    const config = await this.initializerContext.config
      .create<ConfigSchema>()
      .pipe(first())
      .toPromise();
    if (!config.enabled) return;

    const basePath = core.http.basePath.serverBasePath;
    const router = core.http.createRouter();

    // «Resumen del SOC» e «Integraciones»: agregaciones del Indexer con la identidad de quien
    // mira (proxy auth). Nunca con la identidad interna del dashboard.
    router.get({ path: OVERVIEW_ROUTE, validate: false }, async (context, _request, response) => {
      const client = (
        context as { core: { opensearch: { client: { asCurrentUser: SearchClient } } } }
      ).core.opensearch.client.asCurrentUser;
      const body = await buildOverview(client, config.integrations);
      return response.ok({
        body,
        headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
      });
    });

    // Investigación de alertas: evento de origen, eventos relacionados por entidad y documento
    // completo. Siempre con la identidad de quien mira (asCurrentUser), como el resumen.
    const currentUser = (context: unknown): SearchClient =>
      (context as { core: { opensearch: { client: { asCurrentUser: SearchClient } } } }).core
        .opensearch.client.asCurrentUser;
    const json = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
    const docId = schema.string({ maxLength: 128, validate: idValidator });
    router.get(
      {
        path: INVESTIGATION_ROUTES.source,
        validate: {
          query: schema.object({
            id: schema.maybe(docId),
            ruleId: schema.maybe(schema.string({ maxLength: 10, validate: digitsValidator })),
            at: schema.maybe(schema.string({ maxLength: 40 })),
            description: schema.maybe(schema.string({ maxLength: 400 })),
          }),
        },
      },
      async (context, request, response) =>
        response.ok({
          body: await findSource(currentUser(context), request.query as SourceQuery),
          headers: json,
        }),
    );
    router.get(
      {
        path: INVESTIGATION_ROUTES.event,
        validate: { query: schema.object({ id: docId }) },
      },
      async (context, request, response) =>
        response.ok({
          body: await findEvent(currentUser(context), (request.query as { id: string }).id),
          headers: json,
        }),
    );
    router.get(
      {
        path: INVESTIGATION_ROUTES.related,
        validate: {
          query: schema.object({
            e: schema.oneOf([
              schema.string({ maxLength: 300 }),
              schema.arrayOf(schema.string({ maxLength: 300 }), { maxSize: MAX_QUERY_ENTITIES }),
            ]),
            at: schema.string({ maxLength: 40 }),
            window: schema.string({ defaultValue: '24h', maxLength: 4 }),
            exclude: schema.maybe(docId),
            cursor: schema.maybe(schema.string({ maxLength: 2048 })),
          }),
        },
      },
      async (context, request, response) => {
        const query = request.query as RelatedQuery;
        const keys = Array.isArray(query.e) ? query.e : [query.e];
        const entities = keys
          .map(parseEntityKey)
          .filter((entity): entity is NonNullable<typeof entity> => entity !== null);
        const at = Date.parse(query.at);
        const window = (RELATED_WINDOWS as readonly string[]).includes(query.window)
          ? (query.window as RelatedWindow)
          : '24h';
        if (!Number.isFinite(at) || entities.length === 0) {
          return response.badRequest({ body: 'Entidad u hora no válidas.' });
        }
        try {
          return response.ok({
            body: await findRelated(currentUser(context), {
              entities,
              at,
              window,
              excludeId: query.exclude,
              cursor: query.cursor,
            }),
            headers: json,
          });
        } catch {
          return response.badRequest({
            body: 'Cursor de investigacion no valido para estos filtros.',
          });
        }
      },
    );

    // «Tráfico de Cloudflare»: todo b89-cloudflare-traffic-* (HTTP, DNS, firewall, auditoría)
    // con la identidad de quien mira. Solo filtros validados; nunca DSL del navegador.
    const shortText = schema.string({ maxLength: TEXT_MAX });
    const repeated = (maxSize: number) =>
      schema.maybe(
        schema.oneOf([
          schema.string({ maxLength: 300 }),
          schema.arrayOf(schema.string({ maxLength: 253 }), { maxSize }),
        ]),
      );
    const trafficQuery = {
      from: schema.string({ maxLength: 40 }),
      to: schema.string({ maxLength: 40 }),
      dataset: repeated(4),
      zone: repeated(MAX_ZONES),
      ip: schema.maybe(schema.string({ maxLength: 64 })),
      host: schema.maybe(schema.string({ maxLength: 253 })),
      path: schema.maybe(shortText),
      method: schema.maybe(schema.string({ maxLength: 16 })),
      status: schema.maybe(schema.string({ maxLength: 3 })),
      country: schema.maybe(schema.string({ maxLength: 2 })),
      asn: schema.maybe(schema.string({ maxLength: 12 })),
      ua: schema.maybe(schema.string({ maxLength: UA_MAX })),
      q: schema.maybe(shortText),
    };
    const indexerError = (response: TrafficResponseFactory, error: unknown) => {
      const status = readabilityOf(error);
      if (status === 'forbidden') {
        return response.customError({
          statusCode: 403,
          body: { message: 'Tu rol no puede leer b89-cloudflare-traffic-*.' },
        });
      }
      const missing =
        Number((error as { statusCode?: number })?.statusCode) === 404 ||
        Number((error as { meta?: { statusCode?: number } })?.meta?.statusCode) === 404;
      if (missing) {
        return response.customError({
          statusCode: 404,
          body: { message: 'Aún no existe ningún índice b89-cloudflare-traffic-*.' },
        });
      }
      this.logger.warn(`Tráfico de Cloudflare: el Indexer falló (${String(error).slice(0, 200)})`);
      return response.customError({
        statusCode: 502,
        body: { message: 'El Indexer no respondió a la consulta de tráfico.' },
      });
    };
    router.get(
      {
        path: TRAFFIC_ROUTES.search,
        validate: {
          query: schema.object({
            ...trafficQuery,
            cursor: schema.maybe(schema.string({ maxLength: CURSOR_MAX_LENGTH })),
            size: schema.maybe(schema.string({ maxLength: 3 })),
          }),
        },
      },
      async (context, request, response) => {
        const query = request.query as RawTrafficQuery & { cursor?: string; size?: string };
        const filters = normalizeTrafficFilters(query);
        if (!filters.ok) return response.badRequest({ body: { message: filters.error } });
        const size = query.size === undefined ? undefined : Number(query.size);
        if (size !== undefined && !(Number.isInteger(size) && size >= 1 && size <= MAX_PAGE_SIZE)) {
          return response.badRequest({
            body: { message: `Tamaño de página entre 1 y ${MAX_PAGE_SIZE}.` },
          });
        }
        let result;
        try {
          result = await searchTraffic(currentUser(context), filters.value, {
            cursor: query.cursor,
            size,
          });
        } catch (error) {
          if (error instanceof Error && error.message.startsWith('Cursor no válido')) {
            return response.badRequest({ body: { message: error.message } });
          }
          return indexerError(response as TrafficResponseFactory, error);
        }
        return response.ok({ body: result, headers: json });
      },
    );
    router.get(
      { path: TRAFFIC_ROUTES.export, validate: { query: schema.object(trafficQuery) } },
      async (context, request, response) => {
        const filters = normalizeTrafficFilters(request.query as RawTrafficQuery);
        if (!filters.ok) return response.badRequest({ body: { message: filters.error } });
        let rows;
        try {
          rows = await exportTrafficCsv(currentUser(context), filters.value);
        } catch (error) {
          return indexerError(response as TrafficResponseFactory, error);
        }
        return response.ok({
          body: Readable.from(rows),
          headers: {
            ...json,
            'content-type': 'text/csv; charset=utf-8',
            'content-disposition': `attachment; filename="${exportFilename(filters.value)}"`,
          },
        });
      },
    );

    if (!config.login.enabled) return;

    // El login de Wazuh / Security plugin deja de existir: cualquier navegación a él
    // (redirect por sesión ausente, enlace antiguo, logout) llega al login B89.
    core.http.registerOnPreRouting((request, _response, toolkit) => {
      if (request.route.method !== 'get' || !LEGACY_LOGIN_PATHS.includes(request.url.pathname)) {
        return toolkit.next();
      }
      // Se conserva la query (`nextUrl`, `authError`…); `request.url` es un URL WHATWG en 2.19.
      return toolkit.rewriteUrl(`${LOGIN_PATH}${request.url.search}`);
    });

    router.get(
      {
        path: LOGIN_PATH,
        validate: { query: schema.object({}, { unknowns: 'allow' }) },
        options: { authRequired: false, xsrfRequired: false },
      },
      async (_context, request, response) => {
        const query = { ...(request.query as Record<string, unknown>) };
        const raw = rawNextUrl(request.url.search);
        if (raw !== undefined) query.nextUrl = raw;
        const { nextUrl, notice } = readSignInNotice(
          query,
          `${basePath}${config.login.defaultNextUrl}`,
          config.apiPrefix,
        );
        const nonce = randomBytes(16).toString('base64');
        return response.ok({
          body: renderLoginPage({
            basePath,
            apiPrefix: config.apiPrefix,
            nextUrl,
            notice,
            nonce,
            destinationLabel: config.login.destinationLabel,
            passwordEnabled: config.login.passwordEnabled,
            entraEnabled: config.login.entraEnabled,
          }),
          headers: {
            ...NO_STORE_HEADERS,
            'content-type': 'text/html; charset=utf-8',
            'content-security-policy': loginContentSecurityPolicy(nonce),
          },
        });
      },
    );

    router.get(
      {
        path: LOGOUT_PATH,
        validate: false,
        options: { authRequired: false, xsrfRequired: false },
      },
      async (_context, _request, response) => {
        const nonce = randomBytes(16).toString('base64');
        return response.ok({
          body: renderLogoutPage({ basePath, apiPrefix: config.apiPrefix, nonce }),
          headers: {
            ...NO_STORE_HEADERS,
            'content-type': 'text/html; charset=utf-8',
            'content-security-policy': logoutContentSecurityPolicy(nonce),
          },
        });
      },
    );

    this.logger.info(
      `Login B89 activo en ${basePath}${LOGIN_PATH}; ${LEGACY_LOGIN_PATHS.join(', ')} redirigen aquí`,
    );
  }

  public start(_core: CoreStart) {}

  public stop() {}
}
