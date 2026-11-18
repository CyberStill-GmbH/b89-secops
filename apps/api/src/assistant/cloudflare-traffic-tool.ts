/**
 * Herramienta de Bunny/MCP: tráfico de Cloudflare (peticiones HTTP, DNS, firewall, auditoría) con la
 * hora REAL de cada evento, por IP, host o ruta. Query construida aquí (sin DSL del usuario), rango
 * acotado a 31 días y respuesta resumida: agregados, primera/última vez (Lima) y los 25 eventos más
 * recientes. Los datos de GraphQL son muestreados (≈1 de cada 11 peticiones en b89.io).
 */
import { isIP } from 'node:net';

import type { AssistantTool, ToolOutcome } from '@b89/assistant';

import {
  CloudflareTrafficError,
  type CloudflareTrafficSearch,
} from '../runtime/cloudflare-traffic.js';
import { limaLabel } from './investigation-tools.js';

const DAY = 86_400_000;
const MAX_RANGE = 31 * DAY;

function parseTime(value: unknown): number | null {
  if (typeof value !== 'string' || value.length > 40) return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? at : null;
}

const escapeWildcard = (value: string) => value.replace(/[\\*?]/gu, (char) => `\\${char}`);

export type TrafficQuery =
  | { ok: true; body: Record<string, unknown>; from: string; to: string }
  | { ok: false; error: string };

export function buildTrafficQuery(
  input: Readonly<Record<string, unknown>>,
  now: number,
): TrafficQuery {
  const ip = typeof input['ip'] === 'string' ? input['ip'].trim() : '';
  const host = typeof input['host'] === 'string' ? input['host'].trim().toLowerCase() : '';
  const path = typeof input['path'] === 'string' ? input['path'].trim() : '';
  if (!ip && !host && !path) return { ok: false, error: 'Indica al menos «ip», «host» o «path».' };
  if (ip && isIP(ip) === 0) {
    return { ok: false, error: 'La «ip» no es una dirección IPv4/IPv6 válida.' };
  }
  if (host.length > 255 || path.length > 300)
    return { ok: false, error: 'Filtro demasiado largo.' };
  const to = parseTime(input['to']) ?? now;
  const from = parseTime(input['from']) ?? to - 7 * DAY;
  if (from >= to) return { ok: false, error: '«from» debe ser anterior a «to».' };
  if (to - from > MAX_RANGE) return { ok: false, error: 'El rango máximo es de 31 días.' };
  const filter: Record<string, unknown>[] = [
    {
      range: {
        '@timestamp': { gte: new Date(from).toISOString(), lt: new Date(to).toISOString() },
      },
    },
  ];
  if (ip) {
    filter.push({
      bool: {
        should: [{ term: { 'client.ip': ip } }, { term: { 'audit.actor_ip': ip } }],
        minimum_should_match: 1,
      },
    });
  }
  if (host) filter.push({ term: { 'http.host': host } });
  if (path) {
    filter.push({
      wildcard: { 'http.path': { value: `*${escapeWildcard(path)}*`, case_insensitive: true } },
    });
  }
  const top = (field: string, size: number) => ({ terms: { field, size } });
  return {
    ok: true,
    from: new Date(from).toISOString(),
    to: new Date(to).toISOString(),
    body: {
      size: 25,
      track_total_hits: 100_000,
      sort: [{ '@timestamp': 'desc' }],
      _source: [
        '@timestamp',
        'event.dataset',
        'zone.name',
        'client.ip',
        'client.country',
        'client.asn_name',
        'http.method',
        'http.host',
        'http.path',
        'http.status',
        'http.user_agent',
        'dns.query',
        'firewall.action',
        'audit.action',
      ],
      query: { bool: { filter } },
      aggs: {
        datasets: top('event.dataset', 4),
        ips: top('client.ip', 10),
        countries: top('client.country', 10),
        networks: top('client.asn_name', 10),
        hosts: top('http.host', 10),
        paths: top('http.path', 15),
        methods: top('http.method', 8),
        statuses: top('http.status', 10),
        first: { min: { field: '@timestamp' } },
        last: { max: { field: '@timestamp' } },
        perDay: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: 'day',
            time_zone: 'America/Lima',
            min_doc_count: 1,
          },
        },
      },
    },
  };
}

interface Agg {
  readonly buckets?: readonly { key: unknown; key_as_string?: string; doc_count: number }[];
  readonly value_as_string?: string;
}

function buckets(aggs: Record<string, Agg> | undefined, name: string) {
  return (aggs?.[name]?.buckets ?? []).map((bucket) => ({
    value: String(bucket.key),
    count: bucket.doc_count,
  }));
}

export function cloudflareTrafficTool(
  search: CloudflareTrafficSearch,
  now: () => number = Date.now,
): AssistantTool {
  return {
    name: 'cloudflare_traffic',
    label: 'Buscando en el tráfico de Cloudflare',
    description:
      'Busca en TODO el tráfico de Cloudflare de B89 (peticiones HTTP, consultas DNS, eventos de firewall/WAF y auditoría de la cuenta) con la hora REAL de cada evento, por IP de cliente, host y/o fragmento de ruta, en un rango de hasta 31 días (por defecto los últimos 7). Úsala siempre que pregunten qué hizo una IP, quién entró al backoffice o qué pasó en un host o ruta, aunque no haya alertas: las alertas solo cubren lo que dispara reglas. Devuelve totales, primera y última vez (hora de Lima), hosts, rutas, métodos, estados, países, redes y los 25 eventos más recientes. Los datos son muestreados (≈1 de cada 11 peticiones en b89.io): cuentan registros, no peticiones exactas; que algo no aparezca no prueba que no ocurrió.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        ip: { type: 'string', maxLength: 45, description: 'IP del cliente (IPv4 o IPv6).' },
        host: {
          type: 'string',
          maxLength: 255,
          description: 'Host exacto, p. ej. prodv2-apipayments.b89.io.',
        },
        path: {
          type: 'string',
          maxLength: 300,
          description: 'Fragmento de la ruta, p. ej. /backoffice/v2/balances/export.',
        },
        from: { type: 'string', maxLength: 40, description: 'Inicio ISO 8601 con zona.' },
        to: { type: 'string', maxLength: 40, description: 'Fin ISO 8601 con zona.' },
      },
    },
    async run(input): Promise<ToolOutcome> {
      const built = buildTrafficQuery(input, now());
      if (!built.ok) return { ok: false, error: built.error };
      let raw: unknown;
      try {
        raw = await search(built.body);
      } catch (error) {
        const forbidden =
          error instanceof CloudflareTrafficError && error.code === 'TRAFFIC_FORBIDDEN';
        return {
          ok: true,
          data: {
            available: false,
            note: forbidden
              ? 'El despliegue no tiene permiso de lectura sobre el tráfico de Cloudflare.'
              : 'El índice de tráfico de Cloudflare no respondió ahora; no estimes resultados.',
          },
        };
      }
      const body = (raw ?? {}) as {
        hits?: {
          total?: { value?: number; relation?: string };
          hits?: { _source?: Record<string, unknown> }[];
        };
        aggregations?: Record<string, Agg>;
      };
      const aggs = body.aggregations;
      const events = (body.hits?.hits ?? []).map((hit) => {
        const source = hit._source ?? {};
        const pick = (group: string, key: string): string | undefined => {
          const holder = source[group];
          if (!holder || typeof holder !== 'object') return undefined;
          const value = (holder as Record<string, unknown>)[key];
          return value === undefined || value === null ? undefined : String(value).slice(0, 200);
        };
        const at = typeof source['@timestamp'] === 'string' ? source['@timestamp'] : null;
        return {
          horaLima: limaLabel(at),
          utc: at,
          tipo: pick('event', 'dataset'),
          zona: pick('zone', 'name'),
          ip: pick('client', 'ip'),
          pais: pick('client', 'country'),
          red: pick('client', 'asn_name'),
          metodo: pick('http', 'method'),
          host: pick('http', 'host'),
          ruta: pick('http', 'path'),
          estado: pick('http', 'status'),
          userAgent: pick('http', 'user_agent')?.slice(0, 120),
          dns: pick('dns', 'query'),
          firewall: pick('firewall', 'action'),
          auditoria: pick('audit', 'action'),
        };
      });
      const total = body.hits?.total?.value ?? 0;
      return {
        ok: true,
        data: {
          available: true,
          rango: {
            desdeLima: limaLabel(built.from),
            hastaLima: limaLabel(built.to),
            desdeUtc: built.from,
            hastaUtc: built.to,
          },
          total,
          totalEsMinimo: body.hits?.total?.relation === 'gte',
          muestreado: true,
          primeraVezLima: limaLabel(aggs?.['first']?.value_as_string ?? null),
          ultimaVezLima: limaLabel(aggs?.['last']?.value_as_string ?? null),
          porTipo: buckets(aggs, 'datasets'),
          porDia: (aggs?.['perDay']?.buckets ?? []).map((bucket) => ({
            dia: String(bucket.key_as_string ?? bucket.key).slice(0, 10),
            registros: bucket.doc_count,
          })),
          ips: buckets(aggs, 'ips'),
          paises: buckets(aggs, 'countries'),
          redes: buckets(aggs, 'networks'),
          hosts: buckets(aggs, 'hosts'),
          rutas: buckets(aggs, 'paths'),
          metodos: buckets(aggs, 'methods'),
          estados: buckets(aggs, 'statuses'),
          eventosRecientes: events,
          nota:
            total === 0
              ? 'Sin registros para ese filtro y rango. Por el muestreo, eso no prueba que no hubo actividad; prueba ampliar el rango.'
              : 'Registros muestreados (≈1 de cada 11 peticiones en b89.io).',
        },
      };
    },
  };
}
