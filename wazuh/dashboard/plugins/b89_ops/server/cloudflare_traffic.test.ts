/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { normalizeTrafficFilters, TrafficFilters } from '../common/cloudflare_traffic';
import {
  decodeCursor,
  encodeCursor,
  exportFilename,
  exportTrafficCsv,
  FREE_TEXT_FIELDS,
  parseTrafficAggregations,
  parseTrafficEvent,
  searchTraffic,
  trafficSearchBody,
  wildcardLiteral,
} from './cloudflare_traffic';
import type { SearchClient } from './overview';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

function filters(extra: Record<string, string | string[]> = {}): TrafficFilters {
  const result = normalizeTrafficFilters({
    from: '2026-11-17T17:00:00Z',
    to: '2026-11-18T17:00:00Z',
    ...extra,
  });
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

const clauses = (body: Json): Json[] => body.query.bool.filter;

describe('tráfico de Cloudflare: consulta', () => {
  it('rango por @timestamp, orden desc y total acotado; el tipo va en post_filter', () => {
    const body = trafficSearchBody({
      filters: filters({ dataset: 'http' }),
      withAggregations: true,
    });
    expect(clauses(body)[0]).toEqual({
      range: {
        '@timestamp': {
          gte: '2026-11-17T17:00:00.000Z',
          lte: '2026-11-18T17:00:00.000Z',
          format: 'strict_date_optional_time',
        },
      },
    });
    expect(body.sort[0]).toEqual({ '@timestamp': { order: 'desc' } });
    expect(body.track_total_hits).toBe(100000);
    expect(body.post_filter).toEqual({ terms: { 'event.dataset': ['http'] } });
    // Las pestañas cuentan todos los tipos; el resto de agregaciones respeta el tipo elegido.
    expect(body.aggs.datasets).toEqual({ terms: { field: 'event.dataset', size: 4 } });
    expect(body.aggs.scoped.filter).toEqual({ terms: { 'event.dataset': ['http'] } });
    expect(body.aggs.scoped.aggs.histogram.auto_date_histogram.time_zone).toBe('America/Lima');
  });

  it('tamaño de página entre 1 y 200, sin agregaciones al paginar', () => {
    expect(trafficSearchBody({ filters: filters(), size: 5000 }).size).toBe(200);
    expect(trafficSearchBody({ filters: filters(), size: 0 }).size).toBe(1);
    const page = trafficSearchBody({ filters: filters(), searchAfter: [1, 2] });
    expect(page.search_after).toEqual([1, 2]);
    expect(page.aggs).toBeUndefined();
  });

  it('cada filtro produce una cláusula term/range/wildcard sobre su campo', () => {
    const body = trafficSearchBody({
      filters: filters({
        zone: 'b89.io',
        ip: '1.2.3.4',
        host: 'app.b89.io',
        path: '/login',
        method: 'POST',
        status: '5xx',
        country: 'PE',
        asn: '6147',
        ua: 'curl/8.0',
      }),
    });
    const text = JSON.stringify(clauses(body));
    expect(text).toContain('{"terms":{"zone.name":["b89.io"]}}');
    expect(text).toContain('{"term":{"client.ip":"1.2.3.4"}}');
    expect(text).toContain('{"term":{"audit.actor_ip":"1.2.3.4"}}');
    expect(text).toContain('{"term":{"http.host":"app.b89.io"}}');
    expect(text).toContain(
      '{"wildcard":{"http.path":{"value":"*/login*","case_insensitive":true}}}',
    );
    expect(text).toContain('{"term":{"http.method":"POST"}}');
    expect(text).toContain('{"range":{"http.status":{"gte":500,"lte":599}}}');
    expect(text).toContain('{"term":{"client.country":"PE"}}');
    expect(text).toContain('{"term":{"client.asn":6147}}');
    expect(text).toContain('{"term":{"http.user_agent":"curl/8.0"}}');
    expect(
      JSON.stringify(trafficSearchBody({ filters: filters({ status: '404' }) }).query),
    ).toContain('{"term":{"http.status":404}}');
  });

  it('seguridad: los comodines del usuario se escapan y el texto libre no toca otros campos', () => {
    expect(wildcardLiteral('a*b?c\\')).toBe('a\\*b\\?c\\\\');
    const body = trafficSearchBody({ filters: filters({ path: '*', q: 'login OR *:*' }) });
    const wildcard = clauses(body).find((clause) => clause.wildcard);
    expect(wildcard?.wildcard['http.path'].value).toBe('*\\**');
    const sqs = clauses(body).find((clause) => clause.simple_query_string)?.simple_query_string;
    expect(sqs.fields).toEqual([...FREE_TEXT_FIELDS]);
    expect(sqs.fields).not.toContain('*');
    expect(sqs.flags).not.toMatch(/FUZZY|NEAR|SLOP|ALL/u);
    expect(sqs.lenient).toBe(true);
    // Nada de query_string, script ni DSL arbitrario.
    const text = JSON.stringify(body);
    expect(text).not.toContain('"query_string"');
    expect(text).not.toContain('"script"');
  });

  it('un objeto JSON como filtro no se convierte en DSL', () => {
    expect(
      normalizeTrafficFilters({
        from: '2026-11-17T17:00:00Z',
        to: '2026-11-18T17:00:00Z',
        host: '{"match_all":{}}',
      }).ok,
    ).toBe(false);
  });
});

describe('tráfico de Cloudflare: cursor', () => {
  it('ida y vuelta atado a los filtros', () => {
    const base = filters({ ip: '1.2.3.4' });
    const cursor = encodeCursor(base, [1763400000000, 42]) as string;
    expect(decodeCursor(cursor, base)).toEqual([1763400000000, 42]);
    expect(() => decodeCursor(cursor, filters({ ip: '5.6.7.8' }))).toThrow('Cursor no válido');
    expect(() => decodeCursor('no válido!', base)).toThrow('Cursor no válido');
    expect(() => decodeCursor('x'.repeat(600), base)).toThrow('Cursor no válido');
    expect(encodeCursor(base, ['a', 1])).toBeNull();
  });
});

const HIT = {
  _id: 'abc',
  _index: 'b89-cloudflare-traffic-2026.11.17',
  sort: [Date.parse('2026-11-17T17:00:00Z'), 7],
  _source: {
    '@timestamp': '2026-11-17T17:00:00Z',
    ingested_at: '2026-11-17T17:01:00Z',
    event: { dataset: 'http', source: 'graphql-live', sampled: true, history: false },
    zone: { name: 'b89.io', id: 'z1' },
    client: { ip: '1.2.3.4', country: 'PE', asn: 6147, asn_name: 'Telefonica' },
    http: {
      host: 'app.b89.io',
      method: 'POST',
      path: '/login',
      status: 401,
      user_agent: 'curl/8.0',
      security_action: 'managed_challenge',
    },
  },
};

describe('tráfico de Cloudflare: lectura', () => {
  it('evento con sus campos y el documento completo', () => {
    const event = parseTrafficEvent(HIT);
    expect(event).toMatchObject({
      id: 'abc',
      at: '2026-11-17T17:00:00.000Z',
      dataset: 'http',
      sampled: true,
      history: false,
      zone: 'b89.io',
      clientIp: '1.2.3.4',
      country: 'PE',
      asn: 6147,
      method: 'POST',
      host: 'app.b89.io',
      path: '/login',
      status: 401,
      action: 'managed_challenge',
    });
    expect(event.raw).toBe(HIT._source);
  });

  it('auditoría: la IP del actor y un resumen', () => {
    const event = parseTrafficEvent({
      _id: 'x',
      _source: {
        '@timestamp': '2026-11-17T18:00:00Z',
        event: { dataset: 'audit', history: true },
        audit: {
          action: 'token_create',
          result: 'success',
          actor_email: 'a@b89.io',
          actor_ip: '9.9.9.9',
          zone_name: 'b89.io',
        },
      },
    });
    expect(event).toMatchObject({ clientIp: '9.9.9.9', zone: 'b89.io', history: true });
    expect(event.detail).toBe('token_create · success · a@b89.io');
  });

  it('agregaciones: pestañas, histograma, cifras y listas', () => {
    const aggs = parseTrafficAggregations({
      datasets: {
        buckets: [
          { key: 'http', doc_count: 10 },
          { key: 'dns', doc_count: 3 },
        ],
      },
      scoped: {
        histogram: {
          interval: '1h',
          buckets: [
            {
              key: Date.parse('2026-11-17T17:00:00Z'),
              doc_count: 13,
              datasets: {
                buckets: [
                  { key: 'http', doc_count: 10 },
                  { key: 'dns', doc_count: 3 },
                ],
              },
            },
          ],
        },
        unique_ips: { value: 4 },
        countries: { value: 2 },
        with_status: { doc_count: 10 },
        errors_4xx: { doc_count: 2 },
        errors_5xx: { doc_count: 1 },
        sampled: { doc_count: 9 },
        top_ips: { buckets: [{ key: '1.2.3.4', doc_count: 8 }] },
        status_classes: {
          buckets: [
            { key: '2xx', doc_count: 7 },
            { key: '5xx', doc_count: 0 },
          ],
        },
      },
    });
    expect(aggs.datasets).toEqual({ http: 10, dns: 3, firewall: 0, audit: 0 });
    expect(aggs.histogram[0]).toEqual({
      at: '2026-11-17T17:00:00.000Z',
      total: 13,
      byDataset: { http: 10, dns: 3 },
    });
    expect(aggs).toMatchObject({
      uniqueIps: 4,
      countries: 2,
      errors4xx: 2,
      errors5xx: 1,
      sampled: 9,
    });
    expect(aggs.topIps).toEqual([{ key: '1.2.3.4', count: 8 }]);
    expect(aggs.statusClasses).toEqual([{ key: '2xx', count: 7 }]);
    expect(aggs.topHosts).toEqual([]);
  });
});

describe('tráfico de Cloudflare: ejecución', () => {
  it('consulta b89-cloudflare-traffic-* y entrega cursor si la página está llena', async () => {
    const calls: Json[] = [];
    const client: SearchClient = {
      search: async (params) => {
        calls.push(params);
        return { body: { hits: { total: { value: 100000, relation: 'gte' }, hits: [HIT] } } };
      },
    };
    const base = filters();
    const page = await searchTraffic(client, base, { size: 1 });
    expect(calls[0].index).toBe('b89-cloudflare-traffic-*');
    expect(page.total).toEqual({ value: 100000, relation: 'gte' });
    expect(page.nextCursor).not.toBeNull();
    expect(page.aggregations).not.toBeNull();
    const next = await searchTraffic(client, base, { size: 1, cursor: page.nextCursor as string });
    expect(calls[1].body.search_after).toEqual(HIT.sort);
    expect(next.aggregations).toBeNull();
  });

  it('CSV por bloques con tope de filas, BOM y nombre de archivo', async () => {
    let call = 0;
    const client: SearchClient = {
      search: async () => {
        call += 1;
        return { body: { hits: { hits: [HIT, { ...HIT, _id: 'def' }] } } };
      },
    };
    const rows = await exportTrafficCsv(client, filters(), 2);
    let text = '';
    for await (const chunk of rows) text += chunk;
    const lines = text.split('\r\n').filter(Boolean);
    expect(lines[0].startsWith('﻿hora_lima,@timestamp')).toBe(true);
    expect(lines).toHaveLength(3);
    expect(lines[1].startsWith('2026-11-17 12:00:00,2026-11-17T17:00:00Z')).toBe(true);
    expect(call).toBe(1);
    expect(exportFilename(filters())).toBe(
      'b89-cloudflare-trafico_20261117T170000Z_20261118T170000Z.csv',
    );
  });

  it('CSV: un 403 llega antes de empezar la descarga', async () => {
    const client: SearchClient = {
      search: async () => {
        throw Object.assign(new Error('no'), { statusCode: 403 });
      },
    };
    await expect(exportTrafficCsv(client, filters())).rejects.toThrow('no');
  });
});
