/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  eventOf,
  findRelated,
  findSource,
  nearest,
  relatedQuery,
  sourceQuery,
} from './investigation';
import type { SearchClient } from './overview';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const hit = (id: string, timestamp: string, extra: Json = {}) => ({
  _id: id,
  _index: 'wazuh-alerts-4.x-2026.11.08',
  _source: {
    timestamp,
    agent: { id: '000', name: 'wazuh.manager' },
    rule: {
      id: '101503',
      level: 5,
      description: 'B89 Cloudflare: cambio DNS',
      groups: ['cloudflare'],
      mitre: { id: ['T1584.002'], tactic: ['Resource Development'], technique: ['DNS Server'] },
    },
    data: { cloudflare: { zone_name: 'b89.io' } },
    ...extra,
  },
});

function client(responses: unknown[], seen: Json[] = []): SearchClient {
  return {
    search: async (params) => {
      seen.push(params);
      const next = responses.shift();
      if (next instanceof Error) throw next;
      return { body: next };
    },
  };
}

describe('evento de origen', () => {
  it('busca por regla, descripción y ±5 min, y elige el más cercano', async () => {
    const seen: Json[] = [];
    const result = await findSource(
      client(
        [
          {
            hits: {
              hits: [
                hit('a', '2026-11-08T14:50:00.000+0000'),
                hit('b', '2026-11-08T14:57:31.925+0000'),
              ],
            },
          },
        ],
        seen,
      ),
      {
        ruleId: '101503',
        at: '2026-11-08T14:57:31.925Z',
        description: 'B89 Cloudflare: cambio DNS',
      },
    );
    expect(result.match).toBe('matched');
    expect(result.event?.id).toBe('b');
    expect(result.event?.vendor).toBe('cloudflare');
    expect(result.event?.mitre.ids).toEqual(['T1584.002']);
    expect(seen[0].index).toBe('wazuh-alerts-*');
    expect(JSON.stringify(seen[0].body)).toContain(
      '"rule.description":"B89 Cloudflare: cambio DNS"',
    );
  });

  it('reintenta sin descripción si no hay coincidencia exacta', async () => {
    const seen: Json[] = [];
    const result = await findSource(
      client(
        [{ hits: { hits: [] } }, { hits: { hits: [hit('c', '2026-11-08T14:57:00.000+0000')] } }],
        seen,
      ),
      { ruleId: '101503', at: '2026-11-08T14:57:31.925Z', description: 'otra' },
    );
    expect(seen).toHaveLength(2);
    expect(result.event?.id).toBe('c');
  });

  it('un 403 del Security plugin es «forbidden», no un error', async () => {
    const forbidden = Object.assign(new Error('no'), { statusCode: 403 });
    const result = await findSource(client([forbidden]), {
      ruleId: '1',
      at: '2026-11-08T00:00:00Z',
    });
    expect(result).toEqual({ access: 'forbidden', match: 'none', event: null });
  });

  it('sin regla ni id no consulta', () => {
    expect(sourceQuery({ at: '2026-11-08T00:00:00Z' })).toBeNull();
  });

  it('recorta documentos enormes', () => {
    const event = eventOf(hit('d', '2026-11-08T00:00:00.000+0000', { full_log: 'x'.repeat(70000) }));
    expect(event.rawTruncated).toBe(true);
    expect(JSON.stringify(event.raw).length).toBeLessThan(2000);
  });

  it('nearest sin hora devuelve el primero', () => {
    expect(nearest([{ _id: 'x' }, { _id: 'y' }])).toEqual({ _id: 'x' });
  });
});

describe('eventos relacionados', () => {
  it('consulta cualquier campo de las entidades en la ventana y excluye el origen', () => {
    const body = relatedQuery({
      entities: [{ kind: 'zone', value: 'b89.io' }],
      at: Date.parse('2026-11-08T12:00:00Z'),
      window: '1h',
      excludeId: 'src',
    }) as Json;
    expect(body.query.bool.filter[0].range.timestamp).toEqual({
      gte: '2026-11-08T11:00:00.000Z',
      lte: '2026-11-08T13:00:00.000Z',
    });
    expect(body.query.bool.should).toHaveLength(2);
    expect(body.query.bool.must_not).toEqual([{ ids: { values: ['src'] } }]);
    expect(Object.keys(body.aggs.perEntity.filters.filters)).toEqual(['zone:b89.io']);
  });

  it('marca qué entidades aparecen en cada evento y cuenta por entidad', async () => {
    const result = await findRelated(
      client([
        {
          hits: { total: { value: 1 }, hits: [hit('e', '2026-11-08T12:00:00.000+0000')] },
          aggregations: { perEntity: { buckets: { 'zone:b89.io': { doc_count: 7 } } } },
        },
      ]),
      { entities: [{ kind: 'zone', value: 'b89.io' }], at: Date.now(), window: '24h' },
    );
    expect(result.total).toBe(1);
    expect(result.events[0].matched).toEqual(['zone:b89.io']);
    expect(result.perEntity).toEqual({ 'zone:b89.io': 7 });
  });
});
