import { describe, expect, it } from 'vitest';

import {
  buildTrafficQuery,
  cloudflareTrafficTool,
} from '../src/assistant/cloudflare-traffic-tool.js';
import { CloudflareTrafficError } from '../src/runtime/cloudflare-traffic.js';

const NOW = Date.parse('2026-11-18T21:00:00Z');

describe('Bunny · tráfico de Cloudflare', () => {
  it('construye la consulta por IP con la hora real y un rango acotado', () => {
    const built = buildTrafficQuery(
      { ip: '200.111.95.19', from: '2026-11-11T00:00:00-05:00', to: '2026-11-18T00:00:00-05:00' },
      NOW,
    );
    if (!built.ok) throw new Error(built.error);
    const filter = (built.body['query'] as { bool: { filter: unknown[] } }).bool.filter;
    expect(JSON.stringify(filter)).toContain('"client.ip":"200.111.95.19"');
    expect(built.from).toBe('2026-11-11T05:00:00.000Z');
  });

  it('rechaza IP inválida, sin filtros o rango mayor a 31 días', () => {
    expect(buildTrafficQuery({ ip: '200.111.95' }, NOW).ok).toBe(false);
    expect(buildTrafficQuery({}, NOW).ok).toBe(false);
    expect(
      buildTrafficQuery(
        { host: 'b89.io', from: '2026-09-01T00:00:00Z', to: '2026-11-01T00:00:00Z' },
        NOW,
      ).ok,
    ).toBe(false);
  });

  it('escapa comodines de la ruta (nunca DSL del usuario)', () => {
    const built = buildTrafficQuery({ path: '/x*?y' }, NOW);
    if (!built.ok) throw new Error(built.error);
    expect(JSON.stringify(built.body)).toContain('*/x\\\\*\\\\?y*');
  });

  it('resume la respuesta en hora de Lima y avisa del muestreo', async () => {
    const tool = cloudflareTrafficTool(
      async () => ({
        hits: {
          total: { value: 2, relation: 'eq' },
          hits: [
            {
              _source: {
                '@timestamp': '2026-11-16T17:00:16Z',
                event: { dataset: 'http' },
                client: { ip: '54.156.173.233', country: 'US', asn_name: 'Amazon.com, Inc.' },
                http: {
                  method: 'POST',
                  host: 'prodv2-apipayments.b89.io',
                  path: '/backoffice/v2/remittance/orders/bulk-status',
                  status: 200,
                },
              },
            },
          ],
        },
        aggregations: { first: { value_as_string: '2026-11-16T17:00:16Z' } },
      }),
      () => NOW,
    );
    const outcome = await tool.run({ ip: '54.156.173.233' });
    expect(outcome.ok).toBe(true);
    const data = (outcome as { data: Record<string, unknown> }).data;
    expect(data['available']).toBe(true);
    expect(data['muestreado']).toBe(true);
    const events = data['eventosRecientes'] as { ruta?: string; red?: string }[];
    expect(events[0]?.ruta).toBe('/backoffice/v2/remittance/orders/bulk-status');
    expect(events[0]?.red).toBe('Amazon.com, Inc.');
  });

  it('si el índice no responde lo dice, sin inventar', async () => {
    const tool = cloudflareTrafficTool(async () => {
      throw new CloudflareTrafficError('TRAFFIC_UNAVAILABLE');
    });
    const outcome = await tool.run({ ip: '200.111.95.19' });
    expect((outcome as { data: Record<string, unknown> }).data['available']).toBe(false);
  });
});
