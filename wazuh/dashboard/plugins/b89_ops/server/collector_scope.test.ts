/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */
import { describe, expect, it } from 'vitest';

import { parsePlatformHealth } from '../common/platform_health';
import { withCollectorScope } from './overview';

const health = (doc: Record<string, unknown>) =>
  parsePlatformHealth({
    aggregations: {
      status: {
        sources: {
          buckets: [
            {
              key: 'cloudflare',
              latest: {
                hits: {
                  hits: [
                    {
                      _source: {
                        timestamp: '2026-11-16T21:35:13.124Z',
                        data: { b89: { health: doc } },
                      },
                    },
                  ],
                },
              },
            },
          ],
        },
      },
      keys: { buckets: [] },
    },
  });

describe('zonas de Cloudflare vigiladas (alcance del collector)', () => {
  it('muestra las zonas que el collector vigila y aparte cuántas tuvieron eventos', () => {
    const parsed = health({
      source: 'cloudflare',
      source_state: 'ok',
      scope_kind: 'zones',
      scope_count: '3',
      scope_items: 'a, b, c',
    });
    expect(parsed.sources.cloudflare.scopeCount).toBe(3);
    const providers = withCollectorScope(
      { cloudflare: { metrics: { zones: 2, http_24h: 0 } } },
      parsed,
    );
    expect(providers.cloudflare.metrics).toMatchObject({ zones: 3, zones_active: 2 });
  });

  it('sin alcance publicado conserva el conteo por eventos', () => {
    const parsed = health({ source: 'cloudflare', source_state: 'ok' });
    const providers = withCollectorScope({ cloudflare: { metrics: { zones: 2 } } }, parsed);
    expect(providers.cloudflare.metrics).toEqual({ zones: 2 });
  });
});
