import { describe, expect, it } from 'vitest';

import { ConfigurationError } from '../src/configuration.errors.js';
import { loadIngestionConfig } from '../src/configuration-loader.js';

/** Sprint 5 · fase 0 — la ingesta es explícita: sin declararla queda deshabilitada. */
function rejectedPath(load: () => unknown): string {
  try {
    load();
  } catch (error) {
    if (error instanceof ConfigurationError) return error.path;
    throw error;
  }
  throw new Error('Se esperaba un ConfigurationError.');
}

const BASE = { B89_PROFILE: 'test' } as const;
const WAZUH = {
  ...BASE,
  B89_INGESTION_SOURCE: 'wazuh',
  B89_WAZUH_GATEWAY_BASE_URL: 'http://krakend.demo.b89.internal:8080',
  B89_INGESTION_GATEWAY_SCOPE: 'api://00000000-0000-0000-0000-000000000000/.default',
} as const;

describe('Sprint 5 · configuración de ingesta', () => {
  it('sin variables queda deshabilitada', () => {
    expect(loadIngestionConfig(BASE)).toEqual({ source: 'disabled' });
  });

  it('wazuh con valores por defecto de intervalo, ventana y fuente', () => {
    expect(loadIngestionConfig(WAZUH)).toEqual({
      source: 'wazuh',
      sourceId: 'wazuh-indexer',
      gatewayBaseUrl: 'http://krakend.demo.b89.internal:8080',
      gatewayScope: 'api://00000000-0000-0000-0000-000000000000/.default',
      intervalMs: 60_000,
      initialLookbackMs: 3_600_000,
    });
  });

  it('acepta intervalo y ventana declarados', () => {
    expect(
      loadIngestionConfig({
        ...WAZUH,
        B89_INGESTION_INTERVAL: '30s',
        B89_INGESTION_INITIAL_LOOKBACK_MINUTES: '1440',
      }),
    ).toMatchObject({ intervalMs: 30_000, initialLookbackMs: 86_400_000 });
  });

  it('wazuh sin gateway o sin scope no arranca', () => {
    // `production` no trae URL de gateway por defecto (dev y test apuntan al local).
    const { B89_WAZUH_GATEWAY_BASE_URL: _url, ...rest } = WAZUH;
    const withoutUrl = { ...rest, B89_PROFILE: 'production' };
    const { B89_INGESTION_GATEWAY_SCOPE: _scope, ...withoutScope } = WAZUH;
    expect(rejectedPath(() => loadIngestionConfig(withoutUrl))).toBe('B89_WAZUH_GATEWAY_BASE_URL');
    expect(rejectedPath(() => loadIngestionConfig(withoutScope))).toBe(
      'B89_INGESTION_GATEWAY_SCOPE',
    );
  });

  it('rechaza fuente desconocida, scope sin /.default y ventana fuera de rango', () => {
    expect(
      rejectedPath(() => loadIngestionConfig({ ...BASE, B89_INGESTION_SOURCE: 'splunk' })),
    ).toBe('B89_INGESTION_SOURCE');
    expect(
      rejectedPath(() =>
        loadIngestionConfig({ ...WAZUH, B89_INGESTION_GATEWAY_SCOPE: 'api://algo' }),
      ),
    ).toBe('B89_INGESTION_GATEWAY_SCOPE');
    expect(
      rejectedPath(() =>
        loadIngestionConfig({ ...WAZUH, B89_INGESTION_INITIAL_LOOKBACK_MINUTES: '5000' }),
      ),
    ).toBe('B89_INGESTION_INITIAL_LOOKBACK_MINUTES');
  });
});
