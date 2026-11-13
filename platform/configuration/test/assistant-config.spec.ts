import { describe, expect, it } from 'vitest';

import {
  ASSISTANT_VARIABLES,
  ConfigurationError,
  KNOWN_B89_VARIABLES,
  loadApiConfig,
} from '../src/index.js';

function expectInvalid(environment: Record<string, string>, code: string, path: string): void {
  try {
    loadApiConfig({ B89_PROFILE: 'test', ...environment });
    throw new Error('Expected ConfigurationError');
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigurationError);
    expect(error).toMatchObject({ code, path });
    // El valor (posible secreto) nunca aparece en el error.
    for (const value of Object.values(environment)) {
      if (value.length > 6) expect(String((error as Error).message)).not.toContain(value);
    }
  }
}

describe('variables de Bunny en platform/configuration', () => {
  it('todas las variables del asistente son conocidas (el API arranca con Bunny activo)', () => {
    for (const name of ASSISTANT_VARIABLES) expect(KNOWN_B89_VARIABLES.has(name)).toBe(true);
    expect(() =>
      loadApiConfig({
        B89_PROFILE: 'production',
        B89_BUNNY_ENABLED: 'true',
        B89_BUNNY_PROVIDER: 'anthropic',
        B89_BUNNY_MODEL: 'claude-sonnet-5-5',
        B89_BUNNY_EFFORT: 'medium',
        B89_BUNNY_REDACT_PII: 'true',
        B89_BUNNY_API_KEY: 'sk-ant-api03-test-value',
        B89_BUNNY_TIMEOUT_MS: '20000',
        B89_BUNNY_RATE_LIMIT: '20',
        B89_BUNNY_HISTORY_ENABLED: 'true',
        B89_BUNNY_RETENTION_DAYS: '90',
      }),
    ).not.toThrow();
  });

  it('Bunny apagado o sin variables no exige nada', () => {
    expect(() => loadApiConfig({ B89_PROFILE: 'test' })).not.toThrow();
    expect(() => loadApiConfig({ B89_PROFILE: 'test', B89_BUNNY_ENABLED: 'false' })).not.toThrow();
  });

  it('rechaza valores inválidos sin exponerlos', () => {
    expectInvalid({ B89_BUNNY_ENABLED: 'si' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_ENABLED');
    expectInvalid({ B89_BUNNY_PROVIDER: 'deepseek' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_PROVIDER');
    expectInvalid({ B89_BUNNY_EFFORT: 'enorme' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_EFFORT');
    expectInvalid({ B89_BUNNY_MODEL: 'a b' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_MODEL');
    expectInvalid({ B89_BUNNY_RATE_LIMIT: '0' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_RATE_LIMIT');
    expectInvalid(
      { B89_BUNNY_RETENTION_DAYS: '366' },
      'CONFIG_VALUE_INVALID',
      'B89_BUNNY_RETENTION_DAYS',
    );
    expectInvalid({ B89_BUNNY_TIMEOUT_MS: '10' }, 'CONFIG_VALUE_INVALID', 'B89_BUNNY_TIMEOUT_MS');
    expectInvalid(
      { B89_BUNNY_API_KEY: 'clave con espacios' },
      'CONFIG_VALUE_INVALID',
      'B89_BUNNY_API_KEY',
    );
  });

  it('anthropic activo exige B89_BUNNY_API_KEY', () => {
    expectInvalid(
      { B89_BUNNY_ENABLED: 'true', B89_BUNNY_PROVIDER: 'anthropic' },
      'CONFIG_REQUIRED_VALUE_MISSING',
      'B89_BUNNY_API_KEY',
    );
  });
});

describe('variables de informes de Bunny (B89_REPORTS_*)', () => {
  const token = 'tok-' + 'a'.repeat(40);

  it('son conocidas y el API arranca con ellas (o sin ellas: función apagada)', () => {
    expect(KNOWN_B89_VARIABLES.has('B89_REPORTS_URL')).toBe(true);
    expect(KNOWN_B89_VARIABLES.has('B89_REPORTS_TOKEN')).toBe(true);
    for (const name of ['B89_REPORTS_URL', 'B89_REPORTS_TOKEN']) {
      expect((ASSISTANT_VARIABLES as readonly string[]).includes(name)).toBe(true);
    }
    expect(() =>
      loadApiConfig({
        B89_PROFILE: 'production',
        B89_REPORTS_URL: 'http://reports:8090',
        B89_REPORTS_TOKEN: token,
      }),
    ).not.toThrow();
    expect(() => loadApiConfig({ B89_PROFILE: 'test' })).not.toThrow();
  });

  it('rechaza URL o token inválidos sin exponer el valor', () => {
    expectInvalid({ B89_REPORTS_URL: 'no-es-url', B89_REPORTS_TOKEN: token }, 'CONFIG_VALUE_INVALID', 'B89_REPORTS_URL');
    expectInvalid({ B89_REPORTS_URL: 'ftp://reports:8090', B89_REPORTS_TOKEN: token }, 'CONFIG_VALUE_INVALID', 'B89_REPORTS_URL');
    expectInvalid(
      { B89_REPORTS_URL: 'http://user:pass@reports:8090', B89_REPORTS_TOKEN: token },
      'CONFIG_VALUE_INVALID',
      'B89_REPORTS_URL',
    );
    expectInvalid({ B89_REPORTS_URL: 'http://reports:8090', B89_REPORTS_TOKEN: 'corto' }, 'CONFIG_VALUE_INVALID', 'B89_REPORTS_TOKEN');
    expectInvalid(
      { B89_REPORTS_URL: 'http://reports:8090', B89_REPORTS_TOKEN: 'con espacios ' + 'x'.repeat(20) },
      'CONFIG_VALUE_INVALID',
      'B89_REPORTS_TOKEN',
    );
  });

  it('una URL sin token es un error de configuración (nunca un servicio sin autenticar)', () => {
    expectInvalid(
      { B89_REPORTS_URL: 'http://reports:8090' },
      'CONFIG_REQUIRED_VALUE_MISSING',
      'B89_REPORTS_TOKEN',
    );
  });
});
