import { expect, it } from 'vitest';
import { loadApiConfig, loadWorkerEntrypointConfig } from '../src/index.js';

it('requires a validated profile without resolving unused secrets', () => {
  expect(() => loadWorkerEntrypointConfig({})).toThrow();
  const config = loadWorkerEntrypointConfig({
    B89_PROFILE: 'test',
    SECRET_TOKEN: 'synthetic-sensitive',
  });
  expect(config).toEqual({ profile: 'test' });
  expect(Object.isFrozen(config)).toBe(true);
  expect(() => loadWorkerEntrypointConfig({ B89_PROFILE: 'test', B89_UNKNOWN: 'value' })).toThrow();
});

it('allows atomic ephemeral HTTP ports exclusively in our test', () => {
  expect(loadApiConfig({ B89_PROFILE: 'test', B89_API_PORT: '0' }).port).toBe(0);
  expect(() => loadApiConfig({ B89_PROFILE: 'development', B89_API_PORT: '0' })).toThrow();
  expect(() =>
    loadApiConfig({
      B89_PROFILE: 'production',
      B89_API_HOST: '127.0.0.1',
      B89_API_PORT: '0',
    }),
  ).toThrow();
});
