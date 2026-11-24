import { describe, expect, it } from 'vitest';

import { ConfigurationError } from '../src/configuration.errors.js';
import { loadSocClosurePolicy } from '../src/configuration-loader.js';

const BASE = { B89_PROFILE: 'test' } as const;

describe('Aprendizaje SOC · etapa A · política de cierre', () => {
  it('por defecto acepta el cierre heredado sin motivo', () => {
    expect(loadSocClosurePolicy(BASE)).toEqual({ reasonRequired: false });
  });

  it.each([
    ['true', true],
    ['false', false],
  ])('lee %s', (value, expected) => {
    expect(
      loadSocClosurePolicy({ ...BASE, B89_SOC_CLOSURE_REASON_REQUIRED: value }).reasonRequired,
    ).toBe(expected);
  });

  it('rechaza un valor que no es true/false en vez de ignorarlo', () => {
    expect(() => loadSocClosurePolicy({ ...BASE, B89_SOC_CLOSURE_REASON_REQUIRED: 'yes' })).toThrow(
      ConfigurationError,
    );
  });
});
