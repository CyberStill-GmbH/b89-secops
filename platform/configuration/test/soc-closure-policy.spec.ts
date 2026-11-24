import { describe, expect, it } from 'vitest';

import { ConfigurationError } from '../src/configuration.errors.js';
import { loadSocClosurePolicy, loadSocGrouping } from '../src/configuration-loader.js';

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

describe('Aprendizaje SOC · etapa C · agrupación', () => {
  it('por defecto agrupa con 24 h de ventana, 7 d de tramo y 500 alertas por grupo', () => {
    expect(loadSocGrouping(BASE)).toEqual({
      enabled: true,
      windowMs: 24 * 60 * 60 * 1000,
      maxSpanMs: 7 * 24 * 60 * 60 * 1000,
      maxAlerts: 500,
    });
  });

  it('el tope de alertas por grupo se ajusta dentro de 2–10000', () => {
    expect(loadSocGrouping({ ...BASE, B89_SOC_GROUPING_MAX_ALERTS: '50' }).maxAlerts).toBe(50);
    expect(() => loadSocGrouping({ ...BASE, B89_SOC_GROUPING_MAX_ALERTS: '1' })).toThrow(
      ConfigurationError,
    );
    expect(() => loadSocGrouping({ ...BASE, B89_SOC_GROUPING_MAX_ALERTS: '10001' })).toThrow(
      ConfigurationError,
    );
  });

  it('se puede apagar y ajustar dentro de los límites', () => {
    expect(
      loadSocGrouping({
        ...BASE,
        B89_SOC_GROUPING_ENABLED: 'false',
        B89_SOC_GROUPING_WINDOW_HOURS: '6',
        B89_SOC_GROUPING_MAX_SPAN_DAYS: '2',
      }),
    ).toEqual({
      enabled: false,
      windowMs: 6 * 60 * 60 * 1000,
      maxSpanMs: 2 * 24 * 60 * 60 * 1000,
      maxAlerts: 500,
    });
  });

  it.each([
    { B89_SOC_GROUPING_ENABLED: 'si' },
    { B89_SOC_GROUPING_WINDOW_HOURS: '0' },
    { B89_SOC_GROUPING_WINDOW_HOURS: '200' },
    { B89_SOC_GROUPING_MAX_SPAN_DAYS: '31' },
    { B89_SOC_GROUPING_WINDOW_HOURS: '72', B89_SOC_GROUPING_MAX_SPAN_DAYS: '2' },
  ])('rechaza %o', (overrides) => {
    expect(() => loadSocGrouping({ ...BASE, ...overrides })).toThrow(ConfigurationError);
  });
});
