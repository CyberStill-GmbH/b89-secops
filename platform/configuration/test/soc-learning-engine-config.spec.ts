import { describe, expect, it } from 'vitest';

import { ConfigurationError } from '../src/configuration.errors.js';
import { loadLearningEngine, loadSocLearningApprovers } from '../src/configuration-loader.js';
import { redactSecrets } from '../src/redaction/index.js';

const BASE = { B89_PROFILE: 'test' } as const;
const PRODUCTION = { B89_PROFILE: 'production' } as const;
const KEY = 'k'.repeat(40);

describe('Aprendizaje SOC · etapa D · aprobadores designados', () => {
  it('vacío por defecto (la activación queda bloqueada)', () => {
    expect(loadSocLearningApprovers(BASE)).toEqual({ approvers: [] });
  });

  it('lee personas separadas por coma', () => {
    expect(
      loadSocLearningApprovers({ ...BASE, B89_SOC_LEARNING_APPROVERS: 'lead-a, lead-b' }),
    ).toEqual({
      approvers: ['lead-a', 'lead-b'],
    });
  });

  it.each(['svc:b89-soc-learning', 'lead-a,lead-a', 'lead a'])('rechaza %s', (value) => {
    expect(() => loadSocLearningApprovers({ ...BASE, B89_SOC_LEARNING_APPROVERS: value })).toThrow(
      ConfigurationError,
    );
  });
});

describe('Aprendizaje SOC · etapa E · motor', () => {
  it('apagado por defecto, techo en sombra y topes conservadores', () => {
    expect(loadLearningEngine(BASE)).toMatchObject({
      enabled: false,
      maxMode: 'shadow',
      activeRules: [],
      killSwitch: false,
      samplingKey: undefined,
      samplingPercent: 10,
      hourlyCap: 10,
      dailyCap: 30,
      forcedReviewAfter: 20,
      changeCalendarAckUntil: null,
      refreshMinutes: 15,
    });
  });

  it('lee reglas activas, kill switch y calendario confirmado', () => {
    const config = loadLearningEngine({
      ...BASE,
      B89_LEARNING_ENABLED: 'true',
      B89_LEARNING_MAX_MODE: 'active',
      B89_LEARNING_ACTIVE_RULES: 'linux-process:100200, windows-security:4625',
      B89_LEARNING_KILLED_RULES: 'network:101830',
      B89_LEARNING_SAMPLING_KEY: KEY,
      B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL: '2026-12-20',
    });
    expect(config.activeRules).toEqual(['linux-process:100200', 'windows-security:4625']);
    expect(config.killedRules).toEqual(['network:101830']);
    expect(config.changeCalendarAckUntil?.toISOString()).toBe('2026-12-20T00:00:00.000Z');
    expect(config.samplingKey?.reveal()).toBe(KEY);
  });

  it('la clave de muestreo nunca aparece al redactar la configuración', () => {
    const config = loadLearningEngine({ ...BASE, B89_LEARNING_SAMPLING_KEY: KEY });
    expect(JSON.stringify(redactSecrets(config))).not.toContain(KEY);
  });

  it.each([
    ['B89_LEARNING_MAX_MODE', 'on'],
    ['B89_LEARNING_ENABLED', 'yes'],
    ['B89_LEARNING_ACTIVE_RULES', 'sin-dos-puntos'],
    ['B89_LEARNING_SAMPLING_KEY', 'corta'],
    ['B89_LEARNING_SAMPLING_PERCENT', '0'],
    ['B89_LEARNING_HOURLY_CAP', '0'],
    ['B89_LEARNING_REFRESH_MINUTES', '1'],
    ['B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL', 'mañana'],
  ])('rechaza %s=%s en vez de ignorarlo', (name, value) => {
    expect(() => loadLearningEngine({ ...BASE, [name]: value })).toThrow(ConfigurationError);
  });

  it('producción: dry_run/active exigen registro del cambio y clave de muestreo', () => {
    expect(() => loadLearningEngine({ ...PRODUCTION, B89_LEARNING_MAX_MODE: 'active' })).toThrow(
      ConfigurationError,
    );
    expect(() =>
      loadLearningEngine({
        ...PRODUCTION,
        B89_LEARNING_MAX_MODE: 'active',
        B89_LEARNING_PROMOTION_REF: 'docs/22#2026-12-01',
      }),
    ).toThrow(ConfigurationError);
    expect(
      loadLearningEngine({
        ...PRODUCTION,
        B89_LEARNING_MAX_MODE: 'active',
        B89_LEARNING_PROMOTION_REF: 'docs/22#2026-12-01',
        B89_LEARNING_SAMPLING_KEY: KEY,
      }).maxMode,
    ).toBe('active');
    expect(loadLearningEngine({ ...PRODUCTION, B89_LEARNING_MAX_MODE: 'shadow' }).maxMode).toBe(
      'shadow',
    );
  });
});
