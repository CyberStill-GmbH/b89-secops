import { describe, expect, it } from 'vitest';
import { groupAlertReasons } from './alert_reasons';

describe('groupAlertReasons', () => {
  it('keeps ordinary alerts as a single priority group with their codes', () => {
    const grouped = groupAlertReasons([
      { code: 'SEVERITY', detail: 'Nivel 12 de Wazuh.' },
      { code: 'CRITICAL_ASSET', detail: 'Equipo crítico.' },
    ]);
    expect(grouped.scope).toBeNull();
    expect(grouped.groups).toHaveLength(1);
    expect(grouped.groups[0]).toMatchObject({
      id: 'priority',
      items: [{ code: 'SEVERITY' }, { code: 'CRITICAL_ASSET' }],
    });
  });

  it('groups correlator reasons as rendered by the API, without rewriting them', () => {
    const grouped = groupAlertReasons([
      { code: 'ATTACK_CHAIN', detail: 'Patrón identity-change (complete, 3/3 etapas).' },
      {
        code: 'ATTACK_CHAIN',
        detail: 'Explicación: Correlación temporal; no demuestra causalidad ni compromiso.',
      },
      {
        code: 'ATTACK_CHAIN',
        detail:
          'Etapa 1: identity.change · regla 91600 · m365 · 2026-11-18T09:00:00.000Z · criterio: data.office365.Operation=User registered security info',
      },
      { code: 'CORRELATED_ENTITY', detail: 'Evidencia (alertas Wazuh): 1.1, 1.2' },
      { code: 'CORRELATED_ENTITY', detail: 'Siguiente paso: Validar con la persona.' },
      { code: 'CORRELATED_ENTITY', detail: 'Regla: versión sequence-v2-abc · ventana 86400 s' },
      {
        code: 'CORRELATED_ENTITY',
        detail: 'Umbral fuentes distintas: requerido >= 2 · observado 2 · cumplido',
      },
      {
        code: 'CORRELATED_ENTITY',
        detail: 'Umbral confianza del pivote: requerido >= medium · observado low · no cumplido',
      },
      {
        code: 'CORRELATED_ENTITY',
        detail:
          'Contradicción: 1 alertas vinculadas tienen veredicto de analista benigno o falso positivo.',
      },
      { code: 'CORRELATED_ENTITY', detail: 'Dato faltante: Cobertura de windows no verificada.' },
      {
        code: 'CORRELATED_ENTITY',
        detail:
          'Alcance: candidate: agrupación propuesta para investigar; no es un incidente aceptado por el SOC',
      },
    ]);
    expect(grouped.scope).toBe(
      'candidate: agrupación propuesta para investigar; no es un incidente aceptado por el SOC',
    );
    expect(grouped.groups.map((group) => group.id)).toEqual([
      'priority',
      'chain',
      'thresholds',
      'contradictions',
      'missing',
      'evidence',
      'nextSteps',
    ]);
    const byId = Object.fromEntries(grouped.groups.map((group) => [group.id, group.items]));
    expect(byId.chain?.[0]?.text).toBe(
      'Correlación temporal; no demuestra causalidad ni compromiso.',
    );
    expect(byId.chain?.[1]?.text).toMatch(/^Etapa 1: identity\.change .* criterio: /u);
    expect(byId.thresholds).toEqual([
      { code: 'CORRELATED_ENTITY', text: 'Regla: versión sequence-v2-abc · ventana 86400 s' },
      {
        code: 'CORRELATED_ENTITY',
        text: 'fuentes distintas: requerido >= 2 · observado 2',
        met: true,
      },
      {
        code: 'CORRELATED_ENTITY',
        text: 'confianza del pivote: requerido >= medium · observado low',
        met: false,
      },
    ]);
    expect(byId.missing?.[0]?.text).toBe('Cobertura de windows no verificada.');
    expect(byId.nextSteps?.[0]?.text).toBe('Validar con la persona.');
  });
});
