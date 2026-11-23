/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { cleanAlertTitle, explainAlert } from './alert_why';

const base = {
  priority: 'P2' as const,
  reasons: [] as Array<{ code: string; detail: string }>,
  entities: [] as Array<{ ref: string | null; kind: string; label: string }>,
};

describe('título visible de una alerta', () => {
  it('quita el prefijo de fuente y el ID de regla', () => {
    expect(cleanAlertTitle('B89 Microsoft 365: inicio de sesión desde un país inusual (wazuh 100231)')).toBe(
      'Inicio de sesión desde un país inusual',
    );
    expect(cleanAlertTitle('  (wazuh 5)')).toBe('Alerta del SIEM sin descripción');
  });
});

describe('por qué saltó', () => {
  it('cualquier regla sin guía: qué pasó, quién, agravantes y fuente, sin códigos del motor', () => {
    const why = explainAlert({
      ...base,
      title: 'B89 Microsoft 365: inicio de sesión desde un país inusual (wazuh 100231)',
      entities: [
        { ref: 'ent_1', kind: 'user', label: 'ana.perez@b89.io' },
        { ref: 'ent_2', kind: 'ip', label: '203.0.113.7' },
      ],
      reasons: [
        { code: 'BASE_SEVERITY', detail: 'Severidad normalizada high (origen 10).' },
        { code: 'REPEATED_ACTIVITY', detail: '5 eventos equivalentes en la ventana reciente.' },
        { code: 'PRIVILEGED_IDENTITY', detail: 'Identidad privilegiada involucrada: ana.perez@b89.io.' },
      ],
    });
    expect(why.title).toBe('Inicio de sesión desde un país inusual');
    expect(why.line).toBe('Inicio de sesión desde un país inusual · usuario ana.perez@b89.io, IP 203.0.113.7 · se repitió 5 veces');
    expect(why.sentence).toBe(
      'Inicio de sesión desde un país inusual (usuario ana.perez@b89.io y IP 203.0.113.7); se repitió 5 veces y con una cuenta con privilegios (ana.perez@b89.io). Lo detectó Microsoft 365.',
    );
    expect(why.priorityLine).toBe('Es P2 porque la regla la marca como grave, se repitió y la cuenta tiene privilegios.');
    expect(why.ruleId).toBe('100231');
    const visible = [why.title, why.line, why.sentence, why.priorityLine ?? ''].join(' ');
    expect(visible).not.toMatch(/BASE_SEVERITY|REPEATED_ACTIVITY|origen 10|\bhigh\b|wazuh 100231/u);
    expect(why.guide).toBeNull();
    expect(why.nextSteps).toHaveLength(3);
    expect(why.nextSteps[0]).toContain('el usuario ana.perez@b89.io');
  });

  it('usa la guía de la regla cuando existe', () => {
    const why = explainAlert({ ...base, title: 'B89 Cloudflare: login desde hosting (wazuh 101531)' });
    expect(why.guide).not.toBeNull();
    expect(why.nextSteps).toEqual(why.guide!.whatToDo);
    expect(why.line.startsWith(why.guide!.headline.replace(/[.\s]+$/u, ''))).toBe(true);
    expect(why.title).toBe('Login desde hosting');
  });

  it('la explicación del correlador manda y sus siguientes pasos se usan', () => {
    const why = explainAlert({
      ...base,
      title: 'B89 Correlador: cadena de acceso sospechoso',
      reasons: [
        { code: 'CORRELATOR', detail: 'Explicación: Un inicio de sesión riesgoso fue seguido por una regla de reenvío. Dos fuentes.' },
        { code: 'CORRELATOR', detail: 'Siguiente paso: Revoca las sesiones del usuario.' },
      ],
    });
    expect(why.line).toBe('Un inicio de sesión riesgoso fue seguido por una regla de reenvío');
    expect(why.nextSteps).toEqual(['Revoca las sesiones del usuario.']);
  });

  it('explica por qué bajó la prioridad y no inventa sin datos', () => {
    const why = explainAlert({
      ...base,
      priority: 'P4',
      title: 'Cambio de configuración',
      reasons: [{ code: 'MAINTENANCE_WINDOW', detail: 'Ventana de mantenimiento CHG-1.' }],
    });
    expect(why.priorityLine).toBeNull();
    expect(why.loweredLine).toBe('Tiene menos prioridad porque ocurrió en una ventana de mantenimiento.');
    expect(why.sentence).toBe('Cambio de configuración.');
    expect(why.source).toBeNull();
  });
});
