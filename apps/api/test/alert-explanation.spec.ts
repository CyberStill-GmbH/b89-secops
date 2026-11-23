/**
 * La consola explica cualquier alerta con el catálogo de detección: caso de uso, falsos positivos
 * conocidos, cuándo escalar, MITRE y el primer paso del runbook. Misma fuente que el aviso de Teams.
 */

import { describe, expect, it } from 'vitest';

import { SOC_KNOWLEDGE } from '../src/assistant/soc-knowledge.generated.js';
import { explainAlertFromKnowledge } from '../src/soc/alert-explanation.js';

describe('explicación de una alerta desde el catálogo', () => {
  it('una regla estándar de Wazuh con caso de uso trae cómo saber si es real', () => {
    const explanation = explainAlertFromKnowledge({ ruleId: '521', title: 'Posible rootkit' }, SOC_KNOWLEDGE);
    expect(explanation).not.toBeNull();
    expect(explanation!.useCase).toMatch(/Rootcheck/u);
    expect(explanation!.falsePositives.length).toBeGreaterThan(0);
    expect(explanation!.escalateWhen.length).toBeGreaterThan(0);
    expect(explanation!.mitre[0]).toMatchObject({ id: 'T1014' });
  });

  it('cubre la mayoría de las reglas del catálogo', () => {
    const rules = Object.values(SOC_KNOWLEDGE.rules);
    const withAdvice = rules.filter((rule) => {
      const explanation = explainAlertFromKnowledge({ ruleId: rule.id, title: '' }, SOC_KNOWLEDGE);
      return explanation && (explanation.falsePositives.length > 0 || explanation.escalateWhen.length > 0);
    });
    expect(withAdvice.length / rules.length).toBeGreaterThan(0.5);
  });

  it('sin regla conocida no inventa nada', () => {
    expect(explainAlertFromKnowledge({ ruleId: '9999999', title: 'zzz' }, SOC_KNOWLEDGE)).toBeNull();
    expect(explainAlertFromKnowledge({ ruleId: null, title: 'zzz' }, SOC_KNOWLEDGE)).toBeNull();
  });
});
