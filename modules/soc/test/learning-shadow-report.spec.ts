/**
 * Aprendizaje SOC · fase 2 — informe de sombra: estadística exacta y adjudicación.
 */

import { describe, expect, it } from 'vitest';

import {
  buildShadowReport,
  clopperPearsonLower,
  type ShadowRow,
} from '../src/learning-shadow-report.js';

const FROM = new Date('2026-11-23T15:00:00.000Z');
const TO = new Date('2026-11-24T15:00:00.000Z');

function row(overrides: Partial<ShadowRow> = {}): ShadowRow {
  return {
    ruleKey: 'linux-process:100200',
    patternId: 'p-1',
    mode: 'shadow',
    proposedAction: 'AUTO_CLOSE',
    appliedAction: 'NONE',
    escalateReason: null,
    alertStatus: 'closed',
    closureOrigin: 'human',
    closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
    verdict: 'false_positive',
    incidentLinked: false,
    ...overrides,
  };
}

describe('Clopper–Pearson exacto', () => {
  it('con x = n la cota inferior es (α/2)^(1/n)', () => {
    expect(clopperPearsonLower(125, 125)).toBeCloseTo(0.025 ** (1 / 125), 6);
    // 125/125 adjudicadas superan el 97 % (nota del diseño §8.1).
    expect(clopperPearsonLower(125, 125)).toBeGreaterThan(0.97);
    expect(clopperPearsonLower(30, 30)).toBeLessThan(0.97);
  });

  it('valor de referencia y bordes', () => {
    // Referencia: Beta(0.025; 50, 51) = 0.39832…
    expect(clopperPearsonLower(50, 100)).toBeCloseTo(0.3983, 3);
    expect(clopperPearsonLower(0, 10)).toBe(0);
    expect(clopperPearsonLower(0, 0)).toBe(0);
  });
});

describe('informe de sombra', () => {
  it('adjudica: acuerdo humano, TP suprimido (TP_REAL, escalada, incidente) y pendientes', () => {
    const report = buildShadowReport(
      [
        row(),
        row({ verdict: 'benign' }),
        row({ closureReason: 'TP_REAL', verdict: 'true_positive' }),
        row({
          alertStatus: 'escalated',
          closureOrigin: null,
          closureReason: null,
          verdict: 'true_positive',
        }),
        row({
          alertStatus: 'acknowledged',
          closureOrigin: null,
          closureReason: null,
          verdict: null,
          incidentLinked: true,
        }),
        row({ alertStatus: 'new', closureOrigin: null, closureReason: null, verdict: null }),
        // Un cierre de máquina no es juicio humano: queda pendiente.
        row({ closureOrigin: 'ai_analyst' }),
        row({ proposedAction: 'ESCALATE', escalateReason: 'GUARD_CONTEXT' }),
      ],
      { from: FROM, to: TO },
    );
    expect(report.totals).toMatchObject({
      decisions: 8,
      hypotheticalCloses: 7,
      agreed: 2,
      truePositivesSuppressed: 3,
      pending: 2,
      adjudicated: 5,
      escalations: { GUARD_CONTEXT: 1 },
    });
    expect(report.totals.precision).toBeCloseTo(0.4, 6);
    expect(report.goldSet).toBe('NOT_AVAILABLE');
    expect(report.unsafePatterns).toEqual([{ patternId: 'p-1', reason: '3 TP suprimido(s)' }]);
  });

  it('un patrón sin TP pero con cota inferior baja y muestra suficiente es inseguro', () => {
    const rows = [
      ...Array.from({ length: 30 }, () => row({ patternId: 'p-2' })),
      ...Array.from({ length: 2 }, () => row({ patternId: 'p-2', verdict: 'duplicate' })),
    ];
    const healthy = buildShadowReport(rows, { from: FROM, to: TO });
    // 32/32 de acuerdo: cota ≈ 0,891 < 0,97 con 32 adjudicadas → todavía no seguro.
    expect(healthy.unsafePatterns.map((item) => item.patternId)).toEqual(['p-2']);
    const small = buildShadowReport(rows.slice(0, 10), { from: FROM, to: TO });
    // Con menos de 30 adjudicadas no se juzga (falta muestra, no es inseguro).
    expect(small.unsafePatterns).toEqual([]);
  });

  it('sin PII: el informe solo lleva reglas, patrones y conteos', () => {
    const report = buildShadowReport([row()], { from: FROM, to: TO });
    const text = JSON.stringify(report);
    expect(Object.keys(report.byRule[0]!)).toContain('ruleKey');
    expect(text).not.toMatch(/@|\b\d{1,3}(\.\d{1,3}){3}\b/u);
  });
});
