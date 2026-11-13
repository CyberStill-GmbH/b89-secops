/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { bunnyReportPrompt } from './bunny_bridge';

describe('bunnyReportPrompt', () => {
  it('pide el informe de una alerta con la ventana de eventos relacionados', () => {
    const id = '5b1d6b9e-3b0e-4d44-9d52-0a1b2c3d4e5f';
    expect(bunnyReportPrompt({ format: 'pdf', window: '24h', alertId: id })).toBe(
      `Genera un informe PDF profesional de la investigación de la alerta ${id} con eventos relacionados ±24 horas (ventana 24h).`,
    );
    expect(bunnyReportPrompt({ format: 'xlsx', window: '1h', alertId: 'a1' })).toContain(
      'informe Excel profesional',
    );
    expect(bunnyReportPrompt({ format: 'csv', window: '7d', alertId: 'a1' })).toContain(
      '±7 días (ventana 7d)',
    );
  });

  it('sin alerta describe el sujeto investigado', () => {
    expect(
      bunnyReportPrompt({ format: 'pdf', window: '24h', subject: 'usuario jperez' }),
    ).toContain('investigación de usuario jperez con eventos');
    expect(bunnyReportPrompt({ format: 'pdf', window: '24h' })).toContain('la entidad investigada');
  });
});
