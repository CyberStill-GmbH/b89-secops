/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { bunnyNumericChartSvg, bunnyNumericTable, bunnyReportData, collectBunnyInvestigationReport } from './bunny_report';
import { createInvestigationXlsx, investigationPrintHtml } from '../components/investigation_report';
import type { Alert, InvestigationEvent, RelatedResponse } from '../../common';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { BunnyReportActions } from './bunny_report_actions';

describe('informes de Bunny', () => {
  it('monta el control de creación sin exigir una ventana o estado global durante el render', () => {
    const markup = renderToStaticMarkup(React.createElement(BunnyReportActions, {
      api: {} as never,
      basePath: '',
      messageId: 17,
      text: 'Análisis revisado',
      citations: [{ kind: 'alert', id: 'alert-17', label: 'Alerta de prueba' }],
    }));
    expect(markup).toContain('Crear informe');
    expect(markup).not.toContain('Generando');
  });

  it('solo habilita gráficos para tablas Markdown completas con valores numéricos explícitos', () => {
    expect(bunnyNumericTable('No hay tabla cuantitativa.')).toBeNull();
    expect(bunnyNumericTable('| Indicador | Estado |\n| --- | --- |\n| EDR | activo |')).toBeNull();
    expect(bunnyNumericTable('| Día | Alertas |\n| --- | ---: |\n| lunes | 12 |\n| martes | 7 |')).toEqual({
      headers: ['Día', 'Alertas'],
      rows: [['lunes', 12], ['martes', 7]],
    });
  });

  it('escapa etiquetas del SVG y mantiene respuesta/fuentes dentro del PDF generado', () => {
    const table = bunnyNumericTable('| <Entidad> | Conteo |\n| --- | ---: |\n| <script> | 2 |')!;
    const svg = bunnyNumericChartSvg(table);
    expect(svg).toContain('&lt;script&gt;');
    expect(svg).not.toContain('<script>');
    const report = bunnyReportData({
      text: 'Hallazgo confirmado por la evidencia.\n\n| <Entidad> | Conteo |\n| --- | ---: |\n| <script> | 2 |',
      citations: [{ kind: 'alert', id: 'alert-7', label: '<alerta>' }],
      title: 'Resumen SOC',
      includeChart: true,
      now: new Date('2026-11-12T12:00:00Z'),
    });
    const html = investigationPrintHtml(report);
    expect(html).toContain('Hallazgo confirmado por la evidencia.');
    expect(html).toContain('&lt;alerta&gt;');
    expect(html).toContain('<svg');
    expect(html).toContain('Gráfico derivado solo');
    expect(html).not.toContain('0 de 0');
    expect(report.assistantChartData?.rows).toEqual([['<script>', 2]]);
  });

  it('crea un XLSX real con la respuesta, citas y hoja de valores del gráfico', async () => {
    const report = bunnyReportData({
      text: '| Día | Alertas |\n| --- | ---: |\n| lunes | 12 |',
      citations: [{ kind: 'event', id: 'evt-1', label: 'Evento' }],
      includeChart: true,
      now: new Date('2026-11-12T12:00:00Z'),
    });
    const workbook = await createInvestigationXlsx(report);
    expect(workbook.type).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    expect(Array.from(new Uint8Array(await workbook.arrayBuffer()).slice(0, 4))).toEqual([0x50, 0x4b, 0x03, 0x04]);
    expect(workbook.size).toBeGreaterThan(500);
  });

  it('omite el gráfico si no se selecciona aunque la respuesta contenga una tabla', () => {
    const report = bunnyReportData({
      text: '| Día | Alertas |\n| --- | ---: |\n| lunes | 2 |',
      citations: [],
      includeChart: false,
    });
    expect(report.assistantChartSvg).toBeUndefined();
    expect(report.assistantChartData).toBeUndefined();
  });

  it('genera un expediente real desde una alerta citada y carga las páginas autorizadas relacionadas', async () => {
    const alert = {
      id: 'alert-42', title: 'Envío M365 inusual', priority: 'P2', score: 70, status: 'new',
      assigneeId: null, verdict: null, incidentId: null, occurredAt: '2026-11-12T12:00:00Z', revision: 1,
      reasons: [], entities: [{ ref: null, kind: 'user', label: 'analyst@example.test' }],
    } as Alert;
    const event = {
      id: 'evt-1', index: 'wazuh-alerts-test', at: alert.occurredAt, level: 8, ruleId: '101701',
      description: 'Envío sospechoso', groups: ['office365'], vendor: 'office365', agent: null,
      mitre: { ids: [], tactics: [], techniques: [] }, matched: ['user:analyst@example.test'],
      location: null, entities: [{ kind: 'user', value: 'analyst@example.test', field: 'data.office365.UserId' }],
      raw: {}, rawTruncated: false,
    } as InvestigationEvent;
    const page: RelatedResponse = {
      access: 'ok', from: alert.occurredAt, to: alert.occurredAt, total: 1, events: [event], nextCursor: null,
      pageSize: 50, perEntity: { 'user:analyst@example.test': 1 },
    };
    const loadPage = jest.fn(async () => page);
    const report = await collectBunnyInvestigationReport({
      citation: { kind: 'alert', id: alert.id, label: alert.title },
      window: '24h', analysis: 'Análisis de actividad real.', citations: [{ kind: 'alert', id: alert.id, label: alert.title }],
      includeChart: false, loadAlert: async () => alert, loadEvent: async () => ({ access: 'ok', event }),
      loadPage, signal: new AbortController().signal, now: () => new Date('2026-11-12T13:00:00Z'),
    });
    expect(loadPage).toHaveBeenCalledOnce();
    expect(report.alert?.id).toBe('alert-42');
    expect(report.events.map((item) => item.id)).toEqual(['evt-1']);
    expect(report.assistantAnalysis).toBe('Análisis de actividad real.');
    const pdf = investigationPrintHtml(report);
    expect(pdf).toContain('Informe profesional de investigación');
    expect(pdf).toContain('Envío sospechoso');
    expect(pdf).toContain('Análisis de actividad real.');
    const xlsx = await createInvestigationXlsx(report);
    const workbook = new TextDecoder().decode(await xlsx.arrayBuffer());
    expect(workbook).toContain('name="Eventos"');
    expect(workbook).toContain('name="Actividad agrupada"');
    expect(workbook).toContain('name="Análisis Bunny"');
    expect(workbook).toContain('Análisis de actividad real.');
  });

  it('falla cerrada si la página relacionada niega acceso, sin fabricar un informe parcial', async () => {
    const alert = {
      id: 'alert-42', title: 'Alerta', priority: 'P2', score: 70, status: 'new', assigneeId: null,
      verdict: null, incidentId: null, occurredAt: '2026-11-12T12:00:00Z', revision: 1, reasons: [],
      entities: [{ ref: null, kind: 'user', label: 'analyst@example.test' }],
    } as Alert;
    await expect(collectBunnyInvestigationReport({
      citation: { kind: 'alert', id: alert.id, label: alert.title }, window: '24h', analysis: 'texto', citations: [],
      includeChart: false, loadAlert: async () => alert, loadEvent: async () => ({ access: 'ok', event: null }),
      loadPage: async () => ({ access: 'forbidden', from: '', to: '', total: 0, events: [], nextCursor: null, pageSize: 50, perEntity: {} }),
      signal: new AbortController().signal,
    })).rejects.toMatchObject({ kind: 'forbidden' });
  });
});
