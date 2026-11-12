/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { InvestigationEventSummary, RelatedResponse } from '../../common';
import {
  collectInvestigationReport,
  createInvestigationXlsx,
  investigationPrintHtml,
  investigationPrintHtmlWithProgress,
} from './investigation_report';
import { investigationCsv, investigationCsvWithProgress } from './investigation_export';

function event(id: string, at = '2026-11-11T12:00:00.000Z'): InvestigationEventSummary {
  return {
    id,
    index: 'wazuh-alerts-test',
    at,
    level: 8,
    ruleId: '101700',
    description: `Acceso <sospechoso> ${id}`,
    groups: ['office365'],
    vendor: 'office365',
    agent: null,
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: ['user:analyst@example.test'],
  };
}

function page(
  events: InvestigationEventSummary[],
  total: number,
  nextCursor: string | null,
): RelatedResponse {
  return {
    access: 'ok',
    from: '2026-11-10T12:00:00.000Z',
    to: '2026-11-12T12:00:00.000Z',
    total,
    events,
    nextCursor,
    pageSize: 100,
    perEntity: {},
  };
}

const query = {
  entities: [{ kind: 'user' as const, value: 'analyst@example.test' }],
  at: '2026-11-11T12:00:00.000Z',
  window: '24h' as const,
};

describe('reportes de investigación', () => {
  it('recorre el cursor completo y entrega progreso según filas recibidas', async () => {
    const cursors: Array<string | undefined> = [];
    const progress: number[] = [];
    const report = await collectInvestigationReport({
      query,
      alert: null,
      title: 'Investigación Office 365',
      entities: ['Usuario: analyst@example.test'],
      signal: new AbortController().signal,
      now: () => new Date('2026-11-11T13:00:00Z'),
      loadPage: async (_filters, cursor) => {
        cursors.push(cursor);
        return cursor ? page([event('e-2')], 2, null) : page([event('e-1')], 2, 'cursor-2');
      },
      onProgress: (item) => progress.push(item.completed),
    });
    expect(cursors).toEqual([undefined, 'cursor-2']);
    expect(report.events.map((item) => item.id)).toEqual(['e-1', 'e-2']);
    expect(report.totalEvents).toBe(2);
    expect(report.truncated).toBe(false);
    expect(progress).toEqual([0, 1, 2]);
  });

  it('incluye el evento de origen scrubbed, deduplica e indica el límite con honestidad', async () => {
    const report = await collectInvestigationReport({
      query,
      alert: null,
      sourceEvent: event('source'),
      title: 'Informe',
      entities: [],
      signal: new AbortController().signal,
      maximumEvents: 2,
      loadPage: async () => page([event('e-1'), event('e-2')], 3, 'more'),
    });
    expect(report.events.map((item) => item.id)).toEqual(['source', 'e-1']);
    expect(report.totalEvents).toBe(4);
    expect(report.truncated).toBe(true);
  });

  it('no cuenta dos veces el source si aparece entre los eventos relacionados', async () => {
    const report = await collectInvestigationReport({
      query,
      alert: null,
      sourceEvent: event('source'),
      title: 'Informe',
      entities: [],
      signal: new AbortController().signal,
      loadPage: async () => page([event('source'), event('e-1')], 2, null),
    });
    expect(report.events.map((item) => item.id)).toEqual(['source', 'e-1']);
    expect(report.totalEvents).toBe(2);
    expect(report.truncated).toBe(false);
  });

  it('rechaza una página a la que el usuario no tiene acceso y no produce informe parcial', async () => {
    await expect(
      collectInvestigationReport({
        query,
        alert: null,
        title: 'Informe',
        entities: [],
        signal: new AbortController().signal,
        loadPage: async () => ({ ...page([], 0, null), access: 'forbidden' }),
      }),
    ).rejects.toMatchObject({ kind: 'forbidden' });
  });

  it('produce un XLSX ZIP real con hojas, celdas seguras y contenido escapado', async () => {
    const report = {
      alert: null,
      sourceEvent: event('source'),
      title: 'Informe <M365>',
      entities: ['Usuario: analyst@example.test'],
      events: [
        {
          ...event('event-1'),
          description: '=SUM(1,1)\u0001 🛡',
          email: {
            internetMessageId: '<msg@example.test>',
            networkMessageId: 'network-1',
            mailboxOwnerUpn: 'owner@example.test',
            recipients: ['recipient&one@example.test'],
            recipientCount: 120,
            recipientsTruncated: true,
            operation: 'Send',
          },
        },
        {
          ...event('event-2'),
          email: { networkMessageId: 'network-1', operation: 'Receive' },
        },
      ],
      totalEvents: 1,
      generatedAt: new Date('2026-11-11T13:00:00Z'),
      truncated: false,
    };
    const blob = await createInvestigationXlsx(report);
    expect(blob.type).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(new DataView(bytes.buffer).getUint32(0, true)).toBe(0x04034b50);
    const content = new TextDecoder().decode(bytes);
    expect(content).toContain('xl/workbook.xml');
    expect(content).toContain('name="Eventos"');
    expect(content).toContain('name="Actividad agrupada"');
    expect(content).toContain('name="IDs exactos de mensaje"');
    expect(content).toContain('Coincidencia por ID exacto; no implica dirección ni hilo');
    expect(content).toContain('Informe &lt;M365&gt;');
    expect(content).toContain('=SUM(1,1)� 🛡');
    expect(content).toContain('&lt;msg@example.test&gt;');
    expect(content).toContain('recipient&amp;one@example.test');
    expect(content).toContain('Total destinatarios');
    expect(content).toContain('Lista de destinatarios truncada');
    expect(content).toContain('120');
    expect(content).toContain('Sí');
    expect(content).not.toContain('<f>');
  });

  it('reporta progreso monotónico y permite cancelar durante el render XLSX', async () => {
    const events = Array.from({ length: 1_001 }, (_, index) => event(`row-${index}`));
    const input = {
      alert: null,
      title: 'Carga de prueba',
      entities: [],
      events,
      totalEvents: events.length,
      generatedAt: new Date('2026-11-11T13:00:00Z'),
      truncated: false,
    };
    const progress: number[] = [];
    await createInvestigationXlsx(input, (item) => {
      if (item.percent !== undefined) progress.push(item.percent);
    });
    expect(progress.every((value, index) => index === 0 || value >= progress[index - 1]!)).toBe(
      true,
    );
    expect(progress[progress.length - 1]).toBeLessThan(100);

    const controller = new AbortController();
    const cancelled = createInvestigationXlsx(
      input,
      (item) => {
        if (item.phase === 'render' && item.completed === 500) controller.abort();
      },
      controller.signal,
    );
    await expect(cancelled).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('serializa CSV con progreso por filas y permite cancelar', async () => {
    const events = Array.from({ length: 750 }, (_, index) => event(`csv-${index}`));
    const input = {
      alert: null,
      title: 'Informe CSV',
      entities: ['Usuario: analyst@example.test'],
      events,
      totalEvents: events.length,
      generatedAt: new Date('2026-11-11T13:00:00Z'),
    };
    const progress: number[] = [];
    const csv = await investigationCsvWithProgress(input, new AbortController().signal, (item) =>
      progress.push(item.completed),
    );
    expect(csv).toBe(investigationCsv(input));
    expect(progress).toEqual([...progress].sort((a, b) => a - b));
    expect(progress.at(-1)).toBeGreaterThan(750);

    const controller = new AbortController();
    const cancelled = investigationCsvWithProgress(input, controller.signal, (item) => {
      if (item.completed >= 250) controller.abort();
    });
    await expect(cancelled).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('construye PDF imprimible con progreso monotónico y permite cancelar el render HTML', async () => {
    const events = Array.from({ length: 600 }, (_, index) => event(`print-${index}`));
    const input = {
      alert: null,
      title: 'Informe PDF imprimible',
      entities: ['Usuario: analyst@example.test'],
      events,
      totalEvents: events.length,
      generatedAt: new Date('2026-11-11T13:00:00Z'),
      truncated: false,
    };
    const progress: number[] = [];
    const rendered = await investigationPrintHtmlWithProgress(
      input,
      new AbortController().signal,
      (item) => progress.push(item.completed),
    );
    expect(rendered).toBe(investigationPrintHtml(input));
    expect(progress.length).toBeGreaterThan(1);
    expect(progress.every((value, index) => index === 0 || value >= progress[index - 1]!)).toBe(
      true,
    );
    expect(progress.at(-1)).toBeGreaterThan(events.length);

    const controller = new AbortController();
    const cancelled = investigationPrintHtmlWithProgress(input, controller.signal, (item) => {
      if (item.completed >= 250) controller.abort();
    });
    await expect(cancelled).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('escapa el HTML para impresión y advierte que proximidad no es causalidad', () => {
    const html = investigationPrintHtml({
      alert: null,
      title: '<script>alert(1)</script>',
      entities: ['user:<analyst>'],
      events: [
        {
          ...event('event-1'),
          email: {
            internetMessageId: '<m&1>',
            networkMessageId: 'same-network-id',
            recipients: ['a@example.test'],
            recipientCount: 75,
            recipientsTruncated: true,
          },
        },
        {
          ...event('event-2'),
          email: { internetMessageId: '<m&1>', networkMessageId: 'same-network-id' },
        },
      ],
      totalEvents: 1,
      generatedAt: new Date('2026-11-11T13:00:00Z'),
      truncated: false,
    });
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('no establece causalidad');
    expect(html).toContain('InternetMessageId: &lt;m&amp;1&gt;');
    expect(html).toContain('Destinatarios: a@example.test (lista truncada; 75 total)');
    expect(html).toContain('same-network-id');
    expect(html).toContain('Coincidencias por identificador exacto de mensaje');
    expect(html).not.toContain('Dirección:');
  });
});
