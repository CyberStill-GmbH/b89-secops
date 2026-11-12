/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { Alert, InvestigationEventSummary, RelatedResponse } from '../../common';
import {
  groupExactEmailMessages,
  summarizeExactEmailMessageGroup,
} from '../../common/investigation';
import type { EntityKind, RelatedWindow } from '../../common/investigation';
import { groupInvestigationActivity } from './investigation_activity_grouping';

export const REPORT_EVENT_LIMIT = 10_000;

export type ReportEmailMetadata = NonNullable<InvestigationEventSummary['email']>;

export type ReportEventSummary = InvestigationEventSummary & {
  readonly email?: ReportEmailMetadata;
};

export interface InvestigationReportQuery {
  readonly entities: ReadonlyArray<{ readonly kind: EntityKind; readonly value: string }>;
  readonly at: string;
  readonly window: RelatedWindow;
  readonly excludeId?: string;
}

export interface InvestigationReportData {
  readonly alert: Alert | null;
  /** Scrubbed summary of the source event; full `_source` is never exported. */
  readonly sourceEvent?: ReportEventSummary | null;
  readonly title: string;
  readonly entities: readonly string[];
  readonly events: readonly ReportEventSummary[];
  readonly totalEvents: number;
  readonly generatedAt: Date;
  readonly truncated: boolean;
  /** Bunny export preserves the exact validated answer and citations in the same artifact. */
  readonly assistantAnalysis?: string;
  readonly assistantCitations?: readonly {
    readonly kind: string;
    readonly id: string;
    readonly label: string;
  }[];
  /** Optional SVG created only from numeric values explicitly present in the answer. */
  readonly assistantChartSvg?: string;
  readonly assistantChartData?: {
    readonly headers: readonly string[];
    readonly rows: readonly (readonly (string | number)[])[];
  };
}

export interface ReportProgress {
  readonly phase: 'query' | 'render' | 'package';
  readonly completed: number;
  readonly total: number;
  readonly message: string;
  readonly percent?: number;
}

export type RelatedPageLoader = (
  query: InvestigationReportQuery,
  cursor: string | undefined,
  signal: AbortSignal,
) => Promise<RelatedResponse>;

export class ReportCollectionError extends Error {
  public constructor(public readonly kind: 'forbidden' | 'unavailable' | 'invalid') {
    super(`No se pudo preparar el informe: ${kind}`);
    this.name = 'ReportCollectionError';
  }
}

/** Fetch every authorized search_after page; progress counts returned rows, not elapsed time. */
export async function collectInvestigationReport(input: {
  readonly query: InvestigationReportQuery;
  readonly alert: Alert | null;
  readonly sourceEvent?: InvestigationEventSummary | null;
  readonly title: string;
  readonly entities: readonly string[];
  readonly loadPage: RelatedPageLoader;
  readonly signal: AbortSignal;
  readonly now?: () => Date;
  readonly onProgress?: (progress: ReportProgress) => void;
  readonly maximumEvents?: number;
}): Promise<InvestigationReportData> {
  const maximum = Math.min(
    REPORT_EVENT_LIMIT,
    Math.max(1, input.maximumEvents ?? REPORT_EVENT_LIMIT),
  );
  const events = new Map<string, ReportEventSummary>();
  const sourceId = input.sourceEvent?.id;
  if (input.sourceEvent) events.set(input.sourceEvent.id, input.sourceEvent);
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  let expectedTotal = 0;
  let totalEvents = 0;
  let sourceFoundInRelated = false;
  let pages = 0;
  input.onProgress?.({
    phase: 'query',
    completed: 0,
    total: 0,
    percent: 0,
    message: 'Solicitando la primera página a Wazuh Indexer',
  });
  do {
    if (input.signal.aborted) throw new DOMException('Informe cancelado', 'AbortError');
    let page: RelatedResponse;
    try {
      page = await input.loadPage(input.query, cursor, input.signal);
    } catch (error) {
      if (input.signal.aborted || (error instanceof Error && error.name === 'AbortError'))
        throw error;
      throw new ReportCollectionError('unavailable');
    }
    if (page.access === 'forbidden') throw new ReportCollectionError('forbidden');
    if (page.access !== 'ok') throw new ReportCollectionError('unavailable');
    if (pages === 0) {
      expectedTotal = page.total;
      sourceFoundInRelated = Boolean(
        sourceId && page.events.some((event) => event.id === sourceId),
      );
      totalEvents = expectedTotal + (input.sourceEvent && !sourceFoundInRelated ? 1 : 0);
    } else if (page.total !== expectedTotal) throw new ReportCollectionError('invalid');
    if (page.events.length === 0 && page.nextCursor) throw new ReportCollectionError('invalid');
    for (const event of page.events) {
      if (sourceId && event.id === sourceId) sourceFoundInRelated = true;
      if (events.size >= maximum) break;
      if (!events.has(event.id)) events.set(event.id, event as ReportEventSummary);
    }
    pages += 1;
    input.onProgress?.({
      phase: 'query',
      completed: events.size,
      total: Math.min(totalEvents, maximum),
      message: `Consultando página ${pages}: ${events.size.toLocaleString('es-PE')} de ${totalEvents.toLocaleString('es-PE')} eventos`,
      percent: Math.min(
        65,
        totalEvents === 0 ? 65 : Math.floor((events.size / Math.min(totalEvents, maximum)) * 65),
      ),
    });
    if (events.size >= maximum) break;
    const nextCursor = page.nextCursor ?? undefined;
    if (nextCursor && seenCursors.has(nextCursor)) throw new ReportCollectionError('invalid');
    if (nextCursor) seenCursors.add(nextCursor);
    cursor = nextCursor;
  } while (cursor);
  if (sourceFoundInRelated) totalEvents = expectedTotal;

  return {
    alert: input.alert,
    sourceEvent: input.sourceEvent,
    title: input.title,
    entities: input.entities,
    events: [...events.values()],
    totalEvents,
    generatedAt: (input.now ?? (() => new Date()))(),
    truncated: events.size < totalEvents,
  };
}

function xml(value: unknown): string {
  return Array.from(String(value ?? ''), (character) => {
    const codePoint = character.codePointAt(0)!;
    return codePoint === 0x9 ||
      codePoint === 0xa ||
      codePoint === 0xd ||
      (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
      (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
      (codePoint >= 0x10000 && codePoint <= 0x10ffff)
      ? character
      : '\uFFFD';
  })
    .join('')
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&apos;');
}

function columnName(index: number): string {
  let n = index + 1;
  let name = '';
  while (n > 0) {
    n -= 1;
    name = String.fromCharCode(65 + (n % 26)) + name;
    n = Math.floor(n / 26);
  }
  return name;
}

type Cell = string | number;
type Sheet = {
  readonly name: string;
  readonly rows: readonly (readonly Cell[])[];
  readonly autoFilter?: boolean;
};

function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Generación cancelada', 'AbortError');
}

async function worksheetXml(
  sheet: Sheet,
  sheetIndex: number,
  signal?: AbortSignal,
  onProgress?: (progress: ReportProgress) => void,
): Promise<string> {
  const rows: string[] = [];
  for (let rowIndex = 0; rowIndex < sheet.rows.length; rowIndex += 1) {
    abortIfNeeded(signal);
    const row = sheet.rows[rowIndex]!;
    const cells = row
      .map((value, colIndex) => {
        const ref = `${columnName(colIndex)}${rowIndex + 1}`;
        const style = rowIndex === 0 ? ' s="1"' : '';
        if (typeof value === 'number' && Number.isFinite(value)) {
          return `<c r="${ref}"${style}><v>${value}</v></c>`;
        }
        return `<c r="${ref}" t="inlineStr"${style}><is><t xml:space="preserve">${xml(value)}</t></is></c>`;
      })
      .join('');
    rows.push(`<row r="${rowIndex + 1}">${cells}</row>`);
    if ((rowIndex + 1) % 500 === 0 || rowIndex + 1 === sheet.rows.length) {
      onProgress?.({
        phase: 'render',
        completed: rowIndex + 1,
        total: sheet.rows.length,
        message: `Serializando hoja ${sheetIndex + 1}: ${(rowIndex + 1).toLocaleString('es-PE')} de ${sheet.rows.length.toLocaleString('es-PE')} filas`,
      });
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  }
  const rowXml = rows.join('');
  const lastRow = Math.max(1, sheet.rows.length);
  const lastColumn = Math.max(1, ...sheet.rows.map((row) => row.length));
  const dimension = `A1:${columnName(lastColumn - 1)}${lastRow}`;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="${dimension}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/><sheetData>${rowXml}</sheetData>${sheet.autoFilter ? `<autoFilter ref="A1:${columnName(lastColumn - 1)}${lastRow}"/>` : ''}</worksheet>`;
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(view: DataView, offset: number, value: number): void {
  view.setUint16(offset, value, true);
}
function u32(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value >>> 0, true);
}

/** Minimal ZIP32 writer using stored entries, so the XLSX has no runtime dependency. */
async function zipStored(
  files: ReadonlyArray<{ path: string; body: string }>,
  signal?: AbortSignal,
  onProgress?: (progress: ReportProgress) => void,
): Promise<Blob> {
  const encoder = new TextEncoder();
  const locals: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  let centralBytes = 0;
  for (let index = 0; index < files.length; index += 1) {
    abortIfNeeded(signal);
    const file = files[index]!;
    const name = encoder.encode(file.path);
    const data = encoder.encode(file.body);
    const checksum = crc32(data);
    const local = new Uint8Array(30 + name.length + data.length);
    const localView = new DataView(local.buffer);
    u32(localView, 0, 0x04034b50);
    u16(localView, 4, 20);
    u16(localView, 6, 0x0800);
    u16(localView, 8, 0);
    u16(localView, 10, 0);
    u16(localView, 12, 0);
    u32(localView, 14, checksum);
    u32(localView, 18, data.length);
    u32(localView, 22, data.length);
    u16(localView, 26, name.length);
    u16(localView, 28, 0);
    local.set(name, 30);
    local.set(data, 30 + name.length);
    locals.push(local);

    const directory = new Uint8Array(46 + name.length);
    const dirView = new DataView(directory.buffer);
    u32(dirView, 0, 0x02014b50);
    u16(dirView, 4, 20);
    u16(dirView, 6, 20);
    u16(dirView, 8, 0x0800);
    u16(dirView, 10, 0);
    u16(dirView, 12, 0);
    u16(dirView, 14, 0);
    u32(dirView, 16, checksum);
    u32(dirView, 20, data.length);
    u32(dirView, 24, data.length);
    u16(dirView, 28, name.length);
    u16(dirView, 30, 0);
    u16(dirView, 32, 0);
    u16(dirView, 34, 0);
    u16(dirView, 36, 0);
    u32(dirView, 38, 0);
    u32(dirView, 42, offset);
    directory.set(name, 46);
    central.push(directory);
    offset += local.length;
    centralBytes += directory.length;
    onProgress?.({
      phase: 'package',
      completed: index + 1,
      total: files.length,
      percent: 90 + Math.floor(((index + 1) / files.length) * 9),
      message: `Empaquetando libro XLSX: ${index + 1} de ${files.length} partes`,
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  u32(endView, 0, 0x06054b50);
  u16(endView, 4, 0);
  u16(endView, 6, 0);
  u16(endView, 8, files.length);
  u16(endView, 10, files.length);
  u32(endView, 12, centralBytes);
  u32(endView, 16, offset);
  u16(endView, 20, 0);
  return new Blob([...locals, ...central, end], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
}

function workbookFiles(sheets: readonly Sheet[]): { path: string; body: string }[] {
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}</Types>`;
  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((sheet, i) => `<sheet name="${xml(sheet.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Aptos"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Aptos"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF263444"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
  return [
    { path: '[Content_Types].xml', body: contentTypes },
    {
      path: '_rels/.rels',
      body: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
    },
    { path: 'xl/workbook.xml', body: workbook },
    { path: 'xl/_rels/workbook.xml.rels', body: rels },
    { path: 'xl/styles.xml', body: styles },
  ];
}

export async function createInvestigationXlsx(
  input: InvestigationReportData,
  onProgress?: (progress: ReportProgress) => void,
  signal?: AbortSignal,
): Promise<Blob> {
  const eventRows: (readonly Cell[])[] = [
    [
      'Fecha y hora UTC',
      'Nivel',
      'Origen',
      'Regla',
      'Descripción',
      'Entidades coincidentes',
      'Internet Message ID',
      'Network Message ID',
      'Buzón',
      'Destinatarios',
      'Total destinatarios',
      'Lista de destinatarios truncada',
      'Operación de auditoría',
      'ID de evento',
    ],
  ];
  const total = input.events.length;
  onProgress?.({
    phase: 'render',
    completed: 0,
    total,
    percent: 65,
    message: 'Preparando el libro XLSX',
  });
  for (let index = 0; index < total; index += 1) {
    abortIfNeeded(signal);
    const event = input.events[index]!;
    const email = emailMetadataOf(event);
    eventRows.push([
      event.at,
      event.level,
      event.vendor,
      event.ruleId,
      event.description,
      event.matched.join(' | '),
      email?.internetMessageId ?? '',
      email?.networkMessageId ?? '',
      email?.mailboxOwnerUpn ?? '',
      email?.recipients?.join(' | ') ?? '',
      email?.recipientCount ?? '',
      email?.recipientsTruncated ? 'Sí' : 'No',
      email?.operation ?? '',
      event.id,
    ]);
    if ((index + 1) % 500 === 0 || index + 1 === total) {
      onProgress?.({
        phase: 'render',
        completed: index + 1,
        total,
        percent: 65 + (total === 0 ? 10 : Math.floor(((index + 1) / total) * 10)),
        message: `Preparando hoja de eventos: ${(index + 1).toLocaleString('es-PE')} de ${total.toLocaleString('es-PE')}`,
      });
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  }
  const groups = groupInvestigationActivity(input.events);
  const exactEmailGroups = groupExactEmailMessages(input.events);
  const investigationSheets: Sheet[] = [
    {
      name: 'Resumen',
      rows: [
        ['B89 SOC · Informe de investigación'],
        ['Investigación', input.title],
        ['Generado (UTC)', input.generatedAt.toISOString()],
        ['Eventos exportados', input.events.length],
        ['Eventos encontrados', input.totalEvents],
        ['Grupos con identificador de mensaje exacto', exactEmailGroups.length],
        [
          'Informe truncado por límite',
          input.truncated ? 'Sí · refinar filtros para completar' : 'No',
        ],
        ['Alerta B89', input.alert?.id ?? ''],
        ['Evento Wazuh de origen', input.sourceEvent?.id ?? ''],
        ['Entidades', input.entities.join(' | ')],
        [
          'Criterio de actividad',
          'Entidad coincidente y proximidad temporal; no confirma causalidad ni hilo de correo.',
        ],
        [
          'Criterio de mensaje',
          'NetworkMessageId exacto; si no existe, InternetMessageId exacto. No determina dirección ni hilo.',
        ],
      ],
    },
    { name: 'Eventos', rows: eventRows, autoFilter: true },
    {
      name: 'Actividad agrupada',
      autoFilter: true,
      rows: [
        [
          'Entidad coincidente',
          'Primera actividad UTC',
          'Última actividad UTC',
          'Eventos',
          'Orígenes',
          'Reglas',
          'IDs de evento',
          'Interpretación',
        ],
        ...groups.map((group) => [
          group.entity,
          group.firstAt,
          group.lastAt,
          group.events.length,
          [...new Set(group.events.map((event) => event.vendor))].sort().join(' | '),
          [...new Set(group.events.map((event) => event.ruleId))].sort().join(' | '),
          group.events.map((event) => event.id).join(' | '),
          'Proximidad temporal; no determina causalidad ni hilo de correo',
        ]),
      ],
    },
    {
      name: 'IDs exactos de mensaje',
      autoFilter: true,
      rows: [
        [
          'Tipo de identificador',
          'Identificador exacto',
          'Dirección según operaciones explícitas',
          'Eventos',
          'Buzones auditados (MailboxOwnerUPN)',
          'Destinatarios presentes en el DTO allowlisted',
          'Lista de destinatarios truncada',
          'Operaciones auditadas',
          'IDs de evento',
          'Interpretación',
        ],
        ...exactEmailGroups.map((group) => {
          const evidence = summarizeExactEmailMessageGroup(group);
          return [
            group.idType,
            group.id,
            evidence.direction,
            group.events.length,
            evidence.auditedMailboxes.join(' | '),
            evidence.recipients.join(' | '),
            evidence.recipientsTruncated ? 'Sí' : 'No',
            evidence.operations.join(' | '),
            group.events.map((event) => event.id).join(' | '),
            'Coincidencia por ID exacto; no prueba causalidad ni hilo',
          ];
        }),
      ],
    },
  ];
  const sheets: Sheet[] =
    input.assistantAnalysis === undefined || input.events.length > 0 || input.alert !== null
      ? investigationSheets
      : [];
  if (input.assistantAnalysis !== undefined) {
    sheets.unshift({
      name: 'Análisis Bunny',
      rows: [
        ['B89 SOC · Análisis de Bunny'],
        ['Título', input.title],
        ['Generado (UTC)', input.generatedAt.toISOString()],
        ['Respuesta validada'],
        ...input.assistantAnalysis.split(/\r?\n/u).map((line) => [line]),
        [],
        ['Fuentes citadas'],
        ['Tipo', 'ID', 'Referencia'],
        ...(input.assistantCitations ?? []).map((citation) => [
          citation.kind,
          citation.id,
          citation.label,
        ]),
      ],
    });
    if (input.assistantChartSvg) {
      sheets.unshift({
        name: 'Datos del gráfico',
        rows: [
          ['Datos numéricos explícitos de Bunny'],
          ['El gráfico visual se incluye en el PDF imprimible.'],
          [...(input.assistantChartData?.headers ?? [])],
          ...(input.assistantChartData?.rows ?? []).map((row) => [...row]),
        ],
      });
    }
  }
  abortIfNeeded(signal);
  const files = workbookFiles(sheets);
  const worksheets: string[] = [];
  const totalRows = sheets.reduce((sum, sheet) => sum + sheet.rows.length, 0);
  let rowOffset = 0;
  for (const [index, sheet] of sheets.entries()) {
    const body = await worksheetXml(sheet, index + 1, signal, (progress) =>
      onProgress?.({
        ...progress,
        percent: 75 + Math.floor(((rowOffset + progress.completed) / totalRows) * 15),
        message: `Serializando hojas: ${(rowOffset + progress.completed).toLocaleString('es-PE')} de ${totalRows.toLocaleString('es-PE')} filas`,
      }),
    );
    worksheets.push(body);
    rowOffset += sheet.rows.length;
  }
  abortIfNeeded(signal);
  const completeFiles = [
    ...files,
    ...worksheets.map((body, index) => ({ path: `xl/worksheets/sheet${index + 1}.xml`, body })),
  ];
  return zipStored(completeFiles, signal, onProgress);
}

function html(value: unknown): string {
  return String(value ?? '')
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

function emailMetadataOf(event: InvestigationEventSummary): ReportEmailMetadata | undefined {
  return event.email;
}

/** Print-ready report; the browser's native print dialog can save this exact view as PDF. */
function eventPrintRow(input: InvestigationReportData, event: ReportEventSummary): string {
  const email = emailMetadataOf(event);
  const mailValues = [
    email?.internetMessageId ? `InternetMessageId: ${email.internetMessageId}` : '',
    email?.networkMessageId ? `NetworkMessageId: ${email.networkMessageId}` : '',
    email?.mailboxOwnerUpn ? `Buzón: ${email.mailboxOwnerUpn}` : '',
    email?.recipients?.length
      ? `Destinatarios: ${email.recipients.join(', ')}${email.recipientsTruncated ? ` (lista truncada; ${email.recipientCount ?? 'al menos'} total)` : ''}`
      : '',
    email?.recipientsTruncated && !email.recipients?.length
      ? `Destinatarios: lista truncada (${email.recipientCount ?? 'total desconocido'})`
      : '',
    email?.operation ? `Operación: ${email.operation}` : '',
  ]
    .filter(Boolean)
    .join(' · ');
  return `<tr><td>${event.id === input.sourceEvent?.id ? 'Origen' : 'Relacionado'}</td><td>${html(event.at)}</td><td>${html(event.level)}</td><td>${html(event.vendor)}</td><td>${html(event.ruleId)}</td><td>${html(event.description)}</td><td>${html(event.matched.join(' · '))}</td><td>${html(mailValues)}</td><td class="mono">${html(event.id)}</td></tr>`;
}

function activityPrintRow(group: ReturnType<typeof groupInvestigationActivity>[number]): string {
  const vendors = [...new Set(group.events.map((event) => event.vendor))].sort().join(', ');
  return `<tr><td>${html(group.entity)}</td><td>${html(group.firstAt)}</td><td>${html(group.lastAt)}</td><td>${group.events.length}</td><td>${html(vendors)}</td></tr>`;
}

function exactEmailPrintRow(group: ReturnType<typeof groupExactEmailMessages>[number]): string {
  const evidence = summarizeExactEmailMessageGroup(group);
  const recipients = evidence.recipients.join(', ') || 'No provistos en los eventos';
  const truncation = evidence.recipientsTruncated ? 'Sí; la lista está truncada' : 'No';
  return `<tr><td>${html(group.idType)}</td><td class="mono">${html(group.id)}</td><td>${html(evidence.direction)}</td><td>${group.events.length}</td><td>${html(evidence.auditedMailboxes.join(', ') || 'No provisto')}</td><td>${html(recipients)}<br/><small>Lista truncada: ${html(truncation)}</small></td><td>${html(evidence.operations.join(', ') || 'No provista')}</td><td>${html(group.events.map((event) => event.id).join(' · '))}</td></tr>`;
}

interface InvestigationPrintRows {
  readonly events: string;
  readonly activity: string;
  readonly exactEmail: string;
}

function investigationPrintHtmlWithRows(
  input: InvestigationReportData,
  groups: ReturnType<typeof groupInvestigationActivity>,
  exactEmailGroups: ReturnType<typeof groupExactEmailMessages>,
  prepared?: InvestigationPrintRows,
): string {
  if (input.assistantAnalysis !== undefined) {
    const hasInvestigation = Boolean(input.alert || input.sourceEvent || input.events.length > 0);
    const citations = (input.assistantCitations ?? [])
      .map(
        (citation) =>
          `<li><strong>${html(citation.kind)}</strong> · ${html(citation.label)} <code>${html(citation.id)}</code></li>`,
      )
      .join('');
    const investigation = !hasInvestigation
      ? ''
      : `<h2>Evidencia de investigación</h2><div class="meta"><strong>Alerta B89:</strong> ${html(input.alert?.id ?? '—')}<br/><strong>Eventos:</strong> ${input.events.length.toLocaleString('es-PE')} de ${input.totalEvents.toLocaleString('es-PE')}${input.truncated ? ' (límite de exportación)' : ''}<br/><strong>Entidades:</strong> ${html(input.entities.join(' · '))}</div><p class="notice">La actividad agrupada muestra coincidencias y proximidad temporal; no prueba causalidad ni un hilo de correo. Solo las operaciones de envío documentadas permiten clasificar salida; el feed actual no acredita recepción.</p><h3>Actividad agrupada por entidad</h3><table><thead><tr><th>Entidad</th><th>Primera actividad UTC</th><th>Última actividad UTC</th><th>Eventos</th><th>Orígenes</th></tr></thead><tbody>${groups.map(activityPrintRow).join('') || '<tr><td colspan="5">Sin grupos</td></tr>'}</tbody></table><h3>Coincidencias por ID exacto de mensaje</h3><table><thead><tr><th>Tipo</th><th>ID exacto</th><th>Dirección según operaciones</th><th>Eventos</th><th>Buzones auditados</th><th>Destinatarios del DTO</th><th>Operaciones</th><th>IDs de evento</th></tr></thead><tbody>${exactEmailGroups.map(exactEmailPrintRow).join('') || '<tr><td colspan="8">Sin coincidencias</td></tr>'}</tbody></table><h3>Línea de tiempo (${input.events.length.toLocaleString('es-PE')} eventos)</h3><table><thead><tr><th>Tipo</th><th>Fecha UTC</th><th>Nivel</th><th>Origen</th><th>Regla</th><th>Descripción</th><th>Entidades</th><th>Metadatos M365</th><th>ID</th></tr></thead><tbody>${input.events.map((event) => eventPrintRow(input, event)).join('') || '<tr><td colspan="9">Sin eventos autorizados en la ventana seleccionada.</td></tr>'}</tbody></table>`;
    return `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>${html(input.title)} · B89 SOC</title><style>body{font:14px/1.55 Arial,sans-serif;color:#17212b;max-width:1100px;margin:36px auto;padding:0 24px}header{border-bottom:4px solid #df8b26;padding:0 0 18px;margin-bottom:22px}h1{font-size:25px;margin:0 0 8px;color:#263444}h2{font-size:17px;color:#263444;margin:24px 0 8px}h3{font-size:14px;color:#263444;margin:20px 0 8px}.meta,.notice{padding:12px 14px;background:#f2f5f8;border-left:4px solid #df8b26}.analysis{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 Arial,sans-serif}.chart{margin:20px 0}.chart svg{max-width:100%;height:auto}figcaption,small{color:#536477;font-size:11px}li{margin:6px 0}code{font:11px monospace}table{width:100%;border-collapse:collapse;margin-top:10px;table-layout:fixed;font-size:11px}th{background:#263444;color:white;text-align:left}th,td{padding:6px;border:1px solid #cbd2d9;vertical-align:top;overflow-wrap:anywhere}.foot{margin-top:32px;border-top:1px solid #cbd2d9;padding-top:10px;color:#536477;font-size:11px}@page{size:A4 landscape;margin:14mm}@media print{body{margin:0;max-width:none;padding:0}thead{display:table-header-group}tr{break-inside:avoid}}</style></head><body><header><h1>B89 SOC · ${hasInvestigation ? 'Informe profesional de investigación' : 'Informe de análisis Bunny'}</h1><div>${html(input.title)}</div></header><div class="meta"><strong>Generado (UTC):</strong> ${html(input.generatedAt.toISOString())}</div><p class="notice">Respuesta asistida por IA. Revisa las fuentes y valida los hallazgos antes de compartir o tomar decisiones.</p>${input.assistantChartSvg ? `<figure class="chart">${input.assistantChartSvg}<figcaption>Gráfico derivado solo de los valores numéricos explícitos de la respuesta.</figcaption></figure>` : ''}<h2>Análisis de Bunny</h2><pre class="analysis">${html(input.assistantAnalysis)}</pre><h2>Fuentes citadas</h2><ul>${citations || '<li>La respuesta no incluyó fuentes citadas.</li>'}</ul>${investigation}<footer class="foot">B89 SOC · Evidencia consultada con la identidad del analista; contiene solo campos autorizados del contrato de investigación.</footer><script>window.addEventListener('load',()=>window.print());</script></body></html>`;
  }
  const rows =
    prepared?.events ?? input.events.map((event) => eventPrintRow(input, event)).join('');
  const blocks = prepared?.activity ?? groups.map(activityPrintRow).join('');
  const emailBlocks = prepared?.exactEmail ?? exactEmailGroups.map(exactEmailPrintRow).join('');
  const bunnySection =
    input.assistantAnalysis === undefined
      ? ''
      : `<h2>Análisis de Bunny</h2><p class="note">Respuesta asistida por IA; debe revisarse antes de compartir o tomar decisiones.</p>${input.assistantChartSvg ? `<figure>${input.assistantChartSvg}<figcaption>Visualización derivada exclusivamente de la tabla numérica incluida en la respuesta.</figcaption></figure>` : ''}<pre class="analysis">${html(input.assistantAnalysis)}</pre><h3>Fuentes citadas</h3><ul>${(input.assistantCitations ?? []).map((citation) => `<li>${html(citation.kind)} · ${html(citation.label)} (ID ${html(citation.id)})</li>`).join('') || '<li>La respuesta no incluyó fuentes citadas.</li>'}</ul>`;
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>${html(input.title)} · Informe B89 SOC</title><style>body{font:12px/1.45 Arial,sans-serif;color:#17212b;margin:32px}header{border-bottom:3px solid #df8b26;padding-bottom:16px;margin-bottom:24px}h1{font-size:24px;margin:0 0 8px}h2{font-size:16px;margin:28px 0 8px;color:#25384b}.meta{display:grid;grid-template-columns:180px 1fr;gap:5px 12px}.meta strong{color:#536477}table{width:100%;border-collapse:collapse;margin-top:10px;table-layout:fixed}th{background:#263444;color:white;text-align:left}th,td{padding:6px;border:1px solid #cbd2d9;vertical-align:top;overflow-wrap:anywhere}.mono{font-family:monospace;font-size:10px}.note{background:#f2f5f8;padding:10px;border-left:3px solid #df8b26}.analysis{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.55 Arial,sans-serif}.foot{margin-top:24px;color:#536477;font-size:10px}@page{size:A4 landscape;margin:12mm}@media print{body{margin:0}thead{display:table-header-group}tr{break-inside:avoid}h2{break-after:avoid}}</style></head><body><header><h1>B89 SOC · ${input.assistantAnalysis === undefined ? 'Informe de investigación' : 'Análisis asistido por Bunny'}</h1><div>${html(input.title)}</div></header><section class="meta"><strong>Generado (UTC)</strong><span>${html(input.generatedAt.toISOString())}</span><strong>Alerta B89</strong><span>${html(input.alert?.id ?? '—')}</span><strong>Evento Wazuh de origen</strong><span>${html(input.sourceEvent?.id ?? '—')}</span><strong>Eventos incluidos</strong><span>${input.events.length.toLocaleString('es-PE')} de ${input.totalEvents.toLocaleString('es-PE')}${input.truncated ? ' · informe limitado a 10.000 eventos' : ''}</span><strong>Entidades analizadas</strong><span>${html(input.entities.join(' · '))}</span></section>${bunnySection}<p class="note">La actividad por entidad y proximidad no establece causalidad. Los grupos por NetworkMessageId o InternetMessageId son coincidencias exactas; no prueban causalidad ni un hilo. Solo las operaciones de envío documentadas permiten clasificar salida; el feed actual no acredita recepción. Buzones y destinatarios proceden únicamente del DTO allowlisted; un buzón auditado no identifica necesariamente al actor humano. Los campos sensibles excluidos por contrato no se incorporan.</p><h2>Actividad agrupada por entidad y proximidad</h2><table><thead><tr><th>Entidad</th><th>Primera actividad UTC</th><th>Última actividad UTC</th><th>Eventos</th><th>Orígenes</th></tr></thead><tbody>${blocks || '<tr><td colspan="5">Sin bloques de actividad</td></tr>'}</tbody></table><h2>Coincidencias por identificador exacto de mensaje</h2><table><thead><tr><th>Campo</th><th>Identificador exacto</th><th>Dirección según operaciones</th><th>Eventos</th><th>Buzones auditados</th><th>Destinatarios del DTO</th><th>Operaciones auditadas</th><th>IDs de evento</th></tr></thead><tbody>${emailBlocks || '<tr><td colspan="8">Sin identificadores exactos compartidos</td></tr>'}</tbody></table><h2>Línea de tiempo · ${input.events.length.toLocaleString('es-PE')} eventos</h2><table><thead><tr><th>Tipo</th><th>Fecha y hora UTC</th><th>Nivel</th><th>Origen</th><th>Regla</th><th>Descripción</th><th>Entidades</th><th>Metadatos M365 de auditoría</th><th>ID</th></tr></thead><tbody>${rows || '<tr><td colspan="9">Sin eventos</td></tr>'}</tbody></table><footer class="foot">B89 SOC · Evidencia consultada con la identidad del analista. Exportación limitada a los campos visibles del contrato de investigación.</footer><script>window.addEventListener('load',()=>window.print());</script></body></html>`;
}

export function investigationPrintHtml(input: InvestigationReportData): string {
  return investigationPrintHtmlWithRows(
    input,
    groupInvestigationActivity(input.events),
    groupExactEmailMessages(input.events),
  );
}

/** Chunked print rendering supports progress updates and cancellation before opening print UI. */
export async function investigationPrintHtmlWithProgress(
  input: InvestigationReportData,
  signal: AbortSignal,
  onProgress?: (progress: ReportProgress) => void,
): Promise<string> {
  const groups = groupInvestigationActivity(input.events);
  const exactEmailGroups = groupExactEmailMessages(input.events);
  const total = input.events.length + groups.length + exactEmailGroups.length;
  const progress = { completed: 0 };
  const render = async <T>(items: readonly T[], write: (item: T) => string): Promise<string> => {
    const chunks: string[] = [];
    const chunkSize = 250;
    for (let offset = 0; offset < items.length; offset += chunkSize) {
      abortIfNeeded(signal);
      const end = Math.min(offset + chunkSize, items.length);
      chunks.push(items.slice(offset, end).map(write).join(''));
      const completed = progress.completed + end;
      onProgress?.({
        phase: 'render',
        completed,
        total,
        percent: 65 + Math.floor((completed / Math.max(1, total)) * 25),
        message: `Preparando expediente imprimible: ${completed.toLocaleString('es-PE')} de ${total.toLocaleString('es-PE')} filas`,
      });
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
    progress.completed += items.length;
    return chunks.join('');
  };
  const rows: InvestigationPrintRows = {
    events: await render(input.events, (event) => eventPrintRow(input, event)),
    activity: await render(groups, activityPrintRow),
    exactEmail: await render(exactEmailGroups, exactEmailPrintRow),
  };
  abortIfNeeded(signal);
  return investigationPrintHtmlWithRows(input, groups, exactEmailGroups, rows);
}

export function writeInvestigationPrintWindow(
  target: Window,
  input: InvestigationReportData,
): void {
  target.document.open();
  target.document.write(investigationPrintHtml(input));
  target.document.close();
}

export async function writeInvestigationPrintWindowWithProgress(
  target: Window,
  input: InvestigationReportData,
  signal: AbortSignal,
  onProgress?: (progress: ReportProgress) => void,
): Promise<void> {
  const content = await investigationPrintHtmlWithProgress(input, signal, onProgress);
  abortIfNeeded(signal);
  target.document.open();
  target.document.write(content);
  target.document.close();
}

export function downloadInvestigationXlsx(input: InvestigationReportData): Promise<void> {
  return createInvestigationXlsx(input).then((blob) => {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `b89-investigacion-${(input.alert?.id ?? 'grupo').replace(/[^A-Za-z0-9_-]/gu, '_')}.xlsx`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  });
}
