/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { BunnyCitation } from './chat_client';
import type { InvestigationReportData } from '../components/investigation_report';
import type { Alert, EventResponse, InvestigationEntity, InvestigationEvent } from '../../common';
import type { RelatedWindow } from '../../common/investigation';
import { ENTITY_KINDS } from '../../common/investigation';
import { collectInvestigationReport } from '../components/investigation_report';
import type { RelatedPageLoader, ReportProgress, ReportEventSummary } from '../components/investigation_report';

export interface BunnyNumericTable {
  readonly headers: readonly string[];
  readonly rows: readonly (readonly (string | number)[])[];
}

function cells(line: string): string[] {
  return line.trim().replace(/^\|/u, '').replace(/\|$/u, '').split('|').map((cell) => cell.trim());
}

function numericCell(value: string): number | null {
  const cleaned = value.replace(/,/gu, '').trim();
  if (!/^-?\d+(?:\.\d+)?$/u.test(cleaned)) return null;
  const number = Number(cleaned);
  return Number.isFinite(number) ? number : null;
}

/** Detect only complete Markdown tables with explicit category and numeric columns. */
export function bunnyNumericTable(markdown: string): BunnyNumericTable | null {
  const lines = markdown.split(/\r?\n/u);
  for (let index = 0; index < lines.length - 2; index += 1) {
    if (!lines[index]!.includes('|') || !lines[index + 1]!.includes('|')) continue;
    const headers = cells(lines[index]!);
    const separator = cells(lines[index + 1]!);
    if (headers.length < 2 || separator.length !== headers.length || !separator.every((cell) => /^:?-{3,}:?$/u.test(cell))) continue;
    const rows: (string | number)[][] = [];
    for (let rowIndex = index + 2; rowIndex < lines.length && lines[rowIndex]!.includes('|'); rowIndex += 1) {
      const row = cells(lines[rowIndex]!);
      if (row.length !== headers.length) break;
      const parsed = row.map((value, column) => column === 0 ? value : numericCell(value));
      if (parsed[0] && parsed.slice(1).some((value) => typeof value === 'number')) {
        rows.push(parsed.map((value) => value ?? ''));
      }
    }
    const numericColumns = headers.slice(1).filter((_, column) => rows.some((row) => typeof row[column + 1] === 'number')).length;
    if (rows.length > 0 && numericColumns > 0) return { headers, rows };
  }
  return null;
}

function xml(value: string): string {
  return value.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;').replace(/"/gu, '&quot;').replace(/'/gu, '&apos;');
}

/** Small print-safe chart from explicit numeric table cells. No inferred or fabricated values. */
export function bunnyNumericChartSvg(table: BunnyNumericTable): string {
  const values = table.rows.map((row) => row.slice(1).find((cell): cell is number => typeof cell === 'number') ?? 0);
  const maximum = Math.max(1, ...values.map((value) => Math.abs(value)));
  const width = 680;
  const plotWidth = 520;
  const barHeight = 22;
  const rowHeight = 34;
  const height = Math.max(100, 54 + table.rows.length * rowHeight);
  const bars = table.rows.map((row, index) => {
    const y = 38 + index * rowHeight;
    const label = String(row[0]);
    const amount = values[index]!;
    const bar = Math.max(2, Math.abs(amount) / maximum * plotWidth);
    return `<text x="0" y="${y + 16}" font-size="12" fill="#263444">${xml(label.slice(0, 38))}</text><rect x="145" y="${y}" width="${bar.toFixed(1)}" height="${barHeight}" rx="4" fill="#1677a8"/><text x="${Math.min(650, 152 + bar)}" y="${y + 16}" font-size="12" fill="#17212b">${amount}</text>`;
  }).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${xml(`${table.headers[0]}: ${table.headers.slice(1).join(', ')}`)}" viewBox="0 0 ${width} ${height}" width="100%" height="${height}"><rect width="100%" height="100%" fill="#fff"/><text x="0" y="20" font-size="14" font-weight="bold" fill="#263444">${xml(table.headers.slice(1).join(' · '))}</text>${bars}</svg>`;
}

export function bunnyReportData(input: {
  readonly text: string;
  readonly citations: readonly BunnyCitation[];
  readonly title?: string;
  readonly includeChart: boolean;
  readonly now?: Date;
}): InvestigationReportData {
  const table = input.includeChart ? bunnyNumericTable(input.text) : null;
  return {
    alert: null,
    title: input.title?.trim() || 'Análisis de Bunny',
    entities: [],
    events: [],
    totalEvents: 0,
    generatedAt: input.now ?? new Date(),
    truncated: false,
    assistantAnalysis: input.text,
    assistantCitations: input.citations,
    ...(table ? { assistantChartSvg: bunnyNumericChartSvg(table), assistantChartData: table } : {}),
  };
}

export class BunnyInvestigationError extends Error {
  public constructor(public readonly reason: 'no-citation' | 'forbidden' | 'not-found' | 'unavailable' | 'no-entities') {
    super(reason);
    this.name = 'BunnyInvestigationError';
  }
}

function isEntityKind(value: string): value is InvestigationEntity['kind'] {
  return (ENTITY_KINDS as readonly string[]).includes(value);
}

/** Collects the cited source and every authorized related page before producing a real case report. */
export async function collectBunnyInvestigationReport(input: {
  readonly citation: BunnyCitation | null;
  readonly window: RelatedWindow;
  readonly analysis: string;
  readonly citations: readonly BunnyCitation[];
  readonly includeChart: boolean;
  readonly loadAlert: (id: string) => Promise<Alert>;
  readonly loadEvent: (id: string) => Promise<EventResponse>;
  readonly loadPage: RelatedPageLoader;
  readonly signal: AbortSignal;
  readonly onProgress?: (progress: ReportProgress) => void;
  readonly now?: () => Date;
}): Promise<InvestigationReportData> {
  const citation = input.citation;
  if (!citation || (citation.kind !== 'alert' && citation.kind !== 'event')) {
    throw new BunnyInvestigationError('no-citation');
  }
  let alert: Alert | null = null;
  let sourceEvent: InvestigationEvent | null = null;
  if (citation.kind === 'alert') {
    try {
      alert = await input.loadAlert(citation.id);
    } catch {
      throw new BunnyInvestigationError('not-found');
    }
    const rawId = alert.rawRef?.replace(/^raw:/u, '');
    if (rawId) {
      try {
        const response = await input.loadEvent(rawId);
        if (response.access === 'forbidden') throw new BunnyInvestigationError('forbidden');
        if (response.access === 'ok' && response.event) sourceEvent = response.event;
      } catch (error) {
        if (error instanceof BunnyInvestigationError) throw error;
      }
    }
  } else {
    let response: EventResponse;
    try {
      response = await input.loadEvent(citation.id);
    } catch {
      throw new BunnyInvestigationError('unavailable');
    }
    if (response.access === 'forbidden') throw new BunnyInvestigationError('forbidden');
    if (response.access !== 'ok' || !response.event) throw new BunnyInvestigationError('not-found');
    sourceEvent = response.event;
  }

  const entities: InvestigationEntity[] = sourceEvent?.entities?.filter((entity) => isEntityKind(entity.kind)) ?? [];
  if (entities.length === 0 && alert) {
    for (const entity of alert.entities) {
      if (isEntityKind(entity.kind) && entity.label.trim()) {
        entities.push({ kind: entity.kind, value: entity.label, field: `alert.entities.${entity.kind}` });
      }
    }
  }
  if (entities.length === 0) throw new BunnyInvestigationError('no-entities');
  const at = sourceEvent?.at ?? alert?.occurredAt;
  if (!at || Number.isNaN(Date.parse(at))) throw new BunnyInvestigationError('unavailable');
  const report = await collectInvestigationReport({
    query: {
      entities: entities.map(({ kind, value }) => ({ kind, value })),
      at,
      window: input.window,
      ...(sourceEvent?.id ? { excludeId: sourceEvent.id } : {}),
    },
    alert,
    sourceEvent,
    title: `Investigación · ${citation.label || citation.id}`,
    entities: entities.map((entity) => `${entity.kind}: ${entity.value}`),
    loadPage: input.loadPage,
    signal: input.signal,
    onProgress: input.onProgress,
    now: input.now,
  });
  const table = input.includeChart ? bunnyNumericTable(input.analysis) : null;
  return {
    ...report,
    assistantAnalysis: input.analysis,
    assistantCitations: input.citations,
    ...(table ? { assistantChartData: table, assistantChartSvg: bunnyNumericChartSvg(table) } : {}),
  };
}
