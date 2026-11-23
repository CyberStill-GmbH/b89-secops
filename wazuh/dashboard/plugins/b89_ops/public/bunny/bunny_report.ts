/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { BunnyCitation } from './chat_client';
import type { InvestigationReportData } from '../components/investigation_report';
import type { Alert, EventResponse, InvestigationEntity, InvestigationEvent } from '../../common';
import type { RelatedWindow } from '../../common/investigation';
import { ENTITY_KINDS } from '../../common/investigation';
import { B89ApiError } from '../api/client';
import { collectInvestigationReport } from '../components/investigation_report';
import type {
  RelatedPageLoader,
  ReportProgress,
  ReportEventSummary,
} from '../components/investigation_report';

export interface BunnyNumericTable {
  readonly headers: readonly string[];
  readonly rows: readonly (readonly (string | number)[])[];
}

const MAX_REPORT_IPS = 50;
const MAX_CLOUDFLARE_DETAILS = 30;
const CLOUDFLARE_DETAIL_CONCURRENCY = 4;

type BunnyIpObservation = NonNullable<InvestigationReportData['ipObservations']>[number];
type BunnyCloudflareSignal = NonNullable<InvestigationReportData['cloudflareSignals']>[number];

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function safeField(value: unknown, max = 180): string | null {
  if (typeof value !== 'string') return null;
  const text = value.replace(/[\u0000-\u001f\u007f]/gu, ' ').replace(/\s+/gu, ' ').trim();
  return text ? text.slice(0, max) : null;
}

function cloudflareSignal(event: InvestigationEvent): BunnyCloudflareSignal | null {
  if (event.vendor !== 'cloudflare') return null;
  const raw = object(event.raw);
  const data = object(raw.data);
  const cloudflare = object(data.cloudflare);
  const firewall = object(cloudflare.firewall);
  const audit = object(cloudflare.audit);
  const b89 = object(data.b89);
  const eventType = safeField(b89.event_type, 32)?.toLowerCase();
  const kind: BunnyCloudflareSignal['kind'] =
    eventType === 'firewall'
      ? 'firewall'
      : eventType === 'audit'
        ? 'audit'
        : eventType === 'logpush'
          ? 'logpush'
          : 'other';
  const hasDetails = Object.keys(firewall).length > 0 || Object.keys(audit).length > 0;
  if (!hasDetails) return null;
  return {
    eventId: event.id,
    at: event.at,
    kind,
    action: safeField(firewall.action ?? audit.action, 80),
    source: safeField(firewall.source ?? b89.source, 80),
    zone: safeField(cloudflare.zone_name ?? audit.zone_name, 180),
    host: safeField(firewall.host, 180),
    path: safeField(firewall.path, 180),
    clientIp: safeField(firewall.client_ip ?? audit.actor_ip, 45),
    status: safeField(firewall.status, 24),
    ruleId: safeField(firewall.rule_id, 80),
    rule: safeField(firewall.rule_description, 180),
    ray: safeField(firewall.ray, 64),
    actorType: safeField(audit.actor_type, 48),
    result: safeField(audit.result, 24),
    resourceType: safeField(audit.resource_type, 80),
    resourceId: safeField(audit.resource_id, 100),
  };
}

function ipObservations(
  events: readonly ReportEventSummary[],
  sourceEvent: InvestigationEvent | null,
): { items: BunnyIpObservation[]; truncated: boolean } {
  const byIp = new Map<string, { events: Map<string, { source: string; at: string }>; sources: Set<string> }>();
  const add = (value: string, eventId: string, source: string, at: string) => {
    const ip = value.trim();
    if (!ip || ip.length > 45 || /[\u0000-\u001f\u007f\s]/u.test(ip)) return;
    const item = byIp.get(ip) ?? { events: new Map<string, { source: string; at: string }>(), sources: new Set<string>() };
    item.events.set(eventId, { source, at });
    item.sources.add(source);
    byIp.set(ip, item);
  };
  for (const event of events) {
    for (const matched of event.matched) {
      if (matched.startsWith('ip:')) add(matched.slice(3), event.id, event.vendor, event.at);
    }
  }
  if (sourceEvent) {
    for (const entity of sourceEvent.entities) {
      if (entity.kind === 'ip') add(entity.value, sourceEvent.id, sourceEvent.vendor, sourceEvent.at);
    }
  }
  const sorted = [...byIp.entries()].sort((left, right) =>
    left[0].localeCompare(right[0], 'en'),
  );
  return {
    items: sorted.slice(0, MAX_REPORT_IPS).map(([ip, item]) => {
      const times = [...item.events.values()].map((event) => event.at).sort();
      return {
        ip,
        eventCount: item.events.size,
        firstAt: times[0] ?? '',
        lastAt: times[times.length - 1] ?? '',
        sources: [...item.sources].sort((left, right) => left.localeCompare(right, 'es')),
      };
    }),
    truncated: sorted.length > MAX_REPORT_IPS,
  };
}

async function collectCloudflareSignals(input: {
  events: readonly ReportEventSummary[];
  sourceEvent: InvestigationEvent | null;
  loadEvent: (id: string) => Promise<EventResponse>;
  signal: AbortSignal;
  onProgress?: (progress: ReportProgress) => void;
}): Promise<{ items: BunnyCloudflareSignal[]; note?: string }> {
  const summaries = input.events.filter((event) => event.vendor === 'cloudflare');
  const byId = new Map<string, BunnyCloudflareSignal>();
  if (input.sourceEvent) {
    const source = cloudflareSignal(input.sourceEvent);
    if (source) byId.set(source.eventId, source);
  }
  const details = summaries
    .filter((event) => event.id !== input.sourceEvent?.id)
    .slice(0, MAX_CLOUDFLARE_DETAILS);
  let unavailable = 0;
  for (let offset = 0; offset < details.length; offset += CLOUDFLARE_DETAIL_CONCURRENCY) {
    if (input.signal.aborted) throw new DOMException('Informe cancelado', 'AbortError');
    const page = details.slice(offset, offset + CLOUDFLARE_DETAIL_CONCURRENCY);
    const results = await Promise.all(
      page.map(async (event) => {
        try {
          const response = await readEvidence(() => input.loadEvent(event.id), input.signal);
          const full = requireSourceEvent(response);
          return cloudflareSignal(full);
        } catch (error) {
          if (input.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
            throw new DOMException('Informe cancelado', 'AbortError');
          }
          unavailable += 1;
          return null;
        }
      }),
    );
    for (const result of results) if (result) byId.set(result.eventId, result);
    input.onProgress?.({
      phase: 'query',
      completed: Math.min(offset + page.length, details.length),
      total: details.length,
      message: `Revisando señales Cloudflare: ${Math.min(offset + page.length, details.length)} de ${details.length}`,
    });
  }
  const items = [...byId.values()]
    .sort((left, right) => left.at.localeCompare(right.at) || left.eventId.localeCompare(right.eventId))
    .slice(-MAX_CLOUDFLARE_DETAILS - 1);
  const omitted = summaries.length - details.length - (input.sourceEvent && byId.has(input.sourceEvent.id) ? 1 : 0);
  const notes: string[] = [];
  if (unavailable > 0) notes.push(`${unavailable} detalle(s) no disponibles`);
  if (omitted > 0) notes.push(`límite de consulta: ${MAX_CLOUDFLARE_DETAILS} de ${summaries.length} eventos relacionados`);
  return { items, ...(notes.length ? { note: notes.join('; ') } : {}) };
}

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/u, '')
    .replace(/\|$/u, '')
    .split('|')
    .map((cell) => cell.trim());
}

function numericCell(value: string): number | null {
  // A comma may be a decimal or a thousands separator. Never silently change its meaning.
  const cleaned = value.trim();
  if (!/^-?\d+(?:\.\d+)?$/u.test(cleaned)) return null;
  const number = Number(cleaned);
  if (!Number.isFinite(number) || (Number.isInteger(number) && !Number.isSafeInteger(number)))
    return null;
  return number;
}

/** Detect only complete Markdown tables with explicit category and numeric columns. */
export function bunnyNumericTable(markdown: string): BunnyNumericTable | null {
  const lines = markdown.split(/\r?\n/u);
  for (let index = 0; index < lines.length - 2; index += 1) {
    if (!lines[index]!.includes('|') || !lines[index + 1]!.includes('|')) continue;
    const headers = cells(lines[index]!);
    const separator = cells(lines[index + 1]!);
    if (
      headers.length < 2 ||
      separator.length !== headers.length ||
      !separator.every((cell) => /^:?-{3,}:?$/u.test(cell))
    )
      continue;
    const rows: (string | number)[][] = [];
    for (
      let rowIndex = index + 2;
      rowIndex < lines.length && lines[rowIndex]!.includes('|');
      rowIndex += 1
    ) {
      const row = cells(lines[rowIndex]!);
      if (row.length !== headers.length) break;
      const parsed = row.map((value, column) => (column === 0 ? value : numericCell(value)));
      if (parsed[0]) {
        // Preserve absent/ambiguous cells and categories; an unknown value is never zero.
        rows.push(parsed.map((value, column) => value ?? row[column]!));
      }
    }
    const numericColumns = headers
      .slice(1)
      .filter((_, column) => rows.some((row) => typeof row[column + 1] === 'number')).length;
    if (rows.length > 0 && numericColumns > 0) return { headers, rows };
  }
  return null;
}

export function bunnyNumericColumns(table: BunnyNumericTable): number[] {
  return table.headers
    .map((_, column) => column)
    .filter((column) => column > 0 && table.rows.some((row) => typeof row[column] === 'number'));
}

/** One named metric shared by the preview, printable report and Excel data sheet. */
export function bunnyChartSeries(table: BunnyNumericTable, column?: number) {
  const columns = bunnyNumericColumns(table);
  const selected = column === undefined ? columns[0] : column;
  if (selected === undefined || !columns.includes(selected)) return null;
  const rows = table.rows.map((row) => {
    const cell = row[selected];
    return { label: String(row[0]), value: typeof cell === 'number' ? cell : null };
  });
  const values = rows.map(({ value }) => value ?? 0);
  const minimum = Math.min(0, ...values);
  const maximum = Math.max(0, ...values);
  const span = maximum - minimum || 1;
  const zeroPercent = (-minimum / span) * 100;
  return {
    column: selected,
    label: table.headers[selected]!,
    zeroPercent,
    rows: rows.map((row) => ({
      ...row,
      fromPercent:
        row.value === null ? zeroPercent : ((Math.min(0, row.value) - minimum) / span) * 100,
      widthPercent: row.value === null ? 0 : (Math.abs(row.value) / span) * 100,
    })),
    table: {
      headers: [table.headers[0]!, table.headers[selected]!],
      rows: table.rows.map((row) => [row[0]!, row[selected] ?? '']),
    } as BunnyNumericTable,
  };
}

function xml(value: string): string {
  return value
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&apos;');
}

/** Small print-safe chart from explicit numeric table cells. No inferred or fabricated values. */
export function bunnyNumericChartSvg(table: BunnyNumericTable, column?: number): string {
  const series = bunnyChartSeries(table, column);
  if (!series) return '';
  const width = 680;
  const plotWidth = 390;
  const plotLeft = 145;
  const zero = plotLeft + (series.zeroPercent / 100) * plotWidth;
  const barHeight = 22;
  const rowHeight = 34;
  const height = Math.max(100, 54 + table.rows.length * rowHeight);
  const bars = series.rows
    .map((row, index) => {
      const y = 38 + index * rowHeight;
      const amount = row.value === null ? 'Sin dato' : String(row.value);
      const bar =
        row.value === null || row.value === 0
          ? ''
          : `<rect x="${(plotLeft + (row.fromPercent / 100) * plotWidth).toFixed(1)}" y="${y}" width="${((row.widthPercent / 100) * plotWidth).toFixed(1)}" height="${barHeight}" rx="3" fill="#1677a8"/>`;
      return `<g><title>${xml(`${row.label}: ${amount}`)}</title><text x="0" y="${y + 16}" font-size="12" fill="#263444">${xml(row.label.slice(0, 22))}</text>${bar}<text x="550" y="${y + 16}" font-size="12" fill="#17212b">${amount}</text></g>`;
    })
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${xml(`${table.headers[0]}: ${series.label}`)}" viewBox="0 0 ${width} ${height}" width="100%" height="${height}"><title>${xml(series.label)}</title><desc>Una sola métrica. Las barras parten de cero; los valores ausentes o ambiguos se muestran como Sin dato.</desc><rect width="100%" height="100%" fill="#fff"/><text x="0" y="20" font-size="14" font-weight="bold" fill="#263444">${xml(series.label)}</text><line x1="${zero.toFixed(1)}" x2="${zero.toFixed(1)}" y1="30" y2="${height - 12}" stroke="#89919a"/>${bars}</svg>`;
}

function reportChart(text: string, include: boolean, column?: number) {
  const table = include ? bunnyNumericTable(text) : null;
  const series = table ? bunnyChartSeries(table, column) : null;
  return series
    ? { assistantChartSvg: bunnyNumericChartSvg(series.table), assistantChartData: series.table }
    : {};
}

export function bunnyReportData(input: {
  readonly text: string;
  readonly citations: readonly BunnyCitation[];
  readonly title?: string;
  readonly includeChart: boolean;
  readonly chartColumn?: number;
  readonly now?: Date;
}): InvestigationReportData {
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
    ...reportChart(input.text, input.includeChart, input.chartColumn),
  };
}

export class BunnyInvestigationError extends Error {
  public constructor(
    public readonly reason:
      'no-citation' | 'forbidden' | 'not-found' | 'unavailable' | 'no-entities',
  ) {
    super(reason);
    this.name = 'BunnyInvestigationError';
  }
}

function isEntityKind(value: string): value is InvestigationEntity['kind'] {
  return (ENTITY_KINDS as readonly string[]).includes(value);
}

/** Stop immediately even when a legacy read client cannot cancel its own network request. */
async function readEvidence<T>(load: () => Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw new DOMException('Informe cancelado', 'AbortError');
  try {
    return await new Promise<T>((resolve, reject) => {
      const onAbort = () => reject(new DOMException('Informe cancelado', 'AbortError'));
      signal.addEventListener('abort', onAbort, { once: true });
      Promise.resolve()
        .then(() => {
          if (signal.aborted) throw new DOMException('Informe cancelado', 'AbortError');
          return load();
        })
        .then(resolve, reject)
        .finally(() => signal.removeEventListener('abort', onAbort));
    });
  } catch (error) {
    if (signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
      throw new DOMException('Informe cancelado', 'AbortError');
    }
    if (error instanceof B89ApiError) {
      if (error.status === 401 || error.status === 403)
        throw new BunnyInvestigationError('forbidden');
      if (error.status === 404) throw new BunnyInvestigationError('not-found');
    }
    throw new BunnyInvestigationError('unavailable');
  }
}

function requireSourceEvent(response: EventResponse): InvestigationEvent {
  if (response.access === 'forbidden') throw new BunnyInvestigationError('forbidden');
  if (response.access === 'error') throw new BunnyInvestigationError('unavailable');
  if (response.access !== 'ok' || !response.event) throw new BunnyInvestigationError('not-found');
  return response.event;
}

/** Collects the cited source and every authorized related page before producing a real case report. */
export async function collectBunnyInvestigationReport(input: {
  readonly citation: BunnyCitation | null;
  readonly window: RelatedWindow;
  readonly analysis: string;
  readonly citations: readonly BunnyCitation[];
  readonly includeChart: boolean;
  readonly chartColumn?: number;
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
  if (input.signal.aborted) throw new DOMException('Informe cancelado', 'AbortError');
  input.onProgress?.({
    phase: 'query',
    completed: 0,
    total: 0,
    message:
      citation.kind === 'alert' ? 'Verificando la alerta citada…' : 'Verificando el evento citado…',
  });
  let alert: Alert | null = null;
  let sourceEvent: InvestigationEvent | null = null;
  if (citation.kind === 'alert') {
    alert = await readEvidence(() => input.loadAlert(citation.id), input.signal);
    const rawId = alert.rawRef?.replace(/^raw:/u, '');
    if (rawId) {
      const response = await readEvidence(() => input.loadEvent(rawId), input.signal);
      sourceEvent = requireSourceEvent(response);
    }
  } else {
    const response = await readEvidence(() => input.loadEvent(citation.id), input.signal);
    sourceEvent = requireSourceEvent(response);
  }

  const entities: InvestigationEntity[] =
    sourceEvent?.entities?.filter((entity) => isEntityKind(entity.kind) && entity.value.trim()) ??
    [];
  if (entities.length === 0 && alert) {
    for (const entity of alert.entities) {
      if (isEntityKind(entity.kind) && entity.label.trim()) {
        entities.push({
          kind: entity.kind,
          value: entity.label,
          field: `alert.entities.${entity.kind}`,
        });
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
  const ips = ipObservations(report.events, sourceEvent);
  const cloudflare = await collectCloudflareSignals({
    events: report.events,
    sourceEvent,
    loadEvent: input.loadEvent,
    signal: input.signal,
    onProgress: input.onProgress,
  });
  const observationNotes = [
    ...(ips.truncated ? [`se muestran ${MAX_REPORT_IPS} de más IP observadas`] : []),
    ...(cloudflare.note ? [cloudflare.note] : []),
  ];
  return {
    ...report,
    assistantAnalysis: input.analysis,
    assistantCitations: input.citations,
    ipObservations: ips.items,
    cloudflareSignals: cloudflare.items,
    ...(observationNotes.length ? { observationsNote: observationNotes.join('; ') } : {}),
    ...reportChart(input.analysis, input.includeChart, input.chartColumn),
  };
}
