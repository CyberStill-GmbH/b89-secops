/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Salud multiseñal por fuente (API `GET /api/sources/health` → `verdicts`, docs/20 «Salud por
 * fuente»). Rótulos en español del veredicto y de sus motivos; una fuente «Desconocida» nunca se
 * muestra como sana y una señal sin dato se escribe «Sin dato», nunca 0.
 */

import type { HealthTone } from './catalog';

export const SOURCE_VERDICTS = ['healthy', 'quiet', 'degraded', 'failing', 'unknown'] as const;
export type SourceVerdict = (typeof SOURCE_VERDICTS)[number];

export interface SourceVerdictView {
  readonly id: string;
  readonly label: string;
  readonly provider: string;
  readonly verdict: SourceVerdict;
  readonly reasons: readonly string[];
  readonly lastHeartbeatAt: string | null;
  readonly lastSuccessfulRunAt: string | null;
  readonly lastAuthOkAt: string | null;
  readonly lastEventAt: string | null;
  readonly canaryAt: string | null;
  readonly heartbeat: {
    readonly outcome: string | null;
    readonly auth: string | null;
    readonly httpStatusClass: string | null;
    readonly errorCode: string | null;
    readonly itemsFetched: number | null;
    readonly cursorAdvanced: boolean | null;
    readonly cursorPosition: string | null;
    readonly consecutiveFailures: number;
    readonly collectorVersion: string | null;
  } | null;
  readonly providerLagSeconds: number | null;
  readonly ingestLag: {
    readonly samples: number;
    readonly p50Seconds: number | null;
    readonly maxSeconds: number | null;
    readonly clockSkewSamples: number;
  } | null;
  readonly volume: {
    readonly windowHours: number;
    readonly current: number;
    readonly expected: number | null;
    readonly weeksUsed: number;
    readonly drop: boolean;
  } | null;
  readonly expectedHeartbeatMs: number | null;
  readonly measuredAt: string | null;
}

export interface SourceHealthModelInfo {
  readonly version: string;
  readonly status: 'measured' | 'not_configured' | 'unavailable';
  readonly measuredAt: string | null;
  readonly stale: boolean;
}

/**
 * Escala única de salud (fuentes, monitor de plataforma y salud operativa):
 * «Funciona» / «Sin eventos» / «Con problemas» / «Caída» / «Sin comprobar» / «Desactivada».
 */
export const SOURCE_VERDICT_LABEL: Record<SourceVerdict, string> = {
  healthy: 'Funciona',
  quiet: 'Sin eventos (normal)',
  degraded: 'Con problemas',
  failing: 'Caída',
  unknown: 'Sin comprobar',
};

/** «Sin eventos» ≠ caída: tono informativo, no de alerta (igual en el monitor de plataforma). */
export const SOURCE_VERDICT_TONE: Record<SourceVerdict, HealthTone> = {
  healthy: 'ok',
  quiet: 'info',
  degraded: 'warn',
  failing: 'fail',
  unknown: 'neutral',
};

export const SOURCE_VERDICT_REASON_LABEL: Record<string, string> = {
  HEARTBEAT_MISSING: 'El colector dejó de reportar (más de 2 ciclos sin señal)',
  AUTH_DENIED: 'El proveedor rechazó la credencial o el permiso',
  AUTH_EXPIRED: 'Credencial vencida',
  CONSECUTIVE_FAILURES: 'El colector falló varias veces seguidas',
  CONTENT_DISABLED: 'Suscripción del proveedor deshabilitada',
  INGESTION_FAILED: 'B89 no puede leer los eventos de Wazuh',
  RUN_FAILED: 'La última lectura del colector falló',
  RUN_PARTIAL: 'La última lectura quedó a medias (hay eventos pendientes)',
  PROVIDER_LAG: 'El proveedor entrega con atraso',
  INGEST_LAG: 'Los eventos tardan en llegar al SIEM',
  VOLUME_DROP: 'Llegan menos eventos de lo habitual frente a semanas anteriores',
  CANARY_STALE: 'El evento de prueba automático no llegó en las últimas 26 h',
  INGESTION_DEGRADED: 'La lectura de eventos de Wazuh tiene fallos',
  HEARTBEAT_OK: 'El colector reporta y se autentica bien',
  CANARY_OK: 'Evento de prueba automático recibido',
  EVENTS_RECENT: 'Eventos recientes',
  NO_RECENT_EVENTS: 'Sin eventos nuevos; el colector funciona',
  INGESTION_OK: 'Lectura correcta reciente',
  HEARTBEAT_NEVER_SEEN: 'El colector nunca reportó (no está instalado o falta actualizarlo)',
  EVENTS_WITHOUT_HEARTBEAT: 'Llegan eventos, pero el colector no reporta su estado',
  CANARY_NEVER_SEEN: 'Sin evento de prueba automático registrado',
  SIGNALS_NOT_CONFIGURED: 'Este despliegue no mide la salud por fuente',
  SIGNALS_UNAVAILABLE: 'No se pudo leer el SIEM para medir la salud',
  INGESTION_DISABLED: 'Ingesta desactivada por configuración',
  INGESTION_NO_DATA: 'Todavía no hay lecturas registradas',
};

/** Problemas operativos `SOURCE_*` (sección `sources` de `/api/operations/health`). */
export const SOURCE_ISSUE_LABEL: Record<string, string> = {
  SOURCE_AUTH_FAILED: 'Una fuente tiene la credencial vencida o rechazada',
  SOURCE_COLLECTOR_SILENT: 'Un colector dejó de reportar',
  SOURCE_RUNS_FAILING: 'Una fuente falló varias veces seguidas',
  SOURCE_SUBSCRIPTION_DISABLED: 'Una suscripción del proveedor está deshabilitada',
  SOURCE_VOLUME_DROP: 'Una fuente no trae los eventos esperados',
  SOURCE_LAGGING: 'Una fuente llega con atraso',
  SOURCE_CANARY_STALE: 'Un evento de prueba automático no llegó',
  SOURCE_SIGNALS_UNAVAILABLE: 'No se pudo medir la salud de las fuentes',
  SOURCE_SIGNALS_STALE: 'La salud de las fuentes es de una medición anterior',
};

export function verdictReasonLabel(code: string): string {
  return SOURCE_VERDICT_REASON_LABEL[code] ?? code;
}

/** Frase de una línea para tarjetas y píldoras: el motivo más importante. */
export function verdictHeadline(item: Pick<SourceVerdictView, 'verdict' | 'reasons'>): string {
  const first =
    item.verdict === 'healthy' || item.verdict === 'quiet'
      ? item.reasons[item.reasons.length - 1]
      : item.reasons[0];
  return first ? verdictReasonLabel(first) : SOURCE_VERDICT_LABEL[item.verdict];
}

function isVerdict(value: unknown): value is SourceVerdict {
  return (SOURCE_VERDICTS as readonly unknown[]).includes(value);
}

/** Normaliza la lista del API: descarta filas mal formadas, nunca inventa un veredicto. */
export function parseVerdicts(raw: unknown): SourceVerdictView[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(
      (item): item is SourceVerdictView =>
        !!item &&
        typeof item === 'object' &&
        typeof (item as SourceVerdictView).id === 'string' &&
        isVerdict((item as SourceVerdictView).verdict),
    )
    .map((item) => ({ ...item, reasons: Array.isArray(item.reasons) ? item.reasons : [] }))
    .slice(0, 30);
}

/** Fuentes de la API por servicio del catálogo (tarjetas del Resumen e Integraciones). */
export const SERVICE_VERDICT_SOURCES: Readonly<Record<string, readonly string[]>> = {
  office365: ['m365', 'entra'],
  sharepoint: ['sharepoint-posture', 'sharepoint-audit'],
  bitdefender: ['bitdefender'],
  snyk: ['snyk'],
  cloudflare: ['cloudflare'],
  aws: ['aws'],
  wazuh: ['wazuh-indexer', 'wazuh-agents'],
};

/** Orden de lectura en pantalla: primero lo que necesita acción. */
const DISPLAY_ORDER: Record<SourceVerdict, number> = {
  failing: 0,
  degraded: 1,
  unknown: 2,
  quiet: 3,
  healthy: 4,
};

/** Ordena por gravedad (caída, con problemas, sin comprobar, sin eventos, funciona) y nombre. */
export function sortVerdicts(verdicts: readonly SourceVerdictView[]): SourceVerdictView[] {
  return [...verdicts].sort(
    (a, b) =>
      DISPLAY_ORDER[a.verdict] - DISPLAY_ORDER[b.verdict] ||
      a.label.localeCompare(b.label, 'es'),
  );
}

/** Un veredicto que pide atención: caída, con problemas o sin comprobar. */
export function verdictNeedsAttention(verdict: SourceVerdict): boolean {
  return verdict === 'failing' || verdict === 'degraded' || verdict === 'unknown';
}

export interface VerdictSummary {
  readonly total: number;
  /** Funciona o sin eventos (la conexión responde). */
  readonly working: number;
  readonly problems: readonly SourceVerdictView[];
  readonly unchecked: readonly SourceVerdictView[];
  readonly tone: HealthTone;
  /** La respuesta de la página en una frase. */
  readonly headline: string;
  /** Qué falla y por qué, una fuente por elemento («Bitdefender: credencial vencida»). */
  readonly details: readonly string[];
}

function lowerFirst(text: string): string {
  return text ? text.charAt(0).toLowerCase() + text.slice(1) : text;
}

/** Respuesta principal de «Salud de fuentes»: cuántas funcionan, cuáles fallan y por qué. */
export function summarizeVerdicts(verdicts: readonly SourceVerdictView[]): VerdictSummary {
  const sorted = sortVerdicts(verdicts);
  const problems = sorted.filter((item) => item.verdict === 'failing' || item.verdict === 'degraded');
  const unchecked = sorted.filter((item) => item.verdict === 'unknown');
  const total = sorted.length;
  const working = total - problems.length - unchecked.length;
  const tone: HealthTone = problems.some((item) => item.verdict === 'failing')
    ? 'fail'
    : problems.length > 0
      ? 'warn'
      : unchecked.length > 0
        ? 'neutral'
        : 'ok';
  const parts: string[] = [];
  if (total === 0) parts.push('No hay fuentes medidas todavía.');
  else if (working === total) parts.push(total === 1 ? 'La fuente funciona.' : `Las ${total} fuentes funcionan.`);
  else parts.push(`${working} de ${total} fuentes funcionan.`);
  if (problems.length > 0) {
    parts.push(problems.length === 1 ? '1 tiene problemas.' : `${problems.length} tienen problemas.`);
  }
  if (unchecked.length > 0) {
    parts.push(
      unchecked.length === 1 ? '1 no se pudo comprobar.' : `${unchecked.length} no se pudieron comprobar.`,
    );
  }
  const details = [...problems, ...unchecked].map((item) => {
    const first = item.reasons[0];
    const why = first ? lowerFirst(verdictReasonLabel(first)) : lowerFirst(SOURCE_VERDICT_LABEL[item.verdict]);
    return `${item.label}: ${why}`;
  });
  return { total, working, problems, unchecked, tone, headline: parts.join(' '), details };
}

const RANK: Record<SourceVerdict, number> = {
  failing: 4,
  degraded: 3,
  quiet: 2,
  healthy: 1,
  unknown: 0,
};

/**
 * Veredicto de un servicio: el peor entre sus fuentes medidas. Una fuente opcional sin desplegar
 * (`unknown`) no tapa a una hermana medida; si ninguna está medida, el servicio es «Desconocida».
 * `null` si la API no informó ninguna fuente del servicio.
 */
export function serviceVerdict(
  verdicts: readonly SourceVerdictView[] | null | undefined,
  serviceId: string,
): SourceVerdictView | null {
  const ids = SERVICE_VERDICT_SOURCES[serviceId] ?? [];
  const items = (verdicts ?? []).filter((item) => ids.includes(item.id));
  if (items.length === 0) return null;
  return items.reduce((worst, item) => (RANK[item.verdict] > RANK[worst.verdict] ? item : worst));
}
