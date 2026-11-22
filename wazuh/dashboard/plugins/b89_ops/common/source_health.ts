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

export const SOURCE_VERDICT_LABEL: Record<SourceVerdict, string> = {
  healthy: 'Sana',
  quiet: 'Silenciosa',
  degraded: 'Degradada',
  failing: 'Fallando',
  unknown: 'Desconocida',
};

/** Silenciosa ≠ fallando: tono informativo, no de alerta. */
export const SOURCE_VERDICT_TONE: Record<SourceVerdict, HealthTone> = {
  healthy: 'ok',
  quiet: 'info',
  degraded: 'warn',
  failing: 'fail',
  unknown: 'neutral',
};

export const SOURCE_VERDICT_REASON_LABEL: Record<string, string> = {
  HEARTBEAT_MISSING: 'El colector dejó de latir (sin latido en más de 2 ciclos)',
  AUTH_DENIED: 'Credencial o permiso rechazado por el proveedor',
  AUTH_EXPIRED: 'Credencial vencida',
  CONSECUTIVE_FAILURES: 'Varias corridas seguidas del colector fallaron',
  CONTENT_DISABLED: 'Suscripción del proveedor deshabilitada',
  INGESTION_FAILED: 'La lectura de Wazuh hacia B89 está caída',
  RUN_FAILED: 'La última corrida del colector falló',
  RUN_PARTIAL: 'La última corrida quedó a medias (atraso pendiente)',
  PROVIDER_LAG: 'El proveedor entrega con atraso',
  INGEST_LAG: 'Retraso alto del colector al indexador',
  VOLUME_DROP: 'Sin eventos esperados: el volumen cayó frente a semanas anteriores',
  CANARY_STALE: 'El canario sintético no llegó en las últimas 26 h',
  INGESTION_DEGRADED: 'La lectura de Wazuh hacia B89 tiene fallos',
  HEARTBEAT_OK: 'Colector latiendo y autenticado',
  CANARY_OK: 'Canario sintético recibido',
  EVENTS_RECENT: 'Eventos recientes',
  NO_RECENT_EVENTS: 'Sin eventos nuevos; colector OK',
  INGESTION_OK: 'Lectura correcta reciente',
  HEARTBEAT_NEVER_SEEN: 'El colector nunca reportó un latido (no desplegado o sin actualizar)',
  EVENTS_WITHOUT_HEARTBEAT: 'Llegan eventos, pero falta el latido del colector',
  CANARY_NEVER_SEEN: 'Sin canario sintético registrado',
  SIGNALS_NOT_CONFIGURED: 'Este despliegue no mide la salud por fuente',
  SIGNALS_UNAVAILABLE: 'No se pudo leer el indexador para medir la salud',
  INGESTION_DISABLED: 'Ingesta desactivada por configuración',
  INGESTION_NO_DATA: 'Todavía no hay lecturas registradas',
};

/** Problemas operativos `SOURCE_*` (sección `sources` de `/api/operations/health`). */
export const SOURCE_ISSUE_LABEL: Record<string, string> = {
  SOURCE_AUTH_FAILED: 'Una fuente tiene la credencial vencida o rechazada',
  SOURCE_COLLECTOR_SILENT: 'Un colector dejó de latir',
  SOURCE_RUNS_FAILING: 'Una fuente falla en varias corridas seguidas',
  SOURCE_SUBSCRIPTION_DISABLED: 'Una suscripción del proveedor está deshabilitada',
  SOURCE_VOLUME_DROP: 'Una fuente no trae los eventos esperados',
  SOURCE_LAGGING: 'Una fuente llega con atraso',
  SOURCE_CANARY_STALE: 'Un canario sintético no llegó',
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
