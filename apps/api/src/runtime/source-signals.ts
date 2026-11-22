/**
 * Salud real por fuente a partir de señales independientes (docs/20 «Salud por fuente»).
 *
 * El «tiempo desde el último log» no distingue una fuente callada de una rota. Este módulo junta,
 * por fuente, cinco señales leídas del Indexer con una consulta acotada del lector de solo
 * lectura (`readSourceSignals`):
 *
 * 1. Latido del collector (`b89.event_type: source_heartbeat`, reglas 101980/101981): llega por el
 *    mismo camino que los datos, así que prueba collector → manager → indexer aunque no haya
 *    eventos nuevos. Trae resultado de la corrida, autenticación, clase HTTP, ítems, cursor,
 *    atraso del proveedor y código de error saneado.
 * 2. Autenticación activa: el resultado de la sonda de solo lectura de cada corrida (`auth`).
 * 3. Volumen esperado: eventos en la ventana actual contra la mediana de la misma ventana de las
 *    semanas anteriores (ventanas sin ningún documento en el índice no cuentan como cero).
 * 4. Retraso de ingesta: hora de indexado del latido contra su `finished_at`. El Indexer no
 *    guarda una hora de ingesta propia: se mide collector → análisis del manager, no más.
 * 5. Canario sintético diario (incluido el del agente Wazuh por journald, `b89-canary`).
 *
 * El veredicto es `healthy | quiet | degraded | failing | unknown` con códigos de motivo. Un
 * `unknown` nunca se presenta como sano y una suposición nunca como medida.
 */

import type {
  HeartbeatSample,
  SourceDataSelector,
  SourceSignalReading,
  SourceSignalsQuery,
  SourceSignalsReport,
} from '@b89/connectors';
import type { SourceHealthEvaluation } from '@b89/soc';

export const SOURCE_VERDICTS = ['healthy', 'quiet', 'degraded', 'failing', 'unknown'] as const;
export type SourceVerdict = (typeof SOURCE_VERDICTS)[number];

/** Motivos de un veredicto (rótulos en español en `b89_ops/common/source_health.ts`). */
export const SOURCE_REASONS = [
  // failing
  'HEARTBEAT_MISSING',
  'AUTH_DENIED',
  'AUTH_EXPIRED',
  'CONSECUTIVE_FAILURES',
  'CONTENT_DISABLED',
  'INGESTION_FAILED',
  // degraded
  'RUN_FAILED',
  'RUN_PARTIAL',
  'PROVIDER_LAG',
  'INGEST_LAG',
  'VOLUME_DROP',
  'CANARY_STALE',
  'INGESTION_DEGRADED',
  // healthy / quiet
  'HEARTBEAT_OK',
  'CANARY_OK',
  'EVENTS_RECENT',
  'NO_RECENT_EVENTS',
  'INGESTION_OK',
  // unknown
  'HEARTBEAT_NEVER_SEEN',
  'EVENTS_WITHOUT_HEARTBEAT',
  'CANARY_NEVER_SEEN',
  'SIGNALS_NOT_CONFIGURED',
  'SIGNALS_UNAVAILABLE',
  'INGESTION_DISABLED',
  'INGESTION_NO_DATA',
] as const;
export type SourceReason = (typeof SOURCE_REASONS)[number];

export interface SourceDefinition {
  readonly id: string;
  readonly label: string;
  /** Proveedor del catálogo de servicios (tarjetas del Resumen) y de `providerOf` del analista. */
  readonly provider: 'm365' | 'sharepoint' | 'bitdefender' | 'snyk' | 'cloudflare' | 'aws' | 'wazuh';
  readonly heartbeatIds: readonly string[];
  /** Cadencia esperada del latido (timer del collector o intervalo del receptor). */
  readonly scheduleMs: number;
  readonly data: SourceDataSelector;
  readonly canaryRuleIds: readonly string[];
  /** Sin eventos más allá de esto con el latido sano ⇒ `quiet` (no es una falla). */
  readonly quietAfterMs: number;
  /** Claves de cobertura del latido de M365 (`content.<clave>`) que esta fuente exige. */
  readonly contentKeys?: readonly string[];
  /** Umbral propio de atraso del proveedor (s); si falta, el del modelo. */
  readonly providerLagDegradedSeconds?: number;
}

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/**
 * Modelo versionado: umbrales y catálogo de fuentes en un solo objeto. Cambiar un umbral exige
 * subir `version` (queda en cada respuesta y en docs/20).
 */
export const SOURCE_HEALTH_MODEL = Object.freeze({
  version: 'b89-source-health-2026-11-18.1',
  /** Latido ausente más allá de `missedSchedules × cadencia + graceMs` ⇒ `failing`. */
  missedSchedules: 2,
  graceMs: 5 * MIN,
  /** Corridas fallidas seguidas (latidos más recientes) para `failing`. */
  failAfterConsecutive: 3,
  heartbeatSamples: 6,
  heartbeatLookbackMs: 7 * DAY,
  /** Atraso informado por el proveedor (cursor/watermark o último blob). */
  providerLagDegradedSeconds: 2 * 3_600,
  /** Retraso collector → análisis del manager (máximo de las muestras). */
  ingestLagDegradedSeconds: 15 * 60,
  volume: {
    windowMs: 3 * HOUR,
    baselineWeeks: 4,
    /** Semanas con dato necesarias para opinar. */
    minWeeks: 2,
    /** Mediana mínima: por debajo, la fuente es de bajo volumen y no se opina. */
    minExpectedEvents: 20,
    /** Caída: actual < mediana × `dropRatio`. */
    dropRatio: 0.2,
  },
  /** Canario diario: más viejo que esto ⇒ `degraded`. */
  canaryStaleMs: 26 * HOUR,
  /** Caché de la lectura del Indexer (las tres vistas comparten una medición). */
  cacheTtlMs: 5 * MIN,
  /** Una medición vieja sirve, marcada, hasta este límite si el Indexer no responde. */
  staleSnapshotMs: 30 * MIN,
  sources: Object.freeze<readonly SourceDefinition[]>([
    {
      id: 'm365',
      label: 'Microsoft 365 (Exchange, SharePoint, General)',
      provider: 'm365',
      heartbeatIds: ['m365'],
      scheduleMs: 5 * MIN,
      data: {
        kind: 'field',
        field: 'office365.subscription',
        values: ['Audit.Exchange', 'Audit.SharePoint', 'Audit.General'],
      },
      canaryRuleIds: [],
      quietAfterMs: DAY,
      contentKeys: ['exchange', 'sharepoint', 'general'],
      // Microsoft publica los blobs con horas de demora: el umbral es mayor.
      providerLagDegradedSeconds: 6 * 3_600,
    },
    {
      id: 'entra',
      label: 'Entra ID (auditoría e inicios de sesión)',
      provider: 'm365',
      heartbeatIds: ['m365'],
      scheduleMs: 5 * MIN,
      data: { kind: 'field', field: 'office365.subscription', values: ['Audit.AzureActiveDirectory'] },
      canaryRuleIds: [],
      quietAfterMs: DAY,
      contentKeys: ['aad'],
      providerLagDegradedSeconds: 6 * 3_600,
    },
    {
      id: 'sharepoint-posture',
      label: 'SharePoint · postura',
      provider: 'sharepoint',
      heartbeatIds: ['sharepoint-posture'],
      scheduleMs: 60 * MIN,
      data: { kind: 'field', field: 'b89.source', values: ['sharepoint_posture'] },
      canaryRuleIds: [],
      quietAfterMs: 26 * HOUR,
    },
    {
      id: 'sharepoint-audit',
      label: 'SharePoint · auditoría (Purview)',
      provider: 'sharepoint',
      heartbeatIds: ['sharepoint-audit'],
      scheduleMs: 5 * MIN,
      data: { kind: 'field', field: 'b89.source', values: ['sharepoint_audit'] },
      canaryRuleIds: [],
      quietAfterMs: DAY,
    },
    {
      id: 'bitdefender',
      label: 'Bitdefender GravityZone',
      provider: 'bitdefender',
      heartbeatIds: ['bitdefender'],
      scheduleMs: 10 * MIN,
      data: { kind: 'rule_group', value: 'bitdefender' },
      canaryRuleIds: ['101830'],
      quietAfterMs: 26 * HOUR,
    },
    {
      id: 'snyk',
      label: 'Snyk',
      provider: 'snyk',
      heartbeatIds: ['snyk'],
      scheduleMs: 15 * MIN,
      data: { kind: 'rule_group', value: 'snyk' },
      canaryRuleIds: ['101831'],
      // Un evento por cambio de issue: días sin cambios son normales.
      quietAfterMs: 7 * DAY,
    },
    {
      id: 'cloudflare',
      label: 'Cloudflare',
      provider: 'cloudflare',
      heartbeatIds: ['cloudflare'],
      scheduleMs: 5 * MIN,
      data: { kind: 'rule_group', value: 'cloudflare' },
      canaryRuleIds: ['101832'],
      quietAfterMs: 3 * DAY,
    },
    {
      id: 'aws',
      label: 'AWS (EventBridge → SNS)',
      provider: 'aws',
      heartbeatIds: ['aws'],
      scheduleMs: 5 * MIN,
      data: { kind: 'rule_group', value: 'aws' },
      canaryRuleIds: ['101833'],
      quietAfterMs: 3 * DAY,
    },
    {
      id: 'wazuh-agents',
      label: 'Agentes Wazuh',
      provider: 'wazuh',
      heartbeatIds: [],
      scheduleMs: DAY,
      data: { kind: 'agents' },
      canaryRuleIds: ['101835'],
      quietAfterMs: DAY,
    },
  ]),
});

export type SourceHealthModel = typeof SOURCE_HEALTH_MODEL;

export interface VolumeBaseline {
  readonly windowHours: number;
  readonly current: number;
  /** Mediana de las semanas con dato; `null` si no alcanzan `minWeeks`. */
  readonly expected: number | null;
  readonly weeksUsed: number;
  readonly drop: boolean;
}

export interface IngestLag {
  readonly samples: number;
  readonly p50Seconds: number | null;
  readonly maxSeconds: number | null;
  readonly clockSkewSamples: number;
}

export interface SourceVerdictView {
  readonly id: string;
  readonly label: string;
  readonly provider: SourceDefinition['provider'];
  readonly verdict: SourceVerdict;
  readonly reasons: readonly SourceReason[];
  /** Señales: `null` = sin dato (nunca un cero inventado). */
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
  readonly ingestLag: IngestLag | null;
  readonly volume: VolumeBaseline | null;
  readonly expectedHeartbeatMs: number | null;
  readonly measuredAt: string | null;
}

export function median(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle]! : (sorted[middle - 1]! + sorted[middle]!) / 2;
}

/** Línea base por hora de la semana: semanas sin dato (`null`) se excluyen, no son cero. */
export function volumeBaseline(
  current: number,
  weeks: readonly (number | null)[],
  model: SourceHealthModel = SOURCE_HEALTH_MODEL,
): VolumeBaseline {
  const known = weeks.filter((value): value is number => value !== null);
  const expected = known.length >= model.volume.minWeeks ? median(known) : null;
  return {
    windowHours: model.volume.windowMs / HOUR,
    current,
    expected,
    weeksUsed: known.length,
    drop:
      expected !== null &&
      expected >= model.volume.minExpectedEvents &&
      current < expected * model.volume.dropRatio,
  };
}

/** Collector → análisis del manager por latido; los negativos son desfase de reloj. */
export function ingestLag(heartbeats: readonly HeartbeatSample[]): IngestLag | null {
  if (heartbeats.length === 0) return null;
  const lags: number[] = [];
  let clockSkewSamples = 0;
  for (const beat of heartbeats) {
    if (!beat.finishedAt) continue;
    const lag = (Date.parse(beat.indexedAt) - Date.parse(beat.finishedAt)) / 1_000;
    if (!Number.isFinite(lag)) continue;
    if (lag < 0) clockSkewSamples += 1;
    else lags.push(lag);
  }
  lags.sort((left, right) => left - right);
  return {
    samples: lags.length,
    p50Seconds: median(lags),
    maxSeconds: lags.length > 0 ? lags[lags.length - 1]! : null,
    clockSkewSamples,
  };
}

function consecutiveFailures(heartbeats: readonly HeartbeatSample[]): number {
  let failures = 0;
  for (const beat of heartbeats) {
    if (beat.outcome !== 'failed') break;
    failures += 1;
  }
  return failures;
}

function contentFor(definition: SourceDefinition, beat: HeartbeatSample | undefined) {
  if (!definition.contentKeys || !beat?.content) return null;
  const entries = definition.contentKeys.map((key) => beat.content?.[key] ?? null);
  return {
    disabled: entries.some((entry) => entry?.enabled === false),
    lastBlobAt:
      entries
        .map((entry) => entry?.lastBlobAt ?? null)
        .filter((value): value is string => value !== null)
        .sort()
        .pop() ?? null,
  };
}

function ageMs(iso: string | null, now: Date): number {
  return iso ? now.getTime() - Date.parse(iso) : Number.POSITIVE_INFINITY;
}

/** Veredicto puro de una fuente. Misma entrada ⇒ misma salida. */
export function evaluateSourceVerdict(
  definition: SourceDefinition,
  reading: SourceSignalReading,
  now: Date,
  measuredAt: string | null,
  model: SourceHealthModel = SOURCE_HEALTH_MODEL,
): SourceVerdictView {
  const beats = reading.heartbeats;
  const latest = beats[0];
  const failures = consecutiveFailures(beats);
  const content = contentFor(definition, latest);
  // M365: el último blob publicado es la señal de datos del proveedor.
  // Sin blob en la ventana del sondeo, el atraso de esos tipos no está medido (no se toma el de
  // otros tipos de contenido).
  const providerLag = content
    ? content.lastBlobAt && latest
      ? Math.max(
          0,
          Math.round(
            (Date.parse(latest.finishedAt ?? latest.indexedAt) - Date.parse(content.lastBlobAt)) /
              1_000,
          ),
        )
      : null
    : (latest?.providerLagSeconds ?? null);
  const lag = ingestLag(beats);
  const volume = volumeBaseline(reading.currentCount, reading.baselineCounts, model);
  const lastSuccessfulRunAt =
    beats.find((beat) => beat.outcome === 'ok' || beat.outcome === 'partial')?.indexedAt ?? null;
  const expectedHeartbeatMs = definition.heartbeatIds.length > 0 ? definition.scheduleMs : null;
  const eventsRecent =
    ageMs(reading.lastEventAt, now) <= definition.quietAfterMs ||
    ageMs(content?.lastBlobAt ?? null, now) <= definition.quietAfterMs;

  const failing: SourceReason[] = [];
  const degraded: SourceReason[] = [];
  let verdict: SourceVerdict;
  let reasons: SourceReason[];

  const canaryAge = ageMs(reading.canaryAt, now);
  if (definition.canaryRuleIds.length > 0 && reading.canaryAt && canaryAge > model.canaryStaleMs) {
    degraded.push('CANARY_STALE');
  }

  if (definition.heartbeatIds.length === 0) {
    // Sin collector propio (agentes Wazuh): el canario de extremo a extremo es el latido.
    if (!reading.canaryAt) {
      verdict = 'unknown';
      reasons = ['CANARY_NEVER_SEEN', ...(eventsRecent ? ['EVENTS_RECENT' as const] : [])];
    } else if (degraded.length > 0) {
      verdict = 'degraded';
      reasons = degraded;
    } else {
      verdict = eventsRecent ? 'healthy' : 'quiet';
      reasons = ['CANARY_OK', eventsRecent ? 'EVENTS_RECENT' : 'NO_RECENT_EVENTS'];
    }
  } else if (!latest) {
    verdict = 'unknown';
    reasons = reading.lastEventAt ? ['HEARTBEAT_NEVER_SEEN', 'EVENTS_WITHOUT_HEARTBEAT'] : ['HEARTBEAT_NEVER_SEEN'];
  } else {
    const missAfter = model.missedSchedules * definition.scheduleMs + model.graceMs;
    if (ageMs(latest.indexedAt, now) > missAfter) failing.push('HEARTBEAT_MISSING');
    if (latest.auth === 'expired') failing.push('AUTH_EXPIRED');
    else if (latest.auth === 'denied') failing.push('AUTH_DENIED');
    if (failures >= model.failAfterConsecutive) failing.push('CONSECUTIVE_FAILURES');
    if (content?.disabled) failing.push('CONTENT_DISABLED');
    if (failures > 0 && failures < model.failAfterConsecutive && latest.auth !== 'denied' && latest.auth !== 'expired')
      degraded.push('RUN_FAILED');
    if (latest.outcome === 'partial') degraded.push('RUN_PARTIAL');
    if (
      providerLag !== null &&
      providerLag > (definition.providerLagDegradedSeconds ?? model.providerLagDegradedSeconds)
    )
      degraded.push('PROVIDER_LAG');
    if (lag?.maxSeconds != null && lag.maxSeconds > model.ingestLagDegradedSeconds) degraded.push('INGEST_LAG');
    if (volume.drop) degraded.push('VOLUME_DROP');
    if (failing.length > 0) {
      verdict = 'failing';
      reasons = failing;
    } else if (degraded.length > 0) {
      verdict = 'degraded';
      reasons = degraded;
    } else {
      verdict = eventsRecent ? 'healthy' : 'quiet';
      reasons = ['HEARTBEAT_OK', eventsRecent ? 'EVENTS_RECENT' : 'NO_RECENT_EVENTS'];
    }
  }

  return {
    id: definition.id,
    label: definition.label,
    provider: definition.provider,
    verdict,
    reasons,
    lastHeartbeatAt: latest?.indexedAt ?? null,
    lastSuccessfulRunAt,
    lastAuthOkAt: reading.lastAuthOkAt,
    lastEventAt: reading.lastEventAt,
    canaryAt: reading.canaryAt,
    heartbeat: latest
      ? {
          outcome: latest.outcome,
          auth: latest.auth,
          httpStatusClass: latest.httpStatusClass,
          errorCode: latest.errorCode,
          itemsFetched: latest.itemsFetched,
          cursorAdvanced: latest.cursorAdvanced,
          cursorPosition: latest.cursorPosition,
          consecutiveFailures: failures,
          collectorVersion: latest.collectorVersion,
        }
      : null,
    providerLagSeconds: providerLag,
    ingestLag: lag,
    volume,
    expectedHeartbeatMs,
    measuredAt,
  };
}

/** Fuente sin medición posible (sin lector o con el Indexer caído): `unknown` declarado. */
export function unmeasuredVerdict(
  definition: SourceDefinition,
  reason: 'SIGNALS_NOT_CONFIGURED' | 'SIGNALS_UNAVAILABLE',
): SourceVerdictView {
  return {
    id: definition.id,
    label: definition.label,
    provider: definition.provider,
    verdict: 'unknown',
    reasons: [reason],
    lastHeartbeatAt: null,
    lastSuccessfulRunAt: null,
    lastAuthOkAt: null,
    lastEventAt: null,
    canaryAt: null,
    heartbeat: null,
    providerLagSeconds: null,
    ingestLag: null,
    volume: null,
    expectedHeartbeatMs: definition.heartbeatIds.length > 0 ? definition.scheduleMs : null,
    measuredAt: null,
  };
}

/** La ingesta Wazuh → B89 (evaluación por sondeos existente) en el mismo vocabulario. */
export function ingestionVerdict(
  evaluation: SourceHealthEvaluation,
  label: string,
): SourceVerdictView {
  const map: Record<string, [SourceVerdict, SourceReason]> = {
    healthy: ['healthy', 'INGESTION_OK'],
    degraded: ['degraded', 'INGESTION_DEGRADED'],
    failed: ['failing', 'INGESTION_FAILED'],
    disabled: ['unknown', 'INGESTION_DISABLED'],
    unknown: ['unknown', 'INGESTION_NO_DATA'],
  };
  const [verdict, reason] = map[evaluation.state] ?? ['unknown', 'INGESTION_NO_DATA'];
  return {
    id: 'wazuh-indexer',
    label,
    provider: 'wazuh',
    verdict,
    reasons: [reason],
    lastHeartbeatAt: evaluation.lastAttemptAt?.toISOString() ?? null,
    lastSuccessfulRunAt: evaluation.lastSuccessAt?.toISOString() ?? null,
    lastAuthOkAt: evaluation.lastSuccessAt?.toISOString() ?? null,
    lastEventAt: evaluation.lastEventAt?.toISOString() ?? null,
    canaryAt: null,
    heartbeat: null,
    providerLagSeconds: null,
    ingestLag: null,
    volume: null,
    expectedHeartbeatMs: null,
    measuredAt: null,
  };
}

/** Problemas operativos derivados de los veredictos (sin `unknown`: no es un problema medido). */
export function sourceIssues(verdicts: readonly SourceVerdictView[]): {
  readonly codes: readonly string[];
  readonly items: readonly { readonly code: string; readonly sourceId: string }[];
} {
  const items: { code: string; sourceId: string }[] = [];
  for (const item of verdicts) {
    const has = (reason: SourceReason) => item.reasons.includes(reason);
    if (has('AUTH_DENIED') || has('AUTH_EXPIRED')) items.push({ code: 'SOURCE_AUTH_FAILED', sourceId: item.id });
    if (has('HEARTBEAT_MISSING')) items.push({ code: 'SOURCE_COLLECTOR_SILENT', sourceId: item.id });
    if (has('CONSECUTIVE_FAILURES') || has('INGESTION_FAILED'))
      items.push({ code: 'SOURCE_RUNS_FAILING', sourceId: item.id });
    if (has('CONTENT_DISABLED')) items.push({ code: 'SOURCE_SUBSCRIPTION_DISABLED', sourceId: item.id });
    if (has('VOLUME_DROP')) items.push({ code: 'SOURCE_VOLUME_DROP', sourceId: item.id });
    if (has('INGEST_LAG') || has('PROVIDER_LAG')) items.push({ code: 'SOURCE_LAGGING', sourceId: item.id });
    if (has('CANARY_STALE')) items.push({ code: 'SOURCE_CANARY_STALE', sourceId: item.id });
  }
  return { codes: [...new Set(items.map((item) => item.code))], items };
}

export interface SourceSignalsSnapshot {
  readonly modelVersion: string;
  readonly measuredAt: string | null;
  /** `true` si se sirve una medición anterior porque la última lectura falló. */
  readonly stale: boolean;
  readonly status: 'measured' | 'not_configured' | 'unavailable';
  readonly verdicts: readonly SourceVerdictView[];
}

export type SourceSignalsReader = (query: SourceSignalsQuery) => Promise<SourceSignalsReport>;

/**
 * Lectura con caché: `/api/sources/health`, `/api/operations/health` y la evidencia del analista
 * comparten una medición por `cacheTtlMs`, y lecturas concurrentes comparten la consulta.
 */
export class SourceSignalsService {
  #last: { readonly at: number; readonly report: SourceSignalsReport } | null = null;
  #inFlight: Promise<SourceSignalsReport> | null = null;

  public constructor(
    private readonly options: {
      readonly read?: SourceSignalsReader;
      readonly sourceId: string;
      readonly dataset: string;
      readonly model?: SourceHealthModel;
      readonly timeoutMs?: number;
    },
  ) {}

  private get model(): SourceHealthModel {
    return this.options.model ?? SOURCE_HEALTH_MODEL;
  }

  public async snapshot(now: Date): Promise<SourceSignalsSnapshot> {
    const model = this.model;
    const read = this.options.read;
    if (!read) {
      return {
        modelVersion: model.version,
        measuredAt: null,
        stale: false,
        status: 'not_configured',
        verdicts: model.sources.map((source) => unmeasuredVerdict(source, 'SIGNALS_NOT_CONFIGURED')),
      };
    }
    let report: SourceSignalsReport | null = null;
    let stale = false;
    if (this.#last && now.getTime() - this.#last.at < model.cacheTtlMs) {
      report = this.#last.report;
    } else {
      try {
        report = await this.fetch(read, now);
        this.#last = { at: now.getTime(), report };
      } catch {
        if (this.#last && now.getTime() - this.#last.at < model.staleSnapshotMs) {
          report = this.#last.report;
          stale = true;
        }
      }
    }
    if (!report) {
      return {
        modelVersion: model.version,
        measuredAt: null,
        stale: false,
        status: 'unavailable',
        verdicts: model.sources.map((source) => unmeasuredVerdict(source, 'SIGNALS_UNAVAILABLE')),
      };
    }
    const byId = new Map(report.sources.map((reading) => [reading.id, reading]));
    return {
      modelVersion: model.version,
      measuredAt: report.measuredAt,
      stale,
      status: 'measured',
      verdicts: model.sources.map((source) => {
        const reading = byId.get(source.id);
        return reading
          ? evaluateSourceVerdict(source, reading, now, report!.measuredAt, model)
          : unmeasuredVerdict(source, 'SIGNALS_UNAVAILABLE');
      }),
    };
  }

  private fetch(read: SourceSignalsReader, now: Date): Promise<SourceSignalsReport> {
    if (this.#inFlight) return this.#inFlight;
    const model = this.model;
    const signal = AbortSignal.timeout(this.options.timeoutMs ?? 10_000);
    this.#inFlight = read({
      sourceId: this.options.sourceId,
      dataset: this.options.dataset,
      now: now.toISOString(),
      sources: model.sources.map((source) => ({
        id: source.id,
        heartbeatIds: source.heartbeatIds,
        data: source.data,
        canaryRuleIds: source.canaryRuleIds,
      })),
      heartbeatLookbackMs: model.heartbeatLookbackMs,
      heartbeatSamples: model.heartbeatSamples,
      volumeWindowMs: model.volume.windowMs,
      baselineWeeks: model.volume.baselineWeeks,
      signal,
    }).finally(() => {
      this.#inFlight = null;
    });
    return this.#inFlight;
  }
}

/** Estado heredado (`modules/soc`) para consumidores que solo conocen ese catálogo. */
export function legacyState(verdict: SourceVerdict): 'healthy' | 'degraded' | 'failed' | 'unknown' {
  return verdict === 'healthy' || verdict === 'quiet'
    ? 'healthy'
    : verdict === 'degraded'
      ? 'degraded'
      : verdict === 'failing'
        ? 'failed'
        : 'unknown';
}
