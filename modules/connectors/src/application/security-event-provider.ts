export type JsonValue = string | number | boolean | null | readonly JsonValue[] | JsonObject;
export type JsonObject = { readonly [key: string]: JsonValue };

export interface SourceCapabilities {
  readonly providerType: string;
  readonly providerVersion?: string;
  readonly datasets: readonly string[];
  readonly paginationModes: readonly string[];
  readonly supportsRawRecords: boolean;
  readonly supportsReplay: boolean;
  readonly supportsHealth: boolean;
  readonly maxPageSize: number;
  readonly ordering: { readonly primaryField: string; readonly tieBreaker: string };
}

/**
 * Filtros neutrales del explorador de eventos (Sprint 5 · fase 1), en el vocabulario del
 * contrato `SecurityEvent`. Cada proveedor los compila a su consulta; el llamador nunca envía
 * lenguaje de consulta del proveedor.
 */
export interface EventFilters {
  readonly severity?: readonly string[];
  readonly category?: readonly string[];
  readonly outcome?: string;
  /** Entidades para consultas del analista; el proveedor valida y acota el filtro. */
  readonly entities?: readonly EventEntityFilter[];
}

export interface EventEntityFilter {
  readonly kind: 'user' | 'ip';
  readonly value: string;
}

export const EVENT_ENTITY_FILTER_LIMITS = Object.freeze({ maxEntities: 10, minChars: 3, maxChars: 256 });

export interface EventQuery {
  readonly filters?: EventFilters;
  /**
   * Orden por hora del evento. `asc` (por defecto) sirve a la ingesta, que avanza una marca de
   * agua; `desc` sirve al explorador, que muestra primero lo más reciente.
   */
  readonly order?: 'asc' | 'desc';
  readonly sourceId: string;
  readonly dataset: string;
  readonly from: string;
  readonly to: string;
  readonly pageSize: number;
  readonly cursor?: string;
  readonly signal?: AbortSignal;
}

/**
 * Actividad por *stream* de la fuente (p. ej. cada suscripción de un servicio SaaS) en una
 * ventana: cuántos eventos llegaron y cuándo fue el último. Es una medición informativa para la
 * salud por fuente; no prueba que la fuente esté sana.
 */
export interface ActivityQuery {
  readonly sourceId: string;
  readonly dataset: string;
  readonly from: string;
  readonly to: string;
  readonly signal?: AbortSignal;
}

export interface StreamActivity {
  readonly stream: string;
  readonly count: number;
  readonly lastEventAt: string | null;
}

/**
 * Señales de salud por fuente (docs/20 «Salud por fuente»). El llamador elige cada fuente con un
 * selector de una allowlist; el proveedor lo compila a su consulta (nunca recibe DSL).
 */
export type SourceDataSelector =
  | { readonly kind: 'rule_group'; readonly value: string }
  | {
      readonly kind: 'field';
      readonly field: 'office365.subscription' | 'b89.source';
      readonly values: readonly string[];
    }
  | { readonly kind: 'agents' };

export interface SourceSignalSpec {
  /** Id B89 de la fuente. */
  readonly id: string;
  /** `source_id` de los latidos de su collector (vacío: la fuente no tiene latido). */
  readonly heartbeatIds: readonly string[];
  readonly data: SourceDataSelector;
  /** Reglas del canario sintético de la fuente (si tiene). */
  readonly canaryRuleIds: readonly string[];
}

export interface SourceSignalsQuery {
  readonly sourceId: string;
  readonly dataset: string;
  /** ISO 8601: fin de todas las ventanas. */
  readonly now: string;
  readonly sources: readonly SourceSignalSpec[];
  readonly heartbeatLookbackMs: number;
  /** Latidos recientes por collector (1–10). */
  readonly heartbeatSamples: number;
  readonly volumeWindowMs: number;
  /** Semanas de línea base a la misma hora de la semana (1–4). */
  readonly baselineWeeks: number;
  readonly signal?: AbortSignal;
}

export interface HeartbeatSample {
  /** Hora del documento indexado (la del análisis en el manager). */
  readonly indexedAt: string;
  readonly sourceId: string;
  readonly finishedAt: string | null;
  readonly outcome: string | null;
  readonly auth: string | null;
  readonly httpStatusClass: string | null;
  readonly itemsFetched: number | null;
  readonly cursorAdvanced: boolean | null;
  readonly cursorPosition: string | null;
  readonly providerLagSeconds: number | null;
  readonly errorCode: string | null;
  readonly collectorVersion: string | null;
  /** Cobertura por tipo de contenido (latido de M365): habilitado y último blob. */
  readonly content: Readonly<
    Record<string, { readonly enabled: boolean | null; readonly lastBlobAt: string | null }>
  > | null;
}

export interface SourceSignalReading {
  readonly id: string;
  /** Latidos más recientes primero, de todos los `heartbeatIds` de la fuente. */
  readonly heartbeats: readonly HeartbeatSample[];
  readonly lastAuthOkAt: string | null;
  readonly lastEventAt: string | null;
  /** Eventos de datos en la ventana actual. */
  readonly currentCount: number;
  /**
   * Misma ventana 1..N semanas atrás. `null`: el Indexer no tiene ningún documento en esa
   * ventana (retención o despliegue posterior): no cuenta como cero.
   */
  readonly baselineCounts: readonly (number | null)[];
  readonly canaryAt: string | null;
}

export interface SourceSignalsReport {
  readonly measuredAt: string;
  readonly sources: readonly SourceSignalReading[];
}

export interface ProviderRecord {
  readonly sourceRecordId: string;
  readonly dataset: string;
  readonly occurredAt?: string;
  readonly collectedAt: string;
  readonly raw: JsonObject;
  readonly metadata: Readonly<Record<string, JsonValue>>;
}

export interface EventPage {
  readonly items: readonly ProviderRecord[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
  readonly readAt: string;
}

export type ProviderErrorCode =
  | 'PROVIDER_CONFIGURATION_INVALID'
  | 'PROVIDER_GATEWAY_UNAVAILABLE'
  | 'PROVIDER_UPSTREAM_UNAVAILABLE'
  | 'PROVIDER_UPSTREAM_SERVER_ERROR'
  | 'PROVIDER_UNAVAILABLE'
  | 'PROVIDER_AUTHENTICATION_FAILED'
  | 'PROVIDER_AUTHORIZATION_DENIED'
  | 'PROVIDER_TLS_VALIDATION_FAILED'
  | 'PROVIDER_TIMEOUT'
  | 'PROVIDER_RATE_LIMITED'
  | 'PROVIDER_QUERY_REJECTED'
  | 'PROVIDER_RESPONSE_INVALID'
  | 'PROVIDER_CURSOR_INVALID'
  | 'PROVIDER_CURSOR_EXPIRED'
  | 'PROVIDER_CURSOR_INCOMPATIBLE'
  | 'PROVIDER_VERSION_UNSUPPORTED';

export class SecurityEventProviderError extends Error {
  public constructor(
    public readonly code: ProviderErrorCode,
    public readonly operation: 'health' | 'readPage',
    public readonly retryable: boolean,
    message = code,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = 'SecurityEventProviderError';
  }
}

export interface ProviderComponentHealth {
  readonly name: string;
  readonly status: 'healthy' | 'degraded' | 'unhealthy';
  readonly code: string;
  readonly latencyMs?: number;
  readonly message: string;
}

export interface ProviderHealth {
  readonly status: 'healthy' | 'degraded' | 'unhealthy';
  readonly checkedAt: string;
  readonly components: readonly ProviderComponentHealth[];
}

export interface SecurityEventProvider {
  capabilities(): Promise<SourceCapabilities>;
  health(): Promise<ProviderHealth>;
  readPage(query: EventQuery): Promise<EventPage>;
  /** Actividad por stream (opcional: no todo proveedor la ofrece). */
  readActivity?(query: ActivityQuery): Promise<readonly StreamActivity[]>;
  /** Señales de salud por fuente en una consulta acotada (opcional). */
  readSourceSignals?(query: SourceSignalsQuery): Promise<SourceSignalsReport>;
}
