/**
 * Configuración de Bunny, el asistente de IA. Todo llega por variables de entorno; sin
 * `B89_BUNNY_ENABLED=true` el asistente no existe (el endpoint responde 404).
 *
 * Proveedores:
 * - `bedrock` (recomendado en AWS con IAM): Claude vía Amazon Bedrock con el rol IAM de la función;
 *   los datos no salen de la cuenta/región (decisión N1) y no hay clave que guardar.
 * - `anthropic`: Messages API directa de Anthropic con `B89_BUNNY_API_KEY` (modelo por defecto
 *   `claude-sonnet-5-5`). Exige salida a Internet y que Legal acepte el envío de datos del SOC a un
 *   tercero. Es el proveedor del nodo AWS PowerUser, que no tiene IAM para Bedrock.
 *
 * Las mismas reglas se validan al arrancar en `platform/configuration` (assistant.schema.ts).
 */

export const BUNNY_PROVIDERS = ['bedrock', 'anthropic'] as const;
export type BunnyProvider = (typeof BUNNY_PROVIDERS)[number];
export const BUNNY_EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;
export type BunnyEffort = (typeof BUNNY_EFFORTS)[number];

/** Modelo por defecto en Bedrock (sin cambios). */
export const DEFAULT_BUNNY_MODEL = 'claude-opus-5-5';
/** Modelo por defecto con la API directa de Anthropic. */
export const DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-5-5';
/** Tiempo máximo por intento HTTP hacia el proveedor (`B89_BUNNY_TIMEOUT_MS`). */
export const DEFAULT_BUNNY_TIMEOUT_MS = 20_000;

export type AssistantConfig =
  | { readonly enabled: false }
  | {
      readonly enabled: true;
      readonly provider: BunnyProvider;
      /** ID del modelo tal como lo espera el proveedor (en Bedrock lleva el prefijo `anthropic.`). */
      readonly model: string;
      readonly effort: BunnyEffort;
      readonly redactPii: boolean;
      readonly apiKey?: string;
      readonly awsRegion?: string;
      /** Tiempo máximo por intento HTTP (ms); el SDK reintenta con backoff. */
      readonly timeoutMs: number;
      /** Peticiones por persona en la ventana de límite de tasa. */
      readonly rateLimit: { readonly max: number; readonly windowMs: number };
    };

export class AssistantConfigError extends Error {
  public constructor(public readonly variable: string) {
    super(`Configuración de Bunny no válida: ${variable}`);
    this.name = 'AssistantConfigError';
  }
}

type Environment = Readonly<Record<string, string | undefined>>;

function flag(value: string | undefined, fallback: boolean, name: string): boolean {
  if (value === undefined || value === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new AssistantConfigError(name);
}

export function loadAssistantConfig(environment: Environment): AssistantConfig {
  if (!flag(environment['B89_BUNNY_ENABLED'], false, 'B89_BUNNY_ENABLED')) {
    return { enabled: false };
  }
  const provider = (environment['B89_BUNNY_PROVIDER'] || 'bedrock') as BunnyProvider;
  if (!BUNNY_PROVIDERS.includes(provider)) throw new AssistantConfigError('B89_BUNNY_PROVIDER');
  const effort = (environment['B89_BUNNY_EFFORT'] || 'medium') as BunnyEffort;
  if (!BUNNY_EFFORTS.includes(effort)) throw new AssistantConfigError('B89_BUNNY_EFFORT');
  let model =
    environment['B89_BUNNY_MODEL'] ||
    (provider === 'anthropic' ? DEFAULT_ANTHROPIC_MODEL : DEFAULT_BUNNY_MODEL);
  if (!/^[A-Za-z0-9._:-]{3,100}$/u.test(model)) throw new AssistantConfigError('B89_BUNNY_MODEL');
  if (provider === 'bedrock' && !model.startsWith('anthropic.')) model = `anthropic.${model}`;
  const apiKey = environment['B89_BUNNY_API_KEY'];
  if (provider === 'anthropic' && !apiKey) throw new AssistantConfigError('B89_BUNNY_API_KEY');
  const awsRegion = environment['B89_AWS_REGION'] ?? environment['AWS_REGION'];
  if (provider === 'bedrock' && !awsRegion) throw new AssistantConfigError('AWS_REGION');
  const max = Number(environment['B89_BUNNY_RATE_LIMIT'] || '20');
  if (!Number.isInteger(max) || max < 1 || max > 600) {
    throw new AssistantConfigError('B89_BUNNY_RATE_LIMIT');
  }
  const timeoutRaw = environment['B89_BUNNY_TIMEOUT_MS'];
  const timeoutMs = timeoutRaw ? Number(timeoutRaw) : DEFAULT_BUNNY_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
    throw new AssistantConfigError('B89_BUNNY_TIMEOUT_MS');
  }
  return {
    enabled: true,
    provider,
    model,
    effort,
    redactPii: flag(environment['B89_BUNNY_REDACT_PII'], true, 'B89_BUNNY_REDACT_PII'),
    ...(apiKey ? { apiKey } : {}),
    ...(awsRegion ? { awsRegion } : {}),
    timeoutMs,
    rateLimit: { max, windowMs: 10 * 60_000 },
  };
}

/** Historial de conversaciones: activo por defecto, con retención en días (1–365). */
export interface AssistantHistoryConfig {
  readonly enabled: boolean;
  readonly retentionDays: number;
}

export const DEFAULT_BUNNY_RETENTION_DAYS = 90;

/**
 * `B89_BUNNY_HISTORY_ENABLED` (defecto `true`) y `B89_BUNNY_RETENTION_DAYS` (defecto 90). Se
 * validan aunque el historial esté apagado: un valor inválido falla al arrancar, no al usarse.
 */
export function loadAssistantHistoryConfig(environment: Environment): AssistantHistoryConfig {
  const enabled = flag(environment['B89_BUNNY_HISTORY_ENABLED'], true, 'B89_BUNNY_HISTORY_ENABLED');
  const raw = environment['B89_BUNNY_RETENTION_DAYS'];
  const retentionDays =
    raw === undefined || raw === ''
      ? DEFAULT_BUNNY_RETENTION_DAYS
      : /^\d{1,3}$/u.test(raw)
        ? Number(raw)
        : Number.NaN;
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 365) {
    throw new AssistantConfigError('B89_BUNNY_RETENTION_DAYS');
  }
  return { enabled, retentionDays };
}
