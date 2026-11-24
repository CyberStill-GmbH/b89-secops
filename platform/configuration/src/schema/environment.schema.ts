import { configurationError } from '../configuration.errors.js';
import type { EnvironmentInput } from '../configuration.types.js';
import { CONFIGURATION_LIMITS } from '../limits.js';
import type { ConfigurationProfile } from '../profiles/index.js';

export const KNOWN_B89_VARIABLES = new Set([
  'B89_PROFILE',
  'B89_PROCESS_ROLE',
  'B89_API_HOST',
  'B89_API_PORT',
  'B89_POSTGRES_HOST',
  'B89_POSTGRES_PORT',
  'B89_POSTGRES_DATABASE',
  'B89_POSTGRES_USERNAME',
  'B89_POSTGRES_PASSWORD_REF',
  'B89_POSTGRES_TLS',
  'B89_POSTGRES_CONNECTION_TIMEOUT',
  'B89_POSTGRES_STATEMENT_TIMEOUT',
  'B89_POSTGRES_POOL_MIN',
  'B89_POSTGRES_POOL_MAX',
  'B89_REDIS_HOST',
  'B89_REDIS_PORT',
  'B89_REDIS_USERNAME',
  'B89_REDIS_PASSWORD',
  'B89_REDIS_PASSWORD_REF',
  'B89_REDIS_DATABASE',
  'B89_REDIS_TLS',
  'B89_REDIS_CONNECTION_TIMEOUT',
  'B89_REDIS_COMMAND_TIMEOUT',
  'B89_REDIS_RETRY_LIMIT',
  'B89_MINIO_ENDPOINT',
  'B89_MINIO_PORT',
  'B89_MINIO_REGION',
  'B89_MINIO_RAW_BUCKET',
  'B89_MINIO_ACCESS_KEY_REF',
  'B89_MINIO_SECRET_KEY_REF',
  'B89_MINIO_TLS',
  'B89_MINIO_CONNECTION_TIMEOUT',
  'B89_MINIO_REQUEST_TIMEOUT',
  'B89_MINIO_RETRY_LIMIT',
  'B89_WAZUH_GATEWAY_BASE_URL',
  'B89_WAZUH_GATEWAY_ACCESS_TOKEN_REF',
  'B89_WAZUH_GATEWAY_ACCESS_TOKEN',
  'B89_WAZUH_PUSH_SECRET',
  'B89_WAZUH_GATEWAY_AUTH',
  'B89_WAZUH_REQUEST_TIMEOUT',
  'B89_WAZUH_RETRY_LIMIT',
  'B89_WAZUH_PAGE_SIZE',
  'B89_WAZUH_MAX_PAGE_SIZE',
  'B89_WAZUH_DATASET',
  'B89_WAZUH_CURSOR_SECRET_REF',
  'B89_WAZUH_CURSOR_TTL',
  'B89_WAZUH_MAX_RESPONSE_BYTES',
  'B89_CORRELATOR_SERVICE_TOKEN_REF',
  'B89_CORRELATOR_SERVICE_TOKEN',
  'B89_CORRELATOR_URL',
  'B89_CORRELATOR_READ_TOKEN_REF',
  'B89_CORRELATOR_READ_TOKEN',
  'B89_SECRET_PROVIDER_TYPE',
  'B89_SECRET_PROVIDER_TIMEOUT',
  'B89_SECRET_PROVIDER_ENDPOINT',
  'B89_SECRET_FINGERPRINT_KEY_REF',
  'B89_ACCESS_IDENTITY_MODE',
  'B89_ACCESS_ALLOWED_CIDRS',
  'B89_ACCESS_TRUSTED_PROXY_CIDRS',
  'B89_ENTRA_TENANT_ID',
  'B89_ENTRA_CLIENT_ID',
  'B89_ENTRA_CLIENT_SECRET',
  'B89_ENTRA_CLIENT_SECRET_REF',
  'B89_ENTRA_AUTHORITY',
  'B89_ENTRA_REDIRECT_URI',
  'B89_ENTRA_ALLOWED_REDIRECT_URIS',
  'B89_ENTRA_SCOPES',
  'B89_MVP_ROLE_BINDING_OID',
  'B89_MVP_ROLE_BINDING_ROLE',
  'B89_MVP_ROLE_BINDING_EXPIRES_AT',
  'B89_DEMO_MFA_EXCEPTION_UNTIL',
  // MFA relajado temporal para Entra real (apps/api secops-runtime, máximo 90 días).
  'B89_ENTRA_MFA_RELAXED_UNTIL',
  'B89_DEMO_ADMIN_LOGIN_ENABLED',
  'B89_DEMO_ADMIN_LOGIN_UNTIL',
  'B89_DEMO_ADMIN_USERNAME',
  'B89_DEMO_ADMIN_PASSWORD_HASH',
  'B89_DEMO_ADMIN_PASSWORD_HASH_REF',
  'B89_DEMO_ACCOUNTS',
  'B89_DEMO_ACCOUNTS_REF',
  'B89_DEMO_LOGIN_WITH_ENTRA',
  'B89_CONSOLE_BASE_URL',
  'B89_TEAMS_WORKFLOW_URL_REF',
  'B89_DETECTION_PRIVILEGED_IDENTITIES',
  'B89_DETECTION_BREAK_GLASS_IDENTITIES',
  'B89_DETECTION_CRITICAL_ASSETS',
  'B89_DETECTION_INTERNET_FACING_ASSETS',
  'B89_DETECTION_KNOWN_BENIGN_RULES',
  'B89_SOC_PERSISTENCE',
  'B89_POSTGRES_PASSWORD',
  'B89_ENTITY_REF_KEY',
  'B89_ENTITY_REF_KEY_REF',
  'B89_INGESTION_SOURCE',
  'B89_INGESTION_SOURCE_ID',
  'B89_INGESTION_GATEWAY_SCOPE',
  'B89_INGESTION_INTERVAL',
  'B89_INGESTION_INITIAL_LOOKBACK_MINUTES',
  'B89_ROLE_BINDINGS',
  'B89_GROUP_OWNER_OIDS',
  'B89_ADMIN_GROUP_IDS',
  'B89_ACCESS_APPROVER_OIDS',
  'B89_SECURITY_APPROVER_OIDS',
  'B89_DIRECTORY_SYNC',
  'B89_DIRECTORY_GROUP_ID',
  'B89_DIRECTORY_GROUP_NAME',
  'B89_DIRECTORY_SYNC_INTERVAL_MINUTES',
  'B89_TEAMS_WORKFLOW_URL',
  'B89_ALERT_MAIL_SENDER',
  // Generado por el despliegue y consumido por GET /api/cloudflare/allowlist/feed.
  'B89_ALLOWLIST_FEED_TOKEN',
  'B89_VAPID_PRIVATE_KEY',
  'B89_VAPID_PRIVATE_KEY_REF',
  // Bunny (asistente IA); validación en assistant.schema.ts (la lista se repite literal: el
  // despliegue AWS la busca con grep antes de activar el asistente).
  'B89_BUNNY_ENABLED',
  'B89_BUNNY_PROVIDER',
  'B89_BUNNY_MODEL',
  'B89_BUNNY_EFFORT',
  'B89_BUNNY_REDACT_PII',
  'B89_BUNNY_API_KEY',
  'B89_BUNNY_TIMEOUT_MS',
  'B89_BUNNY_RATE_LIMIT',
  'B89_BUNNY_HISTORY_ENABLED',
  'B89_BUNNY_RETENTION_DAYS',
  // Informes de Bunny (servicio b89-reports); validación en assistant.schema.ts.
  'B89_REPORTS_URL',
  'B89_REPORTS_TOKEN',
  // Analista IA (docs/27); validación en assistant.schema.ts. Apagado por defecto; reutiliza el
  // proveedor y las credenciales de Bunny. Lista literal por la misma razón que la de Bunny.
  'B89_ANALYST_ENABLED',
  'B89_ANALYST_ECONOMY_MODEL',
  'B89_ANALYST_ADVANCED_MODEL',
  'B89_ANALYST_DAILY_CEILING_USD',
  'B89_ANALYST_RATE_CARD',
  'B89_ANALYST_CONCURRENCY',
  'B89_ANALYST_BACKLOG_SWEEP',
  // Reputación de IP (AbuseIPDB) para el Analista IA y Bunny; secreto. Sin ella, apagada.
  'B89_ABUSEIPDB_API_KEY',
  'B89_VIRUSTOTAL_API_KEY',
  // Política de ruido de avisos (configuration-loader › loadNotificationPolicy). Sin estas
  // entradas, definir cualquiera tumbaba el arranque con CONFIG_VALUE_INVALID.
  'B89_NOTIFY_QUIET_P1_MINUTES',
  'B89_NOTIFY_QUIET_P2_MINUTES',
  'B89_NOTIFY_STALE_MINUTES',
  'B89_NOTIFY_MAX_PER_HOUR',
  'B89_NOTIFY_DIGEST_MINUTES',
  'B89_NOTIFY_TIME_ZONE',
]);

export function rejectUnknownB89Variables(
  environment: EnvironmentInput,
  profile?: ConfigurationProfile,
): void {
  const unknown = Object.keys(environment)
    .filter((key) => key.startsWith('B89_') && !KNOWN_B89_VARIABLES.has(key))
    .sort();
  if (unknown[0]) throw configurationError('CONFIG_VALUE_INVALID', unknown[0], profile?.name);
}

export function readValue(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): string | undefined {
  const value = environment[name] ?? profile.defaults[name];
  return value === undefined ? undefined : value;
}

export function requireString(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): string {
  const value = readValue(environment, profile, name);
  if (value === undefined || value.trim() === '')
    throw configurationError('CONFIG_REQUIRED_VALUE_MISSING', name, profile.name);
  const hasControlCharacter = [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint < 32 || codePoint === 127);
  });
  if (value !== value.trim() || hasControlCharacter)
    throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
  return value;
}

export function optionalString(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): string | undefined {
  const value = readValue(environment, profile, name);
  if (value === undefined || value === '') return undefined;
  return requireString(environment, profile, name);
}

export function parseBoolean(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): boolean {
  const value = requireString(environment, profile, name);
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
}

export function parseInteger(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
  minimum: number,
  maximum: number,
): number {
  const value = requireString(environment, profile, name);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value))
    throw configurationError('CONFIG_LIMIT_INVALID', name, profile.name);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw configurationError('CONFIG_LIMIT_INVALID', name, profile.name, { minimum, maximum });
  }
  return parsed;
}

export function parsePort(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): number {
  return parseInteger(
    environment,
    profile,
    name,
    CONFIGURATION_LIMITS.portMinimum,
    CONFIGURATION_LIMITS.portMaximum,
  );
}

export function parseDuration(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): number {
  const value = requireString(environment, profile, name);
  const match = /^([1-9][0-9]*)(ms|s|m)$/u.exec(value);
  if (!match) throw configurationError('CONFIG_DURATION_INVALID', name, profile.name);
  const amount = Number(match[1]);
  const multiplier = match[2] === 'm' ? 60_000 : match[2] === 's' ? 1_000 : 1;
  const milliseconds = amount * multiplier;
  if (
    !Number.isSafeInteger(milliseconds) ||
    milliseconds < CONFIGURATION_LIMITS.durationMinimumMs ||
    milliseconds > CONFIGURATION_LIMITS.durationMaximumMs
  ) {
    throw configurationError('CONFIG_DURATION_INVALID', name, profile.name, {
      minimumMs: CONFIGURATION_LIMITS.durationMinimumMs,
      maximumMs: CONFIGURATION_LIMITS.durationMaximumMs,
    });
  }
  return milliseconds;
}
