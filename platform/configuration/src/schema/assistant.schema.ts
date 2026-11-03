import { configurationError } from '../configuration.errors.js';
import type { EnvironmentInput } from '../configuration.types.js';
import type { ConfigurationProfile } from '../profiles/index.js';

/**
 * Variables de Bunny (asistente IA). La configuración efectiva la construye
 * `apps/api/src/assistant/assistant-config.ts`; aquí se valida al arrancar para que un valor
 * inválido falle con `CONFIG_VALUE_INVALID` (sin exponer el valor) antes de servir tráfico.
 */
export const ASSISTANT_VARIABLES = [
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
] as const;

export const ASSISTANT_PROVIDERS = ['bedrock', 'anthropic'] as const;
const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];
const FLAGS = ['true', 'false'];

function integerIn(raw: string, min: number, max: number): boolean {
  if (!/^\d{1,6}$/u.test(raw)) return false;
  const value = Number(raw);
  return value >= min && value <= max;
}

export function validateAssistantEnvironment(
  environment: EnvironmentInput,
  profile?: ConfigurationProfile,
): void {
  const fail = (name: string): never => {
    throw configurationError('CONFIG_VALUE_INVALID', name, profile?.name);
  };
  const value = (name: string): string | undefined => {
    const raw = environment[name];
    return raw === undefined || raw === '' ? undefined : raw;
  };
  for (const name of ['B89_BUNNY_ENABLED', 'B89_BUNNY_REDACT_PII', 'B89_BUNNY_HISTORY_ENABLED']) {
    const raw = value(name);
    if (raw !== undefined && !FLAGS.includes(raw)) fail(name);
  }
  const provider = value('B89_BUNNY_PROVIDER');
  if (provider !== undefined && !(ASSISTANT_PROVIDERS as readonly string[]).includes(provider)) {
    fail('B89_BUNNY_PROVIDER');
  }
  const effort = value('B89_BUNNY_EFFORT');
  if (effort !== undefined && !EFFORTS.includes(effort)) fail('B89_BUNNY_EFFORT');
  const model = value('B89_BUNNY_MODEL');
  if (model !== undefined && !/^[A-Za-z0-9._:-]{3,100}$/u.test(model)) fail('B89_BUNNY_MODEL');
  const rate = value('B89_BUNNY_RATE_LIMIT');
  if (rate !== undefined && !integerIn(rate, 1, 600)) fail('B89_BUNNY_RATE_LIMIT');
  const retention = value('B89_BUNNY_RETENTION_DAYS');
  if (retention !== undefined && !integerIn(retention, 1, 365)) fail('B89_BUNNY_RETENTION_DAYS');
  const timeout = value('B89_BUNNY_TIMEOUT_MS');
  if (timeout !== undefined && !integerIn(timeout, 1000, 120_000)) fail('B89_BUNNY_TIMEOUT_MS');
  const apiKey = value('B89_BUNNY_API_KEY');
  if (apiKey !== undefined && (apiKey.length > 512 || !/^[\x21-\x7e]+$/u.test(apiKey))) {
    fail('B89_BUNNY_API_KEY');
  }
  if (value('B89_BUNNY_ENABLED') === 'true' && provider === 'anthropic' && apiKey === undefined) {
    throw configurationError('CONFIG_REQUIRED_VALUE_MISSING', 'B89_BUNNY_API_KEY', profile?.name);
  }
}
