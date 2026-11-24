/**
 * Aprendizaje SOC · etapa A — política de cierre de alertas (docs/soc-learning/01-diseno.md §3.2).
 *
 * `B89_SOC_CLOSURE_REASON_REQUIRED` decide si `close` sin motivo estructurado se rechaza
 * (`true`) o se acepta como cierre heredado que nunca alimenta el aprendizaje (`false`, por
 * defecto). Se activa cuando la consola ya envía el motivo; antes rompería a sus usuarios.
 */

import { configurationError } from '../configuration.errors.js';
import type { EnvironmentInput } from '../configuration.types.js';
import type { ConfigurationProfile } from '../profiles/index.js';
import { optionalString } from './environment.schema.js';

export interface SocClosurePolicyConfig {
  readonly reasonRequired: boolean;
}

export function parseSocClosurePolicy(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
): SocClosurePolicyConfig {
  const name = 'B89_SOC_CLOSURE_REASON_REQUIRED';
  const raw = optionalString(environment, profile, name);
  if (raw === undefined || raw === 'false') return { reasonRequired: false };
  if (raw === 'true') return { reasonRequired: true };
  throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
}

/**
 * Aprendizaje SOC · etapa C — agrupación de alertas por huella (docs/soc-learning/01-diseno.md §2.3).
 *
 * - `B89_SOC_GROUPING_ENABLED` (por defecto `true`): agrupar no cambia estado ni prioridad de
 *   ninguna alerta; solo las anota. Se puede apagar sin efectos sobre las alertas existentes.
 * - `B89_SOC_GROUPING_WINDOW_HOURS` (1–168, por defecto 24) y
 *   `B89_SOC_GROUPING_MAX_SPAN_DAYS` (1–30, por defecto 7, y nunca menor que la ventana).
 */
export interface SocGroupingConfig {
  readonly enabled: boolean;
  readonly windowMs: number;
  readonly maxSpanMs: number;
}

const HOUR_MS = 60 * 60 * 1000;

function boundedInteger(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = optionalString(environment, profile, name);
  if (raw === undefined) return fallback;
  const value = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
  }
  return value;
}

export function parseSocGrouping(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
): SocGroupingConfig {
  const enabledName = 'B89_SOC_GROUPING_ENABLED';
  const enabledRaw = optionalString(environment, profile, enabledName);
  if (enabledRaw !== undefined && enabledRaw !== 'true' && enabledRaw !== 'false') {
    throw configurationError('CONFIG_VALUE_INVALID', enabledName, profile.name);
  }
  const windowHours = boundedInteger(
    environment,
    profile,
    'B89_SOC_GROUPING_WINDOW_HOURS',
    24,
    1,
    168,
  );
  const spanDays = boundedInteger(environment, profile, 'B89_SOC_GROUPING_MAX_SPAN_DAYS', 7, 1, 30);
  if (spanDays * 24 < windowHours) {
    throw configurationError(
      'CONFIG_VALUE_INVALID',
      'B89_SOC_GROUPING_MAX_SPAN_DAYS',
      profile.name,
    );
  }
  return {
    enabled: enabledRaw !== 'false',
    windowMs: windowHours * HOUR_MS,
    maxSpanMs: spanDays * 24 * HOUR_MS,
  };
}
