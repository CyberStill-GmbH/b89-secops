/**
 * Aprendizaje SOC · etapa A — política de cierre de alertas (docs/soc-learning/01-diseno.md §3.2).
 *
 * `B89_SOC_CLOSURE_REASON_REQUIRED` decide si `close` sin motivo estructurado se rechaza
 * (`true`) o se acepta como cierre heredado que nunca alimenta el aprendizaje (`false`, por
 * defecto). Se activa cuando la consola ya envía el motivo; antes rompería a sus usuarios.
 */

import { configurationError } from '../configuration.errors.js';
import { SecretValue, type EnvironmentInput } from '../configuration.types.js';
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
 * - `B89_SOC_GROUPING_MAX_ALERTS` (2–10000, por defecto 500): un grupo lleno se sella y la
 *   siguiente alerta abre otro. Acota los grupos de huella gruesa demasiado amplios.
 */
export interface SocGroupingConfig {
  readonly enabled: boolean;
  readonly windowMs: number;
  readonly maxSpanMs: number;
  readonly maxAlerts: number;
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
  const maxAlerts = boundedInteger(
    environment,
    profile,
    'B89_SOC_GROUPING_MAX_ALERTS',
    500,
    2,
    10_000,
  );
  return {
    enabled: enabledRaw !== 'false',
    windowMs: windowHours * HOUR_MS,
    maxSpanMs: spanDays * 24 * HOUR_MS,
    maxAlerts,
  };
}

/**
 * Aprendizaje SOC · etapa D — aprobadores designados de patrones de FP (diseño §5.3, regla A / A+B).
 *
 * `B89_SOC_LEARNING_APPROVERS`: `subjectId` de personas separados por coma. Vacío o ausente es el
 * valor por defecto y deja la activación bloqueada (`APPROVERS_NOT_CONFIGURED`, fail-closed): con
 * menos de dos personas no hay A+B posible. Una identidad de servicio (`svc:`) no puede firmar.
 */
export interface SocLearningApproversConfig {
  readonly approvers: readonly string[];
}

const MAXIMUM_APPROVERS = 50;

export function parseSocLearningApprovers(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
): SocLearningApproversConfig {
  const name = 'B89_SOC_LEARNING_APPROVERS';
  const raw = optionalString(environment, profile, name);
  if (raw === undefined || raw.trim() === '') return { approvers: [] };
  const approvers = raw.split(',').map((entry) => entry.trim());
  const valid = approvers.every(
    (entry) =>
      entry.length >= 1 &&
      entry.length <= 128 &&
      !entry.startsWith('svc:') &&
      /^[\p{L}\p{N}._@:|-]+$/u.test(entry),
  );
  if (
    !valid ||
    approvers.length > MAXIMUM_APPROVERS ||
    new Set(approvers).size !== approvers.length
  ) {
    throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
  }
  return { approvers };
}

/**
 * Aprendizaje SOC · etapa E — motor de decisión (docs/soc-learning/01-diseno.md §6.1, §8).
 *
 * Todo apagado por defecto. `B89_LEARNING_ENABLED=true` enciende el refresco de patrones y la
 * evaluación de alertas nuevas; el modo efectivo nunca supera `B89_LEARNING_MAX_MODE`, y por encima
 * de `shadow` solo aplica a las reglas de `B89_LEARNING_ACTIVE_RULES` (la activación es por regla).
 * En producción, `dry_run`/`active` exigen `B89_LEARNING_PROMOTION_REF` (registro del cambio
 * aprobado, docs/22) y `B89_LEARNING_SAMPLING_KEY`.
 */
export const LEARNING_ENGINE_MODES = ['off', 'shadow', 'dry_run', 'active'] as const;
export type LearningEngineMode = (typeof LEARNING_ENGINE_MODES)[number];

export interface LearningEngineConfig {
  readonly enabled: boolean;
  readonly maxMode: LearningEngineMode;
  readonly activeRules: readonly string[];
  readonly killSwitch: boolean;
  readonly killedRules: readonly string[];
  readonly neverSuppressRules: readonly string[];
  readonly samplingKey: SecretValue | undefined;
  readonly samplingPercent: number;
  readonly hourlyCap: number;
  readonly dailyCap: number;
  readonly forcedReviewAfter: number;
  /** Calendario de cambios confirmado hasta esta fecha (§6.2); `null` = sin confirmar. */
  readonly changeCalendarAckUntil: Date | null;
  readonly refreshMinutes: number;
  readonly promotionRef: string | undefined;
}

const RULE_KEY_PATTERN = /^[a-z][a-z0-9-]*:[A-Za-z0-9._:-]{1,128}$/u;
const SAMPLING_KEY_MINIMUM = 32;

function flag(environment: EnvironmentInput, profile: ConfigurationProfile, name: string): boolean {
  const raw = optionalString(environment, profile, name);
  if (raw === undefined || raw === 'false') return false;
  if (raw === 'true') return true;
  throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
}

function ruleKeys(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  name: string,
): readonly string[] {
  const raw = optionalString(environment, profile, name);
  if (raw === undefined || raw.trim() === '') return [];
  const keys = raw.split(',').map((entry) => entry.trim());
  if (keys.length > 500 || keys.some((key) => !RULE_KEY_PATTERN.test(key))) {
    throw configurationError('CONFIG_VALUE_INVALID', name, profile.name);
  }
  return [...new Set(keys)];
}

export function parseLearningEngine(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
): LearningEngineConfig {
  const modeName = 'B89_LEARNING_MAX_MODE';
  const modeRaw = optionalString(environment, profile, modeName) ?? 'shadow';
  if (!(LEARNING_ENGINE_MODES as readonly string[]).includes(modeRaw)) {
    throw configurationError('CONFIG_VALUE_INVALID', modeName, profile.name);
  }
  const maxMode = modeRaw as LearningEngineMode;
  const keyName = 'B89_LEARNING_SAMPLING_KEY';
  const keyRaw = optionalString(environment, profile, keyName);
  if (keyRaw !== undefined && keyRaw.length < SAMPLING_KEY_MINIMUM) {
    throw configurationError('CONFIG_VALUE_INVALID', keyName, profile.name);
  }
  const promotionName = 'B89_LEARNING_PROMOTION_REF';
  const promotionRef = optionalString(environment, profile, promotionName)?.trim() || undefined;
  if (promotionRef !== undefined && !/^[A-Za-z0-9._:/#-]{3,128}$/u.test(promotionRef)) {
    throw configurationError('CONFIG_VALUE_INVALID', promotionName, profile.name);
  }
  const acting = maxMode === 'dry_run' || maxMode === 'active';
  if (acting && profile.name === 'production' && promotionRef === undefined) {
    throw configurationError('CONFIG_REQUIRED_VALUE_MISSING', promotionName, profile.name);
  }
  if (acting && profile.name === 'production' && keyRaw === undefined) {
    throw configurationError('CONFIG_REQUIRED_VALUE_MISSING', keyName, profile.name);
  }
  const ackName = 'B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL';
  const ackRaw = optionalString(environment, profile, ackName);
  let changeCalendarAckUntil: Date | null = null;
  if (ackRaw !== undefined && ackRaw.trim() !== '') {
    const parsed = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z)?$/u.test(ackRaw)
      ? new Date(ackRaw)
      : new Date(Number.NaN);
    if (Number.isNaN(parsed.getTime())) {
      throw configurationError('CONFIG_VALUE_INVALID', ackName, profile.name);
    }
    changeCalendarAckUntil = parsed;
  }
  return {
    enabled: flag(environment, profile, 'B89_LEARNING_ENABLED'),
    maxMode,
    activeRules: ruleKeys(environment, profile, 'B89_LEARNING_ACTIVE_RULES'),
    killSwitch: flag(environment, profile, 'B89_LEARNING_KILL_SWITCH'),
    killedRules: ruleKeys(environment, profile, 'B89_LEARNING_KILLED_RULES'),
    neverSuppressRules: ruleKeys(environment, profile, 'B89_LEARNING_NEVER_SUPPRESS_RULES'),
    samplingKey: keyRaw === undefined ? undefined : new SecretValue(keyRaw),
    samplingPercent: boundedInteger(
      environment,
      profile,
      'B89_LEARNING_SAMPLING_PERCENT',
      10,
      1,
      100,
    ),
    hourlyCap: boundedInteger(environment, profile, 'B89_LEARNING_HOURLY_CAP', 10, 1, 1_000),
    dailyCap: boundedInteger(environment, profile, 'B89_LEARNING_DAILY_CAP', 30, 1, 10_000),
    forcedReviewAfter: boundedInteger(
      environment,
      profile,
      'B89_LEARNING_FORCED_REVIEW_AFTER',
      20,
      1,
      1_000,
    ),
    changeCalendarAckUntil,
    refreshMinutes: boundedInteger(
      environment,
      profile,
      'B89_LEARNING_REFRESH_MINUTES',
      15,
      5,
      1_440,
    ),
    promotionRef,
  };
}
