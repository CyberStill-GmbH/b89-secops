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
