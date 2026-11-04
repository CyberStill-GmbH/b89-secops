/**
 * Excepción demo: acceso con contraseña de UNA cuenta administrativa sintética.
 *
 * Es una excepción temporal y consciente a la política de autenticación (MFA dentro de la red,
 * passkey fuera; docs/04-identidad-y-acceso.md). Por eso la configuración falla cerrada:
 *
 * - Apagada por defecto. Solo `B89_DEMO_ADMIN_LOGIN_ENABLED=true` la activa, y entonces exige
 *   vencimiento (`B89_DEMO_ADMIN_LOGIN_UNTIL`, ISO 8601 UTC, como máximo 30 días desde el
 *   arranque), usuario y hash de contraseña. Cualquier ausencia o forma inválida impide arrancar.
 * - Perfiles: `development` y `test` la admiten. La demo de AWS corre con `B89_PROFILE=production`
 *   (infra/aws/modules/runtime/main.tf), así que en `production` solo se admite si la identidad
 *   configurada es exactamente la del despliegue demo (tenant, client y redirect fijos, los de
 *   infra/aws/environments/demo.tfvars). Un despliegue de producción real tiene otro tenant y su
 *   arranque falla con `CONFIG_VALUE_INVALID` en `B89_DEMO_ADMIN_LOGIN_ENABLED`.
 * - La contraseña nunca llega en claro: solo su hash scrypt. Aquí solo se comprueba que exista;
 *   el formato y los parámetros los valida el API al construir el verificador (y también falla
 *   al arrancar si no cumplen).
 */

import { configurationError } from '../configuration.errors.js';
import { SecretValue, type EnvironmentInput } from '../configuration.types.js';
import type { ConfigurationProfile } from '../profiles/index.js';
import type { AccessConfig } from './access.schema.js';
import { optionalString, requireString } from './environment.schema.js';

/** Vigencia máxima de la excepción contada desde el arranque. */
export const DEMO_ADMIN_LOGIN_MAX_WINDOW_MS = 30 * 86_400_000;

/**
 * Identidad del despliegue demo de AWS (infra/aws/environments/demo.tfvars). Es la misma atadura
 * que usa la excepción de MFA de la demo anterior: fuera de este tenant/app/redirect, `production`
 * no admite la excepción de contraseña.
 */
export const DEMO_DEPLOYMENT_IDENTITY = Object.freeze({
  tenantId: '11111111-1111-4111-8111-111111111111',
  clientId: '22222222-2222-4222-8222-222222222222',
  redirectUri: 'https://app.b89.example/api/auth/callback',
});

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;
/** Usuario en minúsculas, con caracteres de UPN: viaja en cabeceras de proxy auth sin escapar. */
const USERNAME = /^[a-z0-9][a-z0-9._@+-]{2,63}$/u;

export type DemoAdminLoginConfig =
  | { readonly enabled: false }
  | {
      readonly enabled: true;
      /** Perfil efectivo que justificó la excepción; `demo` = producción atada al despliegue demo. */
      readonly deployment: 'development' | 'test' | 'demo';
      readonly until: Date;
      readonly username: string;
      readonly passwordHash: SecretValue;
    };

function isDemoDeployment(access: AccessConfig): boolean {
  return (
    access.identityMode === 'entra' &&
    access.tenantId === DEMO_DEPLOYMENT_IDENTITY.tenantId &&
    access.clientId === DEMO_DEPLOYMENT_IDENTITY.clientId &&
    access.redirectUri === DEMO_DEPLOYMENT_IDENTITY.redirectUri
  );
}

export function parseDemoAdminLogin(
  environment: EnvironmentInput,
  profile: ConfigurationProfile,
  access: AccessConfig,
  now: Date,
): DemoAdminLoginConfig {
  const flag = optionalString(environment, profile, 'B89_DEMO_ADMIN_LOGIN_ENABLED');
  if (flag === undefined || flag === 'false') return { enabled: false };
  if (flag !== 'true') {
    throw configurationError('CONFIG_VALUE_INVALID', 'B89_DEMO_ADMIN_LOGIN_ENABLED', profile.name);
  }
  let deployment: 'development' | 'test' | 'demo';
  if (profile.name === 'production') {
    if (!isDemoDeployment(access)) {
      // Fallo explícito: la excepción no existe en un perfil de producción que no sea la demo.
      throw configurationError(
        'CONFIG_VALUE_INVALID',
        'B89_DEMO_ADMIN_LOGIN_ENABLED',
        profile.name,
        { reason: 'DEMO_ADMIN_LOGIN_NOT_ALLOWED_IN_PROFILE' },
      );
    }
    deployment = 'demo';
  } else {
    deployment = profile.name;
  }
  const rawUntil = requireString(environment, profile, 'B89_DEMO_ADMIN_LOGIN_UNTIL');
  const until = new Date(rawUntil);
  if (!ISO_UTC.test(rawUntil) || !Number.isFinite(until.getTime())) {
    throw configurationError('CONFIG_VALUE_INVALID', 'B89_DEMO_ADMIN_LOGIN_UNTIL', profile.name);
  }
  if (until.getTime() > now.getTime() + DEMO_ADMIN_LOGIN_MAX_WINDOW_MS) {
    throw configurationError('CONFIG_LIMIT_INVALID', 'B89_DEMO_ADMIN_LOGIN_UNTIL', profile.name, {
      maximumDays: 30,
    });
  }
  const username = requireString(environment, profile, 'B89_DEMO_ADMIN_USERNAME');
  if (!USERNAME.test(username)) {
    throw configurationError('CONFIG_VALUE_INVALID', 'B89_DEMO_ADMIN_USERNAME', profile.name);
  }
  // Se lee del entorno ya resuelto (secreto inyectado por ECS o resuelto por `_REF`); nunca de
  // los valores por defecto del perfil.
  const hash = environment['B89_DEMO_ADMIN_PASSWORD_HASH'];
  if (hash === undefined || hash === '') {
    throw configurationError(
      'CONFIG_REQUIRED_VALUE_MISSING',
      'B89_DEMO_ADMIN_PASSWORD_HASH',
      profile.name,
    );
  }
  return {
    enabled: true,
    deployment,
    until,
    username,
    passwordHash: new SecretValue(hash),
  };
}
