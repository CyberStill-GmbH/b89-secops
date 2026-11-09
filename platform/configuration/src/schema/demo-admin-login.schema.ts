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
 * - Cuentas demo adicionales (opcional, `B89_DEMO_ACCOUNTS`, secreto JSON): hasta
 *   `DEMO_ACCOUNTS_MAX` cuentas `{username, role, passwordHash}`, cada una atada a exactamente uno
 *   de los cuatro roles runtime de B89. Comparten la excepción del administrador (mismo
 *   interruptor, mismo vencimiento, mismo perfil permitido): sin la excepción habilitada, su
 *   sola presencia impide arrancar. Usuarios validados y únicos (también frente al admin).
 *   Nunca un rol aprobador: ninguna cuenta demo puede resolver solicitudes de rol (SoD).
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

/** Tope de cuentas demo adicionales (además del administrador). */
export const DEMO_ACCOUNTS_MAX = 8;
/** Tope del JSON de cuentas: acota el parseo de un valor que llega del entorno. */
const DEMO_ACCOUNTS_MAX_BYTES = 8_192;
/**
 * Los cuatro roles runtime solicitables (modules/access, `REQUESTABLE_ROLES`). Los roles
 * aprobadores (`b89.access.approver`, `b89.security.approver`) quedan fuera a propósito.
 */
export const DEMO_ACCOUNT_ROLES = Object.freeze([
  'b89.auditor',
  'b89.platform.admin',
  'b89.soc.analyst',
  'b89.soc.lead',
] as const);
export type DemoAccountRole = (typeof DEMO_ACCOUNT_ROLES)[number];

export interface DemoAccountConfig {
  readonly username: string;
  readonly role: DemoAccountRole;
  readonly passwordHash: SecretValue;
}

export type DemoAdminLoginConfig =
  | { readonly enabled: false }
  | {
      readonly enabled: true;
      /** Perfil efectivo que justificó la excepción; `demo` = producción atada al despliegue demo. */
      readonly deployment: 'development' | 'test' | 'demo';
      readonly until: Date;
      readonly username: string;
      readonly passwordHash: SecretValue;
      /** Cuentas demo adicionales; vacío si `B89_DEMO_ACCOUNTS` no está definida. */
      readonly accounts: readonly DemoAccountConfig[];
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
  const rawAccounts = environment['B89_DEMO_ACCOUNTS'];
  if (flag === undefined || flag === 'false') {
    // Las cuentas adicionales no existen sin la excepción: configurarlas sola es un error.
    if (rawAccounts !== undefined && rawAccounts !== '') {
      throw configurationError('CONFIG_VALUE_INVALID', 'B89_DEMO_ACCOUNTS', profile.name, {
        reason: 'DEMO_ACCOUNTS_REQUIRE_DEMO_ADMIN_LOGIN',
      });
    }
    return { enabled: false };
  }
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
    accounts: parseDemoAccounts(rawAccounts, username, profile),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `B89_DEMO_ACCOUNTS`: arreglo JSON de `{username, role, passwordHash}`. Los errores solo
 * nombran la variable y la posición: nunca el usuario ni el hash.
 */
function parseDemoAccounts(
  raw: string | undefined,
  adminUsername: string,
  profile: ConfigurationProfile,
): readonly DemoAccountConfig[] {
  if (raw === undefined || raw === '') return [];
  const path = 'B89_DEMO_ACCOUNTS';
  const invalid = (reason: string, index?: number) =>
    configurationError('CONFIG_VALUE_INVALID', path, profile.name, {
      reason,
      ...(index === undefined ? {} : { index }),
    });
  if (Buffer.byteLength(raw, 'utf8') > DEMO_ACCOUNTS_MAX_BYTES) {
    throw configurationError('CONFIG_LIMIT_INVALID', path, profile.name, {
      maximumBytes: DEMO_ACCOUNTS_MAX_BYTES,
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw invalid('NOT_JSON');
  }
  if (!Array.isArray(parsed) || parsed.length === 0) throw invalid('NOT_A_NON_EMPTY_ARRAY');
  if (parsed.length > DEMO_ACCOUNTS_MAX) {
    throw configurationError('CONFIG_LIMIT_INVALID', path, profile.name, {
      maximumAccounts: DEMO_ACCOUNTS_MAX,
    });
  }
  const seen = new Set<string>([adminUsername]);
  return parsed.map((entry: unknown, index): DemoAccountConfig => {
    if (!isRecord(entry)) throw invalid('ENTRY_NOT_OBJECT', index);
    const keys = Object.keys(entry).sort();
    if (keys.join(',') !== 'passwordHash,role,username') throw invalid('ENTRY_KEYS', index);
    const { username, role, passwordHash } = entry;
    if (typeof username !== 'string' || !USERNAME.test(username)) {
      throw invalid('USERNAME_INVALID', index);
    }
    if (seen.has(username)) throw invalid('USERNAME_DUPLICATE', index);
    seen.add(username);
    if (typeof role !== 'string' || !(DEMO_ACCOUNT_ROLES as readonly string[]).includes(role)) {
      throw invalid('ROLE_INVALID', index);
    }
    if (typeof passwordHash !== 'string' || !passwordHash.startsWith('$scrypt$')) {
      throw invalid('PASSWORD_HASH_INVALID', index);
    }
    return {
      username,
      role: role as DemoAccountRole,
      passwordHash: new SecretValue(passwordHash),
    };
  });
}
