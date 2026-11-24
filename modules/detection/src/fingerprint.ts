/**
 * Aprendizaje SOC · etapa B — huella de alerta v1 (docs/soc-learning/01-diseno.md §4.4–§4.5).
 *
 * Función pura y determinista sobre el SecurityEvent: dos alertas del mismo comportamiento dan la
 * misma huella aunque cambien PID, timestamp, GUID, ruta temporal o puerto efímero; un usuario,
 * equipo, hash, destino o línea de comando distinto da otra huella.
 *
 * - **Nivel `fine`**: regla + al menos un sujeto (usuario, equipo o IP de origen) + al menos un
 *   observable de comportamiento (proceso, comando, hash, archivo o destino).
 * - **Nivel `coarse`**: todo lo demás. Un patrón grueso nunca autocierra (lo garantiza la base y
 *   el motor); solo agrupa o baja prioridad.
 *
 * El hash cubre la versión, el normalizador, el tenant, el nivel y el NOMBRE de cada componente
 * con `null` explícito: un campo ausente y uno vacío no colisionan, ni dos campos distintos con el
 * mismo valor. El motor compara además los componentes uno por uno antes de actuar.
 */

import { createHash } from 'node:crypto';

import {
  OBSERVABLES_NORMALIZER_VERSION,
  readObservables,
  type SecurityEvent,
} from '@b89/contracts';

import { ruleKeyOf } from './rule-key.js';

export const FINGERPRINT_VERSION = '1' as const;
export const FINGERPRINT_LEVELS = ['fine', 'coarse'] as const;
export type FingerprintLevel = (typeof FINGERPRINT_LEVELS)[number];

export const FINGERPRINT_SUBJECT_COMPONENTS = ['user', 'host', 'srcIp'] as const;
export const FINGERPRINT_BEHAVIOR_COMPONENTS = [
  'processImage',
  'parentImage',
  'commandLine',
  'sha256',
  'filePath',
  'destination',
  'destinationPort',
] as const;

export const FINGERPRINT_COMPONENTS = [
  'ruleKey',
  'ruleName',
  ...FINGERPRINT_SUBJECT_COMPONENTS,
  ...FINGERPRINT_BEHAVIOR_COMPONENTS,
] as const;
export type FingerprintComponent = (typeof FINGERPRINT_COMPONENTS)[number];

/** Valores normalizados y redactados; `null` = ausente. */
export type FingerprintComponents = Readonly<Record<FingerprintComponent, string | null>>;

export interface AlertFingerprint {
  readonly fingerprint: string;
  readonly level: FingerprintLevel;
  readonly version: string;
  readonly normalizerVersion: string;
  readonly ruleKey: string | null;
  readonly components: FingerprintComponents;
}

/** Categorías donde la IP de origen identifica al sujeto cuando no hay usuario. */
const SOURCE_IP_CATEGORIES = new Set([
  'authentication',
  'network',
  'web',
  'api',
  'intrusion_detection',
]);

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function lower(value: string | undefined): string | null {
  const trimmed = value?.trim().toLowerCase();
  return trimmed && trimmed.length > 0 ? trimmed : null;
}

function firstUser(event: SecurityEvent): string | null {
  for (const identity of event.entities.identities) {
    const value = lower(identity.principal ?? identity.id ?? identity.name);
    if (value) return value;
  }
  return null;
}

function firstResource(event: SecurityEvent, kind: string): string | null {
  for (const resource of event.entities.resources) {
    if (resource.kind !== kind) continue;
    const value = lower(resource.id ?? resource.name);
    if (value) return value;
  }
  return null;
}

/** Nombre de la regla: minúsculas y espacios colapsados (no se reemplazan dígitos). */
function ruleNameOf(event: SecurityEvent): string | null {
  const name = event.detection?.rule.name;
  return name ? lower(name.replace(/\s+/gu, ' ')) : null;
}

/** JSON canónico: claves ordenadas, sin espacios. Mismo criterio que la cadena de auditoría. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
}

export function computeFingerprint(event: SecurityEvent): AlertFingerprint {
  const observables = readObservables(event.extensions, sha256Hex);
  const ruleKey = ruleKeyOf(event) ?? null;
  const user = firstUser(event);
  const sourceIpAllowed =
    user === null && event.category.some((category) => SOURCE_IP_CATEGORIES.has(category));
  const destination = observables?.destination;

  const components: FingerprintComponents = {
    ruleKey,
    ruleName: ruleNameOf(event),
    user,
    // El id del agente es estable aunque el equipo cambie de nombre.
    host: lower(observables?.agentId) ?? firstResource(event, 'host'),
    srcIp: sourceIpAllowed ? firstResource(event, 'ip') : null,
    processImage: observables?.process?.image ?? null,
    parentImage: observables?.parent?.image ?? null,
    commandLine: observables?.process?.commandLine ?? null,
    sha256: observables?.process?.sha256 ?? observables?.file?.sha256 ?? null,
    filePath: observables?.file?.path ?? null,
    // El dominio describe el servicio mejor que una IP que rota; sin dominio, la IP.
    destination: destination?.domain ?? destination?.ip ?? null,
    destinationPort: destination?.port === undefined ? null : String(destination.port),
  };

  const hasSubject = FINGERPRINT_SUBJECT_COMPONENTS.some((name) => components[name] !== null);
  const hasBehavior = FINGERPRINT_BEHAVIOR_COMPONENTS.some((name) => components[name] !== null);
  const level: FingerprintLevel = ruleKey !== null && hasSubject && hasBehavior ? 'fine' : 'coarse';

  const digest = sha256Hex(
    canonicalJson({
      v: FINGERPRINT_VERSION,
      normalizer: OBSERVABLES_NORMALIZER_VERSION,
      tenant: event.tenant.id,
      level,
      components,
    }),
  );
  return Object.freeze({
    fingerprint: `fp${FINGERPRINT_VERSION}_${digest}`,
    level,
    version: FINGERPRINT_VERSION,
    normalizerVersion: OBSERVABLES_NORMALIZER_VERSION,
    ruleKey,
    components: Object.freeze(components),
  });
}

/** Componentes que difieren entre dos huellas (para explicar una deriva o una colisión). */
export function differingComponents(
  left: FingerprintComponents,
  right: FingerprintComponents,
): readonly FingerprintComponent[] {
  return FINGERPRINT_COMPONENTS.filter((name) => left[name] !== right[name]);
}
