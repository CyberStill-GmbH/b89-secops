/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Lógica pura de la pantalla «DLP de endpoints»: catálogo de reglas en español, resumen de
 * equipos, cambios sin guardar, comando de instalación y el asistente de conexión. Sin React,
 * para probarla sin DOM.
 */

import { B89ApiError } from '../api/client';
import type { DlpEndpoint, DlpEnrollmentStatus, DlpEnrollmentToken, DlpPolicy, DlpUsbControlGroup, DlpUsbControlPolicy } from '../api/dlp';
import { getDlpEnrollmentStatus } from '../api/dlp';
import type { B89ApiClient } from '../api/client';

// ------------------------------------------------------------------ reglas

export interface DlpRule {
  readonly id: string;
  /** Nombre visible. Las marcas (GitHub, Slack…) van tal cual: no se traducen. */
  readonly label: string;
  /** Una frase para el tooltip, junto al ID técnico. */
  readonly hint: string;
  readonly advanced: boolean;
}

export const DLP_RULES: readonly DlpRule[] = [
  { id: 'B89_CRED_PRIVATE_KEY_PEM', label: 'Claves privadas (PEM, SSH)', hint: 'Archivos de clave RSA, EC, OpenSSH o DSA.', advanced: false },
  { id: 'B89_CRED_GITHUB_TOKEN', label: 'Tokens de GitHub', hint: 'Tokens clásicos y de grano fino.', advanced: false },
  { id: 'B89_CRED_SLACK_TOKEN', label: 'Tokens de Slack', hint: 'Tokens de bot, usuario o aplicación de Slack.', advanced: false },
  { id: 'B89_CRED_GOOGLE_API_KEY', label: 'Claves de API de Google', hint: 'Claves con el prefijo AIza.', advanced: false },
  { id: 'B89_CRED_AZURE_STORAGE_KEY', label: 'Claves de Azure Storage', hint: 'AccountKey dentro de una cadena de conexión.', advanced: false },
  { id: 'B89_CRED_OPENAI_API_KEY', label: 'Claves de API de OpenAI', hint: 'Claves con prefijo sk-.', advanced: false },
  { id: 'B89_CRED_AWS_ACCESS_KEY_PAIR', label: 'Claves de acceso de AWS', hint: 'ID y clave secreta juntos en el mismo archivo.', advanced: true },
  { id: 'B89_SECRET_DATABASE_CONNECTION', label: 'Conexiones a bases de datos con contraseña', hint: 'Cadenas de conexión con usuario y contraseña.', advanced: true },
  { id: 'B89_SECRET_CREDENTIAL_ASSIGNMENT', label: 'Contraseñas escritas en archivos', hint: 'password, client_secret o api_key con un valor visible.', advanced: true },
  { id: 'B89_PII_PERU_DNI_CONTEXTUAL', label: 'Números de DNI', hint: 'Ocho dígitos junto a la palabra DNI. Dato personal: requiere aprobación de privacidad.', advanced: true },
  { id: 'B89_PII_PERU_RUC_CONTEXTUAL', label: 'Números de RUC', hint: 'Once dígitos junto a la palabra RUC.', advanced: true },
];

const RULE_LABEL = new Map(DLP_RULES.map((rule) => [rule.id, rule.label]));

export function ruleLabel(id: string): string {
  return RULE_LABEL.get(id) ?? id;
}

/** Nombre de lo que encontró Ferrispector, incluida la huella de documento (siempre activa). */
export function detectorLabel(id: string | null): string {
  if (!id) return 'Tipo desconocido';
  if (id === 'B89_DLP_EXACT_FILE_FINGERPRINT') return 'Copia de un documento protegido';
  return RULE_LABEL.get(id) ?? 'Otro dato sensible';
}

// ------------------------------------------------------------------ huellas

const HASH = /^[0-9a-f]{64}$/iu;

/** Una huella SHA-256 por línea; `#` comenta. Devuelve los números de línea inválidos. */
export function parseFingerprints(text: string): { values: string[]; invalid: number[] } {
  const values: string[] = [];
  const invalid: number[] = [];
  const seen = new Set<string>();
  text.split(/\r?\n/u).forEach((source, index) => {
    const line = source.trim();
    if (!line || line.startsWith('#')) return;
    if (!HASH.test(line)) {
      invalid.push(index + 1);
      return;
    }
    const normalized = line.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      values.push(normalized);
    }
  });
  return { values, invalid };
}

export function nextVersion(value: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(value);
  if (!match) return '1.0.0';
  return `${match[1]}.${Number(match[2]) + 1}.0`;
}

// ------------------------------------------------------------------ cambios sin guardar

export interface PolicyDiff {
  readonly enabled: readonly string[];
  readonly disabled: readonly string[];
  readonly fingerprintsAdded: number;
  readonly fingerprintsRemoved: number;
  readonly quarantineChanged: boolean;
  readonly usbControlChanged: boolean;
}

export function policyDiff(
  policy: Pick<DlpPolicy, 'enabledRuleIds' | 'fingerprintsSha256' | 'quarantineExactFingerprints' | 'usbControl'>,
  rules: readonly string[],
  fingerprints: readonly string[],
  quarantineExactFingerprints = policy.quarantineExactFingerprints,
  usbControl: DlpUsbControlPolicy = policy.usbControl,
): PolicyDiff {
  const before = new Set(policy.enabledRuleIds);
  const after = new Set(rules);
  const hashesBefore = new Set(policy.fingerprintsSha256);
  const hashesAfter = new Set(fingerprints);
  const order = (ids: string[]) => DLP_RULES.map((rule) => rule.id).filter((id) => ids.includes(id));
  return {
    enabled: order([...after].filter((id) => !before.has(id))),
    disabled: order([...before].filter((id) => !after.has(id))),
    fingerprintsAdded: [...hashesAfter].filter((hash) => !hashesBefore.has(hash)).length,
    fingerprintsRemoved: [...hashesBefore].filter((hash) => !hashesAfter.has(hash)).length,
    quarantineChanged: quarantineExactFingerprints !== policy.quarantineExactFingerprints,
    usbControlChanged: JSON.stringify(usbControl) !== JSON.stringify(policy.usbControl),
  };
}

export function hasChanges(diff: PolicyDiff): boolean {
  return diff.enabled.length + diff.disabled.length + diff.fingerprintsAdded + diff.fingerprintsRemoved > 0 ||
    diff.quarantineChanged || diff.usbControlChanged;
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** Frases cortas para la barra de guardado: «Activa Tokens de Slack», «+3 documentos». */
export function describeDiff(diff: PolicyDiff): string[] {
  const lines: string[] = [];
  if (diff.enabled.length) lines.push(`Activa: ${diff.enabled.map(ruleLabel).join(', ')}`);
  if (diff.disabled.length) lines.push(`Desactiva: ${diff.disabled.map(ruleLabel).join(', ')}`);
  if (diff.fingerprintsAdded) lines.push(`Agrega ${plural(diff.fingerprintsAdded, 'documento', 'documentos')}`);
  if (diff.fingerprintsRemoved) lines.push(`Quita ${plural(diff.fingerprintsRemoved, 'documento', 'documentos')}`);
  if (diff.quarantineChanged) lines.push('Cambia la cuarentena de huellas exactas');
  if (diff.usbControlChanged) lines.push('Cambia los grupos y el bloqueo USB');
  return lines;
}

export function normalizeUsbGroups(groups: readonly DlpUsbControlGroup[]): DlpUsbControlGroup[] {
  return groups.map((group) => ({
    id: group.id.toLowerCase(),
    name: group.name.trim(),
    identities: [...new Set(group.identities.map((identity) => identity.trim().toUpperCase()).filter(Boolean))].sort(),
  }));
}

// ------------------------------------------------------------------ equipos

export type EndpointHealth = 'ok' | 'updating' | 'offline' | 'never' | 'reinstall' | 'revoked';

export function endpointHealth(endpoint: DlpEndpoint): EndpointHealth {
  switch (endpoint.status) {
    case 'revoked':
      return 'revoked';
    case 're-enrollment-required':
      return 'reinstall';
    case 'offline':
      return endpoint.lastSeenAt ? 'offline' : 'never';
    case 'updating':
      return 'updating';
    case 'current':
      return 'ok';
    default:
      // Estado que esta versión de la consola no conoce: no lo damos por bueno.
      return 'offline';
  }
}

export const HEALTH_LABEL: Record<EndpointHealth, string> = {
  ok: 'Protegido',
  updating: 'Aplicando cambios',
  offline: 'Sin conexión',
  never: 'Nunca se conectó',
  reinstall: 'Reinstalar',
  revoked: 'Revocado',
};

export const HEALTH_TONE: Record<EndpointHealth, 'success' | 'primary' | 'warning' | 'danger' | 'hollow'> = {
  ok: 'success',
  updating: 'primary',
  offline: 'warning',
  never: 'warning',
  reinstall: 'danger',
  revoked: 'hollow',
};

/** Qué debe hacer una persona con un equipo en ese estado; `null` si nada. */
export const HEALTH_ACTION: Record<EndpointHealth, string | null> = {
  ok: null,
  updating: null,
  offline: 'Revisa que el equipo esté encendido y con red.',
  never: 'Revisa que el equipo esté encendido y con red.',
  reinstall: 'Revoca este equipo y vuelve a conectarlo con una clave nueva.',
  revoked: null,
};

const HEALTH_ORDER: readonly EndpointHealth[] = ['reinstall', 'offline', 'never', 'updating', 'ok', 'revoked'];

/** Lo que necesita atención primero; después por nombre. */
export function sortEndpoints(endpoints: readonly DlpEndpoint[]): DlpEndpoint[] {
  return [...endpoints].sort((a, b) => {
    const order = HEALTH_ORDER.indexOf(endpointHealth(a)) - HEALTH_ORDER.indexOf(endpointHealth(b));
    return order !== 0 ? order : a.hostname.localeCompare(b.hostname);
  });
}

export interface FleetSummary {
  /** Equipos con credencial vigente (no revocados). */
  readonly total: number;
  readonly counts: Record<EndpointHealth, number>;
  readonly attention: number;
  readonly headline: string;
  readonly tone: 'success' | 'primary' | 'warning' | 'subdued';
}

export function summarizeFleet(endpoints: readonly DlpEndpoint[]): FleetSummary {
  const counts: Record<EndpointHealth, number> = { ok: 0, updating: 0, offline: 0, never: 0, reinstall: 0, revoked: 0 };
  for (const endpoint of endpoints) counts[endpointHealth(endpoint)] += 1;
  const total = endpoints.length - counts.revoked;
  const attention = counts.offline + counts.never + counts.reinstall;
  if (total === 0) {
    return { total, counts, attention, headline: 'Ningún equipo conectado', tone: 'subdued' };
  }
  if (attention > 0) {
    return {
      total,
      counts,
      attention,
      // «1 de 3 equipos necesita atención»: el sustantivo concuerda con el total, el verbo con
      // los que necesitan atención.
      headline: `${attention} de ${total} ${total === 1 ? 'equipo' : 'equipos'} ${attention === 1 ? 'necesita' : 'necesitan'} atención`,
      tone: 'warning',
    };
  }
  if (counts.updating > 0) {
    return {
      total,
      counts,
      attention,
      headline: `${plural(counts.updating, 'equipo está', 'equipos están')} recibiendo la última política`,
      tone: 'primary',
    };
  }
  return {
    total,
    counts,
    attention,
    headline: total === 1 ? 'El equipo está protegido y al día' : `Los ${total} equipos están protegidos y al día`,
    tone: 'success',
  };
}

/** Cuántos equipos activos ya confirmaron la revisión indicada. */
export function rolloutProgress(endpoints: readonly DlpEndpoint[], revision: number): { applied: number; total: number } {
  const active = endpoints.filter((endpoint) => endpointHealth(endpoint) !== 'revoked');
  return {
    applied: active.filter((endpoint) => (endpoint.currentRevision ?? -1) >= revision).length,
    total: active.length,
  };
}

// ------------------------------------------------------------------ instalación

export type InstallOs = 'windows' | 'unix';

export interface InstallInput {
  readonly os: InstallOs;
  /** Origen público de la consola; el agente llama a `{origen}/api/dlp/agent/...`. */
  readonly controlPlaneUrl: string;
  readonly watchRoot: string;
  /** Solo Windows: el instalador lo exige aunque el agente Wazuh ya exista. */
  readonly wazuhManager: string;
  /** Solo Windows: SHA-256 del ZIP, recibido por un canal separado. */
  readonly packageSha256: string;
}

const quotePowerShell = (value: string) => `'${value.replace(/'/gu, "''")}'`;
const quoteShell = (value: string) => `'${value.replace(/'/gu, `'"'"'`)}'`;

/** Campos que faltan para que el comando funcione tal cual. */
export function missingInstallFields(input: InstallInput): string[] {
  const missing: string[] = [];
  if (!input.watchRoot.trim()) missing.push('la carpeta');
  if (input.os === 'windows') {
    if (!input.wazuhManager.trim()) missing.push('el servidor Wazuh');
    if (!/^[0-9a-f]{64}$/iu.test(input.packageSha256.trim())) missing.push('el SHA-256 del paquete');
  }
  return missing;
}

/**
 * Comando listo para pegar. La clave de instalación NO va en el comando: el instalador la pide
 * en una entrada oculta para que no quede en el historial ni en la lista de procesos.
 */
export function installCommand(input: InstallInput): string {
  const root = input.watchRoot.trim() || (input.os === 'windows' ? 'C:\\CARPETA\\APROBADA' : '/ruta/aprobada');
  const url = input.controlPlaneUrl.replace(/\/+$/u, '');
  if (input.os === 'windows') {
    return [
      '.\\install-windows-endpoint.ps1',
      '-RabbitDlpPackage .\\RabbitDLP-windows-x64.zip',
      `-ExpectedPackageSha256 ${input.packageSha256.trim().toLowerCase() || 'SHA256_DEL_PAQUETE'}`,
      `-WazuhManager ${quotePowerShell(input.wazuhManager.trim() || 'SERVIDOR_WAZUH')}`,
      `-WatchRoot ${quotePowerShell(root)}`,
      `-DlpControlPlaneUrl ${quotePowerShell(url)}`,
    ].join(' ');
  }
  return `sudo ./install-unix-endpoint.sh install --watch-root ${quoteShell(root)} --control-plane-url ${quoteShell(url)}`;
}

// ------------------------------------------------------------------ asistente de conexión

export type WizardState =
  | { readonly step: 'closed' }
  | { readonly step: 'create'; readonly busy: boolean; readonly error: unknown; readonly stepUp: boolean }
  | { readonly step: 'waiting'; readonly token: DlpEnrollmentToken }
  | { readonly step: 'connected'; readonly hostname: string; readonly endpointId: string }
  | { readonly step: 'expired' };

export type WizardEvent =
  | { readonly type: 'open' }
  | { readonly type: 'close' }
  | { readonly type: 'creating' }
  | { readonly type: 'created'; readonly token: DlpEnrollmentToken }
  | { readonly type: 'createFailed'; readonly error: unknown }
  | { readonly type: 'status'; readonly status: EnrollmentCheck }
  | { readonly type: 'tick'; readonly now: number };

export type EnrollmentCheck =
  | { readonly state: 'waiting' }
  | { readonly state: 'connected'; readonly hostname: string; readonly endpointId: string }
  | { readonly state: 'expired' }
  /** Error de red o del servidor: se reintenta en el siguiente sondeo sin molestar. */
  | { readonly state: 'unknown' };

export function wizardReducer(state: WizardState, event: WizardEvent): WizardState {
  switch (event.type) {
    case 'open':
      return state.step === 'waiting' ? state : { step: 'create', busy: false, error: null, stepUp: false };
    case 'close':
      return { step: 'closed' };
    case 'creating':
      return { step: 'create', busy: true, error: null, stepUp: false };
    case 'created':
      return { step: 'waiting', token: event.token };
    case 'createFailed': {
      const stepUp = event.error instanceof B89ApiError && event.error.code === 'STEP_UP_REQUIRED';
      return { step: 'create', busy: false, error: stepUp ? null : event.error, stepUp };
    }
    case 'status':
      if (state.step !== 'waiting') return state;
      if (event.status.state === 'connected') {
        return { step: 'connected', hostname: event.status.hostname, endpointId: event.status.endpointId };
      }
      if (event.status.state === 'expired') return { step: 'expired' };
      return state;
    case 'tick':
      if (state.step === 'waiting' && Date.parse(state.token.expiresAt) <= event.now) return { step: 'expired' };
      return state;
    default:
      return state;
  }
}

/** Consulta una vez si la clave ya se usó. Un 404 significa que la clave venció y se limpió. */
export async function checkEnrollment(api: B89ApiClient, id: string): Promise<EnrollmentCheck> {
  let status: DlpEnrollmentStatus;
  try {
    status = await getDlpEnrollmentStatus(api, id);
  } catch (error) {
    if (error instanceof B89ApiError && error.code === 'RESOURCE_UNAVAILABLE') {
      return { state: 'expired' };
    }
    return { state: 'unknown' };
  }
  if ((status.state === 'connected' || status.state === 'revoked') && status.endpoint) {
    return { state: 'connected', hostname: status.endpoint.hostname, endpointId: status.endpoint.id };
  }
  if (status.state === 'expired') return { state: 'expired' };
  return { state: 'waiting' };
}

export function minutesLeft(expiresAt: string, now: number): number {
  return Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 60_000));
}
