/**
 * Ficha 4 — canarios de casi-coincidencia contra la huella REAL del repo
 * (`modules/detection/src/fingerprint.ts`, solo lectura) y un modelo de la decisión del motor
 * según el diseño §7 (el motor aún no existe: la decisión de aquí es un modelo, no el código).
 *
 * Para cada patrón «aprobado» se inyectan variantes que difieren en UN componente o activan una
 * guarda. Invariante: ninguna variante se autocierra. La copia exacta sí se autocierra por
 * construcción: es el punto ciego de cualquier huella exacta y se reporta como tal.
 */

import { createHash } from 'node:crypto';

import {
  buildObservables,
  OBSERVABLES_EXTENSION_NAMESPACE,
  parseSecurityEvent,
  type ObservablesInput,
  type SecurityEvent,
} from '../../../packages/contracts/src/index.js';

import {
  computeFingerprint,
  differingComponents,
  type AlertFingerprint,
} from '../../../modules/detection/src/fingerprint.js';
import { mulberry32, pick, type Rng } from './rng.js';

const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
const hex = (rng: Rng, length: number) =>
  Array.from({ length }, () => Math.floor(rng.next() * 16).toString(16)).join('');
const guid = (rng: Rng) =>
  `${hex(rng, 8)}-${hex(rng, 4)}-${hex(rng, 4)}-${hex(rng, 4)}-${hex(rng, 12)}`.toUpperCase();

export interface Behavior {
  readonly ruleId: string;
  readonly ruleName: string;
  readonly user: string;
  readonly agentId: string;
  readonly image: string;
  readonly parent: string;
  readonly script: string;
  readonly sha256: string;
  readonly domain: string;
  readonly port: number;
}

const IMAGES = [
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  'C:\\Windows\\System32\\cmd.exe',
  'C:\\Program Files\\Veeam\\agent.exe',
  'C:\\Windows\\System32\\schtasks.exe',
];
const PARENTS = ['C:\\Windows\\explorer.exe', 'C:\\Windows\\System32\\services.exe'];
const DOMAINS = ['backup.b89.example', 'updates.vendor.example', 'api.b89.example'];

export function randomBehavior(rng: Rng): Behavior {
  return {
    ruleId: String(101140 + Math.floor(rng.next() * 50)),
    ruleName: `B89 Windows: caso ${Math.floor(rng.next() * 1000)}`,
    user: `svc_${hex(rng, 4)}@b89.example`,
    agentId: String(100 + Math.floor(rng.next() * 800)),
    image: pick(rng, IMAGES),
    parent: pick(rng, PARENTS),
    script: `job_${hex(rng, 3)}`,
    sha256: hex(rng, 64),
    domain: pick(rng, DOMAINS),
    port: pick(rng, [443, 8443, 22, 3389]),
  };
}

/**
 * Evento con las partes variables aleatorias (timestamp, GUID, archivo temporal, perfil de usuario
 * en la ruta, puerto de origen efímero): no deben cambiar la huella.
 */
export function eventFor(behavior: Behavior, rng: Rng): SecurityEvent {
  const day = 1 + Math.floor(rng.next() * 27);
  const iso = `2026-11-${String(day).padStart(2, '0')}T${String(Math.floor(rng.next() * 24)).padStart(2, '0')}:00:00Z`;
  const profile = `user${hex(rng, 3)}`;
  const observed: ObservablesInput = {
    agentId: behavior.agentId,
    processImage: behavior.image,
    parentImage: behavior.parent,
    commandLine: `${behavior.image} -File C:\\Users\\${profile}\\AppData\\Local\\Temp\\tmp${hex(rng, 4).toUpperCase()}.ps1 -Name ${behavior.script} -Run {${guid(rng)}} -At ${iso}`,
    processSha256: `SHA256=${behavior.sha256}`,
    destinationDomain: behavior.domain,
    destinationPort: behavior.port,
  };
  const extension = buildObservables(observed, sha);
  const recordId = `0189${hex(rng, 4)}-7abc-7def-8abc-${hex(rng, 12)}`;
  return parseSecurityEvent({
    schemaVersion: '1.0.0',
    recordId,
    eventUid: `lab:alerts:${recordId}`,
    eventUidType: 'native',
    kind: 'alert',
    occurredAt: iso.replace('Z', '.000Z'),
    observedAt: iso.replace('Z', '.000Z'),
    receivedAt: iso.replace('Z', '.000Z'),
    source: {
      kind: 'siem',
      vendor: 'Lab',
      product: 'Wazuh',
      dataset: 'alerts',
      instanceId: 'lab',
      nativeEventId: recordId,
    },
    tenant: { id: 'tenant-lab' },
    severity: {
      normalized: 'low',
      score: 20,
      originalValue: 4,
      originalLabel: '4',
      originalScale: 'provider-level-0-15',
      mappingId: 'lab',
      mappingVersion: '1.0.0',
    },
    category: ['process'],
    outcome: 'unknown',
    entities: {
      identities: [{ kind: 'user', principal: behavior.user }],
      resources: [{ kind: 'host', id: behavior.agentId, type: 'endpoint' }],
    },
    detection: {
      rule: { id: behavior.ruleId, name: behavior.ruleName, provider: 'wazuh', groups: [] },
    },
    raw: {
      ref: `raw:lab/${recordId}`,
      sha256: 'a'.repeat(64),
      mediaType: 'application/json',
      sizeBytes: 100,
    },
    provenance: {
      connector: 'lab',
      connectorVersion: '1.0.0',
      parserVersion: '1.0.0',
      mappingVersion: '1.0.0',
      timestampQuality: 'source',
      ingestionPath: [
        { kind: 'collector', vendor: 'Lab', product: 'Wazuh' },
        { kind: 'adapter', vendor: 'B89', product: 'B89 SecOps' },
      ],
    },
    ...(extension ? { extensions: { [OBSERVABLES_EXTENSION_NAMESPACE]: extension } } : {}),
  });
}

/* --------------------------------------------- Modelo de la decisión (diseño §7) */

export interface AlertContext {
  readonly priority: 'P1' | 'P2' | 'P3' | 'P4';
  readonly criticalAsset: boolean;
  readonly privilegedIdentity: boolean;
}

export type Decision = 'AUTO_CLOSE' | 'ESCALATE_DRIFT' | 'ESCALATE_GUARD' | 'NONE';

export function decide(
  fingerprint: AlertFingerprint,
  context: AlertContext,
  approved: ReadonlyMap<string, AlertFingerprint>,
): Decision {
  const exact = approved.get(fingerprint.fingerprint);
  if (exact && differingComponents(exact.components, fingerprint.components).length === 0) {
    if (fingerprint.level !== 'fine') return 'NONE';
    if (context.priority !== 'P4' || context.criticalAsset || context.privilegedIdentity) {
      return 'ESCALATE_GUARD';
    }
    return 'AUTO_CLOSE';
  }
  // Casi coincidencia: misma regla y (mismo sujeto o mismo comportamiento) que un patrón aprobado.
  for (const pattern of approved.values()) {
    if (pattern.ruleKey !== fingerprint.ruleKey) continue;
    const diff = differingComponents(pattern.components, fingerprint.components);
    if (diff.length > 0 && diff.length <= 3) return 'ESCALATE_DRIFT';
  }
  return 'NONE';
}

/* ------------------------------------------------------------- Experimento */

export const CANARY_VARIANTS = [
  'copia exacta',
  'otro hash',
  'otro destino',
  'otro puerto',
  'otro usuario',
  'otro equipo',
  'otro proceso padre',
  'otra línea de comando',
  'misma huella, prioridad P2',
  'misma huella, activo crítico',
  'misma huella, identidad privilegiada',
] as const;
export type CanaryVariant = (typeof CANARY_VARIANTS)[number];

function variant(
  behavior: Behavior,
  kind: CanaryVariant,
  rng: Rng,
): { behavior: Behavior; context: AlertContext } {
  const context: AlertContext = { priority: 'P4', criticalAsset: false, privilegedIdentity: false };
  switch (kind) {
    case 'otro hash':
      return { behavior: { ...behavior, sha256: hex(rng, 64) }, context };
    case 'otro destino':
      return {
        behavior: { ...behavior, domain: `exfil-${hex(rng, 4)}.attacker.example` },
        context,
      };
    case 'otro puerto':
      return { behavior: { ...behavior, port: behavior.port === 443 ? 8443 : 443 }, context };
    case 'otro usuario':
      return { behavior: { ...behavior, user: `admin_${hex(rng, 4)}@b89.example` }, context };
    case 'otro equipo':
      return {
        behavior: { ...behavior, agentId: String(900 + Math.floor(rng.next() * 99)) },
        context,
      };
    case 'otro proceso padre':
      return {
        behavior: {
          ...behavior,
          parent: behavior.parent.endsWith('explorer.exe') ? PARENTS[1]! : PARENTS[0]!,
        },
        context,
      };
    case 'otra línea de comando':
      return { behavior: { ...behavior, script: `dump_${hex(rng, 3)}` }, context };
    case 'misma huella, prioridad P2':
      return { behavior, context: { ...context, priority: 'P2' } };
    case 'misma huella, activo crítico':
      return { behavior, context: { ...context, criticalAsset: true } };
    case 'misma huella, identidad privilegiada':
      return { behavior, context: { ...context, privilegedIdentity: true } };
    default:
      return { behavior, context };
  }
}

export interface CanaryResult {
  readonly variant: CanaryVariant;
  readonly injected: number;
  readonly autoClosed: number;
  readonly escalated: number;
}

export function runCanaries(seed: number, patterns: number): CanaryResult[] {
  const rng = mulberry32(seed);
  const behaviors = Array.from({ length: patterns }, () => randomBehavior(rng));
  const approved = new Map<string, AlertFingerprint>();
  for (const behavior of behaviors) {
    const fingerprint = computeFingerprint(eventFor(behavior, rng));
    approved.set(fingerprint.fingerprint, fingerprint);
  }
  return CANARY_VARIANTS.map((kind) => {
    let autoClosed = 0;
    let escalated = 0;
    for (const behavior of behaviors) {
      const { behavior: changed, context } = variant(behavior, kind, rng);
      const decision = decide(computeFingerprint(eventFor(changed, rng)), context, approved);
      if (decision === 'AUTO_CLOSE') autoClosed += 1;
      if (decision === 'ESCALATE_DRIFT' || decision === 'ESCALATE_GUARD') escalated += 1;
    }
    return { variant: kind, injected: behaviors.length, autoClosed, escalated };
  });
}
