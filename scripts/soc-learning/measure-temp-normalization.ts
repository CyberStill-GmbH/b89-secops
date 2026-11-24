/**
 * Mide la estabilidad de la huella ante nombres de archivos temporales (solo lectura).
 *
 * Genera B comportamientos y R repeticiones de cada uno; en cada repetición el script temporal
 * recibe un nombre aleatorio con el estilo de un generador real:
 *   - `GetTempFileName`: `tmp` + 4 hex en mayúsculas (`tmpCBBF.tmp`, `tmp4F2A.tmp`)
 *   - `GetRandomFileName`: 8 caracteres [a-z0-5] (`xkq3z1ab`)
 *   - `mktemp` (Linux): `tmp.` + 10 de [A-Za-z0-9] (`tmp.aBcD3fGh9K`)
 * Ideal: 1 huella por comportamiento. Imprime huellas por comportamiento, grupos resultantes y el
 * % de repeticiones que no coinciden con la huella mayoritaria de su comportamiento.
 *
 *   pnpm exec tsx --conditions=development scripts/soc-learning/measure-temp-normalization.ts
 */

import { createHash } from 'node:crypto';

import {
  buildObservables,
  OBSERVABLES_EXTENSION_NAMESPACE,
  OBSERVABLES_NORMALIZER_VERSION,
  parseSecurityEvent,
  type SecurityEvent,
} from '../../packages/contracts/src/index.js';
import { computeFingerprint } from '../../modules/detection/src/fingerprint.js';

const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

let state = 20261124;
function random(): number {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const choose = (alphabet: string, length: number) =>
  Array.from({ length }, () => alphabet[Math.floor(random() * alphabet.length)]).join('');

type Style = 'gettempfilename' | 'getrandomfilename' | 'mktemp';
const STYLES: readonly Style[] = ['gettempfilename', 'getrandomfilename', 'mktemp'];

function tempPath(style: Style): string {
  switch (style) {
    case 'gettempfilename':
      return `C:\\Users\\svc\\AppData\\Local\\Temp\\tmp${choose('0123456789ABCDEF', 4)}.ps1`;
    case 'getrandomfilename':
      return `C:\\Windows\\Temp\\${choose('abcdefghijklmnopqrstuvwxyz012345', 8)}.ps1`;
    default:
      return `/tmp/tmp.${choose('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 10)}.sh`;
  }
}

function event(behavior: number, style: Style): SecurityEvent {
  const linux = style === 'mktemp';
  const image = linux
    ? '/usr/bin/bash'
    : 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const extension = buildObservables(
    {
      agentId: String(100 + behavior),
      processImage: image,
      commandLine: `${image} ${linux ? '' : '-File '}${tempPath(style)} --job ${behavior}`,
      destinationDomain: `svc${behavior}.b89.example`,
      destinationPort: 443,
    },
    sha,
  );
  const id = `0189${choose('0123456789abcdef', 4)}-7abc-7def-8abc-${choose('0123456789abcdef', 12)}`;
  return parseSecurityEvent({
    schemaVersion: '1.0.0',
    recordId: id,
    eventUid: `m:${id}`,
    eventUidType: 'native',
    kind: 'alert',
    occurredAt: '2026-11-24T00:00:00.000Z',
    observedAt: '2026-11-24T00:00:00.000Z',
    receivedAt: '2026-11-24T00:00:00.000Z',
    source: { kind: 'siem', vendor: 'M', product: 'Wazuh', dataset: 'alerts', instanceId: 'm' },
    tenant: { id: 't' },
    severity: {
      normalized: 'low',
      originalValue: 4,
      originalLabel: '4',
      originalScale: 's',
      mappingId: 'm',
      mappingVersion: '1.0.0',
    },
    category: ['process'],
    outcome: 'unknown',
    entities: { identities: [{ kind: 'user', principal: `u${behavior}` }], resources: [] },
    detection: { rule: { id: '101150', name: 'r', provider: 'wazuh', groups: [] } },
    raw: { ref: 'raw:m', sha256: 'a'.repeat(64), mediaType: 'application/json', sizeBytes: 1 },
    provenance: {
      connector: 'm',
      connectorVersion: '1.0.0',
      parserVersion: '1.0.0',
      mappingVersion: '1.0.0',
      timestampQuality: 'source',
      ingestionPath: [{ kind: 'collector', vendor: 'M', product: 'Wazuh' }],
    },
    ...(extension ? { extensions: { [OBSERVABLES_EXTENSION_NAMESPACE]: extension } } : {}),
  });
}

const BEHAVIORS = 200;
const REPEATS = 20;
console.log(
  `normalizador v${OBSERVABLES_NORMALIZER_VERSION} · ${BEHAVIORS} comportamientos × ${REPEATS} repeticiones por estilo`,
);
console.log(
  '| Estilo | Huellas por comportamiento (media) | Huellas distintas (grupos) | Repeticiones fuera de la huella mayoritaria |',
);
console.log('|---|---:|---:|---:|');
for (const style of STYLES) {
  let distinctTotal = 0;
  let outliers = 0;
  for (let behavior = 0; behavior < BEHAVIORS; behavior += 1) {
    const counts = new Map<string, number>();
    for (let repeat = 0; repeat < REPEATS; repeat += 1) {
      const fingerprint = computeFingerprint(event(behavior, style)).fingerprint;
      counts.set(fingerprint, (counts.get(fingerprint) ?? 0) + 1);
    }
    distinctTotal += counts.size;
    outliers += REPEATS - Math.max(...counts.values());
  }
  console.log(
    `| ${style} | ${(distinctTotal / BEHAVIORS).toFixed(2)} | ${distinctTotal} (ideal ${BEHAVIORS}) | ${((100 * outliers) / (BEHAVIORS * REPEATS)).toFixed(1)} % |`,
  );
}
