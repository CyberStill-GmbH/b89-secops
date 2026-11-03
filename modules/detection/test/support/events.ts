/**
 * Constructor de SecurityEvent para las specs de C-16.
 *
 * Cada evento se valida contra el contrato 1.0.0 antes de usarse: una spec de
 * priorización que corriera sobre un evento inválido estaría probando una entrada que
 * el pipeline nunca produce.
 */

import { parseSecurityEvent, type SecurityEvent } from '@b89/contracts';

type Mutable = {
  -readonly [K in keyof SecurityEvent]: SecurityEvent[K];
};

const BASE: SecurityEvent = parseSecurityEvent({
  schemaVersion: '1.0.0',
  recordId: '01890f47-7abc-7def-8abc-0123456789ab',
  eventUid: 'siem-b89-lab:alerts:evt-0001',
  eventUidType: 'native',
  kind: 'alert',
  occurredAt: '2026-10-07T15:30:00.000Z',
  observedAt: '2026-10-07T15:30:01.000Z',
  receivedAt: '2026-10-07T15:30:02.000Z',
  source: {
    kind: 'siem',
    vendor: 'Wazuh, Inc.',
    product: 'Wazuh',
    dataset: 'alerts',
    instanceId: 'siem-b89-lab',
    nativeEventId: 'evt-0001',
  },
  tenant: { id: 'tenant-1' },
  severity: {
    normalized: 'medium',
    score: 50,
    originalValue: 8,
    originalLabel: 'medium',
    originalScale: 'wazuh-level-0-15',
    mappingId: 'b89.wazuh.severity',
    mappingVersion: '1.0.0',
  },
  category: ['intrusion_detection'],
  outcome: 'unknown',
  action: 'alert.created',
  entities: {
    identities: [{ kind: 'user', id: 'identity-1', principal: 'jperez@b89.example' }],
    resources: [{ kind: 'host', id: 'host-1', name: 'srv-app-01.b89.local', type: 'endpoint' }],
  },
  detection: {
    rule: {
      id: '5716',
      name: 'Intento de autenticación fallido',
      version: '1',
      provider: 'wazuh',
      groups: ['sshd', 'authentication_failed'],
    },
  },
  raw: {
    ref: 'raw:tenant-1/2026/10/07/evt-0001',
    sha256: 'a'.repeat(64),
    mediaType: 'application/json',
    sizeBytes: 2048,
  },
  provenance: {
    connector: 'b89-wazuh-indexer',
    connectorVersion: '1.0.0',
    parserVersion: '1.0.0',
    mappingVersion: '1.0.0',
    timestampQuality: 'source',
    ingestionPath: [
      { kind: 'collector', vendor: 'Wazuh, Inc.', product: 'Wazuh', instanceId: 'siem-b89-lab' },
      { kind: 'adapter', vendor: 'B89', product: 'B89 SecOps' },
    ],
  },
});

export function securityEvent(overrides: Partial<Mutable> = {}): SecurityEvent {
  return parseSecurityEvent({
    ...structuredClone(BASE),
    ...structuredClone(overrides as Mutable),
  });
}

export function withSeverity(
  normalized: SecurityEvent['severity']['normalized'],
  overrides: Partial<Mutable> = {},
): SecurityEvent {
  return securityEvent({
    severity: { ...BASE.severity, normalized, originalLabel: normalized },
    ...overrides,
  });
}
