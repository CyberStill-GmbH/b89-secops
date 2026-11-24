import { describe, expect, it } from 'vitest';

import type { AlertFingerprint, DetectionCandidate } from '@b89/detection';

import { InMemorySoc } from '../src/memory-unit-of-work.js';
import { ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const AT = new Date('2026-11-24T10:00:00.000Z');

const FINGERPRINT: AlertFingerprint = {
  fingerprint: `fp1_${'a'.repeat(64)}`,
  level: 'fine',
  version: '1',
  normalizerVersion: '1',
  ruleKey: 'windows:101150',
  components: {
    ruleKey: 'windows:101150',
    ruleName: 'b89 windows: powershell con script temporal',
    user: 'ana@b89.example',
    host: '017',
    srcIp: null,
    processImage: 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe',
    parentImage: null,
    commandLine: 'powershell.exe -file {TMP}\\tmp{N}.ps{N}',
    sha256: null,
    filePath: null,
    destination: null,
    destinationPort: null,
  },
};

function candidate(overrides: Partial<DetectionCandidate> = {}): DetectionCandidate {
  return {
    id: '0199bf11-0000-7000-8000-0000000000c1',
    tenantId: 'tenant-1',
    eventRecordId: '01890f47-7abc-7def-8abc-0123456789ee',
    eventUid: 'evt-fp-1',
    idempotencyKey: 'key-fp-1',
    priority: 'P4',
    score: 35,
    reasons: [],
    rulesetId: 'b89.detection.prioritization',
    rulesetVersion: '1.1.0',
    occurredAt: AT,
    createdAt: AT,
    title: 'PowerShell con script temporal',
    entityKeys: [],
    signal: 'other',
    ruleId: '101150',
    relatedAlertIds: [],
    ...overrides,
  };
}

function dependencies(soc: InMemorySoc): SocDependencies {
  let sequence = 0;
  return {
    unitOfWork: soc,
    clock: { now: () => AT },
    ids: {
      next: () => {
        sequence += 1;
        return `0199bf22-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
      },
    },
  };
}

describe('Aprendizaje SOC · etapa B · huella persistida con la alerta', () => {
  it('guarda la huella una sola vez, aunque la ingesta se repita', async () => {
    const soc = new InMemorySoc();
    const target = candidate({ fingerprint: FINGERPRINT });
    await ingestCandidate(dependencies(soc), target);
    await ingestCandidate(dependencies(soc), target);
    expect([...soc.fingerprintRows.values()]).toEqual([
      { ...FINGERPRINT, alertId: target.id, tenantId: 'tenant-1', computedAt: AT },
    ]);
  });

  it('un candidato sin huella (p. ej. del correlador) no deja fila', async () => {
    const soc = new InMemorySoc();
    await ingestCandidate(dependencies(soc), candidate());
    expect(soc.fingerprintRows.size).toBe(0);
    expect(soc.alertRows.size).toBe(1);
  });

  it('si la transacción falla, no queda ni la alerta ni la huella', async () => {
    const soc = new InMemorySoc();
    soc.failNextCommit = true;
    await expect(
      ingestCandidate(dependencies(soc), candidate({ fingerprint: FINGERPRINT })),
    ).rejects.toThrow('COMMIT_FAILED');
    expect(soc.fingerprintRows.size).toBe(0);
    expect(soc.alertRows.size).toBe(0);
  });
});
