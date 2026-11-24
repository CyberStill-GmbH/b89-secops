import { describe, expect, it } from 'vitest';

import { OBSERVABLES_EXTENSION_NAMESPACE } from '@b89/contracts';

import {
  normalizeWazuhAlert,
  type WazuhAlertInput,
  type WazuhNormalizationContext,
} from '../src/wazuh-normalization.js';

const context: WazuhNormalizationContext = {
  tenantId: 'tenant-b89-001',
  instanceId: 'siem-b89-lab',
  connector: 'wazuh-indexer',
  connectorVersion: '1.0.0',
  receivedAt: new Date('2026-11-24T12:00:00.000Z'),
};

function alert(raw: Record<string, unknown>, suffix = '01'): WazuhAlertInput {
  return {
    record: {
      sourceRecordId: `evt-obs-${suffix}`,
      dataset: 'alerts',
      collectedAt: '2026-11-24T11:59:30.000Z',
      raw: {
        timestamp: '2026-11-24T11:59:00.000Z',
        rule: {
          id: 101150,
          level: 7,
          description: 'B89 Windows: proceso sospechoso',
          groups: ['windows', 'sysmon'],
          mitre: { id: ['T1059.001'], tactic: ['Execution'] },
        },
        agent: { id: '017', name: 'ws-017.b89.local' },
        ...raw,
      },
    },
    raw: {
      ref: `raw:tenant-b89-001/2026/11/24/evt-obs-${suffix}`,
      sha256: `${suffix.padStart(2, '0').repeat(32)}`.slice(0, 64),
      mediaType: 'application/json',
      sizeBytes: 2048,
    },
  };
}

function observablesOf(input: WazuhAlertInput) {
  const outcome = normalizeWazuhAlert(input, context);
  if (outcome.status !== 'normalized') throw new Error(`cuarentena: ${JSON.stringify(outcome)}`);
  return {
    event: outcome.event,
    observables: outcome.event.extensions?.[OBSERVABLES_EXTENSION_NAMESPACE],
  };
}

describe('mapping 1.4.0 · extensión b89.observables', () => {
  it('Sysmon: proceso, padre, hash, destino y MITRE, con la línea redactada', () => {
    const { event, observables } = observablesOf(
      alert({
        data: {
          win: {
            eventdata: {
              image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe',
              parentImage: 'C:\\Windows\\explorer.exe',
              commandLine: 'powershell.exe -NoP -Command Connect -Password Hunter2! -Id 4242',
              hashes: `MD5=${'a'.repeat(32)},SHA256=${'B'.repeat(64)}`,
              destinationIp: '203.0.113.50',
              destinationPort: '443',
              destinationHostname: 'Updates.Example.com',
            },
          },
        },
      }),
    );
    expect(event.provenance.mappingVersion).toBe('1.4.0');
    expect(observables).toMatchObject({
      v: 1,
      agentId: '017',
      process: {
        image: 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe',
        sha256: 'b'.repeat(64),
      },
      parent: { image: 'c:\\windows\\explorer.exe' },
      destination: { ip: '203.0.113.50', port: 443, domain: 'updates.example.com' },
      mitre: { techniques: ['T1059.001'], tactics: ['execution'] },
    });
    expect(JSON.stringify(event)).not.toContain('Hunter2!');
  });

  it('auditd: la línea se arma con execve en orden', () => {
    const { observables } = observablesOf(
      alert(
        {
          rule: { id: 80792, level: 3, description: 'Audit: command', groups: ['audit'] },
          data: {
            audit: {
              exe: '/usr/bin/curl',
              execve: { a0: 'curl', a1: '-s', a2: 'https://x.example' },
            },
          },
        },
        '02',
      ),
    );
    expect(observables).toMatchObject({
      process: { image: '/usr/bin/curl', commandLine: 'curl -s https://x.example' },
    });
  });

  it('una alerta sin observables de comportamiento ni MITRE no lleva la extensión', () => {
    const { event } = observablesOf(
      alert(
        {
          rule: {
            id: 5716,
            level: 10,
            description: 'SSHD authentication failed',
            groups: ['sshd'],
          },
          data: { srcuser: 'ana', srcip: '10.0.0.5' },
        },
        '03',
      ),
    );
    expect(event.extensions).toBeUndefined();
  });

  it('el puerto efímero y los valores mal formados se descartan sin poner en cuarentena', () => {
    const { observables } = observablesOf(
      alert(
        {
          data: { dstip: 'no-es-ip', dstport: 51515, win: { eventdata: { hashes: 'basura' } } },
        },
        '04',
      ),
    );
    // Queda solo MITRE de la regla.
    expect(observables).toEqual({
      v: 1,
      normalizer: '1',
      agentId: '017',
      mitre: { techniques: ['T1059.001'], tactics: ['execution'] },
    });
  });
});
