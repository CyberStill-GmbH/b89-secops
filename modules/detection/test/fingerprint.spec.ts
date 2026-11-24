import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  buildObservables,
  OBSERVABLES_EXTENSION_NAMESPACE,
  OBSERVABLES_NORMALIZER_VERSION,
  type ObservablesInput,
  type SecurityEvent,
} from '@b89/contracts';

import { canonicalJson, computeFingerprint, differingComponents } from '../src/fingerprint.js';
import { RULE_SOURCE_RANGES, ruleKeyOf } from '../src/rule-key.js';
import { securityEvent } from './support/events.js';

const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

const BASE_OBSERVED: ObservablesInput = {
  agentId: '017',
  processImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  parentImage: 'C:\\Program Files\\Veeam\\agent.exe',
  commandLine:
    'powershell.exe -File C:\\Users\\svc_backup\\AppData\\Local\\Temp\\tmp4F2A.ps1 -Job {3F2504E0-4F89-11D3-9A0C-0305E82C3301} -At 2026-11-24T02:00:00Z',
  processSha256: `SHA256=${'c'.repeat(64)}`,
  destinationDomain: 'backup.b89.example',
  destinationPort: 443,
};

function withObservables(
  observed: ObservablesInput = BASE_OBSERVED,
  overrides: Parameters<typeof securityEvent>[0] = {},
): SecurityEvent {
  const extension = buildObservables(observed, sha);
  return securityEvent({
    detection: {
      rule: {
        id: '101150',
        name: 'B89 Windows: PowerShell con script temporal',
        provider: 'wazuh',
        groups: ['windows', 'sysmon'],
      },
    },
    ...(extension ? { extensions: { [OBSERVABLES_EXTENSION_NAMESPACE]: extension as never } } : {}),
    ...overrides,
  });
}

describe('Aprendizaje SOC · etapa B · huella', () => {
  it('es determinista y fina con sujeto y comportamiento', () => {
    const first = computeFingerprint(withObservables());
    const second = computeFingerprint(withObservables());
    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.fingerprint).toMatch(/^fp1_[0-9a-f]{64}$/u);
    expect(first.level).toBe('fine');
    expect(first.ruleKey).toBe('windows:101150');
    expect(first.components).toMatchObject({
      user: 'jperez@b89.example',
      host: '017',
      destination: 'backup.b89.example',
      destinationPort: '443',
      sha256: 'c'.repeat(64),
    });
  });

  it('misma alerta con otro PID, timestamp, GUID, ruta temporal, perfil y puerto efímero ⇒ misma huella', () => {
    const variant = withObservables(
      {
        ...BASE_OBSERVED,
        commandLine:
          'POWERSHELL.EXE -File c:\\users\\otro\\appdata\\local\\temp\\tmp9C71.ps1 -Job {6BA7B810-9DAD-11D1-80B4-00C04FD430C8} -At 2026-11-25T02:00:07Z',
      },
      {
        recordId: '01890f47-7abc-7def-8abc-0123456789ff',
        eventUid: 'siem-b89-lab:alerts:evt-9999',
        occurredAt: '2026-11-25T02:00:07.000Z',
      },
    );
    expect(computeFingerprint(variant).fingerprint).toBe(
      computeFingerprint(withObservables()).fingerprint,
    );
  });

  it.each([
    [
      'otro usuario',
      {},
      {
        entities: {
          identities: [{ kind: 'user', principal: 'otra.persona@b89.example' }],
          resources: [{ kind: 'host', id: 'host-1', type: 'endpoint' }],
        },
      },
      'user',
    ],
    ['otro equipo', { agentId: '042' }, {}, 'host'],
    ['otro hash', { processSha256: 'd'.repeat(64) }, {}, 'sha256'],
    ['otro destino', { destinationDomain: 'exfil.attacker.example' }, {}, 'destination'],
    ['otro puerto', { destinationPort: 8443 }, {}, 'destinationPort'],
    [
      'otra línea de comando',
      { commandLine: 'powershell.exe -File C:\\Temp\\dump.ps1 -Out lsass.dmp' },
      {},
      'commandLine',
    ],
    ['otro proceso padre', { parentImage: 'C:\\Windows\\System32\\cmd.exe' }, {}, 'parentImage'],
  ] as const)('%s ⇒ huella distinta', (_label, observed, overrides, component) => {
    const base = computeFingerprint(withObservables());
    const changed = computeFingerprint(
      withObservables({ ...BASE_OBSERVED, ...observed }, overrides as never),
    );
    expect(changed.fingerprint).not.toBe(base.fingerprint);
    expect(differingComponents(base.components, changed.components)).toContain(component);
  });

  it('adversarial: imitar proceso y padre de un FP conocido con otro hash y destino no hereda la huella', () => {
    const legit = computeFingerprint(withObservables());
    const mimic = computeFingerprint(
      withObservables({
        ...BASE_OBSERVED,
        processSha256: 'e'.repeat(64),
        destinationDomain: 'backup-b89.example.net',
      }),
    );
    expect(mimic.fingerprint).not.toBe(legit.fingerprint);
    expect(differingComponents(legit.components, mimic.components)).toEqual([
      'sha256',
      'destination',
    ]);
  });

  it('sin observables de comportamiento la huella es gruesa', () => {
    const coarse = computeFingerprint(securityEvent());
    expect(coarse.level).toBe('coarse');
    expect(coarse.ruleKey).toBe('wazuh:5716');
  });

  it('sin sujeto (ni usuario ni equipo ni IP) también es gruesa', () => {
    const event = withObservables(BASE_OBSERVED, {
      entities: { identities: [], resources: [] },
    });
    const noAgent = withObservables(
      { ...BASE_OBSERVED, agentId: undefined },
      {
        entities: { identities: [], resources: [] },
      },
    );
    expect(computeFingerprint(event).level).toBe('fine');
    expect(computeFingerprint(noAgent).level).toBe('coarse');
  });

  it('el tenant entra en la huella', () => {
    const own = computeFingerprint(withObservables());
    const other = computeFingerprint(
      withObservables(BASE_OBSERVED, { tenant: { id: 'tenant-2' } }),
    );
    expect(other.fingerprint).not.toBe(own.fingerprint);
    expect(differingComponents(own.components, other.components)).toEqual([]);
  });

  it('un secreto en la línea de comando nunca llega a los componentes', () => {
    const result = computeFingerprint(
      withObservables({ ...BASE_OBSERVED, commandLine: 'sqlcmd -S db -U sa --password Hunter2!' }),
    );
    expect(JSON.stringify(result)).not.toContain('Hunter2!');
    expect(result.components.commandLine).toContain('{REDACTED}');
  });
});

describe('Aprendizaje SOC · etapa B · clave de regla', () => {
  it('el mismo ID desde dos fuentes da claves distintas', () => {
    const wazuh = securityEvent({
      detection: { rule: { id: '101510', name: 'x', provider: 'wazuh', groups: [] } },
    });
    const anomaly = securityEvent({
      detection: {
        rule: { id: '101510', name: 'x', provider: 'OpenSearch Anomaly Detection', groups: [] },
      },
    });
    expect(ruleKeyOf(wazuh)).toBe('cloudflare:101510');
    expect(ruleKeyOf(anomaly)).toBe('opensearch-anomaly-detection:101510');
  });

  it('respeta el espacio de nombres del correlador y cae al proveedor de origen fuera de rango', () => {
    expect(
      ruleKeyOf(
        securityEvent({
          detection: {
            rule: { id: 'b89-correlator:edge-to-ssh', name: 'x', provider: 'wazuh', groups: [] },
          },
        }),
      ),
    ).toBe('b89-correlator:edge-to-ssh');
    expect(
      ruleKeyOf(
        securityEvent({
          detection: { rule: { id: '109999', name: 'x', provider: 'wazuh', groups: [] } },
        }),
      ),
    ).toBe('wazuh-custom:109999');
  });

  it('la tabla de rangos viene del catálogo (generada y comprobada en tests/architecture/rule-ids.spec.ts)', () => {
    expect(RULE_SOURCE_RANGES.length).toBeGreaterThan(0);
    expect(RULE_SOURCE_RANGES.find((range) => range.from === 101500)?.source).toBe('cloudflare');
  });
});

describe('Normalizador v2 · temporales: determinismo, versión y adversario', () => {
  /** Generador con semilla (mulberry32): reproducible. */
  function generator(seed: number) {
    let state = seed >>> 0;
    const next = () => {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const choose = (alphabet: string, length: number) =>
      Array.from({ length }, () => alphabet[Math.floor(next() * alphabet.length)]).join('');
    return { next, choose };
  }

  /** Nombres de temporales como los de GetTempFileName (hex, cualquier caso) y mktemp. */
  function tempName(g: ReturnType<typeof generator>, style: number): string {
    if (style === 0) return `C:\\Windows\\Temp\\tmp${g.choose('0123456789abcdefABCDEF', 4)}.ps1`;
    if (style === 1) {
      return `C:\\Users\\u${g.choose('abc123', 3)}\\AppData\\Local\\Temp\\${g.choose('abcdef0123456789', 6)}${g.choose('0123456789', 2)}.ps1`;
    }
    return `/tmp/tmp.${g.choose('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 10)}`;
  }

  function withTemp(script: string, overrides: Partial<ObservablesInput> = {}) {
    return withObservables({
      ...BASE_OBSERVED,
      commandLine: `powershell.exe -File ${script} -Job nightly`,
      ...overrides,
    });
  }

  it('regresión: 1000 pares del mismo comportamiento con temporales aleatorios dan la misma huella', () => {
    const g = generator(20261124);
    const mismatches: string[] = [];
    for (let i = 0; i < 1000; i += 1) {
      const style = i % 3;
      const left = computeFingerprint(withTemp(tempName(g, style)));
      const right = computeFingerprint(withTemp(tempName(g, style)));
      if (left.fingerprint !== right.fingerprint) {
        mismatches.push(`${left.components.commandLine} ≠ ${right.components.commandLine}`);
      }
    }
    // v1 fallaba aquí (letras hex sin dígito, mktemp): ver docs/soc-learning/15-normalizador-v2.md.
    expect(mismatches.slice(0, 3), `${mismatches.length} de 1000 pares difieren`).toEqual([]);
  });

  it('la versión del normalizador entra en la huella: misma entrada con v1 daría otro hash', () => {
    const fingerprint = computeFingerprint(withObservables());
    expect(fingerprint.normalizerVersion).toBe(OBSERVABLES_NORMALIZER_VERSION);
    expect(OBSERVABLES_NORMALIZER_VERSION).toBe('2');
    const digest = (normalizer: string) =>
      createHash('sha256')
        .update(
          canonicalJson({
            v: fingerprint.version,
            normalizer,
            tenant: 'tenant-1',
            level: fingerprint.level,
            components: fingerprint.components,
          }),
          'utf8',
        )
        .digest('hex');
    expect(fingerprint.fingerprint).toBe(`fp1_${digest('2')}`);
    expect(digest('1')).not.toBe(digest('2'));
  });

  it('adversario: copia la línea de un temporal legítimo (misma tras normalizar) pero no hereda la huella', () => {
    const legit = computeFingerprint(withTemp('C:\\Windows\\Temp\\tmpcbbf.ps1'));
    const attacks = {
      'otro hash': { processSha256: 'e'.repeat(64) },
      'otro destino': { destinationDomain: 'exfil.attacker.example' },
      'otro proceso padre': { parentImage: 'C:\\Windows\\System32\\cmd.exe' },
    } satisfies Record<string, Partial<ObservablesInput>>;
    for (const [label, overrides] of Object.entries(attacks)) {
      // El atacante elige su propio nombre temporal: normaliza igual que el legítimo…
      const attack = computeFingerprint(withTemp('C:\\Windows\\Temp\\tmp9e1d.ps1', overrides));
      expect(attack.components.commandLine, label).toBe(legit.components.commandLine);
      // …pero hash, destino y padre siguen en la huella: no colisiona.
      expect(attack.fingerprint, label).not.toBe(legit.fingerprint);
      expect(differingComponents(legit.components, attack.components).length, label).toBe(1);
    }
  });

  it('un script con nombre con significado distinto en el temporal no se fusiona', () => {
    const backup = computeFingerprint(withTemp('C:\\Windows\\Temp\\tmpbackup.ps1'));
    const cache = computeFingerprint(withTemp('C:\\Windows\\Temp\\tmpcache.ps1'));
    expect(backup.fingerprint).not.toBe(cache.fingerprint);
  });
});
