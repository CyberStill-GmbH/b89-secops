import { describe, expect, it } from 'vitest';

import type { AlertFingerprint, DetectionCandidate } from '@b89/detection';

import {
  assignToGroup,
  DEFAULT_ALERT_GROUPING_POLICY,
  validateGroupingPolicy,
  type AlertGroup,
  type GroupableAlert,
} from '../src/alert-group.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import { ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const HOUR = 60 * 60 * 1000;
const T0 = new Date('2026-11-24T00:00:00.000Z');
const at = (hours: number) => new Date(T0.getTime() + hours * HOUR);
const FP = `fp1_${'a'.repeat(64)}`;
const POLICY = DEFAULT_ALERT_GROUPING_POLICY; // 24 h de ventana, 7 d de tramo

function alert(id: string, hours: number, overrides: Partial<GroupableAlert> = {}): GroupableAlert {
  return {
    id,
    tenantId: 'tenant-1',
    priority: 'P4',
    occurredAt: at(hours),
    fingerprint: FP,
    ruleKey: 'windows:101150',
    level: 'fine',
    ...overrides,
  };
}

function opened(first: GroupableAlert): AlertGroup {
  const result = assignToGroup(first, undefined, POLICY, 'group-1');
  if (result.kind !== 'open') throw new Error('setup');
  return result.group;
}

describe('Aprendizaje SOC · etapa C · política de agrupación', () => {
  it('la primera alerta de una huella abre un grupo', () => {
    expect(opened(alert('a1', 0))).toMatchObject({
      id: 'group-1',
      status: 'open',
      alertCount: 1,
      primaryAlertId: 'a1',
      firstSeenAt: at(0),
      lastSeenAt: at(0),
    });
  });

  it('dentro de la ventana se suma: contador, primera/última vez y prioridad más alta', () => {
    const group = opened(alert('a1', 0));
    const result = assignToGroup(alert('a2', 5, { priority: 'P2' }), group, POLICY, 'unused');
    expect(result).toMatchObject({
      kind: 'join',
      expectedRevision: 1,
      group: { alertCount: 2, lastSeenAt: at(5), highestPriority: 'P2', revision: 2 },
    });
  });

  it('una alerta tardía dentro de la ventana mueve la primera vez hacia atrás', () => {
    const group = opened(alert('a1', 10));
    const result = assignToGroup(alert('a0', 2), group, POLICY, 'unused');
    expect(result).toMatchObject({
      kind: 'join',
      group: { firstSeenAt: at(2), lastSeenAt: at(10) },
    });
  });

  it('después de la ventana sella el grupo y abre otro', () => {
    const group = opened(alert('a1', 0));
    const result = assignToGroup(alert('a2', 30), group, POLICY, 'group-2');
    expect(result).toMatchObject({
      kind: 'open',
      group: { id: 'group-2', alertCount: 1, firstSeenAt: at(30) },
      seal: { expectedRevision: 1, group: { id: 'group-1', status: 'closed', revision: 2 } },
    });
  });

  it('respeta el tramo máximo aunque cada alerta caiga dentro de la ventana', () => {
    let group = opened(alert('a0', 0));
    for (let day = 1; day <= 7; day += 1) {
      const result = assignToGroup(alert(`a${day}`, day * 23), group, POLICY, `g-${day}`);
      if (result.kind !== 'join') throw new Error(`día ${day}: ${result.kind}`);
      group = result.group;
    }
    // 8 × 23 h = 184 h > 168 h de tramo: abre otro.
    expect(assignToGroup(alert('a8', 8 * 23), group, POLICY, 'g-8').kind).toBe('open');
  });

  it('una alerta muy anterior al grupo abierto queda sin grupo (no abre uno paralelo)', () => {
    const group = opened(alert('a1', 100));
    expect(assignToGroup(alert('old', 10), group, POLICY, 'unused')).toEqual({
      kind: 'none',
      reason: 'LATE_OUTSIDE_WINDOW',
    });
  });

  it('rechaza un grupo de otra huella o de otro tenant', () => {
    const group = opened(alert('a1', 0));
    expect(() =>
      assignToGroup(alert('x', 1, { tenantId: 'tenant-2' }), group, POLICY, 'unused'),
    ).toThrow();
  });

  it('valida la política', () => {
    expect(validateGroupingPolicy(POLICY)).toBe(true);
    expect(validateGroupingPolicy({ windowMs: 1000, maxSpanMs: 2000 })).toBe(false);
    expect(validateGroupingPolicy({ windowMs: 48 * HOUR, maxSpanMs: 24 * HOUR })).toBe(false);
  });
});

describe('Aprendizaje SOC · etapa C · agrupación al ingerir', () => {
  const FINGERPRINT: AlertFingerprint = {
    fingerprint: FP,
    level: 'fine',
    version: '1',
    normalizerVersion: '1',
    ruleKey: 'windows:101150',
    components: {
      ruleKey: 'windows:101150',
      ruleName: 'regla',
      user: 'ana@b89.example',
      host: '017',
      srcIp: null,
      processImage: 'x.exe',
      parentImage: null,
      commandLine: null,
      sha256: null,
      filePath: null,
      destination: null,
      destinationPort: null,
    },
  };

  function candidate(n: number, hours: number, extra: Partial<DetectionCandidate> = {}) {
    const id = `0199bf11-0000-7000-8000-${String(n).padStart(12, '0')}`;
    return {
      id,
      tenantId: 'tenant-1',
      eventRecordId: `01890f47-7abc-7def-8abc-${String(n).padStart(12, '0')}`,
      eventUid: `evt-${n}`,
      idempotencyKey: `key-${n}`,
      priority: 'P4',
      score: 35,
      reasons: [],
      rulesetId: 'b89.detection.prioritization',
      rulesetVersion: '1.1.0',
      occurredAt: at(hours),
      createdAt: at(hours),
      title: 'Alerta',
      entityKeys: [],
      signal: 'other',
      ruleId: '101150',
      relatedAlertIds: [],
      fingerprint: FINGERPRINT,
      ...extra,
    } satisfies DetectionCandidate;
  }

  function dependencies(soc: InMemorySoc, grouping = true): SocDependencies {
    let sequence = 0;
    return {
      unitOfWork: soc,
      clock: { now: () => at(200) },
      ids: {
        next: () => {
          sequence += 1;
          return `0199bf22-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
        },
      },
      ...(grouping ? { groupingPolicy: POLICY } : {}),
    };
  }

  it('suma alertas de la misma huella sin tocar su estado ni su revisión', async () => {
    const soc = new InMemorySoc();
    const deps = dependencies(soc);
    await ingestCandidate(deps, candidate(1, 0));
    await ingestCandidate(deps, candidate(2, 3));
    await ingestCandidate(deps, candidate(2, 3)); // reintento: no cuenta dos veces
    const groups = [...soc.groupRows.values()];
    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({ alertCount: 2, firstSeenAt: at(0), lastSeenAt: at(3) });
    for (const alert of soc.alertRows.values()) {
      expect(alert).toMatchObject({ status: 'new', revision: 1 });
    }
    expect(await soc.alertGroupMembers('tenant-1', groups[0]!.id, 10)).toHaveLength(2);
    const byAlert = await soc.alertGroupsOf('tenant-1', [candidate(1, 0).id, 'otra']);
    expect([...byAlert.keys()]).toEqual([candidate(1, 0).id]);
    const audit = await soc.allAudit();
    expect(audit.find((event) => event.action === 'soc.alert.created')?.metadata).toMatchObject({
      grouping: 'open',
    });
  });

  it('fuera de la ventana sella y abre otro grupo; solo uno queda abierto', async () => {
    const soc = new InMemorySoc();
    const deps = dependencies(soc);
    await ingestCandidate(deps, candidate(1, 0));
    await ingestCandidate(deps, candidate(2, 48));
    const groups = [...soc.groupRows.values()];
    expect(groups.map((group) => group.status).sort()).toEqual(['closed', 'open']);
  });

  it('sin política o sin huella no se agrupa', async () => {
    const off = new InMemorySoc();
    await ingestCandidate(dependencies(off, false), candidate(1, 0));
    expect(off.groupRows.size).toBe(0);
    const noFingerprint = new InMemorySoc();
    const { fingerprint: _omit, ...withoutFingerprint } = candidate(1, 0);
    await ingestCandidate(dependencies(noFingerprint), withoutFingerprint);
    expect(noFingerprint.groupRows.size).toBe(0);
  });
});
