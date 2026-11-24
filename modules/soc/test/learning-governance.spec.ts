/**
 * Aprendizaje SOC · fase 3 — habilitación en dos capas y contexto en base.
 */

import { beforeEach, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';

import { DEFAULT_ENGINE_SETTINGS, effectiveMode } from '../src/learning-engine.js';
import {
  addContextEntry,
  approveRuleEnablement,
  liveContextFrom,
  requestRuleEnablement,
  revokeRuleEnablement,
  ruleModesFrom,
} from '../src/learning-governance.js';
import { LEARNING_SERVICE_ACTOR } from '../src/learning-use-cases.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import type { SocDependencies } from '../src/use-cases.js';

const TENANT = 'tenant-1';
const NOW = new Date('2026-11-24T15:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const RULE = 'linux-process:100200';
const APPROVERS = ['lead-a', 'lead-b'];

function lead(subjectId: string): Actor {
  return {
    subjectId,
    tenantId: TENANT,
    sessionId: 's',
    roles: ['b89.soc.lead'],
    capabilities: capabilitiesForRoles(['b89.soc.lead']),
  };
}

let soc: InMemorySoc;
let now: Date;
let deps: SocDependencies;

beforeEach(() => {
  soc = new InMemorySoc();
  now = NOW;
  let ids = 0;
  deps = {
    unitOfWork: soc,
    clock: { now: () => now },
    ids: { next: () => `0199e600-0000-7000-8000-${(ids += 1).toString().padStart(12, '0')}` },
  };
});

const request = (subject: string, overrides: Record<string, unknown> = {}) =>
  requestRuleEnablement(deps, {
    actor: lead(subject),
    designatedApprovers: APPROVERS,
    correlationId: 'c',
    ruleKey: RULE,
    mode: 'dry_run',
    reason: 'Sombra de 21 días superada con cota ≥ 0,97.',
    expiresInDays: 30,
    ...overrides,
  });

describe('fase 3 · habilitación por regla (capa 2)', () => {
  it('la pide una persona designada y la aprueba OTRA; queda vigente hasta su vencimiento', async () => {
    const asked = await request('lead-a');
    if (!asked.ok) throw new Error(asked.reason);
    expect(
      await approveRuleEnablement(deps, {
        actor: lead('lead-a'),
        designatedApprovers: APPROVERS,
        correlationId: 'c',
        id: asked.value.id,
        expectedRevision: 1,
      }),
    ).toMatchObject({ ok: false, reason: 'SAME_APPROVER_TWICE' });
    const approved = await approveRuleEnablement(deps, {
      actor: lead('lead-b'),
      designatedApprovers: APPROVERS,
      correlationId: 'c',
      id: asked.value.id,
      expectedRevision: 1,
    });
    expect(approved).toMatchObject({
      ok: true,
      value: { status: 'approved', approvedBy: 'lead-b' },
    });
    const rows = await soc.listRuleEnablements(TENANT);
    expect(ruleModesFrom(rows, NOW).get(RULE)).toBe('dry_run');
    expect(ruleModesFrom(rows, new Date(NOW.getTime() + 31 * DAY)).has(RULE)).toBe(false);
  });

  it('rechaza: servicio, no designado, alto impacto, sin vencimiento o > 90 días, motivo corto, doble abierta', async () => {
    expect(
      await requestRuleEnablement(deps, {
        actor: lead(LEARNING_SERVICE_ACTOR),
        designatedApprovers: [...APPROVERS, LEARNING_SERVICE_ACTOR],
        correlationId: 'c',
        ruleKey: RULE,
        mode: 'active',
        reason: 'El servicio se habilita a sí mismo.',
        expiresInDays: 30,
      }),
    ).toMatchObject({ ok: false, reason: 'SERVICE_IDENTITY' });
    expect(await request('intruso')).toMatchObject({
      ok: false,
      reason: 'NOT_A_DESIGNATED_APPROVER',
    });
    expect(await request('lead-a', { ruleKey: 'cloudflare:102001' })).toMatchObject({
      ok: false,
      reason: 'IMPACT_FLOOR',
    });
    expect(await request('lead-a', { expiresInDays: 91 })).toMatchObject({
      ok: false,
      reason: 'ENABLEMENT_INVALID',
    });
    expect(await request('lead-a', { reason: 'corto' })).toMatchObject({
      ok: false,
      reason: 'ENABLEMENT_INVALID',
    });
    expect((await request('lead-a')).ok).toBe(true);
    expect(await request('lead-b')).toMatchObject({ ok: false, reason: 'OPEN_ENABLEMENT_EXISTS' });
  });

  it('revocada deja de contar al instante', async () => {
    const asked = await request('lead-a');
    if (!asked.ok) throw new Error('x');
    await approveRuleEnablement(deps, {
      actor: lead('lead-b'),
      designatedApprovers: APPROVERS,
      correlationId: 'c',
      id: asked.value.id,
      expectedRevision: 1,
    });
    await revokeRuleEnablement(deps, {
      actor: lead('lead-a'),
      designatedApprovers: APPROVERS,
      correlationId: 'c',
      id: asked.value.id,
      expectedRevision: 2,
    });
    expect(ruleModesFrom(await soc.listRuleEnablements(TENANT), NOW).size).toBe(0);
  });

  it('modo efectivo = techo ∩ lista del entorno ∩ habilitación aprobada', () => {
    const base = {
      ...DEFAULT_ENGINE_SETTINGS,
      maxMode: 'active' as const,
      activeRules: new Set([RULE]),
    };
    // Sin capa 2 (ruleModes presente pero vacío): sombra aunque figure en la lista del entorno.
    expect(effectiveMode({ ...base, ruleModes: new Map() }, RULE)).toBe('shadow');
    // Capa 2 aprobada pero la regla no está en el entorno: sombra.
    expect(
      effectiveMode(
        { ...base, activeRules: new Set(), ruleModes: new Map([[RULE, 'active']]) },
        RULE,
      ),
    ).toBe('shadow');
    // Ambas: el mínimo con el techo.
    expect(effectiveMode({ ...base, ruleModes: new Map([[RULE, 'dry_run']]) }, RULE)).toBe(
      'dry_run',
    );
    expect(
      effectiveMode({ ...base, maxMode: 'dry_run', ruleModes: new Map([[RULE, 'active']]) }, RULE),
    ).toBe('dry_run');
  });
});

describe('fase 3 · contexto en base', () => {
  it('entradas aditivas con vencimiento; la confirmación del calendario vence en ≤ 30 días', async () => {
    const add = (kind: 'critical_asset' | 'change_calendar_ack', value: string, days: number) =>
      addContextEntry(deps, {
        actor: lead('lead-a'),
        designatedApprovers: APPROVERS,
        correlationId: 'c',
        kind,
        value,
        reason: 'Inventario revisado con infraestructura.',
        expiresInDays: days,
      });
    expect((await add('critical_asset', 'DC01.b89.local', 90)).ok).toBe(true);
    expect(await add('change_calendar_ack', 'calendario-cab', 31)).toMatchObject({
      ok: false,
      reason: 'CONTEXT_INVALID',
    });
    expect((await add('change_calendar_ack', 'calendario-cab', 30)).ok).toBe(true);
    const live = liveContextFrom(await soc.listContextEntries(TENANT), NOW);
    expect([...live.criticalAssets]).toEqual(['dc01.b89.local']);
    expect(live.changeCalendarAckUntil?.getTime()).toBe(NOW.getTime() + 30 * DAY);
    // Vencidas, no cuentan (fail-closed: el motor escalará por contexto incompleto).
    const later = liveContextFrom(
      await soc.listContextEntries(TENANT),
      new Date(NOW.getTime() + 91 * DAY),
    );
    expect(later.criticalAssets.size).toBe(0);
    expect(later.changeCalendarAckUntil).toBeNull();
  });

  it('la auditoría registra el tipo de entrada, no su valor', async () => {
    await addContextEntry(deps, {
      actor: lead('lead-a'),
      designatedApprovers: APPROVERS,
      correlationId: 'c',
      kind: 'privileged_identity',
      value: 'admin.global@b89.example',
      reason: 'Cuenta de administración global de Entra.',
      expiresInDays: 60,
    });
    const audit = await soc.auditStore.range(TENANT, 0n, 100);
    const text = JSON.stringify(audit, (_key, value: unknown) =>
      typeof value === 'bigint' ? value.toString() : value,
    );
    expect(text).toContain('privileged_identity');
    expect(text).not.toContain('admin.global@b89.example');
  });
});
