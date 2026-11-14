import { describe, expect, it } from 'vitest';
import { InMemoryInvestigationStore } from '../src/investigations/memory-store.js';
import type { NewInvestigationJob } from '../src/investigations/types.js';
import type { InvocationReservationRequest } from '../src/investigations/ports.js';

const now = new Date('2026-11-14T12:00:00Z');
const at = (ms: number) => new Date(now.getTime() + ms);
function draft(id: string, tenantId = 'tenant-a'): NewInvestigationJob {
  return { id, tenantId, subject: { kind: 'alert', id: `alert-${id}`, title: 'Test' },
    alertIds: [`alert-${id}`], priority: 'P1', trigger: 'system', initiatedBy: null,
    idempotencyKey: id, fingerprint: id, policyVersion: 'test-v1', createdAt: now };
}
const reservation: InvocationReservationRequest = { at: now, phase: 'analysis', fingerprint: 'fp',
  tier: 'economy', model: 'test-model', reservedInputTokens: 100, reservedOutputTokens: 100,
  reservedMicroUsd: 60, rateCardVersion: 'test-v1', dailyCeilingMicroUsd: 100, maxCallsPerRun: 1 };

describe('investigation ownership and shared budget', () => {
  it('rejects every write at lease expiry before another worker claims', async () => {
    const store = new InMemoryInvestigationStore();
    await store.enqueue(draft('one'));
    const job = (await store.claim(now, 1000, 3))!;
    const lease = { jobId: job.id, fencingToken: job.fencingToken };
    expect(await store.heartbeat(lease, at(1000), 1000)).toBe('lost');
    expect(await store.checkpoint(lease, { at: at(1000), stage: 'model' })).toBe(false);
    expect(await store.appendEvent(lease, { at: at(1000), stage: 'model', kind: 'started' })).toBe(false);
    expect(await store.finish(lease, { at: at(1000), status: 'completed', result: null, inference: 'none' })).toBeNull();
    expect(await store.reserveInvocation(lease, { ...reservation, at: at(1000) })).toEqual({ ok: false, reason: 'STALE_LEASE' });
    const next = (await store.claim(at(1000), 1000, 3))!;
    expect(next.fencingToken).toBeGreaterThan(lease.fencingToken);
    expect(await store.heartbeat(lease, at(1001), 1000)).toBe('lost');
  });

  it('reserves against one shared tenant cap across concurrent jobs and isolates tenants', async () => {
    const store = new InMemoryInvestigationStore();
    for (const id of ['a', 'b']) await store.enqueue(draft(id));
    const a = (await store.claim(now, 1000, 3))!;
    const b = (await store.claim(now, 1000, 3))!;
    const outcomes = await Promise.all([a, b].map(job => store.reserveInvocation({ jobId: job.id, fencingToken: job.fencingToken }, reservation)));
    expect(outcomes.filter(x => x.ok)).toHaveLength(1);
    expect(outcomes).toContainEqual({ ok: false, reason: 'DAILY_CAP' });
    expect(await store.byId('other-tenant', a.id)).toBeUndefined();
    expect(await store.events('other-tenant', a.id)).toEqual([]);
    expect((await store.budgetSnapshot('tenant-a', now)).reservedMicroUsd).toBe(60);
  });

  it('cannot dispatch an expired reservation or re-send an ambiguous invocation after takeover', async () => {
    const store = new InMemoryInvestigationStore();
    await store.enqueue(draft('one'));
    const job = (await store.claim(now, 1000, 3))!;
    const lease = { jobId: job.id, fencingToken: job.fencingToken };
    const reserved = await store.reserveInvocation(lease, reservation);
    if (!reserved.ok) throw new Error('reservation failed');
    expect(await store.markDispatching(lease, reserved.invocation.id, at(1000))).toBe('stale');
    expect(await store.markDispatching(lease, reserved.invocation.id, at(500))).toBe('ok');
    const next = (await store.claim(at(1000), 1000, 3))!;
    const reused = await store.reserveInvocation({ jobId: next.id, fencingToken: next.fencingToken }, { ...reservation, at: at(1001) });
    expect(reused).toMatchObject({ ok: true, reused: true, invocation: { state: 'dispatching' } });
    expect(await store.markDispatching({ jobId: next.id, fencingToken: next.fencingToken }, reserved.invocation.id, at(1001))).toBe('stale');
  });
});
