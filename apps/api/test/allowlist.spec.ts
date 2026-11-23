/**
 * Lista blanca de la API de pagos: lectura (con la lista inicial importada), guardado con
 * revisión y validación, permisos, sesión reciente y el feed del colector con su token.
 */

import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import { InMemoryAuditStore } from '@b89/audit';

import type { IncomingRequest } from '../src/http/http-contracts.js';
import { InMemoryAllowlistStore } from '../src/runtime/allowlist-store.js';
import type { SecOpsRuntime } from '../src/runtime/secops-runtime.js';
import { AllowlistController } from '../src/soc/allowlist.controller.js';

const TENANT = 'tenant-b89';
const CSRF = 'csrf';
const FEED_TOKEN = 'f'.repeat(40);

function harness(options: { capabilities?: readonly string[]; roles?: readonly string[]; sessionAgeMs?: number } = {}) {
  const now = new Date('2026-11-23T15:00:00.000Z');
  const store = new InMemoryAllowlistStore();
  const runtime = {
    tenantId: TENANT,
    allowlistStore: store,
    allowlistFeedToken: FEED_TOKEN,
    audit: new InMemoryAuditStore(),
    now: () => now,
    csrfTokenFor: () => CSRF,
    resolveActor: async () => ({
      ok: true,
      actor: {
        tenantId: TENANT,
        subjectId: 'user-1',
        sessionId: 'session-1',
        roles: options.roles ?? ['b89.platform.admin'],
        capabilities: new Set(options.capabilities ?? ['allowlist.read', 'allowlist.manage']),
      },
      session: { id: 'session-1', createdAt: new Date(now.getTime() - (options.sessionAgeMs ?? 60_000)) },
    }),
  } as unknown as SecOpsRuntime;
  return { controller: new AllowlistController(runtime), store };
}

const browser = (): IncomingRequest => ({ headers: { cookie: 'b89_session=session-1', 'x-csrf-token': CSRF }, ip: '127.0.0.1' });

async function status(action: () => Promise<unknown>): Promise<number> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpException);
    return (error as HttpException).getStatus();
  }
  throw new Error('se esperaba un error');
}

const entry = (patch: Record<string, unknown> = {}) => ({
  id: 'terrapay-payouts-peru',
  name: 'Terrapay',
  kind: 'client',
  product: 'Payouts',
  country: 'Perú',
  company: 'B89 Payments',
  status: 'with_ip',
  prodIps: ['54.76.150.47'],
  sandboxIps: [],
  markers: ['terrapay'],
  note: null,
  ...patch,
});

describe('lista blanca de la API de pagos', () => {
  it('sin versión guardada devuelve la lista inicial importada del Excel', async () => {
    const { controller } = harness();
    const list = await controller.get(browser());
    expect(list.revision).toBe(0);
    expect(list.canManage).toBe(true);
    expect(list.entries.length).toBeGreaterThanOrEqual(40);
    const terrapay = list.entries.find((item) => item.name === 'Terrapay');
    expect(terrapay?.prodIps).toEqual(['54.76.150.47']);
    // Las IPs que perdieron los puntos no se vigilan: quedan en la nota.
    const bpc = list.entries.find((item) => item.name === 'BPC 1');
    expect(bpc?.prodIps).not.toContain('4421486220');
    expect(bpc?.note).toMatch(/reconfirmar/u);
  });

  it('guarda con revisión, normaliza y rechaza una versión vieja', async () => {
    const { controller } = harness();
    const saved = await controller.put(browser(), { expectedRevision: 0, entries: [entry({ prodIps: [' 54.76.150.47 ', '54.76.150.47', '10.0.0.0/8'] })] });
    expect(saved.revision).toBe(1);
    expect(saved.entries[0]!.prodIps).toEqual(['54.76.150.47', '10.0.0.0/8']);
    expect(await status(() => controller.put(browser(), { expectedRevision: 0, entries: [] }))).toBe(409);
  });

  it('valida IPs, identificadores y duplicados', async () => {
    const { controller } = harness();
    expect(await status(() => controller.put(browser(), { expectedRevision: 0, entries: [entry({ prodIps: ['4421486220'] })] }))).toBe(422);
    expect(await status(() => controller.put(browser(), { expectedRevision: 0, entries: [entry({ markers: ['a b'] })] }))).toBe(422);
    expect(await status(() => controller.put(browser(), { expectedRevision: 0, entries: [entry(), entry()] }))).toBe(422);
  });

  it('solo administración cambia la lista; los demás la leen', async () => {
    const reader = harness({ capabilities: ['allowlist.read'], roles: ['b89.soc.analyst'] });
    expect((await reader.controller.get(browser())).canManage).toBe(false);
    expect(await status(() => reader.controller.put(browser(), { expectedRevision: 0, entries: [] }))).toBeGreaterThanOrEqual(400);
    const nobody = harness({ capabilities: [] });
    expect(await status(() => nobody.controller.get(browser()))).toBeGreaterThanOrEqual(400);
  });

  it('pide sesión reciente salvo al administrador de plataforma', async () => {
    const lead = harness({ roles: ['b89.soc.lead'], sessionAgeMs: 60 * 60_000 });
    expect(await status(() => lead.controller.put(browser(), { expectedRevision: 0, entries: [] }))).toBe(403);
    const admin = harness({ sessionAgeMs: 60 * 60_000 });
    expect((await admin.controller.put(browser(), { expectedRevision: 0, entries: [] })).revision).toBe(1);
  });

  it('el feed del colector exige su token y trae IPs e identificadores por entrada', async () => {
    const { controller } = harness();
    await controller.put(browser(), { expectedRevision: 0, entries: [entry({ sandboxIps: ['3.126.133.76'] })] });
    expect(await status(() => controller.feed({ headers: {}, ip: '10.0.0.1' }))).toBeGreaterThanOrEqual(400);
    expect(await status(() => controller.feed({ headers: { authorization: `Bearer ${'x'.repeat(40)}` }, ip: '10.0.0.1' }))).toBeGreaterThanOrEqual(400);
    const feed = await controller.feed({ headers: { authorization: `Bearer ${FEED_TOKEN}` }, ip: '10.0.0.1' });
    expect(feed).toEqual({
      revision: 1,
      entries: [{ id: 'terrapay-payouts-peru', name: 'Terrapay', kind: 'client', status: 'with_ip', ips: ['54.76.150.47', '3.126.133.76'], markers: ['terrapay'] }],
    });
  });
});
