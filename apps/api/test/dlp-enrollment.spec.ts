/**
 * Conexión de equipos Ferrispector: clave de un solo uso que vence en 30 min, rotación a una
 * credencial propia del equipo, latido/estado, acuse de revisión, revocación y el estado que
 * consulta el asistente de conexión de la consola.
 */

import { createHash } from 'node:crypto';

import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import { InMemoryAuditStore } from '@b89/audit';

import type { IncomingRequest } from '../src/http/http-contracts.js';
import type { DlpEndpointRecord, DlpPolicyRecord, DlpPolicyStore } from '../src/runtime/dlp-policy-store.js';
import type { SecOpsRuntime } from '../src/runtime/secops-runtime.js';
import { DlpPolicyController } from '../src/soc/dlp-policy.controller.js';

const TENANT = 'tenant-b89';
const CSRF = 'csrf-token-for-session';

type Row = {
  -readonly [K in keyof DlpEndpointRecord]: DlpEndpointRecord[K];
} & { tokenHash: string };

/** Mismas reglas que `PrismaDlpPolicyStore`, sin PostgreSQL. */
class MemoryDlpStore implements DlpPolicyStore {
  public row: DlpPolicyRecord | undefined;
  public readonly rows = new Map<string, Row>();

  public async policy() {
    return this.row;
  }

  public async putPolicy(tenantId: string, document: unknown, expectedRevision: number, updatedBy: string, updatedAt: Date) {
    if ((this.row?.revision ?? 0) !== expectedRevision) return false;
    this.row = { tenantId, document, revision: expectedRevision + 1, updatedAt, updatedBy };
    return true;
  }

  public async issueEnrollmentToken(input: { id: string; tenantId: string; tokenHash: string; expiresAt: Date; now: Date }) {
    for (const [id, row] of this.rows) {
      if (!row.enrolledAt && row.enrollmentExpiresAt <= input.now) this.rows.delete(id);
    }
    this.rows.set(input.id, {
      id: input.id,
      tenantId: input.tenantId,
      tokenHash: input.tokenHash,
      hostname: null,
      agentId: null,
      enrolledAt: null,
      lastSeenAt: null,
      revokedAt: null,
      appliedRevision: 0,
      credentialVersion: 0,
      policyVersion: null,
      usbControlStatus: null,
      usbControlCode: null,
      usbControlCheckedAt: null,
      enrollmentExpiresAt: input.expiresAt,
    });
    return true;
  }

  public async enrollEndpoint(input: { tenantId: string; tokenHash: string; credentialHash: string; hostname: string; agentId: string; at: Date }) {
    const row = [...this.rows.values()].find((candidate) => candidate.tokenHash === input.tokenHash);
    if (!row || row.enrolledAt || row.credentialVersion !== 0 || row.enrollmentExpiresAt <= input.at) return undefined;
    Object.assign(row, {
      tokenHash: input.credentialHash,
      credentialVersion: 1,
      hostname: input.hostname,
      agentId: input.agentId,
      enrolledAt: input.at,
      lastSeenAt: input.at,
      enrollmentExpiresAt: input.at,
    });
    return { ...row };
  }

  public async enrollment(input: { tenantId: string; id: string }) {
    const row = this.rows.get(input.id);
    return row && row.tenantId === input.tenantId ? { ...row } : undefined;
  }

  public async cancelEnrollment(input: { tenantId: string; id: string }) {
    const row = this.rows.get(input.id);
    if (!row || row.tenantId !== input.tenantId || row.enrolledAt) return false;
    this.rows.delete(input.id);
    return true;
  }

  public async endpointByToken(input: { tenantId: string; tokenHash: string; at: Date }) {
    const row = [...this.rows.values()].find((candidate) => candidate.tokenHash === input.tokenHash);
    if (!row || !row.enrolledAt || row.credentialVersion !== 1 || row.revokedAt) return undefined;
    row.lastSeenAt = input.at;
    return { ...row };
  }

  public async acknowledgePolicy(input: { endpointId: string; tenantId: string; revision: number; policyVersion: string; usbControlStatus: string; usbControlCode: string | null; at: Date }) {
    const row = this.rows.get(input.endpointId);
    if (!row || row.revokedAt) return false;
    Object.assign(row, {
      appliedRevision: input.revision,
      policyVersion: input.policyVersion,
      usbControlStatus: input.usbControlStatus,
      usbControlCode: input.usbControlCode,
      usbControlCheckedAt: input.at,
      lastSeenAt: input.at,
    });
    return true;
  }

  public async endpoints() {
    return [...this.rows.values()].filter((row) => row.enrolledAt).map((row) => ({ ...row }));
  }

  public async revokeEndpoint(input: { id: string; at: Date }) {
    const row = this.rows.get(input.id);
    if (!row || !row.enrolledAt || row.revokedAt) return false;
    row.revokedAt = input.at;
    return true;
  }
}

function harness(options: { capabilities?: readonly string[]; sessionAgeMs?: number; roles?: readonly string[] } = {}) {
  let now = new Date('2026-11-22T15:00:00.000Z');
  const sessionCreatedAt = new Date(now.getTime() - (options.sessionAgeMs ?? 60_000));
  const store = new MemoryDlpStore();
  const audit = new InMemoryAuditStore();
  const auditActions: string[] = [];
  const append = audit.append.bind(audit);
  audit.append = (event) => {
    auditActions.push(event.action);
    return append(event);
  };
  const runtime = {
    tenantId: TENANT,
    dlpPolicyStore: store,
    audit,
    now: () => now,
    csrfTokenFor: () => CSRF,
    resolveActor: async () => ({
      ok: true,
      actor: {
        tenantId: TENANT,
        subjectId: 'user-admin',
        sessionId: 'session-1',
        roles: options.roles ?? ['b89.platform.admin'],
        capabilities: new Set(options.capabilities ?? ['dlp.read', 'dlp.configure']),
      },
      session: { id: 'session-1', createdAt: sessionCreatedAt },
    }),
  } as unknown as SecOpsRuntime;
  return {
    controller: new DlpPolicyController(runtime),
    store,
    auditActions,
    advance: (ms: number) => {
      now = new Date(now.getTime() + ms);
    },
  };
}

const console = (): IncomingRequest => ({
  headers: { cookie: 'b89_session=session-1', 'x-csrf-token': CSRF },
  ip: '127.0.0.1',
});
const agent = (token: string): IncomingRequest => ({ headers: { authorization: `Bearer ${token}` }, ip: '10.0.0.8' });

async function failure(action: () => Promise<unknown>): Promise<number> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpException);
    return (error as HttpException).getStatus();
  }
  throw new Error('se esperaba un error');
}

describe('conexión de equipos DLP', () => {
  it('la clave vale una sola vez y se cambia por una credencial propia del equipo', async () => {
    const { controller, store } = harness();
    const issued = await controller.createEnrollmentToken(console());
    expect(issued.id).toMatch(/^[0-9a-f-]{36}$/u);
    expect(await controller.enrollmentStatus(console(), issued.id)).toMatchObject({ state: 'waiting', endpoint: null });

    const enrolled = await controller.enrollAgent(agent(issued.token), { hostname: 'PC-FINANZAS-01', agentId: 'a1b2c3d4e5f60718' });
    expect(enrolled.endpointId).toBe(issued.id);
    expect(enrolled.endpointCredential).not.toBe(issued.token);
    // Solo se guarda el hash de la credencial, nunca el valor.
    const row = store.rows.get(issued.id)!;
    expect(row.tokenHash).toBe(createHash('sha256').update(enrolled.endpointCredential, 'utf8').digest('hex'));

    // La clave ya no sirve: ni para inscribir otro equipo ni para pedir la política.
    expect(await failure(() => controller.enrollAgent(agent(issued.token), { hostname: 'OTRO', agentId: 'ffffffffffffffff' }))).toBeGreaterThanOrEqual(400);
    expect(await failure(() => controller.getAgentPolicy(agent(issued.token)))).toBeGreaterThanOrEqual(400);

    const status = await controller.enrollmentStatus(console(), issued.id);
    expect(status).toMatchObject({ state: 'connected', endpoint: { id: issued.id, hostname: 'PC-FINANZAS-01' } });
  });

  it('una clave vencida no inscribe y el asistente la ve vencida', async () => {
    const { controller, advance } = harness();
    const issued = await controller.createEnrollmentToken(console());
    advance(30 * 60_000);
    expect(await failure(() => controller.enrollAgent(agent(issued.token), { hostname: 'PC-1', agentId: 'a1' }))).toBeGreaterThanOrEqual(400);
    expect(await controller.enrollmentStatus(console(), issued.id)).toMatchObject({ state: 'expired' });
  });

  it('cancelar retira una clave sin usar aunque la sesión ya no sea reciente', async () => {
    const { controller, auditActions, advance } = harness({ sessionAgeMs: 60_000, roles: ['b89.soc.lead'] });
    const issued = await controller.createEnrollmentToken(console());
    advance(45 * 60_000); // la sesión pasa de 30 min: crear exige step-up, cancelar no
    expect(await failure(() => controller.createEnrollmentToken(console()))).toBe(403);
    expect(await controller.cancelEnrollmentToken(console(), issued.id)).toMatchObject({ cancelled: true });
    expect(await failure(() => controller.enrollAgent(agent(issued.token), { hostname: 'PC-1', agentId: 'a1' }))).toBeGreaterThanOrEqual(400);
    expect(await failure(() => controller.enrollmentStatus(console(), issued.id))).toBeGreaterThanOrEqual(400);
    expect(auditActions).toContain('dlp.endpoint.enrollment_token_cancelled');
  });

  it('la administración de plataforma no necesita sesión reciente, como en canales', async () => {
    const admin = harness({ sessionAgeMs: 4 * 60 * 60_000 });
    const issued = await admin.controller.createEnrollmentToken(console());
    const { endpointCredential } = await admin.controller.enrollAgent(agent(issued.token), { hostname: 'PC-1', agentId: 'a1' });
    expect(endpointCredential).toBeTruthy();
    await admin.controller.putPolicy(console(), {
      expectedRevision: 0,
      policyVersion: '1.1.0',
      enabledRuleIds: ['B89_CRED_GITHUB_TOKEN'],
      fingerprintsSha256: [],
      quarantineExactFingerprints: false,
      usbControl: { enabled: false, supportedPlanConfirmed: false, allowedGroups: [] },
    });
    await admin.controller.revokeEndpoint(console(), issued.id);

    const lead = harness({ sessionAgeMs: 4 * 60 * 60_000, roles: ['b89.soc.lead'] });
    expect(await failure(() => lead.controller.createEnrollmentToken(console()))).toBe(403);
    expect(await failure(() => lead.controller.putPolicy(console(), {
      expectedRevision: 0,
      policyVersion: '1.1.0',
      enabledRuleIds: ['B89_CRED_GITHUB_TOKEN'],
      fingerprintsSha256: [],
      quarantineExactFingerprints: false,
      usbControl: { enabled: false, supportedPlanConfirmed: false, allowedGroups: [] },
    }))).toBe(403);
  });

  it('no se cancela un equipo ya conectado: se revoca', async () => {
    const { controller } = harness();
    const issued = await controller.createEnrollmentToken(console());
    await controller.enrollAgent(agent(issued.token), { hostname: 'PC-1', agentId: 'a1' });
    expect(await failure(() => controller.cancelEnrollmentToken(console(), issued.id))).toBeGreaterThanOrEqual(400);
  });

  it('latido, acuse de revisión y revocación', async () => {
    const { controller, advance } = harness();
    const issued = await controller.createEnrollmentToken(console());
    const { endpointCredential } = await controller.enrollAgent(agent(issued.token), { hostname: 'PC-1', agentId: 'a1' });

    const saved = await controller.putPolicy(console(), {
      expectedRevision: 0,
      policyVersion: '1.1.0',
      enabledRuleIds: ['B89_CRED_GITHUB_TOKEN'],
      fingerprintsSha256: [],
      quarantineExactFingerprints: false,
      usbControl: { enabled: false, supportedPlanConfirmed: false, allowedGroups: [] },
    });
    expect(saved.revision).toBe(1);

    let list = await controller.listEndpoints(console());
    expect(list.items[0]).toMatchObject({ status: 'updating', currentRevision: 0, enrolledAt: expect.any(String) });
    expect(list.onlineWindowSeconds).toBe(120);

    const policy = await controller.getAgentPolicy(agent(endpointCredential));
    await controller.acknowledgePolicy(agent(endpointCredential), {
      revision: policy.revision,
      policyVersion: policy.policyVersion,
      usbControl: { status: 'disabled', code: 'POLICY_DISABLED' },
    });
    list = await controller.listEndpoints(console());
    expect(list.items[0]).toMatchObject({ status: 'current', currentRevision: 1, currentPolicyVersion: '1.1.0' });

    // Un acuse de una revisión que ya no es la vigente se rechaza.
    expect(await failure(() => controller.acknowledgePolicy(agent(endpointCredential), {
      revision: 0,
      policyVersion: '1.0.0',
      usbControl: { status: 'disabled', code: 'POLICY_DISABLED' },
    }))).toBe(409);

    // Sin latido por más de 2 min: sin conexión. Volver a consultar lo pone en línea.
    advance(121_000);
    expect((await controller.listEndpoints(console())).items[0]!.status).toBe('offline');
    await controller.getAgentPolicy(agent(endpointCredential));
    expect((await controller.listEndpoints(console())).items[0]!.status).toBe('current');

    // Un equipo sin conexión también se puede revocar (p. ej., un portátil perdido).
    advance(10 * 60_000);
    await controller.revokeEndpoint(console(), issued.id);
    expect((await controller.listEndpoints(console())).items[0]!.status).toBe('revoked');
    expect(await failure(() => controller.getAgentPolicy(agent(endpointCredential)))).toBeGreaterThanOrEqual(400);
    expect(await controller.enrollmentStatus(console(), issued.id)).toMatchObject({ state: 'revoked' });
  });

  it('las personas de solo lectura no crean claves ni consultan su estado', async () => {
    const { controller } = harness({ capabilities: ['dlp.read'] });
    expect(await failure(() => controller.createEnrollmentToken(console()))).toBeGreaterThanOrEqual(400);
    expect(await failure(() => controller.enrollmentStatus(console(), '00000000-0000-4000-8000-000000000000'))).toBeGreaterThanOrEqual(400);
    expect((await controller.listEndpoints(console())).items).toEqual([]);
  });
});
