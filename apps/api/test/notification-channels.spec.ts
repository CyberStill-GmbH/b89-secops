/**
 * Canales de aviso administrables: cifrado del webhook, enmascarado, autorización (solo
 * `notifications.manage`, CSRF y sesión reciente), validación y auditoría sin secretos.
 */

import { describe, expect, it } from 'vitest';

import { InMemoryAuditStore } from '@b89/audit';
import { capabilitiesForRoles } from '@b89/access';
import { InMemoryChannelStore } from '@b89/soar';

import { ApiError } from '../src/http/api-error.js';
import {
  decryptSecret,
  deriveChannelKey,
  encryptSecret,
  NotificationChannelRegistry,
} from '../src/runtime/notification-channels.js';
import type { SecOpsRuntime } from '../src/runtime/secops-runtime.js';
import { NotificationChannelsController } from '../src/soc/notification-channels.controller.js';

const URL_A =
  'https://abc123.6a.environment.api.powerplatform.com/powerautomate/automations/direct/cu/05/workflows/82e70dbb3d92/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SECRETSIGNATUREvalue123456';
const URL_B = URL_A.replace('SECRETSIGNATUREvalue123456', 'OTHERSIGNATUREvalue654321');
const NOW = new Date('2026-11-11T15:00:00.000Z');
const KEY = deriveChannelKey('k'.repeat(48));

function registry(store = new InMemoryChannelStore(), fetchImplementation?: typeof fetch) {
  return new NotificationChannelRegistry({
    tenantId: 't1',
    store,
    key: KEY,
    environmentTeamsUrl: URL_A,
    emailConfigured: false,
    pushConfigured: true,
    clock: () => NOW,
    ...(fetchImplementation ? { fetchImplementation } : {}),
  });
}

describe('cifrado del webhook', () => {
  it('AES-GCM con AAD: ida y vuelta, y no se descifra con otro tenant', () => {
    const sealed = encryptSecret(KEY, URL_A, 't1|teams');
    expect(sealed.startsWith('v1:')).toBe(true);
    expect(sealed).not.toContain('SECRETSIGNATURE');
    expect(decryptSecret(KEY, sealed, 't1|teams')).toBe(URL_A);
    expect(() => decryptSecret(KEY, sealed, 't2|teams')).toThrow();
  });
});

describe('registro de canales', () => {
  it('la URL de la base reemplaza a la de entorno, se guarda cifrada y nunca se expone', async () => {
    const store = new InMemoryChannelStore();
    const channels = registry(store);
    await channels.refresh();
    expect(channels.view('teams')).toMatchObject({ source: 'environment', configured: true });
    const result = await channels.setTeamsUrl(URL_B, 'admin-1');
    expect(result.ok).toBe(true);
    expect(channels.teamsUrl()).toEqual({ url: URL_B, source: 'database' });
    const saved = await store.get('t1', 'teams');
    expect(saved?.secretCiphertext).not.toContain('OTHERSIGNATURE');
    expect(JSON.stringify(channels.views())).not.toContain('SIGNATURE');
    // Otra réplica (otro registro sobre la misma base) la recoge al releer.
    const replica = registry(store);
    await replica.refresh();
    expect(replica.teamsUrl()?.url).toBe(URL_B);
  });

  it('rechaza URL inválidas sin tocar la configuración', async () => {
    const channels = registry();
    expect(await channels.setTeamsUrl('http://x.environment.api.powerplatform.com/a', 'a')).toEqual({
      ok: false,
      code: 'URL_NOT_HTTPS',
    });
    expect(channels.teamsUrl()?.source).toBe('environment');
  });

  it('el transporte usa la URL vigente, respeta «desactivado» y registra la salud', async () => {
    const calls: string[] = [];
    const fetchImplementation = ((url: string) => {
      calls.push(url);
      return Promise.resolve(
        new Response(null, { status: 202, headers: { 'x-ms-workflow-run-id': '0858407198265688965' } }),
      );
    }) as unknown as typeof fetch;
    const channels = registry(new InMemoryChannelStore(), fetchImplementation);
    await channels.setTeamsUrl(URL_B, 'admin-1');
    const message = { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: {} }], b89: { version: '2', clientRequestId: 'c', aggregateId: 'a' } } as const;
    const outcome = await channels.teamsTransport.send(message, 'c');
    expect(outcome).toMatchObject({ delivered: true, httpStatus: 202, providerMessageId: 'x-ms-workflow-run-id:0858407198265688965' });
    expect(calls).toEqual([URL_B]);
    expect(channels.view('teams')).toMatchObject({ status: 'ok', health: { lastHttpStatus: 202 } });
    await channels.setEnabled('teams', false, 'admin-1');
    expect(await channels.teamsTransport.send(message, 'c')).toMatchObject({
      delivered: false,
      failure: { code: 'CHANNEL_DISABLED' },
    });
    expect(calls).toHaveLength(1);
    expect(channels.view('teams').status).toBe('disabled');
    expect(channels.view('email').status).toBe('not_configured');
  });
});

describe('autorización y auditoría de la administración', () => {
  function harness(options: { capabilities: readonly string[]; sessionAgeMs?: number; csrf?: boolean }) {
    const audit = new InMemoryAuditStore();
    const channels = registry();
    const runtime = {
      now: () => NOW,
      audit,
      channels,
      consoleBaseUrl: 'https://dev.security.b89.io',
      csrfTokenFor: () => 'csrf-ok',
      resolveActor: () =>
        Promise.resolve({
          ok: true,
          actor: {
            subjectId: 'admin-1',
            tenantId: 't1',
            sessionId: 's1',
            capabilities: new Set(options.capabilities),
            roles: [],
          },
          session: { id: 's1', createdAt: new Date(NOW.getTime() - (options.sessionAgeMs ?? 60_000)) },
        }),
    } as unknown as SecOpsRuntime;
    const request = {
      ip: '10.0.0.1',
      headers: {
        cookie: 'b89_session=s1',
        ...(options.csrf === false ? {} : { 'x-csrf-token': 'csrf-ok' }),
      },
    };
    return { controller: new NotificationChannelsController(runtime), request, audit, channels };
  }
  const code = async (promise: Promise<unknown>) => {
    try {
      await promise;
      return 'OK';
    } catch (error) {
      return error instanceof ApiError ? (error.getResponse() as { code: string }).code : 'THROWN';
    }
  };

  it('solo el administrador de plataforma tiene notifications.manage', () => {
    expect(capabilitiesForRoles(['b89.platform.admin']).has('notifications.manage')).toBe(true);
    expect(capabilitiesForRoles(['b89.soc.lead']).has('notifications.manage')).toBe(false);
    expect(capabilitiesForRoles(['b89.soc.analyst']).has('notifications.manage')).toBe(false);
  });

  it('sin capability, sin CSRF o con sesión vieja no se cambia nada', async () => {
    const lead = harness({ capabilities: ['notifications.read', 'notifications.dispatch'] });
    expect(await code(lead.controller.setTeams(lead.request, { webhookUrl: URL_B }))).toBe('RESOURCE_UNAVAILABLE');
    const noCsrf = harness({ capabilities: ['notifications.manage'], csrf: false });
    expect(await code(noCsrf.controller.setTeams(noCsrf.request, { webhookUrl: URL_B }))).toBe('REQUEST_NOT_VERIFIED');
    const stale = harness({ capabilities: ['notifications.manage'], sessionAgeMs: 2 * 3_600_000 });
    expect(await code(stale.controller.disable(stale.request, 'teams'))).toBe('STEP_UP_REQUIRED');
    for (const h of [lead, noCsrf, stale]) expect(h.channels.teamsUrl()?.source).toBe('environment');
  });

  it('el cambio queda auditado con máscaras, nunca con la URL', async () => {
    const admin = harness({ capabilities: ['notifications.read', 'notifications.manage'] });
    const result = (await admin.controller.setTeams(admin.request, { webhookUrl: URL_B })) as {
      channel: { destination: string };
    };
    expect(result.channel.destination).toBe('https://abc123.…/…654321');
    expect(await code(admin.controller.setTeams(admin.request, { webhookUrl: 'https://evil.example/x' }))).toBe(
      'VALIDATION_FAILED',
    );
    const events = await admin.audit.range('t1', 1n, 10);
    expect(events.map((event) => event.action)).toEqual([
      'notifications.channel.webhook_updated',
      'notifications.channel.webhook_rejected',
    ]);
    const serialized = JSON.stringify(events, (_key, value) => (typeof value === 'bigint' ? String(value) : value));
    expect(serialized).not.toContain('SIGNATURE');
    expect(serialized).not.toContain('sig=');
    const listed = (await admin.controller.list(admin.request)) as { items: unknown[]; canManage: boolean };
    expect(listed.canManage).toBe(true);
    expect(JSON.stringify(listed)).not.toContain('SIGNATURE');
  });
});
