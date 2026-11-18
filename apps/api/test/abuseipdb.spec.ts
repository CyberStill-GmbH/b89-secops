/**
 * Reputación de IP (AbuseIPDB): solo IP públicas, caché, enfriamiento ante 429, y su paso por el
 * lector de evidencia del Analista IA (referencia opaca, nunca la IP) y por la herramienta de Bunny.
 */

import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { InvestigationJob } from '@b89/assistant';
import { createAlert, InMemorySoc, type Alert } from '@b89/soc';

import { RuntimeEvidenceReader } from '../src/assistant/analyst-evidence.js';
import { buildSocTools } from '../src/assistant/soc-tools.js';
import {
  abuseIpdbFromEnvironment,
  AbuseIpdbError,
  createAbuseIpdbClient,
  publicIp,
  type IpReputationLookup,
} from '../src/runtime/abuseipdb.js';

const NOW = new Date('2026-11-18T15:00:00.000Z');
const PUBLIC_IP = '185.220.101.4';

function reply(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const DATA = {
  data: {
    ipAddress: PUBLIC_IP,
    abuseConfidenceScore: 100,
    countryCode: 'DE',
    usageType: 'Data Center/Web Hosting/Transit',
    isp: 'Example Hosting GmbH',
    domain: 'example.net',
    isTor: true,
    isWhitelisted: false,
    totalReports: 812,
    numDistinctUsers: 233,
    lastReportedAt: '2026-11-18T12:01:00+00:00',
  },
};

describe('publicIp', () => {
  it.each([
    ['10.1.2.3', null],
    ['192.168.0.10', null],
    ['172.20.1.1', null],
    ['127.0.0.1', null],
    ['100.64.3.3', null],
    ['203.0.113.9', null],
    ['::1', null],
    ['fe80::1', null],
    ['fd00::1', null],
    ['2001:db8::1', null],
    ['::ffff:8.8.8.8', null],
    ['no-ip', null],
    ['8.8.8.8', '8.8.8.8'],
    ['2606:4700:4700::1111', '2606:4700:4700::1111'],
    ['2606:4700:4700::ABCD', '2606:4700:4700::abcd'],
  ])('%s → %s', (input, expected) => {
    expect(publicIp(input)).toBe(expected);
  });
});

describe('cliente AbuseIPDB', () => {
  it('consulta una IP pública, normaliza la respuesta y la cachea', async () => {
    const calls: { url: string; key: string | null }[] = [];
    const client = createAbuseIpdbClient({
      apiKey: 'test-key',
      now: () => NOW,
      fetch: (async (url: string, init?: RequestInit) => {
        calls.push({ url, key: new Headers(init?.headers).get('Key') });
        return reply(200, DATA);
      }) as typeof fetch,
    });
    const report = await client.check(PUBLIC_IP);
    await client.check(PUBLIC_IP);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toContain(`ipAddress=${PUBLIC_IP}`);
    expect(calls[0]!.url).toContain('maxAgeInDays=90');
    expect(calls[0]!.key).toBe('test-key');
    expect(report).toMatchObject({
      abuseConfidenceScore: 100,
      totalReports: 812,
      distinctUsers: 233,
      countryCode: 'DE',
      isTor: true,
      isWhitelisted: false,
      lastReportedAt: '2026-11-18T12:01:00.000Z',
    });
  });

  it('nunca llama al proveedor por IP privadas', async () => {
    let called = false;
    const client = createAbuseIpdbClient({
      apiKey: 'k',
      fetch: (async () => {
        called = true;
        return reply(200, DATA);
      }) as unknown as typeof fetch,
    });
    expect(await client.check('10.0.0.5')).toBeNull();
    expect(called).toBe(false);
  });

  it('un 429 abre un enfriamiento sin más llamadas', async () => {
    let calls = 0;
    const client = createAbuseIpdbClient({
      apiKey: 'k',
      now: () => NOW,
      fetch: (async () => {
        calls += 1;
        return reply(429, {}, { 'retry-after': '120' });
      }) as unknown as typeof fetch,
    });
    await expect(client.check('8.8.8.8')).rejects.toMatchObject({ code: 'ABUSEIPDB_RATE_LIMITED' });
    await expect(client.check('1.1.1.1')).rejects.toMatchObject({ code: 'ABUSEIPDB_RATE_LIMITED' });
    expect(calls).toBe(1);
  });

  it('clave inválida y respuesta malformada son códigos estables', async () => {
    const unauthorized = createAbuseIpdbClient({
      apiKey: 'k',
      fetch: (async () => reply(401, {})) as unknown as typeof fetch,
    });
    await expect(unauthorized.check('8.8.8.8')).rejects.toMatchObject({
      code: 'ABUSEIPDB_UNAUTHORIZED',
    });
    const malformed = createAbuseIpdbClient({
      apiKey: 'k',
      fetch: (async () => reply(200, { data: {} })) as unknown as typeof fetch,
    });
    await expect(malformed.check('8.8.8.8')).rejects.toMatchObject({
      code: 'ABUSEIPDB_INVALID_RESPONSE',
    });
  });
});

const ENTITY_IP = 'ent_ipaaaaaaaaaaaaa';
const ENTITY_LAN = 'ent_lanbbbbbbbbbbbb';

function putAlert(soc: InMemorySoc, entityKeys: string[], entityRefs: string[]): Alert {
  const id = randomUUID();
  const alert = createAlert({
    id,
    tenantId: 't1',
    candidateId: id,
    eventRecordId: randomUUID(),
    title: 'B89 Wazuh: fuerza bruta SSH',
    priority: 'P3',
    score: 40,
    reasons: [{ code: 'BASE_SEVERITY', delta: 40, detail: 'base' }],
    occurredAt: NOW,
    createdAt: NOW,
    entityKeys,
    entityRefs,
    signal: 'other',
    ruleId: 'rule-5763',
    relatedAlertIds: [],
  });
  soc.alertRows.set(`t1|${id}`, alert);
  return alert;
}

describe('lector de evidencia con reputación de IP', () => {
  const lookup = (score: number): IpReputationLookup & { seen: string[] } => {
    const seen: string[] = [];
    return {
      seen,
      async check(ip) {
        seen.push(ip);
        const client = createAbuseIpdbClient({
          apiKey: 'k',
          now: () => NOW,
          fetch: (async () =>
            reply(200, {
              data: { ...DATA.data, abuseConfidenceScore: score },
            })) as unknown as typeof fetch,
        });
        return client.check(ip);
      },
    };
  };

  it('consulta solo IP públicas y publica la referencia opaca, nunca la IP', async () => {
    const soc = new InMemorySoc();
    const alert = putAlert(soc, [`ip:${PUBLIC_IP}`, 'ip:10.0.0.7'], [ENTITY_IP, ENTITY_LAN]);
    const ipReputation = lookup(97);
    const bundle = await new RuntimeEvidenceReader({
      tenantId: 't1',
      soc,
      ipReputation,
      now: () => NOW,
    }).collect(
      { tenantId: 't1', alertIds: [alert.id] } as unknown as InvestigationJob,
      new AbortController().signal,
    );
    expect(ipReputation.seen).toEqual([PUBLIC_IP]);
    expect(bundle.context?.ipReputation).toEqual([
      expect.objectContaining({
        entityRef: ENTITY_IP,
        abuseConfidenceScore: 97,
        provider: 'abuseipdb',
      }),
    ]);
    expect(JSON.stringify(bundle)).not.toContain(PUBLIC_IP);
  });

  it('una falla del proveedor queda como vacío sin volver parcial la evidencia', async () => {
    const soc = new InMemorySoc();
    const alert = putAlert(soc, [`ip:${PUBLIC_IP}`], [ENTITY_IP]);
    const failing: IpReputationLookup = {
      check: async () => {
        throw new AbuseIpdbError('ABUSEIPDB_RATE_LIMITED');
      },
    };
    const withRep = await new RuntimeEvidenceReader({
      tenantId: 't1',
      soc,
      ipReputation: failing,
      now: () => NOW,
    }).collect(
      { tenantId: 't1', alertIds: [alert.id] } as unknown as InvestigationJob,
      new AbortController().signal,
    );
    expect(withRep.completeness.gaps).toContain(
      'Reputación de IP no disponible: límite de consultas de AbuseIPDB',
    );
    expect(withRep.context?.ipReputation).toEqual([]);

    const without = await new RuntimeEvidenceReader({
      tenantId: 't1',
      soc,
      now: () => NOW,
    }).collect(
      { tenantId: 't1', alertIds: [alert.id] } as unknown as InvestigationJob,
      new AbortController().signal,
    );
    expect(without.completeness.gaps).toContain(
      'Reputación de IP (AbuseIPDB) no configurada en este despliegue',
    );
  });
});

describe('herramienta ip_reputation de Bunny', () => {
  const get = async () => ({ status: 404, body: null });
  const lookup: IpReputationLookup = {
    check: async (ip) =>
      publicIp(ip)
        ? {
            ...DATA.data,
            ip,
            distinctUsers: 233,
            lastReportedAt: null,
            checkedAt: NOW.toISOString(),
            totalReports: 812,
            abuseConfidenceScore: 100,
            isWhitelisted: false,
          }
        : null,
  };

  it('se ofrece solo con lectura de alertas o eventos y con el cliente configurado', () => {
    const names = (capabilities: string[], withLookup: boolean) =>
      buildSocTools(
        get,
        { roles: [], capabilities },
        withLookup ? { ipReputation: lookup } : {},
      ).map((tool) => tool.name);
    expect(names(['alerts.read'], true)).toContain('ip_reputation');
    expect(names(['alerts.read'], false)).not.toContain('ip_reputation');
    expect(names(['audit.read'], true)).not.toContain('ip_reputation');
  });

  it('rechaza IP privadas sin consultar y devuelve la reputación de las públicas', async () => {
    const tool = buildSocTools(
      get,
      { roles: [], capabilities: ['alerts.read'] },
      {
        ipReputation: lookup,
      },
    ).find((item) => item.name === 'ip_reputation')!;
    const lan = await tool.run({ ip: '192.168.1.4' });
    expect(lan).toMatchObject({ ok: true, data: { available: false } });
    const out = await tool.run({ ip: PUBLIC_IP });
    expect(out).toMatchObject({
      ok: true,
      data: {
        available: true,
        abuseConfidenceScore: 100,
        verdictHint: 'Maliciosa conocida (puntaje alto)',
      },
    });
  });
});

describe('VirusTotal como proveedor de reputación', () => {
  it('convierte los motores que marcan la IP en el mismo informe', async () => {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const client = createAbuseIpdbClient({
      apiKey: 'vt-key',
      provider: 'virustotal',
      fetch: (async (url: string, init: RequestInit) => {
        calls.push({ url, headers: init.headers as Record<string, string> });
        return new Response(
          JSON.stringify({
            data: {
              attributes: {
                last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 30 },
                country: 'CO',
                as_owner: 'Datacamp Limited',
                network: '62.93.176.0/21',
                tags: [],
                last_analysis_date: 1763400000,
              },
            },
          }),
          { status: 200 },
        );
      }) as unknown as typeof fetch,
    });
    const report = await client.check('62.93.177.8');
    expect(calls[0]?.url).toBe('https://www.virustotal.com/api/v3/ip_addresses/62.93.177.8');
    expect(calls[0]?.headers['x-apikey']).toBe('vt-key');
    expect(report).toMatchObject({
      provider: 'virustotal',
      abuseConfidenceScore: 70,
      totalReports: 4,
      countryCode: 'CO',
      isp: 'Datacamp Limited',
    });
  });

  it('usa VirusTotal solo si no hay clave de AbuseIPDB', () => {
    expect(abuseIpdbFromEnvironment({})).toBeUndefined();
    expect(abuseIpdbFromEnvironment({ B89_VIRUSTOTAL_API_KEY: 'x' })).toBeDefined();
  });
});
