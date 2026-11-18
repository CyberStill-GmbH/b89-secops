/**
 * Cliente de reputación de IP contra AbuseIPDB (`GET /api/v2/check`, reportes de 90 días).
 *
 * - Solo IP públicas: privadas, reservadas, de documentación, loopback y multicast nunca salen.
 * - Clave en `B89_ABUSEIPDB_API_KEY` (secreto); nunca se registra ni viaja en errores.
 * - Caché en memoria con TTL (por defecto 6 h) y tope de entradas: el plan gratuito permite
 *   1000 consultas al día y la misma IP aparece en muchas alertas.
 * - Un 429 abre un enfriamiento hasta `Retry-After` (o 15 min) en el que no se llama al proveedor.
 * - Errores como códigos estables (`ABUSEIPDB_*`); el llamador decide el vacío a declarar.
 */

import { BlockList, isIP } from 'node:net';

export type IpReputationProvider = 'abuseipdb' | 'virustotal';

export interface IpReputationReport {
  readonly ip: string;
  /** Proveedor que respondió (AbuseIPDB o, si no hay clave, VirusTotal). */
  readonly provider?: IpReputationProvider;
  readonly abuseConfidenceScore: number;
  readonly totalReports: number;
  readonly distinctUsers: number;
  readonly lastReportedAt: string | null;
  readonly countryCode: string | null;
  readonly usageType: string | null;
  readonly isp: string | null;
  readonly domain: string | null;
  readonly isTor: boolean;
  readonly isWhitelisted: boolean | null;
  readonly checkedAt: string;
}

export interface IpReputationLookup {
  /** `null` si la IP no es pública (no se consulta). Lanza `AbuseIpdbError` si el proveedor falla. */
  check(ip: string, signal?: AbortSignal): Promise<IpReputationReport | null>;
}

export type AbuseIpdbErrorCode =
  | 'ABUSEIPDB_UNAUTHORIZED'
  | 'ABUSEIPDB_RATE_LIMITED'
  | 'ABUSEIPDB_UNAVAILABLE'
  | 'ABUSEIPDB_INVALID_RESPONSE';

export class AbuseIpdbError extends Error {
  public constructor(public readonly code: AbuseIpdbErrorCode) {
    super(code);
    this.name = 'AbuseIpdbError';
  }
}

const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
const VIRUSTOTAL_ENDPOINT = 'https://www.virustotal.com/api/v3/ip_addresses/';

/** Rangos que nunca se consultan (RFC 6890 y afines). */
const NON_PUBLIC = (() => {
  const list = new BlockList();
  for (const [net, prefix] of [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
  ] as const) {
    list.addSubnet(net, prefix, 'ipv4');
  }
  // IPv6: `publicIp` ya exige unicast global (2000::/3), que excluye loopback, ULA, enlace local,
  // multicast y el mapeo IPv4. No se agrega `::ffff:0:0/96`: BlockList lo aplica también a IPv4.
  for (const [net, prefix] of [
    ['2001:db8::', 32],
    ['2001:2::', 48],
  ] as const) {
    list.addSubnet(net, prefix, 'ipv6');
  }
  return list;
})();

/** IP pública apta para consultar fuera; normaliza mayúsculas de IPv6. */
export function publicIp(value: string): string | null {
  const ip = value.trim().toLowerCase();
  const family = isIP(ip);
  if (family === 4) return NON_PUBLIC.check(ip, 'ipv4') ? null : ip;
  if (family === 6) {
    // Solo unicast global (2000::/3); el resto (incluido el mapeo IPv4) no se consulta.
    if (!/^[23][0-9a-f]{0,3}:/u.test(ip)) return null;
    return NON_PUBLIC.check(ip, 'ipv6') ? null : ip;
  }
  return null;
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function text(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const clean = [...value]
    .filter((char) => char.charCodeAt(0) >= 0x20 && char.charCodeAt(0) !== 0x7f)
    .join('')
    .trim();
  return clean ? clean.slice(0, max) : null;
}

function isoOrNull(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? new Date(at).toISOString() : null;
}

export interface AbuseIpdbOptions {
  readonly apiKey: string;
  /** `virustotal`: `GET /api/v3/ip_addresses/{ip}` (motores que la marcan) con la misma caché y enfriamiento. */
  readonly provider?: IpReputationProvider;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
  readonly timeoutMs?: number;
  readonly cacheTtlMs?: number;
  readonly maxCacheEntries?: number;
  readonly maxAgeInDays?: number;
}

export function createAbuseIpdbClient(options: AbuseIpdbOptions): IpReputationLookup {
  const doFetch = options.fetch ?? fetch;
  const now = options.now ?? (() => new Date());
  const timeoutMs = options.timeoutMs ?? 4_000;
  const ttlMs = options.cacheTtlMs ?? 6 * 3_600_000;
  const maxEntries = options.maxCacheEntries ?? 2_000;
  const maxAgeInDays = options.maxAgeInDays ?? 90;
  const cache = new Map<string, { at: number; report: IpReputationReport }>();
  const inFlight = new Map<string, Promise<IpReputationReport>>();
  let coolDownUntil = 0;

  const provider: IpReputationProvider = options.provider ?? 'abuseipdb';
  const fetchReport = async (ip: string, signal?: AbortSignal): Promise<IpReputationReport> => {
    const timeout = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const virustotal = provider === 'virustotal';
    const url = virustotal
      ? `${VIRUSTOTAL_ENDPOINT}${encodeURIComponent(ip)}`
      : `${ENDPOINT}?${new URLSearchParams({ ipAddress: ip, maxAgeInDays: String(maxAgeInDays) })}`;
    let response: Response;
    try {
      response = await doFetch(url, {
        method: 'GET',
        headers: virustotal
          ? { 'x-apikey': options.apiKey, Accept: 'application/json' }
          : { Key: options.apiKey, Accept: 'application/json' },
        signal: combined,
        redirect: 'error',
      });
    } catch {
      throw new AbuseIpdbError('ABUSEIPDB_UNAVAILABLE');
    }
    if (response.status === 401 || response.status === 403) {
      throw new AbuseIpdbError('ABUSEIPDB_UNAUTHORIZED');
    }
    if (response.status === 429) {
      const retry = Number(response.headers.get('retry-after'));
      const waitMs =
        Number.isFinite(retry) && retry > 0 ? Math.min(retry, 86_400) * 1_000 : 900_000;
      coolDownUntil = now().getTime() + waitMs;
      throw new AbuseIpdbError('ABUSEIPDB_RATE_LIMITED');
    }
    if (response.status !== 200) throw new AbuseIpdbError('ABUSEIPDB_UNAVAILABLE');
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new AbuseIpdbError('ABUSEIPDB_INVALID_RESPONSE');
    }
    if (virustotal) return virusTotalReport(ip, body, now());
    const data = record(record(body)['data']);
    const score = data['abuseConfidenceScore'];
    if (typeof score !== 'number' || !Number.isFinite(score)) {
      throw new AbuseIpdbError('ABUSEIPDB_INVALID_RESPONSE');
    }
    const country = text(data['countryCode'], 2);
    return {
      ip,
      abuseConfidenceScore: Math.max(0, Math.min(100, Math.round(score))),
      totalReports: count(data['totalReports']),
      distinctUsers: count(data['numDistinctUsers']),
      lastReportedAt: isoOrNull(data['lastReportedAt']),
      countryCode: country && /^[A-Z]{2}$/u.test(country) ? country : null,
      usageType: text(data['usageType'], 80),
      isp: text(data['isp'], 120),
      domain: text(data['domain'], 120),
      isTor: data['isTor'] === true,
      isWhitelisted: typeof data['isWhitelisted'] === 'boolean' ? data['isWhitelisted'] : null,
      checkedAt: now().toISOString(),
      provider: 'abuseipdb',
    };
  };

  return {
    async check(value, signal) {
      const ip = publicIp(value);
      if (!ip) return null;
      const at = now().getTime();
      const hit = cache.get(ip);
      if (hit && at - hit.at < ttlMs) return hit.report;
      if (at < coolDownUntil) throw new AbuseIpdbError('ABUSEIPDB_RATE_LIMITED');
      let pending = inFlight.get(ip);
      if (!pending) {
        pending = fetchReport(ip, signal).finally(() => inFlight.delete(ip));
        inFlight.set(ip, pending);
      }
      const report = await pending;
      cache.delete(ip);
      cache.set(ip, { at: now().getTime(), report });
      while (cache.size > maxEntries) {
        const oldest = cache.keys().next().value;
        if (oldest === undefined) break;
        cache.delete(oldest);
      }
      return report;
    },
  };
}

/**
 * VirusTotal → misma forma que AbuseIPDB. El puntaje (0–100) sale de los motores que marcan la IP:
 * 20 por motor «malicious» y 10 por «suspicious» (2 motores maliciosos ya son 40; 4, 80).
 */
export function virusTotalReport(ip: string, body: unknown, at: Date): IpReputationReport {
  const attributes = record(record(record(body)['data'])['attributes']);
  const stats = record(attributes['last_analysis_stats']);
  if (Object.keys(stats).length === 0) throw new AbuseIpdbError('ABUSEIPDB_INVALID_RESPONSE');
  const malicious = count(stats['malicious']);
  const suspicious = count(stats['suspicious']);
  const country = text(attributes['country'], 2);
  const tags = Array.isArray(attributes['tags']) ? attributes['tags'] : [];
  const lastAnalysis = attributes['last_analysis_date'];
  return {
    ip,
    provider: 'virustotal',
    abuseConfidenceScore: Math.min(100, malicious * 20 + suspicious * 10),
    totalReports: malicious + suspicious,
    distinctUsers: malicious,
    lastReportedAt:
      typeof lastAnalysis === 'number' && Number.isFinite(lastAnalysis)
        ? new Date(lastAnalysis * 1000).toISOString()
        : null,
    countryCode: country && /^[A-Z]{2}$/u.test(country) ? country : null,
    usageType: text(attributes['network'], 80),
    isp: text(attributes['as_owner'], 120),
    domain: null,
    isTor: tags.some((tag) => typeof tag === 'string' && tag.toLowerCase() === 'tor'),
    isWhitelisted: null,
    checkedAt: at.toISOString(),
  };
}

/**
 * Cliente desde el entorno: AbuseIPDB si hay `B89_ABUSEIPDB_API_KEY`; si no, VirusTotal con
 * `B89_VIRUSTOTAL_API_KEY` (plan gratuito: 4/min, por eso la caché de 6 h); `undefined` sin clave.
 */
export function abuseIpdbFromEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): IpReputationLookup | undefined {
  const apiKey = environment['B89_ABUSEIPDB_API_KEY']?.trim();
  if (apiKey) return createAbuseIpdbClient({ apiKey });
  const vtKey = environment['B89_VIRUSTOTAL_API_KEY']?.trim();
  if (vtKey) return createAbuseIpdbClient({ apiKey: vtKey, provider: 'virustotal' });
  return undefined;
}
