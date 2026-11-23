/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  LIMA_OFFSET_MS,
  limaTime,
  normalizeTrafficFilters,
  RawTrafficQuery,
  TopBucket,
  Validation,
} from './cloudflare_traffic';

/**
 * «Tráfico de Cloudflare» → pestaña «Análisis»: contrato y reglas de negocio B89.
 *
 * El servidor agrega `b89-cloudflare-traffic-*` (HTTP) con la identidad de quien mira y estas
 * funciones puras convierten las cifras en sesiones del backoffice puntuadas, movimientos de
 * dinero y hallazgos en lenguaje llano. Todo lo que aquí se decide (qué es dinero, qué es un
 * ASN de hosting, cuántos puntos suma cada motivo) es visible y está probado.
 *
 * Los datos HTTP de Cloudflare (GraphQL) llegan MUESTREADOS (~1 de cada 11 en b89.io): los
 * conteos son registros muestreados, no peticiones reales.
 */

export const ANALYSIS_ROUTE = '/api/b89_ops/cloudflare/analysis';

/** Índices de resultados de OpenSearch Anomaly Detection (alias + históricos ocultos). */
export const ANOMALY_RESULTS_INDEX = '.opendistro-anomaly-results*';
export const ANOMALY_DETECTOR_PREFIX = 'b89-cf-';
export const BASELINE_DAYS = 14;

/* ------------------------------------------------------------- Dominio B89 */

/** Backoffice humano: front + API de producción, y sus variantes de staging/UAT. */
export const BACKOFFICE_HOST_PATTERNS = ['*paymentsv2.b89.io', '*-apipayments.b89.io'] as const;
/** API de integración (máquina a máquina, comercios). */
export const INTEGRATION_HOSTS = ['apipayments.b89.io'] as const;

export const AUTH_LOGIN_PATH = '*auth-service/v1/login';
export const AUTH_REFRESH_PATH = '*auth-service/v1/refresh-token*';
export const STAFF_PATH = '*/backoffice/*';

export const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

export interface EndpointRule {
  readonly id: string;
  readonly label: string;
  /** `write`: POST/PUT/PATCH/DELETE; `read`: GET; `any`: cualquiera. */
  readonly methods: 'write' | 'read' | 'any';
  /** Comodines sobre `http.path` (sin distinguir mayúsculas). */
  readonly paths: readonly string[];
}

/** Llamadas que mueven dinero o cambian estado. El orden decide el rótulo (la primera gana). */
export const MONEY_RULES: readonly EndpointRule[] = [
  {
    id: 'payout-accept',
    label: 'Aceptar cotización de pago',
    methods: 'write',
    paths: ['*payouts/v1/quotes*accept*'],
  },
  {
    id: 'remittance-accept',
    label: 'Aceptar cotización de remesa',
    methods: 'write',
    paths: ['*remittance/*quotes*accept*'],
  },
  {
    id: 'balance-transaction',
    label: 'Transacción de saldo (backoffice)',
    methods: 'write',
    paths: ['*/backoffice/v2/balances/transactions*'],
  },
  {
    id: 'mtc-operation',
    label: 'Operación MTC de remesas',
    methods: 'write',
    paths: ['*remittance/mtc/operation*'],
  },
  {
    id: 'bulk-status',
    label: 'Cambio masivo de estado de órdenes',
    methods: 'write',
    paths: ['*remittance/orders/bulk-status*'],
  },
  { id: 'payin', label: 'Pago entrante (payin)', methods: 'write', paths: ['*payin/v1/payment*'] },
  {
    id: 'manual-rate',
    label: 'Tipo de cambio manual',
    methods: 'write',
    paths: ['*exchange*/rate/manual*'],
  },
  {
    id: 'backoffice-write',
    label: 'Escritura en backoffice',
    methods: 'write',
    paths: [STAFF_PATH],
  },
];

/** Lecturas sensibles: exportaciones y saldos. */
export const SENSITIVE_READ_RULES: readonly EndpointRule[] = [
  { id: 'export', label: 'Exportación', methods: 'any', paths: ['*export*'] },
  {
    id: 'balance-transactions-read',
    label: 'Consulta de transacciones de saldo',
    methods: 'read',
    paths: ['*balances/transactions*'],
  },
  {
    id: 'balances-merchants',
    label: 'Saldos de comercios (solo staff)',
    methods: 'any',
    paths: ['*balances/merchants*'],
  },
];

/** Comodín (`*`) → expresión regular anclada, sin distinguir mayúsculas. */
export function wildcardRegExp(pattern: string): RegExp {
  const body = pattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/gu, '\\$&'))
    .join('.*');
  return new RegExp(`^${body}$`, 'iu');
}

export function matchesWildcard(value: string | null | undefined, pattern: string): boolean {
  return value != null && wildcardRegExp(pattern).test(value);
}

function methodMatches(rule: EndpointRule, method: string | null | undefined): boolean {
  const upper = (method ?? '').toUpperCase();
  if (rule.methods === 'any') return true;
  if (rule.methods === 'read') return upper === 'GET';
  return (WRITE_METHODS as readonly string[]).includes(upper);
}

function ruleFor(
  rules: readonly EndpointRule[],
  method: string | null | undefined,
  path: string | null | undefined,
): EndpointRule | null {
  return (
    rules.find(
      (rule) =>
        methodMatches(rule, method) && rule.paths.some((pattern) => matchesWildcard(path, pattern)),
    ) ?? null
  );
}

/** Regla de movimiento de dinero que cumple una petición (o `null`). */
export function moneyMovementRule(
  method: string | null | undefined,
  path: string | null | undefined,
) {
  return ruleFor(MONEY_RULES, method, path);
}

/** Regla de lectura sensible que cumple una petición (o `null`). */
export function sensitiveReadRule(
  method: string | null | undefined,
  path: string | null | undefined,
) {
  return ruleFor(SENSITIVE_READ_RULES, method, path);
}

export type Channel = 'backoffice' | 'integration' | 'other';

export function channelOfHost(host: string | null | undefined): Channel {
  if (!host) return 'other';
  const lower = host.toLowerCase();
  if ((INTEGRATION_HOSTS as readonly string[]).includes(lower)) return 'integration';
  return BACKOFFICE_HOST_PATTERNS.some((pattern) => matchesWildcard(lower, pattern))
    ? 'backoffice'
    : 'other';
}

export const CHANNEL_LABEL: Readonly<Record<Channel, string>> = {
  backoffice: 'Backoffice (humano)',
  integration: 'Integración (API)',
  other: 'Otro host',
};

/* ---------------------------------------------------------- Hosting / VPN */

interface HostingProvider {
  readonly label: string;
  readonly name: RegExp;
  readonly asns: readonly number[];
}

/**
 * Proveedores de hosting, nube y VPN: una sesión humana del backoffice no debería salir de
 * ellos. Por nombre del ASN y, si falta el nombre, por número.
 */
export const HOSTING_PROVIDERS: readonly HostingProvider[] = [
  { label: 'Datacamp', name: /datacamp/iu, asns: [60068, 212238] },
  { label: 'Amazon', name: /amazon|\baws\b/iu, asns: [16509, 14618, 8987] },
  { label: 'Google Cloud', name: /google (llc|cloud)/iu, asns: [15169, 396982, 19527] },
  { label: 'Hetzner', name: /hetzner/iu, asns: [24940, 213230] },
  { label: 'OVH', name: /\bovh/iu, asns: [16276] },
  { label: 'DigitalOcean', name: /digital\s?ocean/iu, asns: [14061] },
  { label: 'M247', name: /\bm247\b/iu, asns: [9009] },
  { label: 'Leaseweb', name: /leaseweb/iu, asns: [60781, 28753, 16265, 30633] },
  { label: 'Vultr', name: /vultr|constant company|choopa/iu, asns: [20473] },
  { label: 'Linode', name: /linode/iu, asns: [63949] },
  { label: 'Akamai', name: /akamai/iu, asns: [20940, 16625] },
  { label: 'Contabo', name: /contabo/iu, asns: [51167] },
  { label: 'Microsoft', name: /microsoft/iu, asns: [8075] },
  { label: 'Oracle', name: /oracle/iu, asns: [31898] },
  { label: 'Alibaba', name: /alibaba/iu, asns: [45102, 37963] },
  { label: 'Tencent', name: /tencent/iu, asns: [132203, 45090] },
  { label: 'CDN77', name: /cdn77/iu, asns: [] },
  { label: 'G-Core', name: /g-?core/iu, asns: [199524] },
  { label: 'Scaleway', name: /scaleway|online s\.?a\.?s/iu, asns: [12876] },
  { label: 'Cloudflare WARP', name: /cloudflare/iu, asns: [13335] },
  { label: 'Hostinger', name: /hostinger/iu, asns: [47583] },
  { label: 'IONOS', name: /ionos|1&1/iu, asns: [8560] },
  { label: 'Zenlayer', name: /zenlayer/iu, asns: [21859] },
  { label: 'QuadraNet', name: /quadranet/iu, asns: [8100] },
  { label: 'Psychz', name: /psychz/iu, asns: [40676] },
  { label: 'ColoCrossing', name: /colocrossing/iu, asns: [36352] },
  { label: 'Packethub', name: /packethub/iu, asns: [207137] },
  { label: 'VPN comercial', name: /\b(nord|mullvad|proton|surfshark|expressvpn)\b/iu, asns: [] },
];

/** Proveedor de hosting/VPN del ASN (rótulo corto) o `null` si parece acceso residencial. */
export function hostingProvider(
  asnName: string | null | undefined,
  asn?: number | null,
): string | null {
  for (const provider of HOSTING_PROVIDERS) {
    if (asnName && provider.name.test(asnName)) return provider.label;
  }
  if (asn != null) {
    const byNumber = HOSTING_PROVIDERS.find((provider) => provider.asns.includes(asn));
    if (byNumber) return byNumber.label;
  }
  return null;
}

/* ------------------------------------------------------------ Hora de Lima */

/** Hora local de Lima (0–23) de un instante. */
export function limaHour(iso: string): number {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? new Date(ms + LIMA_OFFSET_MS).getUTCHours() : -1;
}

/** Fuera de horario: 22:00–05:59 en Lima. */
export function isOffHours(iso: string): boolean {
  const hour = limaHour(iso);
  return hour >= 22 || (hour >= 0 && hour < 6);
}

/** Horas UTC equivalentes a 22:00–05:59 de Lima (UTC−5): 03:00–10:59. */
export const OFF_HOURS_UTC = { from: 3, to: 10 } as const;

/* ------------------------------------------------------------ Validación */

export interface AnalysisRequest {
  readonly from: string;
  readonly to: string;
  readonly zones: readonly string[];
}

/** `from`/`to` ISO (máx. 31 días) y zonas opcionales; ningún otro parámetro. */
export function normalizeAnalysisQuery(raw: RawTrafficQuery): Validation<AnalysisRequest> {
  const result = normalizeTrafficFilters({ from: raw.from, to: raw.to, zone: raw.zone });
  if (!result.ok) return result;
  return {
    ok: true,
    value: { from: result.value.from, to: result.value.to, zones: result.value.zones },
  };
}

export function analysisQueryParams(request: AnalysisRequest): URLSearchParams {
  const params = new URLSearchParams();
  params.set('from', request.from);
  params.set('to', request.to);
  for (const zone of request.zones) params.append('zone', zone);
  return params;
}

/* -------------------------------------------------------------- Respuesta */

/** Cifras de una IP contra el backoffice (lo que agrega el servidor). */
export interface IpStats {
  readonly ip: string;
  readonly country: string | null;
  readonly asn: number | null;
  readonly asnName: string | null;
  readonly firstSeen: string | null;
  readonly lastSeen: string | null;
  readonly requests: number;
  readonly logins: number;
  readonly loginsFailed: number;
  readonly refreshes: number;
  readonly staffOk: number;
  readonly staffDenied: number;
  readonly writes: number;
  readonly exports: number;
  readonly moneyCalls: number;
  readonly userAgents: number;
  readonly topUserAgents: readonly string[];
  readonly hosts: readonly string[];
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export const RISK_LABEL: Readonly<Record<RiskLevel, string>> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Medio',
  low: 'Bajo',
};

export interface RiskReason {
  readonly code: string;
  readonly label: string;
  readonly points: number;
}

export interface SessionRisk {
  readonly score: number;
  readonly level: RiskLevel;
  readonly reasons: readonly RiskReason[];
}

export interface BackofficeSession extends IpStats {
  readonly hosting: string | null;
  /** IP no vista contra el backoffice en los 14 días previos (`null`: sin línea base). */
  readonly newIp: boolean | null;
  /** Login correcto desde un país sin logins correctos en los 14 días previos. */
  readonly newCountry: boolean | null;
  readonly risk: SessionRisk;
}

export interface MoneyBucket {
  readonly at: string;
  readonly backoffice: number;
  readonly integration: number;
}

export interface Caller {
  readonly ip: string;
  readonly country: string | null;
  readonly asn: number | null;
  readonly asnName: string | null;
  readonly hosting: string | null;
  readonly count: number;
  readonly firstSeen: string | null;
  readonly lastSeen: string | null;
  readonly endpoints: readonly TopBucket[];
  readonly statuses: readonly TopBucket[];
  readonly userAgents: readonly TopBucket[];
  readonly hosts: readonly TopBucket[];
}

export interface MoneyCaller extends Caller {
  readonly channel: Channel | 'mixed';
  readonly offHours: number;
  /** No llamó a endpoints de dinero en los 14 días previos (`null`: sin línea base). */
  readonly newCaller: boolean | null;
}

export interface AnomalyRow {
  readonly id: string;
  readonly start: string;
  readonly end: string;
  readonly detectorId: string;
  readonly detectorName: string | null;
  readonly entity: ReadonlyArray<{ readonly name: string; readonly value: string }>;
  readonly grade: number;
  readonly confidence: number;
  readonly features: ReadonlyArray<{ readonly name: string; readonly value: number | null }>;
}

export type AnomalyStatus = 'ok' | 'forbidden' | 'unavailable' | 'error';

export interface AnomalySection {
  readonly status: AnomalyStatus;
  /** Detectores `b89-cf-*` encontrados (nombre e id); vacío si no se pudieron listar. */
  readonly detectors: ReadonlyArray<{ readonly id: string; readonly name: string }>;
  /** `false`: el rol no puede listar detectores; se muestran sus ids. */
  readonly detectorsResolved: boolean;
  readonly rows: readonly AnomalyRow[];
  readonly message: string | null;
}

/** Filtro de «Registros» que abre un hallazgo o una fila. */
export interface RecordsLink {
  readonly from: string;
  readonly to: string;
  readonly ip?: string;
  readonly host?: string;
  readonly path?: string;
  readonly method?: string;
  readonly country?: string;
}

export interface Finding {
  readonly id: string;
  readonly severity: RiskLevel;
  readonly title: string;
  readonly summary: string;
  readonly evidence: ReadonlyArray<{ readonly label: string; readonly value: string }>;
  readonly records: RecordsLink;
}

export interface CloudflareAnalysis {
  readonly generatedAt: string;
  readonly from: string;
  readonly to: string;
  readonly zones: readonly string[];
  /** Registros HTTP del rango y cuántos vienen muestreados. */
  readonly httpRecords: number;
  readonly sampledRecords: number;
  readonly baseline: { readonly from: string; readonly to: string; readonly available: boolean };
  readonly findings: readonly Finding[];
  readonly sessions: readonly BackofficeSession[];
  readonly money: {
    readonly interval: string;
    readonly histogram: readonly MoneyBucket[];
    readonly totals: { readonly backoffice: number; readonly integration: number };
    readonly callers: readonly MoneyCaller[];
  };
  readonly sensitiveReads: readonly Caller[];
  readonly anomalies: AnomalySection;
  readonly partial: boolean;
}

/* ------------------------------------------------------------ Riesgo */

/** Puntos de cada motivo: la tabla se muestra tal cual en la vista. */
export const RISK_POINTS = {
  hosting: 30,
  refreshWithoutLogin: 25,
  exports: 20,
  outsidePeru: 15,
  writes: 15,
  money: 15,
  newCountry: 15,
  manyUserAgents: 10,
  staffDenied: 10,
  newIp: 10,
  failedLogins: 10,
} as const;

export const MANY_USER_AGENTS = 3;
export const STAFF_DENIED_MIN = 3;
export const FAILED_LOGINS_MIN = 5;

export function riskLevel(score: number): RiskLevel {
  if (score >= 70) return 'critical';
  if (score >= 45) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

const plural = (count: number, one: string, many: string) =>
  `${count.toLocaleString('es-PE')} ${count === 1 ? one : many}`;

/** Puntuación transparente: suma de motivos (tope 100), cada uno con su explicación. */
export function scoreSession(
  stats: IpStats,
  context: { readonly newIp: boolean | null; readonly newCountry: boolean | null },
): SessionRisk {
  const reasons: RiskReason[] = [];
  const add = (code: keyof typeof RISK_POINTS, label: string) =>
    reasons.push({ code, label, points: RISK_POINTS[code] });
  const hosting = hostingProvider(stats.asnName, stats.asn);
  if (hosting) add('hosting', `Sale de hosting/VPN (${hosting})`);
  if (stats.refreshes > 0 && stats.logins === 0) {
    add(
      'refreshWithoutLogin',
      `Renovó token ${plural(stats.refreshes, 'vez', 'veces')} sin iniciar sesión en el rango`,
    );
  }
  if (stats.exports > 0) add('exports', `${plural(stats.exports, 'exportación', 'exportaciones')}`);
  if (stats.country && stats.country !== 'PE')
    add('outsidePeru', `Fuera de Perú (${stats.country})`);
  if (stats.moneyCalls > 0) {
    add('money', `${plural(stats.moneyCalls, 'llamada', 'llamadas')} que mueven dinero`);
  } else if (stats.writes > 0) {
    add('writes', `${plural(stats.writes, 'escritura', 'escrituras')} en el backoffice`);
  }
  if (context.newCountry) add('newCountry', 'Login correcto desde un país nuevo');
  if (stats.userAgents >= MANY_USER_AGENTS) {
    add('manyUserAgents', `${stats.userAgents} navegadores/User-Agents distintos`);
  }
  if (stats.staffDenied >= STAFF_DENIED_MIN) {
    add(
      'staffDenied',
      `${plural(stats.staffDenied, 'acceso denegado', 'accesos denegados')} (403)`,
    );
  }
  if (stats.loginsFailed >= FAILED_LOGINS_MIN) {
    add('failedLogins', `${plural(stats.loginsFailed, 'login fallido', 'logins fallidos')}`);
  }
  if (context.newIp) add('newIp', 'IP no vista en los 14 días previos');
  const score = Math.min(
    100,
    reasons.reduce((sum, reason) => sum + reason.points, 0),
  );
  return { score, level: riskLevel(score), reasons: reasons.sort((a, b) => b.points - a.points) };
}

export interface Baseline {
  readonly available: boolean;
  readonly backofficeIps: ReadonlySet<string>;
  readonly moneyIps: ReadonlySet<string>;
  readonly loginCountries: ReadonlySet<string>;
}

export function buildSession(stats: IpStats, baseline: Baseline): BackofficeSession {
  const newIp = baseline.available ? !baseline.backofficeIps.has(stats.ip) : null;
  const newCountry =
    baseline.available && stats.logins > 0 && stats.country && baseline.loginCountries.size > 0
      ? !baseline.loginCountries.has(stats.country)
      : null;
  return {
    ...stats,
    hosting: hostingProvider(stats.asnName, stats.asn),
    newIp,
    newCountry,
    risk: scoreSession(stats, { newIp, newCountry }),
  };
}

/** Sesiones ordenadas por riesgo (desc) y, a igualdad, por actividad. */
export function rankSessions(sessions: readonly BackofficeSession[]): BackofficeSession[] {
  return [...sessions].sort(
    (a, b) => b.risk.score - a.risk.score || b.requests - a.requests || a.ip.localeCompare(b.ip),
  );
}

/* ------------------------------------------------------------ Hallazgos */

const SEVERITY_ORDER: Readonly<Record<RiskLevel, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function who(item: {
  ip: string;
  asnName: string | null;
  country: string | null;
  hosting?: string | null;
}): string {
  const owner = item.hosting ?? item.asnName ?? 'ASN desconocido';
  return `${item.ip} (${owner}, ${item.country ?? '??'})`;
}

const PADDING_MS = 60 * 1000;

/** Ventana de «Registros» de una IP: su primera y última aparición (± 1 min), dentro del rango. */
function windowOf(
  item: { firstSeen: string | null; lastSeen: string | null },
  range: { from: string; to: string },
): { from: string; to: string } {
  const first = item.firstSeen ? Date.parse(item.firstSeen) : Number.NaN;
  const last = item.lastSeen ? Date.parse(item.lastSeen) : Number.NaN;
  if (!Number.isFinite(first) || !Number.isFinite(last)) return range;
  return {
    from: new Date(Math.max(Date.parse(range.from), first - PADDING_MS)).toISOString(),
    to: new Date(Math.min(Date.parse(range.to), last + PADDING_MS)).toISOString(),
  };
}

const count = (value: number) => value.toLocaleString('es-PE');

/**
 * Hallazgos en lenguaje llano a partir de sesiones, llamadas de dinero y lecturas sensibles.
 * Cada uno con su evidencia y el filtro de «Registros» que la muestra.
 */
export function buildFindings(input: {
  readonly from: string;
  readonly to: string;
  readonly sessions: readonly BackofficeSession[];
  readonly moneyCallers: readonly MoneyCaller[];
  readonly sensitiveReads: readonly Caller[];
}): Finding[] {
  const range = { from: input.from, to: input.to };
  const findings: Finding[] = [];
  for (const session of input.sessions) {
    const authActivity = session.logins + session.refreshes + session.staffOk;
    if (session.hosting && authActivity > 0) {
      const refreshOnly = session.refreshes > 0 && session.logins === 0;
      const acted = session.writes > 0 || session.moneyCalls > 0 || session.exports > 0;
      findings.push({
        id: `hosting-session:${session.ip}`,
        severity: acted ? 'critical' : 'high',
        title: 'Sesión de backoffice desde VPN/hosting',
        summary: refreshOnly
          ? `${who(session)} renovó token ${count(session.refreshes)} ${
              session.refreshes === 1 ? 'vez' : 'veces'
            } sin iniciar sesión`
          : `${who(session)} usó el backoffice (${count(session.logins)} login${
              session.logins === 1 ? '' : 's'
            }, ${count(session.staffOk)} llamadas de staff con 200)`,
        evidence: [
          { label: 'Renovaciones de token', value: count(session.refreshes) },
          { label: 'Logins', value: count(session.logins) },
          { label: 'Llamadas de staff 2xx', value: count(session.staffOk) },
          { label: 'Escrituras', value: count(session.writes) },
          { label: 'Exportaciones', value: count(session.exports) },
          { label: 'Riesgo', value: `${session.risk.score}/100` },
        ],
        records: { ...windowOf(session, range), ip: session.ip },
      });
    } else if (
      session.refreshes > 0 &&
      session.logins === 0 &&
      session.country &&
      session.country !== 'PE'
    ) {
      findings.push({
        id: `refresh-abroad:${session.ip}`,
        severity: 'high',
        title: 'Sesión renovada fuera de Perú sin inicio de sesión',
        summary: `${who(session)} renovó token ${count(session.refreshes)} veces sin iniciar sesión en el rango`,
        evidence: [
          { label: 'Renovaciones de token', value: count(session.refreshes) },
          { label: 'Llamadas de staff 2xx', value: count(session.staffOk) },
          { label: 'Riesgo', value: `${session.risk.score}/100` },
        ],
        records: { ...windowOf(session, range), ip: session.ip },
      });
    }
    if (session.newCountry && session.logins > 0) {
      findings.push({
        id: `new-country:${session.ip}`,
        severity: session.hosting ? 'high' : 'medium',
        title: 'Login correcto desde país nuevo',
        summary: `${who(session)} inició sesión ${count(session.logins)} ${
          session.logins === 1 ? 'vez' : 'veces'
        } desde ${session.country}, país sin logins correctos en los ${BASELINE_DAYS} días previos`,
        evidence: [
          { label: 'Logins correctos', value: count(session.logins) },
          { label: 'Primer evento (Lima)', value: limaTime(session.firstSeen) },
          { label: 'User-Agents', value: count(session.userAgents) },
        ],
        records: {
          ...windowOf(session, range),
          ip: session.ip,
          path: '/auth-service/v1/login',
        },
      });
    }
    if (session.staffDenied >= STAFF_DENIED_MIN && session.staffDenied > session.staffOk) {
      findings.push({
        id: `staff-denied:${session.ip}`,
        severity: 'medium',
        title: 'Intentos sobre endpoints de staff denegados (403)',
        summary: `${who(session)} recibió ${count(session.staffDenied)} respuestas 403 en /backoffice/`,
        evidence: [
          { label: '403 en staff', value: count(session.staffDenied) },
          { label: '2xx en staff', value: count(session.staffOk) },
        ],
        records: { ...windowOf(session, range), ip: session.ip, path: '/backoffice/' },
      });
    }
  }
  for (const reader of input.sensitiveReads) {
    const abroad = reader.country !== null && reader.country !== 'PE';
    if (!abroad && !reader.hosting) continue;
    const exportPath = reader.endpoints.find((endpoint) => /export/iu.test(endpoint.key));
    findings.push({
      id: `sensitive-read:${reader.ip}`,
      severity: reader.hosting ? 'critical' : 'high',
      title: exportPath
        ? 'Exportación de datos desde fuera de Perú'
        : 'Lectura sensible desde fuera de Perú',
      summary: `${who(reader)} ${exportPath ? 'exportó' : 'consultó'} ${
        exportPath ? exportPath.key : (reader.endpoints[0]?.key ?? 'datos sensibles')
      } (${count(reader.count)} registro${reader.count === 1 ? '' : 's'})`,
      evidence: [
        { label: 'Llamadas', value: count(reader.count) },
        { label: 'Rutas', value: reader.endpoints.map((endpoint) => endpoint.key).join(', ') },
        { label: 'Estados', value: reader.statuses.map((status) => status.key).join(', ') },
        { label: 'Primer evento (Lima)', value: limaTime(reader.firstSeen) },
      ],
      records: {
        ...windowOf(reader, range),
        ip: reader.ip,
        ...(exportPath ? { path: 'export' } : {}),
      },
    });
  }
  for (const caller of input.moneyCallers) {
    if (caller.newCaller) {
      findings.push({
        id: `money-new:${caller.ip}`,
        severity: caller.hosting || caller.channel === 'backoffice' ? 'critical' : 'high',
        title: 'Movimiento de dinero desde IP nueva',
        summary: `${who(caller)} hizo ${count(caller.count)} llamada${
          caller.count === 1 ? '' : 's'
        } que mueven dinero (${caller.endpoints[0]?.key ?? '—'}) y no aparece en los ${BASELINE_DAYS} días previos`,
        evidence: [
          { label: 'Llamadas', value: count(caller.count) },
          {
            label: 'Canal',
            value: caller.channel === 'mixed' ? 'Mixto' : CHANNEL_LABEL[caller.channel],
          },
          { label: 'Estados', value: caller.statuses.map((status) => status.key).join(', ') },
          { label: 'Primer evento (Lima)', value: limaTime(caller.firstSeen) },
        ],
        records: { ...windowOf(caller, range), ip: caller.ip },
      });
    }
    if (caller.offHours > 0) {
      findings.push({
        id: `money-off-hours:${caller.ip}`,
        severity: caller.channel === 'backoffice' ? 'high' : 'medium',
        title: 'Movimiento de dinero fuera de horario',
        summary: `${who(caller)} hizo ${count(caller.offHours)} llamada${
          caller.offHours === 1 ? '' : 's'
        } de dinero entre las 22:00 y las 06:00 (Lima)`,
        evidence: [
          { label: 'Fuera de horario', value: count(caller.offHours) },
          { label: 'Total', value: count(caller.count) },
        ],
        records: { ...windowOf(caller, range), ip: caller.ip },
      });
    }
  }
  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.title.localeCompare(b.title),
  );
}

/* ------------------------------------------------------- Línea de tiempo */

export interface TimelineMinute {
  /** `2026-11-17 14:43` en hora de Lima. */
  readonly minute: string;
  readonly count: number;
  readonly lines: ReadonlyArray<{
    readonly text: string;
    readonly count: number;
    readonly money: boolean;
  }>;
}

/**
 * Línea de tiempo minuto a minuto (Lima) de los eventos de una IP: «POST /ruta 200 ×3».
 * Entrada en cualquier orden; salida cronológica.
 */
export function minuteTimeline(
  events: ReadonlyArray<{
    readonly at: string;
    readonly method: string | null;
    readonly host: string | null;
    readonly path: string | null;
    readonly status: number | null;
  }>,
): TimelineMinute[] {
  const minutes = new Map<string, Map<string, { count: number; money: boolean }>>();
  const sorted = [...events].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  for (const event of sorted) {
    const minute = limaTime(event.at, false);
    if (!minute) continue;
    const text =
      `${event.method ?? '—'} ${event.host ?? ''}${event.path ?? ''} ${event.status ?? ''}`.trim();
    const lines = minutes.get(minute) ?? new Map<string, { count: number; money: boolean }>();
    const line = lines.get(text) ?? {
      count: 0,
      money: moneyMovementRule(event.method, event.path) !== null,
    };
    line.count += 1;
    lines.set(text, line);
    minutes.set(minute, lines);
  }
  return Array.from(minutes.entries()).map(([minute, lines]) => ({
    minute,
    count: Array.from(lines.values()).reduce((sum, line) => sum + line.count, 0),
    lines: Array.from(lines.entries()).map(([text, line]) => ({
      text,
      count: line.count,
      money: line.money,
    })),
  }));
}

/* ------------------------------------------------------------ Histograma */

const INTERVALS: ReadonlyArray<readonly [string, number]> = [
  ['1m', 60e3],
  ['5m', 5 * 60e3],
  ['15m', 15 * 60e3],
  ['30m', 30 * 60e3],
  ['1h', 3600e3],
  ['3h', 3 * 3600e3],
  ['6h', 6 * 3600e3],
  ['12h', 12 * 3600e3],
  ['1d', 24 * 3600e3],
];

/** Intervalo fijo para ~48 columnas o menos. */
export function moneyInterval(from: string, to: string): string {
  const span = Math.max(0, Date.parse(to) - Date.parse(from));
  return (INTERVALS.find(([, ms]) => span / ms <= 48) ?? INTERVALS[INTERVALS.length - 1])[0];
}

/* ------------------------------------------------------------ Qué hacer */

const FINDING_NEXT_STEP: Readonly<Record<string, string>> = {
  'hosting-session':
    'Pregunta a la persona dueña de la cuenta si usaba una VPN o un servidor. Si no lo reconoce: cierra sus sesiones, cambia su contraseña y su segundo factor, y bloquea la IP en Cloudflare.',
  'refresh-abroad':
    'Renovar el token sin iniciar sesión suele indicar un token copiado. Si la persona no lo reconoce: cierra sus sesiones y bloquea la IP.',
  'new-country':
    'Confirma con la persona si estaba de viaje. Si no, cambia su contraseña y revisa qué hizo la sesión.',
  'staff-denied':
    'Alguien intentó usar funciones de personal sin permiso. Revisa qué cuenta fue y bloquea la IP si no es interna.',
  'sensitive-read':
    'Confirma quién exportó y si estaba autorizado. Si no, trátalo como posible fuga de datos y abre un incidente.',
  'money-new':
    'Confirma con el equipo de pagos que ese origen es legítimo antes de liquidar las operaciones.',
  'money-off-hours':
    'Verifica con el equipo de pagos que esas operaciones fuera de horario estaban previstas.',
};

/** Siguiente paso en lenguaje llano de un hallazgo (por su tipo, el prefijo del id) o `null`. */
export function findingNextStep(findingId: string): string | null {
  return FINDING_NEXT_STEP[findingId.split(':')[0] ?? ''] ?? null;
}
