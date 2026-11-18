/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  Baseline,
  buildFindings,
  buildSession,
  Caller,
  channelOfHost,
  hostingProvider,
  IpStats,
  isOffHours,
  minuteTimeline,
  MoneyCaller,
  moneyInterval,
  moneyMovementRule,
  normalizeAnalysisQuery,
  rankSessions,
  scoreSession,
  sensitiveReadRule,
} from './cloudflare_analysis';

/** Casos de referencia del 17/11/2026 (credencial robada de un empleado B89). */
const FROM = '2026-11-17T05:00:00.000Z';
const TO = '2026-11-18T05:00:00.000Z';

function stats(overrides: Partial<IpStats> & { ip: string }): IpStats {
  return {
    country: 'PE',
    asn: 6147,
    asnName: 'Telefonica del Peru S.A.A.',
    firstSeen: '2026-11-17T14:00:00.000Z',
    lastSeen: '2026-11-17T22:00:00.000Z',
    requests: 100,
    logins: 0,
    loginsFailed: 0,
    refreshes: 0,
    staffOk: 0,
    staffDenied: 0,
    writes: 0,
    exports: 0,
    moneyCalls: 0,
    userAgents: 1,
    topUserAgents: ['Mozilla/5.0 (Windows NT 10.0)'],
    hosts: ['prodv2-apipayments.b89.io'],
    ...overrides,
  };
}

const OFFICE = stats({ ip: '190.43.10.20', logins: 3, refreshes: 20, staffOk: 400 });
const DATACAMP = stats({
  ip: '62.93.177.8',
  country: 'CO',
  asn: 60068,
  asnName: 'Datacamp Limited',
  refreshes: 13,
  staffOk: 41,
});
const AWS_TAKEOVER = stats({
  ip: '54.156.173.233',
  country: 'US',
  asn: 14618,
  asnName: 'AMAZON-AES',
  firstSeen: '2026-11-17T19:43:00.000Z',
  lastSeen: '2026-11-17T19:58:00.000Z',
  refreshes: 4,
  staffOk: 25,
  writes: 3,
  moneyCalls: 3,
  userAgents: 2,
});
const BRAZIL = stats({
  ip: '2001:1284:f514:51a2::1',
  country: 'BR',
  asn: 28573,
  asnName: 'Claro NXT Telecomunicacoes Ltda',
  firstSeen: '2026-11-17T17:45:43.000Z',
  logins: 1,
  staffOk: 12,
});

const BASELINE: Baseline = {
  available: true,
  backofficeIps: new Set([OFFICE.ip]),
  moneyIps: new Set([OFFICE.ip, '34.200.1.1']),
  loginCountries: new Set(['PE']),
};

function caller(overrides: Partial<Caller> & { ip: string }): Caller {
  return {
    country: 'PE',
    asn: null,
    asnName: null,
    hosting: null,
    count: 1,
    firstSeen: '2026-11-17T15:00:00.000Z',
    lastSeen: '2026-11-17T15:00:00.000Z',
    endpoints: [],
    statuses: [{ key: '200', count: 1 }],
    userAgents: [],
    hosts: [{ key: 'prodv2-apipayments.b89.io', count: 1 }],
    ...overrides,
  };
}

const EXPORT_IN = caller({
  ip: '106.51.247.10',
  country: 'IN',
  asn: 24309,
  asnName: 'Atria Convergence Technologies',
  endpoints: [{ key: '/backoffice/v2/balances/export', count: 2 }],
  count: 2,
});
const EXPORT_DE = caller({
  ip: '3.122.141.238',
  country: 'DE',
  asn: 16509,
  asnName: 'AMAZON-02',
  hosting: 'Amazon',
  endpoints: [{ key: '/backoffice/v2/balances/export', count: 1 }],
});
const MONEY_AWS: MoneyCaller = {
  ...caller({
    ip: AWS_TAKEOVER.ip,
    country: 'US',
    asn: 14618,
    asnName: 'AMAZON-AES',
    hosting: 'Amazon',
    count: 3,
    firstSeen: '2026-11-17T19:44:10.000Z',
    lastSeen: '2026-11-17T19:51:00.000Z',
    endpoints: [{ key: '/backoffice/v2/balances/transactions', count: 3 }],
    statuses: [{ key: '200', count: 3 }],
  }),
  channel: 'backoffice',
  offHours: 0,
  newCaller: true,
};
const MONEY_MERCHANT: MoneyCaller = {
  ...caller({
    ip: '34.200.1.1',
    asnName: 'AMAZON-AES',
    hosting: 'Amazon',
    count: 500,
    endpoints: [{ key: '/payouts/v1/quotes/accept', count: 500 }],
    hosts: [{ key: 'apipayments.b89.io', count: 500 }],
  }),
  channel: 'integration',
  offHours: 0,
  newCaller: false,
};

describe('reglas de negocio B89', () => {
  it('reconoce ASN de hosting/VPN por nombre o número', () => {
    expect(hostingProvider('Datacamp Limited')).toBe('Datacamp');
    expect(hostingProvider('AMAZON-AES')).toBe('Amazon');
    expect(hostingProvider('GOOGLE LLC')).toBe('Google Cloud');
    expect(hostingProvider('The Constant Company, LLC')).toBe('Vultr');
    expect(hostingProvider('Hetzner Online GmbH')).toBe('Hetzner');
    expect(hostingProvider(null, 14061)).toBe('DigitalOcean');
    expect(hostingProvider('Telefonica del Peru S.A.A.', 6147)).toBeNull();
    expect(hostingProvider('Claro NXT Telecomunicacoes Ltda')).toBeNull();
  });

  it('clasifica los movimientos de dinero solo en métodos de escritura', () => {
    expect(moneyMovementRule('POST', '/backoffice/v2/balances/transactions')?.id).toBe(
      'balance-transaction',
    );
    expect(moneyMovementRule('GET', '/backoffice/v2/balances/transactions')).toBeNull();
    expect(moneyMovementRule('POST', '/payouts/v1/quotes/q-1/accept')?.id).toBe('payout-accept');
    expect(moneyMovementRule('POST', '/payouts/v1/quotes')).toBeNull();
    expect(moneyMovementRule('POST', '/remittance/orders/o-9/quotes/accept')?.id).toBe(
      'remittance-accept',
    );
    expect(moneyMovementRule('POST', '/remittance/mtc/operation')?.id).toBe('mtc-operation');
    expect(moneyMovementRule('PUT', '/remittance/orders/bulk-status')?.id).toBe('bulk-status');
    expect(moneyMovementRule('POST', '/payin/v1/payment')?.id).toBe('payin');
    expect(moneyMovementRule('POST', '/exchange-service/v1/rate/manual')?.id).toBe('manual-rate');
    expect(moneyMovementRule('PATCH', '/backoffice/v2/merchants/7')?.id).toBe('backoffice-write');
    expect(moneyMovementRule('POST', '/auth-service/v1/login')).toBeNull();
    expect(moneyMovementRule('POST', '/merchants/v1/sign')).toBeNull();
  });

  it('clasifica las lecturas sensibles', () => {
    expect(sensitiveReadRule('GET', '/backoffice/v2/balances/export')?.id).toBe('export');
    expect(sensitiveReadRule('GET', '/backoffice/v2/balances/transactions')?.id).toBe(
      'balance-transactions-read',
    );
    expect(sensitiveReadRule('GET', '/backoffice/v2/balances/merchants')?.id).toBe(
      'balances-merchants',
    );
    expect(sensitiveReadRule('GET', '/backoffice/v2/users')).toBeNull();
  });

  it('distingue backoffice humano e integración por host', () => {
    expect(channelOfHost('paymentsv2.b89.io')).toBe('backoffice');
    expect(channelOfHost('prodv2-apipayments.b89.io')).toBe('backoffice');
    expect(channelOfHost('uat-apipayments.b89.io')).toBe('backoffice');
    expect(channelOfHost('stgpaymentsv2.b89.io')).toBe('backoffice');
    expect(channelOfHost('apipayments.b89.io')).toBe('integration');
    expect(channelOfHost('www.b89.io')).toBe('other');
  });

  it('fuera de horario es 22:00–05:59 en Lima', () => {
    expect(isOffHours('2026-11-18T03:30:00Z')).toBe(true); // 22:30 Lima
    expect(isOffHours('2026-11-18T10:59:00Z')).toBe(true); // 05:59 Lima
    expect(isOffHours('2026-11-18T11:43:00Z')).toBe(false); // 06:43 Lima
    expect(isOffHours('2026-11-17T19:43:00Z')).toBe(false); // 14:43 Lima
  });

  it('elige un intervalo de histograma de ≤ 48 columnas', () => {
    expect(moneyInterval(FROM, TO)).toBe('30m');
    expect(moneyInterval('2026-11-17T05:00:00Z', '2026-11-17T06:00:00Z')).toBe('5m');
    expect(moneyInterval('2026-11-10T05:00:00Z', '2026-11-17T05:00:00Z')).toBe('6h');
  });

  it('el análisis solo acepta rango y zona', () => {
    const ok = normalizeAnalysisQuery({ from: FROM, to: TO, zone: 'B89.io', ip: '1.2.3.4' });
    expect(ok).toEqual({ ok: true, value: { from: FROM, to: TO, zones: ['b89.io'] } });
    expect(normalizeAnalysisQuery({ from: 'now-24h', to: TO }).ok).toBe(false);
  });
});

describe('riesgo de las sesiones del backoffice', () => {
  it('Datacamp renovando token sin login es crítico y explica por qué', () => {
    const session = buildSession(DATACAMP, BASELINE);
    expect(session.hosting).toBe('Datacamp');
    expect(session.newIp).toBe(true);
    expect(session.risk.score).toBe(80);
    expect(session.risk.level).toBe('critical');
    expect(session.risk.reasons.map((reason) => reason.label)).toEqual([
      'Sale de hosting/VPN (Datacamp)',
      'Renovó token 13 veces sin iniciar sesión en el rango',
      'Fuera de Perú (CO)',
      'IP no vista en los 14 días previos',
    ]);
  });

  it('la oficina en Lima con login normal queda baja', () => {
    const session = buildSession(OFFICE, BASELINE);
    expect(session.risk).toEqual({ score: 0, level: 'low', reasons: [] });
  });

  it('cuenta dinero en lugar de escrituras para no sumar dos veces', () => {
    const risk = scoreSession(AWS_TAKEOVER, { newIp: true, newCountry: null });
    const codes = risk.reasons.map((reason) => reason.code);
    expect(codes).toContain('money');
    expect(codes).not.toContain('writes');
    expect(risk.score).toBe(95);
  });

  it('login desde un país sin logins en la línea base', () => {
    const session = buildSession(BRAZIL, BASELINE);
    expect(session.newCountry).toBe(true);
    expect(session.risk.reasons.map((reason) => reason.code)).toEqual([
      'outsidePeru',
      'newCountry',
      'newIp',
    ]);
    expect(buildSession(BRAZIL, { ...BASELINE, available: false }).newCountry).toBeNull();
  });

  it('ordena por riesgo', () => {
    const ranked = rankSessions(
      [OFFICE, BRAZIL, DATACAMP, AWS_TAKEOVER].map((s) => buildSession(s, BASELINE)),
    );
    expect(ranked.map((session) => session.ip)).toEqual([
      AWS_TAKEOVER.ip,
      DATACAMP.ip,
      BRAZIL.ip,
      OFFICE.ip,
    ]);
  });
});

describe('hallazgos del periodo (casos de referencia del 17/11)', () => {
  const sessions = rankSessions(
    [OFFICE, DATACAMP, AWS_TAKEOVER, BRAZIL].map((s) => buildSession(s, BASELINE)),
  );
  const findings = buildFindings({
    from: FROM,
    to: TO,
    sessions,
    moneyCallers: [MONEY_AWS, MONEY_MERCHANT],
    sensitiveReads: [
      EXPORT_IN,
      EXPORT_DE,
      caller({
        ip: '190.43.10.20',
        endpoints: [{ key: '/backoffice/v2/balances/export', count: 1 }],
      }),
    ],
  });
  const byId = (id: string) => findings.find((finding) => finding.id === id);

  it('sesión de Datacamp: renovó token 13 veces sin iniciar sesión', () => {
    const finding = byId('hosting-session:62.93.177.8');
    expect(finding?.title).toBe('Sesión de backoffice desde VPN/hosting');
    expect(finding?.summary).toBe(
      '62.93.177.8 (Datacamp, CO) renovó token 13 veces sin iniciar sesión',
    );
    expect(finding?.severity).toBe('high');
    expect(finding?.records).toEqual({
      from: '2026-11-17T13:59:00.000Z',
      to: '2026-11-17T22:01:00.000Z',
      ip: '62.93.177.8',
    });
  });

  it('AWS que toma la sesión y mueve dinero es crítico (sesión y dinero desde IP nueva)', () => {
    expect(byId('hosting-session:54.156.173.233')?.severity).toBe('critical');
    const money = byId('money-new:54.156.173.233');
    expect(money?.title).toBe('Movimiento de dinero desde IP nueva');
    expect(money?.severity).toBe('critical');
    expect(money?.summary).toContain('/backoffice/v2/balances/transactions');
    expect(money?.records.ip).toBe('54.156.173.233');
  });

  it('login correcto desde Brasil, país nuevo', () => {
    const finding = byId('new-country:2001:1284:f514:51a2::1');
    expect(finding?.title).toBe('Login correcto desde país nuevo');
    expect(finding?.summary).toContain('desde BR');
    expect(finding?.records.path).toBe('/auth-service/v1/login');
  });

  it('exportaciones desde India y AWS Alemania; la de Lima no es hallazgo', () => {
    expect(byId('sensitive-read:106.51.247.10')?.title).toBe(
      'Exportación de datos desde fuera de Perú',
    );
    expect(byId('sensitive-read:106.51.247.10')?.severity).toBe('high');
    expect(byId('sensitive-read:3.122.141.238')?.severity).toBe('critical');
    expect(byId('sensitive-read:190.43.10.20')).toBeUndefined();
  });

  it('el integrador habitual no genera hallazgos; orden por gravedad', () => {
    expect(findings.some((finding) => finding.id.includes('34.200.1.1'))).toBe(false);
    expect(findings.some((finding) => finding.id.includes(OFFICE.ip))).toBe(false);
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    const severities = findings.map((finding) => order[finding.severity]);
    expect(severities).toEqual([...severities].sort((a, b) => a - b));
    expect(findings[0].severity).toBe('critical');
  });

  it('dinero fuera de horario', () => {
    const night = buildFindings({
      from: FROM,
      to: TO,
      sessions: [],
      moneyCallers: [{ ...MONEY_MERCHANT, offHours: 4 }],
      sensitiveReads: [],
    });
    expect(night.map((finding) => finding.title)).toEqual([
      'Movimiento de dinero fuera de horario',
    ]);
    expect(night[0].severity).toBe('medium');
  });
});

describe('línea de tiempo minuto a minuto', () => {
  it('agrupa por minuto de Lima y marca el dinero', () => {
    const minutes = minuteTimeline([
      {
        at: '2026-11-17T19:44:30Z',
        method: 'POST',
        host: 'prodv2-apipayments.b89.io',
        path: '/backoffice/v2/balances/transactions',
        status: 200,
      },
      {
        at: '2026-11-17T19:43:05Z',
        method: 'POST',
        host: 'prodv2-apipayments.b89.io',
        path: '/auth-service/v1/refresh-token',
        status: 200,
      },
      {
        at: '2026-11-17T19:44:10Z',
        method: 'POST',
        host: 'prodv2-apipayments.b89.io',
        path: '/backoffice/v2/balances/transactions',
        status: 200,
      },
    ]);
    expect(minutes.map((minute) => [minute.minute, minute.count])).toEqual([
      ['2026-11-17 14:43', 1],
      ['2026-11-17 14:44', 2],
    ]);
    expect(minutes[1].lines).toEqual([
      {
        text: 'POST prodv2-apipayments.b89.io/backoffice/v2/balances/transactions 200',
        count: 2,
        money: true,
      },
    ]);
    expect(minutes[0].lines[0].money).toBe(false);
  });
});
