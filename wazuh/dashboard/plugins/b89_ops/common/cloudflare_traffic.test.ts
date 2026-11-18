/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  csvCell,
  csvHeader,
  csvRow,
  fieldValue,
  limaInputToIso,
  limaInputValue,
  limaTime,
  normalizeTrafficFilters,
  trafficQueryParams,
  validIp,
} from './cloudflare_traffic';

const RANGE = { from: '2026-11-17T17:00:00Z', to: '2026-11-18T17:00:00Z' };

describe('tráfico de Cloudflare: validación de filtros', () => {
  it('exige un rango ISO con zona y de como máximo 31 días', () => {
    expect(normalizeTrafficFilters({}).ok).toBe(false);
    expect(normalizeTrafficFilters({ from: 'now-24h', to: 'now' }).ok).toBe(false);
    expect(normalizeTrafficFilters({ from: '2026-11-17T17:00:00', to: RANGE.to }).ok).toBe(false);
    expect(normalizeTrafficFilters({ from: RANGE.to, to: RANGE.from }).ok).toBe(false);
    const tooLong = normalizeTrafficFilters({ from: '2026-10-01T00:00:00Z', to: RANGE.to });
    expect(tooLong).toEqual({ ok: false, error: 'El rango máximo es de 31 días.' });
    const ok = normalizeTrafficFilters({ from: '2026-11-17T12:00:00-05:00', to: RANGE.to });
    expect(ok.ok && ok.value.from).toBe('2026-11-17T17:00:00.000Z');
  });

  it('normaliza tipos, zonas, método, país, estado y ASN', () => {
    const result = normalizeTrafficFilters({
      ...RANGE,
      dataset: ['HTTP', 'dns,http'],
      zone: 'B89.io',
      method: 'post',
      country: 'pe',
      status: '4XX',
      asn: 'AS6147',
      host: 'App.B89.io',
      ip: '190.12.0.0/16',
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({
      datasets: ['http', 'dns'],
      zones: ['b89.io'],
      method: 'POST',
      country: 'PE',
      status: '4xx',
      asn: 6147,
      host: 'app.b89.io',
      ip: '190.12.0.0/16',
    });
  });

  it('rechaza valores fuera de la lista blanca o con caracteres de control', () => {
    const bad = (extra: Record<string, string>) =>
      normalizeTrafficFilters({ ...RANGE, ...extra }).ok;
    expect(bad({ dataset: 'logs' })).toBe(false);
    expect(bad({ ip: '1.2.3.4; DROP' })).toBe(false);
    expect(bad({ ip: '999.1.1.1' })).toBe(false);
    expect(bad({ method: 'GET /' })).toBe(false);
    expect(bad({ status: '6xx' })).toBe(false);
    expect(bad({ status: '99' })).toBe(false);
    expect(bad({ country: 'PER' })).toBe(false);
    expect(bad({ asn: '12a' })).toBe(false);
    expect(bad({ host: 'a b.io' })).toBe(false);
    expect(bad({ zone: '{"match_all":{}}' })).toBe(false);
    expect(bad({ path: '/login\u0000' })).toBe(false);
    expect(bad({ q: 'x'.repeat(201) })).toBe(false);
    expect(bad({ ua: 'Mozilla/5.0 '.repeat(30) })).toBe(true);
  });

  it('IP: v4, v6 y CIDR', () => {
    expect(validIp('1.2.3.4')).toBe(true);
    expect(validIp('2001:db8::1')).toBe(true);
    expect(validIp('2001:db8::/32')).toBe(true);
    expect(validIp('10.0.0.0/4')).toBe(false);
    expect(validIp('1.2.3.4/33')).toBe(false);
    expect(validIp('::1::2')).toBe(false);
    expect(validIp('abc')).toBe(false);
  });

  it('la query de la API repite tipos y zonas y omite lo vacío', () => {
    const result = normalizeTrafficFilters({ ...RANGE, dataset: 'http,dns', ip: '1.2.3.4' });
    if (!result.ok) throw new Error(result.error);
    const params = trafficQueryParams(result.value);
    expect(params.getAll('dataset')).toEqual(['http', 'dns']);
    expect(params.get('ip')).toBe('1.2.3.4');
    expect(params.has('host')).toBe(false);
  });
});

describe('tráfico de Cloudflare: hora de Lima', () => {
  it('muestra la hora de Lima (UTC−5) y convierte la entrada a UTC', () => {
    expect(limaTime('2026-11-17T17:00:05Z')).toBe('2026-11-17 12:00:05');
    expect(limaTime('2026-11-18T03:30:00Z', false)).toBe('2026-11-17 22:30');
    expect(limaTime('nada')).toBe('');
    expect(limaInputValue('2026-11-17T17:00:00Z')).toBe('2026-11-17T12:00');
    expect(limaInputToIso('2026-11-17T12:00')).toBe('2026-11-17T17:00:00.000Z');
    expect(limaInputToIso('2026-11-17 12:00')).toBeNull();
  });
});

describe('tráfico de Cloudflare: CSV', () => {
  it('cabecera con hora_lima y @timestamp', () => {
    expect(csvHeader().startsWith('hora_lima,@timestamp,')).toBe(true);
  });

  it('fila con la hora de Lima, campos anidados o planos, y escapes', () => {
    const row = csvRow({
      '@timestamp': '2026-11-17T17:00:00Z',
      event: { dataset: 'http', sampled: true },
      'client.ip': '1.2.3.4',
      http: { path: '/a,"b"', user_agent: '=cmd|calc' },
    });
    const cells = row.trimEnd();
    expect(cells.startsWith('2026-11-17 12:00:00,2026-11-17T17:00:00Z,,http,,true')).toBe(true);
    expect(cells).toContain('1.2.3.4');
    expect(cells).toContain('"/a,""b"""');
    expect(cells).toContain("'=cmd|calc");
  });

  it('neutraliza fórmulas y serializa objetos', () => {
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell(null)).toBe('');
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
  });

  it('lee campos con puntos anidados o planos', () => {
    expect(fieldValue({ http: { status: 404 } }, 'http.status')).toBe(404);
    expect(fieldValue({ 'http.status': 500 }, 'http.status')).toBe(500);
    expect(fieldValue({ http: { user_agent: 'x' } }, 'http.user_agent')).toBe('x');
    expect(fieldValue({}, 'dns.query')).toBeUndefined();
  });
});
