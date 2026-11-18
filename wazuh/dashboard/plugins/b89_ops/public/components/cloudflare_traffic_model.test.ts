/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { TrafficAggregations, TrafficEvent } from '../../common';
import { cloudflareMetrics } from './service_cards';
import {
  applyTop,
  DEFAULT_STATE,
  errorMessage,
  filterChips,
  flattenSource,
  histogramColumns,
  hostSessionState,
  intervalLabel,
  ipActivityState,
  parseViewState,
  resolveRange,
  statTiles,
  targetOf,
  viewFilters,
  viewStateSearch,
  withFilter,
} from './cloudflare_traffic_model';

const NOW = Date.parse('2026-11-18T15:00:00Z');

const EVENT: TrafficEvent = {
  id: 'abc',
  index: 'b89-cloudflare-traffic-2026.11.17',
  at: '2026-11-17T17:10:00.000Z',
  ingestedAt: null,
  dataset: 'http',
  source: 'logpush',
  sampled: false,
  sampleInterval: null,
  history: false,
  zone: 'b89.io',
  clientIp: '1.2.3.4',
  country: 'PE',
  asn: 6147,
  asnName: 'Telefonica',
  method: 'POST',
  host: 'app.b89.io',
  path: '/login',
  status: 401,
  userAgent: 'curl/8.0',
  action: null,
  detail: null,
  raw: { '@timestamp': '2026-11-17T17:10:00Z', http: { status: 401, host: 'app.b89.io' } },
};

const AGGS: TrafficAggregations = {
  interval: '1h',
  histogram: [
    { at: '2026-11-17T17:00:00.000Z', total: 10, byDataset: { http: 8, dns: 2 } },
    { at: '2026-11-17T18:00:00.000Z', total: 5, byDataset: { http: 5 } },
  ],
  datasets: { http: 13, dns: 2, firewall: 0, audit: 0 },
  uniqueIps: 3,
  countries: 2,
  httpWithStatus: 10,
  errors4xx: 2,
  errors5xx: 1,
  sampled: 0,
  topIps: [],
  topHosts: [],
  topPaths: [],
  statusClasses: [],
  topCountries: [],
  methods: [],
  zones: [],
};

describe('vista de tráfico: estado en la URL', () => {
  it('por defecto 24 h, todos los tipos, sin filtros', () => {
    expect(parseViewState('')).toEqual(DEFAULT_STATE);
    expect(viewStateSearch(DEFAULT_STATE)).toBe('');
  });

  it('enlace compartido: ?from=…&ip=… es un rango personalizado hasta ahora', () => {
    const state = parseViewState('?from=2026-11-17T17:00:00Z&ip=1.2.3.4');
    expect(state.range).toBe('custom');
    expect(state.filters).toEqual({ ip: '1.2.3.4' });
    const range = resolveRange(state, NOW);
    expect(range).toEqual({ from: '2026-11-17T17:00:00.000Z', to: '2026-11-18T15:00:00.000Z' });
    const filters = viewFilters(state, NOW);
    expect(filters.ok && filters.value.ip).toBe('1.2.3.4');
  });

  it('ida y vuelta: rango, tipo y filtros', () => {
    const search = 'r=7d&ds=dns&zone=b89.io&q=login';
    const state = parseViewState(`?${search}`);
    expect(state).toMatchObject({
      range: '7d',
      dataset: 'dns',
      filters: { zone: 'b89.io', q: 'login' },
    });
    expect(viewStateSearch(state)).toBe(search);
    expect(resolveRange(state, NOW).from).toBe('2026-11-11T15:00:00.000Z');
  });

  it('valores inválidos de la URL quedan como error de validación, no como consulta', () => {
    const state = parseViewState('?r=24h&ip=hola&ds=otro');
    expect(state.dataset).toBe('all');
    const filters = viewFilters(state, NOW);
    expect(filters.ok).toBe(false);
  });

  it('chips de filtros y quitar uno', () => {
    const state = withFilter(withFilter(DEFAULT_STATE, 'ip', '1.2.3.4'), 'host', 'app.b89.io');
    expect(filterChips(state).map((chip) => chip.label)).toEqual(['IP', 'Host']);
    expect(filterChips(withFilter(state, 'ip', '')).map((chip) => chip.key)).toEqual(['host']);
  });

  it('clic en una lista filtra por ese valor', () => {
    expect(applyTop(DEFAULT_STATE, 'topIps', '9.9.9.9').filters.ip).toBe('9.9.9.9');
    expect(applyTop(DEFAULT_STATE, 'statusClasses', '5xx').filters.status).toBe('5xx');
    expect(applyTop(DEFAULT_STATE, 'topCountries', 'BR').filters.country).toBe('BR');
  });
});

describe('vista de tráfico: acciones rápidas', () => {
  it('«Ver toda la actividad de esta IP» conserva el rango y quita los demás filtros', () => {
    const state = { ...DEFAULT_STATE, dataset: 'http' as const, filters: { path: '/x' } };
    expect(ipActivityState(state, EVENT)).toEqual({ ...DEFAULT_STATE, filters: { ip: '1.2.3.4' } });
    expect(ipActivityState(state, { ...EVENT, clientIp: null })).toBeNull();
  });

  it('«Ver esta sesión de host»: IP + host + UA, una hora antes y después', () => {
    const session = hostSessionState(EVENT);
    expect(session).toEqual({
      range: 'custom',
      from: '2026-11-17T16:10:00.000Z',
      to: '2026-11-17T18:10:00.000Z',
      dataset: 'all',
      filters: { ip: '1.2.3.4', host: 'app.b89.io', ua: 'curl/8.0' },
    });
    expect(viewStateSearch(session!)).toBe(
      'from=2026-11-17T16%3A10%3A00.000Z&to=2026-11-17T18%3A10%3A00.000Z&ip=1.2.3.4&host=app.b89.io&ua=curl%2F8.0',
    );
    expect(hostSessionState({ ...EVENT, dataset: 'dns' })).toBeNull();
    expect(hostSessionState({ ...EVENT, host: null })).toBeNull();
  });
});

describe('vista de tráfico: cifras y detalle', () => {
  it('cifras: peticiones, IPs, % de errores y países', () => {
    const tiles = statTiles(AGGS, 'all');
    expect(tiles.map((tile) => [tile.label, tile.value])).toEqual([
      ['Peticiones HTTP', '13'],
      ['IPs únicas', '3'],
      ['% errores 4xx/5xx', '30 %'],
      ['Países', '2'],
    ]);
    expect(tiles[2].tone).toBe('danger');
    expect(statTiles({ ...AGGS, httpWithStatus: 0 }, 'all')[2].value).toBe('—');
    expect(statTiles({ ...AGGS, sampled: 12 }, 'all')[0].hint).toContain('muestreados');
  });

  it('histograma en hora de Lima con alturas relativas', () => {
    const [first, second] = histogramColumns(AGGS);
    expect(first.label).toBe('2026-11-17 12:00');
    expect(first.height).toBe(100);
    expect(second.height).toBe(50);
    expect(first.segments).toEqual([
      { dataset: 'http', count: 8 },
      { dataset: 'dns', count: 2 },
    ]);
    expect(first.summary).toContain('(Lima)');
    expect(intervalLabel('1h')).toBe('1 hora');
    expect(intervalLabel('12h')).toBe('12 horas');
    expect(intervalLabel(null)).toBeNull();
  });

  it('detalle: todos los campos aplanados y ordenados', () => {
    expect(flattenSource(EVENT.raw)).toEqual([
      ['@timestamp', '2026-11-17T17:10:00Z'],
      ['http.host', 'app.b89.io'],
      ['http.status', '401'],
    ]);
    expect(targetOf(EVENT)).toBe('app.b89.io/login');
    expect(targetOf({ ...EVENT, dataset: 'dns', detail: 'b89.io · A' })).toBe('b89.io · A');
  });

  it('errores: sin permiso y sin índice como aviso; el resto como error', () => {
    expect(errorMessage(Object.assign(new Error('x'), { status: 403 })).tone).toBe('warning');
    expect(errorMessage(Object.assign(new Error(''), { status: 404 })).title).toContain('índices');
    expect(errorMessage(new Error('boom')).tone).toBe('danger');
  });
});

describe('tarjeta de Cloudflare en el resumen', () => {
  it('muestra tráfico, no bloqueos del WAF, y enlaza a la vista', () => {
    const metrics = cloudflareMetrics({
      traffic_readable: 1,
      http_24h: 1200,
      http_sampled_24h: 10,
      dns_24h: 30,
      security_24h: 4,
      zones: 3,
      zones_active: 2,
    });
    expect(metrics.map((metric) => metric.label)).toEqual([
      'Peticiones HTTP 24 h',
      'Consultas DNS 24 h',
      'Eventos de seguridad 24 h',
      'Zonas vigiladas',
    ]);
    expect(metrics[0].path).toBe('/app/b89-cloudflare-traffic?r=24h&ds=http');
    expect(metrics[0].hint).toContain('muestreados');
    expect(metrics[3].value).toContain('2 con tráfico');
    expect(JSON.stringify(metrics)).not.toMatch(/WAF 24|waf_blocks/u);
  });

  it('sin permiso de lectura del índice de tráfico lo dice', () => {
    const [first] = cloudflareMetrics({ traffic_readable: 0, zones: 2 });
    expect(first.value).toBe('Sin permiso');
  });
});
