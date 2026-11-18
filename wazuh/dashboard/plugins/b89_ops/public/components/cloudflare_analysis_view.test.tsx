/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AnomalyRow, buildFindings, buildSession, CloudflareAnalysis, IpStats } from '../../common';
import { AnalysisContent, AnomaliesSection, TimelineList } from './cloudflare_analysis_view';
import {
  activeTab,
  anomalyRecords,
  DEFAULT_STATE,
  moneyColumns,
  parseViewState,
  recordsState,
  viewStateSearch,
} from './cloudflare_traffic_model';

const FROM = '2026-11-17T05:00:00.000Z';
const TO = '2026-11-18T05:00:00.000Z';

describe('pestañas Análisis / Registros en la URL', () => {
  it('sin parámetros abre «Análisis»; los enlaces antiguos con filtros abren «Registros»', () => {
    expect(activeTab(DEFAULT_STATE)).toBe('analisis');
    expect(activeTab(parseViewState('?r=24h&ds=http'))).toBe('registros');
    expect(activeTab(parseViewState('?ip=1.2.3.4'))).toBe('registros');
    expect(activeTab(parseViewState('?zone=b89.io'))).toBe('analisis');
    expect(activeTab(parseViewState('?tab=analisis&ip=1.2.3.4'))).toBe('analisis');
    expect(activeTab(parseViewState('?tab=registros'))).toBe('registros');
    expect(activeTab(parseViewState('?tab=otra'))).toBe('analisis');
  });

  it('solo escribe `tab` cuando no se deduce', () => {
    expect(viewStateSearch({ ...DEFAULT_STATE, tab: 'analisis' })).toBe('');
    expect(viewStateSearch({ ...DEFAULT_STATE, tab: 'registros' })).toBe('tab=registros');
    expect(viewStateSearch({ ...DEFAULT_STATE, dataset: 'http', tab: 'registros' })).toBe(
      'ds=http',
    );
    expect(viewStateSearch({ ...DEFAULT_STATE, dataset: 'http', tab: 'analisis' })).toBe(
      'tab=analisis&ds=http',
    );
  });

  it('un hallazgo abre «Registros» HTTP con su IP, ruta y ventana', () => {
    const state = recordsState({ from: FROM, to: TO, ip: '62.93.177.8', path: 'export' }, 'b89.io');
    expect(state).toEqual({
      tab: 'registros',
      range: 'custom',
      from: FROM,
      to: TO,
      dataset: 'http',
      filters: { zone: 'b89.io', ip: '62.93.177.8', path: 'export' },
    });
    // Con filtros, `tab=registros` se deduce: el enlace no lo necesita.
    const { tab, ...rest } = state;
    expect(tab).toBe('registros');
    expect(parseViewState(`?${viewStateSearch(state)}`)).toEqual(rest);
  });

  it('una anomalía abre su entidad ± 30 min', () => {
    const row: AnomalyRow = {
      id: 'r',
      start: '2026-11-17T19:40:00.000Z',
      end: '2026-11-17T19:50:00.000Z',
      detectorId: 'd',
      detectorName: 'b89-cf-payments-errors',
      entity: [{ name: 'http.host', value: 'apipayments.b89.io' }],
      grade: 0.7,
      confidence: 0.8,
      features: [],
    };
    expect(anomalyRecords(row)).toEqual({
      from: '2026-11-17T19:10:00.000Z',
      to: '2026-11-17T20:20:00.000Z',
      host: 'apipayments.b89.io',
    });
    expect(anomalyRecords({ ...row, entity: [{ name: 'client.ip', value: '1.2.3.4' }] })?.ip).toBe(
      '1.2.3.4',
    );
  });

  it('el histograma de dinero marca la franja 22:00–06:00 de Lima', () => {
    const columns = moneyColumns(
      [
        { at: '2026-11-18T04:00:00.000Z', backoffice: 1, integration: 1 },
        { at: '2026-11-17T19:30:00.000Z', backoffice: 3, integration: 1 },
      ],
      '30m',
    );
    expect(columns.map((column) => [column.label, column.offHours, column.height])).toEqual([
      ['2026-11-17 23:00', true, 50],
      ['2026-11-17 14:30', false, 100],
    ]);
  });
});

const STATS: IpStats = {
  ip: '62.93.177.8',
  country: 'CO',
  asn: 60068,
  asnName: 'Datacamp Limited',
  firstSeen: '2026-11-17T14:00:00.000Z',
  lastSeen: '2026-11-17T22:00:00.000Z',
  requests: 60,
  logins: 0,
  loginsFailed: 0,
  refreshes: 13,
  staffOk: 41,
  staffDenied: 0,
  writes: 0,
  exports: 0,
  moneyCalls: 0,
  userAgents: 1,
  topUserAgents: ['Mozilla/5.0'],
  hosts: ['prodv2-apipayments.b89.io'],
};

function analysis(overrides: Partial<CloudflareAnalysis> = {}): CloudflareAnalysis {
  const sessions = [
    buildSession(STATS, {
      available: true,
      backofficeIps: new Set(),
      moneyIps: new Set(),
      loginCountries: new Set(['PE']),
    }),
  ];
  return {
    generatedAt: TO,
    from: FROM,
    to: TO,
    zones: [],
    httpRecords: 1200,
    sampledRecords: 1100,
    baseline: { from: '2026-11-03T05:00:00.000Z', to: FROM, available: true },
    findings: buildFindings({ from: FROM, to: TO, sessions, moneyCallers: [], sensitiveReads: [] }),
    sessions,
    money: {
      interval: '30m',
      histogram: [],
      totals: { backoffice: 0, integration: 0 },
      callers: [],
    },
    sensitiveReads: [],
    anomalies: {
      status: 'ok',
      detectors: [],
      detectorsResolved: true,
      rows: [],
      message: 'Aún no hay detectores b89-cf-* creados.',
    },
    partial: false,
    ...overrides,
  };
}

describe('pestaña «Análisis»', () => {
  it('primero el aviso de muestreo y los hallazgos; luego el detalle', () => {
    const html = renderToStaticMarkup(
      <AnalysisContent data={analysis()} basePath="" onOpenRecords={() => undefined} />,
    );
    expect(html).toContain('Datos muestreados.');
    expect(html).toContain('registros muestreados');
    expect(html).toMatch(/1.?200 registros HTTP/);
    const order = [
      'Resumen del periodo',
      'Sesiones del backoffice',
      'Movimientos de dinero',
      'Exportaciones y lecturas sensibles',
      'Anomalías (ML)',
    ].map((title) => html.indexOf(title));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(html).toContain('62.93.177.8 (Datacamp, CO) renovó token 13 veces sin iniciar sesión');
    expect(html).toContain('Ver los registros de este hallazgo');
    expect(html).toContain('VPN/hosting · Datacamp');
    expect(html).toContain('Renovó token 13 veces sin iniciar sesión en el rango');
    expect(html).toContain('Ninguna llamada de dinero en el rango.');
    expect(html).toContain('Aún no hay detectores b89-cf-* creados.');
  });

  it('estados vacíos y sin línea base dichos en claro', () => {
    const html = renderToStaticMarkup(
      <AnalysisContent
        data={analysis({
          findings: [],
          sessions: [],
          httpRecords: 0,
          sampledRecords: 0,
          baseline: { from: '', to: '', available: false },
        })}
        basePath=""
        onOpenRecords={() => undefined}
      />,
    );
    expect(html).toContain('Sin tráfico HTTP en el rango');
    expect(html).toContain('Sin tráfico del backoffice en el rango.');
    expect(html).toContain('Sin línea base de 14 días');
  });

  it('anomalías: 403 con mensaje claro; filas con hora de Lima, grado y enlace', () => {
    const forbidden = renderToStaticMarkup(
      <AnomaliesSection
        anomalies={{
          status: 'forbidden',
          detectors: [],
          detectorsResolved: false,
          rows: [],
          message: 'Tu rol no puede leer los resultados de Anomaly Detection.',
        }}
        onOpenRecords={() => undefined}
      />,
    );
    expect(forbidden).toContain('Tu rol no puede leer los resultados de Anomaly Detection.');
    const rows = renderToStaticMarkup(
      <AnomaliesSection
        anomalies={{
          status: 'ok',
          detectors: [],
          detectorsResolved: false,
          rows: [
            {
              id: 'r',
              start: '2026-11-17T19:40:00.000Z',
              end: '2026-11-17T19:50:00.000Z',
              detectorId: 'AbC123',
              detectorName: null,
              entity: [{ name: 'client.ip', value: '54.156.173.233' }],
              grade: 0.82,
              confidence: 0.9,
              features: [{ name: 'calls', value: 3 }],
            },
          ],
          message: null,
        }}
        onOpenRecords={() => undefined}
      />,
    );
    expect(rows).toContain('se muestran sus identificadores');
    expect(rows).toContain('AbC123');
    expect(rows).toContain('2026-11-17 14:40 → 14:50');
    expect(rows).toContain('82 %');
    expect(rows).toContain('calls = 3');
    expect(rows).toContain('Registros ±30 min');
  });

  it('línea de tiempo minuto a minuto', () => {
    const html = renderToStaticMarkup(
      <TimelineList
        truncated
        minutes={[
          {
            minute: '2026-11-17 14:44',
            count: 3,
            lines: [
              { text: 'POST /backoffice/v2/balances/transactions 200', count: 3, money: true },
            ],
          },
        ]}
      />,
    );
    expect(html).toContain('11-17 14:44');
    expect(html).toContain('×3');
    expect(html).toContain('dinero');
    expect(html).toContain('200 registros más recientes');
  });
});
