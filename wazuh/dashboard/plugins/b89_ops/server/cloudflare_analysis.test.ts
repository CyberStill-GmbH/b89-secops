/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  AnalysisRequest,
  MONEY_RULES,
  moneyMovementRule,
  SENSITIVE_READ_RULES,
} from '../common/cloudflare_analysis';
import {
  AnalysisClient,
  analysisBody,
  analyzeTraffic,
  anomalyResultsBody,
  baselineBody,
  baselineRange,
  DETECTORS_PATH,
  loadAnomalies,
  MONEY_CLAUSE,
  NO_BASELINE,
  OFF_HOURS_SCRIPT,
  parseBaseline,
  SENSITIVE_CLAUSE,
} from './cloudflare_analysis';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const REQUEST: AnalysisRequest = {
  from: '2026-11-17T05:00:00.000Z',
  to: '2026-11-18T05:00:00.000Z',
  zones: ['b89.io'],
};

/** Todos los comodines de `http.path` de una cláusula, en orden. */
function wildcards(clause: unknown): string[] {
  const out: string[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === 'object') {
      const record = node as Json;
      if (record.wildcard?.['http.path']) out.push(record.wildcard['http.path'].value);
      Object.values(record).forEach(walk);
    }
  };
  walk(clause);
  return out;
}

function ipBucket(ip: string, extra: Json = {}): Json {
  return {
    key: ip,
    doc_count: 50,
    country: { buckets: [{ key: extra.country ?? 'PE', doc_count: 50 }] },
    asn: { buckets: [{ key: extra.asn ?? 6147, doc_count: 50 }] },
    asn_name: { buckets: [{ key: extra.asnName ?? 'Telefonica del Peru', doc_count: 50 }] },
    first: { value: Date.parse('2026-11-17T14:00:00Z') },
    last: { value: Date.parse('2026-11-17T22:00:00Z') },
    logins: { doc_count: extra.logins ?? 0 },
    logins_failed: { doc_count: 0 },
    refreshes: { doc_count: extra.refreshes ?? 0 },
    staff_ok: { doc_count: extra.staffOk ?? 0 },
    staff_denied: { doc_count: 0 },
    writes: { doc_count: 0 },
    exports: { doc_count: 0 },
    money: { doc_count: 0 },
    ua_count: { value: 1 },
    user_agents: { buckets: [{ key: 'Mozilla/5.0', doc_count: 50 }] },
    hosts: { buckets: [{ key: 'prodv2-apipayments.b89.io', doc_count: 50 }] },
    endpoints: { buckets: extra.endpoints ?? [] },
    statuses: { buckets: [{ key: 200, doc_count: 50 }] },
    off_hours: { doc_count: extra.offHours ?? 0 },
  };
}

const MAIN_BODY: Json = {
  hits: { total: { value: 1200, relation: 'eq' } },
  _shards: { failed: 0 },
  aggregations: {
    sampled: { doc_count: 1200 },
    backoffice: {
      ips: {
        buckets: [
          ipBucket('190.43.10.20', { logins: 2, refreshes: 10, staffOk: 30 }),
          ipBucket('62.93.177.8', {
            country: 'CO',
            asn: 60068,
            asnName: 'Datacamp Limited',
            refreshes: 13,
            staffOk: 41,
          }),
        ],
      },
    },
    money: {
      doc_count: 3,
      backoffice: { doc_count: 3 },
      integration: { doc_count: 0 },
      histogram: {
        buckets: [
          {
            key: Date.parse('2026-11-17T19:30:00Z'),
            doc_count: 3,
            backoffice: { doc_count: 3 },
            integration: { doc_count: 0 },
          },
        ],
      },
      callers: {
        buckets: [
          ipBucket('54.156.173.233', {
            country: 'US',
            asn: 14618,
            asnName: 'AMAZON-AES',
            endpoints: [{ key: '/backoffice/v2/balances/transactions', doc_count: 3 }],
          }),
        ],
      },
    },
    sensitive: { callers: { buckets: [] } },
  },
};

const BASELINE_BODY: Json = {
  aggregations: {
    backoffice: {
      ips: { buckets: [{ key: '190.43.10.20', doc_count: 900 }] },
      login_countries: { countries: { buckets: [{ key: 'PE', doc_count: 40 }] } },
    },
    money: { ips: { buckets: [{ key: '34.200.1.1', doc_count: 300 }] } },
  },
};

function error(statusCode: number): Error {
  return Object.assign(new Error(`status ${statusCode}`), { meta: { statusCode } });
}

describe('consultas del análisis', () => {
  it('son acotadas, de solo HTTP y sin nada del navegador salvo rango y zona', () => {
    const body = analysisBody(REQUEST);
    expect(body.size).toBe(0);
    const filters = (body.query as Json).bool.filter as Json[];
    expect(filters).toContainEqual({ term: { 'event.dataset': 'http' } });
    expect(JSON.stringify(filters)).toContain('"b89.io"');
    expect(JSON.stringify(filters)).toContain(REQUEST.from);
    const aggs = body.aggs as Json;
    expect(aggs.backoffice.aggs.ips.terms.size).toBe(150);
    expect(aggs.money.aggs.callers.terms.size).toBe(60);
    expect(aggs.money.aggs.histogram.date_histogram.fixed_interval).toBe('30m');
    expect(aggs.money.aggs.callers.aggs.off_hours.filter).toBe(OFF_HOURS_SCRIPT);
  });

  it('las cláusulas de dinero y lecturas sensibles son las mismas reglas que el modelo', () => {
    expect(wildcards(MONEY_CLAUSE)).toEqual(MONEY_RULES.flatMap((rule) => rule.paths));
    expect(wildcards(SENSITIVE_CLAUSE)).toEqual(SENSITIVE_READ_RULES.flatMap((rule) => rule.paths));
    // Las reglas de dinero exigen método de escritura (como `moneyMovementRule`).
    expect(JSON.stringify(MONEY_CLAUSE)).toContain('"http.method":["POST","PUT","PATCH","DELETE"]');
    expect(moneyMovementRule('GET', '/payin/v1/payment')).toBeNull();
  });

  it('la línea base son los 14 días previos al inicio', () => {
    expect(baselineRange(REQUEST)).toEqual({
      from: '2026-11-03T05:00:00.000Z',
      to: '2026-11-17T04:59:59.999Z',
    });
    expect(JSON.stringify(baselineBody(REQUEST))).toContain('2026-11-03T05:00:00.000Z');
    const baseline = parseBaseline(BASELINE_BODY);
    expect(baseline.backofficeIps.has('190.43.10.20')).toBe(true);
    expect(baseline.loginCountries.has('PE')).toBe(true);
  });

  it('anomalías: grado > 0, en el rango y de los detectores b89-cf-*', () => {
    const body = anomalyResultsBody(REQUEST, ['d1']);
    expect(JSON.stringify(body.query)).toContain('"anomaly_grade":{"gt":0}');
    expect(JSON.stringify(body.query)).toContain('"detector_id":["d1"]');
    expect(JSON.stringify(anomalyResultsBody(REQUEST, null).query)).not.toContain('detector_id');
  });
});

describe('analyzeTraffic', () => {
  function client(options: { baseline?: 'ok' | 'fail'; transport?: 'ok' | 'forbidden' } = {}) {
    const calls: Json[] = [];
    const fake: AnalysisClient = {
      search: async (params) => {
        calls.push(params as Json);
        if (params.index === '.opendistro-anomaly-results*') {
          return {
            body: {
              hits: {
                hits: [
                  {
                    _id: 'r1',
                    _source: {
                      detector_id: 'd1',
                      data_start_time: Date.parse('2026-11-17T19:40:00Z'),
                      data_end_time: Date.parse('2026-11-17T19:50:00Z'),
                      anomaly_grade: 0.82,
                      confidence: 0.9,
                      entity: [{ name: 'client.ip', value: '54.156.173.233' }],
                      feature_data: [{ feature_id: 'f1', feature_name: 'calls', data: 3 }],
                    },
                  },
                ],
              },
            },
          };
        }
        const isBaseline = JSON.stringify(params.body).includes('2026-11-03T05:00:00.000Z');
        if (isBaseline) {
          if (options.baseline === 'fail') throw error(500);
          return { body: BASELINE_BODY };
        }
        return { body: MAIN_BODY };
      },
      transport: {
        request: async (params) => {
          calls.push(params as Json);
          if (options.transport === 'forbidden') throw error(403);
          return {
            body: {
              hits: {
                hits: [
                  { _id: 'd1', _source: { name: 'b89-cf-money-movement' } },
                  { _id: 'd9', _source: { name: 'otro-detector' } },
                ],
              },
            },
          };
        },
      },
    };
    return { fake, calls };
  }

  it('arma sesiones, dinero, hallazgos y anomalías', async () => {
    const { fake, calls } = client();
    const result = await analyzeTraffic(fake, REQUEST, new Date('2026-11-18T05:00:00Z'));
    expect(result.httpRecords).toBe(1200);
    expect(result.sampledRecords).toBe(1200);
    expect(result.baseline.available).toBe(true);
    expect(result.sessions[0].ip).toBe('62.93.177.8');
    expect(result.sessions[0].risk.level).toBe('critical');
    expect(result.money.callers[0]).toMatchObject({
      ip: '54.156.173.233',
      hosting: 'Amazon',
      channel: 'backoffice',
      newCaller: true,
      offHours: 0,
    });
    expect(result.money.histogram).toEqual([
      { at: '2026-11-17T19:30:00.000Z', backoffice: 3, integration: 0 },
    ]);
    expect(result.findings.map((finding) => finding.id)).toEqual([
      'money-new:54.156.173.233',
      'hosting-session:62.93.177.8',
    ]);
    expect(result.anomalies).toMatchObject({
      status: 'ok',
      detectorsResolved: true,
      detectors: [{ id: 'd1', name: 'b89-cf-money-movement' }],
    });
    expect(result.anomalies.rows[0]).toMatchObject({
      detectorName: 'b89-cf-money-movement',
      grade: 0.82,
      entity: [{ name: 'client.ip', value: '54.156.173.233' }],
      features: [{ name: 'calls', value: 3 }],
      start: '2026-11-17T19:40:00.000Z',
    });
    expect(calls.some((call) => call.path === DETECTORS_PATH)).toBe(true);
    const adSearch = calls.find((call) => call.index === '.opendistro-anomaly-results*');
    expect(adSearch?.expand_wildcards).toBe('open,hidden');
  });

  it('sin línea base el análisis sigue y no marca «nuevo»', async () => {
    const { fake } = client({ baseline: 'fail' });
    const result = await analyzeTraffic(fake, REQUEST);
    expect(result.baseline.available).toBe(false);
    expect(result.money.callers[0].newCaller).toBeNull();
    expect(result.findings.map((finding) => finding.id)).toEqual(['hosting-session:62.93.177.8']);
  });

  it('un 403 de la consulta principal llega a la ruta', async () => {
    const fake: AnalysisClient = {
      search: async () => {
        throw error(403);
      },
    };
    await expect(analyzeTraffic(fake, REQUEST)).rejects.toThrow('status 403');
  });
});

describe('loadAnomalies', () => {
  it('si no puede listar detectores, muestra los resultados por id', async () => {
    const fake: AnalysisClient = {
      search: async () => ({
        body: {
          hits: { hits: [{ _id: 'r', _source: { detector_id: 'abc', anomaly_grade: 0.5 } }] },
        },
      }),
      transport: {
        request: async () => {
          throw error(403);
        },
      },
    };
    const section = await loadAnomalies(fake, REQUEST);
    expect(section.status).toBe('ok');
    expect(section.detectorsResolved).toBe(false);
    expect(section.rows[0]).toMatchObject({ detectorId: 'abc', detectorName: null });
  });

  it('403 sobre los resultados: mensaje claro, sin romper el análisis', async () => {
    const fake: AnalysisClient = {
      search: async () => {
        throw error(403);
      },
    };
    const section = await loadAnomalies(fake, REQUEST);
    expect(section.status).toBe('forbidden');
    expect(section.message).toContain('Tu rol no puede leer');
  });

  it('sin detectores b89-cf-* no consulta resultados', async () => {
    let searched = false;
    const fake: AnalysisClient = {
      search: async () => {
        searched = true;
        return { body: {} };
      },
      transport: { request: async () => ({ body: { hits: { hits: [] } } }) },
    };
    const section = await loadAnomalies(fake, REQUEST);
    expect(searched).toBe(false);
    expect(section.message).toContain('Aún no hay detectores b89-cf-');
  });

  it('NO_BASELINE no marca nada', () => {
    expect(NO_BASELINE.available).toBe(false);
  });
});
