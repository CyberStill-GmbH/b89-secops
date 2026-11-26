/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { dlpFindingsQuery, dlpWindow, emptyDlpFindings, parseDlpFindings } from '../../common/dlp_findings';
import { explainAlert } from '../../common/alert_why';
import type { DlpEndpoint } from '../api/dlp';
import { dlpOverviewModel, DlpOverviewLineView } from './dlp_overview';
import { FindingsPanel } from './dlp_view';
import { FerrispectorMark } from './ferrispector_mark';

const RESPONSE = {
  hits: {
    total: { value: 3 },
    hits: [
      {
        _id: 'e1',
        _source: {
          timestamp: '2026-11-23T10:00:00.000Z',
          agent: { name: 'PC-FIN-01' },
          rule: { id: '101111' },
          data: { yara_rule_id: 'B89_CRED_GITHUB_TOKEN', file_extension: '.env', file_size_bytes: '120', file_sha256: 'a'.repeat(64) },
        },
      },
    ],
  },
  aggregations: {
    detectors: { buckets: [{ key: 'B89_CRED_GITHUB_TOKEN', doc_count: 2 }, { key: 'B89_DLP_EXACT_FILE_FINGERPRINT', doc_count: 1 }] },
    hosts: { buckets: [{ key: 'PC-FIN-01', doc_count: 3 }] },
    health: { scoped: { hosts: { buckets: [{ key: 'mac-legal', doc_count: 12, rules: { buckets: [{ key: '101114', doc_count: 12 }] }, last: { value: 1763892000000 } }] } } },
  },
};

describe('hallazgos DLP en el SIEM', () => {
  it('consulta solo las reglas de hallazgos y el periodo elegido', () => {
    const query = JSON.stringify(dlpFindingsQuery('24h'));
    expect(query).toContain('"rule.id":["101110","101111","101112"]');
    expect(query).toContain('now-24h');
    expect(query).toContain('"rule.id":["101114","101116"]');
    expect(dlpWindow('1y')).toBe('7d');
  });

  it('lee totales, tipos, equipos, últimos y fallas del agente', () => {
    const findings = parseDlpFindings('7d', RESPONSE);
    expect(findings).toMatchObject({ readable: 'ok', total: 3 });
    expect(findings.byHost).toEqual([{ host: 'PC-FIN-01', count: 3 }]);
    expect(findings.latest[0]).toMatchObject({ host: 'PC-FIN-01', detector: 'B89_CRED_GITHUB_TOKEN', sizeBytes: 120 });
    expect(findings.agentIssues[0]).toMatchObject({ host: 'mac-legal', ruleId: '101114', count: 12 });
  });

  it('la pantalla dice qué encontró, en palabras y sin IDs de regla', () => {
    const html = renderToStaticMarkup(
      <FindingsPanel findings={parseDlpFindings('7d', RESPONSE)} range="7d" onRange={() => undefined} basePath="" />,
    );
    expect(html).toContain('3 hallazgos en 7 días · en 1 equipo');
    expect(html).toContain('Tokens de GitHub');
    expect(html).toContain('Copia de un documento protegido');
    expect(html).toContain('mac-legal</strong>: no recibe la política');
    expect(html).not.toContain('B89_CRED_GITHUB_TOKEN');
    expect(html).toContain('<summary>Últimos hallazgos (1)</summary>');
  });

  it('sin permiso o con error lo dice en vez de mostrar cero', () => {
    const forbidden = renderToStaticMarkup(
      <FindingsPanel findings={emptyDlpFindings('7d', 'forbidden')} range="7d" onRange={() => undefined} basePath="" />,
    );
    expect(forbidden).toContain('Tu rol no tiene permiso para ver los eventos del SIEM');
    expect(forbidden).not.toContain('Sin hallazgos');
  });
});

describe('DLP en el Resumen del SOC', () => {
  const endpoint = (id: string, status: DlpEndpoint['status']): DlpEndpoint => ({
    id,
    hostname: id,
    agentId: 'a1',
    status,
    lastSeenAt: '2026-11-23T10:00:00.000Z',
    currentRevision: 3,
    currentPolicyVersion: '1.2.0',
  });

  it('todo bien: equipos protegidos y sin hallazgos', () => {
    const model = dlpOverviewModel([endpoint('A', 'current'), endpoint('B', 'current')], emptyDlpFindings('24h', 'ok'));
    expect(model).toEqual({ tone: 'ok', text: '2 de 2 equipos protegidos · sin hallazgos en 24 h' });
  });

  it('con hallazgos o fallas pide atención, y lo muestra con el enlace a DLP', () => {
    const model = dlpOverviewModel([endpoint('A', 'offline')], parseDlpFindings('24h', RESPONSE));
    expect(model.tone).toBe('warn');
    expect(model.text).toBe('1 de 1 equipo necesita atención · 3 hallazgos en 24 h · 1 con fallas del agente');
    const html = renderToStaticMarkup(<DlpOverviewLineView model={model} basePath="/base" />);
    expect(html).toContain('href="/base/app/b89-dlp"');
    expect(html).toContain('aria-label="Ferrispector"');
  });

  it('sin respuesta de la API lo dice', () => {
    expect(dlpOverviewModel(null, null)).toMatchObject({ tone: 'unknown' });
  });
});

describe('marca y explicaciones de RabbitDLP', () => {
  it('usa el conejo detective como marca accesible', () => {
    const html = renderToStaticMarkup(<FerrispectorMark size={24} />);
    expect(html).toContain('alt="RabbitDLP"');
    expect(html).toContain('src="/ui/b89/rabbitdlp.png"');
  });

  it('una credencial encontrada explica qué pasó, en qué equipo y qué hacer', () => {
    const why = explainAlert({
      title: 'B89 DLP: Ferrispector encontró una credencial guardada en un archivo del equipo PC-FIN-01 (regla B89_CRED_GITHUB_TOKEN).',
      ruleId: '101111',
      priority: 'P3',
      reasons: [{ code: 'BASE_SEVERITY', detail: 'Severidad normalizada high (origen 8).' }],
      entities: [],
    });
    expect(why.guide?.headline).toBe('Hay una credencial guardada en un archivo de un equipo.');
    expect(why.source).toBe('Ferrispector (DLP de endpoints)');
    expect(why.nextSteps[0]).toBe('Si es real, revócala o rótala ya en el servicio de origen.');
  });
});
