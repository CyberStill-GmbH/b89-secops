/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Alert, InvestigationEventSummary } from '../../common';

// El menú de exportación importa estilos .scss que el entorno de pruebas no compila.
vi.mock('./investigation_report_actions', () => ({ InvestigationReportActions: () => null }));
import {
  ACCESS_MESSAGE,
  activeTimelineEntities,
  AlertStatusLine,
  riskWord,
  TimelineList,
} from './investigation_view';

const ALERT: Alert = {
  id: 'alert-1',
  title: 'Inicio de sesión sospechoso (wazuh 5710)',
  priority: 'P2',
  score: 87,
  status: 'escalated',
  assigneeId: 'user:me',
  verdict: null,
  incidentId: null,
  occurredAt: '2026-11-21T14:35:00.000Z',
  revision: 3,
  reasons: [],
  entities: [],
};

function event(id: string, at: string): InvestigationEventSummary {
  return {
    id,
    index: 'idx',
    at,
    level: 12,
    ruleId: '5710',
    description: `Evento ${id}`,
    groups: [],
    vendor: 'office365',
    agent: null,
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: ['ip:10.0.0.4'],
  };
}

describe('cabecera de la investigación', () => {
  it('muestra estado, responsable y conclusión en palabras llanas', () => {
    const html = renderToStaticMarkup(
      <AlertStatusLine
        alert={ALERT}
        basePath=""
        viewerId="user:me"
        incident={null}
        ruleId="5710"
      />,
    );
    expect(html).toContain('Escalada');
    expect(html).toContain('Responsable:');
    expect(html).toContain('Tú');
    expect(html).toContain('Sin clasificar');
    expect(html).toContain('Detalle técnico');
    expect(html).not.toContain('puntuación');
  });

  it('no usa nombres internos en los mensajes de acceso', () => {
    for (const text of Object.values(ACCESS_MESSAGE)) {
      expect(text).not.toMatch(/Indexer|wazuh-alerts/u);
    }
  });
});

describe('línea de tiempo legible', () => {
  it('muestra hora absoluta, distancia a la alerta, marca con hora y «Ver detalle»', () => {
    const html = renderToStaticMarkup(
      <TimelineList
        basePath=""
        events={[event('b', '2026-11-21T14:47:00.000Z'), event('a', '2026-11-21T14:32:00.000Z')]}
        anchor="2026-11-21T14:35:00.000Z"
        order="asc"
        complete
      />,
    );
    expect(html).toContain('−3 min');
    expect(html).toContain('+12 min');
    expect(html).toContain('Momento de la alerta');
    expect(html).toContain('Ver detalle');
    expect(html).toContain('Coincide con: IP 10.0.0.4');
    expect(html).toContain('Nivel 12 (alto)');
    expect(html.indexOf('−3 min')).toBeLessThan(html.indexOf('+12 min'));
  });
});

describe('entidades activas', () => {
  const list = Array.from({ length: 10 }, (_, index) => ({ kind: 'ip', value: `10.0.0.${index}` }));

  it('usa las primeras 8 sin elección y respeta la elección después', () => {
    expect(activeTimelineEntities(list, null)).toHaveLength(8);
    expect(activeTimelineEntities(list, ['ip:10.0.0.9']).map((item) => item.value)).toEqual([
      '10.0.0.9',
    ]);
  });

  it('describe el riesgo con palabras', () => {
    expect(riskWord(72)).toBe('alto');
    expect(riskWord(45)).toBe('medio');
    expect(riskWord(10)).toBe('bajo');
  });
});
