/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { InvestigationEventSummary } from '../../common';
import { investigationCsv } from './investigation_export';

function event(index: number): InvestigationEventSummary {
  return {
    id: `event-${index}`,
    index: 'wazuh-alerts-test',
    at: `2026-11-08T12:${String(index % 60).padStart(2, '0')}:00.000Z`,
    level: 5,
    ruleId: '101503',
    description: `Evento ${index}`,
    groups: ['office365'],
    vendor: 'office365',
    agent: null,
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: ['user:analyst@example.test'],
  };
}

describe('exportacion de investigacion cargada', () => {
  it('incluye todos los eventos cargados y distingue el total encontrado', () => {
    const events = Array.from({ length: 205 }, (_, index) => event(index));
    const csv = investigationCsv({
      alert: null,
      title: 'Investigacion de prueba',
      entities: ['Usuario: analyst@example.test'],
      events,
      totalEvents: 317,
      generatedAt: new Date('2026-11-11T12:00:00Z'),
    });

    expect(csv).toContain('205');
    expect(csv).toContain('317');
    expect(csv).toContain('event-204');
    expect(csv).not.toContain('event-205');
  });

  it('usa rótulos en español y nombres de fuente legibles', () => {
    const csv = investigationCsv({
      alert: {
        id: 'alert-1',
        title: 'Prueba',
        priority: 'P2',
        score: 50,
        status: 'escalated',
        assigneeId: null,
        verdict: null,
        incidentId: null,
        occurredAt: '2026-11-08T12:00:00.000Z',
        revision: 1,
        reasons: [],
        entities: [],
      },
      title: 'Prueba',
      entities: [],
      events: [event(1)],
    });
    expect(csv).toContain('"Tipo";"Fecha UTC";"Prioridad / nivel"');
    expect(csv).toContain('"Escalada"');
    expect(csv).not.toContain('"office365"');
    expect(csv).toContain('"Actividad agrupada"');
    expect(csv).toContain('"Desde (UTC)"');
    expect(csv).not.toContain('Interpretación');
    expect(csv).not.toContain('hilo de correo');
  });
});
