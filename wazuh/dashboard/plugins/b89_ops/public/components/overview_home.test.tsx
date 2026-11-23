/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Alert } from '../../common';
import { answerLine, AttentionItem, QueueSummary } from './overview_view';
import type { AttentionAlert } from './attention_queue';
import { ServiceCard, ServiceModel } from './service_cards';
import { INTEGRATIONS } from '../../common';

function alert(overrides: Partial<Alert> = {}): AttentionAlert {
  return {
    id: 'a1',
    title: 'B89 Microsoft 365: Inicio de sesión desde un país inusual (wazuh 101531)',
    priority: 'P1',
    score: 90,
    status: 'new',
    assigneeId: null,
    verdict: null,
    incidentId: null,
    occurredAt: '2026-11-22T10:00:00Z',
    revision: 1,
    reasons: [{ code: 'REPEATED_ACTIVITY', detail: '5 eventos equivalentes en 10 min.' }],
    entities: [{ ref: null, kind: 'user', label: 'ana.perez' }],
    ...overrides,
  };
}

function summary(overrides: Partial<QueueSummary> = {}): QueueSummary {
  return {
    open: 9,
    byPriority: { P1: 2, P2: 3, P3: 4, P4: 0 },
    top: [alert()],
    unassigned: 4,
    unassignedPartial: false,
    activeIncidents: 1,
    incidentsAccess: 'ok',
    ...overrides,
  };
}

describe('línea de respuesta del inicio', () => {
  it('dice qué hay abierto, cuánto falta asignar y por dónde empezar', () => {
    const { text, first } = answerLine(summary());
    expect(text).toBe('Tienes 2 alertas P1 y 3 P2 abiertas; 4 sin responsable.');
    expect(first?.id).toBe('a1');
  });

  it('con la cola vacía dice que está al día', () => {
    const { text, first } = answerLine(summary({ open: 0, top: [], unassigned: 0 }));
    expect(text).toBe('La cola está al día. No hay alertas abiertas.');
    expect(first).toBeNull();
  });

  it('sin P1 ni P2, y con conteo parcial, lo dice', () => {
    const { text } = answerLine(
      summary({ open: 140, byPriority: { P1: 0, P2: 0, P3: 100, P4: 40 }, unassignedPartial: true }),
    );
    expect(text).toBe('Tienes 140 alertas abiertas, ninguna P1 ni P2; al menos 4 sin responsable.');
  });
});

describe('alerta en «Alertas que requieren atención»', () => {
  it('muestra el título limpio, el porqué y el responsable, sin ID de regla', () => {
    const html = renderToStaticMarkup(
      <AttentionItem
        alert={{ ...alert(), attention: { score: 150, why: 'Riesgo de entidad 72/100 · 3 fuentes', entityRisk: 72 } }}
        basePath="/base"
        viewerId="me"
      />,
    );
    expect(html).toContain('Inicio de sesión desde un país inusual');
    expect(html).not.toContain('wazuh 101531');
    expect(html).not.toContain('B89 Microsoft 365:');
    expect(html).toContain('usuario ana.perez');
    expect(html).toContain('se repitió 5 veces');
    expect(html).toContain('Arriba porque: el usuario o la IP acumula un riesgo de 72 sobre 100');
    expect(html).toContain('Sin responsable');
    expect(html).toContain('href="/base/app/b89-alerts?id=a1"');
    // Sin paradas de Tab anidadas dentro del enlace.
    expect(html).not.toContain('tabindex');
  });

  it('dice «Tú» cuando la alerta es tuya', () => {
    const html = renderToStaticMarkup(
      <AttentionItem alert={alert({ assigneeId: 'me' })} basePath="" viewerId="me" />,
    );
    expect(html).toContain('Responsable: Tú');
  });
});

describe('tarjeta de servicio en el inicio', () => {
  it('en modo compacto no trae su propia lista de atención', () => {
    const spec = INTEGRATIONS.find((item) => item.id === 'aws')!;
    const model: ServiceModel = {
      spec,
      status: { tone: 'fail', label: 'Sin datos', detail: null },
      metrics: [],
      lastEventAt: null,
      events24h: 0,
      loading: false,
      attention: { access: 'ok', total: 1, events: [] },
    };
    const html = renderToStaticMarkup(<ServiceCard model={model} basePath="" compact />);
    expect(html).not.toContain('Atención prioritaria');
    expect(html).toContain('Sin datos');
  });
});
