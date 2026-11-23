/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { InvestigationEventSummary } from '../../common';
import { InvestigationActivityGroups } from './investigation_activity_groups';

function event(id: string, at: string): InvestigationEventSummary {
  return {
    id,
    index: 'idx',
    at,
    level: 12,
    ruleId: '5710',
    description: `Inicio de sesión ${id}`,
    groups: [],
    vendor: 'office365',
    agent: null,
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: ['user:admin'],
  };
}

describe('vista agrupada de la investigación', () => {
  it('explica el agrupamiento en una frase, sin descargos de causalidad', () => {
    const html = renderToStaticMarkup(
      <InvestigationActivityGroups
        events={[event('a', '2026-11-21T14:00:00.000Z'), event('b', '2026-11-21T14:05:00.000Z')]}
      />,
    );
    expect(html).toContain('Eventos de la misma entidad con menos de 15 min entre sí');
    expect(html).toContain('Usuario admin');
    expect(html).toContain('Nivel 12 (alto)');
    expect(html).toContain('2 eventos');
    expect(html).not.toContain('hilo de correo');
    expect(html).not.toContain('causalidad');
  });

  it('dice qué pasa cuando no hay grupos', () => {
    const html = renderToStaticMarkup(<InvestigationActivityGroups events={[]} />);
    expect(html).toContain('no hay grupos que mostrar');
  });
});
