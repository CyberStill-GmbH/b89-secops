/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { InvestigationEventSummary } from '../../common';
import {
  buildTimelineEntries,
  entityKeyLabel,
  formatOffset,
  investigationActivityCsvRows,
  groupInvestigationActivity,
  levelText,
} from './investigation_activity_grouping';

function event(id: string, at: string, level = 5): InvestigationEventSummary {
  return {
    id,
    index: 'idx',
    at,
    level,
    ruleId: '5710',
    description: `Evento ${id}`,
    groups: [],
    vendor: 'office365',
    agent: null,
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: ['ip:10.0.0.4'],
  };
}

describe('lectura de la línea de tiempo', () => {
  it('expresa la distancia al momento de la alerta con signo', () => {
    const anchor = '2026-11-21T14:35:00.000Z';
    expect(formatOffset('2026-11-21T14:32:00.000Z', anchor)).toBe('−3 min');
    expect(formatOffset('2026-11-21T14:47:00.000Z', anchor)).toBe('+12 min');
    expect(formatOffset('2026-11-21T16:40:00.000Z', anchor)).toBe('+2 h 5 min');
    expect(formatOffset('2026-11-20T11:35:00.000Z', anchor)).toBe('−1 d 3 h');
    expect(formatOffset('2026-11-21T14:35:40.000Z', anchor)).toBe('+40 s');
    expect(formatOffset(anchor, anchor)).toBe('mismo instante');
  });

  it('nombra la entidad con su tipo y el nivel con palabras propias', () => {
    expect(entityKeyLabel('ip:10.0.0.4')).toBe('IP 10.0.0.4');
    expect(entityKeyLabel('user:admin')).toBe('Usuario admin');
    expect(levelText(12)).toBe('Nivel 12 (alto)');
    expect(levelText(3)).toBe('Nivel 3 (bajo)');
    expect(levelText(15)).not.toMatch(/Crítica/u);
  });

  it('ordena de lo más antiguo a lo más reciente con la marca de la alerta en su sitio', () => {
    const events = [
      event('c', '2026-11-21T15:00:00.000Z'),
      event('a', '2026-11-21T14:00:00.000Z'),
      event('b', '2026-11-21T14:30:00.000Z'),
    ];
    const entries = buildTimelineEntries(events, '2026-11-21T14:35:00.000Z', 'asc', true);
    const shape = entries.map((entry) =>
      entry.type === 'event' ? entry.event.id : entry.type,
    );
    expect(shape).toEqual(['day', 'a', 'b', 'anchor', 'c']);

    const desc = buildTimelineEntries(events, '2026-11-21T14:35:00.000Z', 'desc', true).map(
      (entry) => (entry.type === 'event' ? entry.event.id : entry.type),
    );
    expect(desc).toEqual(['day', 'c', 'anchor', 'b', 'a']);
  });

  it('añade un separador cuando cambia el día', () => {
    const entries = buildTimelineEntries(
      [event('a', '2026-11-20T12:00:00.000Z'), event('b', '2026-11-22T12:00:00.000Z')],
      '2026-11-21T12:00:00.000Z',
      'asc',
      true,
    );
    expect(entries.filter((entry) => entry.type === 'day')).toHaveLength(3);
  });

  it('no dibuja la marca si faltan eventos anteriores por cargar', () => {
    const entries = buildTimelineEntries(
      [event('c', '2026-11-21T15:00:00.000Z')],
      '2026-11-21T14:35:00.000Z',
      'asc',
      false,
    );
    expect(entries.some((entry) => entry.type === 'anchor')).toBe(false);
  });

  it('usa un solo nombre para la actividad agrupada y fuentes legibles', () => {
    const rows = investigationActivityCsvRows(
      groupInvestigationActivity([event('a', '2026-11-21T14:00:00.000Z')]),
    );
    expect(rows[0]?.[0]).toBe('Actividad agrupada');
    expect(rows[0]?.[5]).not.toBe('office365');
  });
});
