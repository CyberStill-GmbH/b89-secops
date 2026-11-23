/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest';
import type { Alert } from '../../common';
import {
  countUnassigned,
  loadAttentionTop,
  plainAttentionWhy,
  sortByPriorityThenRecency,
  whyBelowTitle,
} from './attention_queue';

function alert(id: string, priority: Alert['priority'], occurredAt: string): Alert {
  return {
    id,
    title: id,
    priority,
    score: 1,
    status: 'open',
    assigneeId: null,
    verdict: null,
    incidentId: null,
    occurredAt,
    revision: 1,
    reasons: [],
    entities: [],
  };
}

const open = [
  alert('p3-new', 'P3', '2026-11-13T10:00:00Z'),
  alert('p1-old', 'P1', '2026-11-12T10:00:00Z'),
  alert('p3-old', 'P3', '2026-11-13T08:00:00Z'),
];

describe('cola de atención de la vista general', () => {
  it('usa el orden y el porqué que entrega la API', async () => {
    const ranked = [
      { ...alert('p3-old', 'P3', '2026-11-13T08:00:00Z'), attention: { score: 150, why: 'Riesgo de entidad 82/100 · cadena 3 etapas · 4 fuentes', entityRisk: 82 } },
    ];
    const top = await loadAttentionTop({ get: async () => ({ items: ranked }) }, open, 6);
    expect(top.map((a) => a.id)).toEqual(['p3-old']);
    expect(top[0]!.attention!.why).toContain('Riesgo de entidad 82/100');
  });

  it('si la ruta falla conserva el orden histórico sin error', async () => {
    const top = await loadAttentionTop(
      {
        get: async () => {
          throw new Error('DEPENDENCY_DEGRADED');
        },
      },
      open,
      2,
    );
    expect(top.map((a) => a.id)).toEqual(['p1-old', 'p3-new']);
    expect(top.every((a) => a.attention === undefined)).toBe(true);
  });

  it('una respuesta vacía o inesperada también degrada', async () => {
    expect((await loadAttentionTop({ get: async () => ({}) }, open, 6)).map((a) => a.id)).toEqual(
      sortByPriorityThenRecency(open, 6).map((a) => a.id),
    );
    expect((await loadAttentionTop({ get: async () => ({ items: [] }) }, open, 6)).length).toBe(3);
  });
});

describe('textos de la lista de atención del inicio', () => {
  it('traduce el porqué del correlador a palabras llanas', () => {
    expect(plainAttentionWhy('Riesgo de entidad 72/100 · en cadena correlada · 3 fuentes · 1 relacionadas')).toBe(
      'Arriba porque: el usuario o la IP acumula un riesgo de 72 sobre 100, forma parte de una posible cadena de ataque, lo vieron 3 fuentes distintas y tiene 1 alerta relacionada.',
    );
    expect(plainAttentionWhy('cadena 3 etapas')).toBe(
      'Arriba porque: encadena 3 pasos de un posible ataque.',
    );
    expect(plainAttentionWhy(null)).toBeNull();
    expect(plainAttentionWhy('  ')).toBeNull();
  });

  it('cuenta las alertas sin responsable y avisa si el conteo es parcial', () => {
    const items = [{ assigneeId: null }, { assigneeId: 'u1' }, { assigneeId: null }];
    expect(countUnassigned(items, 3)).toEqual({ count: 2, partial: false });
    expect(countUnassigned(items, 140)).toEqual({ count: 2, partial: true });
  });

  it('no repite el título en la línea del porqué', () => {
    expect(whyBelowTitle('Inicio de sesión fallido', 'Inicio de sesión fallido · usuario ana · se repitió 5 veces')).toBe(
      'usuario ana · se repitió 5 veces',
    );
    expect(whyBelowTitle('Inicio de sesión fallido', 'Inicio de sesión fallido')).toBeNull();
    expect(whyBelowTitle('Regla X', 'Alguien probó contraseñas · IP 1.2.3.4')).toBe(
      'Alguien probó contraseñas · IP 1.2.3.4',
    );
  });
});
