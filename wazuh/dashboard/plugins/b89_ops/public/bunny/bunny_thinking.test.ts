/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { BunnyProgressEvent } from './chat_client';
import { BunnyThinking, bunnyProgressTimeline, elapsedLabel } from './bunny_thinking';

describe('progreso real de Bunny', () => {
  const events: BunnyProgressEvent[] = [
    { type: 'model_started', round: 1 },
    { type: 'tool_started', label: 'Buscando alertas citadas' },
    { type: 'tool_finished', label: 'Buscando alertas citadas', ok: false },
    { type: 'model_started', round: 2 },
  ];

  it('deriva estados de la secuencia SSE sin añadir acciones inventadas', () => {
    expect(bunnyProgressTimeline(events)).toEqual([
      { key: 'model:1:0', label: 'Consulta al modelo · ronda 1', status: 'complete' },
      { key: 'tool:Buscando alertas citadas:1', label: 'Buscando alertas citadas', status: 'no-result' },
      { key: 'model:2:3', label: 'Consulta al modelo · ronda 2', status: 'running' },
    ]);
    expect(bunnyProgressTimeline([])).toEqual([]);
  });

  it('muestra estados textuales y tiempo transcurrido accesible sin porcentajes estimados', () => {
    expect(elapsedLabel(68)).toBe('1 min 08 s');
    const markup = renderToStaticMarkup(React.createElement(BunnyThinking, { events, elapsedSeconds: 68 }));
    expect(markup).toContain('En curso');
    expect(markup).toContain('Completo');
    expect(markup).toContain('Sin resultado');
    expect(markup).toContain('Tiempo transcurrido: 1 min 08 s');
    expect(markup).not.toContain('%');
    expect(markup).toContain('Buscando alertas citadas');
  });

  it('no afirma actividad si todavía no llegó un evento SSE', () => {
    const markup = renderToStaticMarkup(React.createElement(BunnyThinking, { events: [], elapsedSeconds: 0 }));
    expect(markup).toContain('Esperando la primera actualización de actividad del servidor');
    expect(markup).not.toContain('Validando sesión');
  });
});
