/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { BunnyProgressEvent } from './chat_client';
import {
  activitySummary,
  BunnyActivity,
  BunnyThinking,
  bunnyProgressTimeline,
  elapsedLabel,
  toolCount,
} from './bunny_thinking';

describe('progreso real de Bunny', () => {
  const events: BunnyProgressEvent[] = [
    { type: 'model_started', round: 1 },
    { type: 'tool_started', label: 'Buscando alertas citadas' },
    { type: 'tool_finished', label: 'Buscando alertas citadas', ok: false },
    { type: 'model_started', round: 2 },
  ];

  it('deriva estados de la secuencia SSE sin añadir acciones inventadas', () => {
    expect(bunnyProgressTimeline(events)).toEqual([
      { key: 'model:1:0', label: 'Analizando (paso 1)', status: 'complete' },
      {
        key: 'tool:Buscando alertas citadas:1',
        label: 'Buscando alertas citadas',
        status: 'no-result',
      },
      { key: 'model:2:3', label: 'Analizando (paso 2)', status: 'running' },
    ]);
    expect(bunnyProgressTimeline([])).toEqual([]);
  });

  it('muestra estados textuales y tiempo transcurrido accesible sin porcentajes estimados', () => {
    expect(elapsedLabel(68)).toBe('1 min 08 s');
    const markup = renderToStaticMarkup(
      React.createElement(BunnyThinking, { events, elapsedSeconds: 68, initiallyExpanded: true }),
    );
    expect(markup).toContain('En curso');
    expect(markup).toContain('Completo');
    expect(markup).toContain('Sin resultado');
    expect(markup).toContain('Tiempo transcurrido: 1 min 08 s');
    expect(markup).not.toContain('%');
    expect(markup).toContain('Buscando alertas citadas');
  });

  it('no afirma actividad si todavía no llegó un evento SSE', () => {
    const markup = renderToStaticMarkup(
      React.createElement(BunnyThinking, { events: [], elapsedSeconds: 0, initiallyExpanded: true }),
    );
    expect(markup).toContain('Pensando…');
    expect(markup).not.toContain('aria-live="polite"');
    expect(markup).not.toContain('Validando sesión');
  });
});

describe('línea de actividad plegable', () => {
  it('resume en vivo con herramientas y tiempo', () => {
    expect(activitySummary({ tools: 3, seconds: 12, live: true })).toBe(
      'Trabajando… · 3 herramientas · 12 s',
    );
    expect(activitySummary({ tools: 1, seconds: 0, live: true })).toBe(
      'Trabajando… · 1 herramienta · 0 s',
    );
    expect(activitySummary({ tools: 0, seconds: 5, live: true })).toBe('Trabajando… · 5 s');
  });

  it('resume al terminar y en el historial (sin duración conocida)', () => {
    expect(activitySummary({ tools: 3, seconds: 68, live: false })).toBe(
      'Trabajó 1 min 08 s · 3 herramientas',
    );
    expect(activitySummary({ tools: 2, live: false })).toBe('Actividad · 2 herramientas');
  });

  it('cuenta solo herramientas, no rondas del modelo', () => {
    const steps = bunnyProgressTimeline([
      { type: 'model_started', round: 1 },
      { type: 'tool_started', label: 'A' },
      { type: 'tool_finished', label: 'A', ok: true },
      { type: 'tool_started', label: 'B' },
    ]);
    expect(toolCount(steps)).toBe(2);
  });

  it('la actividad nace plegada, terminada o en vivo', () => {
    const done = renderToStaticMarkup(
      React.createElement(BunnyActivity, {
        steps: [{ label: 'Buscando alertas', ok: true }],
        seconds: 12,
      }),
    );
    expect(done).toContain('aria-expanded="false"');
    expect(done).toContain('Trabajó 12 s · 1 herramienta');
    expect(done).not.toContain('Buscando alertas');
    const live = renderToStaticMarkup(
      React.createElement(BunnyThinking, {
        events: [{ type: 'tool_started', label: 'Buscando alertas' }],
        elapsedSeconds: 12,
      }),
    );
    expect(live).toContain('aria-expanded="false"');
    expect(live).not.toContain('Buscando alertas');
    expect(live).toContain('Trabajando… · 1 herramienta · 12 s');
    expect(renderToStaticMarkup(React.createElement(BunnyActivity, { steps: [] }))).toBe('');
  });
});
