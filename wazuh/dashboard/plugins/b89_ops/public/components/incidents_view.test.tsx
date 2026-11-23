/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Incident } from '../../common';
import { closeReadiness, closureText, nextStep, timelineLabel } from './incident_flow';
import { CloseChecklist, IncidentSummary, IncidentTitleCell, LifecycleSteps } from './incidents_view';

const noop = () => undefined;
const INCIDENT: Incident = {
  id: 'inc-0001',
  title: 'Acceso sospechoso a la cuenta de pagos',
  severity: 'high',
  status: 'contained',
  ownerId: null,
  alertIds: ['a1', 'a2'],
  summary: 'Inicio de sesión desde hosting seguido de una exportación.',
  openedAt: '2026-11-22T10:00:00.000Z',
  closedAt: null,
  revision: 3,
};

describe('flujo del incidente', () => {
  it('cada estado dice el siguiente paso y una sola acción principal', () => {
    expect(nextStep('open')).toMatchObject({ primary: { name: 'contain' }, secondary: null });
    expect(nextStep('contained')).toMatchObject({
      primary: { name: 'eradicate', label: 'Marcar causa eliminada' },
      secondary: { name: 'resolve', label: 'Resolver sin este paso' },
    });
    expect(nextStep('resolved').primary).toEqual({ name: 'close', label: 'Cerrar incidente' });
    expect(nextStep('closed').primary).toBeNull();
  });

  it('lo que falta para cerrar se sabe antes de intentarlo', () => {
    expect(closeReadiness(2, 1)).toMatchObject({
      ready: false,
      blocker: 'No se puede cerrar todavía: quedan 2 tareas obligatorias y 1 alerta sin clasificar.',
    });
    expect(closeReadiness(0, 0)).toMatchObject({ ready: true, blocker: null });
    // Mientras carga, no se inventa un pendiente.
    expect(closeReadiness(null, null)).toMatchObject({ ready: true, items: [] });
  });

  it('la conclusión encabeza el texto de cierre y la actividad nunca muestra códigos', () => {
    expect(closureText('Falso positivo', ' Era un escaneo autorizado. ')).toBe(
      'Conclusión: Falso positivo. Era un escaneo autorizado.',
    );
    expect(timelineLabel('task.started')).toBe('Tarea iniciada');
    expect(timelineLabel('algo.nuevo')).toBe('Actividad');
  });
});

describe('incidente en pantalla', () => {
  it('el título de la fila es un botón (se abre con teclado)', () => {
    const html = renderToStaticMarkup(<IncidentTitleCell incident={INCIDENT} onOpen={noop} />);
    expect(html).toMatch(/<button type="button" class="b89LinkButton"[^>]*>Acceso sospechoso a la cuenta de pagos<\/button>/u);
    expect(html).toContain('2 alertas');
  });

  it('el ciclo de vida marca el paso actual y dice qué sigue', () => {
    const html = renderToStaticMarkup(<LifecycleSteps status="contained" />);
    expect(html).toContain('aria-current="step"');
    expect(html.indexOf('Abierto')).toBeLessThan(html.indexOf('Contenido'));
    expect(html).toContain('Siguiente: eliminar la causa');
  });

  it('«Para cerrar» lista pendientes con un atajo a la pestaña', () => {
    const html = renderToStaticMarkup(<CloseChecklist openRequiredTasks={1} unclassifiedAlerts={0} onGo={noop} />);
    expect(html).toContain('Pendiente: </span>Faltan 1 tarea obligatoria');
    expect(html).toContain('Ver tareas');
    expect(html).toContain('Cumplido: </span>Alertas vinculadas clasificadas');
  });

  it('resumen: lo que se sabe primero; el identificador plegado; la conclusión si está cerrado', () => {
    const open = renderToStaticMarkup(<IncidentSummary incident={INCIDENT} unclassified={1} onGoAlerts={noop} />);
    expect(open.indexOf('Qué se sabe')).toBeLessThan(open.indexOf('<details'));
    expect(open).toContain('2 alertas vinculadas · 1 sin clasificar');
    expect(open).not.toContain('Cerrado: Abierto');
    const closed = renderToStaticMarkup(
      <IncidentSummary
        incident={{ ...INCIDENT, status: 'closed', closedAt: '2026-11-22T12:00:00.000Z', closureReason: 'Conclusión: Falso positivo. Escaneo autorizado.' }}
        unclassified={0}
        onGoAlerts={noop}
      />,
    );
    expect(closed).toContain('Conclusión del cierre');
    expect(closed).toContain('Conclusión: Falso positivo. Escaneo autorizado.');
  });
});
