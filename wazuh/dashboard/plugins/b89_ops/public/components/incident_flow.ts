/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Ciclo de vida de un incidente en palabras: dónde está, cuál es el siguiente paso y qué falta
 * para cerrarlo (como la lista de tareas y el «Siguiente paso» de un incidente de Sentinel).
 * Las transiciones son las del backend (`modules/soc/src/incident.ts`). Sin React.
 */

import type { IncidentCommandName, IncidentStatus } from '../../common';

export const LIFECYCLE: readonly IncidentStatus[] = ['open', 'contained', 'eradicated', 'resolved', 'closed'];

export interface NextStep {
  /** Qué toca ahora, en una frase. */
  readonly hint: string;
  /** Acción principal para avanzar (si hay). */
  readonly primary: { readonly name: IncidentCommandName | 'close'; readonly label: string } | null;
  /** Atajo opcional (p. ej. resolver sin erradicar). */
  readonly secondary: { readonly name: IncidentCommandName; readonly label: string } | null;
}

export function nextStep(status: IncidentStatus): NextStep {
  switch (status) {
    case 'open':
      return {
        hint: 'Siguiente: contener el daño (aislar el equipo, bloquear la cuenta o la IP).',
        primary: { name: 'contain', label: 'Marcar contenido' },
        secondary: null,
      };
    case 'contained':
      return {
        hint: 'Siguiente: eliminar la causa. Si no hace falta, puedes resolverlo directamente.',
        primary: { name: 'eradicate', label: 'Marcar causa eliminada' },
        secondary: { name: 'resolve', label: 'Resolver sin este paso' },
      };
    case 'eradicated':
      return {
        hint: 'Siguiente: confirmar que todo volvió a la normalidad y resolverlo.',
        primary: { name: 'resolve', label: 'Resolver' },
        secondary: null,
      };
    case 'resolved':
      return {
        hint: 'Siguiente: cerrarlo con la conclusión.',
        primary: { name: 'close', label: 'Cerrar incidente' },
        secondary: null,
      };
    default:
      return { hint: 'Incidente cerrado.', primary: null, secondary: null };
  }
}

export interface CloseReadiness {
  readonly ready: boolean;
  /** Líneas de la lista «Lo que falta para cerrar», cumplidas o no. */
  readonly items: ReadonlyArray<{ readonly ok: boolean; readonly text: string; readonly tab: 'tasks' | 'alerts' }>;
  /** Por qué no se puede cerrar aún, en una frase; null si se puede. */
  readonly blocker: string | null;
}

const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;

/** `null` en un contador significa «todavía no se sabe» (cargando o sin permiso). */
export function closeReadiness(openRequiredTasks: number | null, unclassifiedAlerts: number | null): CloseReadiness {
  const items: Array<{ ok: boolean; text: string; tab: 'tasks' | 'alerts' }> = [];
  if (openRequiredTasks !== null) {
    items.push({
      ok: openRequiredTasks === 0,
      text:
        openRequiredTasks === 0
          ? 'Tareas obligatorias terminadas'
          : `Faltan ${plural(openRequiredTasks, 'tarea obligatoria', 'tareas obligatorias')}`,
      tab: 'tasks',
    });
  }
  if (unclassifiedAlerts !== null) {
    items.push({
      ok: unclassifiedAlerts === 0,
      text:
        unclassifiedAlerts === 0
          ? 'Alertas vinculadas clasificadas'
          : `Faltan clasificar ${plural(unclassifiedAlerts, 'alerta', 'alertas')}`,
      tab: 'alerts',
    });
  }
  const pending = [
    openRequiredTasks ? plural(openRequiredTasks, 'tarea obligatoria', 'tareas obligatorias') : null,
    unclassifiedAlerts ? `${plural(unclassifiedAlerts, 'alerta', 'alertas')} sin clasificar` : null,
  ].filter((part): part is string => Boolean(part));
  return {
    ready: pending.length === 0,
    items,
    blocker: pending.length ? `No se puede cerrar todavía: quedan ${pending.join(' y ')}.` : null,
  };
}

export const CONCLUSIONS = [
  'Amenaza real contenida',
  'Falso positivo',
  'Actividad legítima',
  'Duplicado de otro incidente',
] as const;

/** El backend guarda un solo texto de cierre: la conclusión va al principio, legible en auditoría. */
export function closureText(conclusion: string, reason: string): string {
  const body = reason.trim();
  return conclusion ? `Conclusión: ${conclusion}. ${body}` : body;
}

export const INCIDENT_COMMAND_DONE: Readonly<Record<string, string>> = {
  contain: 'Incidente marcado como contenido.',
  eradicate: 'Causa eliminada: incidente actualizado.',
  resolve: 'Incidente resuelto.',
  close: 'Incidente cerrado.',
  reopen: 'Incidente reabierto.',
  reassign: 'Ahora eres responsable del incidente.',
};

export const TIMELINE_LABEL: Readonly<Record<string, string>> = {
  'incident.opened': 'Incidente abierto',
  'incident.transition': 'Cambio de estado',
  'incident.closed': 'Incidente cerrado',
  'incident.reopened': 'Incidente reabierto',
  'incident.reassigned': 'Cambio de responsable',
  'alert.linked': 'Alerta vinculada',
  'task.created': 'Tarea creada',
  'task.started': 'Tarea iniciada',
  'task.completed': 'Tarea completada',
  'task.cancelled': 'Tarea cancelada',
  'task.reopened': 'Tarea reabierta',
  'task.assigned': 'Tarea asignada',
  'note.added': 'Nota añadida',
};

export function timelineLabel(kind: string): string {
  return TIMELINE_LABEL[kind] ?? 'Actividad';
}
