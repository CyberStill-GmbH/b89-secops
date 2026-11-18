/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { ALERTS_PATH, PRIORITIES, Priority } from '../../common';

/** Nombre de cada prioridad B89, el mismo que dice la tarjeta «Alertas abiertas». */
export const PRIORITY_NAME: Readonly<Record<Priority, string>> = {
  P1: 'Crítica',
  P2: 'Alta',
  P3: 'Media',
  P4: 'Baja',
};

export function isPriority(value: string | null | undefined): value is Priority {
  return value != null && (PRIORITIES as readonly string[]).includes(value);
}

/** Prioridad de `?priority=` (P1–P4, en mayúsculas o minúsculas); cualquier otro valor: sin filtro. */
export function priorityFromParam(value: string | null | undefined): Priority | '' {
  const normalized = value?.trim().toUpperCase() ?? null;
  return isPriority(normalized) ? normalized : '';
}

/** Cola de alertas abiertas filtrada por una prioridad (o sin filtro). */
export function alertsQueueHref(basePath: string, priority?: Priority | ''): string {
  return `${basePath}${ALERTS_PATH}${priority ? `?priority=${priority}` : ''}`;
}

/**
 * Query de la cola tras cambiar el filtro de prioridad: conserva el resto de parámetros (`id`,
 * `q`…) para que el enlace siga siendo compartible y «Atrás» vuelva al filtro anterior.
 */
export function searchWithPriority(search: string, priority: Priority | ''): string {
  const params = new URLSearchParams(search);
  if (priority) params.set('priority', priority);
  else params.delete('priority');
  const next = params.toString();
  return next ? `?${next}` : '';
}
