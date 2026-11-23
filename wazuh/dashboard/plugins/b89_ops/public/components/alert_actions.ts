/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Qué puede hacer la persona con una alerta según su estado y sus permisos, con UNA acción
 * principal por estado (como el «siguiente paso» de Sentinel o el workflow de Splunk ES) y una
 * pista en palabras cuando no puede avanzar. Sin React, para probarlo sin DOM.
 */

import type { Alert } from '../../common';

export type AlertActionId =
  | 'take' // `acknowledge`: en revisión y, si nadie la tenía, quien la toma queda responsable
  | 'assign_me'
  | 'classify'
  | 'escalate'
  | 'open_incident'
  | 'close'
  | 'reopen';

export interface AlertAction {
  readonly id: AlertActionId;
  readonly label: string;
  readonly primary: boolean;
  /** Para el tooltip: en qué se diferencia de las otras acciones. */
  readonly help?: string;
}

export interface AlertActionPlan {
  readonly actions: readonly AlertAction[];
  /** Por qué no hay una acción para avanzar y qué hacer, si aplica. */
  readonly hint: string | null;
}

export interface AlertPermissions {
  readonly canTriage: boolean;
  readonly canAssign: boolean;
  readonly canOpenIncident: boolean;
}

export function alertActionPlan(
  alert: Pick<Alert, 'status' | 'assigneeId' | 'verdict' | 'incidentId'>,
  viewerId: string,
  can: AlertPermissions,
): AlertActionPlan {
  if (!can.canTriage) {
    return { actions: [], hint: 'Solo lectura: tu rol no puede cambiar alertas.' };
  }
  const mine = alert.assigneeId === viewerId;
  const actions: AlertAction[] = [];
  let hint: string | null = null;

  switch (alert.status) {
    case 'new':
      actions.push({
        id: 'take',
        label: 'Tomar alerta',
        primary: true,
        help: alert.assigneeId && !mine
          ? 'La marca en revisión; sigue con su responsable actual.'
          : 'La marca en revisión y quedas como responsable.',
      });
      break;
    case 'acknowledged':
      if (mine) actions.push({ id: 'classify', label: 'Clasificar', primary: true, help: 'Registra si es real o no, con una nota.' });
      else if (can.canAssign) actions.push({ id: 'assign_me', label: 'Asignármela', primary: true });
      else hint = 'Solo la persona responsable puede clasificarla. Pide a tu líder que te la asigne.';
      break;
    case 'triaged':
      if (alert.verdict === 'true_positive') {
        actions.push({ id: 'escalate', label: 'Escalar al líder SOC', primary: true, help: 'Avisa al líder para que decida la respuesta.' });
      }
      if (!mine && can.canAssign) actions.push({ id: 'assign_me', label: 'Asignármela', primary: false });
      break;
    default:
      break;
  }

  if (can.canOpenIncident && !alert.incidentId && alert.status !== 'closed') {
    actions.push({
      id: 'open_incident',
      label: 'Abrir incidente',
      primary: false,
      help: 'Agrupa la respuesta: responsable, tareas obligatorias y notas.',
    });
  }
  if (alert.status === 'acknowledged' || alert.status === 'triaged' || alert.status === 'escalated') {
    actions.push({ id: 'close', label: 'Cerrar alerta', primary: false });
  }
  if (alert.status === 'closed') actions.push({ id: 'reopen', label: 'Reabrir', primary: true });

  // Nunca dos acciones principales compitiendo.
  let primarySeen = false;
  const single = actions.map((action) => {
    if (!action.primary) return action;
    if (primarySeen) return { ...action, primary: false };
    primarySeen = true;
    return action;
  });
  return { actions: single, hint };
}

/** Aviso tras cada acción: dice qué cambió, no solo «listo». */
export const ALERT_ACTION_DONE: Readonly<Record<AlertActionId, string>> = {
  take: 'Alerta tomada: está en revisión y tú eres responsable.',
  assign_me: 'Ahora eres responsable de esta alerta.',
  classify: 'Conclusión guardada.',
  escalate: 'Alerta escalada al líder SOC.',
  open_incident: 'Incidente abierto y vinculado.',
  close: 'Alerta cerrada.',
  reopen: 'Alerta reabierta.',
};
