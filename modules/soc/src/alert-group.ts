/**
 * Aprendizaje SOC · etapa C — agrupación de alertas por huella (docs/soc-learning/01-diseno.md §2.3).
 *
 * Alertas con la misma huella dentro de una ventana forman un grupo con contador, primera y
 * última vez vista. El grupo **no oculta nada**: cada alerta sigue existiendo con su estado y su
 * prioridad; la consola decide cómo mostrarlo (P1/P2 nunca se colapsan). Tampoco cierra ni baja
 * prioridad: eso será del motor (etapa E) y siempre por alerta.
 *
 * Reglas (función pura, sin reloj ni base):
 * - Hay como máximo un grupo abierto por (tenant, huella).
 * - Una alerta se suma al grupo abierto si cae dentro de la ventana respecto de lo ya visto y el
 *   grupo no supera el tramo máximo. Se usa la hora del evento, no la de llegada: un replay no
 *   abre grupos nuevos.
 * - Una alerta posterior a la ventana sella el grupo abierto y abre uno nuevo.
 * - Una alerta muy anterior al grupo abierto (llegó tarde, fuera de la ventana hacia atrás) queda
 *   sin grupo: abrir uno paralelo violaría la unicidad y reescribir el abierto falsearía su tramo.
 */

import type { Priority } from '@b89/detection';

export const ALERT_GROUP_STATUSES = ['open', 'closed'] as const;
export type AlertGroupStatus = (typeof ALERT_GROUP_STATUSES)[number];

export interface AlertGroup {
  readonly id: string;
  readonly tenantId: string;
  readonly fingerprint: string;
  readonly ruleKey: string | null;
  readonly level: 'fine' | 'coarse';
  readonly status: AlertGroupStatus;
  readonly firstSeenAt: Date;
  readonly lastSeenAt: Date;
  readonly alertCount: number;
  readonly primaryAlertId: string;
  readonly highestPriority: Priority;
  readonly revision: number;
}

export interface AlertGroupingPolicy {
  /** Distancia máxima entre una alerta y lo ya visto del grupo para sumarse. */
  readonly windowMs: number;
  /** Tramo máximo (primera → última) de un grupo; después se abre otro. */
  readonly maxSpanMs: number;
  /**
   * Tope de alertas por grupo: uno lleno se sella y la siguiente abre otro. Acota los grupos
   * demasiado amplios (p. ej. una huella gruesa de solo regla). Sin valor, `DEFAULT_GROUP_MAX_ALERTS`.
   */
  readonly maxAlerts?: number;
}

export const DEFAULT_GROUP_MAX_ALERTS = 500;

export const DEFAULT_ALERT_GROUPING_POLICY: AlertGroupingPolicy = Object.freeze({
  windowMs: 24 * 60 * 60 * 1000,
  maxSpanMs: 7 * 24 * 60 * 60 * 1000,
  maxAlerts: DEFAULT_GROUP_MAX_ALERTS,
});

export const ALERT_GROUPING_LIMITS = Object.freeze({
  minimumWindowMs: 5 * 60 * 1000,
  maximumWindowMs: 7 * 24 * 60 * 60 * 1000,
  maximumSpanMs: 30 * 24 * 60 * 60 * 1000,
  minimumAlerts: 2,
  maximumAlerts: 10_000,
});

/**
 * Prioridades que la consola nunca colapsa dentro de un grupo: cada alerta P1/P2 se muestra como
 * su propia fila aunque comparta huella con otras. El backend nunca omite alertas por agruparlas.
 */
export const NEVER_COLLAPSED_PRIORITIES: readonly Priority[] = Object.freeze(['P1', 'P2']);

export function isCollapsible(priority: Priority): boolean {
  return !NEVER_COLLAPSED_PRIORITIES.includes(priority);
}

export interface GroupableAlert {
  readonly id: string;
  readonly tenantId: string;
  readonly priority: Priority;
  readonly occurredAt: Date;
  readonly fingerprint: string;
  readonly ruleKey: string | null;
  readonly level: 'fine' | 'coarse';
}

export type GroupAssignment =
  | { readonly kind: 'join'; readonly group: AlertGroup; readonly expectedRevision: number }
  | {
      readonly kind: 'open';
      readonly group: AlertGroup;
      /** Grupo abierto que se sella antes de abrir el nuevo, con su revisión esperada. */
      readonly seal?: { readonly group: AlertGroup; readonly expectedRevision: number };
    }
  | { readonly kind: 'none'; readonly reason: 'LATE_OUTSIDE_WINDOW' };

const PRIORITY_RANK: Readonly<Record<Priority, number>> = Object.freeze({
  P1: 1,
  P2: 2,
  P3: 3,
  P4: 4,
});

function higher(left: Priority, right: Priority): Priority {
  return PRIORITY_RANK[left] <= PRIORITY_RANK[right] ? left : right;
}

export function validateGroupingPolicy(policy: AlertGroupingPolicy): boolean {
  return (
    Number.isSafeInteger(policy.windowMs) &&
    Number.isSafeInteger(policy.maxSpanMs) &&
    policy.windowMs >= ALERT_GROUPING_LIMITS.minimumWindowMs &&
    policy.windowMs <= ALERT_GROUPING_LIMITS.maximumWindowMs &&
    policy.maxSpanMs >= policy.windowMs &&
    policy.maxSpanMs <= ALERT_GROUPING_LIMITS.maximumSpanMs &&
    (policy.maxAlerts === undefined ||
      (Number.isSafeInteger(policy.maxAlerts) &&
        policy.maxAlerts >= ALERT_GROUPING_LIMITS.minimumAlerts &&
        policy.maxAlerts <= ALERT_GROUPING_LIMITS.maximumAlerts))
  );
}

function openNew(alert: GroupableAlert, groupId: string): AlertGroup {
  return {
    id: groupId,
    tenantId: alert.tenantId,
    fingerprint: alert.fingerprint,
    ruleKey: alert.ruleKey,
    level: alert.level,
    status: 'open',
    firstSeenAt: alert.occurredAt,
    lastSeenAt: alert.occurredAt,
    alertCount: 1,
    primaryAlertId: alert.id,
    highestPriority: alert.priority,
    revision: 1,
  };
}

/**
 * Decide a qué grupo va una alerta recién creada. `open` es el grupo abierto de su huella (si
 * existe); `newGroupId` se usa solo si hay que abrir uno.
 */
export function assignToGroup(
  alert: GroupableAlert,
  open: AlertGroup | undefined,
  policy: AlertGroupingPolicy,
  newGroupId: string,
): GroupAssignment {
  if (!open) return { kind: 'open', group: openNew(alert, newGroupId) };
  if (open.tenantId !== alert.tenantId || open.fingerprint !== alert.fingerprint) {
    throw new Error('El grupo abierto no corresponde a la huella de la alerta.');
  }
  const at = alert.occurredAt.getTime();
  const first = open.firstSeenAt.getTime();
  const last = open.lastSeenAt.getTime();

  if (at < first - policy.windowMs) return { kind: 'none', reason: 'LATE_OUTSIDE_WINDOW' };

  const nextFirst = Math.min(first, at);
  const nextLast = Math.max(last, at);
  const withinWindow = at <= last + policy.windowMs;
  const withinSpan = nextLast - nextFirst <= policy.maxSpanMs;
  const full = open.alertCount >= (policy.maxAlerts ?? DEFAULT_GROUP_MAX_ALERTS);
  if (withinWindow && withinSpan && full) {
    // Lleno: se sella y la alerta abre otro grupo de la misma huella (nunca se descarta).
    return {
      kind: 'open',
      group: openNew(alert, newGroupId),
      seal: {
        expectedRevision: open.revision,
        group: { ...open, status: 'closed', revision: open.revision + 1 },
      },
    };
  }
  if (withinWindow && withinSpan) {
    return {
      kind: 'join',
      expectedRevision: open.revision,
      group: {
        ...open,
        firstSeenAt: new Date(nextFirst),
        lastSeenAt: new Date(nextLast),
        alertCount: open.alertCount + 1,
        highestPriority: higher(open.highestPriority, alert.priority),
        revision: open.revision + 1,
      },
    };
  }
  // Una alerta tardía que estiraría el grupo más allá del tramo tampoco abre uno paralelo.
  if (at < last) return { kind: 'none', reason: 'LATE_OUTSIDE_WINDOW' };
  return {
    kind: 'open',
    group: openNew(alert, newGroupId),
    seal: {
      expectedRevision: open.revision,
      group: { ...open, status: 'closed', revision: open.revision + 1 },
    },
  };
}
