/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  Alert,
  HealthTone,
  NotificationAttempt,
  NotificationChannel,
  NotificationDelivery,
  Priority,
  PRIORITIES,
  VendorId,
  vendorOfProvider,
  vendorOfTitle,
  wazuhRuleIdOfTitle,
} from '../../common';

/** Lógica pura de la bandeja de notificaciones (agrupación, entrega, enmascarado). */

export type DeliveryKind = 'pending' | 'sent' | 'delivered' | 'failed' | 'acknowledged' | 'uncertain';

export const DELIVERY: Record<DeliveryKind, { label: string; tone: HealthTone }> = {
  pending: { label: 'Pendiente', tone: 'neutral' },
  sent: { label: 'Enviado (aceptado por M365)', tone: 'info' },
  delivered: { label: 'Entregado', tone: 'ok' },
  failed: { label: 'Fallido', tone: 'fail' },
  acknowledged: { label: 'Reconocido', tone: 'ok' },
  uncertain: { label: 'Entrega sin confirmar', tone: 'warn' },
};

export interface DeliveryLine {
  readonly key: string;
  readonly channel: NotificationChannel;
  readonly attempt: number;
  readonly kind: DeliveryKind;
  readonly at: string | null;
  readonly reason: string | null;
  readonly actor: string | null;
  readonly link: string | null;
}

/** Historial de entrega de un intento: `deliveries` de la API o, si no llega, su estado. */
export function deliveryLines(item: NotificationAttempt): DeliveryLine[] {
  if (item.deliveries && item.deliveries.length > 0) {
    return item.deliveries.map((d: NotificationDelivery, index) => ({
      key: `${item.id}-${index}`,
      channel: d.channel,
      attempt: d.attempt,
      kind: d.outcome,
      at: d.at,
      reason: d.reason ?? null,
      actor: d.actor ?? null,
      link: d.link ?? null,
    }));
  }
  const base = {
    channel: item.channel,
    attempt: item.attemptCount,
    reason: null as string | null,
    actor: null as string | null,
    link: item.link ?? null,
  };
  const lines: DeliveryLine[] = [];
  const status = item.status;
  if (status === 'pending' || status === 'sending') {
    lines.push({ ...base, key: `${item.id}-p`, kind: 'pending', at: null });
  } else if (status === 'failed') {
    lines.push({
      ...base,
      key: `${item.id}-f`,
      kind: 'failed',
      at: item.sentAt,
      reason: item.lastFailureReason ?? item.lastFailureClass ?? null,
    });
  } else if (status === 'indeterminate') {
    lines.push({ ...base, key: `${item.id}-u`, kind: 'uncertain', at: item.sentAt });
  } else {
    lines.push({ ...base, key: `${item.id}-s`, kind: 'sent', at: item.sentAt });
  }
  if (item.acknowledgedAt) {
    lines.push({
      ...base,
      key: `${item.id}-a`,
      kind: 'acknowledged',
      at: item.acknowledgedAt,
      actor: item.acknowledgedBy,
    });
  }
  return lines;
}

/** Último estado por canal (para la fila). */
export function latestByChannel(items: readonly NotificationAttempt[]): DeliveryLine[] {
  const byChannel = new Map<string, DeliveryLine>();
  for (const item of items) {
    for (const line of deliveryLines(item)) {
      const current = byChannel.get(line.channel);
      if (!current || (line.at ?? '') >= (current.at ?? '')) byChannel.set(line.channel, line);
    }
  }
  return [...byChannel.values()];
}

/** Enmascara una entidad si la API la devolvió en claro (correo o IP). */
export function maskEntity(value: string | null | undefined): string | null {
  if (!value) return null;
  const email = /^([^@]{1,2})[^@]*(@.+)$/u.exec(value);
  if (email) return `${email[1]}***${email[2]}`;
  const ip = /^(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}$/u.exec(value);
  if (ip) return `${ip[1]}.x.x`;
  return value.length > 24 ? `${value.slice(0, 12)}…` : value;
}

export interface NotificationGroup {
  readonly key: string;
  readonly alertId: string | null;
  readonly incidentId: string | null;
  readonly items: readonly NotificationAttempt[];
  readonly latest: NotificationAttempt;
}

const newestFirst = (a: string, b: string) => (a === b ? 0 : a < b ? 1 : -1);

/** Agrupa avisos repetidos de la misma alerta, incidente o mensaje (más reciente primero). */
export function groupNotifications(items: readonly NotificationAttempt[]): NotificationGroup[] {
  const groups = new Map<string, NotificationAttempt[]>();
  for (const item of items) {
    const key = item.alertId
      ? `alert:${item.alertId}`
      : item.incidentId
        ? `incident:${item.incidentId}`
        : item.messageId
          ? `message:${item.messageId}`
          : `attempt:${item.id}`;
    const list = groups.get(key) ?? [];
    list.push(item);
    groups.set(key, list);
  }
  const at = (item: NotificationAttempt) => item.acknowledgedAt ?? item.sentAt ?? '';
  return [...groups.entries()]
    .map(([key, list]) => {
      const sorted = [...list].sort((a, b) => newestFirst(at(a), at(b)));
      return {
        key,
        alertId: sorted[0].alertId ?? null,
        incidentId: sorted.find((item) => item.incidentId)?.incidentId ?? null,
        items: sorted,
        latest: sorted[0],
      };
    })
    .sort((a, b) => newestFirst(at(a.latest), at(b.latest)));
}

const isPriority = (value: unknown): value is Priority =>
  typeof value === 'string' && (PRIORITIES as readonly string[]).includes(value);

/** Datos visibles de un grupo: `subject` de la API o, si falta, la alerta B89. */
export function describeGroup(group: NotificationGroup, alert: Alert | null | undefined) {
  const subject = group.items.find((item) => item.subject)?.subject ?? null;
  const title = subject?.title ?? alert?.title ?? null;
  const priority: Priority | null = isPriority(subject?.priority)
    ? (subject!.priority as Priority)
    : alert
      ? alert.priority
      : null;
  const ruleId = subject?.ruleId ?? (title ? wazuhRuleIdOfTitle(title) : null);
  const vendor: VendorId = subject?.source
    ? vendorOfProvider(subject.source)
    : title
      ? vendorOfTitle(title)
      : 'wazuh';
  const entity = subject?.entity ?? maskEntity(alert?.entities[0]?.label);
  return { title, priority, ruleId, vendor, entity };
}
