/**
 * Puertos de C-20.
 *
 * `OutboxReader.claimPending` toma un lease: dos réplicas del worker no deben despachar
 * el mismo mensaje a la vez. La idempotencia del intento protege igualmente, pero un
 * lease evita gastar dos llamadas al destino por cada crítico.
 */

import type { OutboxMessageDraft } from '@b89/soc';

import type { RenderedEmail } from './notification-content.js';
import type { DeliveryEvidence, NotificationAttempt, NotificationChannel } from './notification.js';
import type { NotificationRecipient } from './notification-routing.js';

export interface OutboxReader {
  claimPending(limit: number, now: Date): Promise<readonly OutboxMessageDraft[]>;
  markPublished(messageId: string, at: Date): Promise<void>;
  scheduleRetry(messageId: string, availableAt: Date, errorCode: string): Promise<void>;
}

export interface AttemptStore {
  byIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<NotificationAttempt | undefined>;
  byId(tenantId: string, attemptId: string): Promise<NotificationAttempt | undefined>;
  save(attempt: NotificationAttempt): Promise<void>;
  /** Bandeja de la consola: más recientes primero, acotada por `limit`. */
  listByTenant(tenantId: string, limit: number): Promise<readonly NotificationAttempt[]>;
  /**
   * Conteo por estado de los intentos creados desde `since` (ventana fija, no "las últimas N
   * filas"). Lo usa la salud operativa: la semántica debe ser estable entre llamadas.
   */
  countByStatusSince(tenantId: string, since: Date): Promise<Readonly<Record<string, number>>>;
  /**
   * Último aviso publicado (enviado, por respaldo, reconocido o sustituido, con `sentAt`) del
   * grupo desde `since`. Base de la agrupación y del re-aviso silencioso.
   */
  lastNotifiedInGroup(
    tenantId: string,
    groupKey: string,
    since: Date,
  ): Promise<NotificationAttempt | undefined>;
  /** Suprimidas del grupo creadas después de `after`, más antiguas primero (acotado). */
  listSuppressedInGroup(
    tenantId: string,
    groupKey: string,
    after: Date,
    limit: number,
  ): Promise<readonly NotificationAttempt[]>;
  /** Avisos inmediatos publicados (con `sentAt`) desde `since`; para el tope por hora. */
  countNotifiedSince(tenantId: string, since: Date): Promise<number>;
  /** Suprimidas que ningún resumen incluyó todavía, más antiguas primero (acotado). */
  listUndigested(tenantId: string, limit: number): Promise<readonly NotificationAttempt[]>;
}

export interface FallbackNotification {
  readonly tenantId: string;
  readonly aggregateType: 'alert' | 'incident';
  readonly aggregateId: string;
  readonly title: string;
  readonly severity: string;
  readonly reason: string;
  readonly at: Date;
  /**
   * Personas del SOC que debían recibir el aviso en Teams (Sprint 5): el respaldo por correo se
   * dirige a ellas. Vacío si no hay padrón.
   */
  readonly recipients?: readonly NotificationRecipient[];
  /** Enlace a B89 para abrir el recurso (requiere sesión). */
  readonly link?: string;
  /** Correo explicativo ya renderizado (asunto, HTML y texto). */
  readonly email?: RenderedEmail;
}

export interface FallbackChannel {
  notify(notification: FallbackNotification): Promise<{
    readonly channel: NotificationChannel;
    readonly reference: string;
    /** Evidencia del canal que finalmente aceptó (o de los que fallaron en el camino). */
    readonly evidence?: readonly DeliveryEvidence[];
  }>;
}

/** Correo directo (copia de P1 y resúmenes): Graph `sendMail`. */
export interface MailChannel {
  send(input: {
    readonly recipients: readonly NotificationRecipient[];
    readonly email: RenderedEmail;
    readonly clientRequestId: string;
  }): Promise<DeliveryEvidence>;
}
