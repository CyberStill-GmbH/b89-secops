/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type {
  AlertStatus,
  AlertVerdict,
  ApiErrorCode,
  CorrelatorFeedbackStatus,
  IncidentSeverity,
  IncidentStatus,
  NotificationChannel,
  NotificationDeliveryChannel,
  NotificationStatus,
  OperationsStatus,
  Priority,
  SessionState,
  SourceState,
  TaskStatus,
} from './api_contract';

/**
 * Catálogo de rótulos (doc 01 §3 de b89-secops). El valor crudo del backend solo se
 * muestra en mono en vistas técnicas; el resto de la UI usa estos textos.
 */

export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'Nueva',
  acknowledged: 'En revisión',
  triaged: 'Clasificada',
  escalated: 'Escalada',
  closed: 'Cerrada',
};

export const VERDICT_LABEL: Record<AlertVerdict, string> = {
  true_positive: 'Real (verdadero positivo)',
  false_positive: 'No es real (falso positivo)',
  benign: 'Real pero esperada (benigna)',
  duplicate: 'Duplicada',
};

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  open: 'Abierto',
  contained: 'Contenido',
  eradicated: 'Erradicado',
  resolved: 'Resuelto',
  closed: 'Cerrado',
};

export const SEVERITY_LABEL: Record<IncidentSeverity, string> = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Media',
  low: 'Baja',
};

export const TASK_STATUS_LABEL: Record<TaskStatus, string> = {
  open: 'Pendiente',
  in_progress: 'En curso',
  done: 'Hecha',
  cancelled: 'Cancelada',
};

export const SOURCE_STATE_LABEL: Record<SourceState, string> = {
  unknown: 'Sin comprobar',
  healthy: 'Funciona',
  degraded: 'Con problemas',
  failed: 'Caída',
  disabled: 'Desactivada',
};

export const SOURCE_REASON_LABEL: Record<string, string> = {
  DISABLED: 'Fuente desactivada por configuración',
  NO_OBSERVATIONS: 'Todavía no hay intentos registrados',
  PERMANENT_ERROR: 'Error permanente del proveedor',
  NO_RECENT_SUCCESS: 'Sin lecturas correctas recientes',
  CONSECUTIVE_FAILURES: 'Falló varias veces seguidas',
  NEVER_SUCCEEDED: 'Nunca ha completado una lectura',
  RECENT_SUCCESS: 'Lectura correcta reciente',
};

export const SESSION_STATE_LABEL: Record<SessionState, string> = {
  active: 'Activa',
  expired: 'Expirada',
  revoked: 'Revocada',
  superseded: 'Reemplazada',
};

export const ROLE_LABEL: Record<string, string> = {
  'b89.soc.analyst': 'Analista SOC',
  'b89.soc.lead': 'Líder SOC',
  'b89.auditor': 'Auditor',
  'b89.platform.admin': 'Administrador de plataforma',
};

export const AUDIT_VIOLATION_LABEL: Record<string, string> = {
  TAMPERED: 'Evento alterado',
  FORKED: 'Cadena bifurcada',
  GAP: 'Hueco en la secuencia',
  OUT_OF_ORDER: 'Secuencia fuera de orden',
};

/** Mensajes públicos del catálogo de errores (packages/contracts de b89-secops). */
export const API_ERROR_MESSAGE: Record<ApiErrorCode, string> = {
  AUTH_REQUIRED: 'Inicia sesión para continuar.',
  AUTH_FAILED: 'No pudimos iniciar tu sesión con esas credenciales. Revísalas e inténtalo de nuevo.',
  SESSION_EXPIRED: 'Tu sesión terminó. Vuelve a iniciar sesión.',
  PASSKEY_REQUIRED:
    'Fuera de la red de B89 necesitas una llave de acceso (passkey) registrada. Entra con ella o conéctate a la red de B89.',
  STEP_UP_REQUIRED:
    'Por seguridad, esta acción pide un inicio de sesión reciente: cierra sesión, vuelve a entrar y repítela.',
  NETWORK_NOT_ALLOWED:
    'Esta red no está autorizada. Conéctate a la red de B89 o entra con tu llave de acceso (passkey).',
  REQUEST_NOT_VERIFIED:
    'No pudimos verificar la solicitud. Recarga la página e inténtalo de nuevo.',
  RATE_LIMITED: 'Demasiados intentos. Espera un minuto y vuelve a intentarlo.',
  RESOURCE_UNAVAILABLE: 'No encontramos este elemento o tu rol no puede verlo.',
  STATE_CONFLICT: 'Alguien cambió este elemento mientras trabajabas. Recárgalo y repite el cambio.',
  VALIDATION_FAILED: 'Revisa los datos marcados y vuelve a enviarlos.',
  DEPENDENCY_DEGRADED:
    'Una parte del sistema responde con retraso; los datos pueden tener unos minutos de atraso.',
  INTERNAL_ERROR:
    'Algo falló de nuestro lado. Reintenta; si se repite, comparte la referencia con plataforma.',
};

/**
 * Severidad por forma + color + rótulo (doc 02 §2.5). P1 y `critical` comparten paso.
 * El glifo distingue el paso en escala de grises y daltonismo.
 */
export interface SeverityStep {
  readonly glyph: string;
  readonly color: string;
  readonly step: 1 | 2 | 3 | 4;
}

export const PRIORITY_STEP: Record<Priority, SeverityStep> = {
  P1: { glyph: '◆', color: '#ff5f57', step: 1 },
  P2: { glyph: '▲', color: '#f0904a', step: 2 },
  P3: { glyph: '■', color: '#d8c35c', step: 3 },
  P4: { glyph: '●', color: '#7f95aa', step: 4 },
};

export const SEVERITY_STEP: Record<IncidentSeverity, SeverityStep> = {
  critical: PRIORITY_STEP.P1,
  high: PRIORITY_STEP.P2,
  medium: PRIORITY_STEP.P3,
  low: PRIORITY_STEP.P4,
};

export type HealthTone = 'ok' | 'warn' | 'fail' | 'neutral' | 'info';

/**
 * Colores como variables CSS (definidas en `theme.scss`) con el valor del tema oscuro de respaldo:
 * el tema claro las redefine para mantener ≥ 3:1 de contraste en glifos y bordes.
 */
export const HEALTH_TONE: Record<HealthTone, { readonly glyph: string; readonly color: string }> = {
  ok: { glyph: '✓', color: 'var(--b89-tone-ok, #5fb98a)' },
  warn: { glyph: '!', color: 'var(--b89-tone-warn, #d8c35c)' },
  fail: { glyph: '×', color: 'var(--b89-tone-fail, #ff5f57)' },
  neutral: { glyph: '–', color: 'var(--b89-tone-neutral, #8f8f95)' },
  info: { glyph: 'i', color: 'var(--b89-tone-info, #8fb3d9)' },
};

export const SOURCE_TONE: Record<SourceState, HealthTone> = {
  unknown: 'neutral',
  healthy: 'ok',
  degraded: 'warn',
  failed: 'fail',
  disabled: 'neutral',
};

/** Entregado ≠ reconocido por una persona (patrón PagerDuty, doc 04 §6.1). */
export const NOTIFICATION_STATUS_LABEL: Record<NotificationStatus, string> = {
  pending: 'Pendiente',
  sending: 'Enviando',
  sent: 'Entregado al canal',
  indeterminate: 'Entrega incierta',
  failed: 'Fallida',
  fallback: 'Por canal alternativo',
  acknowledged: 'Visto por el SOC',
  suppressed: 'Agrupada o en resumen',
  superseded: 'Sustituida',
};

export const NOTIFICATION_TONE: Record<NotificationStatus, HealthTone> = {
  pending: 'neutral',
  sending: 'info',
  sent: 'warn',
  indeterminate: 'warn',
  failed: 'fail',
  fallback: 'warn',
  acknowledged: 'ok',
  suppressed: 'neutral',
  superseded: 'neutral',
};

export const NOTIFICATION_CHANNEL_LABEL: Record<NotificationDeliveryChannel, string> = {
  teams: 'Microsoft Teams',
  fallback_email: 'Correo (alternativo)',
  manual_console: 'Consola',
  email: 'Correo',
  console: 'Consola',
  push: 'Aviso push',
};

export const OPERATIONS_STATUS_LABEL: Record<OperationsStatus, string> = {
  OK: 'Funciona',
  NO_DATA: 'Sin comprobar',
  STALE: 'Con retraso',
  DEGRADED: 'Con problemas',
};

export const OPERATIONS_TONE: Record<OperationsStatus, HealthTone> = {
  OK: 'ok',
  NO_DATA: 'neutral',
  STALE: 'warn',
  DEGRADED: 'warn',
};

export const CORRELATOR_FEEDBACK_STATUS_LABEL: Record<CorrelatorFeedbackStatus, string> = {
  ready: 'Listo',
  pending: 'Inicializando',
  failed: 'Actualización fallida',
  stale: 'Atrasado',
  unavailable: 'Sin respuesta',
  unconfigured: 'No configurado',
};

export const CORRELATOR_FEEDBACK_STATUS_TONE: Record<CorrelatorFeedbackStatus, HealthTone> = {
  ready: 'ok',
  pending: 'info',
  failed: 'fail',
  stale: 'warn',
  unavailable: 'neutral',
  unconfigured: 'neutral',
};

export const DEGRADED_REASON_LABEL: Record<string, string> = {
  DISPATCHER_STOPPED: 'El envío de avisos está detenido',
  OUTBOX_BACKLOG: 'Hay avisos esperando en la cola de envío desde hace más de 5 min',
  OUTBOX_LEASE_EXPIRED: 'Hay avisos atascados en la cola de envío',
  WAZUH_PUSH_TERMINAL_FAILURES: 'El canal rápido de Wazuh dejó eventos sin procesar',
  WAZUH_PUSH_LEASE_EXPIRED: 'Hay eventos de Wazuh atascados en el canal rápido',
  PERSISTENCE_EPHEMERAL: 'Los datos se guardan solo en memoria: se pierden si el servicio reinicia',
  NOTIFICATION_FAILED: 'Hubo notificaciones fallidas en la ventana',
  NOTIFICATION_INDETERMINATE: 'Hubo notificaciones con entrega incierta',
  NOTIFICATION_FALLBACK: 'Hubo notificaciones por el canal alternativo',
  NOTIFICATION_TEAMS_NOT_CONFIGURED: 'Microsoft Teams no tiene un webhook configurado',
  NOTIFICATION_NO_P1_CHANNEL:
    'Ningún canal (Teams o correo) puede entregar un aviso P1; solo queda la bandeja',
  DATABASE_UNAVAILABLE: 'La base de datos no respondió',
  DATABASE_SLOW: 'La base de datos responde lento (> 1 s)',
  CORRELATOR_UNREACHABLE: 'El correlador no respondió o su respuesta no es válida',
  CORRELATOR_NOT_READY:
    'El correlador no está listo (aún carga el historial, va atrasado o no pudo leer el SIEM)',
  CORRELATOR_COVERAGE_INCOMPLETE:
    'Cobertura incompleta: al menos una fuente va atrasada o su colector falló; pueden faltar eventos',
};

/** Motivo de cobertura por fuente (correlador). `unknown` se presenta como no verificada. */
export const SOURCE_COVERAGE_REASON_LABEL: Record<string, string> = {
  no_collector_heartbeat: 'no verificada: el colector no reportó su estado',
  collector_run_partial: 'la última corrida del colector fue parcial',
  collector_run_failed: 'la última corrida del colector falló',
  collector_heartbeat_stale: 'el colector no reporta hace más de 1 h',
  collector_behind_provider: 'el colector va atrasado respecto del proveedor',
  correlator_backfilling: 'el correlador aún está cargando el historial',
  correlator_read_failed: 'el correlador no pudo leer el SIEM',
  correlator_catching_up: 'el correlador se está poniendo al día',
};

/** Métodos de autenticación (`amr` de Entra ID) en palabras. */
export const AMR_LABEL: Record<string, string> = {
  mfa: 'Multifactor',
  pwd: 'Contraseña',
  fido: 'Llave de acceso (passkey)',
  hwk: 'Llave de hardware',
  rsa: 'Certificado',
  wia: 'Windows integrado',
  ngcmfa: 'Windows Hello',
};

/** «Contraseña + Multifactor»; `emptyLabel` si la sesión no informa el método. */
export function amrText(amr: readonly string[], emptyLabel = 'Método sin dato'): string {
  return amr.length === 0 ? emptyLabel : amr.map((method) => AMR_LABEL[method] ?? method).join(' + ');
}

/** Capacidades de la sesión en palabras («Puedes: ver alertas, …»). El código queda plegado. */
export const CAPABILITY_LABEL: Record<string, string> = {
  'alerts.read': 'ver alertas',
  'alerts.triage': 'clasificar alertas',
  'alerts.assign': 'asignar alertas',
  'incidents.read': 'ver incidentes',
  'incidents.write': 'gestionar incidentes',
  'incidents.close': 'cerrar incidentes',
  'incidents.tasks.write': 'gestionar tareas de incidentes',
  'incidents.notes.write': 'escribir notas en incidentes',
  'sources.health.read': 'ver la salud de las fuentes',
  'audit.read': 'ver la auditoría',
  'audit.verify': 'verificar la integridad de la auditoría',
  'users.read': 'ver usuarios',
  'roles.request': 'solicitar cambios de rol',
  'roles.approve': 'aprobar roles (etapa Accesos)',
  'roles.approve.privileged': 'aprobar roles privilegiados (etapa Seguridad)',
  'sessions.read': 'ver sesiones',
  'sessions.revoke': 'revocar sesiones',
  'notifications.read': 'ver notificaciones',
  'notifications.manage': 'configurar canales de aviso',
  'observability.read_soc': 'ver la salud operativa del SOC',
  'observability.read_platform': 'ver la salud de la plataforma',
  'investigations.read': 'ver análisis del Analista IA',
  'investigations.run': 'iniciar y detener análisis del Analista IA',
  'investigations.configure': 'configurar el Analista IA',
  'dlp.read': 'ver DLP en equipos',
  'dlp.configure': 'configurar DLP en equipos',
};
