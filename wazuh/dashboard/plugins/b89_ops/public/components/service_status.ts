/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  HealthTone,
  IntegrationConfig,
  OverviewResponse,
  ProviderId,
  SourceHealth,
} from '../../common';

/**
 * Estado visible de cada servicio a partir de lo declarado (`b89_ops.integrations`) y de lo
 * medido (Indexer, API B89). Una sola tabla de decisión para «Resumen del SOC» e
 * «Integraciones»: la misma integración nunca dice cosas distintas en dos pantallas.
 */
export interface ServiceStatus {
  readonly tone: HealthTone;
  readonly label: string;
  /** Una línea con el porqué (permiso faltante, último evento, error). */
  readonly detail: string | null;
}

/** Horas sin eventos a partir de las cuales un proveedor se considera callado. */
export const STALE_AFTER_HOURS: Readonly<Record<ProviderId, number>> = {
  office365: 2,
  sharepoint: 24,
  bitdefender: 24,
  // Snyk emite un evento por cambio de issue: días sin cambios son normales.
  snyk: 24 * 7,
  cloudflare: 24,
  aws: 24,
};

export function declaredStatus(config: IntegrationConfig | undefined): ServiceStatus | null {
  if (!config || config.state === 'auto') return null;
  const permissions = config.missingPermissions.join(', ');
  if (config.state === 'blocked') {
    return {
      tone: 'warn',
      label: permissions ? `Requiere ${permissions}` : 'Bloqueada',
      detail: config.note || null,
    };
  }
  if (config.state === 'disabled') {
    return { tone: 'neutral', label: 'No configurada', detail: config.note || null };
  }
  return { tone: 'info', label: 'Pendiente', detail: config.note || null };
}

export function providerStatus(
  id: ProviderId,
  overview: OverviewResponse | null,
  now: number = Date.now(),
): ServiceStatus {
  const declared = declaredStatus(overview?.integrations[id]);
  if (declared) return declared;
  if (!overview) return { tone: 'neutral', label: 'Consultando…', detail: null };
  if (overview.alertsAccess === 'forbidden') {
    return {
      tone: 'neutral',
      label: 'Sin permiso de lectura',
      detail: 'Tu rol no puede leer wazuh-alerts-*.',
    };
  }
  const stats = overview.providers?.[id];
  if (!stats) {
    return { tone: 'fail', label: 'Sin respuesta del Indexer', detail: null };
  }
  if (!stats.lastEventAt) {
    return { tone: 'neutral', label: 'Sin datos', detail: 'Todavía no llegó ningún evento.' };
  }
  const ageHours = (now - new Date(stats.lastEventAt).getTime()) / 3_600_000;
  if (ageHours > STALE_AFTER_HOURS[id]) {
    return { tone: 'warn', label: 'Sin eventos recientes', detail: null };
  }
  return { tone: 'ok', label: 'Recibiendo datos', detail: null };
}

export function wazuhStatus(
  overview: OverviewResponse | null,
  source: SourceHealth | null,
): ServiceStatus {
  const declared = declaredStatus(overview?.integrations.wazuh);
  if (declared) return declared;
  if (!overview) return { tone: 'neutral', label: 'Consultando…', detail: null };
  if (overview.alertsAccess === 'error') {
    return { tone: 'fail', label: 'Indexer sin respuesta', detail: null };
  }
  if (source && (source.state === 'failed' || source.state === 'degraded')) {
    return {
      tone: source.state === 'failed' ? 'fail' : 'warn',
      label: source.state === 'failed' ? 'Ingesta caída' : 'Ingesta degradada',
      detail: 'La lectura de alertas hacia la cola B89 tiene fallos.',
    };
  }
  const agents = overview.agents;
  if (agents && agents.total > 0 && agents.disconnected > 0) {
    return {
      tone: 'warn',
      label: 'Agentes desconectados',
      detail: `${agents.disconnected} de ${agents.total} sin conexión.`,
    };
  }
  if (agents && agents.total === 0) {
    return { tone: 'warn', label: 'Sin agentes', detail: 'No hay agentes enrolados.' };
  }
  return { tone: 'ok', label: 'Operativo', detail: null };
}
