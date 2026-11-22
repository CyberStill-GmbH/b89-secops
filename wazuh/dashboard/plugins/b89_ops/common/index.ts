/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

export const PLUGIN_ID = 'b89Ops';
export const PLUGIN_NAME = 'B89 SecOps';
/** Nombre descriptivo del grupo de navegación en el menú lateral. */
export const NAV_CATEGORY_NAME = 'B89 SOC';

/** Rutas propias del dashboard (servidas por este plugin, sin sesión de OSD). */
export const LOGIN_PATH = '/b89/login';
export const LOGOUT_PATH = '/b89/logout';
/** Login heredado del Security plugin / Wazuh que se sustituye por el de B89. */
export const LEGACY_LOGIN_PATHS = ['/app/login', '/login'];

/**
 * Activos de marca servidos por el core en `/ui/b89/` (build.sh los copia a
 * `src/core/server/core_app/assets/b89/`). `/ui/` es público en el edge, así el login
 * puede usarlos sin sesión.
 */
export const BRAND_ASSETS_PATH = '/ui/b89';

/** Atribución visible (NOTICE): B89 SecOps es un trabajo derivado. */
export const ATTRIBUTION = 'Basado en Wazuh (GPLv2) y OpenSearch Dashboards (Apache-2.0).';

/** Categoría del menú para la vigilancia en vivo (la cola de alertas). */
export const MONITORING_CATEGORY_NAME = 'Monitoreo';

/**
 * Apps registradas bajo «B89 SOC» (primera categoría del menú) o «Monitoreo». Cada una monta
 * la misma consola en la vista indicada. El orden sigue `order` dentro de cada categoría.
 */
export const B89_APPS = [
  {
    id: 'b89-overview',
    view: 'overview',
    title: 'Resumen del SOC',
    icon: 'b89-observability.svg',
    order: 1,
    category: 'soc',
  },
  {
    id: 'b89-alerts',
    view: 'alerts',
    title: 'Cola de alertas',
    icon: 'b89-alerts.svg',
    order: 10,
    category: 'monitoring',
  },
  {
    id: 'b89-incidents',
    view: 'incidents',
    title: 'Incidentes',
    icon: 'b89-incidents.svg',
    order: 20,
    category: 'soc',
  },
  {
    id: 'b89-ai-analyst',
    view: 'ai_analyst',
    title: 'Analista IA',
    icon: 'b89-ai-analyst.svg',
    order: 25,
    category: 'soc',
  },
  {
    id: 'b89-notifications',
    view: 'notifications',
    title: 'Notificaciones',
    icon: 'b89-notifications.svg',
    order: 30,
    category: 'soc',
  },
  {
    id: 'b89-integrations',
    view: 'integrations',
    title: 'Integraciones',
    icon: 'b89-sources.svg',
    order: 35,
    category: 'soc',
  },
  {
    id: 'b89-cloudflare-traffic',
    view: 'cloudflare_traffic',
    title: 'Tráfico de Cloudflare',
    icon: 'b89-sources.svg',
    order: 36,
    category: 'soc',
  },
  {
    id: 'b89-policies',
    view: 'policies',
    title: 'Políticas',
    icon: 'b89-audit.svg',
    order: 37,
    category: 'soc',
  },
  {
    id: 'b89-dlp',
    view: 'dlp',
    title: 'DLP de endpoints',
    icon: 'b89-audit.svg',
    order: 38,
    category: 'soc',
  },
  {
    id: 'b89-audit',
    view: 'audit',
    title: 'Auditoría e integridad',
    icon: 'b89-audit.svg',
    order: 40,
    category: 'soc',
  },
  {
    id: 'b89-access',
    view: 'access',
    title: 'Usuarios y sesiones',
    icon: 'b89-access.svg',
    order: 50,
    category: 'soc',
  },
  {
    id: 'b89-sources',
    view: 'sources',
    title: 'Salud de fuentes',
    icon: 'b89-sources.svg',
    order: 60,
    category: 'soc',
  },
  {
    id: 'b89-session',
    view: 'session',
    title: 'Mi sesión',
    icon: 'b89-session.svg',
    order: 70,
    category: 'soc',
  },
] as const;

export type B89View = (typeof B89_APPS)[number]['view'];

/**
 * B89 Respond (SOAR) embebido: app propia del menú B89 que enmarca `/b89-respond/` (mismo
 * origen, detrás de la sesión B89 en el edge). No es una vista de la consola: no usa la API B89.
 */
export const RESPOND_APP = {
  id: 'b89-respond',
  /** Nombre de producto en el menú; «SOAR» queda como descripción (`tooltip`). */
  title: 'B89 Respond',
  subtitle: 'SOAR',
  icon: 'b89-respond.svg',
  order: 5,
} as const;
export const RESPOND_PATH = '/b89-respond/';

/** Destino por defecto tras iniciar sesión (y `uiSettings.overrides.defaultRoute`). */
export const DEFAULT_LANDING = '/app/b89-overview';
/** Cola de alertas (categoría «Monitoreo»): destino de los avisos P1. */
export const ALERTS_PATH = '/app/b89-alerts';

export * from './api_contract';
export * from './catalog';
export * from './discover';
export * from './user_state';
export * from './audit_filters';
export * from './integrations';
export * from './vendors';
export * from './investigation';
export * from './bunny_bridge';
export * from './navigation';
export * from './platform_health';
 export * from './source_health';
export * from './ai_investigations';
export * from './ai_activity';
export * from './cloudflare_traffic';
export * from './cloudflare_analysis';
