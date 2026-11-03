/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

export const PLUGIN_ID = 'b89Ops';
export const PLUGIN_NAME = 'B89 SecOps';
/** Nombre descriptivo del grupo de navegación en el menú lateral. */
export const NAV_CATEGORY_NAME = 'Observabilidad de la aplicación';

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

/**
 * Apps registradas en este orden bajo «Observabilidad de la aplicación» (primera categoría
 * del menú). Cada una monta la misma consola en la vista indicada.
 */
export const B89_APPS = [
  {
    id: 'b89-alerts',
    view: 'alerts',
    title: 'Cola de alertas',
    icon: 'b89-alerts.svg',
    order: 10,
  },
  {
    id: 'b89-incidents',
    view: 'incidents',
    title: 'Incidentes',
    icon: 'b89-incidents.svg',
    order: 20,
  },
  {
    id: 'b89-notifications',
    view: 'notifications',
    title: 'Notificaciones',
    icon: 'b89-notifications.svg',
    order: 30,
  },
  {
    id: 'b89-audit',
    view: 'audit',
    title: 'Auditoría e integridad',
    icon: 'b89-audit.svg',
    order: 40,
  },
  {
    id: 'b89-access',
    view: 'access',
    title: 'Usuarios y sesiones',
    icon: 'b89-access.svg',
    order: 50,
  },
  {
    id: 'b89-sources',
    view: 'sources',
    title: 'Salud de fuentes',
    icon: 'b89-sources.svg',
    order: 60,
  },
  {
    id: 'b89-session',
    view: 'session',
    title: 'Mi sesión',
    icon: 'b89-session.svg',
    order: 70,
  },
] as const;

export type B89View = (typeof B89_APPS)[number]['view'];

/** Destino por defecto tras iniciar sesión (y `uiSettings.overrides.defaultRoute`). */
export const DEFAULT_LANDING = '/app/b89-alerts';

export * from './api_contract';
export * from './catalog';
export * from './discover';
export * from './user_state';
export * from './audit_filters';
