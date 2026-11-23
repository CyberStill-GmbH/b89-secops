/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Navegación del SIEM B89: categorías en español y qué apps del dashboard (B89, app de Wazuh y
 * núcleo de OSD) se muestran en el menú. Lo aplica `public/navigation.ts` con
 * `application.registerAppUpdater` (OSD 2.19 fusiona el resultado del updater con la app, así
 * que también cambia la categoría, el orden y el título). Ocultar del menú no bloquea la URL:
 * los permisos siguen en el Security plugin y en la API B89.
 *
 * Auditoría y motivos: docs/08-frontend-unificado.md § «Navegación del SIEM».
 */

export interface NavCategory {
  readonly id: string;
  readonly label: string;
  readonly order: number;
  /** Icono servido en `/ui/b89/` (solo lo muestra el menú expandido). */
  readonly icon: string;
}

export const NAV_CATEGORIES = {
  summary: { id: 'b89-nav-summary', label: 'Resumen', order: -1000, icon: 'b89-observability.svg' },
  monitoring: { id: 'b89-nav-monitoring', label: 'Monitoreo', order: -990, icon: 'b89-alerts.svg' },
  investigation: {
    id: 'b89-nav-investigation',
    label: 'Investigación y respuesta',
    order: -980,
    icon: 'b89-incidents.svg',
  },
  detection: {
    id: 'b89-nav-detection',
    label: 'Detección',
    order: -970,
    icon: 'b89-ai-analyst.svg',
  },
  compliance: {
    id: 'b89-nav-compliance',
    label: 'Cumplimiento',
    order: -960,
    icon: 'b89-audit.svg',
  },
  integrations: {
    id: 'b89-nav-integrations',
    label: 'Integraciones',
    order: -950,
    icon: 'b89-sources.svg',
  },
  /** Sin entradas propias: B89 Respond vive en «Investigación y respuesta». Se conserva la clave. */
  response: { id: 'b89-nav-response', label: 'Respuesta', order: -940, icon: 'b89-respond.svg' },
  admin: { id: 'b89-nav-admin', label: 'Accesos', order: -930, icon: 'b89-access.svg' },
  platform: {
    id: 'b89-nav-platform',
    label: 'Plataforma (avanzado)',
    order: -920,
    icon: 'b89-session.svg',
  },
} as const;

export type NavCategoryKey = keyof typeof NAV_CATEGORIES;

export interface NavPlacement {
  readonly category: NavCategoryKey;
  readonly order: number;
  /** Título en el menú (en español y sin duplicados entre categorías). */
  readonly title?: string;
  readonly tooltip?: string;
}

/** Apps visibles: categoría, orden y título. Lo que no está aquí ni en `NAV_HIDDEN` no se toca. */
export const NAV_PLACEMENT: Readonly<Record<string, NavPlacement>> = {
  // Resumen
  'b89-overview': {
    category: 'summary',
    order: 10,
    title: 'Resumen del SOC',
    tooltip: 'Portada de B89: alertas por atender, incidentes y estado de las fuentes',
  },
  'wz-home': {
    category: 'summary',
    order: 20,
    title: 'Resumen de Wazuh (agentes y módulos)',
    tooltip: 'Portada de Wazuh: agentes, módulos y eventos del SIEM',
  },
  dashboards: { category: 'summary', order: 30, title: 'Paneles' },
  visualize: { category: 'summary', order: 35, title: 'Editor de visualizaciones' },
  reporting: { category: 'summary', order: 40, title: 'Informes PDF del SIEM' },
  'reports-dashboards': { category: 'summary', order: 50, title: 'Informes programados' },
  // Monitoreo
  'b89-alerts': { category: 'monitoring', order: 10, title: 'Cola de alertas' },
  'b89-notifications': { category: 'monitoring', order: 20, title: 'Notificaciones' },
  'endpoints-summary': { category: 'monitoring', order: 30, title: 'Agentes' },
  'b89-sources': {
    category: 'monitoring',
    order: 40,
    title: 'Salud de fuentes',
    tooltip: '¿Llegan los datos de cada fuente? Estado en vivo y qué falla',
  },
  // Investigación y respuesta
  'b89-incidents': { category: 'investigation', order: 10, title: 'Incidentes' },
  'b89-ai-analyst': {
    category: 'investigation',
    order: 15,
    title: 'Analista IA',
    tooltip: 'Investigación automática de alertas, con evidencia y costo estimado',
  },
  'b89-cloudflare-traffic': {
    category: 'investigation',
    order: 18,
    title: 'Cloudflare: actividad y tráfico',
    tooltip: 'Hallazgos del backoffice y pagos; registros HTTP, DNS y WAF, en hora de Lima',
  },
  'threat-hunting': { category: 'investigation', order: 20, title: 'Búsqueda de amenazas' },
  // OSD 2.19 registra `data-explorer` oculto y `discover` visible (redirige al primero): solo se
  // ve una entrada. Ambas llevan el mismo título por si un despliegue muestra la otra.
  'data-explorer': { category: 'investigation', order: 30, title: 'Explorar eventos' },
  discover: { category: 'investigation', order: 30, title: 'Explorar eventos' },
  'mitre-attack': { category: 'investigation', order: 40, title: 'MITRE ATT&CK' },
  'b89-respond': {
    category: 'investigation',
    order: 50,
    title: 'Respuesta automática (SOAR)',
    tooltip: 'B89 Respond: playbooks y respuesta',
  },
  // Detección
  'vulnerability-detection': {
    category: 'detection',
    order: 10,
    title: 'Vulnerabilidades',
  },
  'malware-detection': { category: 'detection', order: 20, title: 'Malware y rootcheck' },
  'file-integrity-monitoring': {
    category: 'detection',
    order: 30,
    title: 'Integridad de archivos (FIM)',
  },
  'configuration-assessment': {
    category: 'detection',
    order: 40,
    title: 'Configuración segura (SCA)',
  },
  'it-hygiene': { category: 'detection', order: 50, title: 'Inventario (higiene de TI)' },
  rules: { category: 'detection', order: 60, title: 'Reglas' },
  decoders: { category: 'detection', order: 70, title: 'Decodificadores' },
  'cdb-lists': { category: 'detection', order: 80, title: 'Listas CDB' },
  'ruleset-test': { category: 'detection', order: 90, title: 'Probar reglas' },
  // Cumplimiento
  'b89-policies': { category: 'compliance', order: 10, title: 'Políticas' },
  'b89-audit': { category: 'compliance', order: 20, title: 'Auditoría e integridad' },
  'pci-dss': { category: 'compliance', order: 30, title: 'PCI DSS' },
  gdpr: { category: 'compliance', order: 40, title: 'GDPR' },
  hipaa: { category: 'compliance', order: 50, title: 'HIPAA' },
  'nist-800-53': { category: 'compliance', order: 60, title: 'NIST 800-53' },
  tsc: { category: 'compliance', order: 70, title: 'TSC (SOC 2)' },
  // Integraciones
  'b89-integrations': {
    category: 'integrations',
    order: 10,
    title: 'Integraciones',
    tooltip: 'Conexión y permisos de cada proveedor (el estado en vivo está en «Salud de fuentes»)',
  },
  office365: {
    category: 'integrations',
    order: 70,
    title: 'Microsoft 365: vista del módulo Wazuh',
  },
  sharepoint: { category: 'integrations', order: 75, title: 'SharePoint y OneDrive' },
  docker: { category: 'integrations', order: 80, title: 'Docker' },
  // Accesos (personas y control de datos)
  'b89-access': { category: 'admin', order: 10, title: 'Usuarios y sesiones' },
  'b89-session': { category: 'admin', order: 20, title: 'Mi sesión' },
  'b89-dlp': { category: 'admin', order: 25, title: 'DLP en equipos' },
  'endpoint-groups': { category: 'admin', order: 30, title: 'Grupos de agentes' },
  // Plataforma (avanzado): servidor Wazuh, SIEM y dashboard
  'server-status': { category: 'platform', order: 40, title: 'Estado del servidor Wazuh' },
  statistics: { category: 'platform', order: 50, title: 'Estadísticas del servidor Wazuh' },
  logs: { category: 'platform', order: 60, title: 'Registros del servidor Wazuh' },
  settings: { category: 'platform', order: 70, title: 'Configuración del servidor Wazuh' },
  'dashboards-settings': { category: 'platform', order: 75, title: 'Ajustes del dashboard' },
  'app-settings': { category: 'platform', order: 80, title: 'Ajustes de la app Wazuh' },
  'server-apis': { category: 'platform', order: 90, title: 'Conexión API del servidor Wazuh' },
  'dev-tools': { category: 'platform', order: 100, title: 'Consola API del servidor Wazuh' },
  security: { category: 'platform', order: 110, title: 'Roles del servidor Wazuh' },
  opensearch_index_management_dashboards: {
    category: 'platform',
    order: 120,
    title: 'Índices del SIEM',
  },
  opensearch_snapshot_management_dashboards: {
    category: 'platform',
    order: 130,
    title: 'Copias del SIEM (instantáneas)',
  },
  dev_tools: { category: 'platform', order: 140, title: 'Consola del SIEM' },
  management: { category: 'platform', order: 160, title: 'Administración del dashboard' },
};

/**
 * Apps ocultas del menú, con el motivo (también en la auditoría de docs/08):
 * servicios que este despliegue no tiene o duplicados de vistas B89.
 */
export const NAV_HIDDEN: Readonly<Record<string, string>> = {
  'amazon-web-services':
    'El módulo filtra rule.groups: amazon y el receptor B89 usa aws (siempre vacío): el menú abre el panel B89 de AWS.',
  'google-cloud': 'Sin integración de Google Cloud en este despliegue.',
  github: 'Sin integración de GitHub (la de código es Snyk).',
  'microsoft-graph-api':
    'Microsoft 365 entra por el módulo office365; el módulo Graph de Wazuh no está configurado.',
  cluster: 'Manager de un solo nodo: no hay clúster que mostrar.',
  alerting: 'Los avisos los emite B89 (notificaciones y P1); los monitores de OSD no se usan.',
  'anomaly-detection-dashboards': 'Sin detectores de anomalías configurados en el Indexer.',
  'maps-dashboards': 'Sin capas geográficas propias; duplicaba Paneles.',
  'notifications-dashboards':
    'Canales de OSD no usados; las notificaciones del SOC están en «Notificaciones» (B89).',
  'sample-data': 'Datos de ejemplo: no se cargan en un SOC real.',
  about: 'Versión del SIEM visible en «Ajustes de la app Wazuh».',
  'observability-logs': 'Observability de OSD no se usa.',
  'observability-notebooks': 'Observability de OSD no se usa.',
  'observability-dashboards': 'Observability de OSD no se usa.',
  'observability-traces': 'Observability de OSD no se usa.',
  'observability-metrics': 'Observability de OSD no se usa.',
  'search-relevance': 'Herramienta de relevancia de búsqueda: no aplica a un SOC.',
  'query-workbench': 'Usar «Explorar eventos» o «Búsqueda de amenazas».',
  'opensearch-query-workbench': 'Usar «Explorar eventos» o «Búsqueda de amenazas».',
};
