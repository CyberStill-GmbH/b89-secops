/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { schema, TypeOf } from '@osd/config-schema';

/**
 * `b89_ops.*` en `opensearch_dashboards.yml`.
 *
 * El dashboard no tiene login propio: confía en la sesión de B89 SecOps (BFF con
 * Microsoft Entra ID y admisión por el grupo Accesos_SOC). El proxy de borde valida esa
 * sesión con `GET {apiPrefix}/auth/introspect` y la entrega al Security plugin como
 * *proxy auth* (ver b89-secops-unified/wazuh/edge/b89-edge.conf).
 */
export const configSchema = schema.object({
  enabled: schema.boolean({ defaultValue: true }),
  /**
   * Prefijo público de la API de B89 en el mismo origen que el dashboard. El navegador
   * llama a la API directamente (cookie `b89_session` + `x-csrf-token`), sin CORS.
   */
  apiPrefix: schema.string({
    defaultValue: '/api',
    validate: (value: string) =>
      /^\/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$/u.test(value) && !value.includes('//')
        ? undefined
        : 'apiPrefix debe ser una ruta absoluta del mismo origen, sin barra final',
  }),
  /** Aviso de nuevas alertas P1 en la cabecera (todo el dashboard). */
  p1Watch: schema.boolean({ defaultValue: true }),
  login: schema.object({
    /** Sirve el login B89 y sustituye `/app/login` del Security plugin / Wazuh. */
    enabled: schema.boolean({ defaultValue: true }),
    /** Destino tras iniciar sesión cuando no hay `nextUrl`. */
    defaultNextUrl: schema.string({ defaultValue: '/app/b89-alerts' }),
    /** Muestra el formulario de usuario y contraseña junto al acceso con Entra. */
    passwordEnabled: schema.boolean({ defaultValue: true }),
    /** Texto de la barra superior del login («Estás iniciando sesión en …»). */
    destinationLabel: schema.string({ defaultValue: 'B89' }),
  }),
});

export type ConfigSchema = TypeOf<typeof configSchema>;
export type PublicConfigSchema = Pick<ConfigSchema, 'apiPrefix' | 'p1Watch'>;
