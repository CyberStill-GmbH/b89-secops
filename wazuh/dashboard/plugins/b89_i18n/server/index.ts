/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 *
 * `b89_i18n.*` en opensearch_dashboards.yml. `b89_i18n.enabled: false` desactiva el
 * plugin completo (OSD no lo carga); además se expone al navegador por claridad.
 */

import { schema, TypeOf } from '@osd/config-schema';

export const configSchema = schema.object({
  enabled: schema.boolean({ defaultValue: true }),
});

export type B89I18nConfig = TypeOf<typeof configSchema>;

export const config = {
  schema: configSchema,
  exposeToBrowser: { enabled: true },
};

class B89I18nServerPlugin {
  public setup() {
    return {};
  }
  public start() {
    return {};
  }
  public stop() {}
}

export function plugin() {
  return new B89I18nServerPlugin();
}
