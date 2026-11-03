/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { PluginConfigDescriptor, PluginInitializerContext } from '../../../src/core/server';
import { configSchema } from './config';
import type { ConfigSchema } from './config';
import { B89OpsServerPlugin } from './plugin';

export const config: PluginConfigDescriptor<ConfigSchema> = {
  schema: configSchema,
  exposeToBrowser: {
    apiPrefix: true,
    p1Watch: true,
  },
};

export function plugin(initializerContext: PluginInitializerContext) {
  return new B89OpsServerPlugin(initializerContext);
}
