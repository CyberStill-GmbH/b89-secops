/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { PluginInitializerContext } from '../../../src/core/public';
import type { PublicConfigSchema } from '../config';
import './theme.scss';
import './index.scss';
import './bunny/bunny.scss';
import './overview.scss';
import './investigation.scss';
import './investigation_activity_groups.scss';
import './ai_analyst.scss';
import './cloudflare_traffic.scss';
import './allowlist.scss';
import './alerts.scss';
import { B89OpsPublicPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext<PublicConfigSchema>) {
  return new B89OpsPublicPlugin(initializerContext);
}
