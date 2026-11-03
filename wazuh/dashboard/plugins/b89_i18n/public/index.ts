/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { B89I18nInitializerContext, B89I18nPlugin } from './plugin';

export function plugin(initializerContext: B89I18nInitializerContext) {
  return new B89I18nPlugin(initializerContext);
}
