/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */

import type { NotificationChannelView } from '../../common';

/** Summarizes destinations without rendering values that could contain a webhook secret. */
export function channelDestinationSummary(channel: NotificationChannelView): string {
  if (channel.id === 'manual_console') return 'Bandeja interna de B89';
  if (!channel.configured) return 'Sin configurar';
  if (channel.id === 'teams') return 'Webhook configurado · URL protegida';
  return 'Buzón del SOC configurado · dirección protegida';
}
