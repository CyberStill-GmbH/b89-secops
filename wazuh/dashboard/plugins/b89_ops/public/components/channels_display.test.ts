/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */

import type { NotificationChannelView } from '../../common';
import { channelDestinationSummary } from './channels_display';

const channel = (overrides: Partial<NotificationChannelView>): NotificationChannelView => ({
  id: 'teams',
  enabled: true,
  configured: true,
  state: 'active',
  target: null,
  lastDelivery: null,
  ...overrides,
});

describe('resumen seguro del destino de cada canal', () => {
  it('no muestra la URL completa aunque el API devuelva el webhook sin enmascarar', () => {
    const webhook = 'https://contoso.logic.azure.com/workflows/secret-token/triggers/manual';

    const summary = channelDestinationSummary(channel({ target: webhook }));

    expect(summary).toBe('Webhook configurado · URL protegida');
    expect(summary).not.toContain('contoso');
    expect(summary).not.toContain('secret-token');
  });

  it('distingue un canal de correo pendiente de configurar', () => {
    expect(
      channelDestinationSummary(
        channel({ id: 'fallback_email', configured: false, target: null, state: 'unconfigured' }),
      ),
    ).toBe('Sin configurar');
  });

  it('describe la bandeja de B89 sin ofrecer la dirección interna', () => {
    expect(
      channelDestinationSummary(
        channel({ id: 'manual_console', target: 'b89-internal://notification-inbox' }),
      ),
    ).toBe('Bandeja interna de B89');
  });
});
