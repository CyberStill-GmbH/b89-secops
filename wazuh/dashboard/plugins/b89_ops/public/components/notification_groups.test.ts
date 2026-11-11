/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { NotificationAttempt } from '../../common';
import {
  deliveryLines,
  groupNotifications,
  latestByChannel,
  maskEntity,
} from './notification_groups';
import { webhookProblem } from './notification_groups';

const base: NotificationAttempt = {
  id: 'n1',
  status: 'sent',
  channel: 'teams',
  attemptCount: 1,
  sentAt: '2026-11-10T10:00:00Z',
  acknowledgedAt: null,
  acknowledgedBy: null,
  lastFailureClass: null,
};

describe('bandeja de notificaciones', () => {
  it('agrupa los avisos repetidos de la misma alerta', () => {
    const groups = groupNotifications([
      { ...base, id: 'a', alertId: 'x' },
      { ...base, id: 'b', alertId: 'x', sentAt: '2026-11-10T11:00:00Z' },
      { ...base, id: 'c', incidentId: 'i1' },
      { ...base, id: 'd' },
    ]);
    expect(groups.map((g) => [g.key, g.items.length])).toEqual([
      ['alert:x', 2],
      ['incident:i1', 1],
      ['attempt:d', 1],
    ]);
    expect(groups[0].latest.id).toBe('b');
  });

  it('entrega por intento: enviado, fallido con motivo y reconocido por quién', () => {
    expect(deliveryLines(base).map((l) => l.kind)).toEqual(['sent']);
    expect(
      deliveryLines({ ...base, status: 'failed', lastFailureClass: 'TRANSPORT_TIMEOUT' })[0],
    ).toMatchObject({ kind: 'failed', reason: 'TRANSPORT_TIMEOUT' });
    const acked = deliveryLines({
      ...base,
      status: 'acknowledged',
      acknowledgedAt: '2026-11-10T10:05:00Z',
      acknowledgedBy: 'lider@b89.io',
    });
    expect(acked.map((l) => l.kind)).toEqual(['sent', 'acknowledged']);
    expect(acked[1].actor).toBe('lider@b89.io');
  });

  it('usa el historial de la API cuando llega y su enlace a Teams', () => {
    const lines = latestByChannel([
      {
        ...base,
        deliveries: [
          { attempt: 1, channel: 'teams', outcome: 'sent', at: '2026-11-10T10:00:00Z' },
          {
            attempt: 1,
            channel: 'teams',
            outcome: 'delivered',
            at: '2026-11-10T10:00:05Z',
            link: 'https://teams.microsoft.com/l/message/x',
          },
        ],
      },
    ]);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      kind: 'delivered',
      link: 'https://teams.microsoft.com/l/message/x',
    });
  });

  it('enmascara entidades en claro', () => {
    expect(maskEntity('isabel.saravia@b89.io')).toBe('is***@b89.io');
    expect(maskEntity('18.214.220.109')).toBe('18.214.x.x');
    expect(maskEntity(null)).toBeNull();
  });

  it('valida el webhook de Teams (Workflows) sin aceptar conectores retirados', () => {
    expect(
      webhookProblem(
        'https://prod-00.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=xyz',
      ),
    ).toBeNull();
    expect(webhookProblem('http://x.logic.azure.com/workflows/a')).toMatch(/https/);
    expect(webhookProblem('https://b89.webhook.office.com/webhookb2/x')).toMatch(/Workflows/);
    expect(webhookProblem('https://evil.example.com/hook')).toMatch(/host/);
    expect(webhookProblem('')).toMatch(/Pega/);
  });
});
