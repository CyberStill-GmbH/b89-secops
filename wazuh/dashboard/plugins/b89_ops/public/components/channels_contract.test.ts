/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */

import { describe, expect, it } from 'vitest';
import {
  channelTestSuccessLabel,
  normalizeChannelTest,
  normalizeChannelsResponse,
} from './channels_contract';

describe('normalizeChannelsResponse', () => {
  it('uses the latest failed run and shows its failure reason', () => {
    const response = normalizeChannelsResponse({
      channels: [
        {
          id: 'teams',
          enabled: true,
          configured: true,
          health: {
            lastSuccessAt: '2026-11-12T10:00:00Z',
            lastFailureAt: '2026-11-12T11:00:00Z',
            lastFailureReason: 'HTTP 503',
          },
        },
      ],
    });

    expect(response.channels[0].lastDelivery).toEqual({
      ok: false,
      at: '2026-11-12T11:00:00Z',
      reason: 'HTTP 503',
    });
  });

  it('uses the latest successful run and omits the stale failure reason', () => {
    const response = normalizeChannelsResponse({
      channels: [
        {
          id: 'teams',
          enabled: true,
          configured: true,
          health: {
            lastSuccessAt: '2026-11-12T11:00:00Z',
            lastFailureAt: '2026-11-12T10:00:00Z',
            lastFailureReason: 'HTTP 503',
          },
        },
      ],
    });

    expect(response.channels[0].lastDelivery).toEqual({
      ok: true,
      at: '2026-11-12T11:00:00Z',
    });
  });
});

describe('normalizeChannelTest', () => {
  it('marks HTTP 202 as provider acceptance, not delivery', () => {
    const result = normalizeChannelTest({
      result: { ok: true, at: '2026-11-12T11:00:00Z', httpStatus: 202 },
    });
    expect(result).toEqual({
      ok: true,
      accepted: true,
      at: '2026-11-12T11:00:00Z',
    });
    expect(channelTestSuccessLabel(result)).toBe('Prueba aceptada por el proveedor');
    expect(channelTestSuccessLabel({ ...result, accepted: false })).toBe('Prueba correcta');
  });
});
