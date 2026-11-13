/**
 * Política de ruido de avisos (`B89_NOTIFY_*`). Regresión 2026-11-13: el loader las leía pero no
 * estaban en KNOWN_B89_VARIABLES, así que definir cualquiera tumbaba el arranque del API.
 */

import { describe, expect, it } from 'vitest';

import { loadNotificationPolicy } from '../src/index.js';
import { rejectUnknownB89Variables } from '../src/schema/environment.schema.js';

const ALL = {
  B89_NOTIFY_QUIET_P1_MINUTES: '30',
  B89_NOTIFY_QUIET_P2_MINUTES: '120',
  B89_NOTIFY_STALE_MINUTES: '60',
  B89_NOTIFY_MAX_PER_HOUR: '12',
  B89_NOTIFY_DIGEST_MINUTES: '0',
  B89_NOTIFY_TIME_ZONE: 'America/Lima',
};

describe('B89_NOTIFY_*', () => {
  it('son variables conocidas', () => {
    expect(() => rejectUnknownB89Variables(ALL)).not.toThrow();
  });

  it('el resumen P3/P4 se apaga con 0', () => {
    expect(loadNotificationPolicy({ B89_PROFILE: 'production', B89_NOTIFY_DIGEST_MINUTES: '0' })).toMatchObject({
      digestMinutes: 0,
    });
  });
});
