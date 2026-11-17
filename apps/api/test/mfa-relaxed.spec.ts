import { describe, expect, it } from 'vitest';

import { mfaRelaxedFrom } from '../src/bootstrap.js';
import { relaxedMfaAdmits } from '../src/runtime/secops-runtime.js';

const AT = new Date('2026-11-17T12:00:00Z');
const base = {
  demo: false,
  denialReason: 'MFA_REQUIRED',
  tokenValid: true,
  notLocked: true,
  capabilities: 3,
  until: new Date('2026-12-31T00:00:00Z'),
  at: AT,
};

describe('MFA relajado temporal para Entra real', () => {
  it('admite a una identidad autorizada cuyo token no trae amr de MFA, dentro de la ventana', () => {
    expect(relaxedMfaAdmits(base)).toBe(true);
    expect(relaxedMfaAdmits({ ...base, denialReason: 'PASSKEY_REQUIRED' })).toBe(true);
  });

  it('nunca admite sin rol, con token inválido, bloqueado, demo u otra denegación', () => {
    expect(relaxedMfaAdmits({ ...base, capabilities: 0 })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, tokenValid: false })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, notLocked: false })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, demo: true })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, denialReason: 'NO_ROLE_ASSIGNED' })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, denialReason: 'NETWORK_UNTRUSTED' })).toBe(false);
  });

  it('respeta la ventana: vencida, ausente o a más de 90 días no relaja nada', () => {
    expect(relaxedMfaAdmits({ ...base, until: new Date('2026-11-17T11:59:59Z') })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, until: undefined })).toBe(false);
    expect(relaxedMfaAdmits({ ...base, until: new Date('2027-03-01T00:00:00Z') })).toBe(false);
  });

  it('lee la variable de entorno y rechaza fechas inválidas', () => {
    expect(mfaRelaxedFrom({})).toEqual({});
    expect(mfaRelaxedFrom({ B89_ENTRA_MFA_RELAXED_UNTIL: '2026-12-31' }).mfaRelaxedUntil?.toISOString()).toBe(
      '2026-12-31T00:00:00.000Z',
    );
    expect(() => mfaRelaxedFrom({ B89_ENTRA_MFA_RELAXED_UNTIL: 'mañana' })).toThrow(/CONFIG_VALUE_INVALID/u);
  });
});
