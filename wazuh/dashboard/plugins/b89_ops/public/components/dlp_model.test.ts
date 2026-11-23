/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { B89ApiError } from '../api/client';
import type { B89ApiClient } from '../api/client';
import type { DlpEndpoint } from '../api/dlp';
import {
  checkEnrollment,
  describeDiff,
  DLP_RULES,
  endpointHealth,
  installCommand,
  minutesLeft,
  missingInstallFields,
  nextVersion,
  parseFingerprints,
  policyDiff,
  rolloutProgress,
  sortEndpoints,
  summarizeFleet,
  wizardReducer,
} from './dlp_model';
import type { WizardState } from './dlp_model';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function endpoint(partial: Partial<DlpEndpoint> & { id: string }): DlpEndpoint {
  return {
    hostname: partial.id.toUpperCase(),
    agentId: 'a1',
    status: 'current',
    lastSeenAt: '2026-11-22T15:00:00.000Z',
    currentRevision: 3,
    currentPolicyVersion: '1.2.0',
    ...partial,
  };
}

describe('catálogo de reglas', () => {
  it('coincide con DLP_RULE_IDS de la API y del agente, en el mismo orden', () => {
    expect(DLP_RULES.map((rule) => rule.id)).toEqual([
      'B89_CRED_PRIVATE_KEY_PEM',
      'B89_CRED_GITHUB_TOKEN',
      'B89_CRED_SLACK_TOKEN',
      'B89_CRED_GOOGLE_API_KEY',
      'B89_CRED_AZURE_STORAGE_KEY',
      'B89_CRED_OPENAI_API_KEY',
      'B89_CRED_AWS_ACCESS_KEY_PAIR',
      'B89_SECRET_DATABASE_CONNECTION',
      'B89_SECRET_CREDENTIAL_ASSIGNMENT',
      'B89_PII_PERU_DNI_CONTEXTUAL',
      'B89_PII_PERU_RUC_CONTEXTUAL',
    ]);
    expect(DLP_RULES.filter((rule) => !rule.advanced)).toHaveLength(6);
  });

  it('nombra las marcas tal cual y en español', () => {
    const labels = DLP_RULES.map((rule) => rule.label).join(' | ');
    expect(labels).toContain('Tokens de GitHub');
    expect(labels).toContain('Tokens de Slack');
    expect(labels).not.toMatch(/holgura|Accede a|Principales/iu);
  });
});

describe('huellas y versión', () => {
  it('normaliza, quita duplicados y señala líneas inválidas', () => {
    const parsed = parseFingerprints(`# catálogo\n${HASH_A.toUpperCase()}\n${HASH_A}\nno-es-hash\n\n${HASH_B}`);
    expect(parsed.values).toEqual([HASH_A, HASH_B]);
    expect(parsed.invalid).toEqual([4]);
  });

  it('sube la versión menor', () => {
    expect(nextVersion('1.4.2')).toBe('1.5.0');
    expect(nextVersion('raro')).toBe('1.0.0');
  });
});

describe('cambios sin guardar', () => {
  it('dice qué reglas se activan o desactivan y cuántos documentos cambian', () => {
    const diff = policyDiff(
      { enabledRuleIds: ['B89_CRED_GITHUB_TOKEN', 'B89_CRED_SLACK_TOKEN'], fingerprintsSha256: [HASH_A] },
      ['B89_CRED_GITHUB_TOKEN', 'B89_PII_PERU_DNI_CONTEXTUAL'],
      [HASH_B],
    );
    expect(diff).toEqual({
      enabled: ['B89_PII_PERU_DNI_CONTEXTUAL'],
      disabled: ['B89_CRED_SLACK_TOKEN'],
      fingerprintsAdded: 1,
      fingerprintsRemoved: 1,
    });
    expect(describeDiff(diff)).toEqual([
      'Activa: Números de DNI',
      'Desactiva: Tokens de Slack',
      'Agrega 1 documento',
      'Quita 1 documento',
    ]);
  });
});

describe('estado de los equipos', () => {
  it('sin equipos lo dice en una línea', () => {
    expect(summarizeFleet([])).toMatchObject({ total: 0, headline: 'Ningún equipo conectado', tone: 'subdued' });
  });

  it('todo al día', () => {
    expect(summarizeFleet([endpoint({ id: 'a' }), endpoint({ id: 'b' })]).headline).toBe('Los 2 equipos están protegidos y al día');
    expect(summarizeFleet([endpoint({ id: 'a' })]).headline).toBe('El equipo está protegido y al día');
  });

  it('lo que necesita atención va primero y concuerda en número', () => {
    const fleet = [
      endpoint({ id: 'ok' }),
      endpoint({ id: 'off', status: 'offline' }),
      endpoint({ id: 'old', status: 're-enrollment-required' }),
      endpoint({ id: 'gone', status: 'revoked', revokedAt: '2026-11-20T00:00:00.000Z' }),
    ];
    const summary = summarizeFleet(fleet);
    expect(summary.total).toBe(3);
    expect(summary.headline).toBe('2 de 3 equipos necesitan atención');
    expect(summarizeFleet([endpoint({ id: 'a' }), endpoint({ id: 'b', status: 'offline' })]).headline).toBe(
      '1 de 2 equipos necesita atención',
    );
    expect(sortEndpoints(fleet).map((item) => item.id)).toEqual(['old', 'off', 'ok', 'gone']);
  });

  it('distingue «nunca se conectó» y no da por bueno un estado desconocido', () => {
    expect(endpointHealth(endpoint({ id: 'n', status: 'offline', lastSeenAt: null }))).toBe('never');
    expect(endpointHealth(endpoint({ id: 'x', status: 'nuevo' as unknown as DlpEndpoint['status'] }))).toBe('offline');
  });

  it('cuenta quién ya aplicó la revisión, sin los revocados', () => {
    const fleet = [
      endpoint({ id: 'a', currentRevision: 4 }),
      endpoint({ id: 'b', currentRevision: 3, status: 'updating' }),
      endpoint({ id: 'c', currentRevision: null, status: 'offline' }),
      endpoint({ id: 'd', currentRevision: 4, status: 'revoked' }),
    ];
    expect(rolloutProgress(fleet, 4)).toEqual({ applied: 1, total: 3 });
  });
});

describe('comando de instalación', () => {
  const base = { controlPlaneUrl: 'https://dev.security.b89.io/', wazuhManager: '', packageSha256: '' };

  it('Windows: listo para pegar con los valores citados y sin la clave', () => {
    const input = { ...base, os: 'windows' as const, watchRoot: "C:\\Datos\\O'Brien", wazuhManager: 'wazuh.b89.io', packageSha256: HASH_A.toUpperCase() };
    const command = installCommand(input);
    expect(command).toBe(
      `.\\install-windows-endpoint.ps1 -FerrispectorPackage .\\Ferrispector-Windows-x64.zip -ExpectedPackageSha256 ${HASH_A} -WazuhManager 'wazuh.b89.io' -WatchRoot 'C:\\Datos\\O''Brien' -DlpControlPlaneUrl 'https://dev.security.b89.io'`,
    );
    expect(missingInstallFields(input)).toEqual([]);
  });

  it('macOS o Linux: cita la carpeta para el shell', () => {
    const command = installCommand({ ...base, os: 'unix', watchRoot: "/Users/ana/Mis docs'" });
    expect(command).toBe(
      `sudo ./install-unix-endpoint.sh install --watch-root '/Users/ana/Mis docs'"'"'' --control-plane-url 'https://dev.security.b89.io'`,
    );
  });

  it('avisa lo que falta para que funcione tal cual', () => {
    expect(missingInstallFields({ ...base, os: 'windows', watchRoot: '' })).toEqual([
      'la carpeta',
      'el servidor Wazuh',
      'el SHA-256 del paquete',
    ]);
    expect(missingInstallFields({ ...base, os: 'unix', watchRoot: '/datos' })).toEqual([]);
  });
});

describe('asistente de conexión', () => {
  const token = { id: '11111111-1111-4111-8111-111111111111', token: 't'.repeat(43), expiresAt: '2026-11-22T15:30:00.000Z' };

  it('recorre crear → esperar → conectado', () => {
    let state: WizardState = { step: 'closed' };
    state = wizardReducer(state, { type: 'open' });
    expect(state).toMatchObject({ step: 'create', busy: false });
    state = wizardReducer(state, { type: 'creating' });
    expect(state).toMatchObject({ step: 'create', busy: true });
    state = wizardReducer(state, { type: 'created', token });
    expect(state).toEqual({ step: 'waiting', token });
    state = wizardReducer(state, { type: 'status', status: { state: 'waiting' } });
    state = wizardReducer(state, { type: 'status', status: { state: 'unknown' } });
    expect(state.step).toBe('waiting');
    state = wizardReducer(state, { type: 'status', status: { state: 'connected', hostname: 'PC-01', endpointId: token.id } });
    expect(state).toEqual({ step: 'connected', hostname: 'PC-01', endpointId: token.id });
  });

  it('vence sola al pasar la hora y no se reabre encima de una espera', () => {
    const waiting: WizardState = { step: 'waiting', token };
    expect(wizardReducer(waiting, { type: 'open' })).toBe(waiting);
    expect(wizardReducer(waiting, { type: 'tick', now: Date.parse(token.expiresAt) - 1 })).toBe(waiting);
    expect(wizardReducer(waiting, { type: 'tick', now: Date.parse(token.expiresAt) })).toEqual({ step: 'expired' });
    expect(minutesLeft(token.expiresAt, Date.parse('2026-11-22T15:01:30.000Z'))).toBe(29);
  });

  it('pedir reautenticación no es un error genérico', () => {
    const state = wizardReducer({ step: 'create', busy: true, error: null, stepUp: false }, {
      type: 'createFailed',
      error: new B89ApiError('STEP_UP_REQUIRED', 403, null),
    });
    expect(state).toEqual({ step: 'create', busy: false, error: null, stepUp: true });
  });

  it('consulta el estado de la clave y traduce las respuestas', async () => {
    const reply = (value: unknown) => ({ get: async () => value }) as unknown as B89ApiClient;
    const fail = (error: unknown) => ({ get: async () => { throw error; } }) as unknown as B89ApiClient;
    expect(await checkEnrollment(reply({ id: token.id, state: 'waiting', expiresAt: token.expiresAt, endpoint: null }), token.id)).toEqual({ state: 'waiting' });
    expect(
      await checkEnrollment(
        reply({ id: token.id, state: 'connected', expiresAt: token.expiresAt, endpoint: { id: token.id, hostname: 'PC-01', enrolledAt: token.expiresAt, lastSeenAt: null } }),
        token.id,
      ),
    ).toEqual({ state: 'connected', hostname: 'PC-01', endpointId: token.id });
    expect(await checkEnrollment(reply({ id: token.id, state: 'expired', expiresAt: token.expiresAt, endpoint: null }), token.id)).toEqual({ state: 'expired' });
    expect(await checkEnrollment(fail(new B89ApiError('RESOURCE_UNAVAILABLE', 404, null)), token.id)).toEqual({ state: 'expired' });
    expect(await checkEnrollment(fail(new TypeError('red caída')), token.id)).toEqual({ state: 'unknown' });
  });
});
