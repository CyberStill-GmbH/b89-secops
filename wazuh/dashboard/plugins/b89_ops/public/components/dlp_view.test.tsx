/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { DlpEndpoint, DlpPolicy } from '../api/dlp';
import { DLP_RULES, policyDiff, summarizeFleet } from './dlp_model';
import type { InstallInput } from './dlp_model';
import {
  ConnectWizard,
  EndpointList,
  FleetStatus,
  RolloutNotice,
  RulesPanel,
  SaveBar,
  StepUpNotice,
} from './dlp_view';

const noop = () => undefined;
const POLICY: DlpPolicy = {
  revision: 7,
  policyVersion: '1.6.0',
  enabledRuleIds: DLP_RULES.filter((rule) => !rule.advanced).map((rule) => rule.id),
  fingerprintsSha256: [],
  updatedAt: '2026-11-22T14:00:00.000Z',
};

function endpoint(partial: Partial<DlpEndpoint> & { id: string }): DlpEndpoint {
  return {
    hostname: partial.id,
    agentId: 'a1',
    status: 'current',
    lastSeenAt: '2026-11-22T15:00:00.000Z',
    currentRevision: 7,
    currentPolicyVersion: '1.6.0',
    ...partial,
  };
}

const INSTALL: InstallInput = {
  os: 'windows',
  controlPlaneUrl: 'https://dev.security.b89.io',
  watchRoot: '',
  wazuhManager: '',
  packageSha256: '',
};

describe('DLP · estado de los equipos primero', () => {
  it('responde si hay algo que atender, sin relleno', () => {
    const fleet = [endpoint({ id: 'PC-OK' }), endpoint({ id: 'PC-OFF', status: 'offline' })];
    const markup = renderToStaticMarkup(
      <FleetStatus summary={summarizeFleet(fleet)} policy={POLICY} endpointsError={null} stale={false} onRetry={noop} />,
    );
    expect(markup).toContain('1 de 2 equipos necesita atención');
    expect(markup).toContain('1 protegido');
    expect(markup).toContain('1 sin conexión');
    expect(markup).toContain('Política revisión 7');
    expect(markup).not.toContain('Versión 1.6.0');
    expect(markup).not.toContain('Sin dato');
    expect(markup).not.toContain('Reintentar');
  });

  it('estado desconocido cuando la lista no responde', () => {
    const markup = renderToStaticMarkup(
      <FleetStatus summary={null} policy={POLICY} endpointsError={new Error('x')} stale={false} onRetry={noop} />,
    );
    expect(markup).toContain('No se pudo consultar el estado de los equipos');
    expect(markup).toContain('Reintentar');
  });

  it('degradado: conserva los últimos datos y lo dice', () => {
    const markup = renderToStaticMarkup(
      <FleetStatus summary={summarizeFleet([endpoint({ id: 'A' })])} policy={POLICY} endpointsError={new Error('x')} stale onRetry={noop} />,
    );
    expect(markup).toContain('El equipo está protegido y al día');
    expect(markup).toContain('se muestran los últimos datos recibidos');
  });

  it('una política nunca guardada no muestra «revisión 0»', () => {
    const markup = renderToStaticMarkup(
      <FleetStatus summary={summarizeFleet([])} policy={{ ...POLICY, revision: 0, updatedAt: null }} endpointsError={null} stale={false} onRetry={noop} />,
    );
    expect(markup).toContain('Ningún equipo conectado');
    expect(markup).toContain('Política inicial del paquete');
    expect(markup).not.toContain('revisión 0');
  });
});

describe('DLP · lista de equipos', () => {
  it('vacía: una línea y el atajo para conectar el primero', () => {
    const markup = renderToStaticMarkup(<EndpointList endpoints={[]} policyRevision={7} canConfigure onRevoke={noop} onConnect={noop} />);
    expect(markup).toContain('Aún no hay equipos conectados.');
    expect(markup).toContain('Conectar el primero');
    expect(markup).not.toContain('<table');
  });

  it('lo que necesita atención arriba, con qué hacer; revocados plegados', () => {
    const markup = renderToStaticMarkup(
      <EndpointList
        endpoints={[
          endpoint({ id: 'A-OK' }),
          endpoint({ id: 'B-OLD', status: 're-enrollment-required' }),
          endpoint({ id: 'C-LAG', status: 'updating', currentRevision: 5 }),
          endpoint({ id: 'D-GONE', status: 'revoked' }),
        ]}
        policyRevision={7}
        canConfigure
        onRevoke={noop}
      />,
    );
    expect(markup.indexOf('B-OLD')).toBeLessThan(markup.indexOf('C-LAG'));
    expect(markup.indexOf('C-LAG')).toBeLessThan(markup.indexOf('A-OK'));
    expect(markup).toContain('Revoca este equipo y vuelve a conectarlo con una clave nueva.');
    expect(markup).toContain('Tiene la revisión 5; la vigente es 7.');
    expect(markup).toMatch(/<details[^>]*><summary>Revocados \(1\)<\/summary>/u);
    expect(markup).not.toContain('Conectar el primero');
  });

  it('un equipo sin conexión también se puede revocar (portátil perdido)', () => {
    const markup = renderToStaticMarkup(
      <EndpointList endpoints={[endpoint({ id: 'LOST', status: 'offline' })]} policyRevision={7} canConfigure onRevoke={noop} />,
    );
    expect(markup).toContain('aria-label="Revocar LOST"');
  });

  it('solo lectura: sin revocar ni conectar', () => {
    const markup = renderToStaticMarkup(
      <EndpointList endpoints={[endpoint({ id: 'A' })]} policyRevision={7} canConfigure={false} onRevoke={noop} />,
    );
    expect(markup).not.toContain('Revocar');
    const empty = renderToStaticMarkup(<EndpointList endpoints={[]} policyRevision={7} canConfigure={false} onRevoke={noop} />);
    expect(empty).not.toContain('Conectar');
  });
});

describe('DLP · qué detecta', () => {
  const render = (canConfigure: boolean, rules = POLICY.enabledRuleIds) =>
    renderToStaticMarkup(
      <RulesPanel
        rules={rules}
        fingerprintsText=""
        fingerprintError={null}
        canConfigure={canConfigure}
        onToggle={noop}
        onFingerprintsChange={noop}
        onImport={noop}
      />,
    );

  it('interruptores con nombres en español; el ID técnico no se ve', () => {
    const markup = render(true);
    expect(markup).toContain('Tokens de Slack');
    expect(markup).toContain('Tokens de GitHub');
    expect(markup).toContain('6 de 11 reglas');
    for (const rule of DLP_RULES) expect(markup).not.toContain(rule.id);
    expect(markup).not.toMatch(/holgura|Accede a|Reglas principales/iu);
  });

  it('avanzadas y huellas plegadas', () => {
    const markup = render(true);
    expect(markup).toContain('<summary>Reglas avanzadas · 0 de 5 activas</summary>');
    expect(markup).toContain('<summary>Documentos específicos · 0</summary>');
    expect(markup).not.toMatch(/<details[^>]*open/u);
    // Con una avanzada activa, su grupo se abre para que se vea.
    expect(render(true, [...POLICY.enabledRuleIds, 'B89_PII_PERU_DNI_CONTEXTUAL'])).toMatch(/<details[^>]*open=""[^>]*><summary>Reglas avanzadas · 1 de 5/u);
  });

  it('solo lectura: interruptores deshabilitados y sin importar', () => {
    const markup = render(false);
    expect(markup).toContain('disabled=""');
    expect(markup).not.toContain('Importar');
  });
});

describe('DLP · guardar', () => {
  const props = {
    saving: false,
    stepUp: false,
    conflict: false,
    logoutHref: '/app/b89/logout',
    onSave: noop,
    onDiscard: noop,
    onReload: noop,
    onDismissStepUp: noop,
  };

  it('no aparece sin cambios', () => {
    expect(renderToStaticMarkup(<SaveBar diff={policyDiff(POLICY, POLICY.enabledRuleIds, [])} {...props} />)).toBe('');
  });

  it('dice exactamente qué cambiará', () => {
    const diff = policyDiff(POLICY, POLICY.enabledRuleIds.filter((id) => id !== 'B89_CRED_SLACK_TOKEN'), ['a'.repeat(64)]);
    const markup = renderToStaticMarkup(<SaveBar diff={diff} {...props} />);
    expect(markup).toContain('Desactiva: Tokens de Slack');
    expect(markup).toContain('Agrega 1 documento');
    expect(markup).toContain('Guardar y enviar a los equipos');
    expect(markup).not.toContain('vuelve a iniciar sesión');
  });

  it('la reautenticación aparece solo tras intentar guardar', () => {
    const diff = policyDiff(POLICY, [], []);
    const markup = renderToStaticMarkup(<SaveBar diff={diff} {...props} stepUp />);
    expect(markup).toContain('Para guardar, vuelve a iniciar sesión');
    expect(markup).toContain('Cerrar sesión y volver a entrar');
  });

  it('conflicto: ofrece cargar la versión nueva', () => {
    const markup = renderToStaticMarkup(<SaveBar diff={policyDiff(POLICY, POLICY.enabledRuleIds, [])} {...props} conflict />);
    expect(markup).toContain('Alguien guardó otra versión');
    expect(markup).not.toContain('Guardar y enviar');
  });

  it('tras guardar: qué cambió y cuántos equipos ya aplicaron la revisión', () => {
    const progress = renderToStaticMarkup(
      <RolloutNotice revision={8} changes={['Desactiva: Tokens de Slack']} applied={1} total={3} onDismiss={noop} />,
    );
    expect(progress).toContain('Revisión 8 guardada · 1 de 3 equipos la aplicaron');
    expect(progress).toContain('Desactiva: Tokens de Slack');
    const done = renderToStaticMarkup(<RolloutNotice revision={8} changes={[]} applied={3} total={3} onDismiss={noop} />);
    expect(done).toContain('Revisión 8 aplicada en los 3 equipos');
    const none = renderToStaticMarkup(<RolloutNotice revision={8} changes={[]} applied={0} total={0} onDismiss={noop} />);
    expect(none).toContain('No hay equipos conectados que la reciban');
  });
});

describe('DLP · asistente de conexión', () => {
  const props = {
    install: INSTALL,
    now: Date.parse('2026-11-22T15:02:00.000Z'),
    logoutHref: '/app/b89/logout',
    onInstallChange: noop,
    onCreate: noop,
    onCancel: noop,
    onClose: noop,
  };
  const token = { id: '11111111-1111-4111-8111-111111111111', token: 'SECRETO_DE_PRUEBA_0123456789abcdefghijklmnop', expiresAt: '2026-11-22T15:30:00.000Z' };

  it('cerrado no ocupa espacio', () => {
    expect(renderToStaticMarkup(<ConnectWizard state={{ step: 'closed' }} {...props} />)).toBe('');
  });

  it('paso 1: crear la clave, en 3 pasos numerados', () => {
    const markup = renderToStaticMarkup(<ConnectWizard state={{ step: 'create', busy: false, error: null, stepUp: false }} {...props} />);
    expect(markup).toContain('Crear una clave');
    expect(markup).toContain('Instalar en el equipo');
    expect(markup).toContain('Esperar a que aparezca');
    expect(markup).toContain('aria-current="step"');
    expect(markup).toContain('vence en 30 minutos');
    expect(markup).not.toContain('vuelve a iniciar sesión');
  });

  it('paso 1 con step-up: el aviso aparece en el paso que lo pidió', () => {
    const markup = renderToStaticMarkup(<ConnectWizard state={{ step: 'create', busy: false, error: null, stepUp: true }} {...props} />);
    expect(markup).toContain('Para crear la clave, vuelve a iniciar sesión');
  });

  it('pasos 2 y 3: comando listo, clave aparte y espera automática', () => {
    const markup = renderToStaticMarkup(<ConnectWizard state={{ step: 'waiting', token }} {...props} />);
    expect(markup).toContain('install-windows-endpoint.ps1');
    expect(markup).toContain('https://dev.security.b89.io');
    expect(markup).toContain('Copiar comando');
    expect(markup).toContain('Copiar clave');
    expect(markup).toContain(token.token);
    // La clave no va en el comando: el instalador la pide en una entrada oculta.
    const command = /<pre[^>]*>([\s\S]*?)<\/pre>/u.exec(markup)?.[1] ?? '';
    expect(command).not.toContain(token.token);
    expect(markup).toContain('Falta la carpeta, el servidor Wazuh, el SHA-256 del paquete.');
    expect(markup).toContain('Esperando al equipo');
    expect(markup).toContain('La clave vence en 28 min.');
    expect(markup).toContain('Cancelar y anular la clave');
  });

  it('macOS o Linux solo pide la carpeta', () => {
    const markup = renderToStaticMarkup(
      <ConnectWizard state={{ step: 'waiting', token }} {...props} install={{ ...INSTALL, os: 'unix', watchRoot: '/datos' }} />,
    );
    expect(markup).toContain('sudo ./install-unix-endpoint.sh install');
    expect(markup).not.toContain('Servidor Wazuh');
    expect(markup).not.toContain('Falta');
  });

  it('conectado y vencido', () => {
    const connected = renderToStaticMarkup(<ConnectWizard state={{ step: 'connected', hostname: 'PC-01', endpointId: token.id }} {...props} />);
    expect(connected).toContain('PC-01 se conectó');
    expect(connected).toContain('Conectar otro equipo');
    const expired = renderToStaticMarkup(<ConnectWizard state={{ step: 'expired' }} {...props} />);
    expect(expired).toContain('La clave venció');
    expect(expired).toContain('Crear otra clave');
  });
});

describe('DLP · reautenticación', () => {
  it('lleva a cerrar sesión y permite posponer', () => {
    const markup = renderToStaticMarkup(<StepUpNotice action="revocar un equipo" logoutHref="/b89/logout" onDismiss={noop} />);
    expect(markup).toContain('Para revocar un equipo, vuelve a iniciar sesión');
    expect(markup).toContain('Ahora no');
  });
});
