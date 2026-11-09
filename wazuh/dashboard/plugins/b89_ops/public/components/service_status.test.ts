/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { emptyLevels, IntegrationsConfig, OverviewResponse, ProviderStats } from '../../common';
import { providerStatus, wazuhStatus } from './service_status';

const AUTO = { state: 'auto' as const, missingPermissions: [], note: '' };
const NOW = Date.parse('2026-11-04T16:00:00Z');

function stats(lastEventAt: string | null): ProviderStats {
  return { events24h: 1, lastEventAt, levels24h: emptyLevels(), metrics: {} };
}

function overview(patch: Partial<OverviewResponse> = {}): OverviewResponse {
  const integrations = {
    wazuh: AUTO,
    office365: {
      state: 'blocked',
      missingPermissions: ['ActivityFeed.Read'],
      note: 'Pedir consentimiento',
    },
    sharepoint: { state: 'disabled', missingPermissions: [], note: 'Permisos pendientes de validar.' },
    bitdefender: AUTO,
    snyk: AUTO,
    cloudflare: AUTO,
    aws: { state: 'disabled', missingPermissions: [], note: '' },
    respond: AUTO,
    bunny: AUTO,
    alertMail: AUTO,
  } as IntegrationsConfig;
  return {
    generatedAt: new Date(NOW).toISOString(),
    alertsAccess: 'ok',
    monitoringAccess: 'ok',
    siem: null,
    providers: {
      office365: stats(null),
      sharepoint: stats(null),
      bitdefender: stats('2026-11-04T15:50:00Z'),
      snyk: stats('2026-10-30T10:00:00Z'),
      cloudflare: stats('2026-11-02T10:00:00Z'),
      aws: stats(null),
    },
    topEvents: [],
    agents: { total: 1, active: 1, disconnected: 0, other: 0, groups: {}, measuredAt: null },
    integrations,
    ...patch,
  };
}

describe('estado de servicios', () => {
  it('lo declarado manda: permiso faltante, servicio no configurado', () => {
    expect(providerStatus('office365', overview(), NOW)).toEqual({
      tone: 'warn',
      label: 'Requiere ActivityFeed.Read',
      detail: 'Pedir consentimiento',
    });
    expect(providerStatus('aws', overview(), NOW).label).toBe('No configurada');
  });

  it('lo medido: reciente, callado según el ritmo del proveedor', () => {
    expect(providerStatus('bitdefender', overview(), NOW).tone).toBe('ok');
    // Snyk solo emite por cambio: 5 días sin eventos sigue siendo normal.
    expect(providerStatus('snyk', overview(), NOW).tone).toBe('ok');
    expect(providerStatus('cloudflare', overview(), NOW)).toMatchObject({
      tone: 'warn',
      label: 'Sin eventos recientes',
    });
  });

  it('sin permiso de lectura no se presenta como caída', () => {
    expect(providerStatus('snyk', overview({ alertsAccess: 'forbidden' }), NOW)).toMatchObject({
      tone: 'neutral',
      label: 'Sin permiso de lectura',
    });
  });

  it('Wazuh: agentes desconectados degradan; todo activo es operativo', () => {
    expect(wazuhStatus(overview(), null).label).toBe('Operativo');
    expect(
      wazuhStatus(
        overview({
          agents: { total: 3, active: 2, disconnected: 1, other: 0, groups: {}, measuredAt: null },
        }),
        null,
      ),
    ).toMatchObject({ tone: 'warn', label: 'Agentes desconectados' });
  });
});
