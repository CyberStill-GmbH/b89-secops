/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { INTEGRATIONS } from '../../common/integrations';
import type { ServiceModel } from './service_cards';
import { orderServices, ServicesSection } from './overview_view';

function model(id: string, tone: ServiceModel['status']['tone'], critical24h?: number): ServiceModel {
  const spec = INTEGRATIONS.find((item) => item.id === id)!;
  return {
    spec,
    status: { tone, label: tone === 'ok' ? 'Funciona' : tone === 'fail' ? 'Caída' : 'Con problemas', detail: null },
    metrics: [],
    lastEventAt: undefined,
    events24h: null,
    loading: false,
    critical24h,
  };
}

describe('Servicios en el inicio', () => {
  const models = [
    model('wazuh', 'ok', 3),
    model('cloudflare', 'warn', 0),
    model('aws', 'fail', 1),
    model('snyk', 'ok', 0),
  ];

  it('muestra TODOS los servicios, también los que funcionan', () => {
    const html = renderToStaticMarkup(<ServicesSection models={models} basePath="/b" />);
    for (const item of models) expect(html).toContain(`aria-label="${item.spec.name}"`);
    expect(html).toContain('Servicios integrados');
  });

  it('los que necesitan atención primero; con igual estado, más eventos críticos primero', () => {
    expect(orderServices(models).map((item) => item.spec.id)).toEqual(['aws', 'cloudflare', 'wazuh', 'snyk']);
  });

  it('cada tarjeta dice sus eventos críticos de 24 h y enlaza a verlos', () => {
    const html = renderToStaticMarkup(<ServicesSection models={models} basePath="/b" />);
    expect(html).toContain('3 eventos críticos en 24 h →');
    expect(html).toContain('1 evento crítico en 24 h →');
    expect(html).toContain('Sin eventos críticos en 24 h');
    expect(html).toMatch(/class="b89Service__critical"[^>]*href="\/b\/app\/data-explorer\/discover/u);
  });
});
