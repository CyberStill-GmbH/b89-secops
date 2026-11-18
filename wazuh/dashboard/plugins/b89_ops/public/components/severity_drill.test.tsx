/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TopEvent } from '../../common';
import {
  alertsQueueHref,
  PRIORITY_NAME,
  priorityFromParam,
  searchWithPriority,
} from './alerts_filters';
import { PriorityFilter, PriorityFilterNotice } from './alerts_view';
import { LevelLegend, PlatformData, SeverityBar } from './overview_parts';
import { KpiRow } from './overview_view';
import {
  attentionQuery,
  levelBandHref,
  levelBandQuery,
  ServiceAttentionList,
} from './service_attention';
import { severityMetrics } from './service_cards';

const levels = { low: 5, medium: 100, high: 20, critical: 3 };
const decode = (href: string) => decodeURIComponent(href);
const attr = (value: string) => decode(value.replace(/&amp;/g, '&').replace(/&#x27;/g, "'"));

describe('cola de alertas filtrada por prioridad', () => {
  it('construye el enlace de cada prioridad y lo lee de la URL', () => {
    expect(alertsQueueHref('/base', 'P1')).toBe('/base/app/b89-alerts?priority=P1');
    expect(alertsQueueHref('/base')).toBe('/base/app/b89-alerts');
    expect(priorityFromParam('P2')).toBe('P2');
    expect(priorityFromParam(' p1 ')).toBe('P1');
    expect(priorityFromParam('P9')).toBe('');
    expect(priorityFromParam(null)).toBe('');
  });

  it('cambia el filtro en la URL sin perder el resto de parámetros', () => {
    expect(searchWithPriority('?id=a1&priority=P1', 'P3')).toBe('?id=a1&priority=P3');
    expect(searchWithPriority('?priority=P1', '')).toBe('');
    expect(searchWithPriority('', 'P2')).toBe('?priority=P2');
  });

  it('muestra el filtro activo con «Quitar filtro», y nada sin filtro', () => {
    const html = renderToStaticMarkup(
      <PriorityFilterNotice priority="P1" onChange={() => undefined} total={4} />,
    );
    expect(html).toContain('Mostrando solo');
    expect(html).toContain('Crítica');
    expect(html).toContain('4 alertas');
    expect(html).toContain('Quitar filtro');
    expect(
      renderToStaticMarkup(<PriorityFilterNotice priority="" onChange={() => undefined} />),
    ).toBe('');
    const select = renderToStaticMarkup(
      <PriorityFilter priority="P1" onChange={() => undefined} />,
    );
    expect(select).toContain('P1 · Crítica');
    expect(select).toMatch(/<option value="P1" selected/);
  });

  it('cada chip P1–P3 de «Alertas abiertas» abre la cola filtrada por esa prioridad', () => {
    const data = {
      overview: { data: null, loading: false, error: null, reload: () => undefined },
    } as unknown as PlatformData;
    const html = renderToStaticMarkup(
      <KpiRow
        data={data}
        queue={{
          open: 9,
          byPriority: { P1: 2, P2: 3, P3: 4, P4: 0 },
          top: [],
          activeIncidents: 0,
        }}
        queueLoading={false}
        basePath="/base"
      />,
    );
    for (const priority of ['P1', 'P2', 'P3'] as const) {
      expect(html).toContain(`href="/base/app/b89-alerts?priority=${priority}"`);
      expect(html).toContain(PRIORITY_NAME[priority]);
    }
    expect(html).not.toContain('priority=P4');
    // Sin enlaces anidados: la tarjeta «Alertas abiertas» ya no es un <a> que envuelve los chips.
    expect(html.startsWith('<div class="b89KpiRow"><div class="b89Kpi">')).toBe(true);
  });
});

describe('bandas de severidad', () => {
  it('cada banda filtra exactamente su rango de rule.level', () => {
    expect(levelBandQuery('critical')).toBe('rule.level >= 12');
    expect(levelBandQuery('high')).toBe('rule.level >= 8 and rule.level <= 11');
    expect(levelBandQuery('medium')).toBe('rule.level >= 4 and rule.level <= 7');
    expect(levelBandQuery('low')).toBe('rule.level <= 3');
    expect(levelBandQuery('critical', 'aws')).toBe(attentionQuery('aws', true));
    const href = decode(levelBandHref('/base', 'high', 'cloudflare'));
    expect(href).toContain('/base/app/data-explorer/discover');
    expect(href).toContain('rule.level >= 8 and rule.level <= 11 and rule.groups: "cloudflare"');
    expect(href).toContain('now-24h');
  });

  it('los segmentos de la barra y la leyenda enlazan a solo su banda', () => {
    const hrefFor = (band: 'low' | 'medium' | 'high' | 'critical') => `#${band}`;
    const bar = renderToStaticMarkup(
      <SeverityBar levels={levels} label="Eventos" hrefFor={hrefFor} />,
    );
    expect(bar).toContain('href="#critical"');
    expect(bar).toContain('Ver solo 3 críticas');
    const legend = renderToStaticMarkup(<LevelLegend levels={levels} hrefFor={hrefFor} />);
    expect(legend).toMatch(/href="#critical"[^>]*>.*?3<\/strong> críticas →/);
    expect(legend).toMatch(/href="#high"[^>]*>.*?20<\/strong> altas →/);
    // Sin enlaces, la barra sigue siendo una imagen accesible.
    expect(renderToStaticMarkup(<SeverityBar levels={levels} label="x" />)).toContain('role="img"');
  });

  it('«Eventos SIEM · 24 h» ofrece críticas y altas por separado', () => {
    const data = {
      overview: {
        data: {
          siem: {
            levels24h: levels,
            total24h: 128,
            agentsWithAlerts24h: 1,
            trend24h: [],
            trend7d: [],
          },
          agents: null,
        },
        loading: false,
        error: null,
        reload: () => undefined,
      },
    } as unknown as PlatformData;
    const html = renderToStaticMarkup(
      <KpiRow data={data} queue={null} queueLoading={false} basePath="/base" />,
    );
    const critical = /<a class="b89Legend__link" href="([^"]+)" data-band="critical"/.exec(html);
    const high = /<a class="b89Legend__link" href="([^"]+)" data-band="high"/.exec(html);
    expect(attr(critical![1])).toContain("query:'rule.level >= 12'");
    expect(attr(high![1])).toContain("query:'rule.level >= 8 and rule.level <= 11'");
    expect(html).toContain('críticas →');
    expect(html).toContain('altas →');
    expect(html).not.toContain('altas o críticas');
  });
});

describe('tarjetas de servicio', () => {
  it('«Críticas» y «Altas y críticas» cuentan y filtran cosas distintas', () => {
    const [critical, highAndCritical] = severityMetrics('aws', levels);
    expect(critical.label).toBe('Críticas 24 h');
    expect(critical.value).toBe('3');
    expect(critical.focus).toBe('critical');
    expect(critical.drill?.kql).toBe('rule.level >= 12 and rule.groups: "aws"');
    expect(highAndCritical.value).toBe('23');
    expect(highAndCritical.focus).toBe('all');
    expect(highAndCritical.drill?.kql).toBe('rule.level >= 8 and rule.groups: "aws"');
  });

  const events: TopEvent[] = [
    {
      id: 'c1',
      level: 13,
      description: 'Crítico',
      agent: 'a',
      ruleId: '1',
      at: '',
      provider: 'aws',
    },
    { id: 'h1', level: 9, description: 'Alto', agent: 'b', ruleId: '2', at: '', provider: 'aws' },
  ];

  it('tras pulsar «Críticas» la lista muestra solo críticas y el filtro es visible', () => {
    const html = renderToStaticMarkup(
      <ServiceAttentionList
        service="aws"
        name="AWS"
        basePath=""
        data={{ access: 'ok', total: 2, events }}
        focus={{ band: 'critical', seq: 1 }}
        criticalTotal={1}
      />,
    );
    expect(html).toContain('data-filter="critical"');
    expect(html).toMatch(/<input type="checkbox" checked=""/);
    expect(html).toContain('Mostrando solo críticas (nivel ≥ 12)');
    expect(html).toContain('Quitar filtro');
    expect(html).toContain('1 críticas en 24 h');
    expect(html).toContain('Crítico');
    expect(html).not.toContain('Alto<');
  });

  it('sin foco muestra altas y críticas sin aviso de filtro', () => {
    const html = renderToStaticMarkup(
      <ServiceAttentionList
        service="aws"
        name="AWS"
        basePath=""
        data={{ access: 'ok', total: 2, events }}
      />,
    );
    expect(html).toContain('Mostrando altas y críticas (nivel ≥ 8)');
    expect(html).not.toContain('Quitar filtro');
    expect(html).toContain('Alto<');
  });
});
