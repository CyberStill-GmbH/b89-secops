import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AlertGuidePanel } from './alert_guide_panel';
import { AlertQueueTitle } from './alerts_view';

const REASONS = [{ code: 'BASE_SEVERITY', detail: 'Severidad normalizada high (origen 12).' }];

function order(html: string, marks: readonly string[]): number[] {
  return marks.map((mark) => html.indexOf(mark));
}

describe('Por qué saltó (detalle de la alerta)', () => {
  it('con guía: por qué saltó, qué significa, cómo confirmarlo y qué hacer; lo técnico plegado', () => {
    const html = renderToStaticMarkup(
      <AlertGuidePanel title="B89 Cloudflare: … (wazuh 102009)" reasons={REASONS} priority="P2" score={71} />,
    );
    const positions = order(html, ['Por qué saltó', 'Qué significa', '¿Es real?', 'Qué hacer', '<details']);
    expect(positions.every((index) => index >= 0)).toBe(true);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
    expect(html).toContain('Es P2 porque la regla la marca como grave.');
    // Los códigos del motor y la regla solo dentro del detalle técnico.
    expect(html.indexOf('BASE_SEVERITY')).toBeGreaterThan(html.indexOf('<details'));
    expect(html.indexOf('102009')).toBeGreaterThan(html.indexOf('<details'));
    expect(html).toContain('puntuación de prioridad 71');
  });

  it('sin guía también explica por qué saltó y qué hacer, sin jerga arriba', () => {
    const html = renderToStaticMarkup(
      <AlertGuidePanel
        title="B89 Snyk: dependencia con vulnerabilidad crítica (wazuh 101451)"
        reasons={REASONS}
        entities={[{ ref: null, kind: 'host', label: 'api-pagos' }]}
        priority="P2"
        framed={false}
      />,
    );
    const top = html.slice(0, html.indexOf('<details'));
    expect(top).toContain('Por qué saltó');
    expect(top).toContain('Dependencia con vulnerabilidad crítica (equipo api-pagos). Lo detectó Snyk.');
    expect(top).toContain('Qué hacer');
    expect(top).toContain('Abre «Investigar» y revisa qué más pasó con el equipo api-pagos');
    expect(top).not.toMatch(/BASE_SEVERITY|origen 12|wazuh 101451|\bhigh\b/u);
    expect(html).not.toContain('Por qué tiene esta prioridad');
  });
});

describe('fila de la cola', () => {
  it('título limpio como botón y, debajo, por qué saltó en una línea', () => {
    const html = renderToStaticMarkup(
      <AlertQueueTitle
        basePath=""
        onOpen={() => undefined}
        alert={{
          id: 'a1',
          title: 'B89 Microsoft 365: inicio de sesión desde un país inusual (wazuh 100231)',
          priority: 'P2',
          entities: [{ ref: null, kind: 'user', label: 'ana@b89.io' }],
          reasons: [{ code: 'REPEATED_ACTIVITY', detail: '5 eventos equivalentes en la ventana reciente.' }],
        }}
      />,
    );
    expect(html).toMatch(/<button type="button" class="b89LinkButton"[^>]*>Inicio de sesión desde un país inusual<\/button>/u);
    expect(html).toContain('Por qué saltó: </span>usuario ana@b89.io · se repitió 5 veces');
    expect(html).not.toContain('wazuh 100231');
    expect(html).not.toContain('B89 Microsoft 365:');
  });
});
