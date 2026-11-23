/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { BunnyComposer } from './bunny_composer_view';
import { citationKindLabel, finishedAnnouncement, reportNoteBody } from './bunny_text';
import { renderMarkdown } from './markdown';

const ID = '3f9a1c2e-5b7d-4e8f-9a0b-1c2d3e4f5a6b';

describe('Bunny: lector de pantalla y textos', () => {
  it('anuncia el final una sola vez, con el comienzo de la respuesta y sin marcas de formato', () => {
    expect(finishedAnnouncement('**Hallazgo**: la IP `1.2.3.4` es maliciosa.')).toBe(
      'Respuesta de Bunny lista: Hallazgo : la IP 1.2.3.4 es maliciosa.',
    );
    const long = finishedAnnouncement('x'.repeat(500));
    expect(long.length).toBeLessThan(240);
    expect(long.endsWith('…')).toBe(true);
    expect(finishedAnnouncement('')).toBe('Respuesta de Bunny lista.');
  });

  it('la nota para el incidente lleva tipos en español y fecha legible, no ISO', () => {
    const body = reportNoteBody(
      {
        text: 'Resumen del análisis.',
        citations: [
          { kind: 'alert', id: 'a-1', label: 'Acceso raro' },
          { kind: 'incident', id: 'i-2', label: 'Campaña' },
        ],
      },
      new Date('2026-11-15T15:00:00.000Z'),
    );
    expect(body).toContain('- Alerta: Acceso raro (ID a-1)');
    expect(body).toContain('- Incidente: Campaña (ID i-2)');
    expect(body).not.toContain('2026-11-15T15:00:00.000Z');
    expect(body).toContain('2026');
    expect(citationKindLabel('event')).toBe('Evento');
  });

  it('un id citado se enlaza con su nombre; uno sin citar queda como código sin enlace', () => {
    const cited = renderToStaticMarkup(
      <>
        {renderMarkdown(`Ver ${ID}.`, {
          citations: [{ kind: 'incident', id: ID, label: 'Campaña de phishing' }],
          onOpen: () => undefined,
        })}
      </>,
    );
    expect(cited).toContain('aria-label="Abrir incidente: Campaña de phishing"');
    expect(cited).toContain('Campaña de phishing</a>');
    const loose = renderToStaticMarkup(<>{renderMarkdown(`Ver ${ID}.`, { onOpen: () => undefined })}</>);
    expect(loose).not.toContain('<a');
    expect(loose).toContain(`<code class="b89Bunny__id" title="${ID}">${ID}</code>`);
  });

  it('el cuadro de texto muestra el contador cerca del límite y un «Detener respuesta» coherente', () => {
    const props = {
      pending: false,
      maxChars: 4000,
      name: 'Bunny',
      context: null,
      inputRef: { current: null },
      onDraft: () => undefined,
      onSend: () => undefined,
      onStop: () => undefined,
    };
    expect(renderToStaticMarkup(<BunnyComposer {...props} draft="hola" />)).not.toContain('/ 4');
    const near = renderToStaticMarkup(<BunnyComposer {...props} draft={'x'.repeat(3950)} />);
    expect(near).toContain('/ 4');
    expect(near).toContain('3');
    const busy = renderToStaticMarkup(<BunnyComposer {...props} pending draft="" />);
    expect(busy).toContain('aria-label="Detener respuesta"');
    expect(busy).toContain('title="Detener respuesta"');
  });
});
