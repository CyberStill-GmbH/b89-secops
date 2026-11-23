/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { SourceHealth, SourceVerdictView } from '../../common';
import { sortVerdicts, summarizeVerdicts } from '../../common';
import {
  processingCount,
  ProcessingSummary,
  SourceVerdicts,
  SubscriptionActivity,
} from './sources_view';

describe('actividad medida de las fuentes', () => {
  it('distingue una actividad aún no medida', () => {
    const markup = renderToStaticMarkup(<SubscriptionActivity subscriptions={null} />);

    expect(markup).toContain('aún no hay una medición disponible');
    expect(markup).not.toContain('Eventos');
  });

  it('muestra cuándo se midió, aunque un flujo tenga cero eventos', () => {
    const subscriptions: NonNullable<SourceHealth['subscriptions']> = {
      measuredAt: '2026-11-11T15:00:00.000Z',
      windowHours: 24,
      items: [{ stream: 'Audit.Exchange', lastEventAt: null, eventsInWindow: 0 }],
    };
    const markup = renderToStaticMarkup(<SubscriptionActivity subscriptions={subscriptions} />);

    expect(markup).toContain('Medida');
    expect(markup).toContain('2026-11-11T15:00:00.000Z');
    expect(markup).toContain('Audit.Exchange');
    expect(markup).toContain('0');
    expect(markup).not.toContain('aún no hay una medición disponible');
  });
});

describe('desglose del procesamiento de fuentes', () => {
  it('distingue un sondeo sin historial de las métricas históricas desconocidas', () => {
    const empty = renderToStaticMarkup(<ProcessingSummary processing={null} />);
    expect(empty).toContain('Aún no hay un sondeo registrado');

    const historical: NonNullable<SourceHealth['processing']> = {
      attemptedAt: '2026-11-11T15:00:00.000Z',
      completedAt: '2026-11-11T15:00:01.000Z',
      outcome: 'success',
      recordsSeen: 2,
      normalized: null,
      quarantined: 0,
      promoted: 1,
      duplicates: null,
      notPromoted: null,
      belowThreshold: null,
      suppressed: null,
      errorClass: null,
    };
    const markup = renderToStaticMarkup(<ProcessingSummary processing={historical} />);
    expect(markup).toContain('Documentos devueltos');
    expect(markup).toContain('no la actividad total de la fuente');
    expect(processingCount(historical.duplicates)).toBe('Sin desglose histórico');
    expect(processingCount(historical.notPromoted)).toBe('Sin desglose histórico');
    expect(processingCount(0)).toBe('0');
  });
});

function verdict(
  id: string,
  label: string,
  value: SourceVerdictView['verdict'],
  reasons: string[] = [],
): SourceVerdictView {
  return {
    id,
    label,
    provider: id,
    verdict: value,
    reasons,
    lastHeartbeatAt: null,
    lastSuccessfulRunAt: null,
    lastAuthOkAt: null,
    lastEventAt: null,
    canaryAt: null,
    heartbeat: null,
    providerLagSeconds: null,
    ingestLag: null,
    volume: null,
    expectedHeartbeatMs: null,
    measuredAt: null,
  };
}

describe('salud por fuente: la respuesta primero', () => {
  const verdicts = [
    verdict('snyk', 'Snyk', 'healthy', ['HEARTBEAT_OK']),
    verdict('aws', 'AWS', 'degraded', ['HEARTBEAT_MISSING']),
    verdict('m365', 'Microsoft 365', 'quiet', ['NO_RECENT_EVENTS']),
    verdict('bitdefender', 'Bitdefender', 'failing', ['AUTH_EXPIRED']),
    verdict('cloudflare', 'Cloudflare', 'unknown', ['HEARTBEAT_NEVER_SEEN']),
  ];

  it('ordena por gravedad y resume cuántas funcionan y por qué fallan las demás', () => {
    expect(sortVerdicts(verdicts).map((item) => item.id)).toEqual([
      'bitdefender',
      'aws',
      'cloudflare',
      'm365',
      'snyk',
    ]);
    const summary = summarizeVerdicts(verdicts);
    expect(summary.headline).toBe(
      '2 de 5 fuentes funcionan. 2 tienen problemas. 1 no se pudo comprobar.',
    );
    expect(summary.tone).toBe('fail');
    expect(summary.details[0]).toBe('Bitdefender: credencial vencida');
    expect(summarizeVerdicts([verdicts[0]]).headline).toBe('La fuente funciona.');
  });

  it('muestra primero la respuesta y las fuentes con problemas, y pliega las que funcionan', () => {
    const markup = renderToStaticMarkup(<SourceVerdicts verdicts={verdicts} model={null} />);
    const answer = markup.indexOf('2 de 5 fuentes funcionan');
    const failing = markup.indexOf('Bitdefender');
    const folded = markup.indexOf('Ver las 2 fuentes que funcionan');
    expect(answer).toBeGreaterThan(-1);
    expect(failing).toBeGreaterThan(answer);
    expect(folded).toBeGreaterThan(failing);
    expect(markup.indexOf('>Snyk<')).toBeGreaterThan(folded);
    expect(markup).toContain('Caída');
    expect(markup).not.toContain('Sin información');
  });

  it('explica qué hacer cuando no hay medición por fuente', () => {
    const markup = renderToStaticMarkup(<SourceVerdicts verdicts={[]} model={null} />);
    expect(markup).toContain('Pulsa Actualizar');
    expect(markup).not.toContain('versión anterior');
  });
});
