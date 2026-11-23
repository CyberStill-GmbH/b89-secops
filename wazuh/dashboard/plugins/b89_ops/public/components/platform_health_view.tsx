/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiBasicTable, EuiCallOut, EuiLoadingContent, EuiSpacer, EuiTitle } from '@elastic/eui';
import {
  currentSourceState,
  HealthTone,
  PLATFORM_HEALTH_DOC,
  PLATFORM_SOURCE_LABEL,
  PLATFORM_STATE_LABEL,
  PLATFORM_STATE_TONE,
  PlatformProblem,
  PlatformSourceHealth,
  PlatformSourceState,
} from '../../common';
import { fetchOverview } from '../api/overview';
import { DataZone, EmptyLine, ErrorCallout, HealthMark, Mono, Timestamp, useAsync } from './primitives';

const SEVERITY_TONE: Record<PlatformProblem['severity'], HealthTone> = {
  critical: 'fail',
  warning: 'warn',
  info: 'info',
};

const SEVERITY_LABEL: Record<PlatformProblem['severity'], string> = {
  critical: 'Crítico',
  warning: 'Aviso',
  info: 'Informativo',
};

/** Primero lo que necesita acción: caída, sin eventos, sin comprobar, desactivada, funciona. */
const STATE_ORDER: Record<PlatformSourceState, number> = {
  failing: 0,
  silent: 1,
  unknown: 2,
  disabled: 3,
  ok: 4,
};

export function sortPlatformSources(items: readonly PlatformSourceHealth[]): PlatformSourceHealth[] {
  return [...items].sort(
    (a, b) =>
      STATE_ORDER[a.state] - STATE_ORDER[b.state] ||
      (PLATFORM_SOURCE_LABEL[a.source] ?? a.source).localeCompare(
        PLATFORM_SOURCE_LABEL[b.source] ?? b.source,
        'es',
      ),
  );
}

/**
 * «Monitor de plataforma»: último `source_status` por fuente y problemas abiertos del monitor B89
 * (docs/20). Lee el SIEM con la identidad de quien mira (ruta del resumen). Va dentro de
 * «Salud de fuentes», en el detalle técnico: la página tiene un solo botón «Actualizar»
 * (`refreshKey`).
 */
export function PlatformHealthSection({
  basePath,
  refreshKey = 0,
}: {
  basePath: string;
  refreshKey?: number;
}) {
  const overview = useAsync(() => fetchOverview(basePath), [basePath, refreshKey]);
  const health = overview.data?.platformHealth ?? null;
  const now = Date.now();
  const sources = health
    ? sortPlatformSources(
        Object.keys(health.sources).map((source) => currentSourceState(health, source, now)!),
      )
    : [];

  return (
    <section className="b89TechSection" aria-labelledby="b89-platform-monitor-title">
      <EuiTitle size="xs">
        <h3 id="b89-platform-monitor-title">Monitor de plataforma</h3>
      </EuiTitle>
      <p className="b89Muted">
        Estado que publica el monitor de B89 por cada fuente y colector, y los problemas que siguen
        abiertos. Un estado de más de 2 h se muestra como «Sin comprobar».{' '}
        <a href={PLATFORM_HEALTH_DOC} target="_blank" rel="noopener noreferrer">
          Cómo funciona el monitor
        </a>
      </p>
      <EuiSpacer size="s" />
      {overview.error ? (
        <ErrorCallout error={overview.error} onRetry={overview.reload} />
      ) : overview.loading && !overview.data ? (
        <EuiLoadingContent lines={3} />
      ) : !health ? (
        <EmptyLine>No llegaron datos del monitor. Recarga la página.</EmptyLine>
      ) : health.access !== 'ok' ? (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="lock"
          title={
            health.access === 'forbidden'
              ? 'Tu rol no incluye la salud de la plataforma. Pídela a un Administrador de plataforma.'
              : 'El SIEM no respondió a la consulta del monitor. Pulsa Actualizar en unos minutos.'
          }
        />
      ) : sources.length === 0 ? (
        <EmptyLine>
          El monitor de plataforma no publicó estados en las últimas 24 h. Avisa a plataforma para
          que revise el servicio de monitoreo.
        </EmptyLine>
      ) : (
        <DataZone>
          <ul className="b89PlatformSources">
            {sources.map((item) => (
              <li key={item.source} className="b89PlatformSource" data-state={item.state}>
                <span className="b89PlatformSource__name">
                  {PLATFORM_SOURCE_LABEL[item.source] ?? item.source}
                </span>
                <HealthMark
                  tone={PLATFORM_STATE_TONE[item.state]}
                  label={PLATFORM_STATE_LABEL[item.state]}
                />
                <span className="b89PlatformSource__time">
                  <Timestamp iso={item.at || null} />
                </span>
                {item.summary && item.state !== 'ok' && (
                  <span className="b89PlatformSource__summary">{item.summary}</span>
                )}
              </li>
            ))}
          </ul>
          <EuiSpacer size="l" />
          <EuiBasicTable<PlatformProblem>
            items={health.problems as PlatformProblem[]}
            tableCaption="Problemas abiertos del monitor de plataforma"
            noItemsMessage="Sin problemas abiertos: cada aviso del monitor ya se recuperó."
            responsive
            columns={[
              {
                field: 'severity',
                name: 'Severidad',
                width: '130px',
                render: (value: PlatformProblem['severity']) => (
                  <HealthMark tone={SEVERITY_TONE[value]} label={SEVERITY_LABEL[value]} />
                ),
              },
              {
                field: 'summary',
                name: 'Problema',
                render: (value: string, item: PlatformProblem) => (
                  <span className="b89CellTitle">
                    <span>{value || item.check}</span>
                    <span className="b89CellMeta">
                      {PLATFORM_SOURCE_LABEL[item.source] ?? item.source}
                      {item.value
                        ? ` · ${item.value}${item.unit ? ` ${item.unit}` : ''}${
                            item.threshold ? ` (umbral ${item.threshold})` : ''
                          }`
                        : ''}
                      {' · '}
                      <Mono title="Clave del problema en el monitor">{item.key || item.check}</Mono>
                    </span>
                  </span>
                ),
              },
              {
                field: 'since',
                name: 'Desde',
                width: '140px',
                render: (value: string | null, item: PlatformProblem) => (
                  <Timestamp iso={value || item.at || null} />
                ),
              },
            ]}
          />
        </DataZone>
      )}
    </section>
  );
}
