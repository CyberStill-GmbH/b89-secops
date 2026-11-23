/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  EuiBasicTable,
  EuiButtonEmpty,
  EuiDescriptionList,
  EuiFlexGrid,
  EuiFlexItem,
  EuiLoadingContent,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  CAPABILITIES,
  parseVerdicts,
  SOURCE_REASON_LABEL,
  SOURCE_STATE_LABEL,
  SOURCE_TONE,
  SOURCE_VERDICT_LABEL,
  SOURCE_VERDICT_TONE,
  SourceHealth,
  SourceHealthModelInfo,
  SourceVerdictView,
  sortVerdicts,
  summarizeVerdicts,
  verdictNeedsAttention,
  verdictReasonLabel,
} from '../../common';
import { B89Page, useChanges, useConsole } from './console_context';
import { OperationsView } from './operations_view';
import { PlatformHealthSection } from './platform_health_view';
import { EmptyLine, ErrorCallout, HealthMark, Mono, Timestamp, useAsync } from './primitives';

/** Streams medidos por la API: suscripciones de Office 365 y proveedores por grupo de regla. */
const STREAM_LABEL: Readonly<Record<string, string>> = {
  'Audit.AzureActiveDirectory': 'Entra ID',
  'Audit.Exchange': 'Exchange',
  'Audit.SharePoint': 'SharePoint',
  'Audit.General': 'Microsoft 365 General',
  'provider.bitdefender': 'Bitdefender GravityZone',
  'provider.snyk': 'Snyk',
  'provider.cloudflare': 'Cloudflare',
  'provider.aws': 'AWS',
};

function minutes(ms: number): string {
  const value = Math.round(ms / 60000);
  return value === 1 ? '1 min' : `${value} min`;
}

function lag(value: number | null): string {
  if (value === null) return 'Sin muestra';
  if (value < 1_000) return `${value} ms`;
  return `${(value / 1_000).toFixed(1)} s`;
}

/**
 * «Salud de fuentes»: la respuesta primero («X de Y fuentes funcionan; estas fallan y por qué»),
 * las fuentes con problemas abiertas y ordenadas por gravedad, las que funcionan plegadas, y el
 * detalle técnico (historial por conexión, monitor de plataforma y salud operativa) al final,
 * plegado. Un solo botón «Actualizar» recarga todo (`refreshKey`).
 */
export function SourcesView({ basePath = '' }: { basePath?: string }) {
  const { can } = useConsole();
  if (!can(CAPABILITIES.sourcesRead)) {
    return (
      <B89Page title="Salud de fuentes">
        <EmptyLine>
          Tu rol no incluye la salud de las fuentes. Pídela a un Administrador de plataforma si la
          necesitas.
        </EmptyLine>
      </B89Page>
    );
  }
  return <SourcesContent basePath={basePath} />;
}

function SourcesContent({ basePath }: { basePath: string }) {
  const { api } = useConsole();
  const [refreshKey, setRefreshKey] = useState(0);
  const health = useAsync(
    () =>
      api.get<{
        checkedAt: string;
        sources: SourceHealth[];
        verdicts?: unknown;
        healthModel?: SourceHealthModelInfo;
      }>('/sources/health'),
    [api, refreshKey],
  );
  useChanges(['source'], () => health.reload());
  const refresh = () => setRefreshKey((value) => value + 1);

  return (
    <B89Page
      title="Salud de fuentes"
      description="¿Llegan los datos de cada fuente? Lo que falla aparece primero."
      actions={
        <span className="b89SourcesActions">
          {health.data && (
            <span className="b89Muted">
              Actualizado <Timestamp iso={health.data.checkedAt} />
            </span>
          )}
          <EuiButtonEmpty size="s" iconType="refresh" onClick={refresh} isLoading={health.loading}>
            Actualizar
          </EuiButtonEmpty>
        </span>
      }
    >
      <div lang="es-PE" translate="no">
        {health.error != null && <ErrorCallout error={health.error} onRetry={refresh} />}
        {health.loading && !health.data && health.error == null && (
          <EuiLoadingContent lines={4} />
        )}
        {health.data && (
          <>
            <SourceVerdicts
              verdicts={parseVerdicts(health.data.verdicts)}
              model={health.data.healthModel ?? null}
            />
            <EuiSpacer size="l" />
            <p className="b89Muted">
              Para conectar una fuente o revisar sus permisos, ve a{' '}
              <a href={`${basePath}/app/b89-integrations`}>Integraciones</a>.
            </p>
          </>
        )}
        <EuiSpacer size="l" />
        <details className="b89Guide__details">
          <summary>Detalle técnico de la plataforma</summary>
          <EuiSpacer size="s" />
          {health.data && (
            <section aria-labelledby="b89-source-history-title" className="b89TechSection">
              <EuiTitle size="xs">
                <h3 id="b89-source-history-title">Historial de cada conexión</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {health.data.sources.length === 0 ? (
                <EmptyLine>No hay conexiones configuradas para esta organización.</EmptyLine>
              ) : (
                <EuiFlexGrid columns={2} gutterSize="m" responsive>
                  {health.data.sources.map((source) => (
                    <EuiFlexItem key={`${source.sourceId}:${source.dataset}`}>
                      <SourceCard source={source} />
                    </EuiFlexItem>
                  ))}
                </EuiFlexGrid>
              )}
            </section>
          )}
          <EuiSpacer size="l" />
          <PlatformHealthSection basePath={basePath} refreshKey={refreshKey} />
          <EuiSpacer size="l" />
          <OperationsView embedded refreshKey={refreshKey} />
        </details>
      </div>
    </B89Page>
  );
}

type SubscriptionItem = NonNullable<SourceHealth['subscriptions']>['items'][number];

function seconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return 'Sin dato';
  if (value < 60) return `${Math.round(value)} s`;
  if (value < 3600) return `${Math.round(value / 60)} min`;
  return `${(value / 3600).toFixed(1)} h`;
}

/** Volumen de la ventana actual contra la mediana de la misma hora de semanas anteriores. */
export function volumeText(volume: SourceVerdictView['volume']): string {
  if (!volume) return 'Sin dato';
  const window = `${volume.current} en ${volume.windowHours} h`;
  if (volume.expected === null) {
    return `${window} · esperado: Sin dato (${volume.weeksUsed} semana${
      volume.weeksUsed === 1 ? '' : 's'
    } con datos)`;
  }
  return `${window} · esperado ≈ ${Math.round(volume.expected)} (mediana de ${
    volume.weeksUsed
  } semanas)${volume.drop ? ' · por debajo de lo esperado' : ''}`;
}

export function ingestLagText(lag: SourceVerdictView['ingestLag']): string {
  if (!lag || lag.maxSeconds === null) return 'Sin dato';
  return `p50 ${seconds(lag.p50Seconds)} · máx ${seconds(lag.maxSeconds)} · ${lag.samples} muestra${
    lag.samples === 1 ? '' : 's'
  }`;
}

/** Salud por fuente: la respuesta, las fuentes con problemas abiertas y las que funcionan plegadas. */
export function SourceVerdicts({
  verdicts,
  model,
}: {
  verdicts: readonly SourceVerdictView[];
  model: SourceHealthModelInfo | null;
}) {
  const summary = summarizeVerdicts(verdicts);
  const sorted = sortVerdicts(verdicts);
  const attention = sorted.filter((item) => verdictNeedsAttention(item.verdict));
  const working = sorted.filter((item) => !verdictNeedsAttention(item.verdict));
  return (
    <section aria-labelledby="b89-source-verdicts-title">
      <EuiTitle size="xs">
        <h2 id="b89-source-verdicts-title">Salud por fuente</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      {verdicts.length === 0 ? (
        <EmptyLine>
          No se pudo medir la salud por fuente. Pulsa Actualizar; si persiste, avisa a plataforma.
        </EmptyLine>
      ) : (
        <>
          <div className="b89SourcesAnswer" data-tone={summary.tone}>
            <p className="b89SourcesAnswer__headline">
              <HealthMark tone={summary.tone} label={summary.headline} />
            </p>
            {summary.details.length > 0 && (
              <ul className="b89List" aria-label="Fuentes que necesitan atención">
                {summary.details.map((detail) => (
                  <li key={detail}>{detail}</li>
                ))}
              </ul>
            )}
            {model?.stale && (
              <p className="b89Muted">
                Esta medición es de <Timestamp iso={model.measuredAt} />: B89 no pudo consultar el
                SIEM en la última comprobación.
              </p>
            )}
          </div>
          <EuiSpacer size="m" />
          {attention.length > 0 && (
            <EuiFlexGrid columns={3} gutterSize="m" responsive>
              {attention.map((item) => (
                <EuiFlexItem key={item.id}>
                  <SourceVerdictCard item={item} />
                </EuiFlexItem>
              ))}
            </EuiFlexGrid>
          )}
          {working.length > 0 && (
            <>
              <EuiSpacer size="m" />
              <details className="b89Guide__details">
                <summary>
                  {working.length === 1
                    ? 'Ver la fuente que funciona'
                    : `Ver las ${working.length} fuentes que funcionan`}
                </summary>
                <EuiSpacer size="s" />
                <p className="b89Muted">
                  «Sin eventos (normal)» significa que la conexión funciona pero no hubo eventos
                  nuevos en el periodo revisado.
                </p>
                <EuiSpacer size="s" />
                <EuiFlexGrid columns={3} gutterSize="m" responsive>
                  {working.map((item) => (
                    <EuiFlexItem key={item.id}>
                      <SourceVerdictCard item={item} />
                    </EuiFlexItem>
                  ))}
                </EuiFlexGrid>
              </details>
            </>
          )}
        </>
      )}
    </section>
  );
}

export function SourceVerdictCard({ item }: { item: SourceVerdictView }) {
  const verdict = SOURCE_VERDICT_LABEL[item.verdict];
  const firstReason = item.reasons[0] ? verdictReasonLabel(item.reasons[0]) : null;
  const summary =
    item.verdict === 'healthy'
      ? 'La última comprobación confirma que los datos están llegando.'
      : item.verdict === 'quiet'
        ? 'La conexión funciona; no hubo eventos nuevos en el periodo revisado.'
        : item.verdict === 'degraded'
          ? `Los datos llegan, pero con un problema${firstReason ? `: ${firstReason}.` : '.'}`
          : item.verdict === 'failing'
            ? `No se puede confirmar que lleguen datos${firstReason ? `: ${firstReason}.` : '.'}`
            : 'B89 todavía no pudo comprobar si los datos están llegando.';
  const titleId = `b89-source-${item.id}`;
  return (
    <section aria-labelledby={titleId}>
      <EuiPanel hasBorder paddingSize="m" className="b89SourceCard" data-verdict={item.verdict}>
        <EuiTitle size="xxs">
          <h3 id={titleId}>{item.label}</h3>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <HealthMark tone={SOURCE_VERDICT_TONE[item.verdict]} label={verdict} />
        <p>{summary}</p>
        <EuiSpacer size="s" />
        <details className="b89Guide__details">
          <summary>Ver comprobaciones y tiempos</summary>
          <EuiSpacer size="s" />
          {item.reasons.length > 0 && (
            <ul className="b89List" aria-label="Motivos detectados">
              {item.reasons.map((reason) => (
                <li key={reason}>{verdictReasonLabel(reason)}</li>
              ))}
            </ul>
          )}
          <EuiDescriptionList
            type="responsiveColumn"
            compressed
            className="b89Facts"
            listItems={verdictSignalItems(item)}
          />
        </details>
      </EuiPanel>
    </section>
  );
}

/** Línea de tiempo de señales de una fuente; cada señal sin dato dice «Sin dato». */
export function verdictSignalItems(
  item: SourceVerdictView,
): { title: string; description: NonNullable<React.ReactNode> }[] {
  const run = item.heartbeat;
  return [
          {
            title: 'Último reporte del colector',
            description:
              item.expectedHeartbeatMs === null && item.id !== 'wazuh-indexer' ? (
                <span className="b89Muted">No aplica (sin colector propio)</span>
              ) : (
                <Timestamp iso={item.lastHeartbeatAt} />
              ),
          },
          { title: 'Última lectura correcta', description: <Timestamp iso={item.lastSuccessfulRunAt} /> },
          { title: 'Última autenticación correcta', description: <Timestamp iso={item.lastAuthOkAt} /> },
          { title: 'Último evento', description: <Timestamp iso={item.lastEventAt} /> },
          { title: 'Volumen vs lo esperado', description: volumeText(item.volume) },
          { title: 'Retraso hasta el SIEM', description: ingestLagText(item.ingestLag) },
          { title: 'Atraso del proveedor', description: seconds(item.providerLagSeconds) },
          { title: 'Evento de prueba automático', description: <Timestamp iso={item.canaryAt} /> },
          {
            title: 'Última lectura',
            description: run ? (
              <span>
                <Mono>{`${run.outcome ?? '?'} · auth ${run.auth ?? '?'} · HTTP ${
                  run.httpStatusClass ?? '?'
                }`}</Mono>
                {run.errorCode ? (
                  <>
                    {' '}
                    <Mono>{run.errorCode}</Mono>
                  </>
                ) : null}
                {run.consecutiveFailures > 0 ? ` · ${run.consecutiveFailures} fallo(s) seguidos` : ''}
              </span>
            ) : (
              <span className="b89Muted">Sin dato</span>
            ),
          },
  ];
}

function SourceCard({ source }: { source: SourceHealth }) {
  return (
    <EuiPanel hasBorder paddingSize="m" className="b89SourceCard">
      <EuiTitle size="xxs">
        <h4>{source.displayName}</h4>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <HealthMark tone={SOURCE_TONE[source.state]} label={SOURCE_STATE_LABEL[source.state]} />
      <EuiText size="xs" color="subdued">
        <p>{SOURCE_REASON_LABEL[source.reason] ?? source.reason}</p>
      </EuiText>
      <EuiSpacer size="m" />
      <EuiDescriptionList
        type="responsiveColumn"
        compressed
        className="b89Facts"
        listItems={[
          { title: 'Fuente', description: <Mono>{`${source.sourceId} · ${source.dataset}`}</Mono> },
          { title: 'Último intento', description: <Timestamp iso={source.lastAttemptAt} /> },
          {
            title: 'Última lectura correcta',
            description: <Timestamp iso={source.lastSuccessAt} />,
          },
          { title: 'Último evento de fuente', description: <Timestamp iso={source.lastEventAt} /> },
          {
            title: 'Retraso evento → fin de lectura',
            description: (
              <>
                <span className="b89Tabular">
                  p50 {lag(source.eventLag.p50Ms)} · p95 {lag(source.eventLag.p95Ms)} · p99{' '}
                  {lag(source.eventLag.p99Ms)} · muestras {source.eventLag.sampleCount}/
                  {source.eventLag.sampleWindow}
                  {source.eventLag.clockSkewSamples > 0
                    ? ` · ${source.eventLag.clockSkewSamples} con reloj desfasado`
                    : ''}
                </span>
                <br />
                Medido <Timestamp iso={source.eventLag.measuredAt} />
              </>
            ),
          },
          {
            title: 'Fallos consecutivos',
            description: (
              <span className="b89Tabular">
                {source.consecutiveFailures}
                {source.lastErrorClass ? ` · ${source.lastErrorClass}` : ''}
              </span>
            ),
          },
          {
            title: 'Política',
            description: `cada ${minutes(source.policy.intervalMs)} · degradada a ${minutes(
              source.policy.degradeAfterMs,
            )} · caída a ${minutes(source.policy.failAfterMs)}`,
          },
        ]}
      />
      <ProcessingSummary processing={source.processing} />
      <SubscriptionActivity subscriptions={source.subscriptions} />
      {source.transitions.length > 0 && (
        <>
          <EuiSpacer size="m" />
          <EuiTitle size="xxs">
            <h5>Cambios recientes</h5>
          </EuiTitle>
          <EuiSpacer size="s" />
          <ol className="b89Timeline">
            {source.transitions.map((transition) => (
              <li key={transition.id} className="b89Timeline__item">
                <span className="b89Timeline__time">
                  <Timestamp iso={transition.at} />
                </span>
                <span className="b89Timeline__body">
                  <span>
                    {SOURCE_STATE_LABEL[transition.fromState]} →{' '}
                    {SOURCE_STATE_LABEL[transition.toState]}
                  </span>
                  <span className="b89CellMeta">
                    {SOURCE_REASON_LABEL[transition.reason] ?? transition.reason}
                  </span>
                </span>
              </li>
            ))}
          </ol>
        </>
      )}
    </EuiPanel>
  );
}

export function ProcessingSummary({ processing }: { processing: SourceHealth['processing'] }) {
  return (
    <>
      <EuiSpacer size="m" />
      <EuiTitle size="xxs">
        <h5>Último sondeo y procesamiento</h5>
      </EuiTitle>
      {processing ? (
        <>
          <EuiText size="xs" color="subdued">
            <p>
              Completado <Timestamp iso={processing.completedAt} /> · estado{' '}
              {processing.outcome === 'success'
                ? 'correcto'
                : processing.outcome === 'retryable_error'
                  ? 'error reintentable'
                  : 'error permanente'}
              {processing.errorClass ? ` · ${processing.errorClass}` : ''}
            </p>
          </EuiText>
          <EuiDescriptionList
            type="responsiveColumn"
            compressed
            className="b89Facts"
            listItems={[
              {
                title: 'Documentos devueltos',
                description: <span className="b89Tabular">{processing.recordsSeen}</span>,
              },
              { title: 'Normalizados', description: processingCount(processing.normalized) },
              {
                title: 'En cuarentena',
                description: <span className="b89Tabular">{processing.quarantined}</span>,
              },
              {
                title: 'Alertas creadas',
                description: <span className="b89Tabular">{processing.promoted}</span>,
              },
              { title: 'Duplicados', description: processingCount(processing.duplicates) },
              { title: 'Sin promoción', description: processingCount(processing.notPromoted) },
              { title: 'Bajo umbral B89', description: processingCount(processing.belowThreshold) },
              {
                title: 'Suprimidos por política',
                description: processingCount(processing.suppressed),
              },
            ]}
          />
          <EuiText size="xs" color="subdued">
            <p>
              “Bajo umbral B89” no alcanzó el puntaje mínimo; “Suprimidos” coincide con una regla
              benigna o ventana de mantenimiento. “Documentos devueltos” cuenta los resultados del
              sondeo, no la actividad total de la fuente.
            </p>
          </EuiText>
        </>
      ) : (
        <EuiText size="xs" color="subdued">
          <p>Aún no hay un sondeo registrado para esta fuente.</p>
        </EuiText>
      )}
    </>
  );
}

export function processingCount(value: number | null): string {
  return value === null ? 'Sin desglose histórico' : String(value);
}

/** Separates a missing measurement from a successful measurement whose streams are quiet. */
export function SubscriptionActivity({
  subscriptions,
}: {
  subscriptions: SourceHealth['subscriptions'];
}) {
  if (!subscriptions) {
    return (
      <>
        <EuiSpacer size="m" />
        <EuiText size="xs" color="subdued">
          <p>Actividad por flujo: aún no hay una medición disponible.</p>
        </EuiText>
      </>
    );
  }

  return (
    <>
      <EuiSpacer size="m" />
      <EuiTitle size="xxs">
        <h5>Actividad por flujo (últimas {subscriptions.windowHours} h)</h5>
      </EuiTitle>
      <EuiText size="xs" color="subdued">
        <p>
          Medida <Timestamp iso={subscriptions.measuredAt} />
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {subscriptions.items.length === 0 ? (
        <EmptyLine>La medición terminó; no hay flujos registrados.</EmptyLine>
      ) : (
        <EuiBasicTable<SubscriptionItem>
          compressed
          responsive
          items={[...subscriptions.items]}
          columns={[
            {
              field: 'stream',
              name: 'Flujo',
              render: (value: string) =>
                STREAM_LABEL[value] ? (
                  <span>
                    {STREAM_LABEL[value]} <Mono>{value}</Mono>
                  </span>
                ) : (
                  <Mono>{value}</Mono>
                ),
            },
            {
              field: 'eventsInWindow',
              name: 'Eventos',
              align: 'right',
              render: (value: number) => <span className="b89Tabular">{value}</span>,
            },
            {
              field: 'lastEventAt',
              name: 'Último',
              render: (value: string | null) => <Timestamp iso={value} />,
            },
          ]}
        />
      )}
    </>
  );
}
