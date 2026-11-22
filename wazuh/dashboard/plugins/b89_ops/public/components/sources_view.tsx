/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  EuiBasicTable,
  EuiButtonEmpty,
  EuiDescriptionList,
  EuiFlexGrid,
  EuiFlexItem,
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
  verdictReasonLabel,
} from '../../common';
import { B89Page, useChanges, useConsole } from './console_context';
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

export function SourcesView() {
  const { can } = useConsole();
  if (!can(CAPABILITIES.sourcesRead)) {
    return (
      <B89Page title="Salud de fuentes">
        <EmptyLine>Tu rol no incluye la lectura de la salud de las fuentes.</EmptyLine>
      </B89Page>
    );
  }
  return <SourcesContent />;
}

function SourcesContent() {
  const { api } = useConsole();
  const health = useAsync(
    () =>
      api.get<{
        checkedAt: string;
        sources: SourceHealth[];
        verdicts?: unknown;
        healthModel?: SourceHealthModelInfo;
      }>('/sources/health'),
    [api],
  );
  useChanges(['source'], () => health.reload());

  return (
    <B89Page
      title="Salud de fuentes"
      description="Estado de la ingesta que alimenta la cola: cuándo se leyó por última vez y por qué está así."
      actions={
        <EuiButtonEmpty
          size="s"
          iconType="refresh"
          onClick={health.reload}
          isLoading={health.loading}
        >
          Actualizar
        </EuiButtonEmpty>
      }
    >
      {health.error != null && <ErrorCallout error={health.error} onRetry={health.reload} />}
      {health.data && (
        <>
          <EuiText size="xs" color="subdued">
            <p>
              Comprobado <Timestamp iso={health.data.checkedAt} />
            </p>
          </EuiText>
          <EuiSpacer size="m" />
          <SourceVerdicts
            verdicts={parseVerdicts(health.data.verdicts)}
            model={health.data.healthModel ?? null}
          />
          <EuiSpacer size="l" />
          <details>
            <summary>Ver historial y datos técnicos de cada conexión</summary>
            <EuiSpacer size="s" />
            {health.data.sources.length === 0 ? (
              <EmptyLine>No hay fuentes configuradas para este tenant.</EmptyLine>
            ) : (
              <EuiFlexGrid columns={2} gutterSize="m" responsive>
                {health.data.sources.map((source) => (
                  <EuiFlexItem key={`${source.sourceId}:${source.dataset}`}>
                    <SourceCard source={source} />
                  </EuiFlexItem>
                ))}
              </EuiFlexGrid>
            )}
          </details>
        </>
      )}
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

/** Salud por fuente: veredicto, motivos y la línea de tiempo de cada señal. */
export function SourceVerdicts({
  verdicts,
  model,
}: {
  verdicts: readonly SourceVerdictView[];
  model: SourceHealthModelInfo | null;
}) {
  return (
    <section aria-label="Salud por fuente">
      <EuiTitle size="xs">
        <h2>Salud por fuente</h2>
      </EuiTitle>
      <EuiText size="xs" color="subdued">
        <p>
          Aquí puedes saber si los datos están llegando, aunque no haya alertas. «Sin actividad»
          puede ser normal; «Sin información» significa que B89 no pudo comprobar la fuente.
          {model?.stale
            ? ' Estos datos podrían estar desactualizados porque B89 no pudo consultar el indexador.'
            : ''}
        </p>
      </EuiText>
      {model?.measuredAt && (
        <EuiText size="xs" color="subdued">
          <p>
            Medido <Timestamp iso={model.measuredAt} />
          </p>
        </EuiText>
      )}
      <EuiSpacer size="s" />
      {verdicts.length === 0 ? (
        <EmptyLine>La API no informó la salud por fuente (versión anterior o sin permiso).</EmptyLine>
      ) : (
        <EuiFlexGrid columns={3} gutterSize="m" responsive>
          {verdicts.map((item) => (
            <EuiFlexItem key={item.id}>
              <SourceVerdictCard item={item} />
            </EuiFlexItem>
          ))}
        </EuiFlexGrid>
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
        ? 'La conexión está activa; no se han visto eventos nuevos en el periodo revisado.'
        : item.verdict === 'degraded'
          ? `Los datos llegan con una incidencia${firstReason ? `: ${firstReason}` : '.'}`
          : item.verdict === 'failing'
            ? `No se pudo confirmar la llegada de datos${firstReason ? `: ${firstReason}` : '.'}`
            : 'Todavía no hay información suficiente para confirmar si los datos están llegando.';
  return (
    <EuiPanel
      hasBorder
      paddingSize="m"
      className="b89SourceCard"
      data-verdict={item.verdict}
      aria-label={`${item.label}: ${verdict}`}
    >
      <EuiTitle size="xxs">
        <h3>{item.label}</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <HealthMark tone={SOURCE_VERDICT_TONE[item.verdict]} label={verdict} />
      <p>{summary}</p>
      <EuiSpacer size="s" />
      <details>
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
  );
}

/** Línea de tiempo de señales de una fuente; cada señal sin dato dice «Sin dato». */
export function verdictSignalItems(
  item: SourceVerdictView,
): { title: string; description: NonNullable<React.ReactNode> }[] {
  const run = item.heartbeat;
  return [
          {
            title: 'Último latido del colector',
            description:
              item.expectedHeartbeatMs === null && item.id !== 'wazuh-indexer' ? (
                <span className="b89Muted">No aplica (sin colector propio)</span>
              ) : (
                <Timestamp iso={item.lastHeartbeatAt} />
              ),
          },
          { title: 'Última corrida correcta', description: <Timestamp iso={item.lastSuccessfulRunAt} /> },
          { title: 'Última autenticación correcta', description: <Timestamp iso={item.lastAuthOkAt} /> },
          { title: 'Último evento', description: <Timestamp iso={item.lastEventAt} /> },
          { title: 'Volumen vs lo esperado', description: volumeText(item.volume) },
          { title: 'Retraso de ingesta', description: ingestLagText(item.ingestLag) },
          { title: 'Atraso del proveedor', description: seconds(item.providerLagSeconds) },
          { title: 'Canario sintético', description: <Timestamp iso={item.canaryAt} /> },
          {
            title: 'Última corrida',
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
      <EuiTitle size="xs">
        <h2>{source.displayName}</h2>
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
            title: 'Lag evento → fin de lectura',
            description: (
              <>
                <span className="b89Tabular">
                  p50 {lag(source.eventLag.p50Ms)} · p95 {lag(source.eventLag.p95Ms)} · p99{' '}
                  {lag(source.eventLag.p99Ms)} · muestras {source.eventLag.sampleCount}/
                  {source.eventLag.sampleWindow}
                  {source.eventLag.clockSkewSamples > 0
                    ? ` · skew ${source.eventLag.clockSkewSamples}`
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
            <h3>Cambios recientes</h3>
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
        <h3>Último sondeo y procesamiento</h3>
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
        <h3>Actividad por flujo (últimas {subscriptions.windowHours} h)</h3>
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
