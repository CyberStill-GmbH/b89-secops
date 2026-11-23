/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
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
  CORRELATOR_FEEDBACK_STATUS_LABEL,
  CORRELATOR_FEEDBACK_STATUS_TONE,
  CorrelatorCoverage,
  DEGRADED_REASON_LABEL,
  HealthTone,
  NOTIFICATION_STATUS_LABEL,
  NotificationStatus,
  OPERATIONS_STATUS_LABEL,
  OPERATIONS_TONE,
  SocCorrelatorHealth,
  OperationsHealth,
  OperationsStatus,
  SOURCE_COVERAGE_REASON_LABEL,
  SOURCE_ISSUE_LABEL,
  SOURCE_VERDICT_LABEL,
  SOURCE_VERDICT_TONE,
  SourceVerdict,
  verdictReasonLabel,
} from '../../common';
import { B89Page, useChanges, useConsole } from './console_context';
import { EmptyLine, ErrorCallout, HealthMark, Timestamp, useAsync } from './primitives';

function duration(seconds: number | null): string {
  if (seconds === null) return 'Sin dato';
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

export function formatLatencySummary(
  p50: number | null,
  p95: number,
  p99: number | null,
  sampleCount: number,
): string {
  return `p50 ${Math.round(p50 ?? 0)} ms · p95 ${Math.round(p95)} ms · p99 ${Math.round(p99 ?? p95)} ms · ${sampleCount} ${sampleCount === 1 ? 'muestra' : 'muestras'}`;
}

export function formatOutboxQueueSummary(input: {
  pending: number;
  processing: number;
  oldestPendingAgeSeconds: number | null;
  expiredProcessing: number;
  oldestExpiredLeaseAgeSeconds: number | null;
}): string {
  const expired =
    input.expiredProcessing > 0
      ? ` · el más antiguo atascado hace ${duration(input.oldestExpiredLeaseAgeSeconds)}`
      : '';
  return `${input.pending} pendientes · ${input.processing} en curso · más antigua ${duration(input.oldestPendingAgeSeconds)} · ${input.expiredProcessing} atascados${expired}`;
}

export function describeCorrelatorHealth(correlator: SocCorrelatorHealth | null | undefined): {
  label: string;
  tone: HealthTone;
} {
  if (!correlator) return { label: 'Sin respuesta', tone: 'neutral' };

  if (correlator.feedbackStatus === 'stale') {
    const age = correlator.feedbackAgeSeconds;
    return {
      label: age === null ? 'Atrasado' : `Atrasado · ${duration(age)} sin actualizar`,
      tone: CORRELATOR_FEEDBACK_STATUS_TONE.stale,
    };
  }

  if (correlator.feedbackStatus === 'ready') {
    if (correlator.ready === true && correlator.status === 'OK') {
      return {
        label: CORRELATOR_FEEDBACK_STATUS_LABEL.ready,
        tone: CORRELATOR_FEEDBACK_STATUS_TONE.ready,
      };
    }
    if (correlator.ready === false || correlator.status === 'DEGRADED') {
      return { label: 'Con problemas', tone: 'warn' };
    }
    if (correlator.ready === null) return { label: 'Sin respuesta', tone: 'neutral' };
  }

  return {
    label: CORRELATOR_FEEDBACK_STATUS_LABEL[correlator.feedbackStatus],
    tone: CORRELATOR_FEEDBACK_STATUS_TONE[correlator.feedbackStatus],
  };
}

/**
 * Cobertura por fuente vista por el correlador. `unknown` (sin latido del colector) e
 * `incomplete` se presentan como «Cobertura incompleta»: la ausencia de eventos en esas
 * fuentes no prueba ausencia de actividad.
 */
export function describeSourceCoverage(coverage: CorrelatorCoverage | undefined): {
  label: string;
  tone: HealthTone;
  details: readonly string[];
} {
  if (!coverage) return { label: 'Sin dato de cobertura', tone: 'neutral', details: [] };
  const gaps = coverage.sources.filter((source) => source.state !== 'complete');
  if (coverage.complete && gaps.length === 0) {
    return {
      label: coverage.sources.length === 0 ? 'Sin fuentes observadas' : 'Completa',
      tone: coverage.sources.length === 0 ? 'neutral' : 'ok',
      details: [],
    };
  }
  const details = gaps.map((source) => {
    const reason =
      (source.reason && SOURCE_COVERAGE_REASON_LABEL[source.reason]) ??
      (source.state === 'unknown' ? 'no verificada' : 'incompleta');
    const lag =
      source.providerLagSeconds !== null && source.reason === 'collector_behind_provider'
        ? ` (${duration(source.providerLagSeconds)})`
        : '';
    return `${SOURCE_ID_LABEL[source.source] ?? source.source}: ${reason}${lag}`;
  });
  return {
    label: 'Cobertura incompleta',
    tone: gaps.some((source) => source.state === 'incomplete') ? 'warn' : 'neutral',
    details,
  };
}

function SectionPanel({
  title,
  status,
  reasons,
  children,
}: {
  title: string;
  status: OperationsStatus;
  reasons?: readonly string[];
  children: React.ReactNode;
}) {
  return (
    <EuiPanel hasBorder paddingSize="m" className="b89SourceCard">
      <EuiTitle size="xs">
        <h2>{title}</h2>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <HealthMark tone={OPERATIONS_TONE[status]} label={OPERATIONS_STATUS_LABEL[status]} />
      {reasons && reasons.length > 0 && (
        <ul className="b89List">
          {reasons.map((reason) => (
            <li key={reason}>
              {DEGRADED_REASON_LABEL[reason] ?? SOURCE_ISSUE_LABEL[reason] ?? reason}
            </li>
          ))}
        </ul>
      )}
      <EuiSpacer size="m" />
      {children}
    </EuiPanel>
  );
}

/** Nombre legible de las fuentes de `/api/operations/health` (la sección no trae rótulo). */
const SOURCE_ID_LABEL: Readonly<Record<string, string>> = {
  m365: 'Microsoft 365',
  entra: 'Entra ID',
  'sharepoint-posture': 'SharePoint (configuración)',
  'sharepoint-audit': 'SharePoint (auditoría)',
  bitdefender: 'Bitdefender',
  snyk: 'Snyk',
  cloudflare: 'Cloudflare',
  aws: 'AWS',
  'wazuh-indexer': 'SIEM (Wazuh)',
  'wazuh-agents': 'Agentes Wazuh',
};

const VERDICT_ORDER: readonly SourceVerdict[] = ['failing', 'degraded', 'unknown', 'quiet', 'healthy'];

/** Sección `sources` (docs/20): conteo por veredicto y los problemas abiertos por fuente. */
export function SourcesHealthPanel({
  section,
}: {
  section: NonNullable<OperationsHealth['sections']['sources']>;
}) {
  const problems = section.sources.filter(
    (item) => item.verdict === 'failing' || item.verdict === 'degraded',
  );
  return (
    <SectionPanel title="Salud por fuente" status={section.status} reasons={section.degradedReasons}>
      <p className="b89Health__counts">
        {VERDICT_ORDER.map((verdict) => (
          <span key={verdict} className="b89Health__count">
            <HealthMark
              tone={SOURCE_VERDICT_TONE[verdict]}
              label={`${SOURCE_VERDICT_LABEL[verdict]}: ${section.counts[verdict] ?? 0}`}
            />{' '}
          </span>
        ))}
      </p>
      {problems.length > 0 ? (
        <ul className="b89List" aria-label="Fuentes con problemas">
          {problems.map((item) => (
            <li key={item.id}>
              <strong>{SOURCE_ID_LABEL[item.id] ?? item.id}</strong> · {SOURCE_VERDICT_LABEL[item.verdict as SourceVerdict] ?? item.verdict}
              {item.reasons.length > 0 ? ` · ${item.reasons.map(verdictReasonLabel).join('; ')}` : ''}
            </li>
          ))}
        </ul>
      ) : (
        <EuiText size="xs" color="subdued">
          <p>Ninguna fuente medida está degradada ni fallando.</p>
        </EuiText>
      )}
      <EuiText size="xs" color="subdued">
        <p>
          Medido <Timestamp iso={section.measuredAt} /> · modelo {section.modelVersion}
        </p>
      </EuiText>
    </SectionPanel>
  );
}

/** Una línea por área de la plataforma: lo que un analista necesita saber sin abrir el detalle. */
export interface OperationsSummaryRow {
  readonly key: string;
  readonly title: string;
  readonly tone: HealthTone;
  readonly label: string;
  readonly detail: React.ReactNode;
}

export function operationsSummaryRows(data: OperationsHealth): OperationsSummaryRow[] {
  const rows: OperationsSummaryRow[] = [];
  const summary = data.sections.summary;
  rows.push({
    key: 'detection',
    title: 'Detección',
    tone: OPERATIONS_TONE[summary.status],
    label: OPERATIONS_STATUS_LABEL[summary.status],
    detail: summary.lastAlertAt ? (
      <>
        Última alerta <Timestamp iso={summary.lastAlertAt} />
      </>
    ) : (
      'Todavía no llegó ninguna alerta.'
    ),
  });
  const soc = data.sections.soc;
  if (soc) {
    const reasons = soc.degradedReasons.filter(
      (reason) =>
        reason.startsWith('DISPATCHER') ||
        reason.startsWith('OUTBOX') ||
        reason.startsWith('NOTIFICATION'),
    );
    rows.push({
      key: 'dispatch',
      title: 'Envío de avisos',
      tone: !soc.dispatcherRunning ? 'fail' : reasons.length > 0 ? 'warn' : 'ok',
      label: !soc.dispatcherRunning ? 'Detenido' : reasons.length > 0 ? 'Con problemas' : 'Funciona',
      detail:
        reasons.length > 0
          ? reasons.map((reason) => DEGRADED_REASON_LABEL[reason] ?? reason).join('. ')
          : `${soc.outbox.pending} aviso${soc.outbox.pending === 1 ? '' : 's'} en cola.`,
    });
    const correlator = describeCorrelatorHealth(soc.correlator);
    const coverage = describeSourceCoverage(soc.correlator?.coverage);
    const gaps = coverage.details.length;
    rows.push({
      key: 'correlator',
      title: 'Correlador',
      tone: correlator.tone,
      label: correlator.label,
      detail:
        coverage.label === 'Cobertura incompleta'
          ? `Cobertura incompleta: ${gaps} fuente${gaps === 1 ? '' : 's'} sin verificar o con atraso; pueden faltar eventos.`
          : coverage.label === 'Completa'
            ? 'Cobertura completa de fuentes.'
            : coverage.label,
    });
  }
  const platform = data.sections.platform;
  if (platform) {
    rows.push({
      key: 'database',
      title: 'Base de datos',
      tone: platform.databaseLatencyMs === null ? 'fail' : OPERATIONS_TONE[platform.status],
      label:
        platform.databaseLatencyMs === null
          ? 'Sin respuesta'
          : OPERATIONS_STATUS_LABEL[platform.status],
      detail:
        platform.databaseLatencyMs === null
          ? 'La base de datos no respondió.'
          : `Responde en ${platform.databaseLatencyMs} ms.`,
    });
  }
  return rows;
}

/**
 * Salud operativa (doc 12): ¿llegan los datos y funciona el despacho? Dentro de «Salud de
 * fuentes» (`embedded`) muestra una línea por área y pliega las métricas internas; la página
 * padre tiene el único botón «Actualizar» (`refreshKey`).
 */
export function OperationsView({
  embedded = false,
  refreshKey = 0,
}: {
  embedded?: boolean;
  refreshKey?: number;
}) {
  const { can } = useConsole();
  // El backend autoriza cada sección; sin ninguna capacidad de observabilidad no se consulta.
  const allowed =
    can(CAPABILITIES.observabilitySoc) ||
    can(CAPABILITIES.observabilityPlatform) ||
    can(CAPABILITIES.sourcesRead);
  if (!allowed) {
    const line = (
      <EmptyLine>
        Tu rol no incluye la salud operativa de la plataforma. Pídela a un Administrador de
        plataforma si la necesitas.
      </EmptyLine>
    );
    return embedded ? line : <B89Page title="Salud operativa">{line}</B89Page>;
  }
  return <OperationsContent embedded={embedded} refreshKey={refreshKey} />;
}

function OperationsContent({ embedded, refreshKey }: { embedded: boolean; refreshKey: number }) {
  const { api } = useConsole();
  const health = useAsync(() => api.get<OperationsHealth>('/operations/health'), [api, refreshKey]);
  useChanges(['source', 'notification'], () => health.reload(), 2000);

  const data = health.data;
  const body = (
    <>
      {health.error != null && <ErrorCallout error={health.error} onRetry={health.reload} />}
      {health.loading && !data && health.error == null && <EuiLoadingContent lines={3} />}
      {data && (
        <>
          <ul className="b89OpsSummary" aria-label="Estado por área">
            {operationsSummaryRows(data).map((row) => (
              <li key={row.key} className="b89OpsSummary__row">
                <strong className="b89OpsSummary__title">{row.title}</strong>
                <HealthMark tone={row.tone} label={row.label} />
                <span className="b89Muted">{row.detail}</span>
              </li>
            ))}
          </ul>
          <EuiSpacer size="s" />
          <details className="b89Guide__details">
            <summary>Ver métricas internas (colas, tiempos y memoria)</summary>
            <EuiSpacer size="s" />
            <EuiText size="xs" color="subdued">
              <p>
                Medido <Timestamp iso={data.generatedAt} /> · estado global{' '}
                {OPERATIONS_STATUS_LABEL[data.status]}
              </p>
            </EuiText>
            <EuiSpacer size="s" />
          <EuiFlexGrid columns={3} gutterSize="m" responsive>
            <EuiFlexItem>
              <SectionPanel title="Detección" status={data.sections.summary.status}>
                <EuiDescriptionList
                  type="responsiveColumn"
                  compressed
                  className="b89Facts"
                  listItems={[
                    {
                      title: 'Última alerta',
                      description: <Timestamp iso={data.sections.summary.lastAlertAt} />,
                    },
                    {
                      title: 'Antigüedad',
                      description: duration(data.sections.summary.alertFreshnessSeconds),
                    },
                    {
                      title: 'Cobertura por fuente',
                      description:
                        data.sections.summary.sourceCoverage === 'NO_DATA'
                          ? 'Sin medición disponible'
                          : (OPERATIONS_STATUS_LABEL[
                              data.sections.summary.sourceCoverage as OperationsStatus
                            ] ?? data.sections.summary.sourceCoverage),
                    },
                  ]}
                />
              </SectionPanel>
            </EuiFlexItem>
            {data.sections.soc && (
              <EuiFlexItem>
                <SectionPanel
                  title="Operación SOC"
                  status={data.sections.soc.status}
                  reasons={data.sections.soc.degradedReasons}
                >
                  <EuiDescriptionList
                    type="responsiveColumn"
                    compressed
                    className="b89Facts"
                    listItems={[
                      {
                        title: 'Despachador',
                        description: data.sections.soc.dispatcherRunning ? 'En marcha' : 'Detenido',
                      },
                      {
                        title: 'Correlador',
                        description: (() => {
                          const correlator = data.sections.soc?.correlator;
                          const state = describeCorrelatorHealth(correlator);
                          return (
                            <span>
                              <HealthMark tone={state.tone} label={state.label} />
                              {correlator?.lastFeedbackSuccess && (
                                <>
                                  <br />
                                  Último éxito <Timestamp iso={correlator.lastFeedbackSuccess} />
                                </>
                              )}
                            </span>
                          );
                        })(),
                      },
                      {
                        title: 'Cobertura de fuentes',
                        description: (() => {
                          const state = describeSourceCoverage(
                            data.sections.soc?.correlator?.coverage,
                          );
                          return (
                            <span>
                              <HealthMark tone={state.tone} label={state.label} />
                              {state.details.map((detail) => (
                                <React.Fragment key={detail}>
                                  <br />
                                  {detail}
                                </React.Fragment>
                              ))}
                            </span>
                          );
                        })(),
                      },
                      {
                        title: 'Cola de envío de avisos',
                        description: (
                          <span className="b89Tabular">
                            {formatOutboxQueueSummary(data.sections.soc.outbox)}
                          </span>
                        ),
                      },
                      {
                        title: 'Canal rápido de Wazuh',
                        description: data.sections.soc.wazuhPushInbox
                          ? `${data.sections.soc.wazuhPushInbox.counts.pending} pendientes · ${data.sections.soc.wazuhPushInbox.counts.processing} en curso · ${data.sections.soc.wazuhPushInbox.counts['failed-terminal']} terminales · más antigua ${duration(data.sections.soc.wazuhPushInbox.oldestUnresolvedAgeSeconds)}`
                          : 'No configurada',
                      },
                      ...(data.sections.soc.wazuhPushInbox
                        ? [
                            {
                              title: `Canal rápido: fallos definitivos (${data.sections.soc.wazuhPushInbox.terminalWindowHours} h)`,
                              description: (
                                <>
                                  {data.sections.soc.wazuhPushInbox.terminalFailuresRecent} fallidas
                                  · {data.sections.soc.wazuhPushInbox.expiredProcessing} atascados · último éxito{' '}
                                  {data.sections.soc.wazuhPushInbox.lastProcessedAt ? (
                                    <Timestamp
                                      iso={data.sections.soc.wazuhPushInbox.lastProcessedAt}
                                    />
                                  ) : (
                                    'Sin dato'
                                  )}
                                </>
                              ),
                            },
                            {
                              title: `Wazuh → recepción en B89 (${data.sections.soc.wazuhPushInbox.sourceToReceiptMs.windowHours} h)`,
                              description: (() => {
                                const latency = data.sections.soc.wazuhPushInbox?.sourceToReceiptMs;
                                if (!latency || latency.sampleCount === 0 || latency.p95 === null) {
                                  return 'Sin muestras válidas en la ventana';
                                }
                                return `p50 ${Math.round(latency.p50 ?? 0)} ms · p95 ${Math.round(latency.p95)} ms · p99 ${Math.round(latency.p99 ?? latency.p95)} ms · ${latency.sampleCount} muestras${latency.clockSkewSamples > 0 ? ` · ${latency.clockSkewSamples} excluidas por reloj` : ''}${latency.sampleCapReached ? ' · limitada a 10 000 eventos' : ''}`;
                              })(),
                            },
                            {
                              title: `Recepción → procesado (${data.sections.soc.wazuhPushInbox.receiptToHandlerMs.windowHours} h)`,
                              description: (() => {
                                const latency =
                                  data.sections.soc.wazuhPushInbox?.receiptToHandlerMs;
                                if (!latency || latency.sampleCount === 0 || latency.p95 === null) {
                                  return 'Sin muestras completadas';
                                }
                                return formatLatencySummary(
                                  latency.p50,
                                  latency.p95,
                                  latency.p99,
                                  latency.sampleCount,
                                );
                              })(),
                            },
                          ]
                        : []),
                      {
                        title: `Notificaciones (${data.sections.soc.notifications.windowHours} h)`,
                        description:
                          Object.keys(data.sections.soc.notifications.byStatus).length === 0
                            ? 'Ninguna'
                            : Object.entries(data.sections.soc.notifications.byStatus)
                                .map(
                                  ([status, count]) =>
                                    `${NOTIFICATION_STATUS_LABEL[status as NotificationStatus] ?? status}: ${count}`,
                                )
                                .join(' · '),
                      },
                      {
                        title: `Cola de envío → aceptado por el canal (${data.sections.soc.outboxToProviderAcceptanceMs.windowHours} h)`,
                        description: (() => {
                          const latency = data.sections.soc.outboxToProviderAcceptanceMs;
                          if (latency.status === 'NO_DATA' || latency.sampleCount === 0) {
                            return (
                              <span>
                                Sin avisos aceptados por el canal en la ventana. «Aceptado» significa
                                que el canal recibió el aviso, no que alguien lo leyó.
                              </span>
                            );
                          }
                          return (
                            <span>
                              p50 {latency.p50 ?? '—'} ms · p95 {latency.p95 ?? '—'} ms · p99{' '}
                              {latency.p99 ?? '—'} ms · {latency.sampleCount} muestras
                              {latency.excludedClockSkewCount > 0
                                ? ` · ${latency.excludedClockSkewCount} excluidas por reloj`
                                : ''}
                              {latency.sampleCapReached
                                ? ' · ventana limitada a 10 000 mensajes'
                                : ''}
                              <br />
                              «Aceptado» significa que el canal recibió el aviso, no que alguien lo
                              leyó.
                            </span>
                          );
                        })(),
                      },
                      {
                        title: 'Persistencia',
                        description:
                          data.sections.soc.persistence === 'postgres'
                            ? 'PostgreSQL'
                            : 'En memoria',
                      },
                    ]}
                  />
                </SectionPanel>
              </EuiFlexItem>
            )}
            {data.sections.sources && !embedded && (
              <EuiFlexItem>
                <SourcesHealthPanel section={data.sections.sources} />
              </EuiFlexItem>
            )}
            {data.sections.platform && (
              <EuiFlexItem>
                <SectionPanel
                  title="Plataforma"
                  status={data.sections.platform.status}
                  reasons={data.sections.platform.degradedReasons}
                >
                  <EuiDescriptionList
                    type="responsiveColumn"
                    compressed
                    className="b89Facts"
                    listItems={[
                      {
                        title: 'Base de datos',
                        description:
                          data.sections.platform.databaseLatencyMs === null
                            ? 'Sin respuesta'
                            : `${data.sections.platform.databaseLatencyMs} ms`,
                      },
                      {
                        title: 'Activo desde hace',
                        description: duration(data.sections.platform.uptimeSeconds),
                      },
                      {
                        title: 'Memoria',
                        description:
                          data.sections.platform.memoryRssMb === null
                            ? 'Sin dato'
                            : `${data.sections.platform.memoryRssMb} MB`,
                      },
                      {
                        title: 'Runtime',
                        description: data.sections.platform.nodeVersion ?? 'Sin dato',
                      },
                    ]}
                  />
                </SectionPanel>
              </EuiFlexItem>
            )}
          </EuiFlexGrid>
          </details>
        </>
      )}
    </>
  );
  if (embedded) {
    return (
      <section className="b89TechSection" aria-labelledby="b89-operations-title">
        <EuiTitle size="xs">
          <h3 id="b89-operations-title">Salud operativa</h3>
        </EuiTitle>
        <p className="b89Muted">Alertas, envío de avisos, correlador y base de datos.</p>
        <EuiSpacer size="s" />
        {body}
      </section>
    );
  }
  return (
    <B89Page
      title="Salud operativa"
      description="Alertas, envío de avisos, correlador y base de datos."
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
      {body}
    </B89Page>
  );
}
