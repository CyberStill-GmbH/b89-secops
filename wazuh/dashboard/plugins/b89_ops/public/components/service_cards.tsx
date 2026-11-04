/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButtonEmpty, EuiText } from '@elastic/eui';
import {
  INTEGRATIONS,
  IntegrationSpec,
  ProviderId,
  PROVIDER_IDS,
  ServiceId,
  SOURCE_STATE_LABEL,
  SOURCE_TONE,
} from '../../common';
import {
  formatNumber,
  integrationLinks,
  LastEvent,
  Metric,
  MetricList,
  Monogram,
  PlatformData,
  SeverityBar,
  SkeletonCard,
  StatusPill,
} from './overview_parts';
import { declaredStatus, providerStatus, ServiceStatus, wazuhStatus } from './service_status';

export interface ServiceModel {
  readonly spec: IntegrationSpec;
  readonly status: ServiceStatus;
  readonly metrics: readonly Metric[];
  readonly lastEventAt: string | null | undefined;
  readonly events24h: number | null;
  /** `true` mientras su fuente principal sigue cargando. */
  readonly loading: boolean;
}

const isProvider = (id: ServiceId): id is ProviderId =>
  (PROVIDER_IDS as readonly string[]).includes(id);

function providerMetrics(id: ProviderId, data: PlatformData): Metric[] {
  const stats = data.overview.data?.providers?.[id];
  if (!stats) return [];
  const m = stats.metrics;
  const events: Metric = { label: 'Eventos 24 h', value: formatNumber(stats.events24h) };
  switch (id) {
    case 'bitdefender':
      return [
        {
          label: 'Endpoints con hallazgos',
          value: formatNumber(m.endpoints ?? 0),
          hint: 'Endpoints distintos con algún hallazgo en 30 días',
        },
        {
          label: 'Infectados',
          value: formatNumber(m.infected ?? 0),
          emphasis: (m.infected ?? 0) > 0 ? 'danger' : undefined,
        },
        events,
      ];
    case 'snyk':
      return [
        {
          label: 'Críticas',
          value: formatNumber(m.open_critical ?? 0),
          emphasis: (m.open_critical ?? 0) > 0 ? 'danger' : undefined,
        },
        {
          label: 'Altas',
          value: formatNumber(m.open_high ?? 0),
          emphasis: (m.open_high ?? 0) > 0 ? 'warning' : undefined,
        },
        { label: 'Medias', value: formatNumber(m.open_medium ?? 0) },
        { label: 'Bajas', value: formatNumber(m.open_low ?? 0) },
      ];
    case 'cloudflare':
      return [
        { label: 'Bloqueos WAF 24 h', value: formatNumber(m.waf_blocks ?? 0) },
        { label: 'Auditoría 24 h', value: formatNumber(m.audit ?? 0) },
        { label: 'Zonas', value: formatNumber(m.zones ?? 0) },
      ];
    default:
      return [
        events,
        {
          label: 'Altas y críticas 24 h',
          value: formatNumber(stats.levels24h.high + stats.levels24h.critical),
        },
      ];
  }
}

function serviceModel(spec: IntegrationSpec, data: PlatformData): ServiceModel {
  const overview = data.overview.data;
  const declared = declaredStatus(overview?.integrations[spec.id]);
  if (isProvider(spec.id)) {
    const stats = overview?.providers?.[spec.id];
    return {
      spec,
      status: data.overview.error ? errorStatus() : providerStatus(spec.id, overview),
      metrics: providerMetrics(spec.id, data),
      lastEventAt: stats?.lastEventAt,
      events24h: stats?.events24h ?? null,
      loading: data.overview.loading && !overview,
    };
  }
  if (spec.id === 'wazuh') {
    const source = data.sources.data?.[0] ?? null;
    const agents = overview?.agents;
    const metrics: Metric[] = [];
    if (agents && agents.total > 0) {
      metrics.push({
        label: 'Agentes activos',
        value: `${formatNumber(agents.active)} / ${formatNumber(agents.total)}`,
        emphasis: agents.disconnected > 0 ? 'warning' : undefined,
      });
    } else if (overview && overview.monitoringAccess !== 'ok') {
      metrics.push({ label: 'Agentes', value: 'Sin permiso', hint: 'wazuh-monitoring-*' });
    }
    if (overview?.siem) {
      metrics.push({ label: 'Alertas 24 h', value: formatNumber(overview.siem.total24h) });
      metrics.push({
        label: 'Altas y críticas',
        value: formatNumber(overview.siem.levels24h.high + overview.siem.levels24h.critical),
      });
    }
    if (source) {
      metrics.push({
        label: 'Ingesta B89',
        value: SOURCE_STATE_LABEL[source.state],
        emphasis: SOURCE_TONE[source.state] === 'fail' ? 'danger' : undefined,
      });
    }
    return {
      spec,
      status: data.overview.error ? errorStatus() : wazuhStatus(overview, source),
      metrics,
      lastEventAt: source?.lastEventAt ?? overview?.siem?.trend24h.slice(-1)[0]?.at ?? null,
      events24h: overview?.siem?.total24h ?? null,
      loading: data.overview.loading && !overview,
    };
  }
  if (spec.id === 'respond') {
    const up = data.respond.data;
    return {
      spec,
      status:
        declared ??
        (up === null
          ? { tone: 'neutral', label: 'Consultando…', detail: null }
          : up
            ? { tone: 'ok', label: 'Disponible', detail: null }
            : {
                tone: 'fail',
                label: 'Sin respuesta',
                detail: 'El frontal de Respond no respondió.',
              }),
      metrics: [{ label: 'Aprobación', value: 'Líder SOC' }],
      lastEventAt: undefined,
      events24h: null,
      loading: data.respond.loading && up === null,
    };
  }
  if (spec.id === 'bunny') {
    const config = data.bunny.data;
    return {
      spec,
      status:
        declared ??
        (config === null
          ? {
              tone: 'neutral',
              label: data.bunny.loading ? 'Consultando…' : 'Sin dato',
              detail: null,
            }
          : config.enabled
            ? { tone: 'ok', label: 'Disponible', detail: null }
            : {
                tone: 'neutral',
                label: 'Sin proveedor de IA',
                detail: 'La API no tiene un proveedor de IA configurado.',
              }),
      metrics: config
        ? [
            {
              label: 'Modo',
              value: config.readOnly === false ? 'Lectura y escritura' : 'Solo lectura',
            },
          ]
        : [],
      lastEventAt: undefined,
      events24h: null,
      loading: data.bunny.loading && config === null,
    };
  }
  // Correo de alertas.
  const byStatus = data.operations.data?.sections.soc?.notifications.byStatus;
  const failed = byStatus ? (byStatus.failed ?? 0) + (byStatus.indeterminate ?? 0) : null;
  return {
    spec,
    status:
      declared ??
      (failed && failed > 0
        ? { tone: 'warn', label: 'Con fallos de entrega', detail: null }
        : { tone: 'ok', label: 'Configurado', detail: null }),
    metrics: [
      { label: 'Umbral', value: 'Nivel ≥ 8' },
      ...(failed === null ? [] : [{ label: 'Fallidas', value: formatNumber(failed) } as Metric]),
    ],
    lastEventAt: undefined,
    events24h: null,
    loading: false,
  };
}

function errorStatus(): ServiceStatus {
  return {
    tone: 'fail',
    label: 'No se pudo consultar',
    detail: 'El servidor del dashboard no respondió.',
  };
}

export function serviceModels(data: PlatformData): ServiceModel[] {
  return INTEGRATIONS.map((spec) => serviceModel(spec, data));
}

export function ServiceCard({
  model,
  basePath,
  compact = false,
}: {
  model: ServiceModel;
  basePath: string;
  compact?: boolean;
}) {
  if (model.loading) return <SkeletonCard />;
  const { spec, status } = model;
  const links = integrationLinks(spec, basePath).slice(0, compact ? 2 : 6);
  return (
    <article className="b89Service" data-tone={status.tone} aria-label={spec.name}>
      <header className="b89Service__header">
        <Monogram text={spec.monogram} />
        <div className="b89Service__title">
          <h3>{spec.name}</h3>
          <span className="b89Service__vendor">{spec.summary}</span>
        </div>
      </header>
      <div className="b89Service__status">
        <StatusPill status={status} />
        {status.detail && (
          <EuiText size="xs" color="subdued">
            <p>{status.detail}</p>
          </EuiText>
        )}
      </div>
      <MetricList metrics={model.metrics} />
      <footer className="b89Service__footer">
        {model.lastEventAt !== undefined ? <LastEvent iso={model.lastEventAt} /> : <span />}
        <span className="b89Service__links">
          {links.map((link) => (
            <EuiButtonEmpty key={link.href} size="xs" href={link.href} flush="right">
              {link.label}
            </EuiButtonEmpty>
          ))}
        </span>
      </footer>
    </article>
  );
}

export function ProviderSeverity({ model, data }: { model: ServiceModel; data: PlatformData }) {
  if (!isProvider(model.spec.id)) return null;
  const stats = data.overview.data?.providers?.[model.spec.id];
  if (!stats || stats.events24h === 0) return null;
  return <SeverityBar levels={stats.levels24h} label={`${model.spec.name}, eventos 24 h`} />;
}
