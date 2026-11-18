/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState } from 'react';
import {
  AttentionFocus,
  attentionQuery,
  levelBandHref,
  ServiceAttentionList,
} from './service_attention';
import { EuiButtonEmpty, EuiText } from '@elastic/eui';
import {
  INTEGRATIONS,
  IntegrationSpec,
  ProviderId,
  PROVIDER_IDS,
  discoverUrlForQuery,
  ServiceId,
  SOURCE_STATE_LABEL,
  SOURCE_TONE,
  ServiceAttention,
  LevelCounts,
  TRAFFIC_APP_PATH,
} from '../../common';
import {
  formatNumber,
  integrationLinks,
  LastEvent,
  Metric,
  MetricList,
  PlatformData,
  SeverityBar,
  SkeletonCard,
  StatusPill,
} from './overview_parts';
import { ServiceMark } from './vendor_logo';
import { declaredStatus, providerStatus, ServiceStatus, wazuhStatus } from './service_status';

export interface ServiceModel {
  readonly attention?: ServiceAttention;
  /** Críticas (nivel ≥ 12) en 24 h, para el resumen de la lista cuando solo se ven críticas. */
  readonly critical24h?: number;
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

/** Eventos Snyk de una severidad: la lista donde se investiga cada hallazgo contado. */
function snykDrill(severity: string): Metric['drill'] {
  return {
    kql: `rule.groups: "snyk" and data.snyk.issue.severity: "${severity}" and data.snyk.issue.status: "open"`,
    from: 'now-30d',
  };
}

/** Convierte cada conteo con consulta en un enlace a Discover con esas alertas. */
export function linkedMetrics(metrics: readonly Metric[], basePath: string): Metric[] {
  return metrics.map((metric) =>
    metric.drill
      ? {
          ...metric,
          href: discoverUrlForQuery(basePath, metric.drill.kql, metric.drill.from, 'now'),
        }
      : metric.path
        ? { ...metric, href: `${basePath}${metric.path}` }
        : metric,
  );
}

/** Tráfico de Cloudflare de las últimas 24 h, opcionalmente de un tipo. */
function trafficPath(dataset?: string): string {
  return `${TRAFFIC_APP_PATH}?r=24h${dataset ? `&ds=${dataset}` : ''}`;
}

/**
 * Cloudflare: todo su tráfico (`b89-cloudflare-traffic-*`), no solo los bloqueos del WAF.
 * Cada cifra abre «Tráfico de Cloudflare» filtrado por su tipo.
 */
export function cloudflareMetrics(m: Readonly<Record<string, number>>): Metric[] {
  const zones: Metric =
    m.zones_active !== undefined
      ? {
          label: 'Zonas vigiladas',
          value: `${formatNumber(m.zones ?? 0)} · ${formatNumber(m.zones_active)} con tráfico`,
        }
      : { label: 'Zonas vigiladas', value: formatNumber(m.zones ?? 0) };
  if (m.traffic_readable === 0) {
    return [
      {
        label: 'Tráfico 24 h',
        value: 'Sin permiso',
        hint: 'Tu rol no puede leer b89-cloudflare-traffic-*',
      },
      zones,
    ];
  }
  if (m.traffic_readable !== 1) {
    return [
      { label: 'Tráfico 24 h', value: 'Sin dato', hint: 'No se pudo consultar el tráfico' },
      zones,
    ];
  }
  const sampled = (m.http_sampled_24h ?? 0) > 0;
  return [
    {
      label: 'Peticiones HTTP 24 h',
      value: formatNumber(m.http_24h ?? 0),
      hint: sampled
        ? 'Incluye registros muestreados de Cloudflare: cada uno representa varias peticiones'
        : 'Registros de peticiones HTTP en 24 h',
      path: trafficPath('http'),
    },
    { label: 'Consultas DNS 24 h', value: formatNumber(m.dns_24h ?? 0), path: trafficPath('dns') },
    {
      label: 'Eventos de seguridad 24 h',
      value: formatNumber(m.security_24h ?? 0),
      hint: 'Eventos de firewall/WAF (bloqueos, desafíos y solo-registro)',
      path: trafficPath('firewall'),
    },
    zones,
  ];
}

/**
 * «Críticas 24 h» y «Altas y críticas 24 h»: cada cifra muestra exactamente lo que cuenta
 * (en la tarjeta filtra la lista «Atención prioritaria»; sin lista, abre Discover filtrado).
 */
export function severityMetrics(service: ServiceId, levels: LevelCounts): Metric[] {
  return [
    {
      label: 'Críticas 24 h',
      value: formatNumber(levels.critical),
      hint: 'Eventos de nivel ≥ 12',
      drill: { kql: attentionQuery(service, true), from: 'now-24h' },
      focus: 'critical',
      emphasis: levels.critical > 0 ? 'danger' : undefined,
    },
    {
      label: 'Altas y críticas 24 h',
      value: formatNumber(levels.high + levels.critical),
      hint: 'Eventos de nivel ≥ 8',
      drill: { kql: attentionQuery(service, false), from: 'now-24h' },
      focus: 'all',
    },
  ];
}

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
          drill: snykDrill('critical'),
          emphasis: (m.open_critical ?? 0) > 0 ? 'danger' : undefined,
        },
        {
          label: 'Altas',
          value: formatNumber(m.open_high ?? 0),
          drill: snykDrill('high'),
          emphasis: (m.open_high ?? 0) > 0 ? 'warning' : undefined,
        },
        {
          label: 'Medias',
          value: formatNumber(m.open_medium ?? 0),
          drill: snykDrill('medium'),
        },
        {
          label: 'Bajas',
          value: formatNumber(m.open_low ?? 0),
          drill: snykDrill('low'),
        },
      ];
    case 'cloudflare':
      return cloudflareMetrics(m);
    default:
      return [events, ...severityMetrics(id, stats.levels24h)];
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
      metrics.push(...severityMetrics('wazuh', overview.siem.levels24h));
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
  const overview = data.overview.data;
  return INTEGRATIONS.map((spec) => ({
    ...serviceModel(spec, data),
    attention: overview?.attention?.[spec.id],
    critical24h:
      spec.id === 'wazuh'
        ? overview?.siem?.levels24h.critical
        : isProvider(spec.id)
          ? overview?.providers?.[spec.id]?.levels24h.critical
          : undefined,
  }));
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
  const [focus, setFocus] = useState<AttentionFocus>({ band: 'all', seq: 0 });
  const attentionRef = useRef<HTMLDivElement>(null);
  if (model.loading) return <SkeletonCard />;
  const { spec, status } = model;
  const hasAttention = spec.id === 'wazuh' || isProvider(spec.id);
  // «Críticas» deja solo críticas en la lista de la propia tarjeta; «Altas y críticas», ambas.
  // En los dos casos se limpia la búsqueda y el filtro activo queda a la vista.
  const metrics = linkedMetrics(model.metrics, basePath).map((metric) => {
    const band = metric.focus;
    if (!band || !hasAttention || model.attention?.access !== 'ok') return metric;
    return {
      ...metric,
      onSelect: () => {
        setFocus((current) => ({ band, seq: current.seq + 1 }));
        attentionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      },
    };
  });
  const links = integrationLinks(spec, basePath).slice(0, compact ? 2 : 6);
  return (
    <article className="b89Service" data-tone={status.tone} aria-label={spec.name}>
      <header className="b89Service__header">
        <ServiceMark spec={spec} basePath={basePath} />
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
      <MetricList metrics={metrics} />
      {hasAttention && (
        <div ref={attentionRef}>
          <ServiceAttentionList
            service={spec.id}
            name={spec.name}
            data={model.attention}
            basePath={basePath}
            focus={focus}
            criticalTotal={model.critical24h}
          />
        </div>
      )}
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

export function ProviderSeverity({
  model,
  data,
  basePath,
}: {
  model: ServiceModel;
  data: PlatformData;
  basePath: string;
}) {
  if (!isProvider(model.spec.id)) return null;
  const stats = data.overview.data?.providers?.[model.spec.id];
  if (!stats || stats.events24h === 0) return null;
  const service = model.spec.id;
  return (
    <SeverityBar
      levels={stats.levels24h}
      label={`${model.spec.name}, eventos 24 h`}
      hrefFor={(band) => levelBandHref(basePath, band, service)}
    />
  );
}
