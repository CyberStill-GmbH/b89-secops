/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useRef } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiLoadingContent } from '@elastic/eui';
import {
  ALERTS_PATH,
  Alert,
  CAPABILITIES,
  dashboardHref,
  integrationSpec,
  levelBand,
  Page,
  PRIORITIES,
  Priority,
  PROVIDER_DASHBOARDS,
  TopEvent,
} from '../../common';
import { cleanAlertTitle, explainAlert } from '../../common/alert_why';
import { useChanges, useConsole } from './console_context';
import {
  formatNumber,
  LEVEL_COLOR,
  LevelLegend,
  PlatformData,
  SeverityBar,
  TrendChart,
  useInterval,
  usePlatformData,
} from './overview_parts';
import {
  AI_ANALYST_ACTOR,
  AsyncState,
  ErrorCallout,
  PriorityMark,
  relativeTime,
  Timestamp,
  useAsync,
} from './primitives';
import { VendorLogo } from './vendor_logo';
import { indexerUnavailableMessage } from '../../common/indexer_status';
import { vendorOfProvider } from '../../common';
import { alertsQueueHref, PRIORITY_NAME } from './alerts_filters';
import { levelBandHref } from './service_attention';
import { ServiceCard, ServiceModel, serviceModels } from './service_cards';
import {
  AttentionAlert,
  countUnassigned,
  loadAttentionTop,
  plainAttentionWhy,
  whyBelowTitle,
} from './attention_queue';

const REFRESH_MS = 60_000;

export interface QueueSummary {
  readonly open: number;
  readonly byPriority: Readonly<Record<Priority, number>>;
  readonly top: readonly AttentionAlert[];
  /** Abiertas sin responsable entre las cargadas (hasta 100). */
  readonly unassigned: number;
  /** `true` si hay más abiertas que las cargadas: el conteo es un mínimo. */
  readonly unassignedPartial: boolean;
  /** `null` si el rol no puede ver incidentes o la consulta falló (ver `incidentsAccess`). */
  readonly activeIncidents: number | null;
  readonly incidentsAccess: 'ok' | 'forbidden' | 'error';
}

function useQueueSummary() {
  const { api, can } = useConsole();
  return useAsync<QueueSummary | null>(async () => {
    if (!can(CAPABILITIES.alertsRead)) return null;
    const [open, ...counts] = await Promise.all([
      api.get<Page<Alert>>('/alerts', { status: 'open', pageSize: 100 }),
      ...PRIORITIES.map((priority) =>
        api.get<Page<Alert>>('/alerts', { status: 'open', priority, pageSize: 1 }),
      ),
    ]);
    const canIncidents = can(CAPABILITIES.incidentsRead);
    const incidents = canIncidents
      ? await api
          .get<Page<unknown>>('/incidents', { status: 'active', pageSize: 1 })
          .then((page) => page.totalCount ?? page.items.length)
          .catch(() => null)
      : null;
    const byPriority = Object.fromEntries(
      PRIORITIES.map((priority, index) => [priority, counts[index].totalCount ?? 0]),
    ) as Record<Priority, number>;
    // La API ordena por prioridad + riesgo de entidad del correlador + cadena; si no responde,
    // se conserva el orden histórico sobre las alertas ya cargadas.
    const top = await loadAttentionTop(api, open.items, 6);
    const total = open.totalCount ?? open.items.length;
    const unassigned = countUnassigned(open.items, total);
    return {
      open: total,
      byPriority,
      top,
      unassigned: unassigned.count,
      unassignedPartial: unassigned.partial,
      activeIncidents: incidents,
      incidentsAccess: !canIncidents ? 'forbidden' : incidents === null ? 'error' : 'ok',
    };
  }, [api]);
}

/**
 * Conserva el último dato bueno de una carga periódica: una recarga que falla no cambia la lista ni
 * los KPI por un error o por «—» (`useAsync` vacía `data` al fallar; aquí no se toca esa primitiva).
 * `staleSince` es el momento del último dato bueno cuando la recarga más reciente falló.
 */
function useLastGood<T>(state: AsyncState<T>): { data: T | null; staleSince: number | null } {
  const last = useRef<{ data: T; at: number } | null>(null);
  if (state.data != null && last.current?.data !== state.data) {
    last.current = { data: state.data, at: Date.now() };
  }
  const data = state.data ?? last.current?.data ?? null;
  const staleSince =
    state.error != null && state.data == null && last.current ? last.current.at : null;
  return { data, staleSince };
}

function plural(count: number, one: string, many: string): string {
  return `${formatNumber(count)} ${count === 1 ? one : many}`;
}

/**
 * La respuesta del inicio, en una frase: qué hay abierto, cuánto falta asignar y por dónde empezar.
 * `first` es la alerta para «Empieza por: …» (o null si la cola está al día).
 */
export function answerLine(queue: QueueSummary): { text: string; first: AttentionAlert | null } {
  if (queue.open === 0) {
    return { text: 'La cola está al día. No hay alertas abiertas.', first: null };
  }
  const { P1, P2 } = queue.byPriority;
  const unassigned =
    queue.unassigned === 0 && !queue.unassignedPartial
      ? 'todas tienen responsable'
      : `${queue.unassignedPartial ? 'al menos ' : ''}${formatNumber(queue.unassigned)} sin responsable`;
  const head =
    P1 + P2 > 0
      ? `Tienes ${plural(P1, 'alerta', 'alertas')} P1 y ${formatNumber(P2)} P2 abiertas; ${unassigned}.`
      : `Tienes ${plural(queue.open, 'alerta abierta', 'alertas abiertas')}, ninguna P1 ni P2; ${unassigned}.`;
  return { text: head, first: queue.top[0] ?? null };
}

function alertHref(basePath: string, id: string): string {
  return `${basePath}${ALERTS_PATH}?id=${encodeURIComponent(id)}`;
}

function AnswerLine({
  queue,
  allowed,
  failed,
  basePath,
}: {
  queue: QueueSummary | null;
  allowed: boolean;
  failed: boolean;
  basePath: string;
}) {
  if (!allowed) {
    return (
      <p className="b89Answer">
        Tu rol no tiene permiso para ver la cola de alertas. Pide acceso a tu administrador.
      </p>
    );
  }
  if (!queue) {
    return (
      <p className="b89Answer">
        {failed
          ? 'No se pudo cargar la cola de alertas. Reintenta con «Actualizar».'
          : 'Cargando la cola de alertas…'}
      </p>
    );
  }
  const { text, first } = answerLine(queue);
  return (
    <p className="b89Answer">
      {text}
      {first && (
        <>
          {' '}
          Empieza por:{' '}
          <a href={alertHref(basePath, first.id)} data-b89-no-translate="">
            {cleanAlertTitle(first.title)}
          </a>
          .
        </>
      )}
    </p>
  );
}

/** Responsable en texto plano (dentro de un enlace no cabe un tooltip enfocable). */
function ownerText(assigneeId: string | null, viewerId: string): string {
  if (!assigneeId) return 'Sin responsable';
  if (assigneeId === viewerId) return 'Responsable: Tú';
  if (assigneeId === AI_ANALYST_ACTOR) return 'Responsable: Analista IA';
  return 'Responsable: otro analista';
}

export function AttentionItem({
  alert,
  basePath,
  viewerId,
}: {
  alert: AttentionAlert;
  basePath: string;
  viewerId: string;
}) {
  const why = explainAlert(alert);
  const detail = whyBelowTitle(why.title, why.line);
  const raised = plainAttentionWhy(alert.attention?.why);
  return (
    <li>
      <a className="b89Feed__item" href={alertHref(basePath, alert.id)}>
        <PriorityMark priority={alert.priority} />
        <span className="b89Feed__body">
          <span className="b89Feed__title" data-b89-no-translate="">
            {why.title}
          </span>
          {detail && (
            <span className="b89Feed__line" data-b89-no-translate="">
              {detail}
            </span>
          )}
          {raised && <span className="b89Feed__why">{raised}</span>}
        </span>
        <span className="b89Feed__side">
          <span className="b89Feed__time">
            <Timestamp iso={alert.occurredAt} focusable={false} />
          </span>
          <span className="b89Feed__owner" data-unassigned={!alert.assigneeId}>
            {ownerText(alert.assigneeId, viewerId)}
          </span>
        </span>
      </a>
    </li>
  );
}

const PROBLEM_TONES = new Set(['warn', 'fail']);

/** Servicios: solo los que tienen problemas, y una línea para el resto. */
function ServicesSection({ models, basePath }: { models: ServiceModel[]; basePath: string }) {
  const settled = models.filter((model) => !model.loading);
  const problems = settled.filter((model) => PROBLEM_TONES.has(model.status.tone));
  const ok = settled.filter((model) => model.status.tone === 'ok').length;
  const other = settled.length - ok - problems.length;
  const pending = models.length - settled.length;
  const parts = [`${ok} de ${models.length} servicios operativos`];
  if (problems.length) parts.push(plural(problems.length, 'con problemas', 'con problemas'));
  if (other) parts.push(`${other} sin datos o sin configurar`);
  if (pending) parts.push(`${pending} consultando…`);
  return (
    <section aria-labelledby="b89-services-title">
      <div className="b89SectionTitle">
        <h2 id="b89-services-title">
          {problems.length ? 'Servicios con problemas' : 'Servicios integrados'}
        </h2>
        <EuiButtonEmpty size="xs" href={`${basePath}/app/b89-integrations`} flush="right">
          Ver integraciones
        </EuiButtonEmpty>
      </div>
      <p className="b89Services__summary">
        {problems.length === 0 && pending === 0 && other === 0
          ? `Todos los servicios funcionan: ${parts[0]}.`
          : `${parts.join(' · ')}.`}
      </p>
      {problems.length > 0 && (
        <div className="b89ServiceGrid">
          {problems.map((model) => (
            <ServiceCard key={model.spec.id} model={model} basePath={basePath} compact />
          ))}
        </div>
      )}
    </section>
  );
}

export function OverviewView({ basePath }: { basePath: string }) {
  const { session, can } = useConsole();
  const data = usePlatformData(basePath);
  const queue = useQueueSummary();
  const reloadData = data.reload;
  const reloadQueue = queue.reload;
  // Estable entre renderizados: si no, el intervalo se reinicia en cada render y nunca dispara.
  const reloadAll = useCallback(() => {
    reloadData();
    reloadQueue();
  }, [reloadData, reloadQueue]);
  useInterval(reloadAll, REFRESH_MS);
  useChanges(['alert', 'incident'], () => reloadQueue());

  const keptOverview = useLastGood(data.overview);
  const keptQueue = useLastGood(queue);
  const overview = keptOverview.data;
  const queueData = keptQueue.data;
  // Con datos anteriores, un fallo de recarga no vacía las tarjetas: se avisa arriba.
  const shown: PlatformData = {
    ...data,
    overview: {
      ...data.overview,
      data: overview,
      error: keptOverview.staleSince !== null ? null : data.overview.error,
    },
  };
  const staleSince = [keptOverview.staleSince, keptQueue.staleSince].filter(
    (value): value is number => value !== null,
  );
  const alertsAllowed = can(CAPABILITIES.alertsRead);

  return (
    <main className="b89Page b89Overview" lang="es-PE" translate="no">
      <header className="b89Hero">
        <div className="b89Hero__text">
          <h1>Resumen del SOC</h1>
          <AnswerLine
            queue={queueData}
            allowed={alertsAllowed}
            failed={queue.error != null}
            basePath={basePath}
          />
        </div>
        <div className="b89Hero__actions">
          {overview && (
            <span className="b89Hero__updated">
              Actualizado <Timestamp iso={overview.generatedAt} />
            </span>
          )}
          <EuiButtonEmpty
            size="s"
            iconType="refresh"
            onClick={reloadAll}
            isLoading={data.overview.loading || queue.loading}
          >
            Actualizar
          </EuiButtonEmpty>
        </div>
      </header>

      {staleSince.length > 0 && (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="clock"
          title={`No se pudo actualizar. Ves los datos de ${relativeTime(
            new Date(Math.min(...staleSince)).toISOString(),
          )}.`}
        >
          <EuiButtonEmpty size="xs" flush="left" onClick={reloadAll}>
            Reintentar
          </EuiButtonEmpty>
        </EuiCallOut>
      )}
      {data.overview.error != null && !overview && (
        <ErrorCallout error={data.overview.error} onRetry={data.overview.reload} />
      )}
      {overview?.alertsAccess === 'forbidden' && (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="lock"
          title="Tu rol no tiene permiso para ver los eventos del SIEM. Pide acceso a tu administrador."
        />
      )}

      {alertsAllowed && (
        <section className="b89Panel" aria-labelledby="b89-attention-title">
          <div className="b89Panel__header">
            <h2 id="b89-attention-title">Alertas que requieren atención</h2>
            <EuiButtonEmpty size="xs" href={`${basePath}${ALERTS_PATH}`} flush="right">
              Ir a la cola
            </EuiButtonEmpty>
          </div>
          {queue.error != null && !queueData ? (
            <ErrorCallout error={queue.error} onRetry={reloadQueue} />
          ) : !queueData ? (
            <EuiLoadingContent lines={5} />
          ) : queueData.top.length === 0 ? (
            <p className="b89Panel__empty">
              No hay alertas abiertas. La cola está al día; las nuevas aparecerán aquí.
            </p>
          ) : (
            <ol className="b89Feed b89Feed--attention">
              {queueData.top.map((alert) => (
                <AttentionItem
                  key={alert.id}
                  alert={alert}
                  basePath={basePath}
                  viewerId={session.subjectId}
                />
              ))}
            </ol>
          )}
        </section>
      )}

      <KpiRow
        data={shown}
        queue={queueData}
        queueLoading={queue.loading}
        queueFailed={queue.error != null}
        alertsAllowed={alertsAllowed}
        basePath={basePath}
      />

      <ServicesSection models={serviceModels(shown)} basePath={basePath} />

      <section className="b89Panel b89Panel--fold" aria-labelledby="b89-siem-title">
        <details className="b89Guide__details">
          <summary>
            <span id="b89-siem-title">Tendencia y eventos destacados del SIEM</span>
          </summary>
          <div className="b89Fold">
            <div className="b89Fold__block">
              <div className="b89Panel__header">
                <h3>Eventos del SIEM por nivel</h3>
                <span className="b89Panel__meta">Todas las fuentes</span>
              </div>
              {overview?.siem ? (
                <TrendChart
                  trend24h={overview.siem.trend24h}
                  trend7d={overview.siem.trend7d}
                  hrefFor={(band, from) => levelBandHref(basePath, band, undefined, from)}
                />
              ) : data.overview.loading ? (
                <EuiLoadingContent lines={5} />
              ) : (
                <p className="b89Panel__empty">
                  {indexerUnavailableMessage({
                    failed: data.overview.error != null,
                    access: overview?.alertsAccess ?? null,
                  })}
                </p>
              )}
            </div>
            <div className="b89Fold__block">
              <div className="b89Panel__header">
                <h3>Eventos destacados del SIEM</h3>
                <span className="b89Panel__meta">Nivel 8 o más · últimos 7 días</span>
              </div>
              {!overview ? (
                data.overview.loading ? (
                  <EuiLoadingContent lines={5} />
                ) : (
                  <p className="b89Panel__empty">
                    {/* Sin resumen no hay `alertsAccess`: el motivo sale del error de carga. */}
                    {indexerUnavailableMessage({
                      failed: data.overview.error != null,
                      access: null,
                    })}
                  </p>
                )
              ) : overview.topEvents.length === 0 ? (
                <p className="b89Panel__empty">Ningún evento de nivel 8 o más en 7 días.</p>
              ) : (
                <ol className="b89Feed">
                  {overview.topEvents.map((event) => (
                    <TopEventItem key={event.id} event={event} basePath={basePath} />
                  ))}
                </ol>
              )}
            </div>
          </div>
        </details>
      </section>
    </main>
  );
}

function TopEventItem({ event, basePath }: { event: TopEvent; basePath: string }) {
  const band = levelBand(event.level);
  const source = event.provider ? integrationSpec(event.provider).name : (event.agent ?? 'Wazuh');
  const href = event.provider
    ? `${basePath}${dashboardHref(PROVIDER_DASHBOARDS[event.provider])}`
    : `${basePath}/app/threat-hunting`;
  return (
    <li>
      <a className="b89Feed__item" href={href} title={`Regla ${event.ruleId}`}>
        <span className="b89Level" style={{ borderColor: LEVEL_COLOR[band] }}>
          <span className="b89Level__label">Nivel</span>
          <span className="b89Tabular">{event.level}</span>
        </span>
        <span className="b89Feed__body">
          <span className="b89Feed__title" data-b89-no-translate="">
            {event.description}
          </span>
          <span className="b89Feed__meta">
            <VendorLogo
              id={vendorOfProvider(event.provider)}
              basePath={basePath}
              size="s"
              decorative
            />{' '}
            {source}
          </span>
        </span>
        <span className="b89Feed__time">
          <Timestamp iso={event.at || null} focusable={false} />
        </span>
      </a>
    </li>
  );
}

export function KpiRow({
  data,
  queue,
  queueLoading,
  queueFailed = false,
  alertsAllowed = true,
  basePath,
}: {
  data: PlatformData;
  queue: QueueSummary | null;
  queueLoading: boolean;
  queueFailed?: boolean;
  alertsAllowed?: boolean;
  basePath: string;
}) {
  const overview = data.overview.data;
  const agents = overview?.agents;
  const siem = overview?.siem;
  const pending = <span className="b89Kpi__pending">—</span>;
  const incidentsSub = !queue
    ? queueLoading
      ? 'Cargando…'
      : 'Sin dato'
    : queue.incidentsAccess === 'forbidden'
      ? 'Sin permiso para ver incidentes'
      : queue.incidentsAccess === 'error'
        ? 'No se pudo consultar'
        : 'Abiertos, contenidos o erradicados';
  return (
    <div className="b89KpiRow">
      <div className="b89Kpi">
        <a className="b89Kpi__main" href={alertsQueueHref(basePath)}>
          <span className="b89Kpi__label">Alertas abiertas</span>
          <span className="b89Kpi__value b89Tabular">
            {queue ? formatNumber(queue.open) : queueLoading ? pending : '—'}
          </span>
        </a>
        <span className="b89Kpi__sub">
          {queue
            ? PRIORITIES.map((priority) => (
                <a
                  key={priority}
                  className="b89Kpi__chip"
                  href={alertsQueueHref(basePath, priority)}
                  aria-label={`${formatNumber(queue.byPriority[priority])} alertas abiertas ${priority} ${PRIORITY_NAME[priority]}: ver solo estas`}
                >
                  <PriorityMark priority={priority} />
                  <span className="b89Kpi__chipName">{PRIORITY_NAME[priority]}</span>
                  <strong className="b89Tabular">{formatNumber(queue.byPriority[priority])}</strong>
                </a>
              ))
            : !alertsAllowed
              ? 'Sin permiso para ver alertas'
              : queueFailed
                ? 'No se pudo cargar la cola'
                : queueLoading
                  ? 'Cargando…'
                  : 'Sin dato'}
        </span>
      </div>
      <div className="b89Kpi">
        <span className="b89Kpi__label">Eventos SIEM · 24 h</span>
        <span className="b89Kpi__value b89Tabular">
          {siem ? formatNumber(siem.total24h) : data.overview.loading ? pending : '—'}
        </span>
        {siem ? (
          <>
            <SeverityBar
              levels={siem.levels24h}
              label="Eventos de 24 h por nivel"
              hrefFor={(band) => levelBandHref(basePath, band)}
            />
            <LevelLegend
              levels={siem.levels24h}
              hrefFor={(band) => levelBandHref(basePath, band)}
            />
          </>
        ) : (
          <span className="b89Kpi__sub">
            {overview?.alertsAccess === 'forbidden'
              ? 'Sin permiso para ver eventos del SIEM'
              : 'Sin datos del SIEM'}
          </span>
        )}
      </div>
      <a className="b89Kpi" href={`${basePath}/app/endpoints-summary`}>
        <span className="b89Kpi__label">Agentes activos</span>
        <span className="b89Kpi__value b89Tabular">
          {agents && agents.total > 0
            ? `${formatNumber(agents.active)}/${formatNumber(agents.total)}`
            : data.overview.loading
              ? pending
              : '—'}
        </span>
        <span className="b89Kpi__sub">
          {agents && agents.disconnected > 0
            ? `${agents.disconnected} desconectado${agents.disconnected === 1 ? '' : 's'}`
            : siem
              ? `${formatNumber(siem.agentsWithAlerts24h)} con alertas en 24 h`
              : overview?.monitoringAccess === 'forbidden'
                ? 'Sin permiso para ver agentes'
                : 'Sin dato'}
        </span>
      </a>
      <a className="b89Kpi" href={`${basePath}/app/b89-incidents`}>
        <span className="b89Kpi__label">Incidentes activos</span>
        <span className="b89Kpi__value b89Tabular">
          {queue && queue.activeIncidents !== null
            ? formatNumber(queue.activeIncidents)
            : queueLoading
              ? pending
              : '—'}
        </span>
        <span className="b89Kpi__sub">{incidentsSub}</span>
      </a>
    </div>
  );
}
