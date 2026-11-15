/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiLoadingContent } from '@elastic/eui';
import {
  AI_MODE_SUMMARY,
  AiActivity,
  AiActivityBacklog,
  AiActivityFeedItem,
  AiActivityHost,
  AiActivityQueue,
  AiActivityToday,
  AiBudget,
  AiRunSummary,
  BRAND_ASSETS_PATH,
  feedSentence,
  formatCount,
  formatMicroUsd,
  formatShare,
  hostState,
  NO_DATA,
  parseMode,
  PRIORITIES,
  todayShareWithoutInference,
} from '../../common';
import { getAiActivity, isAnalystUnavailable, listAiRuns } from '../api/ai_investigations';
import { AiBudgetPanel, AiBudgetTile } from './ai_analyst_budget';
import { alertHref } from './ai_analyst_case_file';
import { AttentionItem, attentionSummary, AttentionSummary, RunFilters } from './ai_analyst_model';
import { AiTile, ReasonTag } from './ai_analyst_parts';
import { openInPlace, runHref, RunTime } from './ai_analyst_runs';
import { useConsole } from './console_context';
import { DataZone, ErrorCallout, Mono, PriorityMark, relativeTime } from './primitives';

export { runHref } from './ai_analyst_runs';

/** Refresco del panel: solo con la pestaña del navegador visible y «Resumen» seleccionado. */
export const ACTIVITY_POLL_MS = 5000;
/** Las listas de pendientes cambian despacio: se releen cada 30 s. */
const ATTENTION_POLL_MS = 30000;
const ATTENTION_PAGE = 20;

/** Tamaño intrínseco de `b89-ai-analyst-bunny-160.webp` (el de 2x es 453×512). */
const MASCOT_WIDTH = 142;
const MASCOT_HEIGHT = 160;

const LIMA_TIME = new Intl.DateTimeFormat('es-PE', {
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'America/Lima',
});

function limaTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? NO_DATA : LIMA_TIME.format(date);
}

function since(iso: string | null, now: number): string {
  return iso ? relativeTime(iso, now) : NO_DATA;
}

/** Mascota del Analista IA (activos de marca servidos en `/ui/b89/`). */
export function AiAnalystMascot({ basePath }: { basePath: string }) {
  const base = `${basePath}${BRAND_ASSETS_PATH}`;
  const small = `${base}/b89-ai-analyst-bunny-160.webp`;
  const large = `${base}/b89-ai-analyst-bunny.webp`;
  return (
    <img
      className="b89AiStatus__mascot"
      src={small}
      srcSet={`${small} 1x, ${large} 2x`}
      width={MASCOT_WIDTH}
      height={MASCOT_HEIGHT}
      alt="Analista IA"
      decoding="async"
      draggable={false}
    />
  );
}

// ------------------------------------------------------------------ Estado

export function AiActivityHeader({
  host,
  basePath,
  now,
  queue = null,
}: {
  host: AiActivityHost;
  basePath: string;
  now: number;
  queue?: AiActivityQueue | null;
}) {
  const state = hostState(host);
  const mode = parseMode(host.mode);
  return (
    <section className="b89AiStatus" data-state={state.state} aria-label="Estado del Analista IA">
      <AiAnalystMascot basePath={basePath} />
      <div className="b89AiStatus__body">
        <p className="b89AiStatus__state" role="status">
          <span
            aria-hidden="true"
            className="b89AiStatus__dot"
            data-tone={state.tone}
            data-pulse={state.pulsing ? 'true' : 'false'}
          />
          <strong>{state.label}</strong>
          {state.detail && <span className="b89AiStatus__detail">· {state.detail}</span>}
        </p>
        {state.state === 'active' && mode && (
          <p className="b89AiStatus__mode">El analista {AI_MODE_SUMMARY[mode]}.</p>
        )}
        <dl className="b89AiStatus__facts">
          <div>
            <dt>Último ciclo</dt>
            <dd>{since(host.lastTickAt, now)}</dd>
          </div>
          <div>
            <dt>Último expediente terminado</dt>
            <dd>{since(host.lastProcessedAt, now)}</dd>
          </div>
          <div>
            <dt>En curso / simultáneas</dt>
            <dd className="b89Tabular">
              {formatCount(host.inFlight)} / {formatCount(host.concurrency)}
            </dd>
          </div>
          {queue && (
            <div>
              <dt>En cola</dt>
              <dd className="b89Tabular">{formatCount(queue.queued)}</dd>
            </div>
          )}
        </dl>
        {host.lastErrorCode && (
          <p className="b89AiStatus__error" role="status">
            Último fallo sin superar: <ReasonTag code={host.lastErrorCode} />
          </p>
        )}
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ Atención

const ATTENTION_KIND_LABEL: Record<AttentionItem['kind'], string> = {
  review: 'Requiere revisión',
  failed: 'Falló o quedó incompleta',
  escalated: 'Escalada a incidente',
};

/**
 * «Necesita tu atención»: lo primero que mira una persona. Cada cifra lleva a la lista filtrada y
 * cada fila al expediente.
 */
export function AiAttentionPanel({
  summary,
  basePath,
  now,
  loading = false,
  error = null,
  onRetry,
  onSelect,
  onFilter,
}: {
  summary: AttentionSummary | null;
  basePath: string;
  now: number;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  onSelect: (id: string) => void;
  onFilter?: (patch: Partial<RunFilters>) => void;
}) {
  const plus = summary && summary.capped ? '+' : '';
  const total = summary ? summary.review + summary.failed + summary.escalated : 0;
  return (
    <section className="b89Panel b89AiAttention" aria-labelledby="b89AiAttentionTitle">
      <div className="b89Panel__header">
        <h2 id="b89AiAttentionTitle">Necesita tu atención</h2>
        <span className="b89Panel__meta">Últimas 24 horas</span>
      </div>
      {!summary ? (
        error != null ? (
          <div className="b89AiEmpty" role="status">
            <p>No se pudo leer la lista de pendientes.</p>
            {onRetry && (
              <EuiButtonEmpty size="xs" flush="left" onClick={onRetry}>
                Reintentar
              </EuiButtonEmpty>
            )}
          </div>
        ) : loading ? (
          <EuiLoadingContent lines={3} />
        ) : null
      ) : (
        <>
          <div className="b89AiAttention__tiles">
            <AiTile
              label="Revisión pendiente"
              value={`${formatCount(summary.review)}${summary.review > 0 ? plus : ''}`}
              tone={summary.review > 0 ? 'warn' : 'ok'}
              hint="El resultado no superó la verificación: decide una persona"
              onClick={onFilter ? () => onFilter({ status: 'requires_review', view: 'all' }) : undefined}
            />
            <AiTile
              label="Fallidas o incompletas"
              value={`${formatCount(summary.failed)}${summary.failed > 0 ? plus : ''}`}
              tone={summary.failed > 0 ? 'fail' : 'ok'}
              hint="Sin recomendación fiable: reintentar o revisar a mano"
              onClick={onFilter ? () => onFilter({ status: '', view: 'attention' }) : undefined}
            />
            <AiTile
              label="Escaladas a incidente"
              value={formatCount(summary.escalated)}
              tone={summary.escalated > 0 ? 'info' : 'neutral'}
              hint="El analista abrió o vinculó un incidente"
              onClick={onFilter ? () => onFilter({ status: '', view: 'escalated' }) : undefined}
            />
          </div>
          {total === 0 ? (
            <p className="b89AiAttention__clear" role="status">
              <span aria-hidden="true">✓</span> Nada pendiente: ninguna investigación espera revisión
              ni falló en las últimas 24 horas.
            </p>
          ) : (
            <ol className="b89AiAttention__list" aria-label="Pendientes más urgentes">
              {summary.items.map((item) => (
                <li key={item.key}>
                  <a
                    className="b89AiAttention__item"
                    href={runHref(basePath, item.jobId)}
                    data-kind={item.kind}
                    onClick={(event) => openInPlace(event, () => onSelect(item.jobId))}
                  >
                    <span className="b89AiAttention__priority">
                      {item.priority ? (
                        <PriorityMark priority={item.priority} />
                      ) : (
                        <span className="b89Muted">{NO_DATA}</span>
                      )}
                    </span>
                    <span className="b89AiAttention__body">
                      <span className="b89AiAttention__title" data-b89-no-translate="">
                        {item.title || item.jobId}
                      </span>
                      <span className="b89AiAttention__kind">{ATTENTION_KIND_LABEL[item.kind]}</span>
                    </span>
                    <span className="b89AiAttention__time">
                      <RunTime iso={item.at} now={now} />
                    </span>
                  </a>
                </li>
              ))}
            </ol>
          )}
          {error != null && (
            <p className="b89Ai__note" role="status">
              No se pudo actualizar la lista de pendientes: se muestra la última lectura.
            </p>
          )}
        </>
      )}
    </section>
  );
}

// ------------------------------------------------------------------ Indicadores del día

export function AiActivityKpis({
  today,
  budget = null,
}: {
  today: AiActivityToday;
  budget?: AiBudget | null;
}) {
  const share = todayShareWithoutInference(today);
  return (
    <section className="b89AiKpis" aria-label="Actividad de hoy">
      <div className="b89AiKpis__grid">
        <AiTile
          label="Investigadas hoy"
          value={formatCount(today.runs)}
          hint={
            share === null
              ? `${formatCount(today.withoutInference)} resueltas sin IA`
              : `${formatShare(share)} resueltas sin IA, sin costo de modelo`
          }
        />
        <AiTile
          label="Escaladas a incidente"
          value={formatCount(today.escalated)}
          hint={`${formatCount(today.incidentsCreated)} a incidente nuevo · ${formatCount(
            today.incidentsAttached,
          )} a uno existente`}
        />
        <AiTile
          label="Cerradas como benignas"
          value={formatCount(today.closedBenign)}
          hint={`Revisión pedida: ${formatCount(today.reviewRequested)} (${formatCount(
            today.reviewImmediate,
          )} inmediata · ${formatCount(today.reviewDigest)} en resumen)`}
        />
        <AiBudgetTile budget={budget} />
      </div>
      <p className="b89Ai__note">
        Hoy {today.day ? <Mono>{today.day}</Mono> : null} · día de Lima, desde las 00:00 · costo de
        modelo: {formatMicroUsd(today.estimatedMicroUsd)} · fallidas: {formatCount(today.failed)}
      </p>
    </section>
  );
}

// ------------------------------------------------------------------ Cola

export function AiActivityQueuePanel({
  queue,
  backlog,
  now,
}: {
  queue: AiActivityQueue;
  backlog: AiActivityBacklog;
  now: number;
}) {
  return (
    <section className="b89Panel" aria-labelledby="b89AiQueueTitle">
      <div className="b89Panel__header">
        <h2 id="b89AiQueueTitle">Cola del analista</h2>
        <span className="b89Panel__meta">
          {formatCount(queue.queued)} en cola · {formatCount(queue.running)} en curso
        </span>
      </div>
      <ul className="b89AiQueue__priorities" aria-label="En cola por prioridad">
        {PRIORITIES.map((priority) => (
          <li key={priority}>
            <PriorityMark priority={priority} />
            <strong className="b89Tabular">{formatCount(queue.byPriority[priority])}</strong>
          </li>
        ))}
      </ul>
      <dl className="b89AiQueue__facts">
        <div>
          <dt>Más antiguo en cola</dt>
          <dd>{queue.oldestQueuedAt ? since(queue.oldestQueuedAt, now) : 'Sin cola'}</dd>
        </div>
        <div>
          <dt>Alertas abiertas sin expediente</dt>
          <dd className="b89Tabular">{formatCount(backlog.openAlertsWithoutCaseFile)}</dd>
        </div>
        <div>
          <dt>Incidentes abiertos sin expediente</dt>
          <dd className="b89Tabular">{formatCount(backlog.openIncidentsWithoutCaseFile)}</dd>
        </div>
      </dl>
    </section>
  );
}

// ------------------------------------------------------------------ Feed

function refHref(basePath: string, ref: AiActivityFeedItem['ref']): string | null {
  if (!ref) return null;
  if (ref.kind === 'incident') return `${basePath}/app/b89-incidents?id=${encodeURIComponent(ref.id)}`;
  if (ref.kind === 'alert') return alertHref(basePath, ref.id);
  return null;
}

export function AiActivityFeed({
  feed,
  basePath,
  onSelect,
}: {
  feed: readonly AiActivityFeedItem[];
  basePath: string;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="b89Panel b89AiFeed" aria-labelledby="b89AiFeedTitle">
      <div className="b89Panel__header">
        <h2 id="b89AiFeedTitle">Qué hizo el analista</h2>
        <span className="b89Panel__meta">Últimas 24 horas · hora de Lima</span>
      </div>
      {feed.length === 0 ? (
        <p className="b89Panel__empty">
          Sin actividad en las últimas 24 horas. Cuando entren alertas dentro del alcance
          configurado, el analista las investigará y aparecerán aquí.
        </p>
      ) : (
        <ol className="b89AiFeed__list" role="log" aria-live="polite" aria-label="Actividad del analista">
          {feed.map((item) => {
            const sentence = feedSentence(item);
            const target = refHref(basePath, item.ref);
            return (
              <li key={item.key} className="b89AiFeed__item">
                <time dateTime={item.at} className="b89Tabular b89AiFeed__time">
                  {limaTime(item.at)}
                </time>
                <span className="b89AiFeed__mark">
                  {item.priority ? (
                    <PriorityMark priority={item.priority} />
                  ) : (
                    <span className="b89Muted">{NO_DATA}</span>
                  )}
                </span>
                <span className="b89AiFeed__what">
                  <span className="b89AiFeed__sentence">
                    {sentence.text}
                    {sentence.code && (
                      <>
                        {': '}
                        <ReasonTag code={sentence.code} />
                      </>
                    )}
                  </span>
                  <DataZone className="b89CellMeta b89AiFeed__subject">
                    {item.subjectTitle || <Mono>{item.jobId}</Mono>}
                  </DataZone>
                </span>
                <span className="b89AiFeed__links">
                  <a
                    href={runHref(basePath, item.jobId)}
                    onClick={(event) => openInPlace(event, () => onSelect(item.jobId))}
                  >
                    Expediente
                  </a>
                  {target && item.ref && (
                    <a href={target} title={item.ref.id}>
                      {item.ref.kind === 'incident' ? 'Incidente' : 'Alerta'}
                    </a>
                  )}
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

// ------------------------------------------------------------------ Panel completo

export function AiActivityPanel({
  activity,
  basePath,
  now,
  onSelect,
  budget = null,
  attention = null,
  attentionLoading = false,
  attentionError = null,
  onRetryAttention,
  onFilter,
}: {
  activity: AiActivity;
  basePath: string;
  now: number;
  onSelect: (id: string) => void;
  budget?: AiBudget | null;
  attention?: AttentionSummary | null;
  attentionLoading?: boolean;
  attentionError?: unknown;
  onRetryAttention?: () => void;
  onFilter?: (patch: Partial<RunFilters>) => void;
}) {
  const summary =
    attention ??
    (attentionLoading || attentionError != null
      ? null
      : attentionSummary({ runs: [], feed: activity.feed, now }));
  return (
    <div className="b89AiOverview">
      <AiActivityHeader host={activity.host} basePath={basePath} now={now} queue={activity.queue} />
      <AiAttentionPanel
        summary={summary}
        basePath={basePath}
        now={now}
        loading={attentionLoading}
        error={attentionError}
        onRetry={onRetryAttention}
        onSelect={onSelect}
        onFilter={onFilter}
      />
      <AiActivityKpis today={activity.today} budget={budget} />
      <div className="b89AiOverview__columns">
        <AiActivityFeed feed={activity.feed} basePath={basePath} onSelect={onSelect} />
        <div className="b89AiOverview__side">
          <AiActivityQueuePanel queue={activity.queue} backlog={activity.backlog} now={now} />
          {budget && <AiBudgetPanel budget={budget} />}
        </div>
      </div>
    </div>
  );
}

/** Pendientes para «Necesita tu atención»: revisión y fallos, independientes de los filtros. */
function useAttentionRuns(visible: boolean) {
  const { api } = useConsole();
  const [runs, setRuns] = useState<readonly AiRunSummary[] | null>(null);
  const [capped, setCapped] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    try {
      const pages = await Promise.all([
        listAiRuns(api, { status: 'requires_review', pageSize: ATTENTION_PAGE }),
        listAiRuns(api, { status: 'failed', pageSize: ATTENTION_PAGE }),
      ]);
      if (!mounted.current) return;
      setRuns(pages.reduce<AiRunSummary[]>((all, page) => all.concat(page.items), []));
      setCapped(pages.some((page) => page.nextCursor !== null));
      setError(null);
    } catch (failure) {
      if (mounted.current) setError(failure);
    }
  }, [api]);

  useEffect(() => {
    if (!visible) return undefined;
    void load();
    const timer = window.setInterval(() => void load(), ATTENTION_POLL_MS);
    return () => window.clearInterval(timer);
  }, [visible, load]);

  return { runs, capped, error, reload: load };
}

/**
 * Pestaña «Resumen». Monta solo con la pestaña seleccionada; el sondeo se pausa con el
 * navegador oculto. Un fallo durante el sondeo conserva lo visible y lo dice.
 */
export function AiActivityTab({
  basePath,
  visible,
  onSelect,
  budget = null,
  recentRuns = [],
  onFilter,
}: {
  basePath: string;
  visible: boolean;
  onSelect: (id: string) => void;
  budget?: AiBudget | null;
  /** Investigaciones ya cargadas por la lista (suman estados parciales y sin presupuesto). */
  recentRuns?: readonly AiRunSummary[];
  onFilter?: (patch: Partial<RunFilters>) => void;
}) {
  const { api } = useConsole();
  const [activity, setActivity] = useState<AiActivity | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const busy = useRef(false);
  const mounted = useRef(true);
  const attention = useAttentionRuns(visible);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    try {
      const next = await getAiActivity(api);
      if (!mounted.current) return;
      setActivity(next);
      setError(null);
    } catch (failure) {
      if (mounted.current) setError(failure);
    } finally {
      busy.current = false;
      if (mounted.current) {
        setLoading(false);
        setNow(Date.now());
      }
    }
  }, [api]);

  useEffect(() => {
    if (!visible) return undefined;
    void load();
    const timer = window.setInterval(() => void load(), ACTIVITY_POLL_MS);
    return () => window.clearInterval(timer);
  }, [visible, load]);

  if (!activity) {
    if (loading) return <EuiLoadingContent lines={6} />;
    if (isAnalystUnavailable(error)) {
      return (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="offline"
          title="El panel de actividad no está publicado en este entorno"
        >
          <p>
            El servicio no expone la actividad del analista. Las pestañas «Investigaciones»,
            «Informes» y «Configuración» siguen disponibles.
          </p>
          <EuiButtonEmpty size="xs" flush="left" onClick={() => void load()}>
            Volver a comprobar
          </EuiButtonEmpty>
        </EuiCallOut>
      );
    }
    return <ErrorCallout error={error} onRetry={() => void load()} />;
  }
  const summary = attention.runs
    ? attentionSummary({
        runs: [...attention.runs, ...recentRuns],
        feed: activity.feed,
        now,
        capped: attention.capped,
      })
    : null;
  return (
    <>
      <AiActivityPanel
        activity={activity}
        basePath={basePath}
        now={now}
        onSelect={onSelect}
        budget={budget}
        attention={summary}
        attentionLoading={attention.runs === null && attention.error == null}
        attentionError={attention.error}
        onRetryAttention={() => void attention.reload()}
        onFilter={onFilter}
      />
      <p className="b89Ai__note" role="status">
        {error != null
          ? 'No se pudo actualizar: se muestra la última lectura.'
          : visible
            ? 'Se actualiza cada 5 s.'
            : 'Actualización en pausa mientras la pestaña está oculta.'}
      </p>
    </>
  );
}
