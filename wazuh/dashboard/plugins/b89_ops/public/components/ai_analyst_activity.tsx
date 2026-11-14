/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiLoadingContent } from '@elastic/eui';
import {
  AiActivity,
  AiActivityBacklog,
  AiActivityFeedItem,
  AiActivityHost,
  AiActivityQueue,
  AiActivityToday,
  BRAND_ASSETS_PATH,
  feedSentence,
  formatCount,
  formatMicroUsd,
  formatShare,
  hostState,
  NO_DATA,
  PRIORITIES,
  todayShareWithoutInference,
} from '../../common';
import { getAiActivity, isAnalystUnavailable } from '../api/ai_investigations';
import { alertHref } from './ai_analyst_case_file';
import { useConsole } from './console_context';
import { DataZone, ErrorCallout, Mono, PriorityMark, relativeTime } from './primitives';

/** Refresco del panel: solo con la pestaña del navegador visible y «Actividad» seleccionada. */
export const ACTIVITY_POLL_MS = 5000;

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
      className="b89AiActivity__mascot"
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

export function AiActivityHeader({
  host,
  basePath,
  now,
}: {
  host: AiActivityHost;
  basePath: string;
  now: number;
}) {
  const state = hostState(host);
  return (
    <section className="b89AiActivity__header" aria-label="Estado del Analista IA">
      <AiAnalystMascot basePath={basePath} />
      <div className="b89AiActivity__headerBody">
        <p className="b89AiActivity__state" data-state={state.state} role="status">
          <span
            aria-hidden="true"
            className="b89AiActivity__dot"
            data-tone={state.tone}
            data-pulse={state.pulsing ? 'true' : 'false'}
          />
          <strong>{state.label}</strong>
          {state.detail && <span> · {state.detail}</span>}
        </p>
        <dl className="b89AiActivity__facts">
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
        </dl>
        {host.lastErrorCode && (
          <p className="b89Ai__note" role="status">
            Último fallo sin superar: <Mono>{host.lastErrorCode}</Mono>
          </p>
        )}
        <p className="b89Ai__note">
          Estado del proceso del servicio que respondió; con varias réplicas, cada una informa el
          suyo.
        </p>
      </div>
    </section>
  );
}

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string | null }) {
  return (
    <div className="b89Ai__stat">
      <dt>{label}</dt>
      <dd>
        <span className="b89Ai__statValue">{value}</span>
        {hint && <span className="b89CellMeta">{hint}</span>}
      </dd>
    </div>
  );
}

export function AiActivityKpis({ today }: { today: AiActivityToday }) {
  const share = todayShareWithoutInference(today);
  return (
    <section className="b89Ai__budget" aria-label="Actividad de hoy">
      <p className="b89Ai__subhead">
        Hoy {today.day ? <Mono>{today.day}</Mono> : null} · día de Lima, desde las 00:00
      </p>
      <dl className="b89Ai__stats">
        <Kpi label="Investigadas" value={formatCount(today.runs)} />
        <Kpi
          label="Resueltas sin IA"
          value={formatCount(today.withoutInference)}
          hint={share === null ? null : `${formatShare(share)} del día, sin costo de modelo`}
        />
        <Kpi
          label="Escaladas"
          value={formatCount(today.escalated)}
          hint={`${formatCount(today.incidentsCreated)} a incidente nuevo / ${formatCount(
            today.incidentsAttached,
          )} a uno existente`}
        />
        <Kpi label="Cerradas benignas" value={formatCount(today.closedBenign)} />
        <Kpi
          label="Revisión pedida"
          value={formatCount(today.reviewRequested)}
          hint={`${formatCount(today.reviewImmediate)} inmediata / ${formatCount(
            today.reviewDigest,
          )} en resumen`}
        />
        <Kpi label="Fallidas" value={formatCount(today.failed)} />
        <Kpi label="Costo estimado" value={formatMicroUsd(today.estimatedMicroUsd)} />
      </dl>
    </section>
  );
}

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
    <section className="b89Ai__budget" aria-label="Cola del analista">
      <p className="b89Ai__subhead">Cola</p>
      <dl className="b89Ai__stats">
        <Kpi
          label="En cola"
          value={formatCount(queue.queued)}
          hint={`${formatCount(queue.running)} en curso`}
        />
        <div className="b89Ai__stat">
          <dt>Por prioridad</dt>
          <dd>
            <span className="b89AiActivity__priorities">
              {PRIORITIES.map((priority) => (
                <span key={priority} className="b89AiActivity__priority">
                  <PriorityMark priority={priority} />{' '}
                  <span className="b89Tabular">{formatCount(queue.byPriority[priority])}</span>
                </span>
              ))}
            </span>
          </dd>
        </div>
        <Kpi
          label="Más antiguo en cola"
          value={queue.oldestQueuedAt ? since(queue.oldestQueuedAt, now) : 'Sin cola'}
        />
        <Kpi
          label="Alertas abiertas sin expediente"
          value={formatCount(backlog.openAlertsWithoutCaseFile)}
        />
        <Kpi
          label="Incidentes abiertos sin expediente"
          value={formatCount(backlog.openIncidentsWithoutCaseFile)}
        />
      </dl>
    </section>
  );
}

function refHref(basePath: string, ref: AiActivityFeedItem['ref']): string | null {
  if (!ref) return null;
  if (ref.kind === 'incident') return `${basePath}/app/b89-incidents?id=${encodeURIComponent(ref.id)}`;
  if (ref.kind === 'alert') return alertHref(basePath, ref.id);
  return null;
}

export function runHref(basePath: string, jobId: string): string {
  return `${basePath}/app/b89-ai-analyst?id=${encodeURIComponent(jobId)}`;
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
    <section className="b89Ai__budget" aria-label="Actividad reciente">
      <p className="b89Ai__subhead">Últimas 24 horas</p>
      {feed.length === 0 ? (
        <p className="b89Ai__note">Sin actividad en las últimas 24 horas.</p>
      ) : (
        <ol className="b89AiActivity__feed" role="log" aria-live="polite" aria-label="Actividad del analista">
          {feed.map((item) => {
            const sentence = feedSentence(item);
            const target = refHref(basePath, item.ref);
            return (
              <li key={item.key} className="b89AiActivity__item">
                <time dateTime={item.at} className="b89Tabular b89AiActivity__time">
                  {limaTime(item.at)}
                </time>
                <span className="b89AiActivity__mark">
                  {item.priority ? <PriorityMark priority={item.priority} /> : <span className="b89Muted">{NO_DATA}</span>}
                </span>
                <span className="b89AiActivity__what">
                  <span>{sentence.text}</span>
                  {sentence.code && (
                    <>
                      {' '}
                      <Mono>{sentence.code}</Mono>
                    </>
                  )}
                  <DataZone className="b89CellMeta b89AiActivity__subject">
                    {item.subjectTitle || <Mono>{item.jobId}</Mono>}
                  </DataZone>
                </span>
                <span className="b89AiActivity__links">
                  <a
                    href={runHref(basePath, item.jobId)}
                    onClick={(event) => {
                      if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
                      event.preventDefault();
                      onSelect(item.jobId);
                    }}
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

export function AiActivityPanel({
  activity,
  basePath,
  now,
  onSelect,
}: {
  activity: AiActivity;
  basePath: string;
  now: number;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="b89AiActivity">
      <AiActivityHeader host={activity.host} basePath={basePath} now={now} />
      <AiActivityKpis today={activity.today} />
      <AiActivityQueuePanel queue={activity.queue} backlog={activity.backlog} now={now} />
      <AiActivityFeed feed={activity.feed} basePath={basePath} onSelect={onSelect} />
    </div>
  );
}

/**
 * Pestaña «Actividad». Monta solo con la pestaña seleccionada; el sondeo se pausa con el
 * navegador oculto. Un fallo durante el sondeo conserva lo visible y lo dice.
 */
export function AiActivityTab({
  basePath,
  visible,
  onSelect,
}: {
  basePath: string;
  visible: boolean;
  onSelect: (id: string) => void;
}) {
  const { api } = useConsole();
  const [activity, setActivity] = useState<AiActivity | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const busy = useRef(false);
  const mounted = useRef(true);

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
    if (loading) return <EuiLoadingContent lines={4} />;
    if (isAnalystUnavailable(error)) {
      return (
        <EuiCallOut size="s" color="warning" iconType="offline" title="El panel de actividad no está publicado en este entorno">
          <p>El servicio no expone la actividad del analista. Las demás pestañas siguen disponibles.</p>
          <EuiButtonEmpty size="xs" flush="left" onClick={() => void load()}>
            Volver a comprobar
          </EuiButtonEmpty>
        </EuiCallOut>
      );
    }
    return <ErrorCallout error={error} onRetry={() => void load()} />;
  }
  return (
    <>
      <AiActivityPanel activity={activity} basePath={basePath} now={now} onSelect={onSelect} />
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
