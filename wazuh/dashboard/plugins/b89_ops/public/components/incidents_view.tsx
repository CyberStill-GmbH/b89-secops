/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
  EuiFieldSearch,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiSelect,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import {
  CAPABILITIES,
  Incident,
  INCIDENT_STATUS_LABEL,
  IncidentCommandName,
  IncidentNote,
  IncidentStatus,
  IncidentTask,
  LinkedAlerts,
  Page,
  ALERT_STATUS_LABEL,
  VERDICT_LABEL,
  TASK_STATUS_LABEL,
  TaskCommandName,
  Timeline,
} from '../../common';
import { cleanAlertTitle } from '../../common/alert_why';
import { B89ApiError } from '../api/client';
import { B89Page, useChanges, useConsole } from './console_context';
import {
  absoluteTime,
  AsyncState,
  EmptyLine,
  ErrorCallout,
  Mono,
  Person,
  PriorityMark,
  SeverityMark,
  Timestamp,
  useAsync,
  useIsMobile,
} from './primitives';
import { alertInvestigationHref } from './investigation_links';
import {
  closeReadiness,
  closureText,
  CONCLUSIONS,
  INCIDENT_COMMAND_DONE,
  LIFECYCLE,
  nextStep,
  timelineLabel,
} from './incident_flow';

type IncidentFilter = 'active' | IncidentStatus;

const FILTERS: ReadonlyArray<{ id: IncidentFilter; label: string }> = [
  { id: 'active', label: 'Activos' },
  { id: 'open', label: INCIDENT_STATUS_LABEL.open },
  { id: 'contained', label: INCIDENT_STATUS_LABEL.contained },
  { id: 'eradicated', label: INCIDENT_STATUS_LABEL.eradicated },
  { id: 'resolved', label: INCIDENT_STATUS_LABEL.resolved },
  { id: 'closed', label: INCIDENT_STATUS_LABEL.closed },
];

const CLOSURE_MIN = 10;
const REASON_MIN = 10;
const REASON_MAX = 500;

/** Título de la fila como botón: el incidente se abre también con teclado. */
export function IncidentTitleCell({
  incident,
  onOpen,
}: {
  incident: Pick<Incident, 'id' | 'title' | 'alertIds'>;
  onOpen: (id: string) => void;
}) {
  return (
    <span className="b89CellTitle">
      <button
        type="button"
        className="b89LinkButton"
        onClick={(event) => {
          event.stopPropagation();
          onOpen(incident.id);
        }}
        data-b89-no-translate=""
      >
        {incident.title}
      </button>
      <span className="b89CellMeta">
        {incident.alertIds.length} {incident.alertIds.length === 1 ? 'alerta' : 'alertas'}
      </span>
    </span>
  );
}

export function IncidentsView({
  selectedId,
  onSelect,
}: {
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}) {
  const { api, session } = useConsole();
  const [filter, setFilter] = useState<IncidentFilter>('active');
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [items, setItems] = useState<readonly Incident[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);

  const page = useAsync(
    () =>
      api.get<Page<Incident>>('/incidents', {
        status: filter,
        q: query || undefined,
        pageSize: 50,
      }),
    [api, filter, query],
  );

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
      setMoreError(null);
    }
  }, [page.data]);

  useChanges(['incident'], () => page.reload());

  const loadMore = async () => {
    if (!cursor || moreBusy) return;
    setMoreBusy(true);
    setMoreError(null);
    try {
      const next = await api.get<Page<Incident>>('/incidents', {
        status: filter,
        q: query || undefined,
        pageSize: 50,
        cursor,
      });
      setItems((current) => [...current, ...next.items]);
      setCursor(next.nextCursor);
    } catch (failure) {
      setMoreError(failure);
    } finally {
      setMoreBusy(false);
    }
  };

  const columns: Array<EuiBasicTableColumn<Incident>> = [
    {
      field: 'severity',
      name: 'Severidad',
      width: '112px',
      render: (value: Incident['severity']) => <SeverityMark severity={value} />,
      mobileOptions: { header: false },
    },
    {
      field: 'title',
      name: 'Incidente',
      truncateText: false,
      render: (_value: string, incident: Incident) => (
        <IncidentTitleCell incident={incident} onOpen={onSelect} />
      ),
      mobileOptions: { header: false },
    },
    {
      field: 'status',
      name: 'Estado',
      width: '120px',
      render: (value: IncidentStatus) => (
        <EuiBadge color="hollow">{INCIDENT_STATUS_LABEL[value]}</EuiBadge>
      ),
    },
    {
      field: 'ownerId',
      name: 'Responsable',
      width: '140px',
      render: (value: string | null) => <Person id={value} viewerId={session.subjectId} />,
    },
    {
      field: 'openedAt',
      name: 'Apertura',
      width: '120px',
      render: (value: string) => <Timestamp iso={value} focusable={false} />,
    },
  ];

  return (
    <B89Page
      title="Incidentes"
      description="Casos abiertos a partir de alertas. Elige uno para ver en qué paso está y qué falta para cerrarlo."
    >
      <EuiTabs size="s" className="b89Tabs">
        {FILTERS.map((tab) => (
          <EuiTab key={tab.id} isSelected={filter === tab.id} onClick={() => setFilter(tab.id)}>
            {tab.label}
            {filter === tab.id && page.data?.totalCount !== undefined && (
              <span className="b89TabCount">{page.data.totalCount}</span>
            )}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size="m" />
      <EuiFieldSearch
        fullWidth
        compressed
        placeholder="Buscar por título"
        value={search}
        onChange={(event) => setSearch(event.target.value.slice(0, 120))}
        onSearch={(value) => setQuery(value.trim().slice(0, 120))}
        aria-label="Buscar incidentes"
      />
      <EuiSpacer size="m" />
      {page.error ? (
        <ErrorCallout error={page.error} onRetry={page.reload} />
      ) : (
        <>
          <EuiBasicTable<Incident>
            items={items as Incident[]}
            columns={columns}
            loading={page.loading}
            responsive
            tableLayout="auto"
            rowProps={(incident) => ({
              // Ayuda para el ratón; con teclado se abre con el botón del título.
              onClick: () => onSelect(incident.id),
              className: `b89Row b89Row--${incident.severity}${
                incident.id === selectedId ? ' euiTableRow-isSelected' : ''
              }`,
            })}
            noItemsMessage={
              page.loading
                ? 'Cargando incidentes…'
                : query
                  ? 'Ningún incidente coincide con la búsqueda.'
                  : 'No hay incidentes en este estado. Se abren desde una alerta con «Abrir incidente».'
            }
          />
          {moreError != null && <ErrorCallout error={moreError} onRetry={() => void loadMore()} />}
          {cursor && (
            <>
              <EuiSpacer size="s" />
              <EuiButtonEmpty size="s" onClick={() => void loadMore()} isLoading={moreBusy}>
                Ver más incidentes
              </EuiButtonEmpty>
            </>
          )}
        </>
      )}
      {selectedId && (
        <IncidentFlyout
          incidentId={selectedId}
          onClose={() => onSelect(null)}
          onChanged={(updated) =>
            setItems((current) => current.map((item) => (item.id === updated.id ? updated : item)))
          }
        />
      )}
    </B89Page>
  );
}

/** Pasos del ciclo de vida con el actual marcado, y el siguiente paso en una frase. */
export function LifecycleSteps({ status }: { status: IncidentStatus }) {
  const current = LIFECYCLE.indexOf(status);
  return (
    <div className="b89Lifecycle">
      <ol className="b89Lifecycle__steps" aria-label="Ciclo de vida del incidente">
        {LIFECYCLE.map((step, index) => (
          <li
            key={step}
            className={`b89Lifecycle__step${index < current ? ' is-done' : ''}${index === current ? ' is-current' : ''}`}
            aria-current={index === current ? 'step' : undefined}
          >
            <span aria-hidden="true">{index < current ? '✓' : index + 1}</span>
            {INCIDENT_STATUS_LABEL[step]}
          </li>
        ))}
      </ol>
      <p className="b89Lifecycle__next">{nextStep(status).hint}</p>
    </div>
  );
}

/** «Lo que falta para cerrar», siempre a la vista mientras el incidente no esté cerrado. */
export function CloseChecklist({
  openRequiredTasks,
  unclassifiedAlerts,
  onGo,
}: {
  openRequiredTasks: number | null;
  unclassifiedAlerts: number | null;
  onGo: (tab: 'tasks' | 'alerts') => void;
}) {
  const readiness = closeReadiness(openRequiredTasks, unclassifiedAlerts);
  if (readiness.items.length === 0) return null;
  return (
    <section className="b89Checklist" aria-label="Lo que falta para cerrar">
      <strong>Para cerrar</strong>
      <ul>
        {readiness.items.map((item) => (
          <li key={item.text} data-ok={item.ok}>
            <span aria-hidden="true">{item.ok ? '✓' : '✗'}</span>
            <span className="b89VisuallyHidden">{item.ok ? 'Cumplido: ' : 'Pendiente: '}</span>
            {item.text}
            {!item.ok && (
              <EuiButtonEmpty size="xs" onClick={() => onGo(item.tab)}>
                {item.tab === 'tasks' ? 'Ver tareas' : 'Ver alertas'}
              </EuiButtonEmpty>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

type DetailTab = 'summary' | 'alerts' | 'tasks' | 'notes' | 'timeline';

function IncidentFlyout({
  incidentId,
  onClose,
  onChanged,
}: {
  incidentId: string;
  onClose: () => void;
  onChanged: (incident: Incident) => void;
}) {
  const { api, can, session, notifications } = useConsole();
  const mobile = useIsMobile();
  const base = `/incidents/${encodeURIComponent(incidentId)}`;
  const loaded = useAsync(() => api.get<{ incident: Incident }>(base), [api, base]);
  const tasks = useAsync(
    () => api.get<Page<IncidentTask> & { openRequiredCount: number }>(`${base}/tasks`, { pageSize: 200 }),
    [api, base],
  );
  const linked = useAsync(() => api.get<LinkedAlerts>(`${base}/alerts`, { pageSize: 200 }), [api, base]);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [tab, setTab] = useState<DetailTab>('summary');
  const [closing, setClosing] = useState(false);
  const [conclusion, setConclusion] = useState('');
  const [closureReason, setClosureReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const titleRef = useRef<HTMLHeadingElement | null>(null);

  useEffect(() => {
    if (loaded.data) setIncident(loaded.data.incident);
  }, [loaded.data]);

  // Al abrir el panel (también en escritorio, donde no atrapa el foco), el foco va al título.
  useEffect(() => {
    titleRef.current?.focus();
  }, [incidentId]);

  useChanges(['incident'], (changes, resync) => {
    if (!closing && (resync || changes.some((c) => c.resource.id === incidentId))) loaded.reload();
  });
  useChanges(['incident_task'], () => tasks.reload());
  useChanges(['alert', 'incident'], () => linked.reload());

  const command = async (name: IncidentCommandName, extra: Record<string, unknown> = {}) => {
    if (!incident) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ incident: Incident }>(`${base}/commands`, {
        name,
        expectedRevision: incident.revision,
        ...extra,
      });
      setIncident(result.incident);
      onChanged(result.incident);
      setClosing(false);
      setClosureReason('');
      setConclusion('');
      notifications.toasts.addSuccess({ title: INCIDENT_COMMAND_DONE[name] ?? 'Incidente actualizado.' });
    } catch (failure) {
      setError(failure);
      if (failure instanceof B89ApiError && failure.code === 'STATE_CONFLICT') loaded.reload();
    } finally {
      setBusy(false);
    }
  };

  const canWrite = can(CAPABILITIES.incidentsWrite);
  const canClose = can(CAPABILITIES.incidentsClose);
  const step = incident ? nextStep(incident.status) : null;
  const openRequired = tasks.data ? tasks.data.openRequiredCount : null;
  const unclassified = linked.data
    ? linked.data.items.filter((alert) => alert.status === 'new' || alert.status === 'acknowledged').length
    : null;
  const readiness = closeReadiness(openRequired, unclassified);
  const reasonLength = closureReason.trim().length;
  const closeBlocked = !conclusion || reasonLength < CLOSURE_MIN || !readiness.ready;
  const conflict = error instanceof B89ApiError && error.code === 'STATE_CONFLICT';

  const footerNote = !incident
    ? null
    : !canWrite
      ? 'Solo lectura: tu rol no puede cambiar incidentes.'
      : incident.status === 'resolved' && !canClose
        ? 'Para cerrarlo hace falta el permiso de cierre: pídeselo a tu líder SOC.'
        : null;

  return (
    <EuiFlyout
      onClose={onClose}
      size={mobile ? 'l' : 'm'}
      ownFocus={mobile}
      className="b89Flyout"
      aria-labelledby="b89IncidentTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <div lang="es-PE" translate="no">
          {incident && <SeverityMark severity={incident.severity} />}
          <EuiSpacer size="xs" />
          <EuiTitle size="s">
            <h2 id="b89IncidentTitle" data-b89-no-translate="" tabIndex={-1} ref={titleRef}>
              {incident?.title ?? 'Incidente'}
            </h2>
          </EuiTitle>
          {incident && (
            <EuiText size="xs" color="subdued">
              <p className="b89AlertHead__facts">
                {INCIDENT_STATUS_LABEL[incident.status]} · Responsable:{' '}
                <Person id={incident.ownerId} viewerId={session.subjectId} /> · abierto{' '}
                <Timestamp iso={incident.openedAt} />
              </p>
            </EuiText>
          )}
          {incident && (
            <>
              <EuiSpacer size="s" />
              <LifecycleSteps status={incident.status} />
            </>
          )}
          <EuiSpacer size="s" />
          <EuiTabs size="s" className="b89Tabs b89Tabs--flush">
            <EuiTab isSelected={tab === 'summary'} onClick={() => setTab('summary')}>
              Resumen
            </EuiTab>
            <EuiTab isSelected={tab === 'tasks'} onClick={() => setTab('tasks')}>
              Tareas{openRequired ? ` (${openRequired} pendientes)` : ''}
            </EuiTab>
            <EuiTab isSelected={tab === 'alerts'} onClick={() => setTab('alerts')}>
              Alertas{incident ? ` (${incident.alertIds.length})` : ''}
            </EuiTab>
            <EuiTab isSelected={tab === 'notes'} onClick={() => setTab('notes')}>
              Notas
            </EuiTab>
            <EuiTab isSelected={tab === 'timeline'} onClick={() => setTab('timeline')}>
              Actividad
            </EuiTab>
          </EuiTabs>
        </div>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <div lang="es-PE" translate="no">
          {loaded.error != null && <ErrorCallout error={loaded.error} onRetry={loaded.reload} />}
          {!incident && loaded.loading && <EmptyLine>Cargando el incidente…</EmptyLine>}
          {incident && !incident.ownerId && incident.status !== 'closed' && canWrite && (
            <>
              <EuiCallOut size="s" color="warning" title="Este incidente no tiene responsable.">
                <EuiButtonEmpty size="xs" flush="left" isLoading={busy} onClick={() => void command('reassign', { ownerId: session.subjectId })}>
                  Asumirlo yo
                </EuiButtonEmpty>
              </EuiCallOut>
              <EuiSpacer size="m" />
            </>
          )}
          {incident && incident.status !== 'closed' && (
            <>
              <CloseChecklist openRequiredTasks={openRequired} unclassifiedAlerts={unclassified} onGo={setTab} />
              <EuiSpacer size="m" />
            </>
          )}
          {incident && closing && (
            <section className="b89AlertForm" aria-label="Cerrar el incidente">
              <EuiTitle size="xxs">
                <h3>Cerrar el incidente</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <EuiFormRow label="Conclusión" fullWidth>
                <EuiSelect
                  fullWidth
                  value={conclusion}
                  onChange={(event) => setConclusion(event.target.value)}
                  options={[
                    { value: '', text: 'Elige una conclusión…' },
                    ...CONCLUSIONS.map((value) => ({ value, text: value })),
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow
                label="Qué pasó y por qué se cierra"
                helpText={`Una o dos frases · ${reasonLength} caracteres (mínimo ${CLOSURE_MIN})`}
                fullWidth
              >
                <EuiTextArea
                  fullWidth
                  rows={4}
                  value={closureReason}
                  onChange={(event) => setClosureReason(event.target.value)}
                />
              </EuiFormRow>
            </section>
          )}
          {incident && tab === 'summary' && (
            <IncidentSummary incident={incident} unclassified={unclassified} onGoAlerts={() => setTab('alerts')} />
          )}
          {incident && tab === 'alerts' && <LinkedAlertsPanel linked={linked} />}
          {incident && tab === 'tasks' && <TasksPanel incident={incident} tasks={tasks} />}
          {incident && tab === 'notes' && <NotesPanel incident={incident} />}
          {incident && tab === 'timeline' && <TimelinePanel incident={incident} />}
        </div>
      </EuiFlyoutBody>
      {incident && step && (
        <EuiFlyoutFooter>
          <div lang="es-PE" translate="no">
            {error != null && (
              <>
                {conflict ? (
                  <EuiCallOut size="s" color="warning" title="Otra persona cambió este incidente.">
                    <p>Se cargó la versión actual: revísala y vuelve a intentarlo.</p>
                  </EuiCallOut>
                ) : (
                  <ErrorCallout error={error} />
                )}
                <EuiSpacer size="s" />
              </>
            )}
            {footerNote && (
              <EuiText size="xs" color="subdued" className="b89FooterHint">
                <p>{footerNote}</p>
              </EuiText>
            )}
            {closing && (
              <EuiText size="xs" color="subdued" className="b89FooterHint">
                <p role="status">
                  {readiness.blocker ??
                    (!conclusion
                      ? 'Elige la conclusión para cerrar.'
                      : reasonLength < CLOSURE_MIN
                        ? `Escribe al menos ${CLOSURE_MIN} caracteres.`
                        : 'Listo para cerrar.')}
                </p>
              </EuiText>
            )}
            {canWrite && (
              <EuiFlexGroup gutterSize="s" responsive={false} wrap justifyContent="flexEnd">
                {closing ? (
                  <>
                    <EuiFlexItem grow={false}>
                      <EuiButtonEmpty onClick={() => setClosing(false)} disabled={busy}>
                        Volver
                      </EuiButtonEmpty>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiButton
                        fill
                        isLoading={busy}
                        isDisabled={closeBlocked}
                        onClick={() =>
                          void command('close', { closureReason: closureText(conclusion, closureReason) })
                        }
                      >
                        Cerrar incidente
                      </EuiButton>
                    </EuiFlexItem>
                  </>
                ) : (
                  <>
                    {step.secondary && (
                      <EuiFlexItem grow={false}>
                        <EuiButton isLoading={busy} onClick={() => void command(step.secondary!.name)}>
                          {step.secondary.label}
                        </EuiButton>
                      </EuiFlexItem>
                    )}
                    {(incident.status === 'resolved' || incident.status === 'closed') && (
                      <EuiFlexItem grow={false}>
                        <EuiButton isLoading={busy} onClick={() => void command('reopen')}>
                          Reabrir
                        </EuiButton>
                      </EuiFlexItem>
                    )}
                    {incident.ownerId && incident.ownerId !== session.subjectId && incident.status !== 'closed' && (
                      <EuiFlexItem grow={false}>
                        <EuiButton isLoading={busy} onClick={() => void command('reassign', { ownerId: session.subjectId })}>
                          Asumir responsabilidad
                        </EuiButton>
                      </EuiFlexItem>
                    )}
                    {step.primary && (step.primary.name !== 'close' || canClose) && (
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          fill
                          isLoading={busy}
                          onClick={() =>
                            step.primary!.name === 'close'
                              ? setClosing(true)
                              : void command(step.primary!.name as IncidentCommandName)
                          }
                        >
                          {step.primary.label}
                        </EuiButton>
                      </EuiFlexItem>
                    )}
                  </>
                )}
              </EuiFlexGroup>
            )}
          </div>
        </EuiFlyoutFooter>
      )}
    </EuiFlyout>
  );
}

export function IncidentSummary({
  incident,
  unclassified,
  onGoAlerts,
}: {
  incident: Incident;
  unclassified: number | null;
  onGoAlerts: () => void;
}) {
  const alerts = incident.alertIds.length;
  return (
    <>
      <EuiTitle size="xxs">
        <h3>Qué se sabe</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="s" className="b89Prose" data-b89-no-translate="">
        <p>{incident.summary || 'Sin resumen. Añade una nota con lo que se sabe.'}</p>
      </EuiText>
      {incident.status === 'closed' && (
        <>
          <EuiSpacer size="m" />
          <EuiTitle size="xxs">
            <h3>Conclusión del cierre</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <EuiText size="s" className="b89Prose" data-b89-no-translate="">
            <p>
              {incident.closureReason || 'Sin conclusión registrada.'}
              {incident.closedAt && <span className="b89Muted"> · {absoluteTime(incident.closedAt)}</span>}
            </p>
          </EuiText>
        </>
      )}
      <EuiSpacer size="m" />
      <p className="b89CellMeta">
        {alerts === 0 ? 'Sin alertas vinculadas' : `${alerts} ${alerts === 1 ? 'alerta vinculada' : 'alertas vinculadas'}`}
        {unclassified ? ` · ${unclassified} sin clasificar` : ''}
        {alerts > 0 && (
          <>
            {' · '}
            <EuiButtonEmpty size="xs" flush="left" onClick={onGoAlerts}>
              Ver alertas
            </EuiButtonEmpty>
          </>
        )}
      </p>
      <details className="b89Guide__details">
        <summary>Identificador del incidente</summary>
        <Mono>{incident.id}</Mono>
      </details>
    </>
  );
}

/** Alertas vinculadas (`GET /api/incidents/:id/alerts`): un incidente no se cierra con alertas sin clasificar. */
function LinkedAlertsPanel({ linked }: { linked: AsyncState<LinkedAlerts> }) {
  const { basePath } = useConsole();
  if (linked.loading && !linked.data) return <EmptyLine>Cargando alertas vinculadas…</EmptyLine>;
  if (linked.error != null) return <ErrorCallout error={linked.error} onRetry={linked.reload} />;
  const data = linked.data!;
  const untriaged = data.items.filter(
    (alert) => alert.status === 'new' || alert.status === 'acknowledged',
  );

  return (
    <>
      <EuiText size="xs" color="subdued">
        <p>
          {data.totalCount} vinculadas
          {untriaged.length > 0 ? ` · ${untriaged.length} sin clasificar` : ''}
          {data.unavailableCount > 0
            ? ` · ${data.unavailableCount} que tu cuenta no puede ver`
            : ''}
          {data.truncated ? ' · se muestran las más recientes' : ''}
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {data.items.length === 0 ? (
        <EmptyLine>Este incidente no tiene alertas que puedas ver.</EmptyLine>
      ) : (
        <ul className="b89TaskList">
          {data.items.map((alert) => (
            <li key={alert.id} className="b89Task">
              <div className="b89Task__main">
                <span className="b89Task__title">
                  <PriorityMark priority={alert.priority} />{' '}
                  <a
                    href={`${basePath}/app/b89-alerts?id=${encodeURIComponent(alert.id)}`}
                    data-b89-no-translate=""
                  >
                    {cleanAlertTitle(alert.title)}
                  </a>
                </span>
                <span className="b89CellMeta">
                  {ALERT_STATUS_LABEL[alert.status]}
                  {alert.verdict ? ` · ${VERDICT_LABEL[alert.verdict]}` : ''} ·{' '}
                  <Timestamp iso={alert.occurredAt} focusable={false} /> ·{' '}
                  <a
                    href={alertInvestigationHref(basePath, alert.id)}
                    aria-label={`Investigar ${cleanAlertTitle(alert.title)}`}
                  >
                    Investigar
                  </a>
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

type TasksState = AsyncState<Page<IncidentTask> & { openRequiredCount: number }>;

function TasksPanel({ incident, tasks }: { incident: Incident; tasks: TasksState }) {
  const { api, can, session, notifications } = useConsole();
  const base = `/incidents/${encodeURIComponent(incident.id)}/tasks`;
  const [title, setTitle] = useState('');
  const [required, setRequired] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const canWrite = can(CAPABILITIES.tasksWrite) && incident.status !== 'closed';

  const run = async (key: string, action: () => Promise<unknown>, done?: string) => {
    setBusy(key);
    setError(null);
    try {
      await action();
      tasks.reload();
      if (done) notifications.toasts.addSuccess({ title: done });
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  };

  const command = (
    task: IncidentTask,
    name: TaskCommandName,
    extra: Record<string, unknown> = {},
    done?: string,
  ) =>
    run(
      task.id,
      () =>
        api.post(`${base}/${encodeURIComponent(task.id)}/commands`, {
          name,
          expectedRevision: task.revision,
          ...extra,
        }),
      done,
    );

  if (tasks.loading && !tasks.data) return <EmptyLine>Cargando tareas…</EmptyLine>;
  if (tasks.error) return <ErrorCallout error={tasks.error} onRetry={tasks.reload} />;
  const items = tasks.data?.items ?? [];
  const openRequired = tasks.data?.openRequiredCount ?? 0;

  return (
    <>
      {error != null && <ErrorCallout error={error} />}
      <EuiText size="xs" color="subdued">
        <p>
          {items.length} {items.length === 1 ? 'tarea' : 'tareas'} · {openRequired}{' '}
          {openRequired === 1 ? 'obligatoria pendiente' : 'obligatorias pendientes'}
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {items.length === 0 ? (
        <EmptyLine>
          Sin tareas. Añade los pasos de contención y de limpieza que deben cumplirse.
        </EmptyLine>
      ) : (
        <ul className="b89TaskList">
          {items.map((task) => {
            const reasonLength = reason.trim().length;
            const reasonValid = !task.required || (reasonLength >= REASON_MIN && reasonLength <= REASON_MAX);
            return (
              <li key={task.id} className="b89Task" data-status={task.status}>
                <div className="b89Task__main">
                  <span className="b89Task__title" data-b89-no-translate="">
                    {task.title}
                  </span>
                  <span className="b89CellMeta">
                    {TASK_STATUS_LABEL[task.status]}
                    {task.required ? ' · obligatoria' : ''}
                    {task.assigneeId ? (
                      <>
                        {' · responsable: '}
                        <Person id={task.assigneeId} viewerId={session.subjectId} />
                      </>
                    ) : null}
                    {task.dueAt ? <> · vence <Timestamp iso={task.dueAt} focusable={false} /></> : null}
                    {task.cancellationReason ? ` · motivo: ${task.cancellationReason}` : ''}
                  </span>
                  {cancelling === task.id && (
                    <div className="b89TaskCancel">
                      <EuiFormRow
                        label="Motivo de la cancelación"
                        helpText={
                          task.required
                            ? `Obligatorio en tareas obligatorias: entre ${REASON_MIN} y ${REASON_MAX} caracteres. Queda en la actividad.`
                            : 'Opcional. Queda en la actividad.'
                        }
                        fullWidth
                      >
                        <EuiTextArea
                          fullWidth
                          rows={2}
                          maxLength={REASON_MAX}
                          value={reason}
                          onChange={(event) => setReason(event.target.value)}
                        />
                      </EuiFormRow>
                      <EuiFlexGroup gutterSize="s" responsive={false}>
                        <EuiFlexItem grow={false}>
                          <EuiButtonEmpty size="xs" onClick={() => setCancelling(null)}>
                            Volver
                          </EuiButtonEmpty>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiButton
                            size="s"
                            color="danger"
                            isDisabled={!reasonValid}
                            isLoading={busy === task.id}
                            onClick={() =>
                              void command(
                                task,
                                'cancel',
                                reason.trim() ? { reason: reason.trim() } : {},
                                'Tarea cancelada.',
                              ).then(() => setCancelling(null))
                            }
                          >
                            Cancelar tarea
                          </EuiButton>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                    </div>
                  )}
                </div>
                {canWrite && cancelling !== task.id && (
                  <div className="b89Task__actions">
                    {task.status === 'open' && (
                      <EuiButtonEmpty
                        size="xs"
                        isLoading={busy === task.id}
                        onClick={() => void command(task, 'start', {}, 'Tarea en curso.')}
                      >
                        Empezar
                      </EuiButtonEmpty>
                    )}
                    {(task.status === 'open' || task.status === 'in_progress') && (
                      <>
                        <EuiButtonEmpty
                          size="xs"
                          isLoading={busy === task.id}
                          onClick={() => void command(task, 'complete', {}, 'Tarea completada.')}
                        >
                          Completar
                        </EuiButtonEmpty>
                        <EuiButtonEmpty
                          size="xs"
                          color="danger"
                          onClick={() => {
                            setReason('');
                            setCancelling(task.id);
                          }}
                        >
                          Cancelar
                        </EuiButtonEmpty>
                      </>
                    )}
                    {(task.status === 'done' || task.status === 'cancelled') && (
                      <EuiButtonEmpty size="xs" onClick={() => void command(task, 'reopen', {}, 'Tarea reabierta.')}>
                        Reabrir
                      </EuiButtonEmpty>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {canWrite && (
        <>
          <EuiSpacer size="l" />
          <EuiFormRow label="Nueva tarea" fullWidth>
            <EuiFieldText
              fullWidth
              value={title}
              maxLength={200}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Ej.: Revocar las sesiones del usuario afectado"
            />
          </EuiFormRow>
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
            <EuiFlexItem grow>
              <EuiCheckbox
                id={`b89TaskRequired-${incident.id}`}
                label="Obligatoria para cerrar el incidente"
                checked={required}
                onChange={(event) => setRequired(event.target.checked)}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                size="s"
                isDisabled={title.trim().length === 0}
                isLoading={busy === 'new'}
                onClick={() =>
                  void run(
                    'new',
                    async () => {
                      await api.post(base, { title: title.trim(), required });
                      setTitle('');
                    },
                    'Tarea añadida.',
                  )
                }
              >
                Añadir tarea
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}
    </>
  );
}

export function NotesPanel({ incident }: { incident: Incident }) {
  const { api, can, session } = useConsole();
  const base = `/incidents/${encodeURIComponent(incident.id)}/notes`;
  const notes = useAsync(() => api.get<Page<IncidentNote>>(base, { pageSize: 200 }), [api, base]);
  const [body, setBody] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useChanges(['incident_note'], () => notes.reload());

  const add = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(base, { body: body.trim() });
      setBody('');
      notes.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  if (notes.loading && !notes.data) return <EmptyLine>Cargando notas…</EmptyLine>;
  if (notes.error) return <ErrorCallout error={notes.error} onRetry={notes.reload} />;
  const items = notes.data?.items ?? [];

  return (
    <>
      {error != null && <ErrorCallout error={error} />}
      {items.length === 0 ? (
        <EmptyLine>Sin notas todavía. Las notas no se editan; para corregir, añade otra.</EmptyLine>
      ) : (
        <ol className="b89Notes">
          {items.map((note) => (
            <li key={note.id} className="b89Note">
              <div className="b89CellMeta">
                <Person id={note.authorId} viewerId={session.subjectId} emptyLabel="Sistema" /> ·{' '}
                <Timestamp iso={note.createdAt} focusable={false} />
                {note.correctsNoteId ? ' · corrige una nota anterior' : ''}
              </div>
              <EuiText size="s" className="b89Prose" data-b89-no-translate="">
                <p>{note.body}</p>
              </EuiText>
            </li>
          ))}
        </ol>
      )}
      {can(CAPABILITIES.notesWrite) && (
        <>
          <EuiSpacer size="l" />
          <EuiFormRow label="Nueva nota" fullWidth helpText={`${body.trim().length} caracteres`}>
            <EuiTextArea
              fullWidth
              rows={3}
              value={body}
              placeholder="Qué hiciste, qué encontraste o qué falta."
              onChange={(event) => setBody(event.target.value)}
            />
          </EuiFormRow>
          <EuiFlexGroup justifyContent="flexEnd" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiButton
                size="s"
                isLoading={busy}
                isDisabled={body.trim().length === 0}
                onClick={add}
              >
                Añadir nota
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}
    </>
  );
}

function TimelinePanel({ incident }: { incident: Incident }) {
  const { api, session } = useConsole();
  const base = `/incidents/${encodeURIComponent(incident.id)}/timeline`;
  const timeline = useAsync(() => api.get<Timeline>(base, { pageSize: 200 }), [api, base]);
  useChanges(['incident', 'incident_task', 'incident_note', 'alert'], () => timeline.reload());

  if (timeline.loading && !timeline.data) return <EmptyLine>Cargando la actividad…</EmptyLine>;
  if (timeline.error) return <ErrorCallout error={timeline.error} onRetry={timeline.reload} />;
  const data = timeline.data!;

  return (
    <>
      {data.transitions !== 'included' && (
        <EuiText size="xs" color="subdued">
          <p>
            {data.transitions === 'requires_audit_read'
              ? 'Los cambios de estado no se muestran: requieren permiso de lectura de auditoría.'
              : 'Algunos cambios de estado no se pudieron recuperar.'}
          </p>
        </EuiText>
      )}
      {data.items.length === 0 ? (
        <EmptyLine>Sin actividad registrada.</EmptyLine>
      ) : (
        <ol className="b89IncidentLog">
          {data.items.map((entry) => (
            <li key={entry.id}>
              <time dateTime={entry.at} className="b89Tabular b89Muted">
                {absoluteTime(entry.at)}
              </time>
              <span>
                <strong>{timelineLabel(entry.kind)}</strong>{' '}
                <span data-b89-no-translate="">{entry.summary}</span>
                {entry.actorId && (
                  <span className="b89CellMeta">
                    {' · '}
                    <Person id={entry.actorId} viewerId={session.subjectId} />
                  </span>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}
