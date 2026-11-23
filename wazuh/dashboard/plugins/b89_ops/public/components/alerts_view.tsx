/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
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
  EuiToolTip,
} from '@elastic/eui';
import {
  Alert,
  ALERT_STATUS_LABEL,
  ALERT_VERDICTS,
  AlertCommandName,
  AlertStatus,
  AlertVerdict,
  CAPABILITIES,
  discoverUrlForEntity,
  INCIDENT_SEVERITIES,
  IncidentSeverity,
  Page,
  PRIORITIES,
  Priority,
  SEVERITY_LABEL,
  VERDICT_LABEL,
  vendorOfTitle,
} from '../../common';
import { cleanAlertTitle, explainAlert } from '../../common/alert_why';
import { PRIORITY_NAME, priorityFromParam } from './alerts_filters';
import { openIncidentForAlert } from '../api/alert_review';
import { B89ApiError } from '../api/client';
import { alertInvestigationHref } from './investigation_links';
import { VendorLogo } from './vendor_logo';
import { B89Page, useChanges, useConsole } from './console_context';
import {
  DataZone,
  EmptyLine,
  ErrorCallout,
  Mono,
  Person,
  PriorityMark,
  Timestamp,
  useAsync,
  useIsMobile,
} from './primitives';
import { AlertGuidePanel } from './alert_guide_panel';
import { ALERT_ACTION_DONE, alertActionPlan } from './alert_actions';
import type { AlertActionId } from './alert_actions';

type StatusFilter = 'open' | AlertStatus;

const STATUS_TABS: ReadonlyArray<{ id: StatusFilter; label: string }> = [
  { id: 'open', label: 'Abiertas' },
  { id: 'new', label: ALERT_STATUS_LABEL.new },
  { id: 'acknowledged', label: ALERT_STATUS_LABEL.acknowledged },
  { id: 'triaged', label: ALERT_STATUS_LABEL.triaged },
  { id: 'escalated', label: ALERT_STATUS_LABEL.escalated },
  { id: 'closed', label: ALERT_STATUS_LABEL.closed },
];

const ENTITY_KIND_LABEL: Record<string, string> = {
  user: 'Usuario',
  ip: 'IP',
  host: 'Equipo',
};

const NOTE_MIN = 10;
const NOTE_MAX = 2000;

/** Selector de prioridad de la cola («P1 · Crítica»…). */
export function PriorityFilter({
  priority,
  onChange,
}: {
  priority: Priority | '';
  onChange: (priority: Priority | '') => void;
}) {
  return (
    <EuiSelect
      compressed
      fullWidth
      aria-label="Filtrar por prioridad"
      value={priority}
      onChange={(event) => onChange(priorityFromParam(event.target.value))}
      options={[
        { value: '', text: 'Todas las prioridades' },
        ...PRIORITIES.map((value) => ({ value, text: `${value} · ${PRIORITY_NAME[value]}` })),
      ]}
    />
  );
}

/**
 * Aviso del filtro activo con «Quitar filtro»: quien llega desde «P1 Crítica» del resumen ve qué
 * se está filtrando y cómo deshacerlo.
 */
export function PriorityFilterNotice({
  priority,
  onChange,
  total,
}: {
  priority: Priority | '';
  onChange: (priority: Priority | '') => void;
  total?: number;
}) {
  if (!priority) return null;
  return (
    <p className="b89FilterNotice" role="status" data-priority={priority}>
      <span>
        Mostrando solo <PriorityMark priority={priority} /> {PRIORITY_NAME[priority]}
        {total !== undefined ? ` · ${total} alerta${total === 1 ? '' : 's'}` : ''}
      </span>
      <button type="button" className="b89FilterNotice__clear" onClick={() => onChange('')}>
        Quitar filtro
      </button>
    </p>
  );
}

/**
 * Celda principal de la cola: título limpio (botón: se abre con teclado) y, debajo, por qué saltó
 * en una línea. El ID técnico de la regla nunca va en el título.
 */
export function AlertQueueTitle({
  alert,
  basePath,
  onOpen,
}: {
  alert: Pick<Alert, 'id' | 'title' | 'priority' | 'reasons' | 'entities' | 'ruleId'>;
  basePath: string;
  onOpen: (id: string) => void;
}) {
  const why = explainAlert(alert);
  const meta = why.detailLine;
  return (
    <span className="b89CellTitle">
      <span className="b89CellTitle__main">
        <VendorLogo id={vendorOfTitle(alert.title)} basePath={basePath} size="s" />
        <button
          type="button"
          className="b89LinkButton"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(alert.id);
          }}
          data-b89-no-translate=""
        >
          {why.title}
        </button>
      </span>
      {meta && (
        <span className="b89CellMeta b89AlertWhy" title={meta} data-b89-no-translate="">
          <span className="b89VisuallyHidden">Por qué saltó: </span>
          {meta}
        </span>
      )}
    </span>
  );
}

export function AlertsView({
  selectedId,
  onSelect,
  basePath,
  initialPriority = null,
  initialQuery = null,
  onPriorityChange,
}: {
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  basePath: string;
  /** `?priority=` de la URL; se vuelve a leer cada vez que cambia (también con la vista montada). */
  initialPriority?: string | null;
  /** Escribe el filtro en la URL (`?priority=`): así el enlace se comparte y «Atrás» funciona. */
  onPriorityChange?: (priority: Priority | '') => void;
  /** `?q=` (pivote desde una entidad de la investigación). */
  initialQuery?: string | null;
}) {
  const { api, session } = useConsole();
  const [status, setStatus] = useState<StatusFilter>('open');
  const urlPriority = priorityFromParam(initialPriority);
  const [localPriority, setLocalPriority] = useState<Priority | ''>(urlPriority);
  // Con URL, la prioridad es la de la URL (fuente única): un enlace «P1 Crítica» pulsado con la
  // cola ya abierta cambia el filtro sin remontar la vista.
  const priority = onPriorityChange ? urlPriority : localPriority;
  const setPriority = (next: Priority | '') => {
    setLocalPriority(next);
    onPriorityChange?.(next);
  };
  useEffect(() => setLocalPriority(urlPriority), [urlPriority]);
  const [search, setSearch] = useState((initialQuery ?? '').slice(0, 120));
  const [query, setQuery] = useState((initialQuery ?? '').trim().slice(0, 120));
  const [items, setItems] = useState<readonly Alert[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);

  const page = useAsync(
    () =>
      api.get<Page<Alert>>('/alerts', {
        status,
        priority: priority || undefined,
        q: query || undefined,
        pageSize: 50,
      }),
    [api, status, priority, query],
  );

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
      setMoreError(null);
    }
  }, [page.data]);

  // En vivo: una alerta nueva o cambiada recarga la primera página de la cola.
  useChanges(['alert'], () => page.reload());

  const loadMore = async () => {
    if (!cursor || moreBusy) return;
    setMoreBusy(true);
    setMoreError(null);
    try {
      const next = await api.get<Page<Alert>>('/alerts', {
        status,
        priority: priority || undefined,
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

  const columns: Array<EuiBasicTableColumn<Alert>> = [
    {
      field: 'priority',
      name: 'Prioridad',
      width: '104px',
      render: (value: Priority) => <PriorityMark priority={value} />,
      mobileOptions: { header: false },
    },
    {
      field: 'title',
      name: 'Alerta y por qué saltó',
      truncateText: false,
      render: (_value: string, alert: Alert) => (
        <AlertQueueTitle alert={alert} basePath={basePath} onOpen={onSelect} />
      ),
      mobileOptions: { header: false },
    },
    {
      field: 'status',
      name: 'Estado',
      width: '120px',
      render: (value: AlertStatus) => (
        <EuiBadge color="hollow">{ALERT_STATUS_LABEL[value]}</EuiBadge>
      ),
    },
    {
      field: 'assigneeId',
      name: 'Responsable',
      width: '140px',
      render: (value: string | null) => <Person id={value} viewerId={session.subjectId} />,
    },
    {
      field: 'occurredAt',
      name: 'Ocurrió',
      width: '120px',
      render: (value: string) => <Timestamp iso={value} focusable={false} />,
    },
  ];

  return (
    <B89Page
      title="Cola de alertas"
      description="Las más urgentes primero. Abre una para ver por qué saltó y qué hacer."
    >
      <EuiTabs size="s" className="b89Tabs">
        {STATUS_TABS.map((tab) => (
          <EuiTab key={tab.id} isSelected={status === tab.id} onClick={() => setStatus(tab.id)}>
            {tab.label}
            {status === tab.id && page.data?.totalCount !== undefined && (
              <span className="b89TabCount">{page.data.totalCount}</span>
            )}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="s" responsive wrap className="b89Filters">
        <EuiFlexItem grow={3}>
          <EuiFieldSearch
            fullWidth
            compressed
            placeholder="Buscar por título, usuario o IP"
            value={search}
            onChange={(event) => setSearch(event.target.value.slice(0, 120))}
            onSearch={(value) => setQuery(value.trim().slice(0, 120))}
            aria-label="Buscar alertas"
          />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          <PriorityFilter priority={priority} onChange={setPriority} />
        </EuiFlexItem>
      </EuiFlexGroup>
      <PriorityFilterNotice
        priority={priority}
        onChange={setPriority}
        total={page.loading ? undefined : page.data?.totalCount}
      />
      <EuiSpacer size="m" />
      {page.error ? (
        <ErrorCallout error={page.error} onRetry={page.reload} />
      ) : (
        <DataZone>
          <EuiBasicTable<Alert>
            items={items as Alert[]}
            columns={columns}
            loading={page.loading}
            responsive
            tableLayout="auto"
            rowProps={(alert) => ({
              // Ayuda para el ratón; con teclado se abre con el botón del título.
              onClick: () => onSelect(alert.id),
              className: `b89Row b89Row--p${alert.priority.slice(1)}${
                alert.id === selectedId ? ' euiTableRow-isSelected' : ''
              }`,
              'data-test-subj': `b89AlertRow-${alert.id}`,
            })}
            noItemsMessage={
              page.loading
                ? 'Cargando alertas…'
                : query || priority
                  ? 'Ninguna alerta coincide con los filtros. Quita un filtro para ampliar la búsqueda.'
                  : status === 'open'
                    ? 'La cola está al día: no hay alertas abiertas.'
                    : 'No hay alertas en este estado.'
            }
          />
          {moreError != null && <ErrorCallout error={moreError} onRetry={() => void loadMore()} />}
          {cursor && (
            <>
              <EuiSpacer size="s" />
              <EuiButtonEmpty size="s" onClick={() => void loadMore()} isLoading={moreBusy}>
                Ver más alertas ({items.length} mostradas)
              </EuiButtonEmpty>
            </>
          )}
        </DataZone>
      )}
      {selectedId && (
        <AlertFlyout
          alertId={selectedId}
          basePath={basePath}
          onClose={() => onSelect(null)}
          onChanged={(updated) =>
            setItems((current) =>
              current.map((alert) => (alert.id === updated.id ? updated : alert)),
            )
          }
        />
      )}
    </B89Page>
  );
}

type FlyoutMode = 'idle' | 'classify' | 'close' | 'incident';

const COMMAND_OF: Partial<Record<AlertActionId, AlertCommandName>> = {
  take: 'acknowledge',
  assign_me: 'assign',
  escalate: 'escalate',
  reopen: 'reopen',
};

export function AlertFlyout({
  alertId,
  basePath,
  onClose,
  onChanged,
  inInvestigation = false,
}: {
  alertId: string;
  basePath: string;
  onClose: () => void;
  onChanged: (alert: Alert) => void;
  /** Abierto sobre la investigación: sin el botón «Investigar», que llevaría a la misma página. */
  inInvestigation?: boolean;
}) {
  const { api, session, can, notifications } = useConsole();
  const mobile = useIsMobile();
  const loaded = useAsync(
    () => api.get<{ alert: Alert }>(`/alerts/${encodeURIComponent(alertId)}`),
    [api, alertId],
  );
  const [alert, setAlert] = useState<Alert | null>(null);
  const [mode, setMode] = useState<FlyoutMode>('idle');
  const [verdict, setVerdict] = useState<AlertVerdict | ''>('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const formRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (loaded.data) setAlert(loaded.data.alert);
  }, [loaded.data]);

  // Al abrir un formulario, se lleva a la vista y el foco va a su primer campo.
  useEffect(() => {
    if (mode === 'idle' || !formRef.current) return;
    formRef.current.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
    formRef.current.querySelector<HTMLElement>('select, textarea, input')?.focus();
  }, [mode]);

  // Si otra persona cambia esta alerta mientras está abierta, se recarga (no al editar).
  useChanges(['alert'], (changes, resync) => {
    if (mode === 'idle' && (resync || changes.some((c) => c.resource.id === alertId)))
      loaded.reload();
  });

  const command = async (
    action: AlertActionId,
    name: AlertCommandName,
    extra: Record<string, unknown> = {},
  ) => {
    if (!alert) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ alert: Alert }>(
        `/alerts/${encodeURIComponent(alert.id)}/commands`,
        { name, expectedRevision: alert.revision, ...extra },
      );
      setAlert(result.alert);
      onChanged(result.alert);
      setMode('idle');
      setNote('');
      setVerdict('');
      notifications.toasts.addSuccess({ title: ALERT_ACTION_DONE[action] });
    } catch (failure) {
      setError(failure);
      if (failure instanceof B89ApiError && failure.code === 'STATE_CONFLICT') loaded.reload();
    } finally {
      setBusy(false);
    }
  };

  const run = (action: AlertActionId) => {
    if (action === 'classify') return setMode('classify');
    if (action === 'close') return setMode('close');
    if (action === 'open_incident') return setMode('incident');
    const name = COMMAND_OF[action];
    if (!name) return undefined;
    return void command(action, name, action === 'assign_me' ? { assigneeId: session.subjectId } : {});
  };

  const plan = alert
    ? alertActionPlan(alert, session.subjectId, {
        canTriage: can(CAPABILITIES.alertsTriage),
        canAssign: can(CAPABILITIES.alertsAssign),
        canOpenIncident: can(CAPABILITIES.incidentsWrite),
      })
    : null;
  const noteLength = note.trim().length;
  const noteValid = noteLength >= NOTE_MIN && note.length <= NOTE_MAX;
  const noteRequired = mode === 'classify' || (mode === 'close' && alert?.status !== 'triaged');
  const submitBlocked =
    mode === 'classify' ? !verdict || !noteValid : noteRequired ? !noteValid : false;
  const blockedReason =
    mode === 'classify' && !verdict
      ? 'Elige la conclusión para guardar.'
      : noteRequired && !noteValid
        ? `Escribe al menos ${NOTE_MIN} caracteres en la nota para guardar.`
        : null;
  const title = alert ? cleanAlertTitle(alert.title) : 'Alerta';

  return (
    <EuiFlyout
      onClose={onClose}
      size={mobile ? 'l' : 'm'}
      ownFocus={mobile}
      className="b89Flyout"
      aria-labelledby="b89AlertTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <div lang="es-PE" translate="no">
          {alert && (
            <span className="b89AlertHead__source">
              <PriorityMark priority={alert.priority} />
              <VendorLogo id={vendorOfTitle(alert.title)} basePath={basePath} size="s" />
            </span>
          )}
          <EuiSpacer size="xs" />
          <EuiTitle size="s">
            <h2 id="b89AlertTitle" data-b89-no-translate="">
              {title}
            </h2>
          </EuiTitle>
          {alert && (
            <EuiText size="xs" color="subdued">
              <p className="b89AlertHead__facts">
                {ALERT_STATUS_LABEL[alert.status]} · Responsable:{' '}
                <Person id={alert.assigneeId} viewerId={session.subjectId} /> ·{' '}
                <Timestamp iso={alert.occurredAt} />
              </p>
            </EuiText>
          )}
          {alert && !inInvestigation && (
            <>
              <EuiSpacer size="s" />
              <EuiFlexGroup gutterSize="s" responsive={false} wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    size="s"
                    iconType="inspect"
                    href={alertInvestigationHref(basePath, alert.id)}
                    data-test-subj="b89InvestigateAlert"
                  >
                    Investigar
                  </EuiButton>
                </EuiFlexItem>
                {can(CAPABILITIES.investigationsRun) && (
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty
                      size="s"
                      href={`${basePath}/app/b89-ai-analyst?alertId=${encodeURIComponent(alert.id)}`}
                      data-test-subj="b89InvestigateWithAnalyst"
                    >
                      Pedir análisis al Analista IA
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                )}
              </EuiFlexGroup>
            </>
          )}
        </div>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <div lang="es-PE" translate="no">
          {loaded.error != null && <ErrorCallout error={loaded.error} onRetry={loaded.reload} />}
          {!alert && loaded.loading && <EmptyLine>Cargando la alerta…</EmptyLine>}
          {alert && mode !== 'idle' && (
            <div ref={formRef} className="b89AlertForm">
              {mode === 'classify' && (
                <>
                  <EuiTitle size="xxs">
                    <h3>Clasificar la alerta</h3>
                  </EuiTitle>
                  <EuiSpacer size="s" />
                  <EuiFormRow label="Conclusión" fullWidth>
                    <EuiSelect
                      fullWidth
                      value={verdict}
                      onChange={(event) => setVerdict(event.target.value as AlertVerdict)}
                      options={[
                        { value: '', text: 'Elige una conclusión…' },
                        ...ALERT_VERDICTS.map((value) => ({ value, text: VERDICT_LABEL[value] })),
                      ]}
                    />
                  </EuiFormRow>
                  <NoteField note={note} onChange={setNote} required />
                </>
              )}
              {mode === 'close' && (
                <>
                  <EuiTitle size="xxs">
                    <h3>Cerrar la alerta</h3>
                  </EuiTitle>
                  <EuiSpacer size="s" />
                  <NoteField
                    note={note}
                    onChange={setNote}
                    required={alert.status !== 'triaged'}
                    help={
                      alert.status !== 'triaged'
                        ? 'Aún no tiene conclusión: explica por qué se cierra.'
                        : undefined
                    }
                  />
                </>
              )}
              {mode === 'incident' && (
                <OpenIncidentForm
                  alert={alert}
                  onCancel={() => setMode('idle')}
                  onOpened={(incidentId) => {
                    notifications.toasts.addSuccess({
                      title: ALERT_ACTION_DONE.open_incident,
                      text: `Puedes seguirlo en Incidentes (${incidentId}).`,
                    });
                    setMode('idle');
                    loaded.reload();
                  }}
                />
              )}
              <EuiSpacer size="l" />
            </div>
          )}
          {alert && (
            <>
              <AlertGuidePanel
                title={alert.title}
                reasons={alert.reasons}
                priority={alert.priority}
                entities={alert.entities}
                score={alert.score}
                ruleId={alert.ruleId}
                explanation={alert.explanation}
                framed={false}
              />
              <EuiSpacer size="l" />
              <EuiTitle size="xxs">
                <h3>Involucrados</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {alert.entities.length === 0 ? (
                <EmptyLine>El evento no trae usuario, IP ni equipo.</EmptyLine>
              ) : (
                <ul className="b89List">
                  {alert.entities.map((entity, index) => {
                    const discover = discoverUrlForEntity(basePath, entity, alert.occurredAt);
                    return (
                      <li key={entity.ref ?? `${entity.kind}-${index}`}>
                        <span className="b89Muted">
                          {ENTITY_KIND_LABEL[entity.kind] ?? entity.kind}
                        </span>{' '}
                        <Mono>{entity.label}</Mono>
                        {discover && (
                          <>
                            {' '}
                            <a
                              className="b89InlineLink"
                              href={discover}
                              aria-label={`Ver qué más pasó con ${entity.label}, una hora antes y después`}
                            >
                              Ver qué más pasó (±1 h)
                            </a>
                          </>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
              <EuiSpacer size="l" />
              <dl className="b89KeyValues b89AlertFacts">
                <dt>Conclusión</dt>
                <dd>{alert.verdict ? VERDICT_LABEL[alert.verdict] : 'Sin clasificar'}</dd>
                <dt>Incidente</dt>
                <dd>
                  {alert.incidentId ? (
                    <a
                      href={`${basePath}/app/b89-incidents?id=${encodeURIComponent(alert.incidentId)}`}
                    >
                      Ver incidente vinculado
                    </a>
                  ) : (
                    'Sin incidente'
                  )}
                </dd>
              </dl>
              <details className="b89Guide__details">
                <summary>Identificador de la alerta</summary>
                <Mono>{alert.id}</Mono>
              </details>
            </>
          )}
        </div>
      </EuiFlyoutBody>
      {alert && plan && mode !== 'incident' && (
        <EuiFlyoutFooter>
          <div lang="es-PE" translate="no">
            {error != null && (
              <>
                <ErrorCallout error={error} />
                <EuiSpacer size="s" />
              </>
            )}
            {mode !== 'idle' ? (
              <>
                {blockedReason && (
                  <EuiText size="xs" color="subdued" className="b89FooterHint">
                    <p role="status">{blockedReason}</p>
                  </EuiText>
                )}
                <EuiFlexGroup gutterSize="s" responsive={false} wrap justifyContent="flexEnd">
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty onClick={() => setMode('idle')} disabled={busy}>
                      Volver
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButton
                      fill
                      isLoading={busy}
                      isDisabled={submitBlocked}
                      onClick={() =>
                        mode === 'classify'
                          ? void command('classify', 'triage', { verdict, note: note.trim() })
                          : void command('close', 'close', note.trim() ? { note: note.trim() } : {})
                      }
                    >
                      {mode === 'classify' ? 'Guardar conclusión' : 'Cerrar alerta'}
                    </EuiButton>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </>
            ) : (
              <>
                {plan.hint && (
                  <EuiText size="xs" color="subdued" className="b89FooterHint">
                    <p>{plan.hint}</p>
                  </EuiText>
                )}
                {plan.actions.length > 0 && (
                  <EuiFlexGroup gutterSize="s" responsive={false} wrap justifyContent="flexEnd">
                    {plan.actions.map((action) => {
                      const button = (
                        <EuiButton
                          fill={action.primary}
                          isLoading={busy && action.primary}
                          isDisabled={busy}
                          onClick={() => run(action.id)}
                        >
                          {action.label}
                        </EuiButton>
                      );
                      return (
                        <EuiFlexItem grow={false} key={action.id}>
                          {action.help ? (
                            <EuiToolTip content={action.help}>{button}</EuiToolTip>
                          ) : (
                            button
                          )}
                        </EuiFlexItem>
                      );
                    })}
                  </EuiFlexGroup>
                )}
              </>
            )}
          </div>
        </EuiFlyoutFooter>
      )}
    </EuiFlyout>
  );
}

function NoteField({
  note,
  onChange,
  required,
  help,
}: {
  note: string;
  onChange: (value: string) => void;
  required: boolean;
  help?: string;
}) {
  const length = note.trim().length;
  const invalid = required && note.length > 0 && length < NOTE_MIN;
  return (
    <EuiFormRow
      label={required ? 'Nota (obligatoria)' : 'Nota (opcional)'}
      helpText={`${help ? `${help} ` : ''}${length} de ${NOTE_MAX} caracteres${required ? ` · mínimo ${NOTE_MIN}` : ''}`}
      isInvalid={invalid}
      error={invalid ? `Escribe al menos ${NOTE_MIN} caracteres.` : undefined}
      fullWidth
    >
      <EuiTextArea
        fullWidth
        rows={4}
        value={note}
        maxLength={NOTE_MAX}
        isInvalid={invalid}
        placeholder="Qué revisaste y por qué llegas a esta conclusión."
        onChange={(event) => onChange(event.target.value)}
      />
    </EuiFormRow>
  );
}

export function OpenIncidentForm({
  alert,
  onCancel,
  onOpened,
  initialSummary = '',
  heading = 'Abrir incidente desde esta alerta',
}: {
  alert: Alert;
  onCancel: () => void;
  onOpened: (incidentId: string) => void;
  /** Resumen precargado y editable (p. ej. la conclusión del Analista IA). */
  initialSummary?: string;
  heading?: string;
}) {
  const { api } = useConsole();
  const defaultSeverity = useMemo<IncidentSeverity>(
    () => (({ P1: 'critical', P2: 'high', P3: 'medium', P4: 'low' }) as const)[alert.priority],
    [alert.priority],
  );
  const [title, setTitle] = useState(() => cleanAlertTitle(alert.title));
  const [severity, setSeverity] = useState<IncidentSeverity>(defaultSeverity);
  const [summary, setSummary] = useState(initialSummary);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const missing = [
    title.trim().length === 0 ? 'el título' : null,
    summary.trim().length === 0 ? 'el resumen' : null,
  ].filter((part): part is string => Boolean(part));

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      onOpened(await openIncidentForAlert(api, alert, { title, severity, summary }));
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <EuiTitle size="xxs">
        <h3>{heading}</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {error != null && <ErrorCallout error={error} />}
      <EuiFormRow label="Título (obligatorio)" fullWidth>
        <EuiFieldText
          fullWidth
          value={title}
          maxLength={200}
          onChange={(e) => setTitle(e.target.value)}
        />
      </EuiFormRow>
      <EuiFormRow
        label="Severidad"
        fullWidth
        helpText={`Sugerida según la prioridad ${alert.priority} de la alerta.`}
      >
        <EuiSelect
          fullWidth
          value={severity}
          onChange={(event) => setSeverity(event.target.value as IncidentSeverity)}
          options={INCIDENT_SEVERITIES.map((value) => ({ value, text: SEVERITY_LABEL[value] }))}
        />
      </EuiFormRow>
      <EuiFormRow
        label="Resumen (obligatorio)"
        fullWidth
        helpText="Qué se sabe y qué falta confirmar, en 2 o 3 frases."
      >
        <EuiTextArea
          fullWidth
          rows={4}
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
        />
      </EuiFormRow>
      <EuiSpacer size="m" />
      {missing.length > 0 && (
        <EuiText size="xs" color="subdued" className="b89FooterHint">
          <p>Falta {missing.join(' y ')} para abrir el incidente.</p>
        </EuiText>
      )}
      <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty onClick={onCancel} disabled={busy}>
            Volver
          </EuiButtonEmpty>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton fill isLoading={busy} isDisabled={missing.length > 0} onClick={submit}>
            Abrir incidente
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
    </>
  );
}
