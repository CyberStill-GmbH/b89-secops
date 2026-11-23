/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiAccordion,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiCodeBlock,
  EuiContextMenuItem,
  EuiContextMenuPanel,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingContent,
  EuiPanel,
  EuiPopover,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  Alert,
  ALERT_STATUS_LABEL,
  alertQuestion,
  CAPABILITIES,
  discoverUrlForQuery,
  ENTITY_KIND_LABEL,
  entityKey,
  EntityKind,
  entityKql,
  Incident,
  INCIDENT_STATUS_LABEL,
  IndexerAccess,
  InvestigationEntity,
  InvestigationEvent,
  InvestigationEventSummary,
  MAX_QUERY_ENTITIES,
  mitreTechniqueUrl,
  parseEntityKey,
  RELATED_WINDOW_LABEL,
  RELATED_WINDOW_MS,
  RELATED_WINDOWS,
  RelatedWindow,
  RelatedResponse,
  SourceResponse,
  threatHuntingUrl,
  validEntity,
  VendorId,
  vendorOfTitle,
  VENDORS,
  VERDICT_LABEL,
  wazuhRuleIdOfTitle,
} from '../../common';
import {
  EntityRisk,
  fetchEntityRisk,
  fetchEvent,
  fetchRelated,
  fetchSource,
} from '../api/investigation';
import { askBunny } from '../bunny_bridge';
import { AlertFlyout, OpenIncidentForm } from './alerts_view';
import { useConsole } from './console_context';
import { NotesPanel } from './incidents_view';
import {
  DataZone,
  EmptyLine,
  ErrorCallout,
  Mono,
  Person,
  PriorityMark,
  relativeTime,
  useAsync,
} from './primitives';
import { AlertGuidePanel } from './alert_guide_panel';
import { cleanAlertTitle } from '../../common/alert_why';
import { entityInvestigationHref } from './investigation_links';
import { SourceBadge, VendorLogo } from './vendor_logo';
import { InvestigationActivityGroups } from './investigation_activity_groups';
import {
  buildTimelineEntries,
  entityKeyLabel,
  formatClock,
  formatOffset,
  formatShortDateTime,
  levelText,
  levelTone,
  TimelineOrder,
} from './investigation_activity_grouping';
import { InvestigationReportActions } from './investigation_report_actions';
import { InvestigationPagination } from './investigation_pagination';
import type { ReportEventSummary } from './investigation_report';

/**
 * Investigación de una alerta (o de una entidad suelta), en orden de lectura: cabecera con el
 * estado y la decisión → qué pasó y qué hacer → quiénes están involucrados → qué más pasó
 * alrededor (línea de tiempo del SIEM) → evidencia (evento original) → incidente → MITRE.
 * Las consultas al SIEM van con la identidad de quien mira (rutas `/api/b89_ops/investigation/*`).
 */

const ALERT_ENTITY_KIND: Record<string, EntityKind> = { user: 'user', ip: 'ip', host: 'host' };

export const ACCESS_MESSAGE: Record<Exclude<IndexerAccess, 'ok'>, string> = {
  forbidden:
    'Tu cuenta no tiene permiso para ver los eventos del SIEM. Pide acceso a un administrador del SOC.',
  error: 'El SIEM no respondió. Reintenta en unos segundos; si sigue fallando, revisa Salud de fuentes.',
};

type TimelineView = 'list' | 'groups';

const WIDER_WINDOW: Partial<Record<RelatedWindow, RelatedWindow>> = { '1h': '24h', '24h': '7d' };

const ENTITY_ALERTS_LABEL: Record<EntityKind, string> = {
  host: 'Ver alertas de este equipo',
  user: 'Ver alertas de este usuario',
  ip: 'Ver alertas de esta IP',
  project: 'Ver alertas de este proyecto',
  zone: 'Ver alertas de esta zona',
  account: 'Ver alertas de esta cuenta',
};

/** Riesgo 0–100 del motor de correlación en palabras: «alto», «medio», «bajo». */
export function riskWord(score: number): 'alto' | 'medio' | 'bajo' {
  if (score >= 70) return 'alto';
  if (score >= 40) return 'medio';
  return 'bajo';
}

/**
 * Entidades activas en la línea de tiempo: sin elección explícita, las primeras
 * `MAX_QUERY_ENTITIES`; con elección, las elegidas (nunca más del límite del servidor).
 */
export function activeTimelineEntities<T extends { kind: string; value: string }>(
  entities: readonly T[],
  selectedKeys: readonly string[] | null,
): T[] {
  if (selectedKeys == null) return entities.slice(0, MAX_QUERY_ENTITIES);
  const selected = new Set(selectedKeys);
  return entities.filter((entity) => selected.has(entityKey(entity))).slice(0, MAX_QUERY_ENTITIES);
}

export function InvestigationView({
  alertId,
  entity,
  at,
  basePath,
}: {
  alertId: string | null;
  entity: string | null;
  at: string | null;
  basePath: string;
  /** Se conserva por compatibilidad: «Clasificar alerta» abre ahora el panel sin salir. */
  onOpenTriage?: (alertId: string) => void;
}) {
  const { api, notifications, session, can } = useConsole();
  const alert = useAsync(
    () =>
      alertId
        ? api.get<{ alert: Alert }>(`/alerts/${encodeURIComponent(alertId)}`).then((r) => r.alert)
        : Promise.resolve(null),
    [api, alertId],
  );
  const current = alert.data;
  // La API manda la regla aparte (el título ya no lleva «(wazuh N)»); el título queda de respaldo.
  const ruleId = current
    ? (current.ruleId && /^\d{1,7}$/u.test(current.ruleId) ? current.ruleId : wazuhRuleIdOfTitle(current.title))
    : null;
  // La respuesta recuerda para qué alerta se pidió: así no se confunde «aún no llegó» con «vacío».
  const source = useAsync<{ forId: string; response: SourceResponse } | null>(
    () =>
      current
        ? fetchSource(basePath, {
            ruleId,
            at: current.occurredAt,
            description: current.title.replace(/\s*\(wazuh \d+\)\s*$/u, ''),
          }).then((response) => ({ forId: current.id, response }))
        : Promise.resolve(null),
    [basePath, current?.id, current?.occurredAt],
  );
  const sourceData = current && source.data?.forId === current.id ? source.data.response : null;
  const event = sourceData?.event ?? null;
  const incident = useAsync(
    () =>
      current?.incidentId
        ? api
            .get<{ incident: Incident }>(`/incidents/${encodeURIComponent(current.incidentId)}`)
            .then((r) => r.incident)
        : Promise.resolve(null),
    [api, current?.incidentId],
  );
  const pivot = entity ? parseEntityKey(entity) : null;
  const [openedAt] = useState(() => new Date().toISOString());
  const anchor = at ?? event?.at ?? current?.occurredAt ?? openedAt;

  /** Mientras llega la alerta o su evento original no se sabe aún qué entidades hay. */
  const resolving =
    alertId !== null &&
    ((!current && !alert.error) ||
      (current !== null && !source.error && (source.loading || sourceData === null)));

  const entities = useMemo<InvestigationEntity[]>(() => {
    const out: InvestigationEntity[] = [];
    const seen = new Set<string>();
    const push = (item: InvestigationEntity) => {
      const key = entityKey(item);
      if (seen.has(key)) return;
      seen.add(key);
      out.push(item);
    };
    if (pivot) push({ ...pivot, field: '' });
    for (const item of event?.entities ?? []) push(item);
    for (const item of current?.entities ?? []) {
      const kind = ALERT_ENTITY_KIND[item.kind];
      if (kind && validEntity(kind, item.label)) push({ kind, value: item.label, field: '' });
    }
    return out;
  }, [pivot?.kind, pivot?.value, event, current]); // eslint-disable-line react-hooks/exhaustive-deps

  const vendor: VendorId = event?.vendor ?? (current ? vendorOfTitle(current.title) : 'wazuh');
  const title = current
    ? cleanAlertTitle(current.title)
    : pivot
      ? `${ENTITY_KIND_LABEL[pivot.kind]} ${pivot.value}`
      : '';
  const mitre = event?.mitre ?? { ids: [], tactics: [], techniques: [] };
  const reportSourceEvent = useMemo<ReportEventSummary | null>(
    () =>
      event
        ? {
            id: event.id,
            index: event.index,
            at: event.at,
            level: event.level,
            ruleId: event.ruleId,
            description: event.description,
            groups: event.groups,
            vendor: event.vendor,
            agent: event.agent,
            mitre: event.mitre,
            matched: event.matched,
            email: event.email,
          }
        : null,
    [event],
  );
  const [selected, setSelected] = useState<string[] | null>(null);
  const activeEntities = activeTimelineEntities(entities, selected);
  const active = activeEntities.map(entityKey);
  const [range, setRange] = useState<RelatedWindow>('24h');
  const span = RELATED_WINDOW_MS[range];
  const from = new Date(Date.parse(anchor) - span).toISOString();
  const to = new Date(Date.parse(anchor) + span).toISOString();
  const kql =
    activeEntities.length > 0 ? entityKql(activeEntities) : ruleId ? `rule.id:${ruleId}` : '';

  const [triageOpen, setTriageOpen] = useState(false);
  const triageButton = useRef<HTMLButtonElement | null>(null);
  const closeTriage = () => {
    setTriageOpen(false);
    // Devuelve el foco al botón que abrió el panel.
    window.setTimeout(() => triageButton.current?.focus(), 0);
  };

  const toggleEntity = (key: string, on: boolean) =>
    setSelected(on ? [...active, key] : active.filter((k) => k !== key));

  const loadingHeader = alertId !== null && !current && !alert.error;
  if (alertId && alert.error) {
    return (
      <main className="b89Page b89Investigation" lang="es-PE">
        <BackLink basePath={basePath} />
        <ErrorCallout error={alert.error} onRetry={alert.reload} />
      </main>
    );
  }
  if (!alertId && !pivot) {
    return (
      <main className="b89Page b89Investigation" lang="es-PE">
        <BackLink basePath={basePath} />
        <EuiCallOut title="Falta qué investigar" color="warning" iconType="help">
          <p>El enlace está incompleto. Abre una alerta desde la cola.</p>
        </EuiCallOut>
      </main>
    );
  }

  const askBunnyNow = () => {
    const opened = askBunny({
      prompt: current
        ? alertQuestion({
            id: current.id,
            title: current.title,
            priority: current.priority,
            occurredAt: current.occurredAt,
            ruleId,
            entities: entities.map((item) => ({ kind: item.kind, value: item.value })),
            mitre: mitre.ids,
          })
        : `Ayúdame a investigar la entidad ${title}: ¿qué actividad tiene, es sospechosa y qué reviso?`,
      context: current ? { alertId: current.id } : { entity: entity ?? '' },
    });
    if (!opened) {
      // Bunny no está montado en esta página (sin permiso o desactivado).
      notifications.toasts.addWarning({
        title: 'Bunny no está disponible',
        text: 'Pide a un administrador que active el asistente para tu cuenta.',
      });
    }
  };

  const canTriage = can(CAPABILITIES.alertsTriage);
  const triageLabel = !current
    ? 'Clasificar alerta'
    : current.status === 'closed'
      ? 'Ver clasificación'
      : canTriage
        ? 'Clasificar alerta'
        : 'Ver estado de la alerta';

  return (
    <main className="b89Page b89Investigation" aria-busy={loadingHeader} lang="es-PE">
      <BackLink basePath={basePath} />
      <header className="b89Investigation__header">
        <div className="b89Investigation__lead">
          <VendorLogo id={vendor} basePath={basePath} size="l" />
          <div className="b89Investigation__leadText">
            <p className="b89Eyebrow">
              {alertId ? 'Investigación de alerta' : 'Investigación de entidad'} ·{' '}
              {VENDORS[vendor].name}
            </p>
            <EuiTitle size="m">
              <h1 data-b89-no-translate="">{loadingHeader ? 'Cargando alerta…' : title}</h1>
            </EuiTitle>
            {current && (
              <AlertStatusLine
                alert={current}
                basePath={basePath}
                viewerId={session.subjectId}
                incident={incident.data}
                ruleId={ruleId}
              />
            )}
          </div>
        </div>
        <div className="b89Investigation__actions">
          {current && (
            <EuiButton
              size="s"
              fill={current.status !== 'closed' && canTriage}
              iconType="documentEdit"
              buttonRef={(node: HTMLButtonElement | null) => {
                triageButton.current = node;
              }}
              aria-haspopup="dialog"
              onClick={() => setTriageOpen(true)}
              data-test-subj="b89InvestigationTriage"
            >
              {triageLabel}
            </EuiButton>
          )}
          <EuiButton size="s" iconType="discuss" onClick={askBunnyNow}>
            Preguntar a Bunny
          </EuiButton>
          {kql && (
            <SearchMenu
              id="b89SiemSearch"
              label="Buscar en el SIEM"
              items={[
                {
                  key: 'th',
                  name: 'Buscar en Threat Hunting',
                  href: threatHuntingUrl(basePath, kql, from, to),
                },
                {
                  key: 'discover',
                  name: 'Buscar en Discover',
                  href: discoverUrlForQuery(basePath, kql, from, to),
                },
              ]}
              hint={
                activeEntities.length > 0
                  ? `Con las entidades activas, ${RELATED_WINDOW_LABEL[range]}.`
                  : `Por la regla de la alerta, ${RELATED_WINDOW_LABEL[range]}.`
              }
            />
          )}
          <InvestigationReportActions
            basePath={basePath}
            alert={current}
            title={current?.title ?? title}
            entities={activeEntities}
            at={anchor}
            relatedWindow={range}
            excludeId={event?.id}
            sourceEvent={reportSourceEvent}
          />
        </div>
      </header>
      <EuiSpacer size="l" />
      {current && (
        <>
          <AlertGuidePanel
            title={current.title}
            reasons={current.reasons}
            priority={current.priority}
            entities={current.entities}
            score={current.score}
            ruleId={current.ruleId}
            explanation={current.explanation}
          />
          <EuiSpacer size="l" />
        </>
      )}
      <EntitiesSection
        basePath={basePath}
        entities={entities}
        active={active}
        resolving={resolving}
        at={anchor}
        from={from}
        to={to}
        onToggle={toggleEntity}
      />
      <EuiSpacer size="l" />
      <EuiFlexGroup gutterSize="l" alignItems="flexStart" responsive>
        <EuiFlexItem grow={2} className="b89Investigation__main">
          <EuiPanel paddingSize="m" className="b89Card">
            <TimelineSection
              basePath={basePath}
              heading={alertId ? 'Qué más pasó alrededor' : 'Actividad de esta entidad'}
              subject={alertId ? 'esta alerta' : 'esta entidad'}
              anchorLabel={alertId ? 'Momento de la alerta' : 'Momento de referencia'}
              entities={activeEntities}
              allEntities={entities.length}
              resolving={resolving}
              anchor={anchor}
              range={range}
              onRange={setRange}
              excludeId={event?.id}
              hasRuleSearch={Boolean(ruleId)}
            />
          </EuiPanel>
          {alertId && (
            <>
              <EuiSpacer size="l" />
              <SourceEvent
                basePath={basePath}
                access={sourceData?.access ?? 'ok'}
                match={sourceData?.match ?? 'none'}
                event={event}
                loading={resolving}
                error={source.error}
                onRetry={source.reload}
              />
            </>
          )}
        </EuiFlexItem>
        <EuiFlexItem grow={1} className="b89Investigation__side">
          {current && (
            <IncidentPanel
              alert={current}
              basePath={basePath}
              incident={incident}
              onChanged={alert.reload}
            />
          )}
          {(mitre.ids.length > 0 || mitre.tactics.length > 0) && (
            <>
              {current && <EuiSpacer size="l" />}
              <MitrePanel basePath={basePath} mitre={mitre} />
            </>
          )}
        </EuiFlexItem>
      </EuiFlexGroup>
      {triageOpen && current && (
        <AlertFlyout
          alertId={current.id}
          basePath={basePath}
          onClose={closeTriage}
          inInvestigation
          onChanged={(updated) => {
            notifications.toasts.addSuccess({
              title: `Alerta actualizada: ${ALERT_STATUS_LABEL[updated.status]}`,
            });
            alert.reload();
          }}
        />
      )}
    </main>
  );
}

function BackLink({ basePath }: { basePath: string }) {
  return (
    <EuiButtonEmpty
      size="s"
      iconType="arrowLeft"
      flush="left"
      href={`${basePath}/app/b89-alerts`}
      className="b89Investigation__back"
    >
      Cola de alertas
    </EuiButtonEmpty>
  );
}

/** «P2 · Escalada · Responsable: Tú · Conclusión: Sin clasificar · Incidente … · 21 nov 14:35 (hace 2 h)». */
export function AlertStatusLine({
  alert,
  basePath,
  viewerId,
  incident,
  ruleId,
}: {
  alert: Alert;
  basePath: string;
  viewerId: string;
  incident: Incident | null;
  ruleId: string | null;
}) {
  return (
    <>
      <ul className="b89Investigation__facts" aria-label="Estado de la alerta">
        <li>
          <PriorityMark priority={alert.priority} />
        </li>
        <li>
          <span className="b89Investigation__factLabel">Estado:</span>{' '}
          <strong>{ALERT_STATUS_LABEL[alert.status]}</strong>
        </li>
        <li>
          <span className="b89Investigation__factLabel">Responsable:</span>{' '}
          <Person id={alert.assigneeId} viewerId={viewerId} />
        </li>
        <li>
          <span className="b89Investigation__factLabel">Conclusión:</span>{' '}
          {alert.verdict ? (
            <strong>{VERDICT_LABEL[alert.verdict]}</strong>
          ) : (
            <span className="b89Muted">Sin clasificar</span>
          )}
        </li>
        {alert.incidentId && (
          <li>
            <span className="b89Investigation__factLabel">Incidente:</span>{' '}
            <a
              href={`${basePath}/app/b89-incidents?id=${encodeURIComponent(alert.incidentId)}`}
              data-b89-no-translate=""
            >
              {incident ? incident.title : 'Ver incidente'}
            </a>
            {incident && ` (${INCIDENT_STATUS_LABEL[incident.status]})`}
          </li>
        )}
        <li>
          <time dateTime={alert.occurredAt} className="b89Tabular" data-b89-no-translate="">
            {formatShortDateTime(alert.occurredAt)}
          </time>{' '}
          <span className="b89Muted">({relativeTime(alert.occurredAt)})</span>
        </li>
      </ul>
      <details className="b89Guide__details b89Investigation__tech">
        <summary>Detalle técnico</summary>
        <p className="b89Investigation__techBody">
          {ruleId && (
            <>
              Regla de Wazuh <Mono>{ruleId}</Mono> ·{' '}
            </>
          )}
          Id de la alerta <Mono>{alert.id}</Mono>
        </p>
      </details>
    </>
  );
}

/** Botón con menú desplegable real (EuiPopover + EuiContextMenuPanel) de búsquedas. */
function SearchMenu({
  id,
  label,
  ariaLabel,
  items,
  hint,
  size = 's',
  title,
}: {
  id: string;
  label: string;
  ariaLabel?: string;
  items: ReadonlyArray<{ key: string; name: string; href: string; ariaLabel?: string }>;
  hint?: string;
  size?: 's' | 'xs';
  title?: string;
}) {
  const [open, setOpen] = useState(false);
  const button =
    size === 's' ? (
      <EuiButton
        size="s"
        iconType="arrowDown"
        iconSide="right"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((value) => !value)}
      >
        {label}
      </EuiButton>
    ) : (
      <EuiButtonEmpty
        size="xs"
        iconType="arrowDown"
        iconSide="right"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((value) => !value)}
      >
        {label}
      </EuiButtonEmpty>
    );
  return (
    <EuiPopover
      id={id}
      button={button}
      isOpen={open}
      closePopover={() => setOpen(false)}
      panelPaddingSize="none"
      anchorPosition="downLeft"
    >
      <EuiContextMenuPanel
        title={title}
        items={items.map((item) => (
          <EuiContextMenuItem
            key={item.key}
            href={item.href}
            aria-label={item.ariaLabel}
            onClick={() => setOpen(false)}
          >
            {item.name}
          </EuiContextMenuItem>
        ))}
      />
      {hint && <p className="b89ExportMenu__hint">{hint}</p>}
    </EuiPopover>
  );
}

// ------------------------------------------------------------------------------- Entidades

function EntitiesSection({
  basePath,
  entities,
  active,
  resolving,
  at,
  from,
  to,
  onToggle,
}: {
  basePath: string;
  entities: InvestigationEntity[];
  active: readonly string[];
  resolving: boolean;
  at: string;
  from: string;
  to: string;
  onToggle: (key: string, on: boolean) => void;
}) {
  const full = active.length >= MAX_QUERY_ENTITIES;
  return (
    <section className="b89Investigation__entities" aria-labelledby="b89EntitiesTitle">
      <EuiTitle size="xs">
        <h2 id="b89EntitiesTitle">Quiénes están involucrados</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      {resolving ? (
        <EuiLoadingContent lines={2} />
      ) : entities.length === 0 ? (
        <EmptyLine>
          Esta alerta no trae equipo, usuario ni IP reconocibles. Revisa la evidencia más abajo.
        </EmptyLine>
      ) : (
        <>
          <ul className="b89EntityCards">
            {entities.map((item, index) => {
              const key = entityKey(item);
              return (
                <EntityCard
                  key={key}
                  index={index}
                  basePath={basePath}
                  entity={item}
                  on={active.includes(key)}
                  canEnable={!full}
                  at={at}
                  from={from}
                  to={to}
                  onToggle={(on) => onToggle(key, on)}
                />
              );
            })}
          </ul>
          {entities.length > MAX_QUERY_ENTITIES && (
            <p className="b89Investigation__note">
              Puedes incluir hasta {MAX_QUERY_ENTITIES} entidades a la vez en la línea de tiempo.
              {full ? ' Quita alguna para añadir otra.' : ''}
            </p>
          )}
        </>
      )}
    </section>
  );
}

function EntityCard({
  index,
  basePath,
  entity,
  on,
  canEnable,
  at,
  from,
  to,
  onToggle,
}: {
  index: number;
  basePath: string;
  entity: InvestigationEntity;
  on: boolean;
  canEnable: boolean;
  at: string;
  from: string;
  to: string;
  onToggle: (on: boolean) => void;
}) {
  const { api } = useConsole();
  const [risk, setRisk] = useState<EntityRisk | null>(null);
  useEffect(() => {
    let alive = true;
    fetchEntityRisk(api.apiPrefix, entity.kind, entity.value).then((value) => {
      if (alive) setRisk(value);
    });
    return () => {
      alive = false;
    };
  }, [api, entity.kind, entity.value]);
  const kql = entityKql([entity]);
  const kind = ENTITY_KIND_LABEL[entity.kind];
  const named = `${kind} ${entity.value}`;
  const valueId = `b89EntityValue${index}`;
  return (
    <li className={`b89EntityCard${on ? ' b89EntityCard--on' : ''}`}>
      <div className="b89Entity__head">
        <span className="b89Entity__kind">{kind}</span>
        {risk && <RiskChip risk={risk} />}
      </div>
      <span className="b89Entity__value" id={valueId} data-b89-no-translate="">
        {entity.value}
      </span>
      <div className="b89Entity__actions">
        <EuiButtonEmpty
          size="xs"
          flush="left"
          iconType="inspect"
          href={entityInvestigationHref(basePath, entity.kind, entity.value, at)}
          aria-label={`Investigar ${named}`}
        >
          Investigar
        </EuiButtonEmpty>
        <SearchMenu
          id={`b89EntitySearch${index}`}
          size="xs"
          label="Más búsquedas"
          ariaLabel={`Más búsquedas de ${named}`}
          title={entity.field ? `Campo del SIEM: ${entity.field}` : undefined}
          items={[
            {
              key: 'alerts',
              name: ENTITY_ALERTS_LABEL[entity.kind],
              href: `${basePath}/app/b89-alerts?${new URLSearchParams({ q: entity.value })}`,
              ariaLabel: `${ENTITY_ALERTS_LABEL[entity.kind]}: ${entity.value}`,
            },
            {
              key: 'th',
              name: 'Buscar en Threat Hunting',
              href: threatHuntingUrl(basePath, kql, from, to),
              ariaLabel: `Buscar ${entity.value} en Threat Hunting`,
            },
            {
              key: 'discover',
              name: 'Buscar en Discover',
              href: discoverUrlForQuery(basePath, kql, from, to),
              ariaLabel: `Buscar ${entity.value} en Discover`,
            },
          ]}
        />
      </div>
      <EuiSwitch
        compressed
        label="Incluir en la línea de tiempo"
        checked={on}
        disabled={!on && !canEnable}
        aria-describedby={valueId}
        onChange={(event) => onToggle(event.target.checked)}
      />
    </li>
  );
}

/** Riesgo acumulado de la entidad: palabra + escala, no solo color. */
function RiskChip({ risk }: { risk: EntityRisk }) {
  const word = riskWord(risk.score);
  const tone = word === 'alto' ? 'high' : word === 'medio' ? 'medium' : 'low';
  const last = risk.lastSeen
    ? ` · última señal ${new Date(risk.lastSeen).toLocaleString('es-PE', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })}`
    : '';
  return (
    <EuiToolTip content={`Riesgo acumulado de esta entidad en B89 (0–100)${last}`}>
      <span className={`b89Risk b89Risk--${tone}`} tabIndex={0}>
        Riesgo {word} · <strong className="b89Tabular">{Math.round(risk.score)}</strong>/100
      </span>
    </EuiToolTip>
  );
}

// ------------------------------------------------------------------------ Línea de tiempo

function TimelineSection({
  basePath,
  heading,
  subject,
  anchorLabel,
  entities,
  allEntities,
  resolving,
  anchor,
  range,
  onRange,
  excludeId,
  hasRuleSearch,
}: {
  basePath: string;
  heading: string;
  subject: string;
  anchorLabel: string;
  entities: InvestigationEntity[];
  allEntities: number;
  resolving: boolean;
  anchor: string;
  range: RelatedWindow;
  onRange: (range: RelatedWindow) => void;
  excludeId?: string;
  hasRuleSearch: boolean;
}) {
  const [view, setView] = useState<TimelineView>('list');
  const [order, setOrder] = useState<TimelineOrder>('asc');
  return (
    <section aria-labelledby="b89TimelineTitle">
      <EuiTitle size="xs">
        <h2 id="b89TimelineTitle">{heading}</h2>
      </EuiTitle>
      <EuiText size="xs" color="subdued">
        <p>
          Otros eventos del SIEM con el mismo equipo, usuario o IP que {subject}. Elige qué
          entidades incluir en «Quiénes están involucrados».
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <div className="b89TimelineControls">
        <div className="b89TimelineControls__group">
          <span className="b89TimelineControls__label" aria-hidden="true">
            Ventana
          </span>
          <EuiButtonGroup
            legend="Ventana de tiempo alrededor de la alerta"
            buttonSize="compressed"
            options={RELATED_WINDOWS.map((id) => ({ id, label: RELATED_WINDOW_LABEL[id] }))}
            idSelected={range}
            onChange={(id) => onRange(id as RelatedWindow)}
          />
        </div>
        <div className="b89TimelineControls__group">
          <span className="b89TimelineControls__label" aria-hidden="true">
            Ver
          </span>
          <EuiButtonGroup
            legend="Forma de ver los eventos"
            buttonSize="compressed"
            options={[
              { id: 'list', label: 'Lista' },
              { id: 'groups', label: 'Agrupado' },
            ]}
            idSelected={view}
            onChange={(id) => setView(id as TimelineView)}
          />
        </div>
        <div className="b89TimelineControls__group">
          <span className="b89TimelineControls__label" aria-hidden="true">
            Orden
          </span>
          <EuiButtonGroup
            legend="Orden de los eventos"
            buttonSize="compressed"
            options={[
              { id: 'asc', label: 'Antiguos primero' },
              { id: 'desc', label: 'Recientes primero' },
            ]}
            idSelected={order}
            onChange={(id) => setOrder(id as TimelineOrder)}
          />
        </div>
      </div>
      <EuiSpacer size="m" />
      {resolving ? (
        <EuiLoadingContent lines={4} />
      ) : (
        <Timeline
          basePath={basePath}
          entities={entities}
          anchor={anchor}
          anchorLabel={anchorLabel}
          window={range}
          onWiden={WIDER_WINDOW[range] ? () => onRange(WIDER_WINDOW[range]!) : undefined}
          excludeId={excludeId}
          noEntities={allEntities === 0}
          hasRuleSearch={hasRuleSearch}
          view={view}
          order={order}
        />
      )}
    </section>
  );
}

function Timeline({
  basePath,
  entities,
  anchor,
  anchorLabel,
  window,
  onWiden,
  excludeId,
  noEntities,
  hasRuleSearch,
  view,
  order,
}: {
  basePath: string;
  entities: InvestigationEntity[];
  anchor: string;
  anchorLabel: string;
  window: RelatedWindow;
  onWiden?: () => void;
  excludeId?: string;
  noEntities: boolean;
  hasRuleSearch: boolean;
  view: TimelineView;
  order: TimelineOrder;
}) {
  const keys = entities.map(entityKey).join('|');
  const related = useAsync(
    () =>
      entities.length === 0
        ? Promise.resolve(null)
        : fetchRelated(basePath, { entities, at: anchor, window, exclude: excludeId }),
    [basePath, keys, anchor, window, excludeId],
  );
  const data = related.loading ? null : related.data;
  const requestKey = JSON.stringify([keys, anchor, window, excludeId ?? '']);
  const [pageState, setPageState] = useState<{
    key: string;
    pages: RelatedResponse[];
    loading: boolean;
    error: unknown | null;
  }>({ key: requestKey, pages: [], loading: false, error: null });
  const pages = pageState.key === requestKey ? pageState.pages : [];
  const loadingMore = pageState.key === requestKey && pageState.loading;
  const pageError = pageState.key === requestKey ? pageState.error : null;
  const continuationCursor =
    pages.length > 0 ? pages[pages.length - 1].nextCursor : data?.nextCursor;
  const allEvents = useMemo(
    () => (data?.access === 'ok' ? [...data.events, ...pages.flatMap((page) => page.events)] : []),
    [data, pages],
  );
  const loadMore = useCallback(async () => {
    const cursor = continuationCursor;
    if (!cursor || loadingMore) return;
    setPageState((current) => ({
      key: requestKey,
      pages: current.key === requestKey ? current.pages : [],
      loading: true,
      error: null,
    }));
    try {
      const page = await fetchRelated(basePath, {
        entities,
        at: anchor,
        window,
        exclude: excludeId,
        cursor,
      });
      if (page.access !== 'ok') {
        throw new Error(
          page.access === 'forbidden'
            ? ACCESS_MESSAGE.forbidden
            : 'No se pudieron traer más eventos. Reintenta.',
        );
      }
      setPageState((current) =>
        current.key === requestKey
          ? { ...current, pages: [...current.pages, page], loading: false, error: null }
          : current,
      );
    } catch (error) {
      setPageState((current) =>
        current.key === requestKey ? { ...current, loading: false, error } : current,
      );
    }
  }, [
    anchor,
    basePath,
    continuationCursor,
    entities,
    excludeId,
    loadingMore,
    pages,
    requestKey,
    window,
  ]);
  const resetPages = useCallback(() => {
    setPageState({ key: requestKey, pages: [], loading: false, error: null });
    void related.reload();
  }, [related.reload, requestKey]);
  useEffect(() => {
    setPageState({ key: requestKey, pages: [], loading: false, error: null });
  }, [requestKey]);
  if (noEntities) {
    return (
      <EmptyLine>
        Sin equipo, usuario ni IP no hay con qué buscar otros eventos.
        {hasRuleSearch ? ' Usa «Buscar en el SIEM» para buscar por la regla de la alerta.' : ''}
      </EmptyLine>
    );
  }
  if (entities.length === 0) {
    return (
      <EmptyLine>
        Incluye al menos una entidad en «Quiénes están involucrados» para ver su actividad.
      </EmptyLine>
    );
  }
  if (related.loading) return <EuiLoadingContent lines={5} />;
  if (related.error) return <ErrorCallout error={related.error} onRetry={resetPages} />;
  if (!data) return null;
  if (data.access !== 'ok') {
    return (
      <EuiCallOut size="s" color="warning" iconType="lock" title={ACCESS_MESSAGE[data.access]} />
    );
  }
  if (data.events.length === 0 && pages.length === 0) {
    return (
      <>
        <EmptyLine>
          Sin otros eventos de estas entidades en {RELATED_WINDOW_LABEL[window]} alrededor del
          momento de la alerta.
        </EmptyLine>
        {onWiden && (
          <EuiButton size="s" iconType="expand" onClick={onWiden}>
            Ampliar a {RELATED_WINDOW_LABEL[window === '1h' ? '24h' : '7d']}
          </EuiButton>
        )}
      </>
    );
  }
  const complete = !continuationCursor;
  const pagination = continuationCursor ? (
    <div className="b89Investigation__pagination">
      <InvestigationPagination
        loading={loadingMore}
        error={Boolean(pageError)}
        remaining={data.total - allEvents.length}
        pageSize={data.pageSize || data.events.length}
        older={order === 'asc'}
        onLoadMore={loadMore}
        onReset={resetPages}
      />
    </div>
  ) : null;
  return (
    <DataZone>
      <p className="b89Investigation__count">
        {complete
          ? `${allEvents.length} ${allEvents.length === 1 ? 'evento' : 'eventos'}`
          : `Mostrando los ${allEvents.length} más recientes de ${data.total} eventos`}
        {Object.entries(data.perEntity).length > 0 && ' · '}
        {Object.entries(data.perEntity)
          .map(([key, count]) => `${entityKeyLabel(key)}: ${count}`)
          .join(' · ')}
      </p>
      {view === 'groups' ? (
        <>
          <InvestigationActivityGroups events={allEvents} order={order} />
          {pagination}
        </>
      ) : (
        <>
          {order === 'asc' && pagination}
          <TimelineList
            basePath={basePath}
            events={allEvents}
            anchor={anchor}
            anchorLabel={anchorLabel}
            order={order}
            complete={complete}
          />
          {order === 'desc' && pagination}
        </>
      )}
    </DataZone>
  );
}

export function TimelineList({
  basePath,
  events,
  anchor,
  anchorLabel = 'Momento de la alerta',
  order,
  complete,
}: {
  basePath: string;
  events: readonly InvestigationEventSummary[];
  anchor: string;
  anchorLabel?: string;
  order: TimelineOrder;
  complete: boolean;
}) {
  const entries = useMemo(
    () => buildTimelineEntries(events, anchor, order, complete),
    [events, anchor, order, complete],
  );
  return (
    <ol className="b89Timeline" aria-label="Eventos en orden de tiempo">
      {entries.map((entry) =>
        entry.type === 'day' ? (
          <li key={entry.key} className="b89Timeline__day">
            <span>{entry.label}</span>
          </li>
        ) : entry.type === 'anchor' ? (
          <li key={entry.key} className="b89Timeline__anchor">
            <span>
              {anchorLabel} ·{' '}
              <time dateTime={entry.at} className="b89Tabular">
                {formatClock(entry.at)}
              </time>
            </span>
          </li>
        ) : (
          <TimelineRow key={entry.key} basePath={basePath} item={entry.event} anchor={anchor} />
        ),
      )}
    </ol>
  );
}

function TimelineRow({
  basePath,
  item,
  anchor,
}: {
  basePath: string;
  item: InvestigationEventSummary;
  anchor: string;
}) {
  const [open, setOpen] = useState(false);
  const detailId = `b89EventDetail-${item.id.replace(/[^A-Za-z0-9_-]/gu, '_')}`;
  return (
    <li className="b89Timeline__item" data-tone={levelTone(item.level)}>
      <div className="b89Timeline__dot" aria-hidden="true" />
      <div className="b89Timeline__body">
        <div className="b89Timeline__meta">
          <time dateTime={item.at} className="b89Timeline__clock b89Tabular">
            {formatClock(item.at)}
          </time>
          <span className="b89Tabular">{formatOffset(item.at, anchor)}</span>
          <SourceBadge id={item.vendor} basePath={basePath} />
          <span className="b89Level" data-tone={levelTone(item.level)}>
            {levelText(item.level)}
          </span>
          {item.mitre.ids.slice(0, 3).map((id) => (
            <span key={id} className="b89Mitre">
              {id}
            </span>
          ))}
        </div>
        <p className="b89Timeline__title">{item.description || 'Sin descripción'}</p>
        {item.matched.length > 0 && (
          <p className="b89Match">
            Coincide con: {item.matched.map((key) => entityKeyLabel(key)).join(', ')}
          </p>
        )}
        <EuiButtonEmpty
          size="xs"
          flush="left"
          iconType={open ? 'arrowDown' : 'arrowRight'}
          aria-expanded={open}
          aria-controls={detailId}
          onClick={() => setOpen((value) => !value)}
        >
          {open ? 'Ocultar detalle' : 'Ver detalle'}
        </EuiButtonEmpty>
        <div id={detailId}>{open && <EventDetail basePath={basePath} id={item.id} />}</div>
      </div>
    </li>
  );
}

/** Detalle de un evento: campos clave primero, JSON completo plegado. */
function EventDetail({ basePath, id }: { basePath: string; id: string }) {
  const loaded = useAsync(() => fetchEvent(basePath, id), [basePath, id]);
  if (loaded.loading) return <EuiLoadingContent lines={3} />;
  if (loaded.error) return <ErrorCallout error={loaded.error} onRetry={loaded.reload} />;
  const event = loaded.data?.event;
  if (!event) {
    return <EmptyLine>Este evento ya no está en el SIEM. Puede haberse borrado por antigüedad.</EmptyLine>;
  }
  return (
    <div className="b89EventDetail">
      <EventKeyValues basePath={basePath} event={event} />
      <EuiSpacer size="s" />
      <details className="b89Guide__details">
        <summary>JSON completo</summary>
        <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable overflowHeight={360}>
          {JSON.stringify(event.raw, null, 2)}
        </EuiCodeBlock>
      </details>
    </div>
  );
}

function EventKeyValues({ basePath, event }: { basePath: string; event: InvestigationEvent }) {
  const byKind = (kind: EntityKind) =>
    event.entities.filter((item) => item.kind === kind).map((item) => item.value);
  const users = byKind('user');
  const ips = byKind('ip');
  const hosts = byKind('host');
  return (
    <dl className="b89KeyValues" data-b89-no-translate="">
      <dt>Fuente</dt>
      <dd>
        <SourceBadge id={event.vendor} basePath={basePath} />
      </dd>
      <dt>Qué pasó</dt>
      <dd>{event.description || 'Sin descripción'}</dd>
      {(event.agent || hosts.length > 0) && (
        <>
          <dt>Equipo (agente)</dt>
          <dd>{[event.agent, ...hosts].filter(Boolean).filter(unique).join(', ')}</dd>
        </>
      )}
      {users.length > 0 && (
        <>
          <dt>Usuario</dt>
          <dd>{users.join(', ')}</dd>
        </>
      )}
      {ips.length > 0 && (
        <>
          <dt>IP</dt>
          <dd>{ips.join(', ')}</dd>
        </>
      )}
      {event.location && (
        <>
          <dt>Ubicación</dt>
          <dd>
            <Mono>{event.location}</Mono>
          </dd>
        </>
      )}
      <dt>Categorías</dt>
      <dd>{event.groups.join(', ') || '—'}</dd>
      <dt>Regla de Wazuh</dt>
      <dd>
        <Mono>{event.ruleId}</Mono> · {levelText(event.level)}
      </dd>
    </dl>
  );
}

function unique(value: unknown, index: number, list: readonly unknown[]): boolean {
  return list.indexOf(value) === index;
}

// ------------------------------------------------------------------------------ Evidencia

function SourceEvent({
  basePath,
  access,
  match,
  event,
  loading,
  error,
  onRetry,
}: {
  basePath: string;
  access: IndexerAccess;
  match: 'exact' | 'matched' | 'none';
  event: InvestigationEvent | null;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  return (
    <EuiPanel paddingSize="m" className="b89Card">
      <EuiTitle size="xs">
        <h2>Evidencia: evento original</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      {error ? (
        <ErrorCallout error={error} onRetry={onRetry} />
      ) : loading ? (
        <EuiLoadingContent lines={3} />
      ) : access !== 'ok' ? (
        <EuiCallOut size="s" color="warning" iconType="lock" title={ACCESS_MESSAGE[access]} />
      ) : !event ? (
        <EmptyLine>No se encontró el evento original. Puede haberse borrado por antigüedad.</EmptyLine>
      ) : (
        <>
          <EventKeyValues basePath={basePath} event={event} />
          {match === 'matched' && (
            <p className="b89Investigation__note">
              Localizado por regla y hora (la alerta no guarda el id exacto).
            </p>
          )}
          <EuiSpacer size="s" />
          <EuiAccordion
            id="b89-source-json"
            buttonContent="Ver el evento completo (JSON)"
            paddingSize="s"
          >
            <p className="b89Investigation__note">
              Id del documento: <Mono>{event.id}</Mono>
            </p>
            {event.rawTruncated && (
              <EuiCallOut
                size="s"
                color="warning"
                title="El evento es muy grande (más de 64 KB): se muestra recortado."
              />
            )}
            <EuiCodeBlock
              language="json"
              fontSize="s"
              paddingSize="s"
              isCopyable
              overflowHeight={480}
            >
              {JSON.stringify(event.raw, null, 2)}
            </EuiCodeBlock>
          </EuiAccordion>
        </>
      )}
    </EuiPanel>
  );
}

// --------------------------------------------------------------------------------- MITRE

function MitrePanel({
  basePath,
  mitre,
}: {
  basePath: string;
  mitre: { ids: readonly string[]; tactics: readonly string[]; techniques: readonly string[] };
}) {
  return (
    <EuiPanel paddingSize="m" className="b89Card">
      <EuiTitle size="xs">
        <h2>MITRE ATT&amp;CK</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <div className="b89Chips" data-b89-no-translate="">
        {mitre.ids.map((id, index) => {
          const url = mitreTechniqueUrl(id);
          const name = mitre.techniques[index];
          return url ? (
            <a
              key={id}
              className="b89Mitre b89Mitre--link"
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`${id}${name ? ` · ${name}` : ''} (se abre attack.mitre.org en otra pestaña)`}
            >
              {id}
              {name ? ` · ${name}` : ''}
            </a>
          ) : (
            <span key={id} className="b89Mitre">
              {id}
            </span>
          );
        })}
      </div>
      {mitre.tactics.length > 0 && (
        <EuiText size="xs" color="subdued">
          <p>
            {mitre.tactics.length === 1 ? 'Táctica' : 'Tácticas'}: {mitre.tactics.join(', ')}
          </p>
        </EuiText>
      )}
      <EuiSpacer size="s" />
      <EuiButtonEmpty size="xs" flush="left" href={`${basePath}/app/mitre-attack`}>
        Ver la matriz MITRE del SIEM
      </EuiButtonEmpty>
    </EuiPanel>
  );
}

// ------------------------------------------------------------------------------ Incidente

function IncidentPanel({
  alert,
  basePath,
  incident,
  onChanged,
}: {
  alert: Alert;
  basePath: string;
  incident: { data: Incident | null; loading: boolean; error: unknown; reload: () => void };
  onChanged: () => void;
}) {
  const { can, notifications, session } = useConsole();
  const [opening, setOpening] = useState(false);
  const canOpen = can(CAPABILITIES.incidentsWrite);
  return (
    <EuiPanel paddingSize="m" className="b89Card">
      <EuiTitle size="xs">
        <h2>Incidente</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      {!alert.incidentId ? (
        opening ? (
          <OpenIncidentForm
            alert={alert}
            onCancel={() => setOpening(false)}
            onOpened={(incidentId) => {
              notifications.toasts.addSuccess({
                title: 'Incidente abierto y vinculado',
                text: `Ya aparece en la cabecera y en este panel (${incidentId}).`,
              });
              setOpening(false);
              onChanged();
            }}
          />
        ) : (
          <>
            <EmptyLine>Sin incidente. Abre uno si hace falta coordinar tareas o dejar notas.</EmptyLine>
            {alert.status === 'closed' ? (
              <p className="b89Investigation__note">
                La alerta está cerrada: no se puede abrir un incidente.
              </p>
            ) : !canOpen ? (
              <p className="b89Investigation__note">Tu rol no puede abrir incidentes.</p>
            ) : (
              <EuiButton size="s" onClick={() => setOpening(true)}>
                Abrir incidente
              </EuiButton>
            )}
          </>
        )
      ) : incident.loading && !incident.data ? (
        <EuiLoadingContent lines={3} />
      ) : incident.error ? (
        <ErrorCallout error={incident.error} onRetry={incident.reload} />
      ) : incident.data ? (
        <>
          <p className="b89Investigation__incidentTitle" data-b89-no-translate="">
            {incident.data.title}
          </p>
          <ul className="b89Investigation__facts b89Investigation__facts--compact">
            <li>
              <span className="b89Investigation__factLabel">Estado:</span>{' '}
              <strong>{INCIDENT_STATUS_LABEL[incident.data.status]}</strong>
            </li>
            <li>
              <span className="b89Investigation__factLabel">Responsable:</span>{' '}
              <Person id={incident.data.ownerId} viewerId={session.subjectId} />
            </li>
          </ul>
          <EuiSpacer size="s" />
          <EuiButton
            size="s"
            iconType="popout"
            href={`${basePath}/app/b89-incidents?id=${encodeURIComponent(incident.data.id)}`}
          >
            Ver incidente
          </EuiButton>
          <EuiSpacer size="m" />
          <details className="b89Guide__details">
            <summary>Notas del incidente</summary>
            <NotesPanel incident={incident.data} />
          </details>
        </>
      ) : (
        <EmptyLine>No se pudo leer el incidente vinculado. Ábrelo desde Incidentes.</EmptyLine>
      )}
    </EuiPanel>
  );
}
