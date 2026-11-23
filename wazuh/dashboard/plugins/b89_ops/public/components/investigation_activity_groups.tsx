/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo, useState } from 'react';
import type { InvestigationEventSummary } from '../../common';
import { VENDORS } from '../../common';
import {
  DEFAULT_ACTIVITY_GAP_MS,
  entityKeyLabel,
  formatClock,
  formatDay,
  groupInvestigationActivity,
  levelText,
  TimelineOrder,
} from './investigation_activity_grouping';

const INITIAL_LIMIT = 12;

/**
 * Vista «Agrupado» de la línea de tiempo: los mismos eventos ya cargados, reunidos por entidad
 * coincidente y cercanía en el tiempo. Sustituye a la lista (no se dibujan dos veces).
 */
export function InvestigationActivityGroups({
  events,
  gapMs = DEFAULT_ACTIVITY_GAP_MS,
  order = 'asc',
}: {
  events: readonly InvestigationEventSummary[];
  gapMs?: number;
  order?: TimelineOrder;
}) {
  const groups = useMemo(() => {
    const list = groupInvestigationActivity(events, gapMs);
    return list.sort((left, right) =>
      order === 'asc'
        ? Date.parse(left.firstAt) - Date.parse(right.firstAt)
        : Date.parse(right.lastAt) - Date.parse(left.lastAt),
    );
  }, [events, gapMs, order]);
  const [expanded, setExpanded] = useState(false);
  if (groups.length === 0) {
    return (
      <p className="b89ActivityGroups__empty">
        Ningún evento coincide con una entidad activa: no hay grupos que mostrar.
      </p>
    );
  }
  const minutes = Math.round(gapMs / 60000);

  return (
    <section className="b89ActivityGroups" aria-label="Actividad agrupada por entidad">
      <p className="b89ActivityGroups__intro">
        Eventos de la misma entidad con menos de {minutes} min entre sí ·{' '}
        <span className="b89ActivityGroups__count">
          {groups.length} {groups.length === 1 ? 'grupo' : 'grupos'}
        </span>
      </p>
      <ol className="b89ActivityGroups__list">
        {groups.map((group, index) => {
          const sameDay = formatDay(group.firstAt) === formatDay(group.lastAt);
          const ordered =
            order === 'asc' ? group.events : [...group.events].reverse();
          return (
            <li
              key={`${group.entity}:${group.firstAt}:${index}`}
              className={!expanded && index >= INITIAL_LIMIT ? 'is-collapsed' : undefined}
            >
              <details>
                <summary>
                  <span className="b89ActivityGroups__entity" data-b89-no-translate="">
                    {entityKeyLabel(group.entity)}
                  </span>
                  <span className="b89ActivityGroups__range">
                    {formatDay(group.firstAt)}{' '}
                    <time dateTime={group.firstAt} className="b89Tabular">
                      {formatClock(group.firstAt)}
                    </time>{' '}
                    – {sameDay ? '' : `${formatDay(group.lastAt)} `}
                    <time dateTime={group.lastAt} className="b89Tabular">
                      {formatClock(group.lastAt)}
                    </time>
                  </span>
                  <span className="b89ActivityGroups__count">
                    {group.events.length} {group.events.length === 1 ? 'evento' : 'eventos'}
                  </span>
                </summary>
                <ol className="b89ActivityGroups__events">
                  {ordered.map((event) => (
                    <li key={event.id}>
                      <time dateTime={event.at} className="b89Tabular">
                        {formatClock(event.at)}
                      </time>
                      <span>{VENDORS[event.vendor]?.name ?? event.vendor}</span>
                      <span className="b89ActivityGroups__level">{levelText(event.level)}</span>
                      <span className="b89ActivityGroups__description">
                        {event.description || 'Sin descripción'}
                      </span>
                    </li>
                  ))}
                </ol>
              </details>
            </li>
          );
        })}
      </ol>
      {groups.length > INITIAL_LIMIT && (
        <button
          type="button"
          className="b89ActivityGroups__toggle"
          aria-expanded={expanded}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded ? 'Mostrar menos grupos' : `Mostrar los ${groups.length} grupos`}
        </button>
      )}
    </section>
  );
}
