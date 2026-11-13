/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo, useState } from 'react';
import type { InvestigationEventSummary } from '../../common';
import { VENDORS } from '../../common';
import { Mono, Timestamp } from './primitives';
import {
  DEFAULT_ACTIVITY_GAP_MS,
  groupInvestigationActivity,
} from './investigation_activity_grouping';

const INITIAL_LIMIT = 12;

/**
 * Compact review aid for events already returned by the authorized investigation query.
 * Clusters mean shared entity + temporal proximity only; they do not establish causality.
 */
export function InvestigationActivityGroups({
  events,
  gapMs = DEFAULT_ACTIVITY_GAP_MS,
}: {
  events: readonly InvestigationEventSummary[];
  gapMs?: number;
}) {
  const groups = useMemo(() => groupInvestigationActivity(events, gapMs), [events, gapMs]);
  const [expanded, setExpanded] = useState(false);
  if (groups.length === 0) return null;

  return (
    <section className="b89ActivityGroups" aria-labelledby="b89ActivityGroupsTitle">
      <header className="b89ActivityGroups__header">
        <div>
          <h3 id="b89ActivityGroupsTitle">Actividad agrupada por entidad y tiempo</h3>
          <p>
            Cada grupo reúne eventos con una entidad coincidente y hasta {Math.round(gapMs / 60000)}{' '}
            minutos entre eventos. Es una ayuda para revisar la cronología; no confirma causalidad
            ni identifica un hilo de correo. Un evento puede aparecer en más de un grupo si coincide
            con varias entidades.
          </p>
        </div>
        <span className="b89ActivityGroups__count">
          {groups.length} {groups.length === 1 ? 'grupo' : 'grupos'}
        </span>
      </header>
      <ol className="b89ActivityGroups__list">
        {groups.map((group, index) => (
          <li
            key={`${group.entity}:${group.firstAt}:${index}`}
            className={!expanded && index >= INITIAL_LIMIT ? 'is-collapsed' : undefined}
          >
            <details>
              <summary>
                <span className="b89ActivityGroups__entity" data-b89-no-translate="">
                  {group.entity}
                </span>
                <span className="b89ActivityGroups__range">
                  <Timestamp iso={group.firstAt} /> – <Timestamp iso={group.lastAt} />
                </span>
                <span className="b89ActivityGroups__count">
                  {group.events.length} {group.events.length === 1 ? 'evento' : 'eventos'}
                </span>
              </summary>
              <ol className="b89ActivityGroups__events">
                {group.events.map((event) => (
                  <li key={event.id}>
                    <Timestamp iso={event.at} />
                    <span>{VENDORS[event.vendor].name}</span>
                    <span className="b89ActivityGroups__description">{event.description}</span>
                    <span className="b89ActivityGroups__rule">
                      regla <Mono>{event.ruleId}</Mono>
                    </span>
                    <span className="b89ActivityGroups__id" data-b89-no-translate="">
                      {event.id}
                    </span>
                  </li>
                ))}
              </ol>
            </details>
          </li>
        ))}
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
