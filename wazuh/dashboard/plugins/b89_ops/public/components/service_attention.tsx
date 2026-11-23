import React, { useEffect, useRef, useState } from 'react';
import {
  discoverUrlForQuery,
  LEVEL_BAND_RANGES,
  LevelBand,
  ServiceAttention,
  ServiceId,
  TopEvent,
} from '../../common';
import { DataZone, Timestamp } from './primitives';

const GROUPS: Partial<Record<ServiceId, string>> = {
  office365: 'office365',
  sharepoint: 'b89_sharepoint',
  aws: 'aws',
  cloudflare: 'cloudflare',
  bitdefender: 'bitdefender',
  snyk: 'snyk',
};

function withGroup(range: string, service?: ServiceId): string {
  const group = service ? GROUPS[service] : undefined;
  return group ? `${range} and rule.groups: "${group}"` : range;
}

/** Eventos de nivel 8 o más, o solo de nivel 12 o más, de un servicio. */
export function attentionQuery(service: ServiceId, criticalOnly: boolean): string {
  return withGroup(`rule.level >= ${criticalOnly ? 12 : 8}`, service);
}

/**
 * KQL de exactamente una banda de nivel (12–15, 8–11, 4–7 o 0–3), opcionalmente de un servicio. La lista que abre cuenta lo mismo que la cifra.
 */
export function levelBandQuery(band: LevelBand, service?: ServiceId): string {
  const { from, to } = LEVEL_BAND_RANGES[band];
  const range =
    band === 'critical'
      ? `rule.level >= ${from}`
      : from === 0
        ? `rule.level <= ${to - 1}`
        : `rule.level >= ${from} and rule.level <= ${to - 1}`;
  return withGroup(range, service);
}

/** Discover con solo los eventos de una banda en la ventana indicada (por defecto 24 h). */
export function levelBandHref(
  basePath: string,
  band: LevelBand,
  service?: ServiceId,
  from = 'now-24h',
): string {
  return discoverUrlForQuery(basePath, levelBandQuery(band, service), from, 'now');
}

export function filterAttention(events: readonly TopEvent[], criticalOnly: boolean, query: string) {
  const term = query.trim().toLocaleLowerCase();
  return events.filter(
    (event) =>
      (!criticalOnly || event.level >= 12) &&
      `${event.description} ${event.ruleId} ${event.agent ?? ''}`
        .toLocaleLowerCase()
        .includes(term),
  );
}

/**
 * Pulsación de una cifra de la tarjeta sobre la lista «Atención prioritaria»: `critical` deja solo
 * el nivel 12 o más; `all`, el nivel 8 o más. `seq` cambia en cada pulsación (aunque se repita la
 * cifra) para volver a aplicar el filtro y limpiar la búsqueda.
 */
export interface AttentionFocus {
  readonly band: 'critical' | 'all';
  readonly seq: number;
}

export function ServiceAttentionList({
  service,
  name,
  data,
  basePath,
  focus,
  criticalTotal,
}: {
  service: ServiceId;
  name: string;
  data?: ServiceAttention;
  basePath: string;
  focus?: AttentionFocus;
  /** Total de nivel 12 o más en 24 h (de la tarjeta), para el resumen cuando solo se ven esos. */
  criticalTotal?: number;
}) {
  const [criticalOnly, setCriticalOnly] = useState(focus?.band === 'critical');
  const [query, setQuery] = useState('');
  const statusRef = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (!focus || focus.seq === 0) return;
    setCriticalOnly(focus.band === 'critical');
    setQuery('');
    statusRef.current?.focus({ preventScroll: true });
  }, [focus]);
  const events = filterAttention(data?.events ?? [], criticalOnly, query);
  const allHref = discoverUrlForQuery(
    basePath,
    attentionQuery(service, criticalOnly),
    'now-24h',
    'now',
  );
  const filtered = criticalOnly || query.trim() !== '';
  return (
    <section
      className="b89Attention"
      aria-label={`Atención prioritaria: ${name}`}
      data-filter={criticalOnly ? 'critical' : 'all'}
    >
      <header>
        <strong>Atención prioritaria</strong>
        <span>24 h · nivel más alto primero</span>
      </header>
      {!data || data.access !== 'ok' ? (
        <p role="status">
          {data?.access === 'forbidden'
            ? 'Sin permiso para consultar estos eventos.'
            : 'Lista no disponible. Actualiza el resumen para reintentar.'}
        </p>
      ) : (
        <>
          <div className="b89Attention__controls">
            <label className="b89Attention__toggle" data-active={criticalOnly}>
              <input
                type="checkbox"
                checked={criticalOnly}
                onChange={(e) => setCriticalOnly(e.target.checked)}
              />{' '}
              Solo nivel 12 o más
            </label>
            <input
              type="search"
              aria-label={`Buscar en eventos visibles de ${name}`}
              placeholder="Buscar por nombre, regla o equipo"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <p
            className="b89Attention__filter"
            role="status"
            tabIndex={-1}
            ref={statusRef}
            data-active={filtered}
          >
            <span>
              {criticalOnly
                ? 'Mostrando solo nivel 12 o más'
                : 'Mostrando nivel 8 o más'}
              {query.trim() ? ` que contienen «${query.trim()}»` : ''}
            </span>
            {filtered && (
              <button
                type="button"
                className="b89Attention__clear"
                onClick={() => {
                  setCriticalOnly(false);
                  setQuery('');
                }}
              >
                Quitar filtro
              </button>
            )}
          </p>
          <p className="b89Attention__scope">
            {events.length} visibles ·{' '}
            {criticalOnly && criticalTotal !== undefined
              ? `${criticalTotal} de nivel 12 o más en 24 h.`
              : `${data.total} de nivel 8 o más.`}
            {(data.total ?? 0) > data.events.length &&
              ' Se muestran los 100 de nivel más alto; abre la lista completa para ver el resto.'}
          </p>
          {events.length === 0 ? (
            <p>
              {data.total === 0
                ? 'Sin eventos de nivel 8 o más en las últimas 24 h.'
                : criticalOnly && !query.trim()
                  ? 'Ninguno de nivel 12 o más entre los cargados.'
                  : 'Sin coincidencias en los eventos cargados.'}
            </p>
          ) : (
            <ol className="b89Attention__list" tabIndex={0} aria-label={`Eventos de ${name}`}>
              {events.map((event) => (
                <li key={event.id}>
                  <div className="b89Attention__row">
                    <span className="b89Attention__severity" data-critical={event.level >= 12}>
                      <span aria-hidden="true">{event.level >= 12 ? '▲' : '△'}</span> Nivel{' '}
                      {event.level}
                    </span>
                    <Timestamp iso={event.at || null} focusable={false} />
                  </div>
                  <DataZone>
                    <strong>{event.description}</strong>
                  </DataZone>
                  <div className="b89Attention__row">
                    <span data-b89-no-translate="">{event.agent ?? 'Equipo no informado'}</span>
                    <span className="b89Attention__rule">Regla {event.ruleId}</span>
                  </div>
                  <a
                    href={discoverUrlForQuery(
                      basePath,
                      `_id: ${JSON.stringify(event.id)}`,
                      'now-24h',
                      'now',
                    )}
                  >
                    Investigar evento →
                  </a>
                </li>
              ))}
            </ol>
          )}
          <a className="b89Attention__all" href={allHref}>
            Ver todos los eventos de nivel {criticalOnly ? '12' : '8'} o más →
          </a>
        </>
      )}
    </section>
  );
}
