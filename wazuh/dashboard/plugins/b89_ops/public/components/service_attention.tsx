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

/** Eventos de nivel ≥ 8 (altas y críticas) o solo ≥ 12 (críticas) de un servicio. */
export function attentionQuery(service: ServiceId, criticalOnly: boolean): string {
  return withGroup(`rule.level >= ${criticalOnly ? 12 : 8}`, service);
}

/**
 * KQL de exactamente una banda de severidad (Crítica = nivel ≥ 12, Alta = 8–11, Media = 4–7,
 * Baja = 0–3), opcionalmente de un servicio. La lista que abre cuenta lo mismo que la cifra.
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
 * las críticas; `all`, altas y críticas. `seq` cambia en cada pulsación (aunque se repita la
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
  /** Total de críticas en 24 h (de la tarjeta), para el resumen cuando solo se ven críticas. */
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
        <span>24 h · críticas primero</span>
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
              Solo críticas (nivel ≥ 12)
            </label>
            <input
              type="search"
              aria-label={`Buscar en eventos visibles de ${name}`}
              placeholder="Buscar título, regla o equipo"
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
                ? 'Mostrando solo críticas (nivel ≥ 12)'
                : 'Mostrando altas y críticas (nivel ≥ 8)'}
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
              ? `${criticalTotal} críticas en 24 h.`
              : `${data.total} altas y críticas.`}
            {(data.total ?? 0) > data.events.length &&
              ' Vista limitada a los 100 eventos de mayor severidad; abre la lista completa para revisar el resto.'}
          </p>
          {events.length === 0 ? (
            <p>
              {data.total === 0
                ? 'Sin eventos altos o críticos en esta ventana.'
                : criticalOnly && !query.trim()
                  ? 'Sin eventos críticos entre los cargados.'
                  : 'Sin coincidencias en los eventos cargados.'}
            </p>
          ) : (
            <ol className="b89Attention__list" tabIndex={0} aria-label={`Eventos de ${name}`}>
              {events.map((event) => (
                <li key={event.id}>
                  <div className="b89Attention__row">
                    <span className="b89Attention__severity" data-critical={event.level >= 12}>
                      {event.level >= 12 ? 'Crítica' : 'Alta'} · {event.level}
                    </span>
                    <Timestamp iso={event.at || null} />
                  </div>
                  <DataZone>
                    <strong>{event.description}</strong>
                  </DataZone>
                  <div className="b89Attention__row">
                    Regla {event.ruleId} ·{' '}
                    <DataZone>{event.agent ?? 'Equipo no informado'}</DataZone>
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
            Ver todos los eventos {criticalOnly ? 'críticos' : 'altos y críticos'} →
          </a>
          <small>
            Severidad del SIEM; el estado de respuesta se gestiona en la cola B89. Las fuentes
            pueden compartir eventos.
          </small>
        </>
      )}
    </section>
  );
}
