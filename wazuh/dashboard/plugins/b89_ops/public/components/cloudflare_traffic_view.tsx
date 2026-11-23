/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiLoadingContent,
  EuiSelect,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  LIMA_LABEL,
  limaInputToIso,
  limaInputValue,
  limaTime,
  STATUS_CLASSES,
  TRAFFIC_DATASET_LABEL,
  TRAFFIC_DATASETS,
  TrafficAggregations,
  TrafficDataset,
  TrafficEvent,
  TrafficFilters,
  TrafficResponse,
} from '../../common';
import { fetchTraffic, trafficExportHref } from '../api/cloudflare_traffic';
import { CloudflareAnalysisPanel } from './cloudflare_analysis_view';
import {
  activeTab,
  applyTop,
  DATASET_COLOR,
  errorMessage,
  FILTER_KEYS,
  FILTER_LABEL,
  FilterKey,
  filterChips,
  flattenSource,
  formatCount,
  histogramColumns,
  hostSessionState,
  intervalLabel,
  ipActivityState,
  parseViewState,
  RANGE_LABEL,
  RANGE_PRESETS,
  RangeMode,
  recordsState,
  statTiles,
  TRAFFIC_TAB_LABEL,
  TRAFFIC_TABS,
  targetOf,
  TOP_LISTS,
  TopListId,
  totalLabel,
  TrafficViewState,
  truncate,
  viewFilters,
  viewStateSearch,
  withFilters,
} from './cloudflare_traffic_model';
import { B89Page } from './console_context';
import { DataZone, EmptyLine, Mono, useIsMobile } from './primitives';

const PAGE_SIZE = 100;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

interface Navigator {
  readonly search: string;
  readonly push: (search: string) => void;
}

/** Vista «Tráfico de Cloudflare». El estado de filtros vive en la URL (`navigator`). */
export function CloudflareTrafficView({
  basePath,
  navigator,
}: {
  basePath: string;
  navigator: Navigator;
}) {
  const state = useMemo(() => parseViewState(navigator.search), [navigator.search]);
  // Los atajos («24 h») se resuelven al cargar o al pulsar «Actualizar», no en cada render.
  const [tick, setTick] = useState(0);
  const now = useMemo(() => Date.now(), [navigator.search, tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const filters = useMemo(() => viewFilters(state, now), [state, now]);
  const go = useCallback(
    (next: TrafficViewState) => navigator.push(viewStateSearch(next)),
    [navigator],
  );

  const [data, setData] = useState<TrafficResponse | null>(null);
  const [events, setEvents] = useState<readonly TrafficEvent[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [selected, setSelected] = useState<TrafficEvent | null>(null);
  const tab = activeTab(state);

  const key = filters.ok ? JSON.stringify(filters.value) : '';
  useEffect(() => {
    // «Registros» solo se consulta cuando está a la vista.
    if (tab !== 'registros') return undefined;
    if (!filters.ok) {
      setLoading(false);
      return undefined;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    fetchTraffic(basePath, filters.value, { size: PAGE_SIZE, signal: controller.signal }).then(
      (response) => {
        setData(response);
        setEvents(response.events);
        setLoading(false);
      },
      (failure: unknown) => {
        if (controller.signal.aborted) return;
        setError(failure);
        setData(null);
        setEvents([]);
        setLoading(false);
      },
    );
    return () => controller.abort();
  }, [basePath, key, tick, tab]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadMore = async () => {
    if (!filters.ok || !data?.nextCursor) return;
    setLoadingMore(true);
    try {
      const next = await fetchTraffic(basePath, data.filters, {
        cursor: data.nextCursor,
        size: PAGE_SIZE,
      });
      // El desempate interno puede repetir una fila en el borde de la página: se descarta.
      setEvents((current) => {
        const seen = new Set(current.map((event) => `${event.index}/${event.id}`));
        return [
          ...current,
          ...next.events.filter((event) => !seen.has(`${event.index}/${event.id}`)),
        ];
      });
      setData({ ...data, nextCursor: next.nextCursor });
    } catch (failure) {
      setError(failure);
    } finally {
      setLoadingMore(false);
    }
  };

  const copyLink = () => {
    try {
      void window.navigator.clipboard?.writeText(window.location.href);
    } catch {
      // Sin portapapeles: la URL de la barra de direcciones sigue siendo el enlace.
    }
  };

  return (
    <B89Page
      title="Tráfico de Cloudflare"
      description={
        <>
          «Análisis» resume qué pasó en el backoffice y en los pagos (sesiones sospechosas,
          movimientos de dinero, exportaciones y anomalías); «Registros» muestra cada evento tal
          cual (HTTP, DNS, firewall/WAF y auditoría). Todas las horas están en {LIMA_LABEL}.
        </>
      }
      actions={
        <EuiFlexGroup gutterSize="s" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="refresh" onClick={() => setTick((v) => v + 1)}>
              Actualizar
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content="Copia la URL con el rango y los filtros actuales">
              <EuiButtonEmpty size="s" iconType="link" onClick={copyLink}>
                Copiar enlace
              </EuiButtonEmpty>
            </EuiToolTip>
          </EuiFlexItem>
          {tab === 'registros' && (
            <EuiFlexItem grow={false}>
              <EuiButton
                size="s"
                iconType="exportAction"
                href={filters.ok ? trafficExportHref(basePath, filters.value) : undefined}
                isDisabled={!filters.ok}
              >
                Exportar CSV
              </EuiButton>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
      }
    >
      <EuiTabs className="b89Traffic__views" aria-label="Vistas del tráfico">
        {TRAFFIC_TABS.map((id) => (
          <EuiTab
            key={id}
            isSelected={tab === id}
            onClick={() => go({ ...state, tab: id })}
            data-test-subj={`b89TrafficTab-${id}`}
          >
            {TRAFFIC_TAB_LABEL[id]}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size="m" />
      <RangeBar state={state} filters={filters.ok ? filters.value : null} onChange={go} />
      <EuiSpacer size="m" />
      {tab === 'analisis' ? (
        !filters.ok ? (
          <EuiCallOut color="warning" iconType="alert" size="s" title={filters.error} />
        ) : (
          <CloudflareAnalysisPanel
            basePath={basePath}
            from={filters.value.from}
            to={filters.value.to}
            zone={state.filters.zone}
            reloadKey={tick}
            onOpenRecords={(link) => go(recordsState(link, state.filters.zone))}
          />
        )
      ) : (
        <>
          <DatasetTabs state={state} aggs={data?.aggregations ?? null} onChange={go} />
          <EuiSpacer size="m" />
          <FilterBar state={state} zones={data?.aggregations?.zones ?? []} onChange={go} />
          <EuiSpacer size="m" />
          {!filters.ok ? (
            <EuiCallOut color="warning" iconType="alert" size="s" title={filters.error} />
          ) : error ? (
            <EuiCallOut
              color={errorMessage(error).tone}
              iconType="alert"
              size="s"
              title={errorMessage(error).title}
            >
              <EuiButtonEmpty size="xs" flush="left" onClick={() => setTick((v) => v + 1)}>
                Reintentar
              </EuiButtonEmpty>
            </EuiCallOut>
          ) : loading && !data ? (
            <EuiLoadingContent lines={8} />
          ) : data ? (
            <>
              {data.partial && (
                <>
                  <EuiCallOut
                    color="warning"
                    iconType="alert"
                    size="s"
                    title="Respuesta parcial del Indexer: algunos datos pueden faltar. Reintente en unos segundos."
                  />
                  <EuiSpacer size="m" />
                </>
              )}
              {data.aggregations && (
                <>
                  <StatTiles aggs={data.aggregations} dataset={state.dataset} />
                  <EuiSpacer size="m" />
                  {/* Gráfico y rankings plegados: la lista de eventos queda a la vista sin desplazarse. */}
                  <details className="b89Guide__details" data-test-subj="b89TrafficCharts">
                    <summary>
                      Ver gráfico por tiempo y lo más frecuente (IPs, rutas, países…)
                    </summary>
                    <EuiSpacer size="m" />
                    <Histogram aggs={data.aggregations} />
                    <EuiSpacer size="m" />
                    <TopLists
                      aggs={data.aggregations}
                      onPick={(list, value) => go(applyTop(state, list, value))}
                    />
                  </details>
                  <EuiSpacer size="l" />
                </>
              )}
              <ResultsTable
                data={data}
                events={events}
                loading={loading}
                loadingMore={loadingMore}
                onLoadMore={loadMore}
                onSelect={setSelected}
              />
            </>
          ) : null}
        </>
      )}
      {selected && (
        <EventFlyout
          event={selected}
          onClose={() => setSelected(null)}
          onNavigate={(next) => {
            setSelected(null);
            go(next);
          }}
          state={state}
        />
      )}
    </B89Page>
  );
}

/* ------------------------------------------------------------------ Rango */

function RangeBar({
  state,
  filters,
  onChange,
}: {
  state: TrafficViewState;
  filters: TrafficFilters | null;
  onChange: (next: TrafficViewState) => void;
}) {
  const [custom, setCustom] = useState(state.range === 'custom');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  useEffect(() => {
    setCustom(state.range === 'custom');
    if (filters) {
      setFrom(limaInputValue(filters.from));
      setTo(limaInputValue(filters.to));
    }
  }, [state.range, filters?.from, filters?.to]); // eslint-disable-line react-hooks/exhaustive-deps
  const fromIso = limaInputToIso(from);
  const toIso = limaInputToIso(to);
  const applyCustom = () => {
    if (fromIso && toIso) onChange({ ...state, range: 'custom', from: fromIso, to: toIso });
  };
  const selected: RangeMode = custom ? 'custom' : state.range;
  return (
    <div className="b89Traffic__range">
      <EuiButtonGroup
        legend="Rango de tiempo"
        buttonSize="compressed"
        options={[...RANGE_PRESETS, 'custom' as const].map((id) => ({
          id,
          label: RANGE_LABEL[id],
        }))}
        idSelected={selected}
        onChange={(id) => {
          if (id === 'custom') {
            setCustom(true);
            return;
          }
          setCustom(false);
          const next: TrafficViewState = { ...state, range: id as RangeMode };
          delete (next as { from?: string }).from;
          delete (next as { to?: string }).to;
          onChange(next);
        }}
      />
      {custom && (
        <form
          className="b89Traffic__custom"
          onSubmit={(event) => {
            event.preventDefault();
            applyCustom();
          }}
        >
          <label>
            <span>Desde (Lima)</span>
            <EuiFieldText
              compressed
              type="datetime-local"
              step={1}
              value={from}
              onChange={(event) => setFrom(event.target.value)}
              aria-label="Desde, hora de Lima"
            />
          </label>
          <label>
            <span>Hasta (Lima)</span>
            <EuiFieldText
              compressed
              type="datetime-local"
              step={1}
              value={to}
              onChange={(event) => setTo(event.target.value)}
              aria-label="Hasta, hora de Lima"
            />
          </label>
          <EuiButton size="s" type="submit" isDisabled={!fromIso || !toIso}>
            Aplicar
          </EuiButton>
        </form>
      )}
      {filters && (
        <EuiText size="xs" color="subdued" className="b89Traffic__rangeText">
          <p>
            Del <strong>{limaTime(filters.from)}</strong> al <strong>{limaTime(filters.to)}</strong>{' '}
            ({LIMA_LABEL}) · UTC {filters.from.slice(0, 19).replace('T', ' ')} →{' '}
            {filters.to.slice(0, 19).replace('T', ' ')}
          </p>
        </EuiText>
      )}
    </div>
  );
}

/* ------------------------------------------------------------- Pestañas */

function DatasetTabs({
  state,
  aggs,
  onChange,
}: {
  state: TrafficViewState;
  aggs: TrafficAggregations | null;
  onChange: (next: TrafficViewState) => void;
}) {
  const all = aggs
    ? TRAFFIC_DATASETS.reduce((sum, dataset) => sum + aggs.datasets[dataset], 0)
    : null;
  const tabs: Array<{ id: TrafficDataset | 'all'; label: string; count: number | null }> = [
    { id: 'all', label: 'Todo', count: all },
    ...TRAFFIC_DATASETS.map((dataset) => ({
      id: dataset,
      label: TRAFFIC_DATASET_LABEL[dataset],
      count: aggs ? aggs.datasets[dataset] : null,
    })),
  ];
  return (
    <EuiTabs size="s" className="b89Tabs">
      {tabs.map((tab) => (
        <EuiTab
          key={tab.id}
          isSelected={state.dataset === tab.id}
          onClick={() => onChange({ ...state, dataset: tab.id })}
        >
          {tab.id !== 'all' && (
            <span
              aria-hidden="true"
              className="b89Traffic__swatch"
              style={{ backgroundColor: DATASET_COLOR[tab.id] }}
            />
          )}
          {tab.label}
          {tab.count !== null && (
            <span className="b89Traffic__tabCount"> {formatCount(tab.count)}</span>
          )}
        </EuiTab>
      ))}
    </EuiTabs>
  );
}

/* --------------------------------------------------------------- Filtros */

const FIELD_PLACEHOLDER: Readonly<
  Record<Exclude<FilterKey, 'zone' | 'method' | 'status'>, string>
> = {
  ip: 'IP o CIDR, p. ej. 190.12.0.0/16',
  host: 'Host exacto, p. ej. app.b89.io (admite *)',
  path: 'Parte de la ruta, p. ej. /login',
  country: 'País ISO, p. ej. PE',
  asn: 'ASN, p. ej. 6147',
  ua: 'User-Agent exacto',
  q: 'Texto en ruta, UA, DNS, firewall o auditoría',
};

function FilterBar({
  state,
  zones,
  onChange,
}: {
  state: TrafficViewState;
  zones: ReadonlyArray<{ key: string; count: number }>;
  onChange: (next: TrafficViewState) => void;
}) {
  const [draft, setDraft] = useState<Partial<Record<FilterKey, string>>>(state.filters);
  useEffect(() => setDraft(state.filters), [state.filters]);
  const set = (key: FilterKey) => (value: string) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const submit = (event?: React.FormEvent) => {
    event?.preventDefault();
    onChange(withFilters(state, draft));
  };
  const zoneOptions = Array.from(
    new Set([
      ...(state.filters.zone ? [state.filters.zone] : []),
      ...zones.map((zone) => zone.key),
    ]),
  );
  const text = (key: keyof typeof FIELD_PLACEHOLDER, grow: 1 | 2 | 3) => (
    <EuiFlexItem grow={grow} key={key}>
      <EuiFieldText
        compressed
        fullWidth
        placeholder={FIELD_PLACEHOLDER[key]}
        aria-label={FILTER_LABEL[key]}
        value={draft[key] ?? ''}
        onChange={(event) => set(key)(event.target.value)}
      />
    </EuiFlexItem>
  );
  const chips = filterChips(state);
  return (
    <form onSubmit={submit} className="b89Traffic__filters">
      <EuiFlexGroup gutterSize="s" responsive wrap className="b89Filters">
        {text('q', 3)}
        {text('ip', 2)}
        {text('host', 2)}
        {text('path', 2)}
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="s" responsive wrap className="b89Filters">
        <EuiFlexItem grow={2}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Zona"
            value={draft.zone ?? ''}
            onChange={(event) => set('zone')(event.target.value)}
            options={[
              { value: '', text: 'Todas las zonas' },
              ...zoneOptions.map((zone) => ({ value: zone, text: zone })),
            ]}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Método"
            value={draft.method ?? ''}
            onChange={(event) => set('method')(event.target.value)}
            options={[
              { value: '', text: 'Todos los métodos' },
              ...Array.from(new Set([...(draft.method ? [draft.method] : []), ...METHODS])).map(
                (method) => ({ value: method, text: method }),
              ),
            ]}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Estado HTTP"
            value={draft.status ?? ''}
            onChange={(event) => set('status')(event.target.value)}
            options={[
              { value: '', text: 'Todos los estados' },
              ...Array.from(
                new Set([...STATUS_CLASSES, ...(draft.status ? [draft.status] : [])]),
              ).map((status) => ({ value: status, text: status })),
            ]}
          />
        </EuiFlexItem>
        {text('country', 1)}
        {text('asn', 1)}
        <EuiFlexItem grow={false}>
          <EuiButton size="s" type="submit" fill iconType="search">
            Aplicar filtros
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      {chips.length > 0 && (
        <div className="b89Traffic__chips" aria-label="Filtros activos">
          {chips.map((chip) => (
            <EuiBadge
              key={chip.key}
              color="hollow"
              iconType="cross"
              iconSide="right"
              iconOnClick={() => onChange(withFilters(state, { ...state.filters, [chip.key]: '' }))}
              iconOnClickAriaLabel={`Quitar filtro ${chip.label}`}
            >
              {chip.label}: <span data-b89-no-translate="">{truncate(chip.value, 48)}</span>
            </EuiBadge>
          ))}
          <EuiButtonEmpty
            size="xs"
            onClick={() =>
              onChange(withFilters(state, Object.fromEntries(FILTER_KEYS.map((k) => [k, '']))))
            }
          >
            Limpiar filtros
          </EuiButtonEmpty>
        </div>
      )}
    </form>
  );
}

/* ----------------------------------------------------------------- Cifras */

function StatTiles({
  aggs,
  dataset,
}: {
  aggs: TrafficAggregations;
  dataset: TrafficDataset | 'all';
}) {
  return (
    <div className="b89Traffic__tiles">
      {statTiles(aggs, dataset).map((tile) => (
        <div key={tile.id} className="b89Traffic__tile" data-tone={tile.tone}>
          <span className="b89Traffic__tileLabel">{tile.label}</span>
          <strong className="b89Traffic__tileValue b89Tabular">{tile.value}</strong>
          {tile.hint && <span className="b89Traffic__tileHint">{tile.hint}</span>}
        </div>
      ))}
    </div>
  );
}

function Histogram({ aggs }: { aggs: TrafficAggregations }) {
  const columns = histogramColumns(aggs);
  const interval = intervalLabel(aggs.interval);
  const labelEvery = Math.max(1, Math.ceil(columns.length / 8));
  return (
    <section className="b89Traffic__panel" aria-label="Eventos en el tiempo">
      <div className="b89Trend__toolbar">
        <EuiTitle size="xxs">
          <h2>
            Eventos en el tiempo{interval ? ` · cada ${interval}` : ''} · {LIMA_LABEL}
          </h2>
        </EuiTitle>
        <ul className="b89Legend">
          {TRAFFIC_DATASETS.map((dataset) => (
            <li key={dataset}>
              <span
                aria-hidden="true"
                className="b89Legend__swatch"
                style={{ backgroundColor: DATASET_COLOR[dataset] }}
              />
              <span>{TRAFFIC_DATASET_LABEL[dataset]}</span>
            </li>
          ))}
        </ul>
      </div>
      {columns.every((column) => column.total === 0) ? (
        <p className="b89Trend__empty">Sin eventos en este rango.</p>
      ) : (
        <div className="b89Trend__plot" role="list" aria-label="Eventos por intervalo y tipo">
          <span className="b89Trend__max b89Tabular" aria-hidden="true">
            {formatCount(Math.max(...columns.map((column) => column.total)))}
          </span>
          {columns.map((column, index) => (
            <div key={column.at} className="b89Trend__column" role="listitem">
              <EuiToolTip content={column.summary} position="top" display="block">
                <div
                  className="b89Trend__stack"
                  tabIndex={0}
                  aria-label={column.summary}
                  style={{ height: `${column.height}%` }}
                >
                  {[...column.segments].reverse().map((segment) => (
                    <span
                      key={segment.dataset}
                      style={{
                        flexGrow: segment.count,
                        backgroundColor: DATASET_COLOR[segment.dataset],
                      }}
                    />
                  ))}
                </div>
              </EuiToolTip>
              <span className="b89Trend__tick" aria-hidden="true">
                {index % labelEvery === 0 ? column.label.slice(5) : ''}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function TopLists({
  aggs,
  onPick,
}: {
  aggs: TrafficAggregations;
  onPick: (list: TopListId, value: string) => void;
}) {
  return (
    <div className="b89Traffic__tops">
      {TOP_LISTS.map((spec) => {
        const items = aggs[spec.id];
        const max = Math.max(1, ...items.map((item) => item.count));
        return (
          <section key={spec.id} className="b89Traffic__panel" aria-label={spec.title}>
            <EuiTitle size="xxs">
              <h3>{spec.title}</h3>
            </EuiTitle>
            <EuiSpacer size="s" />
            {items.length === 0 ? (
              <EuiText size="xs" color="subdued">
                <p>Sin datos.</p>
              </EuiText>
            ) : (
              <ol className="b89Traffic__topList">
                {items.map((item) => (
                  <li key={item.key}>
                    <button
                      type="button"
                      className="b89Traffic__topItem"
                      onClick={() => onPick(spec.id, item.key)}
                      title={`Filtrar por ${item.key}`}
                    >
                      <span
                        className="b89Traffic__topBar"
                        aria-hidden="true"
                        style={{ width: `${(item.count / max) * 100}%` }}
                      />
                      <span className="b89Traffic__topKey" data-b89-no-translate="">
                        {truncate(item.key, 42)}
                      </span>
                      <span className="b89Traffic__topCount b89Tabular">
                        {formatCount(item.count)}
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </section>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ Tabla */

export function EventBadges({ event }: { event: TrafficEvent }) {
  return (
    <>
      {event.sampled && (
        <EuiToolTip content="Registro muestreado por Cloudflare (GraphQL adaptativo): representa varias peticiones similares.">
          <EuiBadge color="warning">muestreado</EuiBadge>
        </EuiToolTip>
      )}
      {event.history && (
        <EuiToolTip content="Dato histórico recuperado después del evento.">
          <EuiBadge color="hollow">histórico</EuiBadge>
        </EuiToolTip>
      )}
    </>
  );
}

function DatasetBadge({ dataset }: { dataset: string }) {
  const known = (TRAFFIC_DATASETS as readonly string[]).includes(dataset);
  return (
    <EuiBadge color={known ? DATASET_COLOR[dataset as TrafficDataset] : 'hollow'}>
      {known ? TRAFFIC_DATASET_LABEL[dataset as TrafficDataset] : dataset}
    </EuiBadge>
  );
}

function statusColor(status: number | null): string | undefined {
  if (status === null) return undefined;
  if (status >= 500) return 'danger';
  if (status >= 400) return 'warning';
  return undefined;
}

function ResultsTable({
  data,
  events,
  loading,
  loadingMore,
  onLoadMore,
  onSelect,
}: {
  data: TrafficResponse;
  events: readonly TrafficEvent[];
  loading: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  onSelect: (event: TrafficEvent) => void;
}) {
  const columns: Array<EuiBasicTableColumn<TrafficEvent>> = [
    {
      field: 'at',
      name: 'Hora (Lima)',
      width: '150px',
      render: (at: string, event: TrafficEvent) => (
        <span className="b89Traffic__time">
          <time dateTime={at} className="b89Tabular" title={`UTC ${at}`}>
            {limaTime(at)}
          </time>
          <EventBadges event={event} />
        </span>
      ),
    },
    {
      field: 'dataset',
      name: 'Tipo',
      width: '90px',
      render: (dataset: string) => <DatasetBadge dataset={dataset} />,
    },
    {
      field: 'zone',
      name: 'Zona',
      render: (zone: string | null) => <Mono>{zone ?? '—'}</Mono>,
    },
    {
      field: 'clientIp',
      name: 'IP · país · ASN',
      render: (ip: string | null, event: TrafficEvent) => (
        <span className="b89Traffic__ip">
          <Mono>{ip ?? '—'}</Mono>
          <span className="b89Muted">
            {[
              event.country,
              event.asn !== null ? `AS${event.asn}` : null,
              truncate(event.asnName, 24),
            ]
              .filter(Boolean)
              .join(' · ')}
          </span>
        </span>
      ),
    },
    {
      field: 'method',
      name: 'Método',
      width: '80px',
      render: (method: string | null) => (method ? <Mono>{method}</Mono> : '—'),
    },
    {
      field: 'path',
      name: 'Host y ruta / detalle',
      render: (_path: string | null, event: TrafficEvent) => {
        const target = targetOf(event);
        return (
          <span title={target} className="b89Traffic__target">
            <Mono>{truncate(target, 90) || '—'}</Mono>
          </span>
        );
      },
    },
    {
      field: 'status',
      name: 'Estado',
      width: '70px',
      render: (status: number | null) =>
        status === null ? (
          '—'
        ) : (
          <EuiBadge color={statusColor(status) ?? 'default'}>{status}</EuiBadge>
        ),
    },
    {
      field: 'action',
      name: 'Acción de seguridad',
      render: (action: string | null) => (action ? <Mono>{action}</Mono> : '—'),
    },
    {
      field: 'userAgent',
      name: 'User-Agent',
      render: (ua: string | null) => (
        <span title={ua ?? ''} className="b89Muted">
          {truncate(ua, 48) || '—'}
        </span>
      ),
    },
  ];
  return (
    <section aria-label="Eventos">
      <EuiFlexGroup
        alignItems="center"
        justifyContent="spaceBetween"
        gutterSize="s"
        responsive={false}
      >
        <EuiFlexItem grow={false}>
          <EuiTitle size="xs">
            <h2>Eventos</h2>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color="subdued">
            <p>
              {formatCount(events.length)} de {totalLabel(data.total)} · más recientes primero
            </p>
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <DataZone>
        <EuiBasicTable<TrafficEvent>
          items={events as TrafficEvent[]}
          itemId={(event: TrafficEvent) => `${event.index}/${event.id}`}
          columns={columns}
          loading={loading}
          responsive
          compressed
          tableLayout="auto"
          rowProps={(event: TrafficEvent) => ({
            onClick: () => onSelect(event),
            className: 'b89Traffic__row',
            title: 'Ver todos los campos',
          })}
          noItemsMessage={
            loading
              ? 'Cargando tráfico…'
              : 'Sin eventos de Cloudflare en este rango y con estos filtros. Pruebe un rango mayor o quite filtros.'
          }
        />
      </DataZone>
      {data.nextCursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButtonEmpty size="s" onClick={onLoadMore} isLoading={loadingMore}>
            Cargar más
          </EuiButtonEmpty>
        </>
      )}
    </section>
  );
}

/* ----------------------------------------------------------------- Detalle */

function EventFlyout({
  event,
  state,
  onClose,
  onNavigate,
}: {
  event: TrafficEvent;
  state: TrafficViewState;
  onClose: () => void;
  onNavigate: (next: TrafficViewState) => void;
}) {
  const mobile = useIsMobile();
  const ipState = ipActivityState(state, event);
  const sessionState = hostSessionState(event);
  const rows = flattenSource(event.raw);
  return (
    <EuiFlyout
      onClose={onClose}
      size={mobile ? 'l' : 'm'}
      ownFocus={mobile}
      className="b89Flyout"
      aria-labelledby="b89TrafficEventTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <span className="b89Traffic__time">
          <DatasetBadge dataset={event.dataset} />
          <EventBadges event={event} />
        </span>
        <EuiSpacer size="xs" />
        <EuiTitle size="s">
          <h2 id="b89TrafficEventTitle" data-b89-no-translate="">
            {truncate(targetOf(event), 120) || 'Evento de Cloudflare'}
          </h2>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          <p>
            <strong>{limaTime(event.at)}</strong> ({LIMA_LABEL}) · UTC <Mono>{event.at}</Mono>
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiFlexGroup gutterSize="s" wrap responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButton
              size="s"
              fill
              iconType="search"
              isDisabled={!ipState}
              onClick={() => ipState && onNavigate(ipState)}
            >
              Ver toda la actividad de esta IP
            </EuiButton>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content="Misma IP, mismo host y mismo User-Agent, una hora antes y después.">
              <EuiButton
                size="s"
                iconType="clock"
                isDisabled={!sessionState}
                onClick={() => sessionState && onNavigate(sessionState)}
              >
                Ver esta sesión de host
              </EuiButton>
            </EuiToolTip>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {rows.length === 0 ? (
          <EmptyLine>El documento no tiene campos.</EmptyLine>
        ) : (
          <DataZone>
            <table className="b89Traffic__fields">
              <caption className="b89Traffic__caption">
                Todos los campos del documento ({rows.length}) · índice <Mono>{event.index}</Mono>
              </caption>
              <tbody>
                {rows.map(([field, value]) => (
                  <tr key={field}>
                    <th scope="row">
                      <Mono>{field}</Mono>
                    </th>
                    <td>
                      <Mono>{value}</Mono>
                      {field === '@timestamp' && (
                        <span className="b89Muted"> · Lima {limaTime(value)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DataZone>
        )}
      </EuiFlyoutBody>
    </EuiFlyout>
  );
}
