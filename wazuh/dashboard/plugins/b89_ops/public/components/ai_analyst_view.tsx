/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiConfirmModal,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiLoadingContent,
  EuiSelect,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  AI_MODE_LABEL,
  AI_MODE_SUMMARY,
  AI_RUN_STATUS_LABEL,
  AI_RUN_STATUSES,
  AiBudget,
  AiRunDetail,
  AiRunStatus,
  AiRunSummary,
  CAPABILITIES,
  isActive,
  isValidAiRunId,
  isValidAlertId,
  mergeRuns,
  parseMode,
} from '../../common';
import {
  cancelAiRun,
  getAiBudget,
  getAiRun,
  getAiRunReport,
  isAnalystUnavailable,
  listAiRuns,
  retryAiRun,
  startAiRun,
} from '../api/ai_investigations';
import { B89ApiError } from '../api/client';
import { askBunny } from '../bunny_bridge';
import { AiBudgetPanel, AiModeLine } from './ai_analyst_budget';
import { AiCaseFile, AiCaseFileActions, primaryAlertId, runQuestion } from './ai_analyst_case_file';
import { downloadMarkdown } from './ai_analyst_download';
import { AiReportsTab } from './ai_analyst_reports';
import { AiRunsTable, RunStatusMark } from './ai_analyst_runs';
import { AiSettingsTab } from './ai_analyst_settings';
import { B89Page, useConsole } from './console_context';
import { ErrorCallout, Mono, useAsync, useIsMobile } from './primitives';

/** Refresco en vivo: solo con investigaciones activas a la vista y la pestaña visible. */
const POLL_MS = 5000;
/** Tope de investigaciones activas fuera de la primera página que se refrescan una a una. */
const STALE_REFRESH_MAX = 10;

const PAGE_DESCRIPTION =
  'Investigaciones automáticas de alertas con su evidencia, citas, acciones, uso y costo estimado.';

type AnalystTab = 'operation' | 'reports' | 'settings';

const TABS: ReadonlyArray<{ id: AnalystTab; label: string }> = [
  { id: 'operation', label: 'Operación' },
  { id: 'reports', label: 'Informes' },
  { id: 'settings', label: 'Configuración' },
];

/** Qué hará el analista con una investigación nueva, según el modo vigente. */
function modeConsequence(mode: string | null): string {
  const known = parseMode(mode);
  if (!known) {
    return 'No se pudo confirmar el modo de operación vigente: revisa la pestaña «Configuración» antes de continuar.';
  }
  return `${AI_MODE_LABEL[known]}: el analista ${AI_MODE_SUMMARY[known]}.`;
}

function useTabVisible(): boolean {
  const [visible, setVisible] = useState(
    () => typeof document === 'undefined' || document.visibilityState !== 'hidden',
  );
  useEffect(() => {
    const listener = () => setVisible(document.visibilityState !== 'hidden');
    document.addEventListener('visibilitychange', listener);
    return () => document.removeEventListener('visibilitychange', listener);
  }, []);
  return visible;
}

function UnavailableCallout({ onRetry }: { onRetry: () => void }) {
  return (
    <EuiCallOut
      color="warning"
      iconType="offline"
      title="El analista no está habilitado o publicado en este entorno"
    >
      <p>
        El servicio respondió que el recurso no existe. No hay investigaciones que mostrar hasta
        que el Analista IA se publique y se habilite aquí.
      </p>
      <EuiButtonEmpty size="xs" flush="left" onClick={onRetry}>
        Volver a comprobar
      </EuiButtonEmpty>
    </EuiCallOut>
  );
}

export function AiAnalystView({
  selectedId,
  onSelect,
  basePath,
  initialAlertId,
}: {
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  basePath: string;
  /** `?alertId=`: precarga el control «Investigar alerta» (desde el detalle de una alerta). */
  initialAlertId?: string | null;
}) {
  const { can } = useConsole();
  if (!can(CAPABILITIES.investigationsRead)) {
    return (
      <B89Page title="Analista IA" description={PAGE_DESCRIPTION}>
        <EuiCallOut color="warning" iconType="lock" title="Tu cuenta no tiene acceso al Analista IA">
          <p>
            Falta la capacidad <Mono>{CAPABILITIES.investigationsRead}</Mono>. Pídela a quien
            administra los roles del SOC.
          </p>
        </EuiCallOut>
      </B89Page>
    );
  }
  return (
    <AiAnalystConsole
      selectedId={selectedId}
      onSelect={onSelect}
      basePath={basePath}
      initialAlertId={initialAlertId ?? null}
    />
  );
}

function AiAnalystConsole({
  selectedId,
  onSelect,
  basePath,
  initialAlertId,
}: {
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  basePath: string;
  initialAlertId: string | null;
}) {
  const { api, can } = useConsole();
  const canRun = can(CAPABILITIES.investigationsRun);
  const visible = useTabVisible();
  const [filter, setFilter] = useState<AiRunStatus | ''>('');
  const [items, setItems] = useState<readonly AiRunSummary[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);
  const [liveBudget, setLiveBudget] = useState<AiBudget | null>(null);
  const [tab, setTab] = useState<AnalystTab>('operation');

  const page = useAsync(() => listAiRuns(api, { status: filter || null }), [api, filter]);
  const budget = useAsync(() => getAiBudget(api), [api]);

  // Lo que el refresco silencioso necesita leer sin volver a crear el intervalo.
  const filterRef = useRef(filter);
  filterRef.current = filter;
  const itemsRef = useRef(items);
  itemsRef.current = items;
  const refreshing = useRef(false);

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
      setMoreError(null);
    }
  }, [page.data]);

  useEffect(() => {
    if (budget.data) setLiveBudget(budget.data);
  }, [budget.data]);

  const refresh = useCallback(async () => {
    if (refreshing.current) return;
    refreshing.current = true;
    const requested = filterRef.current;
    try {
      const first = await listAiRuns(api, { status: requested || null });
      if (filterRef.current !== requested) return;
      // Una investigación activa que ya no está en la primera página (terminó y salió del filtro,
      // o quedó más abajo) se consulta por id: si no, seguiría «en curso» para siempre.
      const listed = new Set(first.items.map((run) => run.id));
      const stale = itemsRef.current
        .filter((run) => isActive(run.status) && !listed.has(run.id) && isValidAiRunId(run.id))
        .slice(0, STALE_REFRESH_MAX);
      const details = await Promise.all(
        stale.map((run) => getAiRun(api, run.id).catch(() => null)),
      );
      if (filterRef.current !== requested) return;
      const updates: AiRunSummary[] = [...first.items];
      for (const detail of details) if (detail) updates.push(detail);
      setItems((current) => mergeRuns(current, updates));
      const nextBudget = await getAiBudget(api).catch(() => null);
      if (nextBudget) setLiveBudget(nextBudget);
    } catch {
      // Se conserva lo visible; el siguiente ciclo vuelve a intentar.
    } finally {
      refreshing.current = false;
    }
  }, [api]);

  // El modo y el techo cambian al guardar la configuración: la franja debe reflejarlo.
  const refreshBudget = useCallback(async () => {
    const next = await getAiBudget(api).catch(() => null);
    if (next) setLiveBudget(next);
  }, [api]);

  const hasActive = items.some((run) => isActive(run.status));
  useEffect(() => {
    if (!hasActive || !visible) return undefined;
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [hasActive, visible, refresh]);

  const loadMore = async () => {
    if (!cursor || loadingMore) return;
    const requested = filter;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const next = await listAiRuns(api, { status: requested || null, cursor });
      if (filterRef.current !== requested) return;
      setItems((current) => {
        const known = new Set(current.map((run) => run.id));
        return [...current, ...next.items.filter((run) => !known.has(run.id))];
      });
      setCursor(next.nextCursor);
    } catch (failure) {
      setMoreError(failure);
    } finally {
      setLoadingMore(false);
    }
  };

  const upsert = useCallback((run: AiRunSummary) => {
    setItems((current) => mergeRuns(current, [run]));
  }, []);

  const unavailable = page.error != null && isAnalystUnavailable(page.error);
  const shownBudget = liveBudget;
  const mode = shownBudget ? shownBudget.mode : null;

  return (
    <B89Page title="Analista IA" description={PAGE_DESCRIPTION}>
      {!unavailable && (
        <>
          <EuiTabs size="s" className="b89Tabs">
            {TABS.map((item) => (
              <EuiTab key={item.id} isSelected={tab === item.id} onClick={() => setTab(item.id)}>
                {item.label}
              </EuiTab>
            ))}
          </EuiTabs>
          <EuiSpacer size="m" />
        </>
      )}
      {unavailable ? (
        <UnavailableCallout onRetry={page.reload} />
      ) : tab === 'reports' ? (
        <AiReportsTab />
      ) : tab === 'settings' ? (
        <AiSettingsTab onSaved={() => void refreshBudget()} />
      ) : (
        <>
          {shownBudget ? (
            <AiBudgetPanel budget={shownBudget} />
          ) : budget.loading ? (
            <EuiLoadingContent lines={2} />
          ) : (
            <section className="b89Ai__budget" aria-label="Presupuesto y uso del día">
              <AiModeLine mode={null} />
              {isAnalystUnavailable(budget.error) ? (
                <p className="b89Ai__note">El presupuesto del día no está publicado en este entorno.</p>
              ) : (
                <ErrorCallout error={budget.error} onRetry={budget.reload} />
              )}
            </section>
          )}
          <EuiSpacer size="m" />
          <EuiFlexGroup
            className="b89Filters"
            gutterSize="m"
            alignItems="flexEnd"
            justifyContent="spaceBetween"
            responsive
            wrap
          >
            <EuiFlexItem grow={false}>
              <EuiFormRow label="Estado" display="rowCompressed">
                <EuiSelect
                  compressed
                  aria-label="Filtrar investigaciones por estado"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value as AiRunStatus | '')}
                  options={[
                    { value: '', text: 'Todos los estados' },
                    ...AI_RUN_STATUSES.map((status) => ({
                      value: status,
                      text: AI_RUN_STATUS_LABEL[status],
                    })),
                  ]}
                />
              </EuiFormRow>
            </EuiFlexItem>
            {canRun && (
              <EuiFlexItem grow={false}>
                <StartControl
                  initialAlertId={initialAlertId}
                  mode={mode}
                  onStarted={(run) => {
                    upsert(run);
                    onSelect(run.id);
                  }}
                />
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
          <EuiSpacer size="m" />
          {page.error != null ? (
            <ErrorCallout error={page.error} onRetry={page.reload} />
          ) : (
            <>
              <AiRunsTable
                items={items}
                loading={page.loading}
                selectedId={selectedId}
                onSelect={onSelect}
                emptyMessage={
                  page.loading
                    ? 'Cargando investigaciones…'
                    : filter
                      ? 'No hay investigaciones en este estado.'
                      : 'Aún no hay investigaciones. El analista las crea después de las reglas y la correlación.'
                }
              />
              {hasActive && (
                <EuiText size="xs" color="subdued">
                  <p role="status">
                    {visible
                      ? 'Hay investigaciones en curso: la lista se actualiza cada 5 s.'
                      : 'Actualización en pausa mientras la pestaña está oculta.'}
                  </p>
                </EuiText>
              )}
              {moreError != null && (
                <>
                  <EuiSpacer size="s" />
                  <ErrorCallout error={moreError} onRetry={loadMore} />
                </>
              )}
              {cursor && (
                <>
                  <EuiSpacer size="s" />
                  <EuiButtonEmpty size="s" onClick={loadMore} isLoading={loadingMore}>
                    Cargar más
                  </EuiButtonEmpty>
                </>
              )}
            </>
          )}
        </>
      )}
      {selectedId && !unavailable && tab === 'operation' && (
        <RunFlyout
          key={selectedId}
          runId={selectedId}
          basePath={basePath}
          mode={mode}
          canRun={canRun}
          visible={visible}
          onClose={() => onSelect(null)}
          onChanged={upsert}
        />
      )}
    </B89Page>
  );
}

// ------------------------------------------------------------------ Iniciar

function StartControl({
  initialAlertId,
  mode,
  onStarted,
}: {
  initialAlertId: string | null;
  mode: string | null;
  onStarted: (run: AiRunDetail) => void;
}) {
  const { api } = useConsole();
  const [alertId, setAlertId] = useState(initialAlertId ?? '');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [outcome, setOutcome] = useState<{ id: string; created: boolean | null } | null>(null);
  const trimmed = alertId.trim();
  const valid = isValidAlertId(trimmed);
  const invalid = trimmed.length > 0 && !valid;

  const start = async () => {
    setBusy(true);
    setError(null);
    setOutcome(null);
    try {
      const result = await startAiRun(api, trimmed);
      setOutcome({ id: result.run.id, created: result.created });
      setAlertId('');
      onStarted(result.run);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  };

  return (
    <div className="b89Ai__start">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (valid && !busy) setConfirming(true);
        }}
      >
        <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false} wrap>
          <EuiFlexItem grow>
            <EuiFormRow
              label="Investigar alerta"
              display="rowCompressed"
              isInvalid={invalid}
              error={invalid ? 'Usa el identificador de la alerta, sin espacios.' : undefined}
            >
              <EuiFieldText
                compressed
                value={alertId}
                maxLength={128}
                isInvalid={invalid}
                placeholder="ID de la alerta"
                aria-label="Identificador de la alerta a investigar"
                data-b89-no-translate=""
                onChange={(event) => setAlertId(event.target.value)}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton size="s" type="submit" isDisabled={!valid} isLoading={busy}>
              Investigar
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </form>
      {error != null && (
        <>
          <EuiSpacer size="s" />
          <ErrorCallout error={error} />
        </>
      )}
      {outcome && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            size="s"
            color={outcome.created === false ? 'primary' : 'success'}
            iconType={outcome.created === false ? 'iInCircle' : 'check'}
            title={
              outcome.created === false
                ? 'Ya existía una investigación idéntica: se reutilizó'
                : outcome.created === true
                  ? 'Investigación creada'
                  : 'Investigación registrada'
            }
          >
            <p role="status">
              {outcome.created === false
                ? 'No se inició una corrida nueva ni se consumió presupuesto adicional. '
                : ''}
              Expediente <Mono>{outcome.id}</Mono>.
            </p>
          </EuiCallOut>
        </>
      )}
      {confirming && (
        <EuiConfirmModal
          title="Investigar esta alerta"
          aria-label="Confirmar la investigación de la alerta"
          onCancel={() => setConfirming(false)}
          onConfirm={start}
          cancelButtonText="Cancelar"
          confirmButtonText="Investigar"
          confirmButtonDisabled={busy}
          defaultFocusedButton="confirm"
        >
          <p>
            Se investigará la alerta <Mono>{trimmed}</Mono>. {modeConsequence(mode)}
          </p>
          <p>
            Puede consumir presupuesto de inferencia del día si las reglas deterministas no la
            resuelven. Si ya existe una investigación idéntica, se reutiliza sin costo adicional.
          </p>
        </EuiConfirmModal>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ Expediente

function RunFlyout({
  runId,
  basePath,
  mode,
  canRun,
  visible,
  onClose,
  onChanged,
}: {
  runId: string;
  basePath: string;
  mode: string | null;
  canRun: boolean;
  visible: boolean;
  onClose: () => void;
  onChanged: (run: AiRunDetail) => void;
}) {
  const { api, notifications } = useConsole();
  const mobile = useIsMobile();
  const validId = isValidAiRunId(runId);
  const loaded = useAsync(
    () => (validId ? getAiRun(api, runId) : Promise.resolve(null)),
    [api, runId, validId],
  );
  const [run, setRun] = useState<AiRunDetail | null>(null);
  const [confirm, setConfirm] = useState<'cancel' | 'retry' | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [now, setNow] = useState(() => Date.now());
  const [downloading, setDownloading] = useState(false);
  const changed = useRef(onChanged);
  changed.current = onChanged;

  useEffect(() => {
    if (loaded.data) {
      setRun(loaded.data);
      changed.current(loaded.data);
    }
  }, [loaded.data]);

  const active = run !== null && isActive(run.status);

  // Reloj del tiempo transcurrido: solo corre mientras la investigación sigue activa.
  useEffect(() => {
    if (!active || !visible) return undefined;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active, visible]);

  // Progreso real: se vuelve a leer el expediente; no hay SSE ni pasos simulados.
  useEffect(() => {
    if (!active || !visible || confirm !== null || busy) return undefined;
    let cancelled = false;
    const timer = window.setInterval(() => {
      getAiRun(api, runId).then(
        (next) => {
          if (cancelled) return;
          setRun(next);
          changed.current(next);
        },
        () => undefined,
      );
    }, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [active, visible, confirm, busy, api, runId]);

  const command = async (kind: 'cancel' | 'retry') => {
    if (!run || run.revision === null) return;
    setBusy(true);
    setError(null);
    try {
      const result =
        kind === 'cancel'
          ? await cancelAiRun(api, run.id, run.revision)
          : await retryAiRun(api, run.id, run.revision);
      setRun(result.run);
      changed.current(result.run);
    } catch (failure) {
      setError(failure);
      // Otra persona o el propio trabajador cambió la corrida: se recarga antes de reintentar.
      if (failure instanceof B89ApiError && failure.code === 'STATE_CONFLICT') loaded.reload();
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  };

  const downloadReport = async () => {
    if (!run || downloading) return;
    setDownloading(true);
    setError(null);
    try {
      const report = await getAiRunReport(api, run.id);
      downloadMarkdown(report.filename, report.markdown);
    } catch (failure) {
      setError(failure);
    } finally {
      setDownloading(false);
    }
  };

  const ask = () => {
    if (!run) return;
    const alertId = primaryAlertId(run);
    const opened = askBunny({
      prompt: runQuestion(run),
      ...(alertId ? { context: { alertId } } : {}),
    });
    if (!opened) {
      notifications.toasts.addWarning({
        title: 'Bunny no está disponible en esta página',
      });
    }
  };

  return (
    <EuiFlyout
      onClose={onClose}
      size={mobile ? 'l' : 'm'}
      ownFocus={mobile}
      className="b89Flyout b89Ai__flyout"
      aria-labelledby="b89AiRunTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <p className="b89Eyebrow">Expediente · Analista IA</p>
        <EuiTitle size="s">
          <h2 id="b89AiRunTitle" data-b89-no-translate="">
            {run ? run.subject.title || run.id : 'Investigación'}
          </h2>
        </EuiTitle>
        {run && (
          <>
            <EuiSpacer size="xs" />
            <RunStatusMark status={run.status} />
          </>
        )}
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {!validId && (
          <EuiCallOut
            size="s"
            color="warning"
            iconType="alert"
            title="El identificador de la investigación no es válido"
          >
            <p>Abre el expediente desde la lista de investigaciones.</p>
          </EuiCallOut>
        )}
        {validId && loaded.loading && !run && <EuiLoadingContent lines={6} />}
        {validId && loaded.error != null && !run && (
          <ErrorCallout error={loaded.error} onRetry={loaded.reload} />
        )}
        {error != null && (
          <>
            <ErrorCallout error={error} />
            <EuiSpacer size="m" />
          </>
        )}
        {run && <AiCaseFile run={run} basePath={basePath} now={now} mode={mode} />}
      </EuiFlyoutBody>
      {run && (
        <EuiFlyoutFooter>
          <AiCaseFileActions
            run={run}
            basePath={basePath}
            canRun={canRun}
            busy={busy}
            onCancel={() => setConfirm('cancel')}
            onRetry={() => setConfirm('retry')}
            onAskBunny={ask}
            onDownloadReport={() => void downloadReport()}
            downloading={downloading}
          />
        </EuiFlyoutFooter>
      )}
      {confirm === 'cancel' && (
        <EuiConfirmModal
          title="Detener la investigación"
          aria-label="Confirmar la detención de la investigación"
          onCancel={() => setConfirm(null)}
          onConfirm={() => command('cancel')}
          cancelButtonText="Seguir investigando"
          confirmButtonText="Detener"
          buttonColor="danger"
          confirmButtonDisabled={busy}
          defaultFocusedButton="cancel"
        >
          <p>
            La investigación se detiene al terminar el paso en curso y no produce recomendación.
            Las acciones que el analista ya ejecutó no se deshacen.
          </p>
          <p>
            Una llamada que ya se envió al modelo no se puede anular y puede cobrarse igualmente.
          </p>
        </EuiConfirmModal>
      )}
      {confirm === 'retry' && (
        <EuiConfirmModal
          title="Reintentar la investigación"
          aria-label="Confirmar el reintento de la investigación"
          onCancel={() => setConfirm(null)}
          onConfirm={() => command('retry')}
          cancelButtonText="Cancelar"
          confirmButtonText="Reintentar"
          confirmButtonDisabled={busy}
          defaultFocusedButton="confirm"
        >
          <p>
            El reintento es idempotente: retoma la misma investigación y no repite las fases que ya
            quedaron confirmadas.
          </p>
          <p>
            Las fases pendientes pueden consumir presupuesto de inferencia del día.{' '}
            {modeConsequence(mode)}
          </p>
        </EuiConfirmModal>
      )}
    </EuiFlyout>
  );
}
