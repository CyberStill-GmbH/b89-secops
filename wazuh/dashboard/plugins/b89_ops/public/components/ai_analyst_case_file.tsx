/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiToolTip } from '@elastic/eui';
import {
  AI_ACTION_KIND_LABEL,
  AI_ACTION_STATE_LABEL,
  AI_ACTION_STATE_TONE,
  AI_CITATION_KIND_LABEL,
  AI_EVENT_KIND_LABEL,
  AI_INFERENCE_LABEL,
  AI_IP_REPUTATION_BAND_LABEL,
  AI_INVOCATION_STATE_LABEL,
  AI_INVOCATION_STATE_TONE,
  AI_RUN_STATUS_LABEL,
  AI_TRIGGER_LABEL,
  AiCitation,
  AiEvidence,
  AiIpReputation,
  AiIpReputationBand,
  AiResult,
  AiRunAction,
  AiRunDetail,
  AiStatement,
  buildProgressTimeline,
  canCancel,
  canRetry,
  changedAlert,
  confidenceLabel,
  elapsedMs,
  evidenceSourceStateLabel,
  executedActions,
  formatCount,
  formatDuration,
  formatMicroUsd,
  HealthTone,
  inferenceLabel,
  ipReputationBand,
  isActive,
  isTerminal,
  NO_DATA,
  parseMode,
  sanitizeErrorCode,
  SOURCE_STATES,
  SOURCE_TONE,
  SourceState,
  stageLabel,
  verdictLabel,
} from '../../common';
import { citationPath } from '../bunny/chat_client';
import { describeDetail } from './ai_analyst_model';
import { ConfidenceMeter, ReasonTag, VerdictBadge } from './ai_analyst_parts';
import { runCostText } from './ai_analyst_runs';
import { DataZone, HealthMark, Mono, PriorityMark, Timestamp } from './primitives';

/** Alerta principal de la corrida (para «Abrir alerta»); `null` si no hay una sola. */
export function primaryAlertId(run: AiRunDetail): string | null {
  if (run.subject.kind === 'alert' && run.subject.id) return run.subject.id;
  return run.alertIds.length === 1 ? run.alertIds[0] : null;
}

export function alertHref(basePath: string, alertId: string): string {
  return `${basePath}/app/b89-alerts?id=${encodeURIComponent(alertId)}`;
}

/** Borrador para Bunny: pide contrastar la recomendación, no ejecutarla. */
export function runQuestion(run: AiRunDetail): string {
  const lines = [
    `Revisa la investigación ${run.id} del Analista IA sobre «${run.subject.title || run.subject.id}».`,
  ];
  if (run.result) {
    lines.push(
      `Recomendación del analista: ${verdictLabel(run.result.verdict)} (${confidenceLabel(
        run.result.confidence,
      ).toLowerCase()}).`,
    );
  }
  lines.push(
    'Contrasta sus hechos e inferencias con la evidencia disponible, dime qué falta verificar y qué revisarías antes de decidir. No cambies la alerta.',
  );
  return lines.join('\n');
}

// ------------------------------------------------------------------ Avisos por estado

/** Un aviso distinto por cada estado que exige leer el expediente con cuidado. */
export function AiRunStatusCallout({ run }: { run: AiRunDetail }) {
  if (isActive(run.status)) {
    if (!run.cancelRequested) return null;
    return (
      <EuiCallOut size="s" color="warning" iconType="clock" title="Detención solicitada">
        <p>
          La investigación se detendrá al terminar el paso en curso. Una llamada que ya se envió al
          modelo puede cobrarse igualmente.
        </p>
      </EuiCallOut>
    );
  }
  switch (run.status) {
    // «Requiere revisión» ya lo dicen «Tu revisión» y la línea de verificación de la conclusión:
    // un tercer aviso solo repetiría lo mismo.
    case 'budget_exhausted':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Presupuesto diario agotado">
          <p>
            No se usó la IA porque ya se alcanzó el gasto máximo de IA de hoy. Puedes reintentar
            cuando haya presupuesto (mañana o si alguien sube el techo diario).
          </p>
        </EuiCallOut>
      );
    case 'usage_unreconciled':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Costo pendiente de confirmar">
          <p>
            No sabemos aún cuánto costó la llamada a la IA. No se reintenta para no cobrarla dos
            veces.
          </p>
        </EuiCallOut>
      );
    case 'partial':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Resultado parcial">
          <p>
            La investigación terminó sin cubrir toda la evidencia. Lo que aparece abajo está
            incompleto: revisa los vacíos antes de usarlo.
          </p>
        </EuiCallOut>
      );
    case 'failed': {
      const code = sanitizeErrorCode(run.lastErrorCode);
      return (
        <EuiCallOut size="s" color="danger" iconType="cross" title="La investigación falló">
          <p>
            No hay recomendación.{' '}
            {code ? (
              <>
                Causa: <ReasonTag code={code} />
              </>
            ) : (
              'El servicio no informó un código de error.'
            )}
          </p>
        </EuiCallOut>
      );
    }
    case 'cancelled':
      return (
        <EuiCallOut size="s" iconType="minusInCircle" title="Investigación detenida">
          <p>
            Se detuvo antes de terminar. Una llamada que ya se había enviado al modelo puede
            haberse cobrado igualmente.
          </p>
        </EuiCallOut>
      );
    case 'unknown':
      return (
        <EuiCallOut size="s" color="warning" iconType="questionInCircle" title="Estado no reconocido">
          <p>
            Esta versión de la consola no conoce el estado que informó el servicio. No se ofrecen
            acciones ni se asume que la investigación terminó.
          </p>
        </EuiCallOut>
      );
    default:
      return null;
  }
}

// ------------------------------------------------------------------ Piezas

function Section({
  id,
  title,
  count,
  hint,
  children,
}: {
  id: string;
  title: string;
  count?: number;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="b89AiSection" aria-labelledby={id}>
      <h3 id={id} className="b89AiSection__title" tabIndex={-1}>
        {title}
        {count !== undefined && <span className="b89AiSection__count b89Tabular">{count}</span>}
      </h3>
      {hint && <p className="b89AiSection__hint">{hint}</p>}
      {children}
    </section>
  );
}

function CitationChip({ citation, basePath }: { citation: AiCitation; basePath: string }) {
  const path = citation.kind === 'unknown' ? null : citationPath({ ...citation, kind: citation.kind });
  const body = (
    <>
      <span className="b89Chip__kind">{AI_CITATION_KIND_LABEL[citation.kind]}</span>
      <span data-b89-no-translate="" translate="no">
        {citation.label}
      </span>
    </>
  );
  return path ? (
    <a className="b89Chip b89Ai__cite" href={`${basePath}${path}`} title={citation.id}>
      {body}
    </a>
  ) : (
    <span className="b89Chip b89Chip--static" title={citation.id}>
      {body}
    </span>
  );
}

/** Una referencia puede venir como `id` o como `tipo:id`; si no resuelve, se muestra cruda. */
function resolveCitation(ref: string, citations: readonly AiCitation[]): AiCitation | null {
  for (const citation of citations) {
    if (citation.id === ref || `${citation.kind}:${citation.id}` === ref) return citation;
  }
  return null;
}

function Statements({
  items,
  citations,
  basePath,
  variant,
}: {
  items: readonly AiStatement[];
  citations: readonly AiCitation[];
  basePath: string;
  variant: 'fact' | 'inference';
}) {
  const List = variant === 'fact' ? 'ol' : 'ul';
  return (
    <List className="b89AiStatements" data-variant={variant}>
      {items.map((item, index) => (
        <li key={index}>
          <DataZone className="b89Prose">{item.text}</DataZone>
          {item.citations.length === 0 ? (
            <span className="b89AiStatements__nocite">Sin cita a la evidencia</span>
          ) : (
            <span className="b89Chips">
              {item.citations.map((ref) => {
                const citation = resolveCitation(ref, citations);
                return citation ? (
                  <CitationChip key={ref} citation={citation} basePath={basePath} />
                ) : (
                  <span key={ref} className="b89Chip b89Chip--static" title="Cita sin resolver">
                    <Mono>{ref}</Mono>
                  </span>
                );
              })}
            </span>
          )}
        </li>
      ))}
    </List>
  );
}

function TextList({
  items,
  variant,
  ordered = false,
}: {
  items: readonly string[];
  variant: 'gap' | 'step';
  ordered?: boolean;
}) {
  const List = ordered ? 'ol' : 'ul';
  return (
    <List className="b89AiStatements" data-variant={variant}>
      {items.map((item, index) => (
        <li key={index}>
          <DataZone className="b89Prose">{item}</DataZone>
        </li>
      ))}
    </List>
  );
}

// ------------------------------------------------------------------ Conclusión

/** Largo del resumen dentro de la conclusión; el resto queda en «Explicación del analista». */
export const CONCLUSION_SUMMARY_MAX = 320;
/** Pasos recomendados que se ven en la conclusión. */
export const CONCLUSION_STEPS_MAX = 3;

/** Recorta en un límite de palabra; `clipped` dice si quedó texto fuera. */
export function clipText(text: string, max: number): { text: string; clipped: boolean } {
  const clean = text.trim();
  if (clean.length <= max) return { text: clean, clipped: false };
  const cut = clean.slice(0, max);
  const space = cut.lastIndexOf(' ');
  return { text: `${(space > max * 0.6 ? cut.slice(0, space) : cut).replace(/[\s.,;:]+$/u, '')}…`, clipped: true };
}

const PRIORITY_RANK: Readonly<Record<string, number>> = { P1: 1, P2: 2, P3: 3, P4: 4 };

/** Prioridad sugerida frente a la de la alerta, en palabras. */
export function priorityAdvice(
  current: AiRunDetail['priority'],
  suggested: AiResult['recommendedPriority'],
): string | null {
  if (!suggested) return null;
  if (!current || !(current in PRIORITY_RANK)) return `Sugiere ${suggested}`;
  if (current === suggested) return `Mantener en ${suggested}`;
  return PRIORITY_RANK[suggested] < PRIORITY_RANK[current]
    ? `Sugiere subir a ${suggested}`
    : `Sugiere bajar a ${suggested}`;
}

/** Qué significa cada nivel de confianza (ayuda breve junto al medidor). */
export const CONFIDENCE_HELP: Readonly<Record<string, string>> = {
  high: 'Alta: hechos con cita y sin vacíos relevantes.',
  medium: 'Media: la evidencia apunta en esa dirección, pero hay algo sin confirmar.',
  low: 'Baja: poca evidencia o vacíos importantes; tómala como una pista.',
  unknown: 'El servicio no informó un nivel de confianza reconocible.',
};

function gapCountText(count: number): string {
  return count === 1 ? 'Falta verificar 1 punto' : `Falta verificar ${formatCount(count)} puntos`;
}

function jumpTo(id: string) {
  return (event: React.MouseEvent<HTMLAnchorElement>) => {
    const target = document.getElementById(id);
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ block: 'start' });
    if (target.hasAttribute('tabindex')) target.focus({ preventScroll: true });
  };
}

/**
 * Lo primero del expediente, al estilo de un copiloto de SOC: qué concluyó (veredicto, confianza,
 * resumen), qué recomienda (primeros pasos) y qué falta verificar. Sin resultado dice por qué.
 */
export function AiConclusion({ run }: { run: AiRunDetail }) {
  const result = run.result;
  const active = isActive(run.status);
  if (!result) {
    const stage = stageLabel(run.stage);
    return (
      <section className="b89AiConclusion" data-tone="neutral" aria-labelledby="b89AiConclusion">
        <h3 id="b89AiConclusion" className="b89AiConclusion__eyebrow" tabIndex={-1}>
          Conclusión del Analista IA
        </h3>
        {/* Región de estado breve: solo cambia cuando cambia la etapa (no cada segundo). */}
        <p className="b89AiConclusion__empty" role={active ? 'status' : undefined}>
          {active
            ? `Aún no hay conclusión: la investigación sigue en curso${
                stage ? ` (${stage.toLowerCase()})` : ''
              }.`
            : 'Esta investigación no produjo una conclusión.'}
        </p>
      </section>
    );
  }
  const alertChanged = changedAlert(run.actions);
  const summary = clipText(result.summary, CONCLUSION_SUMMARY_MAX);
  const steps = result.nextSteps.slice(0, CONCLUSION_STEPS_MAX);
  const moreSteps = result.nextSteps.length - steps.length;
  const advice = priorityAdvice(run.priority, result.recommendedPriority);
  const confidenceKey = result.confidence ?? 'unknown';
  return (
    <section
      className="b89AiConclusion"
      data-verdict={result.verdict ?? 'none'}
      aria-labelledby="b89AiConclusion"
    >
      <h3 id="b89AiConclusion" className="b89AiConclusion__eyebrow" tabIndex={-1}>
        Conclusión del Analista IA{run.status === 'partial' ? ' (resultado parcial)' : ''}
      </h3>
      {active && (
        <p className="b89AiSrOnly" role="status">
          {`La investigación sigue en curso${
            stageLabel(run.stage) ? `: ${stageLabel(run.stage)!.toLowerCase()}` : ''
          }.`}
        </p>
      )}
      <div className="b89AiConclusion__grid">
        <div className="b89AiConclusion__verdict">
          <VerdictBadge verdict={result.verdict} size="l" />
        </div>
        <dl className="b89AiConclusion__facts">
          <div>
            <dt>Confianza</dt>
            <dd>
              <EuiToolTip content={CONFIDENCE_HELP[confidenceKey] ?? CONFIDENCE_HELP.unknown}>
                <span tabIndex={0} className="b89AiConclusion__help">
                  <ConfidenceMeter confidence={result.confidence} short />
                </span>
              </EuiToolTip>
            </dd>
          </div>
          <div>
            <dt>Prioridad</dt>
            <dd>
              {advice ? (
                <span className="b89AiConclusion__priority">
                  {result.recommendedPriority && <PriorityMark priority={result.recommendedPriority} />}
                  <span>{advice}</span>
                </span>
              ) : (
                <span className="b89Muted">Sin sugerencia</span>
              )}
            </dd>
          </div>
          <div>
            <dt>Uso de IA</dt>
            <dd>
              <span className="b89Ai__tier" data-tier={run.inference ?? 'unknown'}>
                {run.inference === 'none'
                  ? `${AI_INFERENCE_LABEL.none} · sin costo`
                  : `${inferenceLabel(run.inference)} · ${runCostText(run)}`}
              </span>
            </dd>
          </div>
        </dl>
      </div>
      <p className="b89AiConclusion__verification" data-verified={result.verified ? 'true' : 'false'}>
        {result.verified ? (
          <HealthMark tone="ok" label="Citas verificadas contra la evidencia" />
        ) : (
          <HealthMark
            tone="warn"
            label="Sin verificar: las afirmaciones no se pudieron comprobar contra la evidencia citada. Trátala como hipótesis."
          />
        )}
      </p>
      {summary.text ? (
        <DataZone className="b89Prose b89AiConclusion__summary">
          {summary.text}
          {summary.clipped && (
            <>
              {' '}
              <a href="#b89AiSummary" onClick={jumpTo('b89AiSummary')}>
                Leer la explicación completa
              </a>
            </>
          )}
        </DataZone>
      ) : (
        <p className="b89Muted">El analista no dejó un resumen.</p>
      )}
      <div className="b89AiConclusion__next">
        <h4 className="b89AiConclusion__subhead">Qué recomienda</h4>
        {steps.length === 0 ? (
          <p className="b89Muted">No sugirió pasos concretos.</p>
        ) : (
          <ol className="b89AiConclusion__steps">
            {steps.map((step, index) => (
              <li key={index}>
                <DataZone className="b89Prose">{step}</DataZone>
              </li>
            ))}
          </ol>
        )}
        {moreSteps > 0 && (
          <a href="#b89AiNextSteps" onClick={jumpTo('b89AiNextSteps')}>
            {moreSteps === 1 ? 'Ver 1 paso más' : `Ver ${formatCount(moreSteps)} pasos más`}
          </a>
        )}
      </div>
      {result.gaps.length > 0 && (
        <p className="b89AiConclusion__gaps">
          <HealthMark tone="warn" label={gapCountText(result.gaps.length)} />{' '}
          <a href="#b89AiGaps" onClick={jumpTo('b89AiGaps')}>
            Ver qué falta
          </a>
        </p>
      )}
      <p className="b89AiConclusion__note">
        {alertChanged
          ? 'El analista actuó sobre esta alerta según la configuración vigente; el detalle está en «Acciones del analista». La prioridad sugerida es solo una recomendación.'
          : 'Es una recomendación: el analista no cambió la alerta.'}
      </p>
    </section>
  );
}

// ------------------------------------------------------------------ Resultado

export function AiResultView({
  result,
  partial,
  basePath,
}: {
  result: AiResult;
  partial: boolean;
  basePath: string;
  /** Se conserva por compatibilidad: la nota de cambio vive ahora en la conclusión. */
  alertChanged?: boolean;
}) {
  const summary = clipText(result.summary, CONCLUSION_SUMMARY_MAX);
  return (
    <>
      <Section
        id="b89AiFacts"
        title="Hechos observados"
        count={result.facts.length}
        hint="Lo que consta en la evidencia, con su cita."
      >
        {result.facts.length === 0 ? (
          <p className="b89Muted">No se registraron hechos observados.</p>
        ) : (
          <Statements
            items={result.facts}
            citations={result.citations}
            basePath={basePath}
            variant="fact"
          />
        )}
        {result.citations.length > 0 && (
          <div className="b89AiCitations">
            <p className="b89Ai__subhead">
              Evidencia citada{' '}
              <span className="b89AiSection__count b89Tabular">{result.citations.length}</span>
            </p>
            <span className="b89Chips">
              {result.citations.map((citation) => (
                <CitationChip
                  key={`${citation.kind}:${citation.id}`}
                  citation={citation}
                  basePath={basePath}
                />
              ))}
            </span>
          </div>
        )}
      </Section>
      <Section
        id="b89AiInferences"
        title="Hipótesis"
        count={result.inferences.length}
        hint="Lo que el analista deduce a partir de los hechos: contrástalo antes de actuar."
      >
        {result.inferences.length === 0 ? (
          <p className="b89Muted">No se registraron hipótesis.</p>
        ) : (
          <Statements
            items={result.inferences}
            citations={result.citations}
            basePath={basePath}
            variant="inference"
          />
        )}
      </Section>
      <Section
        id="b89AiGaps"
        title="Vacíos de evidencia"
        count={result.gaps.length}
        hint="Lo que el analista no pudo ver y podría cambiar la conclusión."
      >
        {result.gaps.length === 0 ? (
          <p className="b89Muted">El resultado no declara vacíos de evidencia.</p>
        ) : (
          <TextList items={result.gaps} variant="gap" />
        )}
      </Section>
      {result.nextSteps.length > CONCLUSION_STEPS_MAX && (
        <Section id="b89AiNextSteps" title="Siguientes pasos" count={result.nextSteps.length}>
          <TextList items={result.nextSteps} variant="step" ordered />
        </Section>
      )}
      {summary.clipped && (
        <Section
          id="b89AiSummary"
          title={partial ? 'Explicación del analista (resultado parcial)' : 'Explicación del analista'}
        >
          <DataZone className="b89Prose b89AiSummary">{result.summary}</DataZone>
        </Section>
      )}
      {result.deterministicReasons.length > 0 && (
        <Section id="b89AiDeterministic" title="Por qué decidió así">
          <ul className="b89AiReasons">
            {result.deterministicReasons.map((code) => (
              <li key={code}>
                <ReasonTag code={code} />
              </li>
            ))}
          </ul>
        </Section>
      )}
    </>
  );
}

// ------------------------------------------------------------------ Acciones del analista

type ActionRef = NonNullable<AiRunAction['ref']>;

function actionRefHref(basePath: string, ref: ActionRef): string | null {
  switch (ref.kind) {
    case 'alert':
      return alertHref(basePath, ref.id);
    case 'incident':
      return `${basePath}/app/b89-incidents?id=${encodeURIComponent(ref.id)}`;
    case 'notification':
      return `${basePath}/app/b89-notifications`;
    default:
      return null;
  }
}

const ACTION_REF_LABEL: Record<ActionRef['kind'], string> = {
  alert: 'Alerta',
  incident: 'Incidente',
  notification: 'Notificación',
  report: 'Informe',
  unknown: 'Referencia',
};

/**
 * Lo que el analista hizo, propuso u omitió. Solo «Ejecutada» significa que algo cambió: una
 * acción propuesta, omitida o fallida no modificó nada.
 */
export function AiRunActions({
  actions,
  basePath,
  mode = null,
  active = false,
}: {
  actions: readonly AiRunAction[];
  basePath: string;
  mode?: string | null;
  active?: boolean;
}) {
  const executed = executedActions(actions).length;
  const known = parseMode(mode);
  return (
    <Section id="b89AiActions" title="Acciones del analista" count={actions.length}>
      <p className="b89AiSection__hint" data-test-subj="b89AiActionsSummary">
        {executed > 0
          ? `El analista ejecutó ${formatCount(executed)} ${
              executed === 1 ? 'acción' : 'acciones'
            } en esta investigación.`
          : active
            ? 'El analista aún no ejecutó ninguna acción.'
            : 'El analista no ejecutó ninguna acción: no cambió alertas ni envió avisos por esta investigación.'}
        {executed === 0 &&
          known === 'shadow' &&
          ' En modo sombra las acciones solo quedan como propuesta.'}
        {executed === 0 &&
          known === 'assisted' &&
          ' En modo asistido solo puede pedir revisión humana; no cambia alertas.'}
      </p>
      {actions.length > 0 && (
        <ul className="b89AiActionList">
          {actions.map((action) => {
            const href = action.ref ? actionRefHref(basePath, action.ref) : null;
            const errorCode = sanitizeErrorCode(action.errorCode);
            return (
              <li key={action.id} className="b89AiAction" data-state={action.state}>
                <span className="b89AiAction__head">
                  <strong>
                    {action.kind === 'unknown' && action.rawKind ? (
                      <Mono>{action.rawKind}</Mono>
                    ) : (
                      AI_ACTION_KIND_LABEL[action.kind]
                    )}
                  </strong>
                  <HealthMark
                    tone={AI_ACTION_STATE_TONE[action.state]}
                    label={AI_ACTION_STATE_LABEL[action.state]}
                  />
                </span>
                <span className="b89AiAction__line">
                  <span className="b89Muted">Motivo: </span>
                  {action.reason ? <ReasonTag code={action.reason} /> : <span className="b89Muted">{NO_DATA}</span>}
                </span>
                {action.state === 'failed' && (
                  <span className="b89AiAction__line">
                    <span className="b89Muted">Error: </span>
                    {errorCode ? (
                      <ReasonTag code={errorCode} />
                    ) : (
                      'El servicio no informó un código de error.'
                    )}
                  </span>
                )}
                <span className="b89AiAction__line b89CellMeta">
                  <Timestamp iso={action.executedAt ?? action.at} />
                  {action.ref && (
                    <>
                      {' · '}
                      {ACTION_REF_LABEL[action.ref.kind]}:{' '}
                      {href ? (
                        <a href={href}>
                          <Mono>{action.ref.id}</Mono>
                        </a>
                      ) : (
                        <Mono>{action.ref.id}</Mono>
                      )}
                    </>
                  )}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ Progreso

const CLOCK = new Intl.DateTimeFormat('es-PE', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

/** Hora absoluta (HH:MM:SS): no cambia cada segundo como «hace 12 s». */
function ClockTime({ iso }: { iso: string | null }) {
  if (!iso) return <span className="b89Muted">{NO_DATA}</span>;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return <span className="b89Muted">{NO_DATA}</span>;
  return (
    <time dateTime={iso} className="b89Tabular" data-b89-no-translate="">
      {CLOCK.format(date)}
    </time>
  );
}

export function AiProgress({ run, now }: { run: AiRunDetail; now: number }) {
  const active = isActive(run.status);
  const steps = buildProgressTimeline(run.events, active);
  const elapsed = active
    ? formatDuration(elapsedMs(run.createdAt, now))
    : formatDuration(elapsedMs(run.createdAt, run.finishedAt));
  return (
    <Section
      id="b89AiProgress"
      title="Cronología"
      hint={
        <>
          {active ? 'Tiempo transcurrido' : 'Duración'}:{' '}
          <span className="b89Tabular">{elapsed ?? NO_DATA}</span>
          {run.attempt !== null && ` · intento ${formatCount(run.attempt)}`}. Solo se muestran las
          etapas que el servicio registró.
        </>
      }
    >
      {/* Sin región viva: el cambio de etapa se anuncia una vez en la conclusión (role="status"). */}
      <div aria-label="Etapas registradas por el servicio" role="group">
        {steps.length === 0 ? (
          <p className="b89Muted">
            {active
              ? 'El servicio aún no registró ninguna etapa.'
              : 'El servicio no registró etapas para esta investigación.'}
          </p>
        ) : (
          <ol className="b89AiSteps">
            {steps.map((step) => {
              const label = stageLabel(step.stage);
              const duration = formatDuration(step.durationMs);
              const entries = describeDetail(step.detail);
              const plain = entries.filter((entry) => entry.label !== null);
              const technical = entries.filter((entry) => entry.label === null);
              return (
                <li key={step.key} className="b89AiStep" data-status={step.status}>
                  <span className="b89AiStep__mark" aria-hidden="true" />
                  <span className="b89AiStep__body">
                    <strong>{label ?? <Mono>{step.stage}</Mono>}</strong>
                    <span className="b89CellMeta">
                      {AI_EVENT_KIND_LABEL[step.status]}
                      {duration && ` · ${duration}`}
                      {' · '}
                      <ClockTime iso={step.endedAt ?? step.startedAt} />
                    </span>
                    {plain.length > 0 && (
                      <span className="b89AiStep__detail">
                        {plain.map((entry) => (
                          <span key={entry.key}>
                            <span className="b89Muted">{entry.label}: </span>
                            {entry.text}
                            {entry.codes.map((code) => (
                              <React.Fragment key={code}>
                                {' '}
                                <ReasonTag code={code} />
                              </React.Fragment>
                            ))}
                          </span>
                        ))}
                      </span>
                    )}
                    {technical.length > 0 && (
                      <details className="b89AiDetails">
                        <summary>Datos sin traducir</summary>
                        <span className="b89Ai__detail" data-b89-no-translate="" translate="no">
                          {technical.map((entry) => (
                            <code key={entry.key} className="b89Mono">
                              {entry.key}={String(step.detail[entry.key])}
                            </code>
                          ))}
                        </span>
                      </details>
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </Section>
  );
}

// ------------------------------------------------------------------ Evidencia

function sourceTone(state: string) {
  return (SOURCE_STATES as readonly string[]).includes(state)
    ? SOURCE_TONE[state as SourceState]
    : 'neutral';
}

export function AiEvidenceCoverage({ evidence }: { evidence: AiEvidence | null }) {
  if (!evidence) {
    return (
      <Section id="b89AiEvidence" title="Evidencia examinada">
        <p className="b89Muted">Sin registro de evidencia para esta investigación.</p>
      </Section>
    );
  }
  return (
    <Section id="b89AiEvidence" title="Evidencia examinada">
      <div className="b89AiCoverage">
        {evidence.complete === true ? (
          <HealthMark tone="ok" label="Evidencia completa" />
        ) : evidence.complete === false ? (
          <HealthMark tone="warn" label="Evidencia parcial" />
        ) : (
          <HealthMark tone="neutral" label="Cobertura sin dato" />
        )}
        {evidence.truncated === true && (
          <HealthMark tone="warn" label="Truncada: quedó evidencia sin examinar" />
        )}
      </div>
      <dl className="b89AiCoverage__counts">
        <div>
          <dt>Alertas examinadas</dt>
          <dd className="b89Tabular">{formatCount(evidence.alertsScanned)}</dd>
        </div>
        <div>
          <dt>Eventos examinados</dt>
          <dd className="b89Tabular">{formatCount(evidence.eventsScanned)}</dd>
        </div>
        <div>
          <dt>Fuentes consultadas</dt>
          <dd className="b89Tabular">{formatCount(evidence.sources.length)}</dd>
        </div>
      </dl>
      {evidence.sources.length === 0 ? (
        <p className="b89Muted">No se informó el estado de las fuentes consultadas.</p>
      ) : (
        <ul className="b89AiSources">
          {evidence.sources.map((source) => {
            const state = evidenceSourceStateLabel(source.state);
            return (
              <li key={source.id}>
                <span className="b89AiSources__name" data-b89-no-translate="">
                  {source.label}
                </span>
                <span className="b89AiSources__state">
                  {state ? (
                    <HealthMark tone={sourceTone(source.state)} label={state} />
                  ) : (
                    <Mono>{source.state}</Mono>
                  )}
                </span>
                <span className="b89CellMeta">
                  {source.fresh === true
                    ? 'datos al día'
                    : source.fresh === false
                      ? 'datos desactualizados'
                      : 'frescura sin dato'}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {evidence.gaps.length > 0 && (
        <>
          <p className="b89Ai__subhead">Vacíos detectados al recolectar</p>
          <TextList items={evidence.gaps} variant="gap" />
        </>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ Reputación de IP

const IP_BAND_TONE: Record<AiIpReputationBand, HealthTone> = {
  malicious: 'fail',
  suspicious: 'warn',
  low: 'info',
  clean: 'ok',
  whitelisted: 'ok',
};

function ipReputationMeta(entry: AiIpReputation): string[] {
  const parts: string[] = [];
  if (entry.totalReports !== null) {
    parts.push(
      `${formatCount(entry.totalReports)} ${entry.totalReports === 1 ? 'reporte' : 'reportes'}` +
        (entry.distinctUsers !== null
          ? ` de ${formatCount(entry.distinctUsers)} ${entry.distinctUsers === 1 ? 'usuario' : 'usuarios'}`
          : ''),
    );
  }
  if (entry.countryCode) parts.push(entry.countryCode);
  if (entry.usageType) parts.push(entry.usageType);
  if (entry.isp) parts.push(entry.isp);
  if (entry.isTor === true) parts.push('Nodo Tor');
  return parts;
}

/** Reputación externa de las IP públicas de la alerta, tal como la recibió el analista. */
export function AiIpReputationView({ evidence }: { evidence: AiEvidence | null }) {
  if (!evidence || evidence.ipReputation.length === 0) return null;
  return (
    <Section id="b89AiIpReputation" title="Reputación de IP (AbuseIPDB)">
      <ul className="b89Ai__sources">
        {evidence.ipReputation.map((entry) => {
          const band = ipReputationBand(entry);
          return (
            <li key={entry.entityRef}>
              <span>
                <HealthMark
                  tone={IP_BAND_TONE[band]}
                  label={`${AI_IP_REPUTATION_BAND_LABEL[band]} · puntaje ${entry.abuseConfidenceScore}/100`}
                />
              </span>
              <span className="b89CellMeta">
                <Mono>{entry.entityRef}</Mono>
                {ipReputationMeta(entry).map((part, index) => (
                  <React.Fragment key={index}>
                    {' · '}
                    <span data-b89-no-translate="">{part}</span>
                  </React.Fragment>
                ))}
              </span>
              <span className="b89CellMeta">
                Último reporte:{' '}
                {entry.lastReportedAt ? <Timestamp iso={entry.lastReportedAt} /> : 'nunca'}
                {' · '}consultada <Timestamp iso={entry.checkedAt} />
              </span>
            </li>
          );
        })}
      </ul>
      <p className="b89Ai__note">
        Reportes de los últimos 90 días en AbuseIPDB. Es contexto del origen: un puntaje alto no
        prueba que el ataque tuviera éxito y un puntaje bajo no prueba que la IP sea legítima.
      </p>
    </Section>
  );
}

// ------------------------------------------------------------------ Uso y costo

export function AiUsageView({ run }: { run: AiRunDetail }) {
  const unknownUsage = run.invocations.some((item) => item.state === 'usage_unknown');
  if (run.inference === 'none' && run.invocations.length === 0) {
    return (
      <Section id="b89AiUsage" title="Uso y costo">
        <p className="b89AiSection__hint">
          <span className="b89Ai__tier" data-tier="none">
            {AI_INFERENCE_LABEL.none}
          </span>{' '}
          Resuelta con reglas automáticas, sin usar IA (sin costo).
        </p>
      </Section>
    );
  }
  return (
    <Section id="b89AiUsage" title="Uso y costo">
      <dl className="b89AiFile">
        <dt>Costo</dt>
        <dd className="b89Tabular">{runCostText(run)}</dd>
        <dt>Uso de IA</dt>
        <dd>{inferenceLabel(run.inference)}</dd>
        <dt>Volumen de texto enviado / recibido (tokens)</dt>
        <dd className="b89Tabular">
          {formatCount(run.usage ? run.usage.inputTokens : null)} /{' '}
          {formatCount(run.usage ? run.usage.outputTokens : null)}
        </dd>
        <dt>Texto reutilizado / guardado para reutilizar (tokens)</dt>
        <dd className="b89Tabular">
          {formatCount(run.usage ? run.usage.cacheReadTokens : null)} /{' '}
          {formatCount(run.usage ? run.usage.cacheWriteTokens : null)}
        </dd>
      </dl>
      {run.invocations.length > 0 && (
        <ul className="b89AiInvocations" aria-label="Llamadas a la IA">
          {run.invocations.map((item, index) => (
            <li key={index}>
              <span className="b89AiInvocations__head">
                <strong>{stageLabel(item.phase) ?? <Mono>{item.phase}</Mono>}</strong>
                <span className="b89Tabular">{formatMicroUsd(item.estimatedMicroUsd)}</span>
              </span>
              <span className="b89CellMeta">
                {AI_INFERENCE_LABEL[item.tier]} · <Mono>{item.model}</Mono>
              </span>
              <HealthMark
                tone={AI_INVOCATION_STATE_TONE[item.state]}
                label={AI_INVOCATION_STATE_LABEL[item.state]}
              />
            </li>
          ))}
        </ul>
      )}
      <p className="b89Ai__note">
        {unknownUsage && 'Hay llamadas con costo pendiente de confirmar. '}
        Costo aproximado; puede diferir de la factura.
      </p>
    </Section>
  );
}

// ------------------------------------------------------------------ Ficha

export function AiCaseFacts({ run, basePath }: { run: AiRunDetail; basePath: string }) {
  const active = isActive(run.status);
  const stage = stageLabel(run.stage);
  return (
    <Section id="b89AiFile" title="Datos del expediente">
      <dl className="b89AiFile">
        <dt>Estado</dt>
        <dd>
          {AI_RUN_STATUS_LABEL[run.status]}
          {active && run.stage && <> · {stage ?? <Mono>{run.stage}</Mono>}</>}
        </dd>
        <dt>Prioridad de la alerta</dt>
        <dd>
          {run.priority ? (
            <PriorityMark priority={run.priority} />
          ) : (
            <span className="b89Muted">{NO_DATA}</span>
          )}
        </dd>
        <dt>Alertas</dt>
        <dd>
          {run.alertIds.length === 0 ? (
            <span className="b89Muted">
              {run.alertCount === null ? NO_DATA : formatCount(run.alertCount)}
            </span>
          ) : (
            <span className="b89IdList">
              {run.alertIds.map((id) => (
                <a key={id} href={alertHref(basePath, id)}>
                  <Mono>{id}</Mono>
                </a>
              ))}
            </span>
          )}
        </dd>
        <dt>Origen</dt>
        <dd>
          {AI_TRIGGER_LABEL[run.trigger]}
          {run.initiatedBy && (
            <>
              {' · '}
              <span data-b89-no-translate="">{run.initiatedBy}</span>
            </>
          )}
        </dd>
        <dt>Creada</dt>
        <dd>
          <Timestamp iso={run.createdAt} />
        </dd>
        <dt>Finalizada</dt>
        <dd>{active ? 'En curso' : <Timestamp iso={run.finishedAt} />}</dd>
        <dt>Política</dt>
        <dd>{run.policyVersion ? <Mono>{run.policyVersion}</Mono> : NO_DATA}</dd>
        <dt>Identificador</dt>
        <dd>
          <Mono>{run.id}</Mono>
        </dd>
      </dl>
    </Section>
  );
}

// ------------------------------------------------------------------ Expediente

export function AiCaseFile({
  run,
  basePath,
  now,
  mode = null,
  review = null,
}: {
  run: AiRunDetail;
  basePath: string;
  now: number;
  /** Modo vigente del analista (no el de la corrida, que el contrato no informa). */
  mode?: string | null;
  /** «Tu revisión»: va justo después de la conclusión, para decidir con ella a la vista. */
  review?: React.ReactNode;
}) {
  const active = isActive(run.status);
  return (
    <div className="b89AiCase">
      <AiRunStatusCallout run={run} />
      <AiConclusion run={run} />
      {review}
      <div className="b89AiCase__main">
        {run.result && (
          <AiResultView
            result={run.result}
            partial={run.status === 'partial'}
            basePath={basePath}
            alertChanged={changedAlert(run.actions)}
          />
        )}
        <AiRunActions actions={run.actions} basePath={basePath} mode={mode} active={active} />
        <AiIpReputationView evidence={run.evidence} />
        {/* En curso, la cronología es lo que importa: se ve sin desplegar nada. */}
        {active && <AiProgress run={run} now={now} />}
        <AiTechnicalDetails>
          {!active && <AiProgress run={run} now={now} />}
          <AiEvidenceCoverage evidence={run.evidence} />
          <AiUsageView run={run} />
          <AiCaseFacts run={run} basePath={basePath} />
        </AiTechnicalDetails>
      </div>
    </div>
  );
}

/** Todo lo técnico (cronología, cobertura, uso y costo, datos del expediente) bajo un solo pliegue. */
export function AiTechnicalDetails({ children }: { children: React.ReactNode }) {
  return (
    <details className="b89AiDetails b89AiTechnical">
      <summary id={TECHNICAL_ID}>
        Detalles técnicos
        <span className="b89CellMeta"> · cronología, evidencia examinada, uso y costo, datos del expediente</span>
      </summary>
      <div className="b89AiTechnical__body">{children}</div>
    </details>
  );
}

export const TECHNICAL_ID = 'b89AiTechnical';
/** Acciones del expediente. Detener y reintentar solo con `investigations.run`. */
export function AiCaseFileActions({
  run,
  basePath,
  canRun,
  busy,
  onCancel,
  onRetry,
  onAskBunny,
  onDownloadReport,
  downloading = false,
}: {
  run: AiRunDetail;
  basePath: string;
  canRun: boolean;
  busy: boolean;
  onCancel: () => void;
  onRetry: () => void;
  onAskBunny: () => void;
  onDownloadReport?: () => void;
  downloading?: boolean;
}) {
  const alertId = primaryAlertId(run);
  return (
    <div className="b89Ai__actions">
      {alertId && (
        <EuiButtonEmpty
          size="s"
          iconType="popout"
          href={alertHref(basePath, alertId)}
          data-test-subj="b89AiOpenAlert"
        >
          Abrir alerta
        </EuiButtonEmpty>
      )}
      <EuiButtonEmpty size="s" iconType="discuss" onClick={onAskBunny} data-test-subj="b89AiAskBunny">
        Preguntar a Bunny
      </EuiButtonEmpty>
      {onDownloadReport && isTerminal(run.status) && (
        <EuiButtonEmpty
          size="s"
          iconType="download"
          isLoading={downloading}
          onClick={onDownloadReport}
          data-test-subj="b89AiDownloadReport"
        >
          Guardar informe como PDF
        </EuiButtonEmpty>
      )}
      {canRun && canCancel(run) && (
        <EuiButton
          size="s"
          color="danger"
          isDisabled={busy}
          onClick={onCancel}
          data-test-subj="b89AiCancel"
        >
          Detener
        </EuiButton>
      )}
      {canRun && canRetry(run) && (
        <EuiButton size="s" fill isDisabled={busy} onClick={onRetry} data-test-subj="b89AiRetry">
          Reintentar
        </EuiButton>
      )}
    </div>
  );
}
