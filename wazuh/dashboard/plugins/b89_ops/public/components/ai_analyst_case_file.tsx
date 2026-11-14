/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut } from '@elastic/eui';
import {
  actionReasonLabel,
  AI_ACTION_KIND_LABEL,
  AI_ACTION_STATE_LABEL,
  AI_ACTION_STATE_TONE,
  AI_CITATION_KIND_LABEL,
  AI_EVENT_KIND_LABEL,
  AI_INFERENCE_LABEL,
  AI_INVOCATION_STATE_LABEL,
  AI_INVOCATION_STATE_TONE,
  AI_RUN_STATUS_LABEL,
  AI_TRIGGER_LABEL,
  AiCitation,
  AiEvidence,
  AiResult,
  AiRunAction,
  AiRunDetail,
  AiStatement,
  buildProgressTimeline,
  canCancel,
  canRetry,
  changedAlert,
  confidenceLabel,
  deterministicReasonLabel,
  elapsedMs,
  evidenceSourceStateLabel,
  executedActions,
  formatCount,
  formatDuration,
  formatMicroUsd,
  inferenceLabel,
  isActive,
  isTerminal,
  NO_DATA,
  parseMode,
  sanitizeErrorCode,
  stageLabel,
  verdictLabel,
} from '../../common';
import { citationPath } from '../bunny/chat_client';
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
    case 'requires_review':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Requiere revisión humana">
          <p>
            El resultado no superó la verificación automática. Trátalo como hipótesis y contrasta
            cada afirmación con la evidencia antes de actuar.
          </p>
        </EuiCallOut>
      );
    case 'budget_exhausted':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Presupuesto diario agotado">
          <p>
            No se llamó al modelo porque el techo diario de inferencia ya estaba comprometido. Se
            puede reintentar cuando haya presupuesto.
          </p>
        </EuiCallOut>
      );
    case 'usage_unreconciled':
      return (
        <EuiCallOut size="s" color="warning" iconType="alert" title="Uso por conciliar">
          <p>
            Se envió una llamada al modelo y su consumo no se confirmó. El costo de esta
            investigación es desconocido hasta la conciliación; la consola no la reintenta para no
            duplicar el gasto.
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
                Código: <Mono>{code}</Mono>
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

// ------------------------------------------------------------------ Resultado

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
}: {
  items: readonly AiStatement[];
  citations: readonly AiCitation[];
  basePath: string;
}) {
  return (
    <ul className="b89Ai__statements">
      {items.map((item, index) => (
        <li key={index}>
          <DataZone className="b89Prose">{item.text}</DataZone>
          {item.citations.length === 0 ? (
            <span className="b89CellMeta">Sin cita</span>
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
    </ul>
  );
}

function TextList({ items }: { items: readonly string[] }) {
  return (
    <ul className="b89Ai__statements">
      {items.map((item, index) => (
        <li key={index}>
          <DataZone className="b89Prose">{item}</DataZone>
        </li>
      ))}
    </ul>
  );
}

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="b89Ai__section" aria-labelledby={id}>
      <h3 id={id} className="b89Ai__sectionTitle">
        {title}
      </h3>
      {children}
    </section>
  );
}

export function AiResultView({
  result,
  partial,
  basePath,
  alertChanged = false,
}: {
  result: AiResult;
  partial: boolean;
  basePath: string;
  /** El analista ejecutó una acción que modificó la alerta (ver «Acciones del analista»). */
  alertChanged?: boolean;
}) {
  return (
    <>
      {!result.verified && (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="alert"
          title="Sin citas verificadas: requiere revisión humana"
        >
          <p>Las afirmaciones no se pudieron comprobar contra la evidencia citada.</p>
        </EuiCallOut>
      )}
      <Section id="b89AiSummary" title={partial ? 'Resumen (resultado parcial)' : 'Resumen'}>
        <DataZone className="b89Prose">
          {result.summary || <span className="b89Muted">Sin resumen.</span>}
        </DataZone>
      </Section>
      <Section id="b89AiRecommendation" title="Recomendación">
        <dl className="b89KeyValues">
          <dt>Veredicto</dt>
          <dd>{verdictLabel(result.verdict)}</dd>
          <dt>Confianza</dt>
          <dd>{confidenceLabel(result.confidence)}</dd>
          <dt>Prioridad sugerida</dt>
          <dd>
            {result.recommendedPriority ? (
              <PriorityMark priority={result.recommendedPriority} />
            ) : (
              <span className="b89Muted">Sin sugerencia</span>
            )}
          </dd>
        </dl>
        <p className="b89Ai__note">
          {alertChanged
            ? 'El analista actuó sobre esta alerta según la configuración vigente; el detalle está en «Acciones del analista». La prioridad sugerida es solo una recomendación.'
            : 'Es una recomendación: el analista no cambió la alerta.'}
        </p>
      </Section>
      {result.deterministicReasons.length > 0 && (
        <Section id="b89AiDeterministic" title="Motivos deterministas">
          <ul className="b89Ai__reasons">
            {result.deterministicReasons.map((code) => {
              const label = deterministicReasonLabel(code);
              return (
                <li key={code}>
                  {label ?? <Mono>{code}</Mono>}
                  {label && (
                    <span className="b89CellMeta">
                      {' '}
                      <Mono>{code}</Mono>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      )}
      <Section id="b89AiFacts" title="Hechos observados">
        {result.facts.length === 0 ? (
          <p className="b89Muted">No se registraron hechos observados.</p>
        ) : (
          <Statements items={result.facts} citations={result.citations} basePath={basePath} />
        )}
      </Section>
      <Section id="b89AiInferences" title="Inferencias">
        {result.inferences.length === 0 ? (
          <p className="b89Muted">No se registraron inferencias.</p>
        ) : (
          <Statements items={result.inferences} citations={result.citations} basePath={basePath} />
        )}
      </Section>
      <Section id="b89AiGaps" title="Vacíos de evidencia">
        {result.gaps.length === 0 ? (
          <p className="b89Muted">El resultado no declara vacíos de evidencia.</p>
        ) : (
          <TextList items={result.gaps} />
        )}
      </Section>
      <Section id="b89AiNextSteps" title="Siguientes pasos">
        {result.nextSteps.length === 0 ? (
          <p className="b89Muted">No se sugirieron pasos.</p>
        ) : (
          <TextList items={result.nextSteps} />
        )}
      </Section>
      {result.citations.length > 0 && (
        <Section id="b89AiCitations" title="Citas">
          <span className="b89Chips">
            {result.citations.map((citation) => (
              <CitationChip
                key={`${citation.kind}:${citation.id}`}
                citation={citation}
                basePath={basePath}
              />
            ))}
          </span>
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
    <Section id="b89AiActions" title="Acciones del analista">
      <p className="b89Ai__note" data-test-subj="b89AiActionsSummary">
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
        <ul className="b89Ai__actionList">
          {actions.map((action) => {
            const reason = action.reason ? actionReasonLabel(action.reason) : null;
            const href = action.ref ? actionRefHref(basePath, action.ref) : null;
            const errorCode = sanitizeErrorCode(action.errorCode);
            return (
              <li key={action.id} className="b89Ai__action" data-state={action.state}>
                <span className="b89Ai__actionHead">
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
                <span className="b89CellMeta">
                  {action.reason ? (
                    <>Motivo: {reason ?? <Mono>{action.reason}</Mono>}</>
                  ) : (
                    'Motivo sin dato'
                  )}
                  {' · '}
                  <Timestamp iso={action.executedAt ?? action.at} />
                </span>
                {action.state === 'failed' && (
                  <span className="b89CellMeta">
                    {errorCode ? (
                      <>
                        Código de error: <Mono>{errorCode}</Mono>
                      </>
                    ) : (
                      'El servicio no informó un código de error.'
                    )}
                  </span>
                )}
                {action.ref && (
                  <span className="b89CellMeta">
                    {ACTION_REF_LABEL[action.ref.kind]}:{' '}
                    {href ? (
                      <a href={href}>
                        <Mono>{action.ref.id}</Mono>
                      </a>
                    ) : (
                      <Mono>{action.ref.id}</Mono>
                    )}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ Progreso

export function AiProgress({ run, now }: { run: AiRunDetail; now: number }) {
  const active = isActive(run.status);
  const steps = buildProgressTimeline(run.events, active);
  const elapsed = active
    ? formatDuration(elapsedMs(run.createdAt, now))
    : formatDuration(elapsedMs(run.createdAt, run.finishedAt));
  return (
    <Section id="b89AiProgress" title="Progreso">
      <p className="b89CellMeta">
        {active ? 'Tiempo transcurrido' : 'Duración'}:{' '}
        <span className="b89Tabular">{elapsed ?? NO_DATA}</span>
        {run.attempt !== null && ` · intento ${formatCount(run.attempt)}`}
      </p>
      <div
        role="log"
        aria-live="polite"
        aria-relevant="additions text"
        aria-label="Etapas registradas por el servicio"
      >
        {steps.length === 0 ? (
          <p className="b89Muted">
            {active
              ? 'El servicio aún no registró ninguna etapa.'
              : 'El servicio no registró etapas para esta investigación.'}
          </p>
        ) : (
          <ol className="b89Ai__steps">
            {steps.map((step) => {
              const label = stageLabel(step.stage);
              const duration = formatDuration(step.durationMs);
              const detail = Object.keys(step.detail);
              return (
                <li key={step.key} className="b89Ai__step" data-status={step.status}>
                  <span className="b89Ai__stepMark" aria-hidden="true" />
                  <span className="b89Ai__stepBody">
                    <strong>{label ?? <Mono>{step.stage}</Mono>}</strong>
                    <span className="b89CellMeta">
                      {AI_EVENT_KIND_LABEL[step.status]}
                      {duration && ` · ${duration}`}
                      {' · '}
                      <Timestamp iso={step.endedAt ?? step.startedAt} />
                    </span>
                    {detail.length > 0 && (
                      <span className="b89Ai__detail" data-b89-no-translate="" translate="no">
                        {detail.map((key) => (
                          <code key={key} className="b89Mono">
                            {key}={String(step.detail[key])}
                          </code>
                        ))}
                      </span>
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </div>
      <p className="b89Ai__note">
        Solo se muestran las etapas que el servicio registró; no se estima porcentaje ni pasos
        pendientes.
      </p>
    </Section>
  );
}

// ------------------------------------------------------------------ Evidencia

export function AiEvidenceCoverage({ evidence }: { evidence: AiEvidence | null }) {
  if (!evidence) {
    return (
      <Section id="b89AiEvidence" title="Cobertura de evidencia">
        <p className="b89Muted">Sin registro de evidencia para esta investigación.</p>
      </Section>
    );
  }
  return (
    <Section id="b89AiEvidence" title="Cobertura de evidencia">
      <div className="b89Ai__coverage">
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
      <dl className="b89KeyValues">
        <dt>Alertas examinadas</dt>
        <dd className="b89Tabular">{formatCount(evidence.alertsScanned)}</dd>
        <dt>Eventos examinados</dt>
        <dd className="b89Tabular">{formatCount(evidence.eventsScanned)}</dd>
      </dl>
      {evidence.sources.length === 0 ? (
        <p className="b89Muted">No se informó el estado de las fuentes consultadas.</p>
      ) : (
        <ul className="b89Ai__sources">
          {evidence.sources.map((source) => {
            const state = evidenceSourceStateLabel(source.state);
            return (
              <li key={source.id}>
                <span data-b89-no-translate="">{source.label}</span>
                <span className="b89CellMeta">
                  {state ?? <Mono>{source.state}</Mono>}
                  {' · '}
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
          <TextList items={evidence.gaps} />
        </>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ Uso y costo

export function AiUsageView({ run }: { run: AiRunDetail }) {
  const unknownUsage = run.invocations.some((item) => item.state === 'usage_unknown');
  if (run.inference === 'none' && run.invocations.length === 0) {
    return (
      <Section id="b89AiUsage" title="Uso y costo">
        <p>
          <span className="b89Ai__tier" data-tier="none">
            {AI_INFERENCE_LABEL.none}
          </span>{' '}
          Resuelta con reglas deterministas, sin llamada al modelo: no generó costo de inferencia.
        </p>
      </Section>
    );
  }
  return (
    <Section id="b89AiUsage" title="Uso y costo">
      <dl className="b89KeyValues">
        <dt>Nivel de inferencia</dt>
        <dd>{inferenceLabel(run.inference)}</dd>
        <dt>Tokens de entrada</dt>
        <dd className="b89Tabular">{formatCount(run.usage ? run.usage.inputTokens : null)}</dd>
        <dt>Tokens de salida</dt>
        <dd className="b89Tabular">{formatCount(run.usage ? run.usage.outputTokens : null)}</dd>
        <dt>Caché (lectura / escritura)</dt>
        <dd className="b89Tabular">
          {formatCount(run.usage ? run.usage.cacheReadTokens : null)} /{' '}
          {formatCount(run.usage ? run.usage.cacheWriteTokens : null)}
        </dd>
        <dt>Costo</dt>
        <dd className="b89Tabular">{runCostText(run)}</dd>
      </dl>
      {run.invocations.length > 0 && (
        <div className="b89Ai__tableWrap">
          <table className="b89Ai__invocations">
            <thead>
              <tr>
                <th scope="col">Fase</th>
                <th scope="col">Nivel / modelo</th>
                <th scope="col">Estado</th>
                <th scope="col">Costo</th>
              </tr>
            </thead>
            <tbody>
              {run.invocations.map((item, index) => (
                <tr key={index}>
                  <td>
                    <Mono>{item.phase}</Mono>
                  </td>
                  <td>
                    {AI_INFERENCE_LABEL[item.tier]}
                    <br />
                    <Mono>{item.model}</Mono>
                  </td>
                  <td>
                    <HealthMark
                      tone={AI_INVOCATION_STATE_TONE[item.state]}
                      label={AI_INVOCATION_STATE_LABEL[item.state]}
                    />
                  </td>
                  <td className="b89Tabular">{formatMicroUsd(item.estimatedMicroUsd)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="b89Ai__note">
        {unknownUsage && 'Hay llamadas con uso por conciliar: el costo real puede diferir. '}
        Costo estimado según el tarifario; facturación no conectada.
      </p>
    </Section>
  );
}

// ------------------------------------------------------------------ Expediente

export function AiCaseFile({
  run,
  basePath,
  now,
  mode = null,
}: {
  run: AiRunDetail;
  basePath: string;
  now: number;
  /** Modo vigente del analista (no el de la corrida, que el contrato no informa). */
  mode?: string | null;
}) {
  const active = isActive(run.status);
  const stage = stageLabel(run.stage);
  return (
    <div className="b89Ai__caseFile">
      <AiRunStatusCallout run={run} />
      <dl className="b89KeyValues">
        <dt>Identificador</dt>
        <dd>
          <Mono>{run.id}</Mono>
        </dd>
        <dt>Estado</dt>
        <dd>
          {AI_RUN_STATUS_LABEL[run.status]}
          {active && run.stage && <> · {stage ?? <Mono>{run.stage}</Mono>}</>}
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
        <dt>Política</dt>
        <dd>{run.policyVersion ? <Mono>{run.policyVersion}</Mono> : NO_DATA}</dd>
        <dt>Creada</dt>
        <dd>
          <Timestamp iso={run.createdAt} />
        </dd>
        <dt>Finalizada</dt>
        <dd>{active ? 'En curso' : <Timestamp iso={run.finishedAt} />}</dd>
      </dl>
      {run.result ? (
        <AiResultView
          result={run.result}
          partial={run.status === 'partial'}
          basePath={basePath}
          alertChanged={changedAlert(run.actions)}
        />
      ) : (
        <Section id="b89AiSummary" title="Resultado">
          <p className="b89Muted">
            {active
              ? 'Aún no hay resultado: la investigación sigue en curso.'
              : 'Esta investigación no produjo un resultado.'}
          </p>
        </Section>
      )}
      <AiRunActions actions={run.actions} basePath={basePath} mode={mode} active={active} />
      <AiProgress run={run} now={now} />
      <AiEvidenceCoverage evidence={run.evidence} />
      <AiUsageView run={run} />
    </div>
  );
}

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
        <EuiButtonEmpty size="s" href={alertHref(basePath, alertId)} data-test-subj="b89AiOpenAlert">
          Abrir alerta
        </EuiButtonEmpty>
      )}
      <EuiButtonEmpty size="s" onClick={onAskBunny} data-test-subj="b89AiAskBunny">
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
          Descargar informe
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
