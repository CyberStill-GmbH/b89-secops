/**
 * Proyección HTTP del Analista IA. La forma es EXACTAMENTE la que normaliza la consola en
 * `wazuh/dashboard/plugins/b89_ops/common/ai_investigations.ts` (fuente de verdad del contrato):
 * cambiar un campo aquí exige revisar ese archivo.
 *
 * Nunca salen: prompts, paquete de evidencia, respuesta cruda del modelo, claves de entidad,
 * identificadores de persona sin enmascarar ni texto de instrucciones del administrador fuera de
 * `GET /settings` (que solo lee quien puede verlas en la consola).
 */

import {
  ANALYST_MODES,
  type AnalystMode,
  type AnalystSettings,
  type BudgetSnapshot,
  type InvestigationAction,
  type InvestigationCursor,
  type InvestigationEvent,
  type InvestigationInvocation,
  type InvestigationJob,
  type OperationsDigest,
  type RunReport,
  type StoredAnalystSettings,
} from '@b89/assistant';
import { maskText } from '@b89/soar';

const UUID_LIKE = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/iu;

/** Identificador de persona enmascarado para la consola; servicios y sistema se muestran tal cual. */
export function maskActorRef(value: string | null | undefined): string | null {
  if (!value) return null;
  if (/^(svc|system):/u.test(value)) return value.slice(0, 80);
  if (value.includes('@')) return maskText(value).slice(0, 120);
  if (UUID_LIKE.test(value) || value.length > 12) return `${value.slice(0, 8)}…`;
  return `${value.slice(0, 2)}***`;
}

const iso = (value: Date | null | undefined): string | null => (value ? value.toISOString() : null);

/** Cursor opaco `createdAt|id` en base64url. */
export function encodeCursor(cursor: InvestigationCursor | null): string | null {
  return cursor
    ? Buffer.from(`${cursor.createdAt.toISOString()}|${cursor.id}`, 'utf8').toString('base64url')
    : null;
}

export function decodeCursor(raw: string): InvestigationCursor | undefined {
  if (!/^[A-Za-z0-9_-]{1,400}$/u.test(raw)) return undefined;
  const text = Buffer.from(raw, 'base64url').toString('utf8');
  const [at, id, extra] = text.split('|');
  const createdAt = new Date(at ?? '');
  if (extra !== undefined || !id || id.length > 128 || Number.isNaN(createdAt.getTime())) {
    return undefined;
  }
  return { createdAt, id };
}

export interface RunExtras {
  readonly invocations: readonly InvestigationInvocation[];
  readonly actions: readonly InvestigationAction[];
}

function estimatedCost(invocations: readonly InvestigationInvocation[]): number {
  return invocations.reduce(
    (sum, row) => sum + (row.state === 'settled' && row.estimatedMicroUsd !== null ? row.estimatedMicroUsd : 0),
    0,
  );
}

export function runSummaryView(job: InvestigationJob, extras: RunExtras) {
  return {
    id: job.id,
    status: job.status,
    stage: job.stage,
    priority: job.priority,
    trigger: job.trigger,
    source: job.source,
    initiatedBy: maskActorRef(job.initiatedBy),
    subject: { kind: job.subject.kind, id: job.subject.id, title: maskText(job.subject.title) },
    alertCount: job.alertIds.length,
    inference: job.inference,
    verdict: job.result?.verdict ?? null,
    confidence: job.result?.confidence ?? null,
    createdAt: iso(job.createdAt),
    updatedAt: iso(job.updatedAt),
    finishedAt: iso(job.finishedAt),
    revision: job.revision,
    estimatedCostMicroUsd: estimatedCost(extras.invocations),
    actionKinds: [
      ...new Set(
        extras.actions.filter((action) => action.state === 'executed').map((action) => action.kind),
      ),
    ],
  };
}

/** Modo con que corrió: lo deja el runner en el evento final de la bitácora. */
export function runModeOf(events: readonly InvestigationEvent[]): AnalystMode | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const mode = events[index]!.detail['mode'];
    if (typeof mode === 'string' && (ANALYST_MODES as readonly string[]).includes(mode)) {
      return mode as AnalystMode;
    }
  }
  return null;
}

export function runDetailView(
  job: InvestigationJob,
  events: readonly InvestigationEvent[],
  extras: RunExtras,
) {
  const settled = extras.invocations.filter((row) => row.usage !== null);
  const usage =
    settled.length === 0
      ? null
      : settled.reduce(
          (sum, row) => ({
            inputTokens: sum.inputTokens + row.usage!.inputTokens,
            outputTokens: sum.outputTokens + row.usage!.outputTokens,
            cacheReadTokens: sum.cacheReadTokens + row.usage!.cacheReadTokens,
            cacheWriteTokens: sum.cacheWriteTokens + row.usage!.cacheWriteTokens,
          }),
          { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 },
        );
  const evidence = job.evidence;
  const result = job.result;
  return {
    ...runSummaryView(job, extras),
    mode: runModeOf(events),
    policyVersion: job.policyVersion,
    attempt: job.attempt,
    lastErrorCode: job.lastErrorCode,
    cancelRequested: job.cancelRequested,
    alertIds: job.alertIds,
    events: events.map((event) => ({
      sequence: event.sequence,
      at: iso(event.at),
      stage: event.stage,
      kind: event.kind,
      detail: event.detail,
    })),
    evidence: evidence
      ? {
          complete: evidence.complete,
          truncated: evidence.truncated || evidence.packTruncated,
          alertsScanned: evidence.alertCount + evidence.relatedAlertCount,
          eventsScanned: evidence.eventCount,
          // La lista de fuentes no se persiste; el conteo de las no sanas va en los vacíos.
          sources: [],
          gaps: [
            ...(evidence.unhealthySourceCount > 0
              ? [`${evidence.unhealthySourceCount} fuente(s) sin datos frescos o con falla al leer`]
              : []),
            ...evidence.gaps,
          ],
        }
      : null,
    result: result
      ? {
          summary: result.summary,
          verdict: result.verdict,
          confidence: result.confidence,
          recommendedPriority: result.recommendedPriority,
          // Citas como ids planos que coinciden con `citations[].id`.
          facts: result.facts.map((fact) => ({ text: fact.text, citations: [...fact.citations] })),
          inferences: result.inferences.map((entry) => ({
            text: entry.text,
            citations: [...entry.citations],
          })),
          gaps: result.gaps,
          nextSteps: result.nextSteps,
          citations: result.citations.map((citation) => ({
            kind: citation.kind,
            id: citation.id,
            label: maskText(citation.label),
          })),
          verified: result.verified,
          deterministic: { reasons: result.deterministic.reasons },
        }
      : null,
    usage,
    invocations: extras.invocations.map((row) => ({
      phase: row.phase,
      tier: row.tier,
      model: row.model,
      state: row.state,
      estimatedMicroUsd: row.state === 'settled' ? row.estimatedMicroUsd : null,
    })),
    actions: extras.actions.map((action) => ({
      id: action.id,
      kind: action.kind,
      state: action.state,
      reason: action.reason,
      urgency: action.urgency,
      at: iso(action.at),
      executedAt: iso(action.executedAt),
      ref: action.ref,
      errorCode: action.errorCode,
    })),
  };
}

export function settingsView(stored: StoredAnalystSettings | undefined, settings: AnalystSettings) {
  return {
    ...settings,
    revision: stored?.revision ?? 0,
    updatedAt: iso(stored?.updatedAt),
    updatedBy: maskActorRef(stored?.updatedBy),
  };
}

export function budgetView(input: {
  readonly snapshot: BudgetSnapshot;
  readonly settings: AnalystSettings;
  readonly deploymentEnabled: boolean;
  readonly limitMicroUsd: number | null;
  readonly rateCardVersion: string;
}) {
  const { snapshot, settings } = input;
  const runs = snapshot.runsToday;
  return {
    enabled: input.deploymentEnabled && settings.enabled,
    mode: settings.mode,
    inferenceEnabled: input.deploymentEnabled && input.limitMicroUsd !== null,
    day: {
      date: snapshot.day,
      limitMicroUsd: input.limitMicroUsd,
      reservedMicroUsd: snapshot.reservedMicroUsd + snapshot.unknownMicroUsd,
      settledMicroUsd: snapshot.settledMicroUsd,
      unknownInvocations: snapshot.unknownCount,
    },
    tokens: snapshot.tokens,
    runs: {
      today: runs.none + runs.economy + runs.advanced,
      withoutInference: runs.none,
      economy: runs.economy,
      advanced: runs.advanced,
    },
    rateCardVersion: input.rateCardVersion,
    billing: 'not_connected',
  };
}

export function digestView(digest: OperationsDigest) {
  return {
    from: digest.from.toISOString(),
    to: digest.to.toISOString(),
    totals: digest.totals,
    byPriority: digest.byPriority,
    topRules: digest.topRules.map((rule) => ({ ruleId: rule.ruleId, count: rule.runs })),
    estimatedMicroUsd: digest.estimatedMicroUsd,
    coverage: digest.coverage,
    markdown: digest.markdown,
  };
}

export function reportView(report: RunReport, generatedAt: Date) {
  return { filename: report.filename, markdown: report.markdown, generatedAt: generatedAt.toISOString() };
}
