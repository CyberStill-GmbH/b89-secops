/**
 * Contrato HTTP del Analista IA: lo que proyecta el API (`ai-investigations.dto.ts`) lo lee sin
 * pérdidas el normalizador de la consola (`common/ai_investigations.ts`, fuente de verdad).
 */

import { describe, expect, it } from 'vitest';

import {
  ACTION_REASON_CODES,
  DEFAULT_ANALYST_SETTINGS,
  buildDigest,
  type InvestigationAction,
  type InvestigationEvent,
  type InvestigationInvocation,
  type InvestigationJob,
} from '../../modules/assistant/src/index';

import {
  budgetView,
  digestView,
  reportView,
  runDetailView,
  runSummaryView,
  settingsView,
} from '../../apps/api/src/assistant/ai-investigations.dto';
import {
  actionReasonLabel,
  normalizeBudget,
  normalizeDigest,
  normalizeRunDetail,
  normalizeRunPage,
  normalizeRunReport,
  normalizeSettingsView,
} from '../../wazuh/dashboard/plugins/b89_ops/common/ai_investigations';

const AT = new Date('2026-11-14T10:00:00.000Z');
const ID = '0f8e2c1a-1111-4222-8333-444455556666';

const job: InvestigationJob = {
  id: ID,
  tenantId: 't1',
  subject: { kind: 'alert', id: 'alert-1', title: 'B89 Wazuh: acceso', ruleId: '5716' },
  alertIds: ['alert-1'],
  priority: 'P2',
  trigger: 'user',
  source: 'manual',
  initiatedBy: 'jperez@b89.example',
  idempotencyKey: 'manual:alert-1:1',
  fingerprint: 'f'.repeat(64),
  policyVersion: 'b89-analyst-2026-11-14.1',
  status: 'completed',
  stage: null,
  inference: 'economy',
  attempt: 1,
  availableAt: AT,
  leaseUntil: null,
  fencingToken: 1,
  cancelRequested: false,
  lastErrorCode: null,
  result: {
    summary: 'Resumen',
    verdict: 'likely_true_positive',
    confidence: 'high',
    recommendedPriority: 'P1',
    facts: [{ text: 'Hecho', citations: ['alert-1'] }],
    inferences: [],
    gaps: [],
    nextSteps: ['Revisar'],
    citations: [{ kind: 'alert', id: 'alert-1', label: 'Alerta alert-1' }],
    verified: true,
    deterministic: { reasons: ['P2_MULTI_SOURCE'] },
  },
  plannedStatus: null,
  evidence: {
    alertCount: 1,
    relatedAlertCount: 2,
    eventCount: 3,
    sourceCount: 1,
    unhealthySourceCount: 0,
    complete: true,
    truncated: false,
    gaps: ['Correlador no configurado: sin riesgo de la entidad'],
    watermark: 'w1',
    fingerprint: 'f'.repeat(64),
    estimatedInputTokens: 900,
    packTruncated: false,
  },
  createdAt: AT,
  updatedAt: AT,
  startedAt: AT,
  finishedAt: AT,
  revision: 3,
};

const events: InvestigationEvent[] = [
  { jobId: ID, sequence: 1, at: AT, stage: 'fetching_evidence', kind: 'started', detail: { attempt: 1 } },
  { jobId: ID, sequence: 2, at: AT, stage: 'writing', kind: 'completed', detail: { status: 'completed', mode: 'assisted' } },
];
const invocations: InvestigationInvocation[] = [
  {
    id: 'inv-1',
    jobId: ID,
    tenantId: 't1',
    phase: 'analysis',
    fingerprint: 'f'.repeat(64),
    tier: 'economy',
    model: 'claude-haiku-5-5',
    state: 'settled',
    reservedInputTokens: 1000,
    reservedOutputTokens: 700,
    reservedMicroUsd: 500,
    usage: { inputTokens: 800, outputTokens: 200, cacheReadTokens: 100, cacheWriteTokens: 0 },
    estimatedMicroUsd: 181,
    rateCardVersion: 'v',
    createdAt: AT,
    settledAt: AT,
  },
];
const actions: InvestigationAction[] = [
  {
    id: 'act-1',
    jobId: ID,
    tenantId: 't1',
    kind: 'request_review',
    state: 'executed',
    reason: 'REVIEW_ESCALATION_RECOMMENDED',
    urgency: 'immediate',
    groupKey: 'rule:5716|entity:ent_x',
    at: AT,
    executedAt: AT,
    ref: { kind: 'notification', id: 'n-1' },
    errorCode: null,
  },
];

describe('contrato del Analista IA (API ↔ consola)', () => {
  it('detalle, página y resumen se normalizan sin pérdidas', () => {
    const detail = normalizeRunDetail(JSON.parse(JSON.stringify(runDetailView(job, events, { invocations, actions }))));
    expect(detail).not.toBeNull();
    expect(detail).toMatchObject({
      id: ID,
      status: 'completed',
      priority: 'P2',
      trigger: 'user',
      initiatedBy: 'jp***@b89.example',
      inference: 'economy',
      verdict: 'likely_true_positive',
      revision: 3,
      estimatedCostMicroUsd: 181,
      actionKinds: ['request_review'],
      alertIds: ['alert-1'],
      usage: { inputTokens: 800, cacheReadTokens: 100 },
      evidence: { complete: true, alertsScanned: 3, eventsScanned: 3 },
    });
    // Citas de los hechos: ids planos que coinciden con `citations[].id`.
    expect(detail!.result!.facts[0]!.citations).toEqual(['alert-1']);
    expect(detail!.result!.citations.map((citation) => citation.id)).toContain('alert-1');
    expect(detail!.actions[0]).toMatchObject({ kind: 'request_review', state: 'executed', ref: { kind: 'notification' } });
    expect(detail!.invocations[0]).toMatchObject({ tier: 'economy', state: 'settled', estimatedMicroUsd: 181 });
    // El modo con que corrió viaja en el DTO (la consola puede mostrarlo).
    expect(runDetailView(job, events, { invocations, actions }).mode).toBe('assisted');

    const page = normalizeRunPage(
      JSON.parse(JSON.stringify({ items: [runSummaryView(job, { invocations, actions })], nextCursor: 'abc' })),
    );
    expect(page.items[0]).toMatchObject({ id: ID, status: 'completed' });
    expect(page.nextCursor).toBe('abc');
  });

  it('ajustes, presupuesto, informe y resumen se leen en estricto', () => {
    const view = normalizeSettingsView(
      JSON.parse(JSON.stringify({ settings: settingsView(undefined, DEFAULT_ANALYST_SETTINGS), canConfigure: true })),
    );
    expect(view).toMatchObject({ canConfigure: true, settings: { revision: 0, enabled: false, mode: 'shadow' } });

    const budget = normalizeBudget(
      JSON.parse(
        JSON.stringify(
          budgetView({
            snapshot: {
              tenantId: 't1',
              day: '2026-11-14',
              limitMicroUsd: 2_000_000,
              reservedMicroUsd: 10,
              settledMicroUsd: 181,
              unknownCount: 0,
              unknownMicroUsd: 0,
              tokens: { input: 800, output: 200, cacheRead: 100, cacheWrite: 0 },
              runsToday: { none: 5, economy: 1, advanced: 0 },
            },
            settings: { ...DEFAULT_ANALYST_SETTINGS, enabled: true },
            deploymentEnabled: true,
            limitMicroUsd: 2_000_000,
            rateCardVersion: 'anthropic-list-2026-11-03-estimate',
          }),
        ),
      ),
    );
    expect(budget).toMatchObject({
      enabled: true,
      inferenceEnabled: true,
      day: { date: '2026-11-14', limitMicroUsd: 2_000_000, settledMicroUsd: 181 },
      runs: { today: 6, withoutInference: 5 },
      billing: 'not_connected',
    });

    const report = normalizeRunReport(reportView({ filename: `expediente-analista-${ID}.md`, markdown: '# x' }, AT), ID);
    expect(report).toMatchObject({ filename: `expediente-analista-${ID}.md`, generatedAt: AT.toISOString() });

    const digest = normalizeDigest(
      JSON.parse(JSON.stringify(digestView(buildDigest([job], actions, new Date(AT.getTime() - 1), new Date(AT.getTime() + 1))))),
    );
    expect(digest).toMatchObject({ totals: { runs: 1 }, topRules: [{ ruleId: '5716', count: 1 }] });
  });

  it('la consola tiene rótulo para cada motivo de acción del backend', () => {
    for (const code of ACTION_REASON_CODES) expect(actionReasonLabel(code)).not.toBeNull();
  });
});
