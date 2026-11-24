/**
 * Aprendizaje SOC · etapas D y E — superficie HTTP de patrones, decisiones y revisiones.
 *
 * Igual que el resto del BFF: la sesión se resuelve aquí, la autorización vive en el caso de uso y
 * las mutaciones exigen CSRF. Las lecturas exigen `learning.read`. Los motivos de separación de
 * funciones de una firma rechazada se devuelven a quien ya tiene la capability de aprobar: sin
 * ellos no sabría por qué no puede firmar.
 */

import { Body, Controller, Get, Inject, Param, Post, Query, Req } from '@nestjs/common';

import {
  approveLearningPattern,
  LEARNING_REVIEW_STATUSES,
  PATTERN_STATUSES,
  rejectLearningPattern,
  renewLearningPattern,
  resolveLearningReview,
  resumeLearningPattern,
  revertLearningDecision,
  revokeLearningPattern,
  type LearningDecisionRecord,
  type LearningPattern,
  type LearningReviewRecord,
  type LearningReviewStatus,
  type PatternDecisionRequest,
  type PatternStatus,
  type SocFailureCode,
  type SocResult,
} from '@b89/soc';

import type { IncomingRequest } from '../http/http-contracts.js';
import { ApiError, fromSocFailure } from '../http/api-error.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';
import { mutatingActor, readingActor } from './session-actor.js';
import { SECOPS_RUNTIME } from './tokens.js';

const LIST_LIMIT = 200;

/** Motivos que se explican a un aprobador autorizado (no revelan datos de otros tenants). */
const EXPLAINED_REASONS = new Set([
  'NOT_A_DESIGNATED_APPROVER',
  'SERVICE_IDENTITY',
  'APPROVER_IS_PROPOSER',
  'APPROVER_CLOSED_ORIGIN_ALERTS',
  'SAME_APPROVER_TWICE',
  'NOT_AWAITING_APPROVAL',
  'COMMENT_REQUIRED',
  'INVALID_TRANSITION',
  'PATTERN_EXPIRED',
  'OPEN_PATTERN_EXISTS',
  'REVIEW_RESOLVED',
  'NOT_ENGINE_CLOSED',
]);

function failureOf(
  result: { readonly code: SocFailureCode; readonly reason: string },
  correlationId: string,
): ApiError {
  if (EXPLAINED_REASONS.has(result.reason)) {
    return new ApiError(
      result.code === 'CONFLICT' ? 'STATE_CONFLICT' : 'VALIDATION_FAILED',
      correlationId,
      ['learning', result.reason],
    );
  }
  return fromSocFailure(result.code, correlationId);
}

export function patternView(pattern: LearningPattern) {
  return {
    id: pattern.id,
    ruleKey: pattern.ruleKey,
    fingerprint: pattern.fingerprint,
    normalizerVersion: pattern.normalizerVersion,
    level: pattern.level,
    maxAction: pattern.maxAction,
    closureReason: pattern.closureReason,
    status: pattern.status,
    proposedBy: pattern.proposedBy,
    ownerId: pattern.ownerId,
    originAlertIds: pattern.originAlertIds,
    originClosers: pattern.originClosers,
    evidence: {
      confirmations: pattern.confirmations,
      distinctAlerts: pattern.distinctAlerts,
      distinctDays: pattern.distinctDays,
      distinctAnalysts: pattern.distinctAnalysts,
      truePositiveSeen: pattern.truePositiveSeen,
      priorityCeiling: pattern.priorityCeiling,
    },
    readinessBlockers: pattern.readinessBlockers,
    createdAt: pattern.createdAt.toISOString(),
    updatedAt: pattern.updatedAt.toISOString(),
    activatedAt: pattern.activatedAt?.toISOString() ?? null,
    expiresAt: pattern.expiresAt?.toISOString() ?? null,
    renewalCount: pattern.renewalCount,
    revision: pattern.revision,
  };
}

function decisionView(decision: LearningDecisionRecord) {
  return { ...decision, at: decision.at.toISOString() };
}

function reviewView(review: LearningReviewRecord) {
  return {
    ...review,
    at: review.at.toISOString(),
    resolvedAt: review.resolvedAt?.toISOString() ?? null,
  };
}

interface DecisionBody {
  readonly expectedRevision?: number;
  readonly comment?: string;
}

@Controller('api')
export class LearningController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  private async reader(request: IncomingRequest) {
    const resolved = await readingActor(this.runtime, request);
    if (!resolved.actor.capabilities.has('learning.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', resolved.correlationId);
    }
    return resolved;
  }

  @Get('learning/readiness')
  public async readiness(@Req() request: IncomingRequest) {
    const { correlationId } = await this.reader(request);
    const snapshot = await this.runtime.learningReadiness();
    const context = this.runtime.learningEngineContext();
    return {
      correlationId,
      enabled: this.runtime.learningEnabled,
      gates: {
        closureReasonRequired: snapshot.closureReasonRequired,
        designatedApprovers: snapshot.designatedApprovers,
        closedAlertsWithoutOrigin: snapshot.closedAlertsWithoutOrigin,
        sourceCoverage: Object.fromEntries(snapshot.sourceCoverage),
        collidingRuleKeys: snapshot.collidingRuleKeys.size,
        currentNormalizerVersion: snapshot.currentNormalizerVersion,
      },
      engineContext: {
        criticalAssets: context.criticalAssets,
        privilegedIdentities: context.privilegedIdentities,
        changeCalendarAckUntil: context.changeCalendarAckUntil?.toISOString() ?? null,
        sourceState: context.sourceState,
        samplingConfigured: context.samplingKey !== null,
      },
    };
  }

  /** Salud del motor (meta-monitoreo): líder y administración (`observability.read_soc`). */
  @Get('learning/health')
  public async health(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    if (!actor.capabilities.has('observability.read_soc')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const { report, metrics } = await this.runtime.learningHealth();
    return {
      correlationId,
      status: report.status,
      alerts: report.alerts,
      metrics: {
        ...metrics,
        heartbeatAt: metrics.heartbeatAt?.toISOString() ?? null,
        backlog: {
          ...metrics.backlog,
          oldestPendingAt: metrics.backlog.oldestPendingAt?.toISOString() ?? null,
        },
      },
    };
  }

  @Get('learning/patterns')
  public async patterns(@Req() request: IncomingRequest, @Query('status') status?: string) {
    const { actor, correlationId } = await this.reader(request);
    if (status !== undefined && !(PATTERN_STATUSES as readonly string[]).includes(status)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['status']);
    }
    const result = (await this.runtime.soc.listLearningPatterns?.({
      tenantId: actor.tenantId,
      ...(status ? { status: status as PatternStatus } : {}),
      limit: LIST_LIMIT,
    })) ?? { items: [], total: 0 };
    return { correlationId, items: result.items.map(patternView), totalCount: result.total };
  }

  @Get('learning/patterns/:id')
  public async pattern(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await this.reader(request);
    const pattern = await this.runtime.soc.learningPatternById?.(actor.tenantId, id);
    if (!pattern) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const history = (await this.runtime.soc.learningPatternHistory?.(actor.tenantId, id)) ?? {
      approvals: [],
      events: [],
    };
    return {
      correlationId,
      pattern: patternView(pattern),
      approvals: history.approvals.map((row) => ({ ...row, at: row.at.toISOString() })),
      events: history.events.map((row) => ({ ...row, at: row.at.toISOString() })),
    };
  }

  private async decide(
    request: IncomingRequest,
    id: string,
    body: DecisionBody,
    action: (request: PatternDecisionRequest) => Promise<SocResult<LearningPattern>>,
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    if (typeof body.expectedRevision !== 'number' || typeof body.comment !== 'string') {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['expectedRevision', 'comment']);
    }
    const result = await action({
      actor,
      patternId: id,
      expectedRevision: body.expectedRevision,
      comment: body.comment,
      designatedApprovers: this.runtime.learningApprovers,
      correlationId,
    });
    if (!result.ok) throw failureOf(result, correlationId);
    return { correlationId, pattern: patternView(result.value) };
  }

  @Post('learning/patterns/:id/approve')
  public approve(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: DecisionBody,
  ) {
    return this.decide(request, id, body, (input) =>
      approveLearningPattern(this.runtime.socDependencies(), input),
    );
  }

  @Post('learning/patterns/:id/reject')
  public reject(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: DecisionBody,
  ) {
    return this.decide(request, id, body, (input) =>
      rejectLearningPattern(this.runtime.socDependencies(), input),
    );
  }

  @Post('learning/patterns/:id/revoke')
  public revoke(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: DecisionBody,
  ) {
    return this.decide(request, id, body, (input) =>
      revokeLearningPattern(this.runtime.socDependencies(), input),
    );
  }

  @Post('learning/patterns/:id/resume')
  public resume(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: DecisionBody,
  ) {
    return this.decide(request, id, body, (input) =>
      resumeLearningPattern(this.runtime.socDependencies(), input),
    );
  }

  @Post('learning/patterns/:id/renew')
  public renew(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: DecisionBody,
  ) {
    return this.decide(request, id, body, (input) =>
      renewLearningPattern(this.runtime.socDependencies(), input),
    );
  }

  @Get('learning/decisions')
  public async decisions(
    @Req() request: IncomingRequest,
    @Query('alertId') alertId?: string,
    @Query('patternId') patternId?: string,
  ) {
    const { actor, correlationId } = await this.reader(request);
    const result = (await this.runtime.soc.listLearningDecisions?.({
      tenantId: actor.tenantId,
      ...(alertId ? { alertId } : {}),
      ...(patternId ? { patternId } : {}),
      limit: LIST_LIMIT,
    })) ?? { items: [], total: 0 };
    return { correlationId, items: result.items.map(decisionView), totalCount: result.total };
  }

  @Post('learning/decisions/:id/revert')
  public async revert(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: { readonly reason?: string },
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    if (typeof body.reason !== 'string')
      throw new ApiError('VALIDATION_FAILED', correlationId, ['reason']);
    const result = await revertLearningDecision(this.runtime.socDependencies(), {
      actor,
      decisionId: id,
      reason: body.reason,
      correlationId,
    });
    if (!result.ok) throw failureOf(result, correlationId);
    this.runtime.dispatcher.kick();
    return { correlationId, ...result.value };
  }

  @Get('learning/reviews')
  public async reviews(@Req() request: IncomingRequest, @Query('status') status?: string) {
    const { actor, correlationId } = await this.reader(request);
    if (status !== undefined && !(LEARNING_REVIEW_STATUSES as readonly string[]).includes(status)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['status']);
    }
    const result = (await this.runtime.soc.listLearningReviews?.({
      tenantId: actor.tenantId,
      ...(status ? { status: status as LearningReviewStatus } : {}),
      limit: LIST_LIMIT,
    })) ?? { items: [], total: 0 };
    return { correlationId, items: result.items.map(reviewView), totalCount: result.total };
  }

  @Post('learning/reviews/:id/resolve')
  public async resolve(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body()
    body: {
      readonly expectedRevision?: number;
      readonly outcome?: string;
      readonly truePositive?: boolean;
      readonly comment?: string;
    },
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    if (
      typeof body.expectedRevision !== 'number' ||
      (body.outcome !== 'agree' && body.outcome !== 'disagree') ||
      typeof body.comment !== 'string'
    ) {
      throw new ApiError('VALIDATION_FAILED', correlationId, [
        'expectedRevision',
        'outcome',
        'comment',
      ]);
    }
    const result = await resolveLearningReview(this.runtime.socDependencies(), {
      actor,
      reviewId: id,
      expectedRevision: body.expectedRevision,
      outcome: body.outcome,
      truePositive: body.truePositive === true,
      comment: body.comment,
      correlationId,
    });
    if (!result.ok) throw failureOf(result, correlationId);
    this.runtime.dispatcher.kick();
    return { correlationId, review: reviewView(result.value) };
  }
}
