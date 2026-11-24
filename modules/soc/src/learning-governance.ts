/**
 * Aprendizaje SOC · fase 3 — habilitación en dos capas y contexto en base.
 *
 * - **Habilitación por regla y tenant** (capa 2): una persona designada la pide (modo `dry_run` o
 *   `active`, motivo y vencimiento ≤ 90 días) y OTRA persona designada la aprueba. El modo efectivo
 *   de una regla es el mínimo del techo del entorno (capa 1), de `B89_LEARNING_ACTIVE_RULES` y de la
 *   habilitación aprobada y vigente; sin ella, la regla queda en sombra. Las reglas de alto impacto
 *   no se pueden pedir.
 * - **Contexto** (activos críticos, identidades privilegiadas, break-glass, confirmación del
 *   calendario de cambios, reglas que nunca se suprimen): entradas aditivas con vencimiento, que se
 *   suman a las listas del entorno. Si falta o vence, el motor escala (`GUARD_CONTEXT`).
 *
 * Nada se borra: se revoca o vence. Todo queda auditado.
 */

import { authorize, type Actor } from '@b89/access';
import { recordAudit } from '@b89/audit';
import { isHighImpactRuleKey } from '@b89/detection';

import type { SocTransactionContext } from './ports.js';
import { socAuditDraft, socFailure, type SocDependencies, type SocResult } from './use-cases.js';

const DAY = 24 * 60 * 60 * 1000;
const RULE_KEY = /^[a-z][a-z0-9-]*:[A-Za-z0-9._:-]{1,128}$/u;

export const ENABLEMENT_MODES = ['dry_run', 'active'] as const;
export type EnablementMode = (typeof ENABLEMENT_MODES)[number];
export const ENABLEMENT_STATUSES = ['pending', 'approved', 'revoked'] as const;
export type EnablementStatus = (typeof ENABLEMENT_STATUSES)[number];

export interface RuleEnablement {
  readonly id: string;
  readonly tenantId: string;
  readonly ruleKey: string;
  readonly mode: EnablementMode;
  readonly status: EnablementStatus;
  readonly reason: string;
  readonly requestedBy: string;
  readonly requestedAt: Date;
  readonly approvedBy: string | null;
  readonly approvedAt: Date | null;
  readonly expiresAt: Date;
  readonly revokedBy: string | null;
  readonly revokedAt: Date | null;
  readonly revision: number;
}

export const CONTEXT_KINDS = [
  'critical_asset',
  'privileged_identity',
  'break_glass',
  'change_calendar_ack',
  'never_suppress_rule',
] as const;
export type ContextKind = (typeof CONTEXT_KINDS)[number];

export interface ContextEntry {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: ContextKind;
  readonly value: string;
  readonly reason: string;
  readonly createdBy: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly revokedBy: string | null;
  readonly revokedAt: Date | null;
  readonly revision: number;
}

/** Dentro de la unidad de trabajo. `insert*` es `false` si choca con una abierta. */
export interface LearningGovernanceStore {
  enablementById(tenantId: string, id: string): Promise<RuleEnablement | undefined>;
  insertEnablement(row: RuleEnablement): Promise<boolean>;
  updateEnablement(row: RuleEnablement, expectedRevision: number): Promise<boolean>;
  contextById(tenantId: string, id: string): Promise<ContextEntry | undefined>;
  insertContext(row: ContextEntry): Promise<void>;
  updateContext(row: ContextEntry, expectedRevision: number): Promise<boolean>;
}

/* ------------------------------------------------------------ Lectura pura */

/** Habilitaciones aprobadas y vigentes según el reloj del servidor. */
export function ruleModesFrom(
  rows: readonly RuleEnablement[],
  now: Date,
): ReadonlyMap<string, EnablementMode> {
  const modes = new Map<string, EnablementMode>();
  for (const row of rows) {
    if (row.status !== 'approved' || row.expiresAt.getTime() <= now.getTime()) continue;
    if (isHighImpactRuleKey(row.ruleKey)) continue;
    modes.set(row.ruleKey, row.mode);
  }
  return modes;
}

export interface LiveContext {
  readonly criticalAssets: ReadonlySet<string>;
  readonly privilegedIdentities: ReadonlySet<string>;
  readonly breakGlass: ReadonlySet<string>;
  readonly neverSuppressRules: ReadonlySet<string>;
  readonly changeCalendarAckUntil: Date | null;
}

export function liveContextFrom(rows: readonly ContextEntry[], now: Date): LiveContext {
  const live = rows.filter(
    (row) => row.revokedAt === null && row.expiresAt.getTime() > now.getTime(),
  );
  const values = (kind: ContextKind) =>
    new Set(live.filter((row) => row.kind === kind).map((row) => row.value.trim().toLowerCase()));
  const acks = live
    .filter((row) => row.kind === 'change_calendar_ack')
    .map((row) => row.expiresAt.getTime());
  return {
    criticalAssets: values('critical_asset'),
    privilegedIdentities: values('privileged_identity'),
    breakGlass: values('break_glass'),
    neverSuppressRules: new Set(
      live.filter((row) => row.kind === 'never_suppress_rule').map((row) => row.value.trim()),
    ),
    changeCalendarAckUntil: acks.length === 0 ? null : new Date(Math.max(...acks)),
  };
}

/* ------------------------------------------------------------ Casos de uso */

interface Governed {
  readonly actor: Actor;
  readonly designatedApprovers: readonly string[];
  readonly correlationId: string;
}

async function guard(
  dependencies: SocDependencies,
  context: SocTransactionContext,
  request: Governed,
  action: string,
  resource: { readonly type: string; readonly id: string },
  at: Date,
): Promise<string | undefined> {
  const decision = authorize({
    actor: request.actor,
    capability: 'learning.patterns.approve',
    resource: { ...resource, tenantId: request.actor.tenantId },
  });
  const subject = request.actor.subjectId;
  const problem = !decision.allowed
    ? decision.reason
    : subject.startsWith('svc:')
      ? 'SERVICE_IDENTITY'
      : !request.designatedApprovers.includes(subject)
        ? 'NOT_A_DESIGNATED_APPROVER'
        : undefined;
  if (problem) {
    await recordAudit(
      context.audit,
      socAuditDraft({
        id: dependencies.ids.next(),
        actor: request.actor,
        action,
        resource,
        outcome: 'denied',
        correlationId: request.correlationId,
        at,
        reason: problem,
      }),
    );
  }
  return problem;
}

async function audited(
  dependencies: SocDependencies,
  context: SocTransactionContext,
  request: Governed,
  action: string,
  resource: { readonly type: string; readonly id: string },
  at: Date,
  metadata: Readonly<Record<string, string | number | boolean>>,
): Promise<void> {
  await recordAudit(
    context.audit,
    socAuditDraft({
      id: dependencies.ids.next(),
      actor: request.actor,
      action,
      resource,
      outcome: 'succeeded',
      correlationId: request.correlationId,
      at,
      metadata,
    }),
  );
}

export async function requestRuleEnablement(
  dependencies: SocDependencies,
  request: Governed & {
    readonly ruleKey: string;
    readonly mode: EnablementMode;
    readonly reason: string;
    readonly expiresInDays: number;
  },
): Promise<SocResult<RuleEnablement>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const resource = { type: 'learning_enablement', id: request.ruleKey };
    const problem = await guard(
      dependencies,
      context,
      request,
      'learning.enablement.request',
      resource,
      now,
    );
    if (problem) return socFailure('FORBIDDEN', problem, problem);
    if (
      !RULE_KEY.test(request.ruleKey) ||
      !(ENABLEMENT_MODES as readonly string[]).includes(request.mode)
    ) {
      return socFailure('INVALID_COMMAND', 'ENABLEMENT_INVALID', 'Regla o modo no válidos.');
    }
    if (isHighImpactRuleKey(request.ruleKey)) {
      return socFailure(
        'INVALID_COMMAND',
        'IMPACT_FLOOR',
        'Una regla de alto impacto no se habilita.',
      );
    }
    const reason = request.reason.trim();
    const days = Math.floor(request.expiresInDays);
    if (reason.length < 10 || days < 1 || days > 90) {
      return socFailure(
        'INVALID_COMMAND',
        'ENABLEMENT_INVALID',
        'Motivo (≥ 10) y vencimiento (1–90 días).',
      );
    }
    const row: RuleEnablement = {
      id: dependencies.ids.next(),
      tenantId: request.actor.tenantId,
      ruleKey: request.ruleKey,
      mode: request.mode,
      status: 'pending',
      reason,
      requestedBy: request.actor.subjectId,
      requestedAt: now,
      approvedBy: null,
      approvedAt: null,
      expiresAt: new Date(now.getTime() + days * DAY),
      revokedBy: null,
      revokedAt: null,
      revision: 1,
    };
    if (!(await context.learningGovernance.insertEnablement(row))) {
      return socFailure(
        'CONFLICT',
        'OPEN_ENABLEMENT_EXISTS',
        'Ya hay una habilitación abierta para la regla.',
      );
    }
    await audited(
      dependencies,
      context,
      request,
      'learning.enablement.request',
      { type: 'learning_enablement', id: row.id },
      now,
      {
        ruleKey: row.ruleKey,
        mode: row.mode,
        expiresInDays: days,
      },
    );
    return { ok: true as const, value: row };
  });
}

export async function approveRuleEnablement(
  dependencies: SocDependencies,
  request: Governed & { readonly id: string; readonly expectedRevision: number },
): Promise<SocResult<RuleEnablement>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const resource = { type: 'learning_enablement', id: request.id };
    const problem = await guard(
      dependencies,
      context,
      request,
      'learning.enablement.approve',
      resource,
      now,
    );
    if (problem) return socFailure('FORBIDDEN', problem, problem);
    const row = await context.learningGovernance.enablementById(request.actor.tenantId, request.id);
    if (!row) return socFailure('NOT_FOUND', 'ENABLEMENT_NOT_FOUND', 'La habilitación no existe.');
    if (row.revision !== request.expectedRevision) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'La habilitación cambió.');
    }
    if (row.status !== 'pending')
      return socFailure('INVALID_COMMAND', 'NOT_AWAITING_APPROVAL', 'No está pendiente.');
    if (row.requestedBy === request.actor.subjectId) {
      return socFailure('FORBIDDEN', 'SAME_APPROVER_TWICE', 'Quien pidió no puede aprobar.');
    }
    if (row.expiresAt.getTime() <= now.getTime()) {
      return socFailure('INVALID_COMMAND', 'ENABLEMENT_EXPIRED', 'La habilitación ya venció.');
    }
    const next: RuleEnablement = {
      ...row,
      status: 'approved',
      approvedBy: request.actor.subjectId,
      approvedAt: now,
      revision: row.revision + 1,
    };
    if (!(await context.learningGovernance.updateEnablement(next, row.revision))) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó la habilitación.');
    }
    await audited(dependencies, context, request, 'learning.enablement.approve', resource, now, {
      ruleKey: row.ruleKey,
      mode: row.mode,
    });
    return { ok: true as const, value: next };
  });
}

export async function revokeRuleEnablement(
  dependencies: SocDependencies,
  request: Governed & { readonly id: string; readonly expectedRevision: number },
): Promise<SocResult<RuleEnablement>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const resource = { type: 'learning_enablement', id: request.id };
    const problem = await guard(
      dependencies,
      context,
      request,
      'learning.enablement.revoke',
      resource,
      now,
    );
    if (problem) return socFailure('FORBIDDEN', problem, problem);
    const row = await context.learningGovernance.enablementById(request.actor.tenantId, request.id);
    if (!row) return socFailure('NOT_FOUND', 'ENABLEMENT_NOT_FOUND', 'La habilitación no existe.');
    if (row.status === 'revoked')
      return socFailure('INVALID_COMMAND', 'INVALID_TRANSITION', 'Ya está revocada.');
    if (row.revision !== request.expectedRevision)
      return socFailure('CONFLICT', 'REVISION_STALE', 'Cambió.');
    const next: RuleEnablement = {
      ...row,
      status: 'revoked',
      revokedBy: request.actor.subjectId,
      revokedAt: now,
      revision: row.revision + 1,
    };
    if (!(await context.learningGovernance.updateEnablement(next, row.revision))) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó la habilitación.');
    }
    await audited(dependencies, context, request, 'learning.enablement.revoke', resource, now, {
      ruleKey: row.ruleKey,
    });
    return { ok: true as const, value: next };
  });
}

export async function addContextEntry(
  dependencies: SocDependencies,
  request: Governed & {
    readonly kind: ContextKind;
    readonly value: string;
    readonly reason: string;
    readonly expiresInDays: number;
  },
): Promise<SocResult<ContextEntry>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const resource = { type: 'learning_context', id: request.kind };
    const problem = await guard(
      dependencies,
      context,
      request,
      'learning.context.add',
      resource,
      now,
    );
    if (problem) return socFailure('FORBIDDEN', problem, problem);
    const value = request.value.trim();
    const reason = request.reason.trim();
    const days = Math.floor(request.expiresInDays);
    const maxDays = request.kind === 'change_calendar_ack' ? 30 : 90;
    if (
      !(CONTEXT_KINDS as readonly string[]).includes(request.kind) ||
      value.length < 1 ||
      value.length > 256 ||
      reason.length < 10 ||
      days < 1 ||
      days > maxDays ||
      (request.kind === 'never_suppress_rule' && !RULE_KEY.test(value))
    ) {
      return socFailure(
        'INVALID_COMMAND',
        'CONTEXT_INVALID',
        `Entrada no válida (vencimiento 1–${maxDays} días).`,
      );
    }
    const row: ContextEntry = {
      id: dependencies.ids.next(),
      tenantId: request.actor.tenantId,
      kind: request.kind,
      value,
      reason,
      createdBy: request.actor.subjectId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + days * DAY),
      revokedBy: null,
      revokedAt: null,
      revision: 1,
    };
    await context.learningGovernance.insertContext(row);
    // La auditoría registra el tipo, no el valor (puede ser una identidad).
    await audited(
      dependencies,
      context,
      request,
      'learning.context.add',
      { type: 'learning_context', id: row.id },
      now,
      {
        kind: row.kind,
        expiresInDays: days,
      },
    );
    return { ok: true as const, value: row };
  });
}

export async function revokeContextEntry(
  dependencies: SocDependencies,
  request: Governed & { readonly id: string; readonly expectedRevision: number },
): Promise<SocResult<ContextEntry>> {
  const now = dependencies.clock.now();
  return dependencies.unitOfWork.run(async (context) => {
    const resource = { type: 'learning_context', id: request.id };
    const problem = await guard(
      dependencies,
      context,
      request,
      'learning.context.revoke',
      resource,
      now,
    );
    if (problem) return socFailure('FORBIDDEN', problem, problem);
    const row = await context.learningGovernance.contextById(request.actor.tenantId, request.id);
    if (!row) return socFailure('NOT_FOUND', 'CONTEXT_NOT_FOUND', 'La entrada no existe.');
    if (row.revokedAt !== null)
      return socFailure('INVALID_COMMAND', 'INVALID_TRANSITION', 'Ya está revocada.');
    if (row.revision !== request.expectedRevision)
      return socFailure('CONFLICT', 'REVISION_STALE', 'Cambió.');
    const next: ContextEntry = {
      ...row,
      revokedBy: request.actor.subjectId,
      revokedAt: now,
      revision: row.revision + 1,
    };
    if (!(await context.learningGovernance.updateContext(next, row.revision))) {
      return socFailure('CONFLICT', 'REVISION_STALE', 'Otra escritura modificó la entrada.');
    }
    await audited(dependencies, context, request, 'learning.context.revoke', resource, now, {
      kind: row.kind,
    });
    return { ok: true as const, value: next };
  });
}
