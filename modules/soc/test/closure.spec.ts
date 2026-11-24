import { beforeEach, describe, expect, it } from 'vitest';

import { capabilitiesForRoles, type Actor } from '@b89/access';
import type { DetectionCandidate } from '@b89/detection';

import { applyAlertCommand, createAlert, type Alert, type TriageVerdict } from '../src/alert.js';
import {
  CLOSURE_REASON_VERDICTS,
  CLOSURE_REASONS,
  closureOriginFor,
  validateClosure,
  type ClosureInput,
} from '../src/closure.js';
import { InMemorySoc } from '../src/memory-unit-of-work.js';
import { executeAlertCommand, ingestCandidate, type SocDependencies } from '../src/use-cases.js';

const AT = new Date('2026-11-24T09:00:00.000Z');

const LEGIT: ClosureInput = {
  reason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
  justification: {
    evidenceType: 'scheduled_job',
    statement: 'Tarea programada de respaldo documentada en el runbook de backups.',
    legitimacyField: 'process.image',
    legitimacyValue: 'c:\\program files\\veeam\\agent.exe',
  },
  evidenceRefs: [{ kind: 'ticket', ref: 'CHG-1042' }],
};

function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    ...createAlert({
      id: 'alert-1',
      tenantId: 'tenant-1',
      candidateId: 'cand-1',
      eventRecordId: 'rec-1',
      title: 'Proceso sospechoso',
      priority: 'P4',
      score: 30,
      reasons: [],
      occurredAt: AT,
      createdAt: AT,
    }),
    ...overrides,
  };
}

function triaged(verdict: TriageVerdict): Alert {
  return alert({ status: 'triaged', verdict, assigneeId: 'analyst-1', triageNote: 'nota previa' });
}

function close(target: Alert, extra: Record<string, unknown> = {}, actorId = 'analyst-1') {
  return applyAlertCommand(target, {
    name: 'close',
    actorId,
    at: AT,
    expectedRevision: target.revision,
    ...extra,
  } as Parameters<typeof applyAlertCommand>[1]);
}

describe('Aprendizaje SOC · etapa A · catálogo de cierre', () => {
  it('cada motivo del catálogo tiene al menos un veredicto compatible', () => {
    for (const reason of CLOSURE_REASONS) {
      expect(CLOSURE_REASON_VERDICTS[reason].length).toBeGreaterThan(0);
    }
  });

  it('el origen sale del actor, nunca del cliente', () => {
    expect(closureOriginFor('analyst-1')).toBe('human');
    expect(closureOriginFor('svc:b89-ai-analyst')).toBe('ai_analyst');
    expect(closureOriginFor('svc:b89-detection-engineering')).toBe('bulk_script');
    expect(closureOriginFor('svc:b89-soc-learning')).toBe('learning_engine');
    expect(closureOriginFor('svc:otro')).toBe('service_other');
  });

  it('acepta un cierre completo y lo normaliza', () => {
    const result = validateClosure({
      ...LEGIT,
      justification: { ...LEGIT.justification, statement: `  ${LEGIT.justification.statement}  ` },
    });
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.closure.justification.statement).toBe(LEGIT.justification.statement);
  });

  it.each([
    ['sin motivo', { ...LEGIT, reason: undefined }, 'CLOSURE_REASON_REQUIRED'],
    ['motivo fuera del catálogo', { ...LEGIT, reason: 'FP_PORQUE_SI' }, 'CLOSURE_REASON_REQUIRED'],
    ['sin justificación', { ...LEGIT, justification: undefined }, 'CLOSURE_INVALID'],
    [
      'justificación corta',
      { ...LEGIT, justification: { ...LEGIT.justification, statement: 'ok' } },
      'CLOSURE_INVALID',
    ],
    ['sin evidencia', { ...LEGIT, evidenceRefs: [] }, 'CLOSURE_INVALID'],
    [
      'evidencia con control',
      { ...LEGIT, evidenceRefs: [{ kind: 'ticket', ref: 'CHG\u0000' }] },
      'CLOSURE_INVALID',
    ],
    [
      'actividad legítima sin dato de legitimidad',
      {
        ...LEGIT,
        justification: { evidenceType: 'scheduled_job', statement: LEGIT.justification.statement },
      },
      'CLOSURE_INVALID',
    ],
    [
      'duplicada sin la original',
      { ...LEGIT, reason: 'DUPLICADA', evidenceRefs: [{ kind: 'ticket', ref: 'X-1' }] },
      'CLOSURE_INVALID',
    ],
    [
      'pentest sin ticket',
      {
        ...LEGIT,
        reason: 'TP_BENIGNO_PRUEBA_O_PENTEST',
        evidenceRefs: [{ kind: 'alert', ref: 'a-1' }],
      },
      'CLOSURE_INVALID',
    ],
  ])('rechaza %s', (_label, input, code) => {
    const result = validateClosure(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(code);
  });
});

describe('Aprendizaje SOC · etapa A · cierre de la alerta', () => {
  it('cierra con motivo, origen humano, quién y cuándo', () => {
    const result = close(triaged('false_positive'), { closure: LEGIT });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.alert).toMatchObject({
      status: 'closed',
      verdict: 'false_positive',
      closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
      closureOrigin: 'human',
      closedBy: 'analyst-1',
      closedAt: AT,
      triageNote: 'nota previa',
    });
  });

  it('marca como ai_analyst el cierre del Analista IA', () => {
    const result = close(triaged('false_positive'), { closure: LEGIT }, 'svc:b89-ai-analyst');
    expect(result.ok && result.alert.closureOrigin).toBe('ai_analyst');
  });

  it('rechaza un motivo que no corresponde al veredicto', () => {
    const result = close(triaged('true_positive'), { closure: LEGIT });
    expect(result).toMatchObject({ ok: false, code: 'CLOSURE_VERDICT_MISMATCH' });
  });

  it('sin triaje solo cierra una duplicada, y la etiqueta como duplicate', () => {
    const acknowledged = alert({ status: 'acknowledged', assigneeId: 'analyst-1' });
    expect(close(acknowledged, { closure: LEGIT })).toMatchObject({
      ok: false,
      code: 'CLOSURE_REQUIRES_TRIAGE',
    });
    const duplicate = close(acknowledged, {
      closure: {
        reason: 'DUPLICADA',
        justification: {
          evidenceType: 'other',
          statement: 'Misma detección que la alerta original.',
        },
        evidenceRefs: [{ kind: 'alert', ref: 'alert-0' }],
      },
    });
    expect(duplicate).toMatchObject({
      ok: true,
      alert: { verdict: 'duplicate', closureReason: 'DUPLICADA' },
    });
  });

  it('con la política activa rechaza el cierre sin motivo', () => {
    const result = close(triaged('false_positive'), { closureReasonRequired: true });
    expect(result).toMatchObject({ ok: false, code: 'CLOSURE_REASON_REQUIRED' });
  });

  it('sin política acepta el cierre heredado, sin motivo pero con origen', () => {
    const result = close(triaged('false_positive'));
    expect(result).toMatchObject({
      ok: true,
      alert: { closureReason: null, closureOrigin: 'human', closedBy: 'analyst-1' },
    });
  });

  it('reabrir limpia el cierre vigente y conserva el veredicto', () => {
    const closed = close(triaged('false_positive'), { closure: LEGIT });
    if (!closed.ok) throw new Error('setup');
    const reopened = applyAlertCommand(closed.alert, {
      name: 'reopen',
      actorId: 'analyst-2',
      at: AT,
      expectedRevision: closed.alert.revision,
    });
    expect(reopened).toMatchObject({
      ok: true,
      alert: {
        status: 'acknowledged',
        verdict: 'false_positive',
        closureReason: null,
        closureOrigin: null,
        closedBy: null,
        closedAt: null,
      },
    });
  });
});

describe('Aprendizaje SOC · etapa A · bitácora y estadísticas', () => {
  let soc: InMemorySoc;
  let sequence: number;
  let dependencies: SocDependencies;

  const CANDIDATE: DetectionCandidate = {
    id: '0199bf11-0000-7000-8000-0000000000b1',
    tenantId: 'tenant-1',
    eventRecordId: '01890f47-7abc-7def-8abc-0123456789cd',
    eventUid: 'evt-1',
    idempotencyKey: 'key-closure-1',
    priority: 'P4',
    score: 30,
    reasons: [],
    rulesetId: 'b89.detection.prioritization',
    rulesetVersion: '1.1.0',
    occurredAt: AT,
    createdAt: AT,
    title: 'Proceso sospechoso',
    entityKeys: ['user:ana@b89.example'],
    signal: 'other',
    ruleId: '100100',
    relatedAlertIds: [],
  };

  function actorOf(subjectId: string): Actor {
    return {
      subjectId,
      tenantId: 'tenant-1',
      sessionId: 'sess-1',
      roles: ['b89.soc.analyst'],
      capabilities: capabilitiesForRoles(['b89.soc.analyst']),
    };
  }

  async function triageAndClose(subjectId: string, closure?: ClosureInput) {
    const actor = actorOf(subjectId);
    const run = async (command: Parameters<typeof executeAlertCommand>[1]['command']) => {
      const result = await executeAlertCommand(dependencies, {
        actor,
        alertId: CANDIDATE.id,
        correlationId: 'corr',
        command,
        decisionGroupId: '0199bf33-0000-7000-8000-000000000001',
      });
      if (!result.ok) throw new Error(`${command.name}:${result.reason}`);
      return result.value;
    };
    let current = await run({ name: 'acknowledge', expectedRevision: 1 });
    current = await run({
      name: 'triage',
      verdict: 'false_positive',
      note: 'Proceso de backup conocido.',
      expectedRevision: current.revision,
    });
    return run({
      name: 'close',
      expectedRevision: current.revision,
      ...(closure ? { closure } : {}),
    });
  }

  beforeEach(async () => {
    soc = new InMemorySoc();
    sequence = 0;
    dependencies = {
      unitOfWork: soc,
      clock: { now: () => AT },
      ids: {
        next: () => {
          sequence += 1;
          return `0199bf22-0000-7000-8000-${sequence.toString().padStart(12, '0')}`;
        },
      },
      entityRefs: (_tenant, key) => `ent_${key.length}`,
    };
    await ingestCandidate(dependencies, CANDIDATE);
  });

  it('cada cierre deja una fila append-only con motivo, origen y grupo de decisión', async () => {
    await triageAndClose('analyst-1', LEGIT);
    expect(soc.closureRows).toHaveLength(1);
    expect(soc.closureRows[0]).toMatchObject({
      kind: 'close',
      alertId: CANDIDATE.id,
      verdict: 'false_positive',
      closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
      origin: 'human',
      actorId: 'analyst-1',
      decisionGroupId: '0199bf33-0000-7000-8000-000000000001',
      evidenceRefs: [{ kind: 'ticket', ref: 'CHG-1042' }],
    });
    const audit = await soc.allAudit();
    expect(audit.at(-1)?.metadata).toMatchObject({
      closureReason: 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
      closureOrigin: 'human',
    });
  });

  it('una política que rechaza el cierre no deja fila en la bitácora', async () => {
    dependencies = { ...dependencies, closurePolicy: { reasonRequired: true } };
    await expect(triageAndClose('analyst-1')).rejects.toThrow('CLOSURE_REASON_REQUIRED');
    expect(soc.closureRows).toHaveLength(0);
  });

  it('el historial de FP solo cuenta cierres humanos (sin autorrefuerzo)', async () => {
    await triageAndClose('svc:b89-ai-analyst', LEGIT);
    const ref = `ent_${'user:ana@b89.example'.length}`;
    const byAi = await soc.alertStats({ tenantId: 'tenant-1', entityRef: ref });
    expect(byAi.falsePositive).toBe(0);
    const withAi = await soc.alertStats({
      tenantId: 'tenant-1',
      entityRef: ref,
      falsePositiveOrigins: ['human', 'ai_analyst'],
    });
    expect(withAi.falsePositive).toBe(1);
  });
});
