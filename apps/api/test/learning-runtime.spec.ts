/**
 * Aprendizaje SOC · fase 2 — cableado real del API: con `B89_LEARNING_ENABLED=true` (sombra por
 * defecto) la ingesta solo encola, el worker decide fuera de ella y la salud lo refleja.
 */

import { afterEach, describe, expect, it } from 'vitest';

import {
  candidateId,
  FINGERPRINT_COMPONENTS,
  promotionKey,
  type DetectionCandidate,
  type FingerprintComponents,
} from '@b89/detection';
import { capabilitiesForRoles } from '@b89/access';
import { approveRuleEnablement, ingestCandidate, requestRuleEnablement } from '@b89/soc';

import { buildApi } from '../src/bootstrap.js';

let stop: (() => Promise<void>) | undefined;

afterEach(async () => {
  await stop?.();
  stop = undefined;
});

function candidate(tenantId: string, sequence: number): DetectionCandidate {
  const eventRecordId = `0199ea00-0000-7000-8000-${String(sequence).padStart(12, '0')}`;
  const occurredAt = new Date();
  const key = promotionKey(tenantId, eventRecordId, '1.1.0');
  const components = {
    ...(Object.fromEntries(FINGERPRINT_COMPONENTS.map((name) => [name, null])) as Record<
      string,
      null
    >),
    ruleKey: 'linux-process:100200',
    user: 'svc-backup',
  } as FingerprintComponents;
  return {
    id: candidateId(key, occurredAt),
    tenantId,
    eventRecordId,
    eventUid: `evt-${sequence}`,
    idempotencyKey: key,
    priority: 'P4',
    score: 20,
    reasons: [{ code: 'BASE_SEVERITY', delta: 20, detail: 'low' }],
    rulesetId: 'b89.detection.prioritization',
    rulesetVersion: '1.1.0',
    occurredAt,
    createdAt: occurredAt,
    title: 'Tarea programada',
    entityKeys: [],
    signal: 'other',
    ruleId: '100200',
    relatedAlertIds: [],
    fingerprint: {
      fingerprint: `fp1_${'a'.repeat(64)}`,
      level: 'fine',
      version: '1',
      normalizerVersion: '2',
      ruleKey: 'linux-process:100200',
      components,
    },
    guardSignals: { severity: 'low', mitreTactics: [], threatIntelHit: false },
  };
}

describe('fase 2 · motor en el API', () => {
  it('apagado (por defecto): no encola, no decide y la salud dice OFF', async () => {
    const built = await buildApi({ B89_PROFILE: 'test' }, () => {});
    stop = built.stop;
    const { runtime } = built;
    expect(runtime.learningEnabled).toBe(false);
    const result = await ingestCandidate(runtime.socDependencies(), candidate(runtime.tenantId, 1));
    expect(result.ok).toBe(true);
    expect(await runtime.drainLearning()).toEqual({ claimed: 0, done: 0, retried: 0, dead: 0 });
    expect((await runtime.learningHealth()).report.status).toBe('OFF');
  });

  it('encendido en sombra: la ingesta encola, el worker decide sin efectos y deja latido', async () => {
    const built = await buildApi({ B89_PROFILE: 'test', B89_LEARNING_ENABLED: 'true' }, () => {});
    stop = built.stop;
    const { runtime } = built;
    const created = await ingestCandidate(
      runtime.socDependencies(),
      candidate(runtime.tenantId, 2),
    );
    if (!created.ok) throw new Error(created.code);
    // Antes del worker, la alerta existe y nadie la decidió todavía.
    expect(created.value.alert.status).toBe('new');
    const summary = await runtime.drainLearning();
    expect(summary).toMatchObject({ claimed: 1, done: 1 });
    const alert = await runtime.soc.alertById(runtime.tenantId, created.value.alert.id);
    expect(alert?.status).toBe('new');
    const decisions = await runtime.soc.listLearningDecisions?.({
      tenantId: runtime.tenantId,
      alertId: created.value.alert.id,
      limit: 5,
    });
    expect(decisions?.items[0]).toMatchObject({ mode: 'shadow', appliedAction: 'NONE' });
    const { report, metrics } = await runtime.learningHealth();
    expect(metrics.heartbeatAt).not.toBeNull();
    expect(metrics.backlog.pending).toBe(0);
    // Sin listas de contexto ni fuente medida, la salud lo avisa (y el motor escala todo).
    expect(report.alerts.map((item) => item.id)).toContain('SOURCE_NOT_HEALTHY');
  });
});

describe('fase 3 · piso de impacto al arrancar', () => {
  it('el API no arranca si se habilita una regla de alto impacto', async () => {
    await expect(
      buildApi(
        {
          B89_PROFILE: 'test',
          B89_LEARNING_ENABLED: 'true',
          B89_LEARNING_MAX_MODE: 'active',
          B89_LEARNING_ACTIVE_RULES: 'cloudflare:102001',
        },
        () => {},
      ),
    ).rejects.toThrow(/alto impacto/u);
  });
});

describe('fase 3 · sin canal de notificación el motor no pasa de sombra', () => {
  it('se pide activo sin Teams: queda en sombra y la salud lo marca crítico', async () => {
    const built = await buildApi(
      {
        B89_PROFILE: 'test',
        B89_LEARNING_ENABLED: 'true',
        B89_LEARNING_MAX_MODE: 'active',
        B89_LEARNING_ACTIVE_RULES: 'linux-process:100200',
      },
      () => {},
    );
    stop = built.stop;
    const { report, metrics } = await built.runtime.learningHealth();
    expect(metrics.maxMode).toBe('shadow');
    expect(report.alerts.map((alert) => alert.id)).toContain('NOTIFICATION_CHANNEL_MISSING');
  });
});

describe('fase 3 · habilitación en dos capas en el API', () => {
  it('la regla en el entorno no basta: sin habilitación aprobada en base, sombra; con ella, dry_run', async () => {
    const built = await buildApi(
      {
        B89_PROFILE: 'test',
        B89_LEARNING_ENABLED: 'true',
        B89_LEARNING_MAX_MODE: 'dry_run',
        B89_LEARNING_ACTIVE_RULES: 'linux-process:100200',
        B89_LEARNING_SAMPLING_KEY: 'k'.repeat(40),
        B89_TEAMS_WORKFLOW_URL:
          'https://prod-00.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke',
        B89_SOC_LEARNING_APPROVERS: 'lead-a,lead-b',
      },
      () => {},
    );
    stop = built.stop;
    const { runtime } = built;
    const decide = async (sequence: number) => {
      const created = await ingestCandidate(
        runtime.socDependencies(),
        candidate(runtime.tenantId, sequence),
      );
      if (!created.ok) throw new Error(created.code);
      await runtime.drainLearning();
      const decisions = await runtime.soc.listLearningDecisions?.({
        tenantId: runtime.tenantId,
        alertId: created.value.alert.id,
        limit: 1,
      });
      return decisions?.items[0];
    };
    expect((await decide(10))?.mode).toBe('shadow');
    const lead = (subjectId: string) => ({
      subjectId,
      tenantId: runtime.tenantId,
      sessionId: 's',
      roles: ['b89.soc.lead'],
      capabilities: capabilitiesForRoles(['b89.soc.lead']),
    });
    const asked = await requestRuleEnablement(runtime.socDependencies(), {
      actor: lead('lead-a'),
      designatedApprovers: runtime.learningApprovers,
      correlationId: 'c',
      ruleKey: 'linux-process:100200',
      mode: 'dry_run',
      reason: 'Sombra superada según el informe semanal.',
      expiresInDays: 30,
    });
    if (!asked.ok) throw new Error(asked.reason);
    await approveRuleEnablement(runtime.socDependencies(), {
      actor: lead('lead-b'),
      designatedApprovers: runtime.learningApprovers,
      correlationId: 'c',
      id: asked.value.id,
      expectedRevision: asked.value.revision,
    });
    expect((await decide(11))?.mode).toBe('dry_run');
  });
});
