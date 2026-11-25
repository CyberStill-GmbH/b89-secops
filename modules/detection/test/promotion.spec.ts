import { describe, expect, it } from 'vitest';

import {
  candidateId,
  decidePromotion,
  promotionKey,
  type DetectionCandidate,
} from '../src/promotion.js';
import type { DetectionCandidateStore } from '../src/ports.js';
import type { CorrelationSignal } from '../src/correlation.js';
import {
  isPromotable,
  prioritize,
  PRIORITIZATION_RULESET_VERSION,
  PROMOTION_CONTEXT_REASONS,
  type PrioritizationContext,
} from '../src/prioritization.js';
import { withSeverity } from './support/events.js';

const NOW = new Date('2026-10-07T15:31:00.000Z');

const CONTEXT: PrioritizationContext = {
  privilegedIdentities: new Set(['jperez@b89.example']),
  criticalAssets: new Set(['host-1']),
};

class MemoryCandidateStore implements DetectionCandidateStore {
  public readonly rows = new Map<string, DetectionCandidate>();

  public byIdempotencyKey(tenantId: string, key: string): Promise<DetectionCandidate | undefined> {
    return Promise.resolve(this.rows.get(`${tenantId}|${key}`));
  }

  public insertIfAbsent(candidate: DetectionCandidate): Promise<boolean> {
    const key = `${candidate.tenantId}|${candidate.idempotencyKey}`;
    if (this.rows.has(key)) return Promise.resolve(false);
    this.rows.set(key, candidate);
    return Promise.resolve(true);
  }
}

async function promote(store: MemoryCandidateStore, event = withSeverity('high')) {
  const key = promotionKey(event.tenant.id, event.recordId, PRIORITIZATION_RULESET_VERSION);
  const existing = await store.byIdempotencyKey(event.tenant.id, key);
  const decision = decidePromotion(event, CONTEXT, existing, NOW);
  if (decision.outcome === 'promoted') await store.insertIfAbsent(decision.candidate);
  return decision;
}

describe('C-16 · promoción', () => {
  it('promueve una alerta Wazuh que supera el umbral', async () => {
    const store = new MemoryCandidateStore();
    const decision = await promote(store);

    expect(decision.outcome).toBe('promoted');
    expect(decision.outcome === 'promoted' && decision.candidate.priority).toBe('P1');
    expect(decision.outcome === 'promoted' && decision.candidate.title).toContain('wazuh');
    expect(store.rows.size).toBe(1);
  });

  it('C-23: el título sin ID lo decide el borde, no el dominio', () => {
    const event = withSeverity('high', {
      detection: {
        rule: {
          id: 'detector-7f3a',
          name: 'Volumen anómalo de inicios',
          provider: 'detector-x',
          groups: [],
        },
      },
    });
    const plain = decidePromotion(event, CONTEXT, undefined, NOW);
    const bare = decidePromotion(event, CONTEXT, undefined, NOW, {
      bareTitleProviders: new Set(['detector-x']),
    });
    expect(plain.outcome === 'promoted' && plain.candidate.title).toBe(
      'Volumen anómalo de inicios (detector-x detector-7f3a)',
    );
    expect(bare.outcome === 'promoted' && bare.candidate.title).toBe('Volumen anómalo de inicios');
  });

  it('no promueve por debajo del umbral y declara el motivo', async () => {
    const store = new MemoryCandidateStore();
    const decision = await promote(
      store,
      withSeverity('low', { entities: { identities: [], resources: [] } }),
    );

    expect(decision).toMatchObject({ outcome: 'not_promoted', reasonCode: 'BELOW_THRESHOLD' });
    expect(store.rows.size).toBe(0);
  });

  it('no promueve lo suprimido aunque el puntaje base fuera alto', async () => {
    const event = withSeverity('critical');
    const decision = decidePromotion(
      event,
      { ...CONTEXT, knownBenignRuleIds: new Set(['5716']) },
      undefined,
      NOW,
    );

    expect(decision).toMatchObject({ outcome: 'not_promoted', reasonCode: 'SUPPRESSED' });
  });

  it('repetir la promoción no crea un segundo candidato', async () => {
    const store = new MemoryCandidateStore();
    const first = await promote(store);
    const second = await promote(store);

    expect(first.outcome).toBe('promoted');
    expect(second.outcome).toBe('duplicate');
    expect(second.outcome === 'duplicate' && second.existing.id).toBe(
      first.outcome === 'promoted' && first.candidate.id,
    );
    expect(store.rows.size).toBe(1);
  });

  it('dos workers concurrentes dejan un único candidato', async () => {
    const store = new MemoryCandidateStore();
    const event = withSeverity('high');
    const decisions = [
      decidePromotion(event, CONTEXT, undefined, NOW),
      decidePromotion(event, CONTEXT, undefined, NOW),
    ];
    const inserted = await Promise.all(
      decisions.map((decision) =>
        decision.outcome === 'promoted' ? store.insertIfAbsent(decision.candidate) : false,
      ),
    );

    expect(inserted.filter(Boolean)).toHaveLength(1);
    expect(store.rows.size).toBe(1);
  });

  it('deriva un identificador estable entre reintentos', () => {
    const event = withSeverity('high');
    const key = promotionKey(event.tenant.id, event.recordId, '1.0.0');

    expect(candidateId(key, new Date(event.occurredAt))).toBe(
      candidateId(key, new Date(event.occurredAt)),
    );
    expect(candidateId(key, new Date(event.occurredAt))).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  });

  it('separa la clave por tenant, evento y versión del ruleset', () => {
    const key = promotionKey('tenant-1', 'record-1', '1.0.0');

    expect(promotionKey('tenant-2', 'record-1', '1.0.0')).not.toBe(key);
    expect(promotionKey('tenant-1', 'record-2', '1.0.0')).not.toBe(key);
    expect(promotionKey('tenant-1', 'record-1', '1.1.0')).not.toBe(key);
  });

  it('conserva el candidato existente aunque el contexto cambie entre pasadas', async () => {
    const store = new MemoryCandidateStore();
    const first = await promote(store);
    const event = withSeverity('high');
    const existing = await store.byIdempotencyKey(
      event.tenant.id,
      promotionKey(event.tenant.id, event.recordId, PRIORITIZATION_RULESET_VERSION),
    );
    const second = decidePromotion(
      event,
      { ...CONTEXT, knownBenignRuleIds: new Set(['5716']) },
      existing,
      NOW,
    );

    expect(second.outcome).toBe('duplicate');
    expect(first.outcome === 'promoted' && store.rows.size).toBe(1);
  });

  it('conserva las razones dentro del candidato promovido', async () => {
    const decision = await promote(new MemoryCandidateStore());
    const codes =
      decision.outcome === 'promoted' ? decision.candidate.reasons.map((r) => r.code) : [];

    expect(codes).toEqual(
      expect.arrayContaining(['BASE_SEVERITY', 'PRIVILEGED_IDENTITY', 'CRITICAL_ASSET']),
    );
  });
});

describe('C-16 · promoción 1.2.0: media o menor solo con contexto', () => {
  const NO_CONTEXT: PrioritizationContext = {
    privilegedIdentities: new Set(),
    criticalAssets: new Set(),
  };
  const correlated = (relatedCount: number, recentSimilarCount: number): CorrelationSignal => ({
    version: 'test',
    entityKeys: ['user:jperez@b89.example'],
    signal: 'other',
    relatedAlertIds: Array.from({ length: relatedCount }, (_, i) => `alert-${i}`),
    relatedCount,
    recentSimilarCount,
  });
  const decide = (event: ReturnType<typeof withSeverity>, context: PrioritizationContext) =>
    decidePromotion(event, context, undefined, NOW);

  it('una alerta media sin contexto queda consultable pero no abre alerta', () => {
    const decision = decide(withSeverity('medium'), NO_CONTEXT);

    expect(decision).toMatchObject({ outcome: 'not_promoted', reasonCode: 'BELOW_THRESHOLD' });
    expect(decision.evaluation.score).toBe(40);
  });

  it('repetir el mismo ruido medio no lo promueve', () => {
    const decision = decide(withSeverity('medium'), {
      ...NO_CONTEXT,
      correlation: correlated(0, 50),
    });

    expect(decision.evaluation.reasons.map((r) => r.code)).toContain('REPEATED_ACTIVITY');
    expect(decision.outcome).toBe('not_promoted');
  });

  it('un activo expuesto por sí solo no cuenta como contexto', () => {
    const decision = decide(withSeverity('medium'), {
      ...NO_CONTEXT,
      internetFacingAssets: new Set(['host-1']),
    });

    expect(decision.evaluation.reasons.map((r) => r.code)).toContain('EXTERNAL_EXPOSURE');
    expect(decision.outcome).toBe('not_promoted');
  });

  it.each([
    ['activo crítico', { ...NO_CONTEXT, criticalAssets: new Set(['host-1']) }],
    [
      'identidad privilegiada',
      { ...NO_CONTEXT, privilegedIdentities: new Set(['jperez@b89.example']) },
    ],
    ['correlación con otras alertas', { ...NO_CONTEXT, correlation: correlated(3, 0) }],
  ])('una alerta media con %s sí se promueve', (_label, context) => {
    const decision = decide(withSeverity('medium'), context);

    expect(decision.outcome).toBe('promoted');
    expect(decision.outcome === 'promoted' && decision.candidate.priority).toBe('P3');
  });

  it('una baja con identidad privilegiada alcanza el umbral y tiene contexto', () => {
    const decision = decide(withSeverity('low'), {
      ...NO_CONTEXT,
      privilegedIdentities: new Set(['jperez@b89.example']),
    });

    expect(decision.outcome).toBe('promoted');
  });

  it('alta y crítica se promueven sin contexto, como antes', () => {
    expect(decide(withSeverity('high'), NO_CONTEXT).outcome).toBe('promoted');
    expect(decide(withSeverity('critical'), NO_CONTEXT).outcome).toBe('promoted');
  });

  it('isPromotable refleja la misma regla para quien solo tiene la evaluación', () => {
    const event = withSeverity('medium');
    const evaluation = prioritize(event, NO_CONTEXT);

    expect(isPromotable('medium', evaluation)).toBe(false);
    expect(isPromotable('high', prioritize(withSeverity('high'), NO_CONTEXT))).toBe(true);
    expect(PROMOTION_CONTEXT_REASONS.has('REPEATED_ACTIVITY')).toBe(false);
  });
});
