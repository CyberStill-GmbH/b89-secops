/**
 * El aviso de Teams/correo incluye el contexto del correlador en «Por qué importa» cuando está
 * disponible y sale igual (sin ese contexto) cuando el correlador falla.
 *
 * La explicación «salud de la plataforma» (que sugiere cerrar como benigna) solo aplica al rango
 * del monitor de plataforma 102100–102149; los IDs 1018xx son detecciones de red reales.
 */

import { describe, expect, it } from 'vitest';
import type { Alert, OutboxMessageDraft } from '@b89/soc';

import { notificationEnricher } from '../src/runtime/notification-enricher.js';
import { parseEntityRisk, NO_ENTITY_RISK } from '../src/runtime/entity-risk.js';
import type { SocKnowledge } from '../src/assistant/soc-knowledge.js';

const knowledge = { rules: {}, useCases: [], runbooks: [], techniques: {} } as unknown as SocKnowledge;

const alert = {
  id: 'al_1',
  tenantId: 't',
  title: 'B89 M365: inicio de sesión sospechoso (wazuh 100001)',
  priority: 'P2',
  score: 60,
  reasons: [],
  status: 'open',
  occurredAt: new Date('2026-11-13T10:00:00Z'),
  entityKeys: ['user:victima@b89.example'],
  entityRefs: [],
  relatedAlertIds: ['a', 'b', 'c'],
  ruleId: '100001',
  incidentId: null,
  candidateId: 'c',
} as unknown as Alert;

const message = {
  tenantId: 't',
  aggregateType: 'alert',
  messageType: 'soc.alert.created',
  aggregateId: 'al_1',
  availableAt: new Date('2026-11-13T10:00:00Z'),
  payload: {},
} as unknown as OutboxMessageDraft;

describe('contexto del correlador en los avisos', () => {
  it('agrega riesgo, fuentes y alertas relacionadas a «Por qué importa»', async () => {
    const enricher = notificationEnricher({
      alertById: async () => alert,
      knowledge,
      entityRisk: {
        snapshot: async () => ({
          available: true,
          byKey: parseEntityRisk({
            items: [
              {
                key: 'user:victima@b89.example',
                score: 82,
                sources: ['aws', 'm365', 'pam'],
                candidateIds: ['rc_1'],
              },
            ],
          }),
        }),
      },
    });
    const { context } = await enricher.contextFor(message);
    expect(context.whyItMatters).toContain(
      'Contexto del correlador: Riesgo de entidad 82/100 · en cadena correlada · 3 fuentes · 3 relacionadas.',
    );
    expect(context.relatedAlertCount).toBe(3);
  });

  it('si el correlador no está disponible o falla, el aviso sale sin ese contexto', async () => {
    for (const entityRisk of [
      { snapshot: async () => NO_ENTITY_RISK },
      {
        snapshot: async () => {
          throw new Error('down');
        },
      },
      undefined,
    ]) {
      const enricher = notificationEnricher({
        alertById: async () => alert,
        knowledge,
        ...(entityRisk ? { entityRisk } : {}),
      });
      const { context } = await enricher.contextFor(message);
      expect(context.whyItMatters ?? '').not.toContain('correlador');
      expect(context.title).toContain('inicio de sesión sospechoso');
    }
  });
});

describe('explicación de salud de plataforma solo para el rango del monitor', () => {
  const contextForRule = async (ruleId: string, title: string) => {
    const enricher = notificationEnricher({
      alertById: async () => ({ ...alert, ruleId, title }) as Alert,
      knowledge,
    });
    return (await enricher.contextFor(message)).context;
  };

  it.each([
    ['102100', 'B89 Plataforma: evento del monitor de salud.'],
    ['102107', 'B89 Plataforma: disco por encima del umbral (/).'],
    ['102122', 'B89 Canario: el evento sintético de snyk no completó el recorrido.'],
    ['102149', 'B89 Canario: límite superior del rango.'],
  ])('%s (monitor de plataforma) se explica como salud de la plataforma', async (ruleId, title) => {
    const context = await contextForRule(ruleId, title);
    expect(context.whyItMatters).toContain('Salud de la plataforma SOC');
    expect(context.nextStep).toContain('Salud de fuentes');
  });

  it.each([
    // Detecciones de red que antes caían en 101800–101849 y se mandaban a cerrar como benignas.
    ['101845', 'B89 Edge: fuerza bruta contra el login del SOC.'],
    ['101821', 'B89 Linux: sesión SSH desde origen nuevo.'],
    ['101800', 'B89 Linux: puerto en escucha inesperado.'],
    ['101830', 'B89 Edge: ataque HTTP.'],
    ['101849', 'B89 Red: límite superior del rango antiguo.'],
    // Bordes del nuevo rango y priorización de vulnerabilidades (no es salud de plataforma).
    ['102099', 'B89 Red: fuera de rango.'],
    ['102150', 'B89 Snyk: vulnerabilidad CRÍTICA priorizada P1.'],
    ['102162', 'B89 Vulnerabilidad: P1 en activo.'],
  ])('%s no se explica como salud de plataforma ni se sugiere cerrar como benigna', async (ruleId, title) => {
    const context = await contextForRule(ruleId, title);
    expect(context.whyItMatters ?? '').not.toContain('Salud de la plataforma');
    expect(context.nextStep ?? '').not.toContain('benigna');
  });
});
