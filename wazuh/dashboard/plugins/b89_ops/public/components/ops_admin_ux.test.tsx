/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { OperationsHealth, PlatformSourceHealth, RoleRequestView } from '../../common';
import {
  amrText,
  API_ERROR_MESSAGE,
  NOTIFICATION_STATUS_LABEL,
  OPERATIONS_STATUS_LABEL,
  PLATFORM_STATE_LABEL,
  PLATFORM_STATE_TONE,
  SOURCE_STATE_LABEL,
  SOURCE_VERDICT_LABEL,
  SOURCE_VERDICT_TONE,
} from '../../common';
import { PersonName, RoleRequestSentence } from './access_view';
import { auditActionLabel, integrityHeadline } from './audit_view';
import { DELIVERY } from './notification_groups';
import { operationsSummaryRows } from './operations_view';
import { sortPlatformSources } from './platform_health_view';
import { capabilitySentence } from './session_view';

describe('una sola escala de salud', () => {
  it('usa las mismas palabras en fuentes, monitor de plataforma y salud operativa', () => {
    expect(SOURCE_VERDICT_LABEL.healthy).toBe('Funciona');
    expect(SOURCE_STATE_LABEL.healthy).toBe('Funciona');
    expect(PLATFORM_STATE_LABEL.ok).toBe('Funciona');
    expect(OPERATIONS_STATUS_LABEL.OK).toBe('Funciona');
    expect(SOURCE_VERDICT_LABEL.failing).toBe(PLATFORM_STATE_LABEL.failing);
    expect(SOURCE_VERDICT_LABEL.unknown).toBe(PLATFORM_STATE_LABEL.unknown);
    // «Sin eventos» es informativo en ambos lados, nunca un aviso.
    expect(SOURCE_VERDICT_TONE.quiet).toBe('info');
    expect(PLATFORM_STATE_TONE.silent).toBe('info');
  });

  it('ordena el monitor de plataforma con lo que falla primero', () => {
    const item = (source: string, state: PlatformSourceHealth['state']): PlatformSourceHealth => ({
      source,
      state,
      at: '2026-11-22T10:00:00Z',
      severity: 'info',
      summary: '',
      lastSeen: null,
      since: null,
    });
    expect(
      sortPlatformSources([item('snyk', 'ok'), item('aws', 'failing'), item('canary', 'silent')]).map(
        (entry) => entry.source,
      ),
    ).toEqual(['aws', 'canary', 'snyk']);
  });

  it('resume la salud operativa en una línea por área', () => {
    const data = {
      generatedAt: '2026-11-22T10:00:00Z',
      status: 'OK',
      sections: {
        summary: {
          status: 'OK',
          lastAlertAt: null,
          alertFreshnessSeconds: null,
          sourceCoverage: 'OK',
        },
        platform: {
          status: 'OK',
          degradedReasons: [],
          databaseLatencyMs: 12,
          uptimeSeconds: 10,
          memoryRssMb: 100,
          nodeVersion: 'v22',
        },
      },
    } as unknown as OperationsHealth;
    const rows = operationsSummaryRows(data);
    expect(rows.map((row) => row.title)).toEqual(['Detección', 'Base de datos']);
    expect(rows[1].detail).toBe('Responde en 12 ms.');
  });
});

describe('mensajes de error en tú y accionables', () => {
  it('no promete lo que la interfaz no puede verificar ni usa usted', () => {
    const all = Object.values(API_ERROR_MESSAGE).join(' ');
    expect(all).not.toMatch(/ya fue notificado/);
    expect(all).not.toMatch(/\b(Inicie|Vuelva|Revise|Recargue|Reintente|su cuenta|Su sesión)\b/);
    expect(API_ERROR_MESSAGE.RATE_LIMITED).toContain('Espera un minuto');
  });
});

describe('vocabulario de avisos', () => {
  it('usa «Entregado al canal» y «Visto por el SOC» en la bandeja y en el catálogo', () => {
    expect(NOTIFICATION_STATUS_LABEL.sent).toBe(DELIVERY.sent.label);
    expect(NOTIFICATION_STATUS_LABEL.acknowledged).toBe(DELIVERY.acknowledged.label);
    expect(DELIVERY.acknowledged.label).toBe('Visto por el SOC');
  });
});

describe('accesos: personas con nombre', () => {
  const request = {
    id: 'r1',
    targetOid: 'oid-luis',
    action: 'grant',
    role: 'b89.soc.analyst',
    reason: 'Nuevo turno de noche',
    ticket: null,
    status: 'pending_access',
    approvalStage: 'access',
    requesterOid: 'oid-ana',
    priorApproverOid: null,
    securityApproverOid: null,
    closure: null,
    createdAt: '2026-11-22T10:00:00Z',
    updatedAt: '2026-11-22T10:00:00Z',
    revision: 1,
  } as RoleRequestView;
  const names = new Map([
    ['oid-ana', 'Ana Pérez'],
    ['oid-luis', 'Luis Rojas'],
  ]);

  it('dice quién pide qué para quién, con el identificador solo en el tooltip', () => {
    const markup = renderToStaticMarkup(
      <RoleRequestSentence request={request} names={names} viewerId="oid-otro" />,
    );
    expect(markup).toContain('Ana Pérez');
    expect(markup).toContain('pide');
    expect(markup).toContain('conceder Analista SOC a');
    expect(markup).toContain('Luis Rojas');
    expect(markup).not.toContain('>oid-ana<');
  });

  it('nombra a quien mira como «Tú» y a quien no está en el padrón sin inventar nombre', () => {
    expect(
      renderToStaticMarkup(<PersonName oid="oid-ana" names={names} viewerId="oid-ana" />),
    ).toContain('Tú');
    expect(
      renderToStaticMarkup(<PersonName oid="oid-x" names={names} viewerId="oid-ana" />),
    ).toContain('Persona fuera del padrón');
  });

  it('muestra los métodos de acceso en palabras', () => {
    expect(amrText(['pwd', 'mfa'])).toBe('Contraseña + Multifactor');
    expect(amrText([])).toBe('Método sin dato');
  });
});

describe('Mi sesión y Auditoría responden primero', () => {
  it('resume los permisos en palabras', () => {
    expect(capabilitySentence(['alerts.read', 'alerts.triage', 'x.unknown'])).toBe(
      'Puedes: ver alertas, clasificar alertas, 1 permiso más (ver datos técnicos).',
    );
    expect(capabilitySentence([])).toBeNull();
  });

  it('da acciones legibles y el resultado de integridad en una frase', () => {
    expect(auditActionLabel('access.session.revoked')).toBe('Sesión revocada');
    expect(auditActionLabel('otra.accion')).toBe('otra.accion');
    expect(
      integrityHeadline({ ok: true, checked: 12, headSequence: '12', violations: [] } as never),
    ).toBe('Cadena íntegra: 12 eventos verificados, ninguno alterado.');
  });
});
