/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  entityClauses,
  entityKey,
  entityKql,
  extractEntities,
  groupExactEmailMessages,
  parseEntityKey,
  selectQueryEntities,
  validEntity,
} from './investigation';
import { discoverUrlForQuery, mitreTechniqueUrl, threatHuntingUrl } from './discover';
import { vendorLogoUrl, vendorOfGroups, vendorOfTitle, wazuhRuleIdOfTitle } from './vendors';
import { alertQuestion } from './bunny_bridge';
import { NAV_CATEGORIES, NAV_HIDDEN, NAV_PLACEMENT } from './navigation';

describe('entidades de un evento de wazuh-alerts-*', () => {
  it('mantiene la selección visible alineada con el límite de entidades consultadas', () => {
    const entities = Array.from({ length: 10 }, (_, index) => ({
      kind: 'host' as const,
      value: `host-${index}`,
      field: 'agent.name',
    }));

    expect(selectQueryEntities(entities)).toEqual(entities.slice(0, 8));
    expect(selectQueryEntities(entities, ['host:host-1', 'host:host-9'])).toEqual([entities[1]]);
    expect(selectQueryEntities(entities, [])).toEqual([]);
  });

  it('extrae usuario, IP y zona de Cloudflare sin el manager como equipo', () => {
    const source = {
      agent: { id: '000', name: 'wazuh.manager' },
      data: {
        cloudflare: {
          zone_name: 'b89.io',
          audit: { actor_email: 'b89service@b89.io', actor_ip: '18.214.220.109' },
        },
      },
    };
    expect(extractEntities(source).map(entityKey)).toEqual([
      'user:b89service@b89.io',
      'ip:18.214.220.109',
      'zone:b89.io',
    ]);
  });

  it('usa mailbox owner y destinatarios del schema como pivotes de usuario', () => {
    const source = {
      agent: { id: '000', name: 'wazuh.manager' },
      data: {
        office365: {
          UserId: 'sender@example.test',
          MailboxOwnerUPN: 'owner@example.test',
          recipientList: [
            { Address: 'recipient@example.test', Name: 'Recipient' },
            { Address: 'recipient@example.test', Name: 'duplicate' },
            { Name: 'missing address' },
          ],
        },
      },
    };
    expect(extractEntities(source).map(entityKey)).toEqual([
      'user:sender@example.test',
      'user:owner@example.test',
      'user:recipient@example.test',
    ]);
    expect(entityClauses([{ kind: 'user', value: 'recipient@example.test' }])).toContainEqual({
      term: { 'data.office365.recipientList.Address': 'recipient@example.test' },
    });
  });

  it('usa el agente cuando no es el manager y quita duplicados y ruido', () => {
    const source = {
      agent: { id: '001', name: 'web-01', ip: '10.0.0.5' },
      data: { srcip: '10.0.0.5', srcuser: '-', bitdefender: { endpoint: { name: 'web-01' } } },
    };
    expect(extractEntities(source).map(entityKey)).toEqual(['host:web-01', 'ip:10.0.0.5']);
  });

  it('valida las claves de pivote', () => {
    expect(parseEntityKey('ip:2001:db8::1')).toEqual({ kind: 'ip', value: '2001:db8::1' });
    expect(parseEntityKey('ip:no-es-ip')).toBeNull();
    expect(parseEntityKey('otro:x')).toBeNull();
    expect(validEntity('host', 'wazuh.manager')).toBe(false);
    expect(validEntity('user', `a${String.fromCharCode(0)}b`)).toBe(false);
  });

  it('consulta todos los campos de cada entidad (Indexer y KQL)', () => {
    expect(entityClauses([{ kind: 'zone', value: 'b89.io' }])).toEqual([
      { term: { 'data.cloudflare.zone_name': 'b89.io' } },
      { term: { 'data.cloudflare.audit.zone_name': 'b89.io' } },
    ]);
    expect(entityKql([{ kind: 'project', value: 'a"b' }])).toBe('data.snyk.project.name:"a\\"b"');
  });
});

describe('correlación de mensajes M365 por identificador exacto', () => {
  const summary = (
    id: string,
    email?: {
      networkMessageId?: string;
      internetMessageId?: string;
      operation?: string;
    },
  ) => ({
    id,
    index: 'wazuh-alerts-test',
    at: '2026-11-11T12:00:00.000Z',
    level: 8,
    ruleId: '101700',
    description: `evento ${id}`,
    groups: ['office365'],
    vendor: 'office365' as const,
    agent: null,
    ...(email ? { email } : {}),
    mitre: { ids: [], tactics: [], techniques: [] },
    matched: [],
  });

  it('agrupa envío y recepción por NetworkMessageId compartido e ignora proximidad sin ID', () => {
    const sender = summary('send-1', {
      networkMessageId: 'abcdef01-2345-6789-abcd-ef0123456789',
      internetMessageId: '<message-1@example.test>',
      operation: 'Send',
    });
    const receiver = summary('receive-1', {
      networkMessageId: 'ABCDEF01-2345-6789-ABCD-EF0123456789',
      internetMessageId: '<message-1@example.test>',
      operation: 'Receive',
    });
    const sameUserAndTime = summary('nearby-1');

    expect(groupExactEmailMessages([sender, receiver, sameUserAndTime])).toEqual([
      {
        idType: 'NetworkMessageId',
        id: 'abcdef01-2345-6789-abcd-ef0123456789',
        events: [sender, receiver],
      },
    ]);
  });

  it('agrupa por InternetMessageId solo cuando no hay NetworkMessageId común', () => {
    const first = summary('send-2', { internetMessageId: '<message-2@example.test>' });
    const second = summary('receive-2', { internetMessageId: '<message-2@example.test>' });
    const conflictingNetwork = summary('other-2', {
      networkMessageId: '12345678-1234-1234-1234-123456789abc',
      internetMessageId: '<message-2@example.test>',
    });
    const groups = groupExactEmailMessages([first, second, conflictingNetwork]);
    expect(groups).toEqual([
      {
        idType: 'InternetMessageId',
        id: '<message-2@example.test>',
        events: [first, second],
      },
    ]);
    expect(
      groupExactEmailMessages([
        first,
        summary('case-variant', { internetMessageId: '<MESSAGE-2@EXAMPLE.TEST>' }),
      ]),
    ).toEqual([]);
  });
});

describe('enlaces de investigación', () => {
  it('Threat Hunting y Discover llevan la consulta y la ventana', () => {
    const th = threatHuntingUrl(
      '',
      'rule.id:1',
      '2026-01-01T00:00:00.000Z',
      '2026-01-02T00:00:00.000Z',
    );
    expect(th.startsWith('/app/threat-hunting#/overview/?tab=general&tabView=events&_a=')).toBe(
      true,
    );
    expect(decodeURIComponent(th)).toContain("query:'rule.id:1'");
    expect(decodeURIComponent(th)).toContain("from:'2026-01-01T00:00:00.000Z'");
    const discover = discoverUrlForQuery('/base', 'x:"y"', 'a', 'b');
    expect(discover.startsWith('/base/app/data-explorer/discover#?_a=')).toBe(true);
  });

  it('MITRE: técnica y subtécnica', () => {
    expect(mitreTechniqueUrl('T1562.001')).toBe('https://attack.mitre.org/techniques/T1562/001/');
    expect(mitreTechniqueUrl('T1110')).toBe('https://attack.mitre.org/techniques/T1110/');
    expect(mitreTechniqueUrl('javascript:1')).toBeNull();
  });
});

describe('proveedores', () => {
  it('reconoce el origen por grupo, por data.b89.vendor y por título', () => {
    expect(vendorOfGroups(['b89_waf', 'cloudflare'])).toBe('cloudflare');
    expect(vendorOfGroups(['syslog'], 'snyk')).toBe('snyk');
    expect(vendorOfGroups(['sshd'])).toBe('wazuh');
    expect(vendorOfTitle('B89 Bitdefender: firmas desactualizadas en X. (wazuh 101407)')).toBe(
      'bitdefender',
    );
    expect(vendorOfTitle('Inicio de sesión en Office 365')).toBe('office365');
    expect(vendorOfTitle('sshd: autenticación fallida')).toBe('wazuh');
    expect(wazuhRuleIdOfTitle('B89 Cloudflare: cambio DNS. (wazuh 101503)')).toBe('101503');
    expect(wazuhRuleIdOfTitle('sin regla')).toBeNull();
    expect(vendorLogoUrl('/b', 'aws', true)).toBe('/b/ui/b89/vendors/aws-on-dark.svg');
  });
});

describe('Preguntar a Bunny', () => {
  it('arma una pregunta con la alerta, la regla, MITRE y entidades', () => {
    const text = alertQuestion({
      id: 'a1',
      title: 'B89 Cloudflare: cambio DNS',
      priority: 'P3',
      occurredAt: '2026-11-08T14:57:31.925Z',
      ruleId: '101503',
      entities: [{ kind: 'zone', value: 'b89.io' }],
      mitre: ['T1584.002'],
    });
    expect(text).toContain('«B89 Cloudflare: cambio DNS»');
    expect(text).toContain('Regla de Wazuh: 101503.');
    expect(text).toContain('MITRE ATT&CK: T1584.002.');
    expect(text).toContain('zone b89.io');
  });
});

describe('navegación del SIEM', () => {
  it('cada app visible cae en una categoría conocida y ninguna está a la vez oculta', () => {
    for (const [id, placement] of Object.entries(NAV_PLACEMENT)) {
      expect(NAV_CATEGORIES[placement.category]).toBeDefined();
      expect(NAV_HIDDEN[id]).toBeUndefined();
    }
  });

  it('B89 Respond aparece con su nombre de producto, no como «SOAR»', () => {
    expect(NAV_PLACEMENT['b89-respond'].title).toBe('B89 Respond');
    expect(NAV_PLACEMENT['b89-respond'].category).toBe('response');
  });

  it('oculta los módulos sin servicio en este despliegue', () => {
    for (const id of ['google-cloud', 'github', 'microsoft-graph-api', 'cluster']) {
      expect(NAV_HIDDEN[id]).toBeTruthy();
    }
  });
});
