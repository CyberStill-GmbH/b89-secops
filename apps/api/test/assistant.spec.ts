import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { AssistantConfigError, loadAssistantConfig } from '../src/assistant/assistant-config.js';
import { createClaudeModel, type MessagesClient } from '../src/assistant/claude-model.js';
import { createInternalGet } from '../src/assistant/internal-client.js';
import { SOC_KNOWLEDGE } from '../src/assistant/soc-knowledge.generated.js';
import { buildSocTools } from '../src/assistant/soc-tools.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('configuración de Bunny', () => {
  it('está apagado por defecto', () => {
    expect(loadAssistantConfig({})).toEqual({ enabled: false });
  });

  it('en Bedrock antepone el prefijo anthropic. al modelo y exige región', () => {
    const config = loadAssistantConfig({ B89_BUNNY_ENABLED: 'true', AWS_REGION: 'us-east-1' });
    expect(config).toMatchObject({
      enabled: true,
      provider: 'bedrock',
      model: 'anthropic.claude-opus-5-5',
      effort: 'medium',
      redactPii: true,
    });
    expect(() => loadAssistantConfig({ B89_BUNNY_ENABLED: 'true' })).toThrow(AssistantConfigError);
  });

  it('el proveedor anthropic exige clave y respeta el modelo y el esfuerzo', () => {
    expect(() =>
      loadAssistantConfig({ B89_BUNNY_ENABLED: 'true', B89_BUNNY_PROVIDER: 'anthropic' }),
    ).toThrow(AssistantConfigError);
    expect(
      loadAssistantConfig({
        B89_BUNNY_ENABLED: 'true',
        B89_BUNNY_PROVIDER: 'anthropic',
        B89_BUNNY_API_KEY: 'k',
        B89_BUNNY_MODEL: 'claude-sonnet-5-5',
        B89_BUNNY_EFFORT: 'low',
        B89_BUNNY_REDACT_PII: 'false',
      }),
    ).toMatchObject({ model: 'claude-sonnet-5-5', effort: 'low', redactPii: false });
  });

  it('rechaza valores inválidos', () => {
    for (const env of [
      { B89_BUNNY_ENABLED: 'si' },
      { B89_BUNNY_ENABLED: 'true', AWS_REGION: 'x', B89_BUNNY_EFFORT: 'enorme' },
      { B89_BUNNY_ENABLED: 'true', AWS_REGION: 'x', B89_BUNNY_MODEL: 'a b' },
      { B89_BUNNY_ENABLED: 'true', AWS_REGION: 'x', B89_BUNNY_RATE_LIMIT: '0' },
    ]) {
      expect(() => loadAssistantConfig(env)).toThrow(AssistantConfigError);
    }
  });
});

describe('adaptador de Claude', () => {
  const config = loadAssistantConfig({ B89_BUNNY_ENABLED: 'true', AWS_REGION: 'us-east-1' });
  if (!config.enabled) throw new Error('config');

  it('traduce la petición al formato de la API y la respuesta al dominio', async () => {
    let sent: Record<string, unknown> = {};
    const client = {
      messages: {
        async create(params: Record<string, unknown>) {
          sent = params;
          return {
            content: [
              { type: 'text', text: 'Voy a buscar.' },
              { type: 'tool_use', id: 'tu_1', name: 'list_alerts', input: { priority: 'P1' } },
            ],
            stop_reason: 'tool_use',
            usage: { input_tokens: 12, output_tokens: 7 },
          };
        },
      },
    } as unknown as MessagesClient;
    const model = createClaudeModel(config, client);
    const response = await model.complete({
      system: 'sistema',
      messages: [
        { role: 'user', content: 'hola' },
        { role: 'assistant', content: [{ type: 'tool_use', id: 'a', name: 'x', input: {} }] },
        {
          role: 'user',
          content: [{ type: 'tool_result', tool_use_id: 'a', content: 'ok', is_error: true }],
        },
      ],
      tools: [{ name: 'list_alerts', description: 'd', inputSchema: { type: 'object' } }],
      maxTokens: 500,
      allowTools: false,
    });
    expect(sent).toMatchObject({
      model: 'anthropic.claude-opus-5-5',
      max_tokens: 500,
      tool_choice: { type: 'none' },
      output_config: { effort: 'medium' },
    });
    expect(sent).not.toHaveProperty('temperature');
    expect(response.stopReason).toBe('tool_use');
    expect(response.usage).toEqual({
      inputTokens: 12,
      outputTokens: 7,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
    // Caché: punto en el sistema (prefijo herramientas + sistema) y caché automática del historial.
    expect(sent).toMatchObject({
      cache_control: { type: 'ephemeral' },
      system: [{ type: 'text', cache_control: { type: 'ephemeral' } }],
    });
    expect(response.content[1]).toEqual({
      type: 'tool_use',
      id: 'tu_1',
      name: 'list_alerts',
      input: { priority: 'P1' },
    });
  });

  it('pide resúmenes de razonamiento y reenvía los bloques de pensamiento sin tocarlos', async () => {
    let sent: Record<string, unknown> = {};
    const client = {
      messages: {
        async create(params: Record<string, unknown>) {
          sent = params;
          return {
            content: [
              { type: 'thinking', thinking: 'Pienso…', signature: 'sig' },
              { type: 'redacted_thinking', data: 'opaco' },
              { type: 'text', text: 'ok' },
            ],
            stop_reason: 'end_turn',
            usage: { input_tokens: 1, output_tokens: 1 },
          };
        },
      },
    } as unknown as MessagesClient;
    const model = createClaudeModel(config, client);
    const response = await model.complete({
      system: 's',
      messages: [
        { role: 'user', content: 'x' },
        {
          role: 'assistant',
          content: [
            { type: 'thinking', thinking: 'Pienso…', signature: 'sig' },
            { type: 'redacted_thinking', data: 'opaco' },
            { type: 'tool_use', id: 'a', name: 'x', input: {} },
          ],
        },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'a', content: 'ok' }] },
      ],
      tools: [],
      maxTokens: 10,
      allowTools: true,
    });
    expect(sent).toMatchObject({ thinking: { type: 'adaptive', display: 'summarized' } });
    const echoed = (sent['messages'] as { content: unknown }[])[1]?.content as { type: string }[];
    expect(echoed.map((block) => block.type)).toEqual([
      'thinking',
      'redacted_thinking',
      'tool_use',
    ]);
    expect(response.content.map((block) => block.type)).toEqual([
      'thinking',
      'redacted_thinking',
      'text',
    ]);
  });

  it('con herramientas permitidas no fuerza tool_choice', async () => {
    let sent: Record<string, unknown> = {};
    const client = {
      messages: {
        async create(params: Record<string, unknown>) {
          sent = params;
          return {
            content: [],
            stop_reason: 'refusal',
            usage: { input_tokens: 1, output_tokens: 0 },
          };
        },
      },
    } as unknown as MessagesClient;
    const response = await createClaudeModel(config, client).complete({
      system: 's',
      messages: [{ role: 'user', content: 'x' }],
      tools: [],
      maxTokens: 10,
      allowTools: true,
    });
    expect(sent).not.toHaveProperty('tool_choice');
    expect(response.stopReason).toBe('refusal');
  });
});

describe('herramientas del SOC', () => {
  const analyst = { roles: ['b89.soc.analyst'], capabilities: ['alerts.read', 'incidents.read'] };

  it('solo ofrece las herramientas que el rol puede usar, en orden estable', () => {
    const build = () =>
      buildSocTools(async () => ({ status: 200, body: {} }), analyst).map((t) => t.name);
    const names = build();
    expect(names).toEqual(
      expect.arrayContaining([
        'whoami',
        'find_alerts',
        'get_alert_context',
        'entity_activity',
        'get_entity_risk',
        'get_rule_mitre',
        'lookup_runbook',
        'get_incident',
      ]),
    );
    expect(names).not.toContain('audit_events');
    expect(names).not.toContain('list_users');
    expect(names).not.toContain('search_events');
    // Orden determinista: el prefijo de herramientas se cachea.
    expect(build()).toEqual(names);
  });

  it('valida los parámetros antes de llamar a la API', async () => {
    let called = false;
    const tools = buildSocTools(async () => {
      called = true;
      return { status: 200, body: {} };
    }, analyst);
    const findAlerts = tools.find((t) => t.name === 'find_alerts');
    for (const input of [
      { priority: 'P9' },
      { limit: 999 },
      { text: 'x'.repeat(200) },
      { provider: 'splunk' },
      { from: '2026-11-01' },
    ]) {
      expect(await findAlerts?.run(input)).toMatchObject({ ok: false });
    }
    const context = tools.find((t) => t.name === 'get_alert_context');
    expect(await context?.run({ id: '../../admin' })).toMatchObject({ ok: false });
    const risk = tools.find((t) => t.name === 'get_entity_risk');
    expect(await risk?.run({ type: 'ip', value: '../admin' })).toMatchObject({ ok: false });
    expect(called).toBe(false);
  });

  it('traduce 403/404 y 5xx a mensajes sin detalles internos y quita el correlationId', async () => {
    let status = 404;
    const tools = buildSocTools(
      async () => ({ status, body: { correlationId: 'c', items: [] } }),
      analyst,
    );
    const getIncident = tools.find((t) => t.name === 'get_incident');
    const notFound = await getIncident?.run({ id: 'i-1' });
    expect(notFound).toMatchObject({ ok: false });
    expect(JSON.stringify(notFound)).toContain('tu rol');
    status = 503;
    expect(await getIncident?.run({ id: 'i-1' })).toMatchObject({ ok: false });
    status = 200;
    const list = await tools.find((t) => t.name === 'list_incidents')?.run({});
    expect(list).toEqual({ ok: true, data: { items: [] } });
  });

  it('find_alerts filtra por proveedor, entidad y rango, y resume con hora de Lima', async () => {
    const urls: string[] = [];
    const alert = (id: string, title: string, occurredAt: string, label = '10.0.0.9') => ({
      id,
      title,
      priority: 'P1',
      status: 'new',
      occurredAt,
      reasons: [{ code: 'r', detail: 'Activo expuesto' }],
      entities: [{ ref: 'ent_x', kind: 'ip', label }],
    });
    const tools = buildSocTools(async (url) => {
      urls.push(url);
      return {
        status: 200,
        body: {
          items: [
            alert('a-3', 'B89 Cloudflare: oleada distribuida contra pagos', '2026-11-05T14:12:00Z'),
            alert('a-2', 'B89 Snyk: vulnerabilidad crítica', '2026-11-04T10:00:00Z'),
            alert('a-1', 'B89 Cloudflare: auditoría', '2026-10-01T10:00:00Z', '10.0.0.7'),
          ],
          nextCursor: null,
        },
      };
    }, analyst);
    const result = await tools.find((t) => t.name === 'find_alerts')?.run({
      provider: 'cloudflare',
      entity: '10.0.0.9',
      from: '2026-11-01T00:00:00Z',
      status: 'open',
    });
    expect(urls[0]).toBe('/api/alerts?pageSize=200&status=open');
    expect(result).toMatchObject({
      ok: true,
      data: {
        matched: 1,
        complete: true,
        byProvider: { cloudflare: 1 },
        items: [
          {
            id: 'a-3',
            provider: 'cloudflare',
            occurredAtLima: '2026-11-05 09:12 Lima (14:12 UTC)',
            ruleId: '101740',
            mitre: ['T1595.002', 'T1190'],
          },
        ],
      },
      citations: [{ kind: 'alert', id: 'a-3' }],
    });
  });

  it('get_alert_context une la alerta, su regla con MITRE y runbook, y el evento de origen', async () => {
    const lead = {
      roles: ['b89.soc.lead'],
      capabilities: ['alerts.read', 'events.read', 'events.read_raw'],
    };
    const tools = buildSocTools(async (url) => {
      if (url.startsWith('/api/alerts/')) {
        return {
          status: 200,
          body: {
            alert: {
              id: 'a-3',
              title: 'B89 Cloudflare: oleada distribuida contra pagos.b89.pe: 50+ bloqueos',
              priority: 'P1',
              occurredAt: '2026-11-05T14:12:00Z',
              rawRef: 'raw:rec-1',
              relatedAlertIds: ['a-2'],
              entities: [],
              reasons: [],
            },
          },
        };
      }
      return {
        status: 200,
        body: { items: [{ recordId: 'rec-1', title: 'x', raw: { data: 1 } }], nextCursor: null },
      };
    }, lead);
    const result = await tools.find((t) => t.name === 'get_alert_context')?.run({ id: 'a-3' });
    expect(result).toMatchObject({
      ok: true,
      data: {
        rule: {
          ruleId: '101740',
          mitre: [{ id: 'T1595.002' }, { id: 'T1190' }],
          runbooks: [{ id: 'oleada-waf' }],
        },
        sourceEvent: { recordId: 'rec-1', raw: { data: 1 } },
      },
    });
    expect(result && result.ok ? result.citations?.map((c) => c.id) : []).toEqual(['a-3', 'a-2']);
  });

  it('el riesgo de entidad se degrada con claridad si el motor no existe', async () => {
    const urls: string[] = [];
    const tools = buildSocTools(async (url) => {
      urls.push(url);
      return { status: 404, body: null };
    }, analyst);
    const result = await tools
      .find((t) => t.name === 'get_entity_risk')
      ?.run({ type: 'user', value: 'ana@b89.io' });
    expect(urls[0]).toBe('/api/risk/entities/user/ana%40b89.io');
    expect(result).toMatchObject({ ok: true, data: { available: false } });
  });

  it('el conocimiento de docs/17 responde mapeo MITRE y runbooks', async () => {
    const tools = buildSocTools(async () => ({ status: 200, body: {} }), analyst);
    const mitre = tools.find((t) => t.name === 'get_rule_mitre');
    expect(await mitre?.run({ ruleId: '101740' })).toMatchObject({
      ok: true,
      data: { found: true, ruleId: '101740', runbooks: [{ id: 'oleada-waf' }] },
    });
    expect(await mitre?.run({ ruleId: '999999' })).toMatchObject({
      ok: true,
      data: { found: false },
    });
    expect(await mitre?.run({ technique: 'T1110' })).toMatchObject({
      ok: true,
      data: { found: true },
    });
    const runbook = tools.find((t) => t.name === 'lookup_runbook');
    expect(await runbook?.run({ query: 'malware bitdefender' })).toMatchObject({
      ok: true,
      data: { found: true, runbook: { id: 'malware-edr' } },
    });
    expect(await runbook?.run({ ruleId: '101740', includePlaybooks: true })).toMatchObject({
      ok: true,
      data: { runbook: { id: 'oleada-waf' }, playbooks: expect.stringContaining('B89 Respond') },
    });
  });

  it('el conocimiento empaquetado coincide con los runbooks de docs/17', () => {
    const dir = join(ROOT, 'docs/detection-engineering/runbooks');
    const files = readdirSync(dir).filter((name) => name.endsWith('.md') && name !== 'README.md');
    expect(SOC_KNOWLEDGE.runbooks.map((runbook) => `${runbook.id}.md`).sort()).toEqual(
      files.sort(),
    );
    for (const runbook of SOC_KNOWLEDGE.runbooks) {
      expect(runbook.markdown, `regenera con generate-bunny-knowledge.py (${runbook.id})`).toBe(
        readFileSync(join(dir, `${runbook.id}.md`), 'utf8').replace(/\r\n/gu, '\n').trim(),
      );
    }
  });
});

describe('cliente interno', () => {
  it('rechaza rutas fuera de /api y reenvía la sesión de la persona', async () => {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const server = {
      async inject(options: { url: string; headers: Record<string, string> }) {
        calls.push(options);
        return { statusCode: 200, body: '{"ok":true}' };
      },
    };
    const get = createInternalGet(server as never, {
      headers: { cookie: 'b89_session=abc', 'x-forwarded-for': '10.0.0.1' },
      ip: '10.0.0.2',
    });
    expect((await get('/otra/ruta')).status).toBe(400);
    expect((await get('/api/../admin')).status).toBe(400);
    expect(await get('/api/alerts')).toEqual({ status: 200, body: { ok: true } });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers['cookie']).toBe('b89_session=abc');
  });
});
