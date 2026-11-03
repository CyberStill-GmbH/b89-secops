import { describe, expect, it } from 'vitest';

import { AssistantConfigError, loadAssistantConfig } from '../src/assistant/assistant-config.js';
import { createClaudeModel, type MessagesClient } from '../src/assistant/claude-model.js';
import { createInternalGet } from '../src/assistant/internal-client.js';
import { buildSocTools } from '../src/assistant/soc-tools.js';

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
    expect(response.usage).toEqual({ inputTokens: 12, outputTokens: 7 });
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

  it('solo ofrece las herramientas que el rol puede usar', () => {
    const names = buildSocTools(async () => ({ status: 200, body: {} }), analyst).map(
      (t) => t.name,
    );
    expect(names).toContain('list_alerts');
    expect(names).toContain('get_incident');
    expect(names).toContain('whoami');
    expect(names).not.toContain('audit_events');
    expect(names).not.toContain('list_users');
    expect(names).not.toContain('search_events');
  });

  it('valida los parámetros antes de llamar a la API', async () => {
    let called = false;
    const tools = buildSocTools(async () => {
      called = true;
      return { status: 200, body: {} };
    }, analyst);
    const listAlerts = tools.find((t) => t.name === 'list_alerts');
    for (const input of [
      { priority: 'P9' },
      { pageSize: 999 },
      { q: 'x'.repeat(200) },
      { entity: 'user@x.com' },
    ]) {
      expect(await listAlerts?.run(input)).toMatchObject({ ok: false });
    }
    const getAlert = tools.find((t) => t.name === 'get_alert');
    expect(await getAlert?.run({ id: '../../admin' })).toMatchObject({ ok: false });
    expect(called).toBe(false);
  });

  it('traduce 403/404 y 5xx a mensajes sin detalles internos y quita el correlationId', async () => {
    let status = 404;
    const tools = buildSocTools(
      async () => ({ status, body: { correlationId: 'c', items: [] } }),
      analyst,
    );
    const getAlert = tools.find((t) => t.name === 'get_alert');
    const notFound = await getAlert?.run({ id: 'a-1' });
    expect(notFound).toMatchObject({ ok: false });
    expect(JSON.stringify(notFound)).toContain('tu rol');
    status = 503;
    expect(await getAlert?.run({ id: 'a-1' })).toMatchObject({ ok: false });
    status = 200;
    const list = await tools.find((t) => t.name === 'list_alerts')?.run({});
    expect(list).toEqual({ ok: true, data: { items: [] } });
  });

  it('construye URLs acotadas con la paginación por defecto', async () => {
    const urls: string[] = [];
    const tools = buildSocTools(async (url) => {
      urls.push(url);
      return { status: 200, body: {} };
    }, analyst);
    await tools.find((t) => t.name === 'list_alerts')?.run({ priority: 'P1', status: 'open' });
    expect(urls[0]).toBe('/api/alerts?status=open&priority=P1&pageSize=10');
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
