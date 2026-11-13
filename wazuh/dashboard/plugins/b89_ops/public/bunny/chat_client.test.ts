/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  askBunny,
  askBunnyStream,
  citationPath,
  deleteAllConversations,
  deleteConversation,
  formatWhen,
  getConversation,
  HISTORY_TURNS,
  listConversations,
  loadBunnyConfigState,
  suggestionsFor,
} from './chat_client';
import type { B89ApiClient } from '../api/client';
import { B89ApiError } from '../api/client';

const ANSWER = { reply: 'ok', outcome: 'answered', steps: [], citations: [] } as const;

function streamResponse(chunks: readonly (string | Error)[]): Response {
  let index = 0;
  const reader = {
    read: jest.fn(async () => {
      const chunk = chunks[index++];
      if (chunk instanceof Error) throw chunk;
      if (chunk === undefined) return { done: true, value: undefined };
      return { done: false, value: new TextEncoder().encode(chunk) };
    }),
    releaseLock: jest.fn(),
  };
  return {
    status: 200,
    headers: { get: () => 'text/event-stream; charset=utf-8' },
    body: { getReader: () => reader },
  } as unknown as Response;
}

describe('citationPath', () => {
  it('lleva alertas e incidentes a su vista con el id codificado', () => {
    expect(citationPath({ kind: 'alert', id: 'a 1/2', label: 'x' })).toBe(
      '/app/b89-alerts?id=a%201%2F2',
    );
    expect(citationPath({ kind: 'incident', id: 'i-9', label: 'x' })).toBe(
      '/app/b89-incidents?id=i-9',
    );
  });

  it('fuentes y auditoría llevan a su vista; los eventos no tienen enlace', () => {
    expect(citationPath({ kind: 'source', id: 's', label: 'x' })).toBe('/app/b89-sources');
    expect(citationPath({ kind: 'audit', id: 'a', label: 'x' })).toBe('/app/b89-audit');
    expect(citationPath({ kind: 'event', id: 'e', label: 'x' })).toBeNull();
  });
});

describe('suggestionsFor', () => {
  it('cambia los ejemplos según la página y siempre ofrece alguno', () => {
    expect(suggestionsFor('/app/b89-incidents')[0]?.title).toBe('Incidentes activos');
    expect(suggestionsFor('/app/b89-sources')[0]?.title).toBe('Salud de fuentes');
    expect(suggestionsFor('/app/b89-audit').length).toBeGreaterThan(0);
    expect(suggestionsFor('/app/home').length).toBeGreaterThan(0);
  });
});

describe('askBunny', () => {
  it('envía solo los últimos turnos y la página actual', async () => {
    let body: { history: unknown[]; page: string; message: string } | undefined;
    const api = {
      post: async (_path: string, payload: typeof body) => {
        body = payload;
        return { reply: 'ok', outcome: 'answered', steps: [], citations: [] };
      },
    } as unknown as B89ApiClient;
    const history = Array.from({ length: 30 }, (_, index) => ({
      role: index % 2 === 0 ? ('user' as const) : ('assistant' as const),
      content: `m${index}`,
    }));
    await askBunny(api, 'hola', history, '/app/b89-alerts');
    expect(body?.history).toHaveLength(HISTORY_TURNS);
    expect(body?.page).toBe('/app/b89-alerts');
    expect(body?.message).toBe('hola');
  });
});

describe('Bunny config availability', () => {
  it('distingue servicio deshabilitado de configuración no disponible y permite reintentar', async () => {
    const get = jest.fn().mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce({
      enabled: false,
      name: 'Bunny',
    });
    const api = { get } as unknown as B89ApiClient;

    expect(await loadBunnyConfigState(api)).toEqual({ status: 'unavailable' });
    expect(await loadBunnyConfigState(api)).toEqual({
      status: 'ready',
      config: { enabled: false, name: 'Bunny' },
    });
  });
});

describe('askBunnyStream', () => {
  it('pasa la señal de cancelación al transporte SSE', async () => {
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    const api = {
      postStream: async (_path: string, _body: unknown, signal?: AbortSignal) => {
        observedSignal = signal;
        return streamResponse([
          `event: complete\ndata: ${JSON.stringify(ANSWER)}\n\n`,
        ]);
      },
    } as unknown as B89ApiClient;

    await askBunnyStream(api, 'pregunta', [], '/app/home', jest.fn(), undefined, controller.signal);
    expect(observedSignal).toBe(controller.signal);
  });

  it('usa JSON solo tras un rechazo explícito previo a aceptar el stream', async () => {
    const post = jest.fn().mockResolvedValue(ANSWER);
    const onProgress = jest.fn();
    const api = {
      postStream: jest.fn().mockRejectedValue(new B89ApiError('DEPENDENCY_DEGRADED', 415, null)),
      post,
    } as unknown as B89ApiClient;

    await expect(askBunnyStream(api, 'pregunta', [], '/app/home', onProgress)).resolves.toEqual(
      ANSWER,
    );
    expect(post).toHaveBeenCalledWith('/assistant/chat', {
      message: 'pregunta',
      history: [],
      page: '/app/home',
    });
    expect(onProgress).toHaveBeenCalledWith({ type: 'transport_fallback' });
  });

  it.each([
    new B89ApiError('DEPENDENCY_DEGRADED', 0, null),
    new B89ApiError('DEPENDENCY_DEGRADED', 502, null),
    new B89ApiError('RESOURCE_UNAVAILABLE', 404, 'api-correlation'),
  ])('no repite solicitudes en fallos ambiguos o procesados (%s)', async (error) => {
    const post = jest.fn();
    const api = { postStream: jest.fn().mockRejectedValue(error), post } as unknown as B89ApiClient;
    await expect(askBunnyStream(api, 'pregunta', [], '/app/home', jest.fn())).rejects.toBe(error);
    expect(post).not.toHaveBeenCalled();
  });

  it('no repite una llamada si se corta un stream aceptado parcialmente', async () => {
    const post = jest.fn();
    const api = {
      postStream: async () =>
        streamResponse([
          'event: started\ndata: {"correlationId":"corr-1"}\n\n',
          new TypeError('connection dropped'),
        ]),
      post,
    } as unknown as B89ApiClient;

    await expect(askBunnyStream(api, 'pregunta', [], '/app/home', jest.fn())).rejects.toThrow(
      'connection dropped',
    );
    expect(post).not.toHaveBeenCalled();
  });

  it('acepta una respuesta JSON completa del proxy sin volver a enviar la pregunta', async () => {
    const post = jest.fn();
    const response = {
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ANSWER,
    } as unknown as Response;
    const api = { postStream: jest.fn().mockResolvedValue(response), post } as unknown as B89ApiClient;

    await expect(askBunnyStream(api, 'pregunta', [], '/app/home', jest.fn())).resolves.toEqual(
      ANSWER,
    );
    expect(post).not.toHaveBeenCalled();
  });
});

describe('historial', () => {
  function recorder() {
    const calls: { method: string; path: string; body?: unknown; query?: unknown }[] = [];
    const api = {
      get: async (path: string, query?: unknown) => {
        calls.push({ method: 'GET', path, query });
        return { items: [], nextCursor: null };
      },
      delete: async (path: string) => {
        calls.push({ method: 'DELETE', path });
      },
      post: async (path: string, body: unknown) => {
        calls.push({ method: 'POST', path, body });
        return { reply: 'ok', outcome: 'answered', steps: [], citations: [] };
      },
    } as unknown as B89ApiClient;
    return { api, calls };
  }

  it('lista, abre y borra por las rutas del historial', async () => {
    const { api, calls } = recorder();
    await listConversations(api, 'c1');
    await getConversation(api, 'abc-123');
    await deleteConversation(api, 'abc-123');
    await deleteAllConversations(api);
    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      'GET /assistant/conversations',
      'GET /assistant/conversations/abc-123',
      'DELETE /assistant/conversations/abc-123',
      'DELETE /assistant/conversations',
    ]);
    expect(calls[0]?.query).toEqual({ pageSize: 30, cursor: 'c1' });
  });

  it('rechaza ids que podrían alterar la ruta', async () => {
    const { api } = recorder();
    await expect(getConversation(api, '../admin')).rejects.toThrow();
    await expect(deleteConversation(api, 'a/b')).rejects.toThrow();
  });

  it('continúa una conversación enviando su id', async () => {
    const { api, calls } = recorder();
    await askBunny(api, 'hola', [], '/app/x', 'conv-1');
    expect((calls[0]?.body as { conversationId?: string }).conversationId).toBe('conv-1');
    await askBunny(api, 'hola', [], '/app/x');
    expect(calls[1]?.body).not.toHaveProperty('conversationId');
  });

  it('formatea fechas relativas', () => {
    const now = new Date('2026-11-03T12:00:00Z');
    expect(formatWhen('2026-11-03T11:59:40Z', now)).toBe('ahora');
    expect(formatWhen('2026-11-03T11:30:00Z', now)).toBe('hace 30 min');
    expect(formatWhen('2026-11-03T09:00:00Z', now)).toBe('hace 3 h');
    expect(formatWhen('2026-11-02T10:00:00Z', now)).toBe('ayer');
    expect(formatWhen('2026-10-30T10:00:00Z', now)).toBe('hace 4 días');
    expect(formatWhen('no-es-fecha', now)).toBe('');
  });
});
