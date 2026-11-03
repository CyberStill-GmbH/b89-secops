/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import {
  askBunny,
  citationPath,
  deleteAllConversations,
  deleteConversation,
  formatWhen,
  getConversation,
  HISTORY_TURNS,
  listConversations,
  suggestionsFor,
} from './chat_client';
import type { B89ApiClient } from '../api/client';

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
