/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { B89ApiClient } from '../api/client';

export interface BunnyConfig {
  readonly enabled: boolean;
  readonly name: string;
  readonly readOnly?: boolean;
  readonly redactsPersonalData?: boolean;
}

export interface BunnyStep {
  readonly tool: string;
  readonly label: string;
  readonly ok: boolean;
}

export interface BunnyCitation {
  readonly kind: 'alert' | 'incident' | 'event' | 'source' | 'audit';
  readonly id: string;
  readonly label: string;
}

/** Línea de tiempo del razonamiento: lo que pensó Bunny y lo que consultó, en orden. */
export type BunnyReasoning =
  | { readonly kind: 'thought'; readonly text: string }
  | { readonly kind: 'tool'; readonly label: string; readonly ok: boolean };

export interface BunnyReply {
  readonly conversationId?: string;
  readonly title?: string;
  /** `false` si la respuesta no pudo guardarse en el historial. */
  readonly saved?: boolean;
  readonly reasoning?: readonly BunnyReasoning[];
  readonly reply: string;
  readonly outcome: 'answered' | 'budget' | 'refused' | 'truncated';
  readonly steps: readonly BunnyStep[];
  readonly citations: readonly BunnyCitation[];
}

export interface BunnyTurn {
  readonly role: 'user' | 'assistant';
  readonly content: string;
}

/** Cuántos turnos previos viajan con cada pregunta (la API vuelve a recortar). */
export const HISTORY_TURNS = 12;

export function fetchBunnyConfig(api: B89ApiClient): Promise<BunnyConfig> {
  return api.get<BunnyConfig>('/assistant/config');
}

export function askBunny(
  api: B89ApiClient,
  message: string,
  history: readonly BunnyTurn[],
  page: string,
  conversationId?: string,
): Promise<BunnyReply> {
  return api.post<BunnyReply>('/assistant/chat', {
    message,
    // Con `conversationId` el servidor usa el historial guardado e ignora este.
    history: history.slice(-HISTORY_TURNS),
    page,
    ...(conversationId ? { conversationId } : {}),
  });
}

export interface ConversationSummary {
  readonly id: string;
  readonly title: string;
  readonly updatedAt: string;
  readonly messageCount: number;
}

export interface ConversationList {
  readonly items: readonly ConversationSummary[];
  readonly nextCursor: string | null;
}

export interface StoredMessage {
  readonly id: string | number;
  readonly role: 'user' | 'assistant';
  readonly text: string;
  readonly reasoning?: readonly BunnyReasoning[];
  readonly steps?: readonly BunnyStep[];
  readonly citations?: readonly BunnyCitation[];
  readonly tone?: 'error' | 'notice';
  readonly createdAt?: string;
}

export interface StoredConversation {
  readonly id: string;
  readonly title: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly messages: readonly StoredMessage[];
}

const ID = /^[A-Za-z0-9-]{1,64}$/u;

function conversationPath(id: string): string {
  if (!ID.test(id)) throw new Error('Identificador de conversación no válido');
  return `/assistant/conversations/${id}`;
}

export function listConversations(api: B89ApiClient, cursor?: string): Promise<ConversationList> {
  return api.get<ConversationList>('/assistant/conversations', {
    pageSize: 30,
    ...(cursor ? { cursor } : {}),
  });
}

export async function getConversation(api: B89ApiClient, id: string): Promise<StoredConversation> {
  return api.get<StoredConversation>(conversationPath(id));
}

export async function deleteConversation(api: B89ApiClient, id: string): Promise<void> {
  return api.delete<void>(conversationPath(id));
}

export function deleteAllConversations(api: B89ApiClient): Promise<void> {
  return api.delete<void>('/assistant/conversations');
}

/** «hace 5 min», «ayer»… para la lista del historial (sin dependencias de i18n). */
export function formatWhen(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return '';
  const minutes = Math.floor((now.getTime() - then.getTime()) / 60000); // sin separador `_`: el webpack 4 de OSD 2.19 no lo parsea
  if (minutes < 1) return 'ahora';
  if (minutes < 60) return `hace ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `hace ${hours} h`;
  const days = Math.floor(hours / 24);
  if (days === 1) return 'ayer';
  if (days < 7) return `hace ${days} días`;
  return then.toLocaleDateString('es-PE', { day: 'numeric', month: 'short' });
}

/** Ruta de la consola para abrir lo que Bunny citó; `null` si no hay vista para ese tipo. */
export function citationPath(citation: BunnyCitation): string | null {
  switch (citation.kind) {
    case 'alert':
      return `/app/b89-alerts?id=${encodeURIComponent(citation.id)}`;
    case 'incident':
      return `/app/b89-incidents?id=${encodeURIComponent(citation.id)}`;
    case 'source':
      return '/app/b89-sources';
    case 'audit':
      return '/app/b89-audit';
    default:
      return null;
  }
}

export interface Suggestion {
  readonly title: string;
  readonly prompt: string;
}

/** Ejemplos según la página: Bunny es sensible al contexto, como Amazon Q. */
export function suggestionsFor(page: string): readonly Suggestion[] {
  if (page.includes('b89-incidents')) {
    return [
      {
        title: 'Incidentes activos',
        prompt: '¿Qué incidentes siguen activos y cuál es el más urgente?',
      },
      {
        title: 'Resumir un caso',
        prompt: 'Resume el incidente abierto: qué pasó, estado y siguientes pasos.',
      },
      { title: 'Tareas pendientes', prompt: '¿Qué tareas pendientes hay en mis incidentes?' },
    ];
  }
  if (page.includes('b89-sources')) {
    return [
      {
        title: 'Salud de fuentes',
        prompt: '¿Hay fuentes de datos degradadas o sin eventos recientes?',
      },
      { title: 'Última recepción', prompt: '¿Cuándo llegó el último evento de cada fuente?' },
    ];
  }
  if (page.includes('b89-audit')) {
    return [
      {
        title: 'Cambios de acceso',
        prompt: '¿Quién cambió roles o accesos en los últimos 7 días?',
      },
      { title: 'Integridad', prompt: 'Verifica la integridad de la cadena de auditoría.' },
    ];
  }
  return [
    { title: 'Alertas P1', prompt: '¿Cuáles son las alertas P1 abiertas ahora mismo?' },
    { title: 'Resumen del día', prompt: 'Dame un resumen de lo más importante en el SOC hoy.' },
    { title: 'Salud de fuentes', prompt: '¿Hay fuentes de datos con problemas?' },
    {
      title: 'Inicios de sesión fallidos',
      prompt: 'Busca inicios de sesión fallidos en las últimas 24 horas.',
    },
  ];
}
