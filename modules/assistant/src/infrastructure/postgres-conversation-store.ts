/**
 * Adaptador PostgreSQL del historial de Bunny. Se publica como subpath
 * (`@b89/assistant/postgres`) para que el runtime en memoria no cargue Prisma.
 *
 * Los mensajes se guardan como arreglo `jsonb` con fechas ISO. Al leer, cada mensaje se valida
 * campo por campo: un valor fuera de forma se omite del campo opcional o, si rompe el mensaje,
 * se reporta como error de integridad (no se adivina).
 */

import {
  closeDatabaseClient,
  createDatabaseClient,
  type DatabaseConnectionOptions,
} from '@b89/database';
import {
  PrismaAssistantConversationStore,
  type AssistantConversationRow,
} from '@b89/database/assistant-conversation-stores';

import {
  assertStorableMessages,
  CONVERSATION_LIMITS,
  ConversationError,
  normalizeConversationTitle,
  type ConversationCursor,
  type ConversationOwner,
  type ConversationPage,
  type ConversationStore,
  type CreatedConversation,
  type NewConversation,
  type StoredConversation,
  type StoredMessage,
} from '../conversations.js';
import type { Citation } from '../ports.js';
import type { AssistantStep, ReasoningEntry } from '../run.js';

export class ConversationIntegrityError extends Error {
  public constructor() {
    super('Mensaje fuera de forma en assistant_conversations.messages.');
    this.name = 'ConversationIntegrityError';
  }
}

interface MessageJson {
  readonly id: string;
  readonly role: 'user' | 'assistant';
  readonly text: string;
  readonly createdAt: string;
  readonly reasoning?: readonly ReasoningEntry[];
  readonly steps?: readonly AssistantStep[];
  readonly citations?: readonly Citation[];
  readonly tone?: 'error' | 'notice';
}

function toJson(message: StoredMessage): MessageJson {
  return {
    id: message.id,
    role: message.role,
    text: message.text,
    createdAt: message.createdAt.toISOString(),
    ...(message.reasoning ? { reasoning: message.reasoning } : {}),
    ...(message.steps ? { steps: message.steps } : {}),
    ...(message.citations ? { citations: message.citations } : {}),
    ...(message.tone ? { tone: message.tone } : {}),
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function reasoningOf(value: unknown): ReasoningEntry[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.flatMap((entry): ReasoningEntry[] => {
    if (!isRecord(entry)) return [];
    if (entry['kind'] === 'thought' && typeof entry['text'] === 'string') {
      return [{ kind: 'thought', text: entry['text'] }];
    }
    if (
      entry['kind'] === 'tool' &&
      typeof entry['label'] === 'string' &&
      typeof entry['ok'] === 'boolean'
    ) {
      return [{ kind: 'tool', label: entry['label'], ok: entry['ok'] }];
    }
    return [];
  });
}

function stepsOf(value: unknown): AssistantStep[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.flatMap((entry): AssistantStep[] =>
    isRecord(entry) &&
    typeof entry['tool'] === 'string' &&
    typeof entry['label'] === 'string' &&
    typeof entry['ok'] === 'boolean'
      ? [{ tool: entry['tool'], label: entry['label'], ok: entry['ok'] }]
      : [],
  );
}

const CITATION_KINDS: readonly Citation['kind'][] = [
  'alert',
  'incident',
  'event',
  'source',
  'audit',
];

function citationsOf(value: unknown): Citation[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.flatMap((entry): Citation[] =>
    isRecord(entry) &&
    CITATION_KINDS.includes(entry['kind'] as Citation['kind']) &&
    typeof entry['id'] === 'string' &&
    typeof entry['label'] === 'string'
      ? [{ kind: entry['kind'] as Citation['kind'], id: entry['id'], label: entry['label'] }]
      : [],
  );
}

function fromJson(value: unknown): StoredMessage {
  if (
    !isRecord(value) ||
    typeof value['id'] !== 'string' ||
    (value['role'] !== 'user' && value['role'] !== 'assistant') ||
    typeof value['text'] !== 'string' ||
    typeof value['createdAt'] !== 'string'
  ) {
    throw new ConversationIntegrityError();
  }
  const createdAt = new Date(value['createdAt']);
  if (Number.isNaN(createdAt.getTime())) throw new ConversationIntegrityError();
  const reasoning = reasoningOf(value['reasoning']);
  const steps = stepsOf(value['steps']);
  const citations = citationsOf(value['citations']);
  const tone = value['tone'] === 'error' || value['tone'] === 'notice' ? value['tone'] : undefined;
  return {
    id: value['id'],
    role: value['role'],
    text: value['text'],
    createdAt,
    ...(reasoning ? { reasoning } : {}),
    ...(steps ? { steps } : {}),
    ...(citations ? { citations } : {}),
    ...(tone ? { tone } : {}),
  };
}

function messagesOf(row: AssistantConversationRow): StoredMessage[] {
  if (!Array.isArray(row.messages)) throw new ConversationIntegrityError();
  return row.messages.map(fromJson);
}

function toConversation(row: AssistantConversationRow): StoredConversation {
  return {
    id: row.id,
    tenantId: row.tenantId,
    ownerId: row.ownerId,
    title: row.title,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    messages: messagesOf(row),
  };
}

/** Un id que no es UUID no puede existir: se responde como inexistente sin consultar. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

/** Reintentos del compare-and-set de `append` ante escrituras concurrentes. */
const APPEND_ATTEMPTS = 3;

export class PostgresConversationStore implements ConversationStore {
  private constructor(
    private readonly store: PrismaAssistantConversationStore,
    private readonly closeClient: () => Promise<void>,
  ) {}

  public static connect(options: DatabaseConnectionOptions): PostgresConversationStore {
    const client = createDatabaseClient(options);
    return new PostgresConversationStore(new PrismaAssistantConversationStore(client), () =>
      closeDatabaseClient(client),
    );
  }

  public async list(
    owner: ConversationOwner,
    options: { readonly limit?: number; readonly after?: ConversationCursor } = {},
  ): Promise<ConversationPage> {
    const limit = Math.max(
      1,
      Math.min(options.limit ?? 50, CONVERSATION_LIMITS.maxConversationsPerOwner),
    );
    const rows = await this.store.list(owner, limit + 1, options.after);
    const items = rows.slice(0, limit);
    const last = items.at(-1);
    return {
      items,
      next: rows.length > limit && last ? { updatedAt: last.updatedAt, id: last.id } : null,
    };
  }

  public async get(owner: ConversationOwner, id: string): Promise<StoredConversation | undefined> {
    if (!UUID.test(id)) return undefined;
    const row = await this.store.get(owner, id);
    return row ? toConversation(row) : undefined;
  }

  public async create(
    owner: ConversationOwner,
    draft: NewConversation,
  ): Promise<CreatedConversation> {
    assertStorableMessages(draft.messages);
    const lastAt = draft.messages.at(-1)?.createdAt ?? draft.createdAt;
    const conversation: StoredConversation = {
      id: draft.id,
      tenantId: owner.tenantId,
      ownerId: owner.ownerId,
      title: draft.title,
      createdAt: draft.createdAt,
      updatedAt: lastAt > draft.createdAt ? lastAt : draft.createdAt,
      messages: [...draft.messages],
    };
    const evicted = await this.store.create(
      {
        ...conversation,
        messageCount: conversation.messages.length,
        messages: conversation.messages.map(toJson),
      },
      CONVERSATION_LIMITS.maxConversationsPerOwner,
    );
    return { conversation, evicted };
  }

  public async append(
    owner: ConversationOwner,
    id: string,
    messages: readonly StoredMessage[],
    at: Date,
  ): Promise<StoredConversation | undefined> {
    if (!UUID.test(id)) return undefined;
    for (let attempt = 0; attempt < APPEND_ATTEMPTS; attempt += 1) {
      const row = await this.store.get(owner, id);
      if (!row) return undefined;
      const current = messagesOf(row);
      assertStorableMessages(messages, current.length);
      const next = [...current, ...messages];
      const written = await this.store.replaceMessages(
        owner,
        id,
        row.messageCount,
        next.map(toJson),
        next.length,
        at,
      );
      if (written) return { ...toConversation(row), updatedAt: at, messages: next };
    }
    throw new ConversationError('CONFLICT');
  }

  public async rename(owner: ConversationOwner, id: string, title: string): Promise<boolean> {
    if (!UUID.test(id)) return false;
    return this.store.rename(owner, id, normalizeConversationTitle(title));
  }

  public async delete(owner: ConversationOwner, id: string): Promise<boolean> {
    if (!UUID.test(id)) return false;
    return this.store.delete(owner, id);
  }

  public deleteAllByOwner(owner: ConversationOwner): Promise<number> {
    return this.store.deleteAllByOwner(owner);
  }

  public purgeOlderThan(tenantId: string, cutoff: Date): Promise<number> {
    return this.store.purgeOlderThan(tenantId, cutoff);
  }

  public close(): Promise<void> {
    return this.closeClient();
  }
}
