/**
 * Bunny, el asistente de IA de B89 SOC: `POST /api/assistant/chat` y el historial de
 * conversaciones (`/api/assistant/conversations`).
 *
 * Reglas:
 * - Exige sesión; las mutaciones (chat, renombrar, borrar) exigen además el token CSRF.
 * - Solo ofrece herramientas que la persona podría usar y las ejecuta **con su propia sesión**
 *   (`internal-client.ts`): la autorización y las redacciones son las de la API, no las de Bunny.
 * - Sin `B89_BUNNY_ENABLED=true` responde 404 (`RESOURCE_UNAVAILABLE`).
 * - Historial (`B89_BUNNY_HISTORY_ENABLED`, defecto `true`): cada conversación pertenece a
 *   (tenant, `subjectId`) y solo su dueño la lista, lee, continúa, renombra o borra; ni un
 *   administrador ve las ajenas. Un id ajeno o vencido responde igual que uno inexistente.
 *   Apagado, el chat no guarda y los endpoints del historial responden 404.
 * - Con historial activo el servidor usa el historial **guardado** (o ninguno, si la conversación
 *   es nueva) e ignora el `history` del cliente, que solo se usa con el historial apagado
 *   (compatibilidad). El turno se guarda después de obtener
 *   la respuesta, en una sola escritura; si falla, la respuesta sale igual con `saved: false`.
 * - Auditoría: `assistant.ask` por pregunta (herramientas usadas), `assistant.conversation.delete`
 *   y `assistant.conversation.purge` con conteos. El texto nunca va a auditoría ni a logs.
 */

import { randomUUID } from 'node:crypto';

import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  Param,
  Patch,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import {
  AssistantInputError,
  CONVERSATION_LIMITS,
  Pseudonymizer,
  clampStoredText,
  conversationTitleFrom,
  normalizeConversationTitle,
  runAssistant,
  type AssistantResult,
  type ConversationOwner,
  type StoredConversation,
  type StoredMessage,
} from '@b89/assistant';

import { ApiError } from '../http/api-error.js';
import type { IncomingRequest } from '../http/http-contracts.js';
import { paginate, type PageQuery } from '../http/pagination.js';
import { mutatingActor, readingActor } from '../soc/session-actor.js';
import { SECOPS_RUNTIME } from '../soc/tokens.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';
import type { AssistantService } from './assistant-service.js';
import { auditConversationRemoval, type ConversationHistory } from './conversation-history.js';
import { createInternalGet } from './internal-client.js';
import { buildSocTools } from './soc-tools.js';

/** Capacidades de lectura: haber una basta para usar a Bunny (las herramientas filtran el resto). */
const READ_CAPABILITIES = [
  'alerts.read',
  'incidents.read',
  'events.read',
  'sources.health.read',
  'notifications.read',
  'audit.read',
  'observability.read_soc',
  'users.read',
] as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

interface ChatBody {
  message?: unknown;
  history?: unknown;
  page?: unknown;
  conversationId?: unknown;
}

interface Actor {
  readonly subjectId: string;
  readonly tenantId: string;
  readonly capabilities: ReadonlySet<string>;
}

function parseHistory(
  value: unknown,
): { role: 'user' | 'assistant'; content: string }[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 60) return undefined;
  const history: { role: 'user' | 'assistant'; content: string }[] = [];
  for (const entry of value as unknown[]) {
    const item = entry as { role?: unknown; content?: unknown };
    if ((item.role !== 'user' && item.role !== 'assistant') || typeof item.content !== 'string') {
      return undefined;
    }
    history.push({ role: item.role, content: item.content });
  }
  return history;
}

function canUseBunny(service: AssistantService | undefined, actor: Actor): boolean {
  return (
    service !== undefined &&
    READ_CAPABILITIES.some((capability) => actor.capabilities.has(capability))
  );
}

function ownerOf(actor: Actor): ConversationOwner {
  return { tenantId: actor.tenantId, ownerId: actor.subjectId };
}

/** Mensaje tal como lo recibe la interfaz. */
function messageView(message: StoredMessage) {
  return {
    id: message.id,
    role: message.role,
    text: message.text,
    ...(message.reasoning ? { reasoning: message.reasoning } : {}),
    ...(message.steps ? { steps: message.steps } : {}),
    ...(message.citations ? { citations: message.citations } : {}),
    ...(message.tone ? { tone: message.tone } : {}),
    createdAt: message.createdAt.toISOString(),
  };
}

/** Respuesta del modelo lista para guardar: textos recortados al máximo almacenable. */
function assistantMessage(result: AssistantResult, at: Date): StoredMessage {
  const max = CONVERSATION_LIMITS.maxEntriesPerMessage;
  return {
    id: randomUUID(),
    role: 'assistant',
    text: clampStoredText(result.reply),
    reasoning: result.reasoning
      .slice(0, max)
      .map((entry) =>
        entry.kind === 'thought' ? { kind: 'thought', text: clampStoredText(entry.text) } : entry,
      ),
    steps: result.steps.slice(0, max),
    citations: result.citations.slice(0, max),
    ...(result.outcome === 'refused' ? { tone: 'notice' as const } : {}),
    createdAt: at,
  };
}

@Controller('api/assistant')
export class AssistantController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  /** La consola pregunta si Bunny está disponible para mostrar o no el botón. */
  @Get('config')
  public async config(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const service = this.runtime.assistant;
    const available = canUseBunny(service, actor);
    return {
      correlationId,
      enabled: available,
      name: 'Bunny',
      ...(available && service
        ? {
            readOnly: true,
            redactsPersonalData: service.config.redactPii,
            history: service.history !== undefined,
            ...(service.history ? { retentionDays: service.history.retentionDays } : {}),
          }
        : {}),
    };
  }

  @Post('chat')
  @HttpCode(200)
  public async chat(@Req() request: IncomingRequest, @Body() body: ChatBody | undefined) {
    const { actor, session, correlationId } = await mutatingActor(this.runtime, request);
    const service = this.runtime.assistant;
    if (!service || !canUseBunny(service, actor)) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const message = typeof body?.message === 'string' ? body.message : undefined;
    const clientHistory = parseHistory(body?.history);
    const page = typeof body?.page === 'string' ? body.page.slice(0, 200) : undefined;
    const rawConversationId = body?.conversationId;
    if (message === undefined) throw new ApiError('VALIDATION_FAILED', correlationId, ['message']);
    if (clientHistory === undefined) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['history']);
    }
    if (
      rawConversationId !== undefined &&
      rawConversationId !== null &&
      (typeof rawConversationId !== 'string' || !UUID.test(rawConversationId))
    ) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['conversationId']);
    }
    const conversationId = typeof rawConversationId === 'string' ? rawConversationId : undefined;
    if (!service.limiter.take(actor.subjectId, this.runtime.now().getTime())) {
      throw new ApiError('RATE_LIMITED', correlationId);
    }

    const history = service.history;
    const owner = ownerOf(actor);
    let stored: StoredConversation | undefined;
    if (conversationId !== undefined) {
      // Sin historial no hay conversaciones que continuar.
      if (!history) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
      stored = await this.ownedConversation(history, owner, conversationId, correlationId);
      if (stored.messages.length + 2 > CONVERSATION_LIMITS.maxMessagesPerConversation) {
        // Conversación llena: la interfaz debe ofrecer empezar una nueva.
        throw new ApiError('VALIDATION_FAILED', correlationId, ['messageLimit']);
      }
    }

    const server = this.runtime.internalServer;
    if (!server) throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    const capabilities = [...actor.capabilities].sort();
    const tools = buildSocTools(createInternalGet(server, request), {
      roles: actor.roles,
      capabilities,
    });
    // Con historial activo manda el servidor: el del cliente se ignora (una conversación nueva
    // empieza vacía) para que lo guardado sea exactamente lo que vio el modelo. Sin historial,
    // el del cliente sigue sirviendo por compatibilidad.
    const turnHistory = stored
      ? stored.messages
          .filter((entry) => entry.tone === undefined)
          .map((entry) => ({ role: entry.role, content: entry.text }))
      : history
        ? []
        : clientHistory;
    const askedAt = this.runtime.now();
    let result: AssistantResult;
    try {
      result = await runAssistant({
        model: service.model,
        tools,
        turn: {
          message,
          history: turnHistory,
          context: {
            displayName: session.displayName,
            roles: actor.roles,
            capabilities,
            ...(page ? { page } : {}),
          },
        },
        pseudonymizer: new Pseudonymizer(service.config.redactPii),
        now: () => this.runtime.now(),
      });
      await this.runtime.auditAssistant(actor.subjectId, correlationId, 'succeeded', [
        ...new Set(result.steps.map((step) => step.tool)),
      ]);
    } catch (error) {
      if (error instanceof AssistantInputError) {
        throw new ApiError('VALIDATION_FAILED', correlationId, ['message']);
      }
      await this.runtime.auditAssistant(actor.subjectId, correlationId, 'failed', []);
      // Sin detalles del proveedor: el motivo interno no sale de la API.
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    }

    const saved = history
      ? await this.saveTurn(history, owner, stored, message, askedAt, result, correlationId)
      : undefined;
    return {
      correlationId,
      reply: result.reply,
      reasoning: result.reasoning,
      outcome: result.outcome,
      steps: result.steps,
      citations: result.citations,
      usage: result.usage,
      conversationId: saved?.id ?? null,
      title: saved?.title ?? null,
      saved: saved?.saved ?? false,
    };
  }

  @Get('conversations')
  public async listConversations(@Req() request: IncomingRequest, @Query() query: PageQuery) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const history = this.historyFor(actor, correlationId);
    await history.purgeExpired(
      this.runtime.audit,
      actor.tenantId,
      this.runtime.now(),
      correlationId,
    );
    const all = await this.guarded(correlationId, () =>
      history.store.list(ownerOf(actor), {
        limit: CONVERSATION_LIMITS.maxConversationsPerOwner,
      }),
    );
    const cutoff = history.cutoff(this.runtime.now());
    const page = paginate(
      all.items.filter((item) => item.updatedAt >= cutoff),
      (item) => ({ at: item.updatedAt.getTime(), id: item.id }),
      query,
      'assistant-conversations',
      correlationId,
    );
    return {
      correlationId,
      items: page.items.map((item) => ({
        id: item.id,
        title: item.title,
        updatedAt: item.updatedAt.toISOString(),
        messageCount: item.messageCount,
      })),
      nextCursor: page.nextCursor,
    };
  }

  @Get('conversations/:id')
  public async getConversation(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const history = this.historyFor(actor, correlationId);
    const conversation = await this.ownedConversation(history, ownerOf(actor), id, correlationId);
    return {
      correlationId,
      id: conversation.id,
      title: conversation.title,
      createdAt: conversation.createdAt.toISOString(),
      updatedAt: conversation.updatedAt.toISOString(),
      messages: conversation.messages.map(messageView),
    };
  }

  @Patch('conversations/:id')
  public async renameConversation(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body() body: { title?: unknown } | undefined,
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    const history = this.historyFor(actor, correlationId);
    let title: string;
    try {
      title = normalizeConversationTitle(body?.title);
    } catch {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['title']);
    }
    const owner = ownerOf(actor);
    // Una conversación vencida no se renombra: se comporta como inexistente.
    await this.ownedConversation(history, owner, id, correlationId);
    const store = history.store;
    const renamed = store.rename
      ? await this.guarded(correlationId, () => store.rename!(owner, id, title))
      : false;
    if (!renamed) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    return { correlationId, id, title };
  }

  @Delete('conversations/:id')
  @HttpCode(200)
  public async deleteConversation(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    const history = this.historyFor(actor, correlationId);
    const deleted = UUID.test(id)
      ? await this.guarded(correlationId, () => history.store.delete(ownerOf(actor), id))
      : false;
    if (!deleted) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    await auditConversationRemoval(this.runtime.audit, {
      tenantId: actor.tenantId,
      actor: { id: actor.subjectId, type: 'user' },
      action: 'assistant.conversation.delete',
      resourceId: id,
      count: 1,
      correlationId,
      at: this.runtime.now(),
    });
    return { correlationId, deleted: 1 };
  }

  /** Borra todo mi historial (y solo el mío). */
  @Delete('conversations')
  @HttpCode(200)
  public async deleteAllConversations(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    const history = this.historyFor(actor, correlationId);
    const deleted = await this.guarded(correlationId, () =>
      history.store.deleteAllByOwner(ownerOf(actor)),
    );
    if (deleted > 0) {
      await auditConversationRemoval(this.runtime.audit, {
        tenantId: actor.tenantId,
        actor: { id: actor.subjectId, type: 'user' },
        action: 'assistant.conversation.delete',
        resourceId: 'all',
        count: deleted,
        correlationId,
        at: this.runtime.now(),
      });
    }
    return { correlationId, deleted };
  }

  /** Historial disponible para esta persona, o 404 (Bunny o historial apagados, sin permisos). */
  private historyFor(actor: Actor, correlationId: string): ConversationHistory {
    const service = this.runtime.assistant;
    if (!service?.history || !canUseBunny(service, actor)) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    return service.history;
  }

  /** La conversación si es mía y no venció; si no, la misma respuesta que una inexistente. */
  private async ownedConversation(
    history: ConversationHistory,
    owner: ConversationOwner,
    id: string,
    correlationId: string,
  ): Promise<StoredConversation> {
    const conversation = UUID.test(id)
      ? await this.guarded(correlationId, () => history.store.get(owner, id))
      : undefined;
    if (!conversation || conversation.updatedAt < history.cutoff(this.runtime.now())) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    return conversation;
  }

  /** Un fallo del almacén sale como dependencia degradada, sin detalles internos. */
  private async guarded<T>(correlationId: string, work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch {
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    }
  }

  /**
   * Guarda el turno (pregunta + respuesta) en una sola escritura. Nunca falla hacia el chat:
   * si el almacén no responde, `saved: false` y la respuesta sale igual.
   */
  private async saveTurn(
    history: ConversationHistory,
    owner: ConversationOwner,
    stored: StoredConversation | undefined,
    question: string,
    askedAt: Date,
    result: AssistantResult,
    correlationId: string,
  ): Promise<{ id: string | null; title: string | null; saved: boolean }> {
    const answeredAt = this.runtime.now();
    const turn: StoredMessage[] = [
      { id: randomUUID(), role: 'user', text: question.trim(), createdAt: askedAt },
      assistantMessage(result, answeredAt),
    ];
    let outcome: { id: string | null; title: string | null; saved: boolean };
    let evicted = 0;
    try {
      if (stored) {
        const updated = await history.store.append(owner, stored.id, turn, answeredAt);
        outcome = { id: stored.id, title: stored.title, saved: updated !== undefined };
      } else {
        const created = await history.store.create(owner, {
          id: randomUUID(),
          title: conversationTitleFrom(question),
          createdAt: askedAt,
          messages: turn,
        });
        outcome = { id: created.conversation.id, title: created.conversation.title, saved: true };
        evicted = created.evicted;
      }
    } catch {
      // Topes del dominio o almacén caído: la respuesta ya existe y se entrega sin guardar.
      outcome = stored
        ? { id: stored.id, title: stored.title, saved: false }
        : { id: null, title: null, saved: false };
    }
    if (evicted > 0) {
      // Tope de conversaciones por persona: se descartaron las menos recientes.
      await auditConversationRemoval(this.runtime.audit, {
        tenantId: owner.tenantId,
        actor: { id: owner.ownerId, type: 'user' },
        action: 'assistant.conversation.purge',
        resourceId: 'limit',
        count: evicted,
        reason: `limit:${CONVERSATION_LIMITS.maxConversationsPerOwner}`,
        correlationId,
        at: answeredAt,
      }).catch(() => undefined);
    }
    await history.purgeExpired(this.runtime.audit, owner.tenantId, answeredAt, correlationId);
    return outcome;
  }
}
