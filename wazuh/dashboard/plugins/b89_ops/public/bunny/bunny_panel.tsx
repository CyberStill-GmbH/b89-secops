/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import type { CoreStart } from '../../../../src/core/public';
import type { BunnyAskDetail } from '../../common';
import { BRAND_ASSETS_PATH, BUNNY_ASK_EVENT, CAPABILITIES } from '../../common';
import { B89ApiError } from '../api/client';
import type { B89ApiClient } from '../api/client';
import type {
  BunnyCitation,
  BunnyConfig,
  BunnyConfigState,
  BunnyFeedback,
  BunnyProgressEvent,
  BunnyStep,
  BunnyUsage,
  BunnyTurn,
  ConversationSummary,
} from './chat_client';
import {
  askBunnyStream,
  citationPath,
  deleteAllConversations,
  deleteConversation,
  fetchBunnyUsage,
  formatWhen,
  getConversation,
  loadBunnyConfigState,
  listConversations,
  rateMessage,
  suggestionsFor,
} from './chat_client';
import { renderMarkdown } from './markdown';
import { BunnyReportActions } from './bunny_report_actions';
import { BunnyThinking } from './bunny_thinking';

/**
 * Bunny, el asistente de IA de B89 SOC. Panel lateral a la derecha al estilo de Amazon Q en la
 * consola de AWS: se abre desde la cabecera, se ajusta a la pantalla, saluda con
 * ejemplos de la página actual, muestra las consultas realizadas, cita lo
 * que afirma con enlaces a la consola y guarda las conversaciones en un historial que se puede
 * reabrir y borrar. Es de solo lectura y responde con los permisos de la persona.
 */

const MAX_CHARS = 4000;
const NAME = 'Bunny';

interface Message {
  readonly id: number;
  readonly role: 'user' | 'assistant';
  readonly text: string;
  readonly steps?: readonly BunnyStep[];
  readonly citations?: readonly BunnyCitation[];
  readonly tone?: 'error' | 'notice';
  /** Id del mensaje guardado en el historial (necesario para la valoración). */
  readonly serverId?: string;
  readonly feedback?: BunnyFeedback;
}

/** Página de contexto para una pregunta abierta desde una vista («Preguntar a Bunny»). */
export function contextPage(context: BunnyAskDetail['context']): string | null {
  const alertId = context?.['alertId'];
  if (alertId && /^[A-Za-z0-9_-]{1,64}$/u.test(alertId)) {
    return `/app/b89-alerts?id=${encodeURIComponent(alertId)}`;
  }
  const incidentId = context?.['incidentId'];
  if (incidentId && /^[A-Za-z0-9_-]{1,64}$/u.test(incidentId)) {
    return `/app/b89-incidents?id=${encodeURIComponent(incidentId)}`;
  }
  return null;
}

/** Valoración 👍/👎 de una respuesta guardada; se persiste con la conversación. */
function Feedback({
  value,
  disabled,
  onRate,
}: {
  value?: BunnyFeedback;
  disabled: boolean;
  onRate: (rating: BunnyFeedback | null) => void;
}) {
  return (
    <span className="b89Bunny__feedback" role="group" aria-label="Valora esta respuesta">
      <button
        type="button"
        className={value === 'up' ? 'is-active' : ''}
        aria-pressed={value === 'up'}
        title="Respuesta útil"
        disabled={disabled}
        onClick={() => onRate(value === 'up' ? null : 'up')}
      >
        👍
      </button>
      <button
        type="button"
        className={value === 'down' ? 'is-active' : ''}
        aria-pressed={value === 'down'}
        title="Respuesta incorrecta o poco útil"
        disabled={disabled}
        onClick={() => onRate(value === 'down' ? null : 'down')}
      >
        👎
      </button>
    </span>
  );
}

type View = 'chat' | 'history' | 'usage';

/** Estado compartido entre el botón de la cabecera y el panel (ambos montan por separado). */
export class BunnyState {
  private open = false;
  private readonly listeners = new Set<() => void>();
  public isOpen(): boolean {
    return this.open;
  }
  public set(open: boolean): void {
    if (this.open === open) return;
    this.open = open;
    this.listeners.forEach((listener) => listener());
  }
  public toggle(): void {
    this.set(!this.open);
  }
  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

function useBunnyOpen(state: BunnyState): boolean {
  const [open, setOpen] = useState(state.isOpen());
  useEffect(() => state.subscribe(() => setOpen(state.isOpen())), [state]);
  return open;
}

function errorText(error: unknown): string {
  if (error instanceof B89ApiError) {
    if (error.code === 'RATE_LIMITED') {
      return 'Hiciste muchas preguntas seguidas. Espera unos minutos y vuelve a intentarlo.';
    }
    if (error.code === 'DEPENDENCY_DEGRADED') {
      return 'Bunny no pudo conectar con el modelo de IA ahora mismo. Inténtalo de nuevo en un momento.';
    }
    if (error.code === 'VALIDATION_FAILED') {
      return 'Esa pregunta no es válida (¿está vacía o es muy larga?).';
    }
    if (error.code === 'RESOURCE_UNAVAILABLE') return 'Bunny no está disponible con tu rol.';
  }
  return 'No pude responder. Inténtalo de nuevo.';
}

function reportNoteBody(message: Message): string {
  const citations = (message.citations ?? [])
    .map((citation) => `- ${citation.kind}: ${citation.label} (ID ${citation.id})`)
    .join('\n');
  const body = [
    'BORRADOR PRELIMINAR ASISTIDO POR IA. Requiere revisión humana antes de compartir o decidir.',
    `Generado: ${new Date().toISOString()}`,
    '',
    message.text,
    '',
    'Fuentes citadas',
    citations || 'Sin fuentes citadas; verificar antes de utilizar.',
  ].join('\n');
  return body.length <= 10000
    ? body
    : `${body.slice(0, 9950)}\n[Truncado al límite de notas del incidente]`;
}

export function BunnyLauncher({ state, imageUrl }: { state: BunnyState; imageUrl: string }) {
  const open = useBunnyOpen(state);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    const button = buttonRef.current;
    if (!button) return;
    // React 16 delegates clicks at document. OUI can stop bubbling in the chrome,
    // so bind at the button itself and keep a single toggle handler.
    const toggle = () => state.toggle();
    button.addEventListener('click', toggle);
    return () => button.removeEventListener('click', toggle);
  }, [state]);
  return (
    <button
      type="button"
      className={`b89Bunny__launcher${open ? ' b89Bunny__launcher--open' : ''}`}
      aria-label={`${NAME}, asistente de IA. ${open ? 'Cerrar' : 'Abrir'} el panel`}
      aria-expanded={open}
      aria-controls="b89-bunny-panel"
      title={`${NAME}, asistente de IA`}
      data-test-subj="b89BunnyLauncher"
      ref={buttonRef}
    >
      <img src={imageUrl} alt="" width={30} height={30} />
    </button>
  );
}

/** Actividad visible limitada a pasos de herramientas que realmente ejecutó el servidor. */
function Activity({ steps }: { steps?: readonly BunnyStep[] }) {
  const [shown, setShown] = useState(false);
  if (!steps || steps.length === 0) return null;
  return (
    <div className="b89Bunny__activity">
      <button type="button" aria-expanded={shown} onClick={() => setShown(!shown)}>
        <span aria-hidden="true">{shown ? '▾' : '▸'}</span> {shown ? 'Ocultar' : 'Mostrar'}{' '}
        actividad
      </button>
      {shown && (
        <ol>
          {steps.map((step, index) => (
            <li key={`${step.tool}-${index}`} className={step.ok ? 'is-ok' : 'is-failed'}>
              <span aria-hidden="true">{step.ok ? '✓' : '✕'}</span> {step.label}
              {step.ok ? '' : ' (sin resultado)'}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function Sources({
  citations,
  open,
}: {
  citations: readonly BunnyCitation[];
  open: (path: string) => void;
}) {
  if (citations.length === 0) return null;
  return (
    <div className="b89Bunny__sources" aria-label="Fuentes">
      <span>Fuentes</span>
      {citations.slice(0, 8).map((citation) => {
        const path = citationPath(citation);
        const label = `${citation.kind === 'alert' ? 'Alerta' : citation.kind === 'incident' ? 'Incidente' : 'SOC'} ${citation.id}`;
        return path ? (
          <button
            type="button"
            key={`${citation.kind}:${citation.id}`}
            title={citation.label}
            onClick={() => open(path)}
          >
            {label}
          </button>
        ) : (
          <em key={`${citation.kind}:${citation.id}`}>{label}</em>
        );
      })}
    </div>
  );
}

function HistoryView({
  api,
  currentId,
  onOpen,
  onNew,
  onDeleted,
}: {
  api: B89ApiClient;
  currentId: string | null;
  onOpen: (id: string) => void;
  onNew: () => void;
  onDeleted: (id: string | null) => void;
}) {
  const [items, setItems] = useState<readonly ConversationSummary[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [confirming, setConfirming] = useState<string | 'all' | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    (next?: string) => {
      listConversations(api, next).then(
        (page) => {
          setItems((current) => (next && current ? [...current, ...page.items] : page.items));
          setCursor(page.nextCursor);
          setFailed(false);
        },
        () => setFailed(true),
      );
    },
    [api],
  );
  useEffect(() => load(), [load]);

  const remove = async (target: string | 'all') => {
    setBusy(true);
    try {
      if (target === 'all') await deleteAllConversations(api);
      else await deleteConversation(api, target);
      setItems((current) =>
        target === 'all' ? [] : (current ?? []).filter((item) => item.id !== target),
      );
      onDeleted(target === 'all' ? null : target);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
      setConfirming(null);
    }
  };

  return (
    <div className="b89Bunny__history">
      <div className="b89Bunny__historyHead">
        <h3>Historial</h3>
        <button type="button" onClick={onNew}>
          + Nueva conversación
        </button>
      </div>
      {failed && (
        <p className="b89Bunny__historyNote" role="alert">
          No pude cargar el historial. Inténtalo de nuevo.
        </p>
      )}
      {items === null && !failed && <p className="b89Bunny__historyNote">Cargando…</p>}
      {items !== null && items.length === 0 && !failed && (
        <p className="b89Bunny__historyNote">
          Aún no tienes conversaciones guardadas. Lo que le preguntes a {NAME} aparecerá aquí.
        </p>
      )}
      <ul>
        {(items ?? []).map((item) => (
          <li key={item.id} className={item.id === currentId ? 'is-current' : ''}>
            <button type="button" className="b89Bunny__historyOpen" onClick={() => onOpen(item.id)}>
              <strong>{item.title || 'Conversación sin título'}</strong>
              <span>
                {formatWhen(item.updatedAt)} · {item.messageCount}{' '}
                {item.messageCount === 1 ? 'mensaje' : 'mensajes'}
              </span>
            </button>
            {confirming === item.id ? (
              <span className="b89Bunny__confirm">
                ¿Borrar?
                <button type="button" disabled={busy} onClick={() => remove(item.id)}>
                  Sí
                </button>
                <button type="button" onClick={() => setConfirming(null)}>
                  No
                </button>
              </span>
            ) : (
              <button
                type="button"
                className="b89Bunny__iconButton"
                title="Borrar conversación"
                aria-label={`Borrar la conversación ${item.title}`}
                onClick={() => setConfirming(item.id)}
              >
                🗑
              </button>
            )}
          </li>
        ))}
      </ul>
      {cursor && (
        <button type="button" className="b89Bunny__more" onClick={() => load(cursor)}>
          Cargar más
        </button>
      )}
      {items !== null && items.length > 0 && (
        <div className="b89Bunny__historyFoot">
          {confirming === 'all' ? (
            <span className="b89Bunny__confirm">
              ¿Borrar todo el historial? No se puede deshacer.
              <button type="button" disabled={busy} onClick={() => remove('all')}>
                Sí, borrar
              </button>
              <button type="button" onClick={() => setConfirming(null)}>
                Cancelar
              </button>
            </span>
          ) : (
            <button type="button" onClick={() => setConfirming('all')}>
              Borrar todo el historial
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function BunnyUsageView({
  api,
  configState,
  onRetryConfig,
}: {
  api: B89ApiClient;
  configState: BunnyConfigState;
  onRetryConfig: () => void;
}) {
  const [usage, setUsage] = useState<BunnyUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const initialized = useRef(false);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      try {
        const page = await fetchBunnyUsage(api, {
          ...(usage?.period ? { from: usage.period.from, to: usage.period.to } : {}),
          ...(cursor ? { cursor } : {}),
        });
        setUsage((current) => {
          if (!cursor || !current) return page;
          return {
            ...page,
            totals: {
              requests: current.totals.requests + page.totals.requests,
              succeeded: current.totals.succeeded + page.totals.succeeded,
              failed: current.totals.failed + page.totals.failed,
              measured: current.totals.measured + page.totals.measured,
              inputTokens: current.totals.inputTokens + page.totals.inputTokens,
              outputTokens: current.totals.outputTokens + page.totals.outputTokens,
              cacheReadTokens: current.totals.cacheReadTokens + page.totals.cacheReadTokens,
              cacheWriteTokens: current.totals.cacheWriteTokens + page.totals.cacheWriteTokens,
            },
          };
        });
        setFailed(false);
      } catch {
        setFailed(true);
      } finally {
        setLoading(false);
      }
    },
    [api, usage?.period.from, usage?.period.to],
  );

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    void load();
  }, [load]);

  return (
    <section className="b89Bunny__usage" aria-label="Uso y configuración de Bunny">
      <h3>Uso y configuración</h3>
      <p className="b89Bunny__usageIntro">
        Vista administrativa de solo lectura. No muestra prompts, respuestas ni claves.
      </p>
      {configState.status === 'ready' ? (
        <dl>
          <div>
            <dt>Estado</dt>
            <dd>{configState.config.enabled ? 'Habilitado' : 'Deshabilitado'}</dd>
          </div>
          <div>
            <dt>Proveedor</dt>
            <dd>{configState.config.provider ?? 'Sin dato'}</dd>
          </div>
          <div>
            <dt>Modelo</dt>
            <dd>{configState.config.model ?? 'Sin dato'}</dd>
          </div>
          <div>
            <dt>Esfuerzo</dt>
            <dd>{configState.config.effort ?? 'Sin dato'}</dd>
          </div>
          <div>
            <dt>Límite por persona</dt>
            <dd>{configState.config.rateLimit ?? 'Sin dato'} preguntas / 10 min</dd>
          </div>
          <div>
            <dt>Datos personales</dt>
            <dd>{configState.config.redactsPersonalData ? 'Seudonimizados' : 'Redacción desactivada'}</dd>
          </div>
        </dl>
      ) : configState.status === 'loading' ? (
        <p role="status">Consultando configuración del servicio…</p>
      ) : (
        <div role="alert">
          <p>No se pudo comprobar la configuración. El estado del asistente es desconocido.</p>
          <button type="button" onClick={onRetryConfig}>
            Reintentar configuración
          </button>
        </div>
      )}
      <h4>Consumo · últimos 30 días</h4>
      {loading && !usage && <p role="status">Consultando auditoría…</p>}
      {failed && <p role="alert">No se pudieron cargar todas las métricas.</p>}
      {failed && !usage && (
        <button type="button" disabled={loading} onClick={() => void load()}>
          {loading ? 'Cargando…' : 'Reintentar'}
        </button>
      )}
      {usage && (
        <>
          <dl>
            <div>
              <dt>Solicitudes</dt>
              <dd>{usage.totals.requests}</dd>
            </div>
            <div>
              <dt>Completadas / fallidas</dt>
              <dd>
                {usage.totals.succeeded} / {usage.totals.failed}
              </dd>
            </div>
            <div>
              <dt>Tokens de entrada</dt>
              <dd>{usage.totals.inputTokens.toLocaleString('es-PE')}</dd>
            </div>
            <div>
              <dt>Tokens de salida</dt>
              <dd>{usage.totals.outputTokens.toLocaleString('es-PE')}</dd>
            </div>
            <div>
              <dt>Lecturas de caché</dt>
              <dd>{usage.totals.cacheReadTokens.toLocaleString('es-PE')}</dd>
            </div>
            <div>
              <dt>Solicitudes medidas</dt>
              <dd>
                {usage.totals.measured} / {usage.totals.requests}
              </dd>
            </div>
          </dl>
          <div className="b89Bunny__usageTableWrap">
            <table>
              <thead>
                <tr>
                  <th>Proveedor / modelo</th>
                  <th>Solicitudes</th>
                  <th>Tokens entrada/salida</th>
                </tr>
              </thead>
              <tbody>
                {usage.models.map((item) => (
                  <tr key={`${item.provider}:${item.model}`}>
                    <td>
                      {item.provider}
                      <small>{item.model}</small>
                    </td>
                    <td>{item.requests}</td>
                    <td>
                      {item.inputTokens.toLocaleString('es-PE')} /{' '}
                      {item.outputTokens.toLocaleString('es-PE')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="b89Bunny__usageNote">
            El costo facturado no está conectado a este panel. Los datos provienen de eventos de
            auditoría; usa «Cargar más» para recorrer el periodo completo.
          </p>
          {usage.nextCursor && (
            <button
              type="button"
              disabled={loading}
              onClick={() => void load(usage.nextCursor ?? undefined)}
            >
              {loading ? 'Cargando…' : 'Cargar más uso'}
            </button>
          )}
        </>
      )}
    </section>
  );
}

export function BunnyPanel({
  core,
  api,
  state,
  imageUrl,
}: {
  core: CoreStart;
  api: B89ApiClient;
  state: BunnyState;
  imageUrl: string;
}) {
  const open = useBunnyOpen(state);
  const [configState, setConfigState] = useState<BunnyConfigState>({ status: 'loading' });
  const config = configState.status === 'ready' ? configState.config : null;
  const [canSeeUsage, setCanSeeUsage] = useState(false);
  const [canWriteNotes, setCanWriteNotes] = useState(false);
  const [view, setView] = useState<View>('chat');
  const [messages, setMessages] = useState<Message[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [notSaved, setNotSaved] = useState(false);
  const [draft, setDraft] = useState('');
  const [pending, setPending] = useState(false);
  const [progressEvents, setProgressEvents] = useState<BunnyProgressEvent[]>([]);
  const [thinkingStartedAt, setThinkingStartedAt] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [copied, setCopied] = useState<number | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<{
    messageId: number;
    incidentId: string;
  } | null>(null);
  const [savingNoteId, setSavingNoteId] = useState<number | null>(null);
  const [noteStatus, setNoteStatus] = useState<{ id: number; text: string } | null>(null);
  /** Contexto recibido de «Preguntar a Bunny» (alerta/incidente) para la siguiente pregunta. */
  const [askContext, setAskContext] = useState<string | null>(null);
  const nextId = useRef(1);
  const activeChatRun = useRef<AbortController | null>(null);
  const configRequest = useRef(0);
  const listRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  const loadConfig = useCallback(async () => {
    const requestId = ++configRequest.current;
    setConfigState({ status: 'loading' });
    const result = await loadBunnyConfigState(api);
    if (requestId === configRequest.current) setConfigState(result);
  }, [api]);

  useEffect(() => {
    if (!pending || thinkingStartedAt === null) return undefined;
    const updateElapsed = () =>
      setElapsedSeconds(Math.floor((Date.now() - thinkingStartedAt) / 1000));
    updateElapsed();
    const timer = window.setInterval(updateElapsed, 1000);
    return () => window.clearInterval(timer);
  }, [pending, thinkingStartedAt]);

  useEffect(() => {
    void loadConfig();
    api.session().then(
      (session) => {
        setCanSeeUsage(session.capabilities.includes('observability.read_platform'));
        setCanWriteNotes(session.capabilities.includes(CAPABILITIES.notesWrite));
      },
      () => {
        setCanSeeUsage(false);
        setCanWriteNotes(false);
      },
    );
    return () => {
      configRequest.current += 1;
    };
  }, [api, loadConfig]);

  useEffect(() => {
    if (open && view === 'chat') inputRef.current?.focus();
  }, [open, view]);

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, pending, view]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey && event.shiftKey && event.key.toLowerCase() === 'b') {
        event.preventDefault();
        state.toggle();
      } else if (event.key === 'Escape' && state.isOpen()) {
        state.set(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [state]);

  const page = window.location.pathname;
  const append = useCallback((message: Omit<Message, 'id'>) => {
    setMessages((current) => [...current, { ...message, id: nextId.current++ }]);
  }, []);

  const newConversation = useCallback(() => {
    setMessages([]);
    setConversationId(null);
    setNotSaved(false);
    setView('chat');
  }, []);

  const openConversation = useCallback(
    async (id: string) => {
      try {
        const stored = await getConversation(api, id);
        nextId.current = 1;
        setMessages(
          stored.messages.map((message) => ({
            id: nextId.current++,
            role: message.role,
            text: message.text,
            ...(message.steps ? { steps: message.steps } : {}),
            ...(message.citations ? { citations: message.citations } : {}),
            ...(message.tone ? { tone: message.tone } : {}),
            ...(message.role === 'assistant' ? { serverId: String(message.id) } : {}),
            ...(message.feedback ? { feedback: message.feedback } : {}),
          })),
        );
        setConversationId(stored.id);
        setNotSaved(false);
        setView('chat');
      } catch {
        append({ role: 'assistant', text: 'No pude abrir esa conversación.', tone: 'error' });
        setView('chat');
      }
    },
    [api, append],
  );

  const send = useCallback(
    async (raw: string) => {
      const text = raw.trim();
      if (!text || pending) return;
      const history: BunnyTurn[] = messages
        .filter((message) => !message.tone)
        .map(({ role, text: content }) => ({ role, content }));
      setDraft('');
      const userMessageId = nextId.current;
      append({ role: 'user', text });
      setPending(true);
      setThinkingStartedAt(Date.now());
      setElapsedSeconds(0);
      setProgressEvents([]);
      const controller = new AbortController();
      activeChatRun.current = controller;
      try {
        const reply = await askBunnyStream(
          api,
          text,
          history,
          askContext ?? `${window.location.pathname}${window.location.search}`,
          (event) => setProgressEvents((current) => [...current, event]),
          conversationId ?? undefined,
          controller.signal,
        );
        setAskContext(null);
        if (reply.conversationId) setConversationId(reply.conversationId);
        setNotSaved(reply.saved === false);
        append({
          role: 'assistant',
          text: reply.reply,
          steps: reply.steps,
          citations: reply.citations,
          ...(reply.messageId ? { serverId: reply.messageId } : {}),
          ...(reply.outcome === 'refused' || reply.outcome === 'unverified'
            ? { tone: 'notice' as const }
            : {}),
        });
      } catch (error) {
        if (controller.signal.aborted) {
          setDraft(text);
          setMessages((current) =>
            current.map((message) =>
              message.id === userMessageId ? { ...message, tone: 'notice' } : message,
            ),
          );
          append({
            role: 'assistant',
            text: 'Consulta cancelada. No se reintentó automáticamente; revisa la actividad antes de volver a enviarla.',
            tone: 'notice',
          });
        } else {
          append({ role: 'assistant', text: errorText(error), tone: 'error' });
        }
      } finally {
        if (activeChatRun.current === controller) activeChatRun.current = null;
        setPending(false);
        inputRef.current?.focus();
      }
    },
    [api, append, askContext, conversationId, messages, pending],
  );

  // API pública del panel: `window.dispatchEvent(new CustomEvent(BUNNY_ASK_EVENT, …))` (ver
  // `common/bunny_bridge.ts` y `public/bunny_bridge.ts#askBunny`). Abre el panel en el chat, deja
  // la pregunta como borrador (o la envía con `autoSend`) y usa `context` como página de contexto.
  const sendRef = useRef(send);
  sendRef.current = send;
  useEffect(() => {
    const onAsk = (event: Event) => {
      const detail = (event as CustomEvent<BunnyAskDetail>).detail;
      if (!detail || typeof detail.prompt !== 'string' || detail.prompt.trim() === '') return;
      event.preventDefault();
      state.set(true);
      setView('chat');
      setAskContext(contextPage(detail.context));
      const prompt = detail.prompt.slice(0, MAX_CHARS);
      if (detail.autoSend) {
        // El contexto se aplica en el siguiente render; se envía después.
        window.setTimeout(() => void sendRef.current(prompt), 0);
      } else {
        setDraft(prompt);
        window.setTimeout(() => inputRef.current?.focus(), 0);
      }
    };
    window.addEventListener(BUNNY_ASK_EVENT, onAsk);
    return () => window.removeEventListener(BUNNY_ASK_EVENT, onAsk);
  }, [state]);

  const rate = useCallback(
    async (message: Message, rating: BunnyFeedback | null) => {
      if (!conversationId || !message.serverId) return;
      const previous = message.feedback;
      const patch = (feedback: BunnyFeedback | undefined) =>
        setMessages((current) =>
          current.map((item) => {
            if (item.id !== message.id) return item;
            const { feedback: _old, ...rest } = item;
            return feedback ? { ...rest, feedback } : rest;
          }),
        );
      patch(rating ?? undefined);
      try {
        await rateMessage(api, conversationId, message.serverId, rating);
      } catch {
        patch(previous);
      }
    },
    [api, conversationId],
  );

  const navigate = useCallback(
    (path: string) => core.application.navigateToUrl(core.http.basePath.prepend(path)),
    [core],
  );

  if (!open) return null;

  const suggestions = suggestionsFor(page);
  return (
    <aside
      id="b89-bunny-panel"
      className="b89Bunny__panel"
      role="dialog"
      aria-label={`${NAME}, asistente de IA de B89 SOC`}
      data-test-subj="b89BunnyPanel"
    >
      <header className="b89Bunny__header">
        <img src={imageUrl} alt="" width={36} height={36} />
        <div>
          <h2>{NAME}</h2>
          <p>Asistente de IA de B89 SOC</p>
        </div>
        {canSeeUsage && (
          <button
            type="button"
            className={`b89Bunny__iconButton${view === 'usage' ? ' is-active' : ''}`}
            title="Uso y configuración del asistente"
            aria-label="Uso y configuración del asistente"
            aria-pressed={view === 'usage'}
            onClick={() => setView(view === 'usage' ? 'chat' : 'usage')}
          >
            i
          </button>
        )}
        <button
          type="button"
          className={`b89Bunny__iconButton${view === 'history' ? ' is-active' : ''}`}
          title="Historial de conversaciones"
          aria-label="Historial de conversaciones"
          aria-pressed={view === 'history'}
          onClick={() => setView(view === 'history' ? 'chat' : 'history')}
        >
          🕘
        </button>
        <button
          type="button"
          className="b89Bunny__iconButton"
          title="Nueva conversación"
          aria-label="Nueva conversación"
          disabled={pending || (messages.length === 0 && view === 'chat')}
          onClick={newConversation}
        >
          ＋
        </button>
        <button
          type="button"
          className="b89Bunny__iconButton"
          title="Cerrar (Esc)"
          aria-label="Cerrar el panel"
          onClick={() => state.set(false)}
        >
          ✕
        </button>
      </header>

      {view === 'usage' && canSeeUsage ? (
        <BunnyUsageView
          api={api}
          configState={configState}
          onRetryConfig={() => void loadConfig()}
        />
      ) : configState.status === 'loading' ? (
        <div className="b89Bunny__unavailable" role="status">
          Comprobando disponibilidad del asistente...
        </div>
      ) : configState.status === 'unavailable' ? (
        <section className="b89Bunny__unavailable" role="alert">
          <h3>No se pudo comprobar la disponibilidad</h3>
          <p>El servicio de configuración no respondió. El estado de Bunny es desconocido.</p>
          <button type="button" onClick={() => void loadConfig()}>
            Reintentar
          </button>
        </section>
      ) : configState.status === 'ready' && !configState.config.enabled ? (
        <section className="b89Bunny__unavailable" role="status">
          <h3>Bunny está instalado</h3>
          <p>
            La interfaz del asistente está lista. Para activar las respuestas, un administrador debe
            habilitar y configurar el proveedor de IA en el servicio B89. Con Bedrock, la API usa el
            rol de AWS.
          </p>
          <p>El envío de mensajes está deshabilitado hasta que el servicio confirme la conexión.</p>
        </section>
      ) : view === 'history' ? (
        <HistoryView
          api={api}
          currentId={conversationId}
          onOpen={openConversation}
          onNew={newConversation}
          onDeleted={(id) => {
            if (id === null || id === conversationId) newConversation();
            setView('history');
          }}
        />
      ) : (
        <>
          <div className="b89Bunny__list" ref={listRef} role="log" aria-live="polite">
            {messages.length === 0 && (
              <section className="b89Bunny__welcome">
                <img src={imageUrl} alt="" width={96} height={96} />
                <h3>Hola, soy {NAME}</h3>
                <p>
                  Pregúntame por alertas, incidentes, eventos, la salud de las fuentes o la
                  auditoría. Veo lo mismo que tú: lo que tu rol no puede ver, yo tampoco.
                </p>
                <ul className="b89Bunny__suggestions">
                  {suggestions.map((suggestion) => (
                    <li key={suggestion.title}>
                      <button type="button" onClick={() => send(suggestion.prompt)}>
                        <strong>{suggestion.title}</strong>
                        <span>{suggestion.prompt}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            )}
            {messages.map((message) => (
              <article
                key={message.id}
                className={`b89Bunny__message b89Bunny__message--${message.role}${message.tone ? ` is-${message.tone}` : ''}`}
              >
                {message.role === 'assistant' && (
                  <img src={imageUrl} alt="" width={24} height={24} />
                )}
                <div className="b89Bunny__bubble">
                  {message.role === 'user' ? (
                    <p>{message.text}</p>
                  ) : (
                    renderMarkdown(message.text, {
                      citations: message.citations ?? [],
                      onOpen: navigate,
                    })
                  )}
                  {message.role === 'assistant' && <Activity steps={message.steps} />}
                  {message.citations && <Sources citations={message.citations} open={navigate} />}
                  {message.role === 'assistant' && !message.tone && (
                    <div className="b89Bunny__actions">
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard?.writeText(message.text).then(
                            () => {
                              setCopied(message.id);
                              window.setTimeout(() => setCopied(null), 1500);
                            },
                            () => undefined,
                          );
                        }}
                      >
                        {copied === message.id ? 'Copiado' : 'Copiar'}
                      </button>
                      {conversationId && message.serverId && (
                        <Feedback
                          value={message.feedback}
                          disabled={pending}
                          onRate={(rating) => void rate(message, rating)}
                        />
                      )}
                      <BunnyReportActions
                        api={api}
                        basePath={core.http.basePath.get()}
                        messageId={message.id}
                        text={message.text}
                        citations={message.citations ?? []}
                      />
                      {canWriteNotes &&
                        message.citations?.some((citation) => citation.kind === 'incident') && (
                          <>
                            <select
                              aria-label="Incidente donde guardar el borrador"
                              value={
                                (selectedIncident?.messageId === message.id
                                  ? selectedIncident.incidentId
                                  : '') ||
                                message.citations?.find((citation) => citation.kind === 'incident')
                                  ?.id ||
                                ''
                              }
                              onChange={(event) =>
                                setSelectedIncident({
                                  messageId: message.id,
                                  incidentId: event.target.value,
                                })
                              }
                            >
                              {(message.citations ?? [])
                                .filter((citation) => citation.kind === 'incident')
                                .map((citation) => (
                                  <option key={citation.id} value={citation.id}>
                                    {citation.label}
                                  </option>
                                ))}
                            </select>
                            <button
                              type="button"
                              disabled={savingNoteId === message.id}
                              onClick={async () => {
                                const incidentId =
                                  (selectedIncident?.messageId === message.id
                                    ? selectedIncident.incidentId
                                    : '') ||
                                  message.citations?.find(
                                    (citation) => citation.kind === 'incident',
                                  )?.id;
                                if (!incidentId) return;
                                setSavingNoteId(message.id);
                                setNoteStatus(null);
                                try {
                                  await api.post(
                                    `/incidents/${encodeURIComponent(incidentId)}/notes`,
                                    { body: reportNoteBody(message) },
                                  );
                                  setNoteStatus({
                                    id: message.id,
                                    text: 'Borrador guardado en las notas del incidente.',
                                  });
                                } catch {
                                  setNoteStatus({
                                    id: message.id,
                                    text: 'No se pudo guardar. Verifica tu acceso al incidente.',
                                  });
                                } finally {
                                  setSavingNoteId(null);
                                }
                              }}
                            >
                              {savingNoteId === message.id ? 'Guardando…' : 'Guardar en incidente'}
                            </button>
                          </>
                        )}
                      <button type="button" onClick={() => navigate('/app/b89-respond')}>
                        Abrir B89 Respond
                      </button>
                    </div>
                  )}
                  {noteStatus?.id === message.id && (
                    <p className="b89Bunny__notice" role="status">
                      {noteStatus.text}
                    </p>
                  )}
                </div>
              </article>
            ))}
            {pending && (
              <article className="b89Bunny__message b89Bunny__message--assistant" aria-busy="true">
                <img src={imageUrl} alt="" width={24} height={24} />
                <div className="b89Bunny__bubble">
                  <BunnyThinking events={progressEvents} elapsedSeconds={elapsedSeconds} />
                  <button
                    type="button"
                    className="b89Bunny__cancelChat"
                    onClick={() => activeChatRun.current?.abort()}
                  >
                    Cancelar consulta
                  </button>
                </div>
              </article>
            )}
          </div>

          {askContext && (
            <p className="b89Bunny__context" role="status">
              Contexto: {askContext.includes('incidents') ? 'incidente' : 'alerta'}{' '}
              <code>{decodeURIComponent(askContext.split('id=')[1] ?? '')}</code>
              <button
                type="button"
                onClick={() => setAskContext(null)}
                aria-label="Quitar contexto"
              >
                ✕
              </button>
            </p>
          )}
          {notSaved && (
            <p className="b89Bunny__notice" role="status">
              Esta conversación no se guardó en el historial.
            </p>
          )}
          <form
            className="b89Bunny__composer"
            onSubmit={(event) => {
              event.preventDefault();
              send(draft);
            }}
          >
            <textarea
              ref={inputRef}
              value={draft}
              maxLength={MAX_CHARS}
              rows={2}
              placeholder={`Pregúntale algo a ${NAME}…`}
              aria-label={`Escribe tu pregunta para ${NAME}`}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
                  event.preventDefault();
                  send(draft);
                }
              }}
            />
            <button type="submit" disabled={pending || draft.trim() === ''} aria-label="Enviar">
              ➤
            </button>
          </form>
        </>
      )}
      <p className="b89Bunny__disclaimer">
        <strong>IA generativa: verifica antes de actuar.</strong> {NAME} solo lee datos del SOC con
        tus permisos; no ejecuta, aprueba ni solicita acciones (toda contención va por B89 Respond
        con aprobación del Líder SOC). Horas en Lima (UTC−5). Tus conversaciones y valoraciones se
        guardan en tu historial y solo tú puedes verlas.
        {config?.enabled && config.redactsPersonalData
          ? ' Correos e IP se seudonimizan antes de enviarse al modelo.'
          : ''}
      </p>
    </aside>
  );
}

/** Monta el panel en el `body` (el botón vive en la cabecera) y devuelve el desmontaje. */
export function mountBunnyPanel(core: CoreStart, api: B89ApiClient, state: BunnyState): () => void {
  const container = document.createElement('div');
  container.dataset.b89Bunny = 'panel';
  // OSD vuelve a renderizar <body> después del `start` de los plugins y elimina los nodos
  // añadidos antes: el contenedor se (re)inserta cada vez que el panel se abre.
  const attach = () => {
    if (!container.isConnected) document.body.appendChild(container);
  };
  attach();
  const imageUrl = core.http.basePath.prepend(`${BRAND_ASSETS_PATH}/b89-bunny.webp`);
  ReactDOM.render(
    <BunnyPanel core={core} api={api} state={state} imageUrl={imageUrl} />,
    container,
  );
  const unsubscribe = state.subscribe(() => {
    if (state.isOpen()) attach();
  });
  return () => {
    unsubscribe();
    document.documentElement.classList.remove('b89-bunny-open');
    ReactDOM.unmountComponentAtNode(container);
    container.remove();
  };
}

/** Registra Bunny a la derecha del navbar; el panel se monta fuera de la cabecera. */
export function registerBunnyLauncher(core: CoreStart, state: BunnyState): () => void {
  const targets = new Set<HTMLElement>();
  let stopped = false;
  const imageUrl = core.http.basePath.prepend(`${BRAND_ASSETS_PATH}/b89-bunny.webp`);
  core.chrome.navControls.registerRight({
    order: 900,
    mount: (target: HTMLElement) => {
      if (stopped) return () => undefined;
      targets.add(target);
      ReactDOM.render(<BunnyLauncher state={state} imageUrl={imageUrl} />, target);
      return () => {
        ReactDOM.unmountComponentAtNode(target);
        targets.delete(target);
      };
    },
  });
  return () => {
    stopped = true;
    targets.forEach((target) => ReactDOM.unmountComponentAtNode(target));
    targets.clear();
  };
}
