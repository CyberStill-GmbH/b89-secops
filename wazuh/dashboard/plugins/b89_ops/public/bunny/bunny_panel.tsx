/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import type { CoreStart } from '../../../../src/core/public';
import { BRAND_ASSETS_PATH } from '../../common';
import { B89ApiError, type B89ApiClient } from '../api/client';
import {
  askBunny,
  citationPath,
  deleteAllConversations,
  deleteConversation,
  fetchBunnyConfig,
  formatWhen,
  getConversation,
  listConversations,
  suggestionsFor,
  type BunnyCitation,
  type BunnyConfig,
  type BunnyReasoning,
  type BunnyStep,
  type BunnyTurn,
  type ConversationSummary,
} from './chat_client';
import { renderMarkdown } from './markdown';

/**
 * Bunny, el asistente de IA de B89 SOC. Panel anclado a la izquierda al estilo de Amazon Q en la
 * consola de AWS: se abre desde la cabecera, empuja el contenido en lugar de taparlo, saluda con
 * ejemplos de la página actual, muestra su razonamiento (lo que pensó y lo que consultó), cita lo
 * que afirma con enlaces a la consola y guarda las conversaciones en un historial que se puede
 * reabrir y borrar. Es de solo lectura y responde con los permisos de la persona.
 */

const MAX_CHARS = 4000;
const NAME = 'Bunny';

interface Message {
  readonly id: number;
  readonly role: 'user' | 'assistant';
  readonly text: string;
  readonly reasoning?: readonly BunnyReasoning[];
  readonly steps?: readonly BunnyStep[];
  readonly citations?: readonly BunnyCitation[];
  readonly tone?: 'error' | 'notice';
}

type View = 'chat' | 'history';

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

export function BunnyLauncher({ state, imageUrl }: { state: BunnyState; imageUrl: string }) {
  const open = useBunnyOpen(state);
  return (
    <button
      type="button"
      className={`b89Bunny__launcher${open ? ' b89Bunny__launcher--open' : ''}`}
      aria-label={`${NAME}, asistente de IA. ${open ? 'Cerrar' : 'Abrir'} el panel`}
      aria-expanded={open}
      aria-controls="b89-bunny-panel"
      title={`${NAME} · asistente de IA (Alt+Shift+B)`}
      data-test-subj="b89BunnyLauncher"
      onClick={() => state.toggle()}
    >
      <img src={imageUrl} alt="" width={30} height={30} />
    </button>
  );
}

/** Razonamiento visible: lo que pensó Bunny y lo que consultó, en orden (como «Show reasoning» de AWS). */
function Reasoning({
  reasoning,
  steps,
}: {
  reasoning?: readonly BunnyReasoning[];
  steps?: readonly BunnyStep[];
}) {
  const [shown, setShown] = useState(false);
  const entries: readonly BunnyReasoning[] =
    reasoning && reasoning.length > 0
      ? reasoning
      : (steps ?? []).map((step) => ({ kind: 'tool' as const, label: step.label, ok: step.ok }));
  if (entries.length === 0) return null;
  return (
    <div className="b89Bunny__reasoning">
      <button type="button" aria-expanded={shown} onClick={() => setShown(!shown)}>
        <span aria-hidden="true">{shown ? '▾' : '▸'}</span> {shown ? 'Ocultar' : 'Mostrar'}{' '}
        razonamiento
      </button>
      {shown && (
        <ol>
          {entries.map((entry, index) =>
            entry.kind === 'thought' ? (
              <li key={index} className="is-thought">
                <span className="b89Bunny__reasoningLabel">Pensé</span>
                {renderMarkdown(entry.text)}
              </li>
            ) : (
              <li key={index} className={entry.ok ? 'is-ok' : 'is-failed'}>
                <span aria-hidden="true">{entry.ok ? '✓' : '✕'}</span> {entry.label}
                {entry.ok ? '' : ' (sin resultado)'}
              </li>
            ),
          )}
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
  const [config, setConfig] = useState<BunnyConfig | null>(null);
  const [view, setView] = useState<View>('chat');
  const [messages, setMessages] = useState<Message[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [notSaved, setNotSaved] = useState(false);
  const [draft, setDraft] = useState('');
  const [pending, setPending] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const nextId = useRef(1);
  const listRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    fetchBunnyConfig(api).then(setConfig, () => setConfig({ enabled: false, name: NAME }));
  }, [api]);

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
            ...(message.reasoning ? { reasoning: message.reasoning } : {}),
            ...(message.steps ? { steps: message.steps } : {}),
            ...(message.citations ? { citations: message.citations } : {}),
            ...(message.tone ? { tone: message.tone } : {}),
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
      append({ role: 'user', text });
      setPending(true);
      try {
        const reply = await askBunny(
          api,
          text,
          history,
          window.location.pathname,
          conversationId ?? undefined,
        );
        if (reply.conversationId) setConversationId(reply.conversationId);
        setNotSaved(reply.saved === false);
        append({
          role: 'assistant',
          text: reply.reply,
          ...(reply.reasoning ? { reasoning: reply.reasoning } : {}),
          steps: reply.steps,
          citations: reply.citations,
          ...(reply.outcome === 'refused' ? { tone: 'notice' as const } : {}),
        });
      } catch (error) {
        append({ role: 'assistant', text: errorText(error), tone: 'error' });
      } finally {
        setPending(false);
        inputRef.current?.focus();
      }
    },
    [api, append, conversationId, messages, pending],
  );

  const navigate = useCallback(
    (path: string) => core.application.navigateToUrl(core.http.basePath.prepend(path)),
    [core],
  );

  if (!open || !config?.enabled) return null;

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

      {view === 'history' ? (
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
                  {message.role === 'user' ? <p>{message.text}</p> : renderMarkdown(message.text)}
                  {message.role === 'assistant' && (
                    <Reasoning reasoning={message.reasoning} steps={message.steps} />
                  )}
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
                    </div>
                  )}
                </div>
              </article>
            ))}
            {pending && (
              <article className="b89Bunny__message b89Bunny__message--assistant" aria-busy="true">
                <img src={imageUrl} alt="" width={24} height={24} />
                <div className="b89Bunny__bubble b89Bunny__thinking" role="status">
                  <span className="b89Bunny__dots" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                  {NAME} está pensando y consultando el SOC…
                </div>
              </article>
            )}
          </div>

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
        {NAME} usa IA generativa y puede equivocarse: verifica lo importante. Es de solo lectura y
        no ejecuta acciones. Tus conversaciones se guardan en tu historial y solo tú puedes verlas.
        {config.redactsPersonalData
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
  // El panel va a la izquierda y empuja el contenido: una clase en <html> activa el desplazamiento.
  const sync = () => {
    if (state.isOpen()) attach();
    document.documentElement.classList.toggle('b89-bunny-open', state.isOpen());
  };
  const unsubscribe = state.subscribe(sync);
  const imageUrl = core.http.basePath.prepend(`${BRAND_ASSETS_PATH}/b89-bunny.webp`);
  ReactDOM.render(
    <BunnyPanel core={core} api={api} state={state} imageUrl={imageUrl} />,
    container,
  );
  return () => {
    unsubscribe();
    document.documentElement.classList.remove('b89-bunny-open');
    ReactDOM.unmountComponentAtNode(container);
    container.remove();
  };
}

/** Registra el botón de la cabecera. */
export function registerBunnyLauncher(core: CoreStart, state: BunnyState): void {
  const imageUrl = core.http.basePath.prepend(`${BRAND_ASSETS_PATH}/b89-bunny.webp`);
  core.chrome.navControls.registerRight({
    order: 900,
    mount: (target: HTMLElement) => {
      ReactDOM.render(<BunnyLauncher state={state} imageUrl={imageUrl} />, target);
      return () => ReactDOM.unmountComponentAtNode(target);
    },
  });
}
