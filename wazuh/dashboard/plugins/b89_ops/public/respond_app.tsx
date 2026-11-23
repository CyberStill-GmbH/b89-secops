/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreStart } from '../../../src/core/public';
import { CAPABILITIES, RESPOND_PATH } from '../common';
import type { B89ApiClient } from './api/client';

/**
 * B89 Respond (SOAR) embebido en el SIEM: un iframe del mismo origen de `/b89-respond/` dentro
 * del chrome del dashboard (cabecera y menú visibles). El edge solo permite enmarcarlo desde el
 * propio origen (`frame-ancestors 'self'`) y lo protege con la sesión B89 (auth_request).
 * La autenticación propia de B89 Respond sigue vigente dentro del iframe (docs/13).
 */

type State = 'checking' | 'forbidden' | 'loading' | 'ready' | 'unavailable';

/** Tiempo máximo para que el iframe cargue antes de mostrar «no disponible». */
const LOAD_TIMEOUT_MS = 20000;

function RespondView({ api, basePath }: { api: B89ApiClient; basePath: string }) {
  const src = `${basePath}${RESPOND_PATH}`;
  const [state, setState] = useState<State>('checking');
  const [attempt, setAttempt] = useState(0);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    setState('checking');
    (async () => {
      try {
        const session = await api.session();
        if (!session.capabilities.includes(CAPABILITIES.incidentsWrite)) {
          if (!cancelled) setState('forbidden');
          return;
        }
        // Sondeo del mismo origen: el edge responde 502/504 si B89 Respond no está levantado.
        const probe = await fetch(src, { credentials: 'same-origin', redirect: 'manual' });
        if (cancelled) return;
        if (probe.status >= 500 || probe.status === 0) {
          setState('unavailable');
          return;
        }
        setState('loading');
        timer.current = window.setTimeout(() => {
          setState((current) => (current === 'loading' ? 'unavailable' : current));
        }, LOAD_TIMEOUT_MS);
      } catch {
        if (!cancelled) setState('unavailable');
      }
    })();
    return () => {
      cancelled = true;
      window.clearTimeout(timer.current);
    };
  }, [api, src, attempt]);

  const openInTab = (
    <a className="b89RespondLink" href={src} target="_blank" rel="noopener noreferrer">
      Abrir en pestaña
    </a>
  );

  if (state === 'forbidden') {
    return (
      <div className="b89RespondNotice" role="status" lang="es-PE">
        <h2>Respuesta automática (SOAR)</h2>
        <p>
          B89 Respond requiere un rol con gestión de incidentes, y el tuyo no la incluye. Revisa tu
          rol en <a href={`${basePath}/app/b89-session`}>Mi sesión</a> y pide el cambio a tu Líder
          SOC.
        </p>
      </div>
    );
  }

  return (
    <div className="b89Respond">
      <div className="b89RespondBar">
        <span className="b89RespondTitle">B89 Respond</span>
        <span className="b89RespondHint">Automatización y respuesta (SOAR)</span>
        {openInTab}
      </div>
      {(state === 'checking' || state === 'loading') && (
        <div className="b89RespondNotice" role="status" aria-live="polite">
          <span className="b89RespondSpinner" aria-hidden="true" />
          <p>Cargando B89 Respond…</p>
        </div>
      )}
      {state === 'unavailable' && (
        <div className="b89RespondNotice" role="alert">
          <h2>B89 Respond no está disponible</h2>
          <p>
            El servicio no respondió. Reintenta o ábrelo en una pestaña aparte; si sigue sin
            cargar, avisa a plataforma.
          </p>
          <p>
            <button type="button" className="b89RespondRetry" onClick={() => setAttempt((n) => n + 1)}>
              Reintentar
            </button>{' '}
            {openInTab}
          </p>
        </div>
      )}
      {(state === 'loading' || state === 'ready') && (
        <iframe
          key={attempt}
          className="b89RespondFrame"
          title="B89 Respond"
          src={src}
          style={{ visibility: state === 'ready' ? 'visible' : 'hidden' }}
          onLoad={() => {
            window.clearTimeout(timer.current);
            setState('ready');
          }}
        />
      )}
    </div>
  );
}

export function renderRespondApp(core: CoreStart, params: AppMountParameters, api: B89ApiClient) {
  params.element.classList.add('b89App', 'b89RespondApp');
  ReactDOM.render(
    <core.i18n.Context>
      <RespondView api={api} basePath={core.http.basePath.get()} />
    </core.i18n.Context>,
    params.element,
  );
  return () => {
    ReactDOM.unmountComponentAtNode(params.element);
    params.element.classList.remove('b89App', 'b89RespondApp');
  };
}
