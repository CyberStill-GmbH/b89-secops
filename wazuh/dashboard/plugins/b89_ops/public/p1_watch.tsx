/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import {
  EuiHeaderSectionItemButton,
  EuiIcon,
  EuiNotificationBadge,
  EuiToolTip,
} from '@elastic/eui';
import type { CoreStart } from '../../../src/core/public';
import { ALERTS_PATH, Alert, CAPABILITIES, ChangeEvent } from '../common';
import type { ChangeFeed } from './api/change_feed';
import type { B89ApiClient } from './api/client';

/**
 * Como mucho una consulta cada 30 s, y solo si llegaron alertas creadas. Antes se leía cada alerta
 * por su id: una ráfaga (p. ej. una recuperación histórica que crea miles de alertas P3) generaba
 * cientos de peticiones por minuto desde cada pestaña y el WAF bloqueaba la IP (403, 2026-11-18).
 */
export const P1_LOOKUP_INTERVAL_MS = 30_000;
const P1_LOOKUP_PAGE = 20;

/**
 * Aviso de nuevas alertas P1 en la cabecera de todo el dashboard (también en el SIEM).
 *
 * Usa el feed compartido de `/api/changes` (no abre otro long-poll): ante una alerta *creada*,
 * la lee por su endpoint normal (que vuelve a autorizar) y, si es P1 y sigue «nueva», suma al
 * contador y muestra un aviso. Sin `alerts.read` no se pinta nada. El contador cuenta desde que
 * se abrió la página; no es un KPI ni sustituye a la cola.
 */
function P1Badge({ core, api, feed }: { core: CoreStart; api: B89ApiClient; feed: ChangeFeed }) {
  const [enabled, setEnabled] = useState(false);
  const [count, setCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    api.session().then(
      (session) => {
        if (!cancelled) setEnabled(session.capabilities.includes(CAPABILITIES.alertsRead));
      },
      () => undefined, // Sin sesión el cliente ya llevó al login; con API degradada no hay aviso.
    );
    return () => {
      cancelled = true;
    };
  }, [api]);

  useEffect(() => {
    if (!enabled) return undefined;
    const seen = new Set<string>();
    let primed = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let lastRun = 0;
    let cancelled = false;
    const lookup = async () => {
      timer = null;
      lastRun = Date.now();
      try {
        const page = await api.get<{ items: readonly Alert[] }>(
          `/alerts?status=open&priority=P1&pageSize=${P1_LOOKUP_PAGE}`,
        );
        if (cancelled) return;
        const fresh = page.items.filter((alert) => alert.status === 'new' && !seen.has(alert.id));
        for (const alert of page.items) seen.add(alert.id);
        // La primera lectura solo marca lo que ya existía: el contador cuenta desde que se abrió.
        if (!primed) {
          primed = true;
          return;
        }
        if (fresh.length === 0) return;
        setCount((value) => value + fresh.length);
        core.notifications.toasts.addDanger({
          title: fresh.length === 1 ? 'Nueva alerta P1' : `${fresh.length} alertas P1 nuevas`,
          text: fresh[0]?.title,
          'data-test-subj': 'b89P1Toast',
        });
      } catch {
        // API degradada: sin aviso; se reintenta con la próxima alerta creada.
      }
    };
    const schedule = () => {
      if (timer || cancelled) return;
      const wait = Math.max(0, lastRun + P1_LOOKUP_INTERVAL_MS - Date.now());
      timer = setTimeout(() => void lookup(), wait);
    };
    void lookup();
    const unsubscribe = feed.subscribe(
      ['alert'],
      (changes: readonly ChangeEvent[], resync: boolean) => {
        if (resync) return; // Un resync no dice qué es nuevo: la cola lo mostrará al abrirla.
        if (!changes.some((change) => change.kind === 'created')) return;
        schedule();
      },
    );
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      unsubscribe();
    };
  }, [enabled, api, feed, core]);

  if (!enabled || count === 0) return null;
  const label = count === 1 ? '1 alerta P1 nueva' : `${count} alertas P1 nuevas`;
  return (
    <EuiToolTip content={label} position="bottom">
      <EuiHeaderSectionItemButton
        aria-label={`${label}. Abrir la cola de alertas`}
        className="b89P1Badge"
        data-test-subj="b89P1Badge"
        notification={
          <EuiNotificationBadge color="accent">{count > 99 ? '99+' : count}</EuiNotificationBadge>
        }
        onClick={() => {
          setCount(0);
          core.application.navigateToUrl(core.http.basePath.prepend(`${ALERTS_PATH}?priority=P1`));
        }}
      >
        <EuiIcon type="bell" size="m" />
      </EuiHeaderSectionItemButton>
    </EuiToolTip>
  );
}

export function mountP1Watch(core: CoreStart, api: B89ApiClient, feed: ChangeFeed): () => void {
  let element: HTMLElement | null = null;
  core.chrome.navControls.registerRight({
    order: 1000,
    mount: (target: HTMLElement) => {
      element = target;
      ReactDOM.render(<P1Badge core={core} api={api} feed={feed} />, target);
      return () => {
        ReactDOM.unmountComponentAtNode(target);
        element = null;
      };
    },
  });
  return () => {
    if (element) ReactDOM.unmountComponentAtNode(element);
  };
}
