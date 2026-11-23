/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButton, EuiCallOut } from '@elastic/eui';

/** Pagination controls kept as a small component so the actual React click handlers are testable. */
export function InvestigationPagination({
  loading,
  error,
  remaining,
  pageSize = 100,
  older = false,
  onLoadMore,
  onReset,
}: {
  readonly loading: boolean;
  readonly error: boolean;
  readonly remaining: number;
  /** Eventos que trae cada página (la respuesta del servidor lo indica). */
  readonly pageSize?: number;
  /** `true` cuando la lista va de lo más antiguo a lo más reciente: lo que falta es anterior. */
  readonly older?: boolean;
  readonly onLoadMore: () => Promise<unknown>;
  readonly onReset: () => void;
}) {
  if (error) {
    return (
      <EuiCallOut
        size="s"
        color="danger"
        iconType="alert"
        title="No se pudieron traer más eventos"
      >
        <p>Los eventos que ya ves siguen aquí. Reintenta para continuar donde se quedó.</p>
        <EuiButton size="s" onClick={() => void onLoadMore()}>
          Reintentar
        </EuiButton>{' '}
        <EuiButton size="s" color="text" onClick={onReset}>
          Empezar de nuevo
        </EuiButton>
      </EuiCallOut>
    );
  }

  const left = Math.max(0, remaining);
  const next = Math.min(Math.max(1, pageSize), left);
  return (
    <EuiButton size="s" isLoading={loading} isDisabled={loading} onClick={() => void onLoadMore()}>
      {loading
        ? 'Buscando eventos…'
        : `Ver ${next} ${next === 1 ? 'evento' : 'eventos'} ${
            older ? (next === 1 ? 'anterior' : 'anteriores') : 'más'
          } (quedan ${left})`}
    </EuiButton>
  );
}
