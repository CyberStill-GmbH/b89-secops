/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButtonEmpty,
  EuiSpacer,
  EuiSwitch,
} from '@elastic/eui';
import {
  ACKNOWLEDGEABLE,
  CAPABILITIES,
  NOTIFICATION_CHANNEL_LABEL,
  NOTIFICATION_STATUS_LABEL,
  NOTIFICATION_TONE,
  NotificationAttempt,
  Page,
} from '../../common';
import { B89ApiError } from '../api/client';
import { B89Page, useChanges, useConsole } from './console_context';
import {
  DataZone,
  EmptyLine,
  ErrorCallout,
  HealthMark,
  Mono,
  Timestamp,
  useAsync,
} from './primitives';

/**
 * Bandeja de notificaciones (doc 04 §6): distingue **entregado** de **reconocido por una
 * persona**. Un P1 que llegó a Teams pero nadie acusó sigue pendiente de atención.
 */
export function NotificationsView() {
  const { can } = useConsole();
  if (!can(CAPABILITIES.notificationsRead)) {
    return (
      <B89Page title="Notificaciones">
        <EmptyLine>Tu rol no incluye la bandeja de notificaciones.</EmptyLine>
      </B89Page>
    );
  }
  return <NotificationsContent />;
}

function NotificationsContent() {
  const { api, notifications } = useConsole();
  const [onlyPending, setOnlyPending] = useState(true);
  const [items, setItems] = useState<readonly NotificationAttempt[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const page = useAsync(
    () => api.get<Page<NotificationAttempt>>('/notifications', { pageSize: 100 }),
    [api],
  );

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
    }
  }, [page.data]);

  useChanges(['notification'], () => page.reload());

  const loadMore = async () => {
    if (!cursor) return;
    const next = await api.get<Page<NotificationAttempt>>('/notifications', {
      pageSize: 100,
      cursor,
    });
    setItems((current) => [...current, ...next.items]);
    setCursor(next.nextCursor);
  };

  const acknowledge = async (attempt: NotificationAttempt) => {
    setBusy(attempt.id);
    setError(null);
    try {
      const result = await api.post<{ status: NotificationAttempt['status'] }>(
        `/notifications/${encodeURIComponent(attempt.id)}/acknowledge`,
      );
      setItems((current) =>
        current.map((item) =>
          item.id === attempt.id
            ? { ...item, status: result.status, acknowledgedAt: new Date().toISOString() }
            : item,
        ),
      );
      notifications.toasts.addSuccess({ title: 'Acuse registrado' });
    } catch (failure) {
      setError(failure);
      if (failure instanceof B89ApiError && failure.code === 'STATE_CONFLICT') page.reload();
    } finally {
      setBusy(null);
    }
  };

  const visible = onlyPending ? items.filter((item) => item.status !== 'acknowledged') : items;
  const columns: Array<EuiBasicTableColumn<NotificationAttempt>> = [
    {
      field: 'status',
      name: 'Estado',
      width: '180px',
      render: (value: NotificationAttempt['status']) => (
        <HealthMark tone={NOTIFICATION_TONE[value]} label={NOTIFICATION_STATUS_LABEL[value]} />
      ),
      mobileOptions: { header: false },
    },
    {
      field: 'channel',
      name: 'Canal',
      render: (value: NotificationAttempt['channel'], item: NotificationAttempt) => (
        <span className="b89CellTitle">
          <span>{NOTIFICATION_CHANNEL_LABEL[value] ?? value}</span>
          <span className="b89CellMeta">
            <Mono>{item.id.slice(0, 12)}</Mono> · {item.attemptCount}{' '}
            {item.attemptCount === 1 ? 'intento' : 'intentos'}
            {item.lastFailureClass ? ` · ${item.lastFailureClass}` : ''}
          </span>
        </span>
      ),
    },
    {
      field: 'sentAt',
      name: 'Enviada',
      render: (value: string | null) => <Timestamp iso={value} />,
    },
    {
      field: 'acknowledgedAt',
      name: 'Acuse',
      render: (value: string | null, item: NotificationAttempt) =>
        value ? (
          <span className="b89CellTitle">
            <Timestamp iso={value} />
            {item.acknowledgedBy && (
              <span className="b89CellMeta">
                <Mono>{item.acknowledgedBy.slice(0, 12)}</Mono>
              </span>
            )}
          </span>
        ) : (
          <span className="b89Muted">Sin acuse</span>
        ),
    },
    {
      name: 'Acciones',
      width: '140px',
      render: (item: NotificationAttempt) =>
        ACKNOWLEDGEABLE.includes(item.status) ? (
          <EuiButtonEmpty size="xs" isLoading={busy === item.id} onClick={() => acknowledge(item)}>
            Acusar recibo
          </EuiButtonEmpty>
        ) : null,
    },
  ];

  return (
    <B89Page
      title="Notificaciones"
      description="Avisos críticos por Teams, correo alternativo o consola. Entregado no es lo mismo que reconocido."
      actions={
        <EuiSwitch
          compressed
          label="Solo sin acuse"
          checked={onlyPending}
          onChange={(event) => setOnlyPending(event.target.checked)}
        />
      }
    >
      {error != null && (
        <>
          <ErrorCallout error={error} />
          <EuiSpacer size="m" />
        </>
      )}
      {page.error != null ? (
        <ErrorCallout error={page.error} onRetry={page.reload} />
      ) : (
        <DataZone>
          <EuiBasicTable<NotificationAttempt>
            items={visible as NotificationAttempt[]}
            columns={columns}
            loading={page.loading}
            responsive
            tableLayout="auto"
            rowProps={(item) => ({
              className: ACKNOWLEDGEABLE.includes(item.status) ? 'b89Row b89Row--p2' : 'b89Row',
            })}
            noItemsMessage={
              page.loading
                ? 'Cargando notificaciones…'
                : onlyPending
                  ? 'No hay notificaciones pendientes de acuse.'
                  : 'Todavía no se ha enviado ninguna notificación.'
            }
          />
          {cursor && (
            <>
              <EuiSpacer size="s" />
              <EuiButtonEmpty size="s" onClick={loadMore}>
                Cargar más
              </EuiButtonEmpty>
            </>
          )}
        </DataZone>
      )}
    </B89Page>
  );
}
