/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiLoadingContent,
  EuiSpacer,
  EuiSwitch,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  ACKNOWLEDGEABLE,
  Alert,
  ALERT_STATUS_LABEL,
  alertQuestion,
  CAPABILITIES,
  NOTIFICATION_CHANNEL_LABEL,
  NotificationAttempt,
  Page,
} from '../../common';
import { B89ApiError } from '../api/client';
import { fetchSource } from '../api/investigation';
import { askBunny } from '../bunny_bridge';
import { B89Page, useChanges, useConsole } from './console_context';
import { alertInvestigationHref } from './investigation_links';
import {
  DataZone,
  EmptyLine,
  ErrorCallout,
  HealthMark,
  Mono,
  PriorityMark,
  Timestamp,
  useAsync,
  useIsMobile,
} from './primitives';
import { VendorLogo } from './vendor_logo';
import { ChannelsPanel } from './channels_panel';
import {
  DELIVERY,
  deliveryLines,
  describeGroup,
  groupNotifications,
  latestByChannel,
  NotificationGroup,
} from './notification_groups';

/**
 * Bandeja de notificaciones (doc 04 §6). Agrupa los avisos de la misma alerta o incidente,
 * muestra de qué alerta se trata (título, prioridad, origen, entidad enmascarada y regla) y el
 * estado de entrega por canal e intento: Enviado (aceptado por M365) / Entregado / Fallido /
 * Reconocido. Entregado no es lo mismo que reconocido por una persona.
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
  const { api, notifications, basePath } = useConsole();
  const [onlyPending, setOnlyPending] = useState(true);
  const [items, setItems] = useState<readonly NotificationAttempt[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<Record<string, Alert | null>>({});
  const [tab, setTab] = useState<'inbox' | 'channels'>('inbox');
  // La pestaña permanece visible aunque la API falle: ocultarla hacía parecer que
  // la configuración de Teams no existía. ChannelsPanel presenta el error real.
  const showChannels = true;
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

  const groups = useMemo(() => groupNotifications(items), [items]);
  const visible = onlyPending
    ? groups.filter((group) => group.items.some((item) => item.status !== 'acknowledged'))
    : groups;
  const visibleKey = visible.map((group) => group.key).join('|');

  // Título y prioridad de la alerta cuando la API solo trae su id (máx. 50 por carga).
  useEffect(() => {
    const missing = visible
      .filter((group) => group.alertId && !(group.alertId in alerts))
      .slice(0, 50)
      .map((group) => group.alertId as string);
    if (missing.length === 0) return undefined;
    let alive = true;
    Promise.all(
      missing.map((id) =>
        api
          .get<{ alert: Alert }>(`/alerts/${encodeURIComponent(id)}`)
          .then((r): [string, Alert | null] => [id, r.alert])
          .catch((): [string, Alert | null] => [id, null]),
      ),
    ).then((pairs) => {
      if (!alive) return;
      setAlerts((current) => {
        const next = { ...current };
        for (const [id, alert] of pairs) next[id] = alert;
        return next;
      });
    });
    return () => {
      alive = false;
    };
  }, [api, visibleKey]); // eslint-disable-line react-hooks/exhaustive-deps

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

  const selected = groups.find((group) => group.key === open) ?? null;

  return (
    <B89Page
      title="Notificaciones"
      description="Avisos por Teams, correo alternativo o consola, agrupados por alerta. Enviado no es lo mismo que entregado, ni entregado lo mismo que reconocido por una persona."
      actions={
        showChannels && tab === 'channels' ? undefined : (
          <EuiSwitch
            compressed
            label="Solo sin acuse"
            checked={onlyPending}
            onChange={(event) => setOnlyPending(event.target.checked)}
          />
        )
      }
    >
      {showChannels && (
        <EuiTabs size="s" className="b89Tabs">
          <EuiTab isSelected={tab === 'inbox'} onClick={() => setTab('inbox')}>
            Bandeja
          </EuiTab>
          <EuiTab isSelected={tab === 'channels'} onClick={() => setTab('channels')}>
            Canales
          </EuiTab>
        </EuiTabs>
      )}
      <EuiSpacer size="m" />
      {showChannels && tab === 'channels' ? (
        <ChannelsPanel />
      ) : (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="iInCircle"
            title="Tiempos y estado de los avisos"
          >
            <p>
              P1 genera un intento inmediato; P2 recientes también. Las P2 procesadas con más de una
              hora de atraso y los avisos agrupados aparecen en resúmenes; P3 y P4 se consolidan
              cada seis horas. Revisa «Canales» para confirmar la configuración y «Salud de fuentes»
              para ver la última actividad recibida.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          {error != null && (
            <>
              <ErrorCallout error={error} />
              <EuiSpacer size="m" />
            </>
          )}
          {page.error != null ? (
            <ErrorCallout error={page.error} onRetry={page.reload} />
          ) : page.loading && items.length === 0 ? (
            <EuiLoadingContent lines={6} />
          ) : visible.length === 0 ? (
            <EmptyLine>
              {onlyPending
                ? 'No hay notificaciones pendientes de acuse.'
                : 'Todavía no se ha enviado ninguna notificación.'}
            </EmptyLine>
          ) : (
            <DataZone>
              <ul className="b89NotifList" aria-label="Notificaciones agrupadas por alerta">
                {visible.map((group) => {
                  const info = describeGroup(group, group.alertId ? alerts[group.alertId] : null);
                  const pending = group.items.some((item) => ACKNOWLEDGEABLE.includes(item.status));
                  return (
                    <li key={group.key}>
                      <button
                        type="button"
                        className={`b89Notif${pending ? ' b89Notif--pending' : ''}`}
                        onClick={() => setOpen(group.key)}
                        aria-haspopup="dialog"
                      >
                        <span className="b89Notif__lead">
                          <VendorLogo id={info.vendor} basePath={basePath} size="m" />
                          {info.priority && <PriorityMark priority={info.priority} />}
                        </span>
                        <span className="b89Notif__body">
                          <span className="b89Notif__title">
                            {info.title ??
                              (group.alertId
                                ? 'Cargando la alerta…'
                                : `Aviso ${(group.latest.messageId ?? group.latest.id).slice(0, 12)}`)}
                            {group.items.length > 1 && (
                              <EuiBadge color="hollow" className="b89Notif__count">
                                ×{group.items.length}
                              </EuiBadge>
                            )}
                          </span>
                          <span className="b89CellMeta">
                            {[info.entity, info.ruleId ? `regla ${info.ruleId}` : null]
                              .filter(Boolean)
                              .join(' · ') ||
                              'La API no informó la alerta de este aviso (ver detalle).'}
                          </span>
                          <span className="b89Notif__deliveries">
                            {latestByChannel(group.items).map((line) => (
                              <span key={line.channel} className="b89Notif__delivery">
                                <span className="b89Muted">
                                  {NOTIFICATION_CHANNEL_LABEL[line.channel] ?? line.channel}:
                                </span>{' '}
                                <HealthMark
                                  tone={DELIVERY[line.kind].tone}
                                  label={DELIVERY[line.kind].label}
                                />
                              </span>
                            ))}
                          </span>
                        </span>
                        <span className="b89Notif__time">
                          <Timestamp iso={group.latest.sentAt ?? group.latest.acknowledgedAt} />
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
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
        </>
      )}
      {selected && (
        <NotificationFlyout
          group={selected}
          alert={selected.alertId ? alerts[selected.alertId] : null}
          busy={busy}
          onAcknowledge={acknowledge}
          onClose={() => setOpen(null)}
        />
      )}
    </B89Page>
  );
}

function NotificationFlyout({
  group,
  alert,
  busy,
  onAcknowledge,
  onClose,
}: {
  group: NotificationGroup;
  alert: Alert | null | undefined;
  busy: string | null;
  onAcknowledge: (attempt: NotificationAttempt) => void;
  onClose: () => void;
}) {
  const { basePath, notifications } = useConsole();
  const mobile = useIsMobile();
  const info = describeGroup(group, alert);
  const source = useAsync(
    () =>
      alert
        ? fetchSource(basePath, {
            ruleId: info.ruleId,
            at: alert.occurredAt,
            description: alert.title.replace(/\s*\(wazuh \d+\)\s*$/u, ''),
          })
        : Promise.resolve(null),
    [basePath, alert?.id],
  );
  const mitre = source.data?.event?.mitre;
  const incidentId = group.incidentId ?? alert?.incidentId ?? null;
  const acknowledgeable = group.items.filter((item) => ACKNOWLEDGEABLE.includes(item.status));
  const acknowledged = group.items.filter((item) => item.acknowledgedAt);
  const lines = group.items
    .flatMap((item) => deliveryLines(item))
    .sort((a, b) => ((a.at ?? '') < (b.at ?? '') ? 1 : -1));

  return (
    <EuiFlyout
      onClose={onClose}
      size={mobile ? 'l' : 'm'}
      ownFocus
      className="b89Flyout"
      aria-labelledby="b89NotifTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
          <EuiFlexItem grow={false}>
            <VendorLogo id={info.vendor} basePath={basePath} size="m" />
          </EuiFlexItem>
          {info.priority && (
            <EuiFlexItem grow={false}>
              <PriorityMark priority={info.priority} />
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiTitle size="s">
          <h2 id="b89NotifTitle" data-b89-no-translate="">
            {info.title ?? 'Aviso sin alerta asociada'}
          </h2>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          <p>
            {group.items.length} {group.items.length === 1 ? 'aviso' : 'avisos agrupados'}
            {info.entity ? ` · ${info.entity}` : ''}
            {info.ruleId ? ` · regla ${info.ruleId}` : ''}
          </p>
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <DataZone>
          <EuiTitle size="xxs">
            <h3>Resumen de la alerta</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          {!group.alertId ? (
            <EmptyLine>
              La API de notificaciones todavía no informa qué alerta originó este aviso (campo
              alertId). En cuanto lo haga, aquí aparecen su resumen y la investigación.
            </EmptyLine>
          ) : alert === undefined ? (
            <EuiLoadingContent lines={2} />
          ) : alert === null ? (
            <EmptyLine>No se pudo leer la alerta (sin permiso o ya no existe).</EmptyLine>
          ) : (
            <dl className="b89KeyValues">
              <dt>Estado</dt>
              <dd>{ALERT_STATUS_LABEL[alert.status]}</dd>
              <dt>Ocurrió</dt>
              <dd>
                <Timestamp iso={alert.occurredAt} />
              </dd>
              <dt>Puntuación</dt>
              <dd className="b89Tabular">{alert.score}</dd>
              {incidentId && (
                <>
                  <dt>Incidente</dt>
                  <dd>
                    <Mono>{incidentId}</Mono>
                  </dd>
                </>
              )}
            </dl>
          )}
          {alert && (
            <>
              <EuiSpacer size="l" />
              <EuiTitle size="xxs">
                <h3>Por qué importa</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              {mitre && mitre.ids.length > 0 && (
                <p className="b89Chips">
                  {mitre.ids.map((id, index) => (
                    <span key={id} className="b89Mitre">
                      {id}
                      {mitre.techniques[index] ? ` · ${mitre.techniques[index]}` : ''}
                    </span>
                  ))}
                </p>
              )}
              {alert.reasons.length === 0 ? (
                <EmptyLine>El motor de priorización no registró motivos.</EmptyLine>
              ) : (
                <ul className="b89List">
                  {alert.reasons.map((reason) => (
                    <li key={reason.code}>
                      <Mono>{reason.code}</Mono> {reason.detail}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          <EuiSpacer size="l" />
          <EuiTitle size="xxs">
            <h3>Entrega por canal e intento</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <ol className="b89DeliveryList">
            {lines.map((line) => (
              <li key={line.key} className="b89DeliveryList__item">
                <HealthMark tone={DELIVERY[line.kind].tone} label={DELIVERY[line.kind].label} />
                <span className="b89CellMeta">
                  {NOTIFICATION_CHANNEL_LABEL[line.channel] ?? line.channel} · intento{' '}
                  {line.attempt} · <Timestamp iso={line.at} />
                  {line.kind === 'acknowledged' && line.actor ? (
                    <>
                      {' '}
                      · por <Mono>{line.actor.slice(0, 24)}</Mono>
                    </>
                  ) : null}
                  {line.reason ? ` · ${line.reason}` : ''}
                </span>
                {line.link && (
                  <a href={line.link} target="_blank" rel="noopener noreferrer">
                    Ver en Teams
                  </a>
                )}
              </li>
            ))}
          </ol>
          <EuiSpacer size="l" />
          <EuiTitle size="xxs">
            <h3>Acuse</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          {acknowledged.length > 0 ? (
            <ul className="b89List">
              {acknowledged.map((item) => (
                <li key={item.id}>
                  Reconocido <Timestamp iso={item.acknowledgedAt} />
                  {item.acknowledgedBy ? (
                    <>
                      {' '}
                      por <Mono>{item.acknowledgedBy.slice(0, 24)}</Mono>
                    </>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <EmptyLine>Nadie ha acusado recibo todavía.</EmptyLine>
          )}
          {acknowledgeable.length > 0 && (
            <EuiButtonEmpty
              size="s"
              flush="left"
              isLoading={busy === acknowledgeable[0].id}
              onClick={() => onAcknowledge(acknowledgeable[0])}
            >
              Acusar recibo
            </EuiButtonEmpty>
          )}
        </DataZone>
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" wrap responsive={false}>
          {incidentId && (
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                href={`${basePath}/app/b89-incidents?id=${encodeURIComponent(incidentId)}`}
              >
                Ver incidente
              </EuiButtonEmpty>
            </EuiFlexItem>
          )}
          {alert && (
            <EuiFlexItem grow={false}>
              <EuiButton
                iconType="discuss"
                onClick={() => {
                  const opened = askBunny({
                    prompt: alertQuestion({
                      id: alert.id,
                      title: alert.title,
                      priority: alert.priority,
                      occurredAt: alert.occurredAt,
                      ruleId: info.ruleId,
                      mitre: mitre?.ids,
                    }),
                    context: { alertId: alert.id },
                  });
                  if (!opened)
                    notifications.toasts.addWarning({ title: 'Bunny no está disponible' });
                }}
              >
                Preguntar a Bunny
              </EuiButton>
            </EuiFlexItem>
          )}
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              iconType="inspect"
              isDisabled={!group.alertId}
              href={group.alertId ? alertInvestigationHref(basePath, group.alertId) : undefined}
            >
              Abrir en investigación
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
}
