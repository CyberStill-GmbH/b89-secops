/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiConfirmModal,
  EuiFieldText,
  EuiFormRow,
  EuiLink,
  EuiLoadingContent,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import {
  CAPABILITIES,
  HealthTone,
  NOTIFICATION_CHANNEL_LABEL,
  NotificationChannel,
  NotificationChannelState,
  NotificationChannelTest,
  NotificationChannelView,
} from '../../common';
import { B89ApiError } from '../api/client';
import {
  channelTestSuccessLabel,
  normalizeChannelTest,
  normalizeChannelsResponse,
} from './channels_contract';
import { channelDestinationSummary } from './channels_display';
import { useConsole } from './console_context';
import { webhookProblem } from './notification_groups';
import { EmptyLine, ErrorCallout, HealthMark, Mono, Timestamp, useAsync } from './primitives';

/**
 * «Canales»: estado de Microsoft Teams, correo y consola; webhook de Teams, prueba y
 * activación. Solo `notifications.manage` (b89.platform.admin) cambia algo; el resto lo ve en
 * lectura. El destino sensible no se vuelve a renderizar en la interfaz.
 */

export const WORKFLOWS_HELP_URL =
  'https://support.microsoft.com/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498';

const STATE: Record<NotificationChannelState, { label: string; tone: HealthTone }> = {
  active: { label: 'Activo', tone: 'ok' },
  inactive: { label: 'Inactivo', tone: 'neutral' },
  failing: { label: 'Con errores', tone: 'fail' },
  unconfigured: { label: 'No configurado', tone: 'warn' },
  unknown: { label: 'Sin una prueba reciente', tone: 'neutral' },
};

const CHANNEL_HINT: Record<NotificationChannel, string> = {
  teams: 'Envía avisos al canal del SOC mediante un flujo de Workflows en Microsoft Teams.',
  fallback_email:
    'Envía un correo al buzón del SOC si Teams no confirma. El destino se configura en el servicio.',
  manual_console: 'Bandeja interna de B89. Siempre disponible como último canal de respaldo.',
};

export function ChannelsPanel() {
  const { api, can, notifications } = useConsole();
  const manage = can(CAPABILITIES.notificationsManage);
  const loaded = useAsync(
    async () => normalizeChannelsResponse(await api.get<unknown>('/notifications/channels')),
    [api],
  );
  const [editing, setEditing] = useState(false);
  const [toggle, setToggle] = useState<NotificationChannelView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<string, NotificationChannelTest | { error: string }>>(
    {},
  );
  const [error, setError] = useState<unknown>(null);

  const unavailable =
    loaded.error instanceof B89ApiError &&
    (loaded.error.status === 404 || loaded.error.code === 'RESOURCE_UNAVAILABLE');

  const runTest = async (channel: NotificationChannelView) => {
    setBusy(`test-${channel.id}`);
    try {
      const response = await api.post<unknown>(
        `/notifications/channels/${encodeURIComponent(channel.apiId ?? channel.id)}/test`,
      );
      const result = normalizeChannelTest(response);
      setTests((current) => ({ ...current, [channel.id]: result }));
      loaded.reload();
    } catch (failure) {
      setTests((current) => ({
        ...current,
        [channel.id]: {
          error: failure instanceof B89ApiError ? failure.message : 'No se pudo enviar la prueba.',
        },
      }));
    } finally {
      setBusy(null);
    }
  };

  const setEnabled = async (channel: NotificationChannelView, enabled: boolean) => {
    setBusy(`toggle-${channel.id}`);
    setError(null);
    try {
      await api.post(
        `/notifications/channels/${encodeURIComponent(channel.apiId ?? channel.id)}/${enabled ? 'enable' : 'disable'}`,
        channel.revision !== undefined ? { expectedRevision: channel.revision } : {},
      );
      notifications.toasts.addSuccess({
        title: `${NOTIFICATION_CHANNEL_LABEL[channel.id]} ${enabled ? 'activado' : 'desactivado'}`,
      });
      loaded.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
      setToggle(null);
    }
  };

  if (loaded.loading && !loaded.data) return <EuiLoadingContent lines={4} />;
  if (unavailable) {
    return (
      <EmptyLine>
        La gestión de canales todavía no está publicada en la API B89 (GET
        /api/notifications/channels). La bandeja sigue funcionando.
      </EmptyLine>
    );
  }
  if (loaded.error) return <ErrorCallout error={loaded.error} onRetry={loaded.reload} />;
  const channels = loaded.data?.channels ?? [];
  const teams = channels.find((channel) => channel.id === 'teams') ?? null;

  return (
    <>
      {!manage && (
        <>
          <EuiCallOut
            size="s"
            iconType="lock"
            title="Solo lectura: cambiar canales requiere el rol de administración de la plataforma."
          />
          <EuiSpacer size="m" />
        </>
      )}
      {error != null && (
        <>
          <ErrorCallout error={error} />
          <EuiSpacer size="m" />
        </>
      )}
      {channels.length === 0 ? (
        <EmptyLine>No hay canales de notificación para mostrar.</EmptyLine>
      ) : (
        <ul className="b89Channels" lang="es-PE" translate="no">
          {channels.map((channel) => {
            const state = STATE[channel.state] ?? STATE.unconfigured;
            const test = tests[channel.id];
            return (
              <li key={channel.id} className="b89Channel" data-state={channel.state}>
                <div className="b89Channel__head">
                  <h3>{NOTIFICATION_CHANNEL_LABEL[channel.id] ?? channel.id}</h3>
                  <HealthMark tone={state.tone} label={state.label} />
                </div>
                <p className="b89CellMeta">{CHANNEL_HINT[channel.id]}</p>
                {channel.enabled && !channel.configured && channel.id !== 'manual_console' && (
                  <p className="b89CellMeta" role="status">
                    El canal está activado, pero falta configurar el destino. No podrá entregar
                    avisos hasta que esté listo.
                  </p>
                )}
                <dl className="b89KeyValues">
                  <dt>Destino</dt>
                  <dd>{channelDestinationSummary(channel)}</dd>
                  <dt>Último intento de entrega</dt>
                  <dd>
                    {channel.lastDelivery ? (
                      <>
                        {channel.lastDelivery.ok ? 'Correcta' : 'Fallida'} ·{' '}
                        <Timestamp iso={channel.lastDelivery.at} />
                        {channel.lastDelivery.reason ? ` · ${channel.lastDelivery.reason}` : ''}
                      </>
                    ) : (
                      'Aún no hay intentos de entrega'
                    )}
                  </dd>
                  {channel.updatedAt && (
                    <>
                      <dt>Cambiado</dt>
                      <dd>
                        <Timestamp iso={channel.updatedAt} />
                        {channel.updatedBy ? (
                          <>
                            {' '}
                            por <Mono>{channel.updatedBy.slice(0, 24)}</Mono>
                          </>
                        ) : null}
                      </dd>
                    </>
                  )}
                </dl>
                {test && (
                  <EuiText size="xs" className="b89Channel__test" role="status">
                    <p>
                      {'error' in test ? (
                        <HealthMark tone="fail" label={`Prueba fallida: ${test.error}`} />
                      ) : test.ok ? (
                        <HealthMark
                          tone="ok"
                          label={`${channelTestSuccessLabel(test)}${test.latencyMs ? ` en ${test.latencyMs} ms` : ''}`}
                        />
                      ) : (
                        <HealthMark
                          tone="fail"
                          label={`Prueba fallida${test.reason ? `: ${test.reason}` : ''}`}
                        />
                      )}
                    </p>
                  </EuiText>
                )}
                {manage &&
                  (channel.id === 'manual_console' ? (
                    <p className="b89CellMeta b89Channel__alwaysOn" role="note">
                      Este canal de respaldo siempre está disponible y no se puede desactivar.
                    </p>
                  ) : (
                    <div
                      className="b89Channel__actions"
                      role="group"
                      aria-label={`Acciones para ${NOTIFICATION_CHANNEL_LABEL[channel.id]}`}
                    >
                      {channel.id === 'teams' && (
                        <EuiButton size="s" onClick={() => setEditing(true)}>
                          {channel.configured ? 'Cambiar configuración' : 'Configurar Teams'}
                        </EuiButton>
                      )}
                      <EuiButtonEmpty
                        size="s"
                        isDisabled={!channel.configured}
                        isLoading={busy === `test-${channel.id}`}
                        onClick={() => runTest(channel)}
                      >
                        Enviar prueba
                      </EuiButtonEmpty>
                      <EuiButtonEmpty
                        size="s"
                        color={channel.enabled ? 'danger' : 'primary'}
                        isDisabled={!channel.configured && !channel.enabled}
                        isLoading={busy === `toggle-${channel.id}`}
                        onClick={() => setToggle(channel)}
                      >
                        {channel.enabled ? 'Desactivar' : 'Activar'}
                      </EuiButtonEmpty>
                    </div>
                  ))}
              </li>
            );
          })}
        </ul>
      )}
      {editing && teams && (
        <WebhookModal
          channel={teams}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            notifications.toasts.addSuccess({ title: 'Webhook de Teams actualizado' });
            loaded.reload();
          }}
        />
      )}
      {toggle && (
        <EuiConfirmModal
          title={`¿${toggle.enabled ? 'Desactivar' : 'Activar'} ${NOTIFICATION_CHANNEL_LABEL[toggle.id]}?`}
          onCancel={() => setToggle(null)}
          onConfirm={() => setEnabled(toggle, !toggle.enabled)}
          cancelButtonText="Cancelar"
          confirmButtonText={toggle.enabled ? 'Desactivar' : 'Activar'}
          buttonColor={toggle.enabled ? 'danger' : 'primary'}
        >
          <p>
            {toggle.enabled
              ? 'Los avisos dejarán de salir por este canal hasta que lo vuelvas a activar. El cambio queda en la auditoría.'
              : 'Los avisos volverán a salir por este canal. El cambio queda en la auditoría.'}
          </p>
        </EuiConfirmModal>
      )}
    </>
  );
}

function WebhookModal({
  channel,
  onClose,
  onSaved,
}: {
  channel: NotificationChannelView;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { api } = useConsole();
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = webhookProblem(value);
  const touched = value.length > 0;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.put('/notifications/channels/teams', {
        webhookUrl: value.trim(),
        ...(channel.revision !== undefined ? { expectedRevision: channel.revision } : {}),
      });
      onSaved();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiModal onClose={onClose} aria-labelledby="b89WebhookTitle" lang="es-PE" translate="no">
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          <h2 id="b89WebhookTitle">Webhook de Microsoft Teams</h2>
        </EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiText size="s">
          <p>
            En el canal del SOC, configura un flujo de Workflows para publicar los avisos de B89.
            Después pega aquí la URL que genera el flujo.{' '}
            <EuiLink href={WORKFLOWS_HELP_URL} target="_blank" external>
              Instrucciones de Microsoft
            </EuiLink>
          </p>
          {channel.target && (
            <p>
              Actual: URL protegida. Para cambiarla, pega la nueva URL; la anterior no se puede
              recuperar.
            </p>
          )}
        </EuiText>
        <EuiSpacer size="m" />
        {error != null && <ErrorCallout error={error} />}
        <EuiFormRow
          label="URL del webhook"
          fullWidth
          isInvalid={touched && problem !== null}
          error={touched && problem ? problem : undefined}
          helpText="La URL se guarda cifrada y no volverá a mostrarse completa."
        >
          <EuiFieldText
            fullWidth
            type="password"
            autoComplete="off"
            value={value}
            isInvalid={touched && problem !== null}
            onChange={(event) => setValue(event.target.value)}
            placeholder="https://….logic.azure.com/workflows/…"
          />
        </EuiFormRow>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose} isDisabled={busy}>
          Cancelar
        </EuiButtonEmpty>
        <EuiButton fill isLoading={busy} isDisabled={problem !== null} onClick={save}>
          Guardar webhook
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
