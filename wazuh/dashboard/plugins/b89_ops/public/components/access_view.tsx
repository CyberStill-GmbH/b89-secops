/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiDescriptionList,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiLoadingContent,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiSelect,
  EuiTab,
  EuiTabs,
  EuiTextArea,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  AdminSession,
  amrText,
  CAPABILITIES,
  LOGOUT_PATH,
  DirectorySync,
  DirectoryUser,
  DirectoryUserDetail,
  Page,
  RequestableRole,
  ROLE_LABEL,
  RoleGrantView,
  RoleRequestAction,
  RoleRequestListResponse,
  RoleRequestView,
  SESSION_STATE_LABEL,
  ROLE_ORIGIN_LABEL,
  userState,
} from '../../common';
import { B89ApiError } from '../api/client';
import { B89Page, useChanges, useConsole } from './console_context';
import { EmptyLine, ErrorCallout, HealthMark, Mono, Timestamp, useAsync } from './primitives';

const REASON_MIN = 10;
const REASON_MAX = 500;

/**
 * La identidad de servicio no tiene un app role de lectura de grupos concedido en Microsoft Graph.
 * No es un error: el API reintenta solo y el padrón se activa sin reiniciar al concederse.
 */
function PermissionMissingCallout({
  nextAttemptAt,
  diagnostic,
}: {
  nextAttemptAt: string | null | undefined;
  diagnostic?: DirectorySync['diagnostic'];
}) {
  return (
    <EuiCallOut
      size="s"
      color="warning"
      iconType="lock"
      title="La identidad de B89 no tiene permiso de lectura de grupos en Microsoft Graph"
    >
      <p>
        B89 recibió una denegación de Graph al resolver o leer Accesos_SOC. Revisa que la identidad
        de aplicación configurada en el API tenga GroupMember.Read.All o Group.Read.All como permiso
        de aplicación de Microsoft Graph, con consentimiento de administrador, en el mismo registro
        de aplicación que usa B89. El token se renovará automáticamente y el grupo se volverá a
        resolver sin reiniciar el servicio.
      </p>
      {diagnostic && (
        <p>
          Diagnóstico Graph: HTTP {diagnostic.status}
          {diagnostic.errorCode ? ` · ${diagnostic.errorCode}` : ''}
          {diagnostic.operation ? ` · ${diagnostic.operation}` : ''}
          {diagnostic.requestId ? ` · request-id ${diagnostic.requestId}` : ''}
        </p>
      )}
      {nextAttemptAt && (
        <p>
          Próximo intento automático: <Timestamp iso={nextAttemptAt} />
        </p>
      )}
    </EuiCallOut>
  );
}

function Roles({ roles }: { roles: readonly string[] }) {
  if (roles.length === 0) return <span className="b89Muted">Sin rol</span>;
  return (
    <span className="b89IdList">
      {roles.map((role) => (
        <EuiBadge key={role} color="hollow">
          {ROLE_LABEL[role] ?? role}
        </EuiBadge>
      ))}
    </span>
  );
}

export function AccessView() {
  const { can } = useConsole();
  const canUsers = can(CAPABILITIES.usersRead);
  const canSessions = can(CAPABILITIES.sessionsRead);
  const canRoleRequests = can(CAPABILITIES.rolesRequest);
  const canReviewRoles = can(CAPABILITIES.rolesApprove) || can(CAPABILITIES.rolesApprovePrivileged);
  const requestedTab =
    typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('tab') : null;
  const [tab, setTab] = useState<'users' | 'sessions' | 'role-requests'>(
    requestedTab === 'role-requests' && (canRoleRequests || canReviewRoles)
      ? 'role-requests'
      : requestedTab === 'sessions' && canSessions
        ? 'sessions'
        : canUsers
          ? 'users'
          : canSessions
            ? 'sessions'
            : 'role-requests',
  );

  return (
    <B89Page
      title="Usuarios y sesiones"
      description="Entra quien está en el grupo Accesos_SOC de Microsoft Entra ID. Salir del grupo cierra sus sesiones abiertas."
    >
      <div lang="es-PE" translate="no">
      {!canUsers && !canSessions && !canRoleRequests && !canReviewRoles ? (
        <EmptyLine>Tu rol no incluye la administración de accesos.</EmptyLine>
      ) : (
        <>
          <EuiTabs size="s" className="b89Tabs">
            {canUsers && (
              <EuiTab isSelected={tab === 'users'} onClick={() => setTab('users')}>
                Miembros
              </EuiTab>
            )}
            {canSessions && (
              <EuiTab isSelected={tab === 'sessions'} onClick={() => setTab('sessions')}>
                Sesiones
              </EuiTab>
            )}
            {(canRoleRequests || canReviewRoles) && (
              <EuiTab isSelected={tab === 'role-requests'} onClick={() => setTab('role-requests')}>
                Solicitudes de rol
              </EuiTab>
            )}
          </EuiTabs>
          <EuiSpacer size="m" />
          {tab === 'users' && canUsers && <UsersPanel />}
          {tab === 'sessions' && canSessions && <SessionsPanel />}
          {tab === 'role-requests' && (canRoleRequests || canReviewRoles) && (
            <RoleRequestsPanel canReviewRoles={canReviewRoles} />
          )}
        </>
      )}
      </div>
    </B89Page>
  );
}

function UsersPanel() {
  const { api } = useConsole();
  const users = useAsync(
    () =>
      api.get<{ sync: DirectorySync; items: DirectoryUser[]; totalCount: number }>('/admin/users'),
    [api],
  );
  const [selected, setSelected] = useState<string | null>(null);
  useChanges(['session'], () => users.reload(), 1000);
  if (users.error) return <ErrorCallout error={users.error} onRetry={users.reload} />;

  const columns: Array<EuiBasicTableColumn<DirectoryUser>> = [
    {
      field: 'displayName',
      name: 'Persona',
      truncateText: false,
      render: (value: string | null, user: DirectoryUser) => (
        <span className="b89CellTitle" data-b89-no-translate="">
          <EuiButtonEmpty
            size="xs"
            flush="left"
            onClick={() => setSelected(user.oid)}
            aria-label={`Abrir el detalle de ${value ?? user.upn ?? 'esta persona'}`}
          >
            {value ?? 'Sin nombre'}
          </EuiButtonEmpty>
          <span className="b89CellMeta">{user.upn ?? 'Sin cuenta en el directorio'}</span>
        </span>
      ),
      mobileOptions: { header: false },
    },
    {
      name: 'Estado',
      render: (user: DirectoryUser) => {
        const state = userState(user);
        return <HealthMark tone={state.tone} label={state.label} />;
      },
    },
    {
      field: 'membership',
      name: 'Grupo Accesos_SOC',
      render: (value: DirectoryUser['membership'], user: DirectoryUser) =>
        value === 'member' ? (
          user.isOwner ? (
            'Propietario'
          ) : (
            'Miembro'
          )
        ) : value === 'removed' ? (
          'Retirado'
        ) : user.isOwner ? (
          'Propietario'
        ) : (
          <span className="b89Muted">Sin dato</span>
        ),
    },
    {
      field: 'roles',
      name: 'Rol y origen',
      render: (roles: string[], user: DirectoryUser) => (
        <span className="b89CellTitle">
          <Roles roles={roles} />
          <span className="b89CellMeta">
            {ROLE_ORIGIN_LABEL[user.roleOrigin] ?? user.roleOrigin}
          </span>
        </span>
      ),
    },
    {
      field: 'activeSessions',
      name: 'Sesiones activas',
      align: 'right',
      render: (value: number) => <span className="b89Tabular">{value}</span>,
    },
    {
      field: 'lastSeenAt',
      name: 'Última actividad',
      render: (value: string | null) => <Timestamp iso={value} />,
    },
  ];

  const sync = users.data?.sync;
  // Miembros vigentes sin ningún rol: el administrador debe asignarles uno.
  const pending = (users.data?.items ?? []).filter(
    (user) =>
      user.membership === 'member' && user.accountEnabled === true && user.roles.length === 0,
  );
  return (
    <>
      {sync && sync.mode !== 'graph' && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="iInCircle"
            title="Sin sincronización con Microsoft Graph."
          >
            <p>
              Solo se listan los dueños del grupo y las asignaciones del despliegue; no hay datos de
              cuenta ni de pertenencia.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {sync?.permissionMissing && (
        <>
          <PermissionMissingCallout
            nextAttemptAt={sync.nextAttemptAt}
            diagnostic={sync.diagnostic}
          />
          <EuiSpacer size="m" />
        </>
      )}
      {pending.length > 0 && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="user"
            title={`${pending.length} ${pending.length === 1 ? 'miembro pendiente' : 'miembros pendientes'} de rol`}
          >
            <p>
              Entraron a Accesos_SOC y todavía no tienen rol en B89: no pueden operar hasta que se
              les asigne uno. Abre cada persona y usa «Asignar rol».
            </p>
            <ul className="b89IdList">
              {pending.map((user) => (
                <li key={user.oid}>
                  <EuiButtonEmpty
                    size="xs"
                    iconType="plusInCircle"
                    onClick={() => setSelected(user.oid)}
                    data-b89-no-translate=""
                  >
                    {user.displayName ?? user.upn ?? user.oid}
                  </EuiButtonEmpty>
                </li>
              ))}
            </ul>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {sync &&
        sync.mode === 'graph' &&
        !sync.permissionMissing &&
        (sync.status !== 'ok' || sync.stale) && (
          <>
            <EuiCallOut
              size="s"
              color="warning"
              iconType="alert"
              title={
                sync.status === 'never'
                  ? 'El directorio todavía no se ha sincronizado con Entra ID.'
                  : sync.status === 'failed'
                    ? `La última sincronización con Entra ID falló${sync.lastErrorClass ? ` (${sync.lastErrorClass})` : ''}.`
                    : 'La sincronización con Entra ID está desactualizada.'
              }
            >
              <p>
                Última correcta: <Timestamp iso={sync.lastSuccessAt} />
              </p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        )}
      <EuiBasicTable<DirectoryUser>
        items={users.data?.items ?? []}
        columns={columns}
        loading={users.loading}
        responsive
        tableLayout="auto"
        rowProps={(user: DirectoryUser) => ({
          onClick: () => setSelected(user.oid),
          className: 'b89Row',
        })}
        noItemsMessage={
          users.loading ? 'Cargando miembros…' : 'El grupo no tiene miembros sincronizados.'
        }
      />
      {selected && <UserFlyout oid={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

/** Detalle de una persona (`GET /api/admin/users/:oid`): estado, rol y sus sesiones de 7 días. */
function UserFlyout({ oid, onClose }: { oid: string; onClose: () => void }) {
  const { api, can } = useConsole();
  const canRequestRole = can(CAPABILITIES.rolesRequest);
  const detail = useAsync(
    () => api.get<DirectoryUserDetail>(`/admin/users/${encodeURIComponent(oid)}`),
    [api, oid],
  );
  const user = detail.data?.user;
  const state = user ? userState(user) : null;
  const [requestingRole, setRequestingRole] = useState(false);
  return (
    <EuiFlyout onClose={onClose} size="m" className="b89Flyout" aria-labelledby="b89UserTitle">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h2 id="b89UserTitle" data-b89-no-translate="">
            {user?.displayName ?? user?.upn ?? 'Persona'}
          </h2>
        </EuiTitle>
        {state && (
          <>
            <EuiSpacer size="xs" />
            <HealthMark tone={state.tone} label={state.label} />
          </>
        )}
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {detail.error != null && <ErrorCallout error={detail.error} onRetry={detail.reload} />}
        {user && detail.data && (
          <>
            <EuiDescriptionList
              type="responsiveColumn"
              compressed
              className="b89Facts"
              listItems={[
                {
                  title: 'Cuenta',
                  description: user.upn ? <Mono>{user.upn}</Mono> : 'Sin dato',
                },
                { title: 'Identificador en Entra', description: <Mono>{user.oid}</Mono> },
                {
                  title: 'Cuenta en Entra',
                  description:
                    user.accountEnabled === null
                      ? 'Sin dato'
                      : user.accountEnabled
                        ? 'Habilitada'
                        : 'Deshabilitada',
                },
                {
                  title: 'Grupo Accesos_SOC',
                  description:
                    user.membership === 'member'
                      ? 'Miembro'
                      : user.membership === 'removed'
                        ? 'Retirado'
                        : 'Sin dato',
                },
                { title: 'Roles', description: <Roles roles={user.roles} /> },
                {
                  title: 'Origen del rol',
                  description: ROLE_ORIGIN_LABEL[user.roleOrigin] ?? user.roleOrigin,
                },
              ]}
            />
            {canRequestRole && (
              <>
                <EuiSpacer size="m" />
                <EuiButton
                  size="s"
                  iconType="pencil"
                  isDisabled={user.membership !== 'member' || user.accountEnabled !== true}
                  onClick={() => setRequestingRole(true)}
                >
                  {user.roles.length === 0 ? 'Asignar rol' : 'Cambiar rol'}
                </EuiButton>
                {user.membership !== 'member' ? (
                  <p className="b89CellMeta">
                    Solo se pueden solicitar roles para miembros vigentes de Accesos_SOC.
                  </p>
                ) : user.accountEnabled !== true ? (
                  <p className="b89CellMeta">
                    La cuenta está deshabilitada o sin dato en Entra: habilítala allí para poder
                    cambiar su rol.
                  </p>
                ) : null}
              </>
            )}
            <EuiSpacer size="l" />
            <EuiTitle size="xxs">
              <h3>Sesiones (últimos 7 días)</h3>
            </EuiTitle>
            <EuiSpacer size="s" />
            {detail.data.sessions.length === 0 ? (
              <EmptyLine>Sin sesiones en la ventana.</EmptyLine>
            ) : (
              <ol className="b89Timeline">
                {detail.data.sessions.map((item) => (
                  <li key={item.ref} className="b89Timeline__item">
                    <span className="b89Timeline__time">
                      <Timestamp iso={item.lastSeenAt} />
                    </span>
                    <span className="b89Timeline__body">
                      <span>
                        {SESSION_STATE_LABEL[item.state]}
                        {item.current ? ' · esta sesión' : ''}
                      </span>
                      <span className="b89CellMeta">
                        {amrText(item.amr)}
                        {item.revocationReason ? ` · ${item.revocationReason}` : ''}
                      </span>
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </>
        )}
      </EuiFlyoutBody>
      {requestingRole && user && (
        <RoleChangeModal
          user={user}
          onClose={() => setRequestingRole(false)}
          onSubmitted={() => {
            setRequestingRole(false);
            detail.reload();
          }}
        />
      )}
    </EuiFlyout>
  );
}

const ROLE_REQUEST_STATUS_LABEL: Record<RoleRequestView['status'], string> = {
  pending_access: 'Espera aprobación de Accesos',
  pending_security: 'Espera aprobación de Seguridad',
  approved: 'Aprobada',
  rejected: 'Rechazada',
  cancelled: 'Cancelada',
};

/** Nombre de una persona del padrón por su identificador de Entra; el identificador en el tooltip. */
export function PersonName({
  oid,
  names,
  viewerId,
}: {
  oid: string;
  names: ReadonlyMap<string, string>;
  viewerId: string;
}) {
  const name = oid === viewerId ? 'Tú' : names.get(oid);
  return (
    <EuiToolTip content={`Identificador en Entra: ${oid}`}>
      <span tabIndex={0} className="b89Person" data-b89-no-translate="">
        {name ?? 'Persona fuera del padrón'}
      </span>
    </EuiToolTip>
  );
}

/** «Ana Pérez pide conceder Analista SOC a Luis Rojas». */
export function RoleRequestSentence({
  request,
  names,
  viewerId,
}: {
  request: RoleRequestView;
  names: ReadonlyMap<string, string>;
  viewerId: string;
}) {
  const role = ROLE_LABEL[request.role] ?? request.role;
  return (
    <span>
      <PersonName oid={request.requesterOid} names={names} viewerId={viewerId} />{' '}
      {request.requesterOid === viewerId ? 'pides' : 'pide'}{' '}
      {request.action === 'grant' ? `conceder ${role} a` : `retirar ${role} a`}{' '}
      <PersonName oid={request.targetOid} names={names} viewerId={viewerId} />
    </span>
  );
}

/** Nombres del padrón (`GET /api/admin/users`) por identificador, si el rol puede leerlo. */
function useDirectoryNames(): ReadonlyMap<string, string> {
  const { api, can } = useConsole();
  const canUsers = can(CAPABILITIES.usersRead);
  const users = useAsync(
    () =>
      canUsers
        ? api.get<{ items: DirectoryUser[] }>('/admin/users')
        : Promise.resolve({ items: [] as DirectoryUser[] }),
    [api, canUsers],
  );
  return useMemo(() => {
    const map = new Map<string, string>();
    for (const user of users.data?.items ?? []) {
      const name = user.displayName ?? user.upn;
      if (name) map.set(user.oid, name);
    }
    return map;
  }, [users.data]);
}

function RoleRequestsPanel({ canReviewRoles }: { canReviewRoles: boolean }) {
  const { api, can, session } = useConsole();
  const requests = useAsync(() => api.get<RoleRequestListResponse>('/admin/role-requests'), [api]);
  const names = useDirectoryNames();
  const [filter, setFilter] = useState<'pending' | 'all'>('pending');
  const [selected, setSelected] = useState<RoleRequestView | null>(null);
  const [items, setItems] = useState<readonly RoleRequestView[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);
  const canApproveAccess = can(CAPABILITIES.rolesApprove);
  const canApproveSecurity = can(CAPABILITIES.rolesApprovePrivileged);

  useEffect(() => {
    if (requests.data) {
      setItems(requests.data.items);
      setCursor(requests.data.nextCursor);
    }
  }, [requests.data]);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const next = await api.get<RoleRequestListResponse>('/admin/role-requests', { cursor });
      setItems((current) => [...current, ...next.items]);
      setCursor(next.nextCursor);
    } catch (error) {
      setMoreError(error);
    } finally {
      setLoadingMore(false);
    }
  };

  if (requests.error) return <ErrorCallout error={requests.error} onRetry={requests.reload} />;
  const directoryState = requests.data?.directory;
  const isPending = (request: RoleRequestView) => request.status.startsWith('pending');
  const pendingCount = items.filter(isPending).length;
  const visible = filter === 'pending' ? items.filter(isPending) : [...items];
  const securityPending = items.filter(
    (request) => request.approvalStage === 'security' && isPending(request),
  ).length;

  const columns: Array<EuiBasicTableColumn<RoleRequestView>> = [
    {
      field: 'createdAt',
      name: 'Creada',
      render: (value: string) => <Timestamp iso={value} />,
    },
    {
      name: 'Cambio solicitado',
      render: (request: RoleRequestView) => (
        <span className="b89CellTitle">
          <RoleRequestSentence request={request} names={names} viewerId={session.subjectId} />
          {request.ticket && <span className="b89CellMeta">Ticket {request.ticket}</span>}
        </span>
      ),
    },
    {
      field: 'approvalStage',
      name: 'Etapa',
      render: (stage: RoleRequestView['approvalStage']) =>
        stage === 'security'
          ? 'Seguridad (pide inicio de sesión reciente)'
          : stage === 'access'
            ? 'Accesos'
            : 'Terminada',
    },
    {
      field: 'status',
      name: 'Estado',
      render: (status: RoleRequestView['status']) => (
        <EuiBadge color={status.startsWith('pending') ? 'warning' : 'hollow'}>
          {ROLE_REQUEST_STATUS_LABEL[status]}
        </EuiBadge>
      ),
    },
    {
      name: 'Acciones',
      width: '130px',
      render: (request: RoleRequestView) => {
        const stageCapability =
          request.approvalStage === 'access'
            ? canApproveAccess
            : request.approvalStage === 'security'
              ? canApproveSecurity
              : false;
        if (request.approvalStage === null) return null;
        if (request.requesterOid === session.subjectId) {
          return <span className="b89CellMeta">La revisa otra persona</span>;
        }
        if (!stageCapability) {
          return (
            <span className="b89CellMeta">
              {request.approvalStage === 'security'
                ? 'La aprueba Seguridad'
                : 'La aprueba Accesos'}
            </span>
          );
        }
        return (
          <EuiButtonEmpty size="xs" onClick={() => setSelected(request)}>
            Revisar
          </EuiButtonEmpty>
        );
      },
    },
  ];

  return (
    <>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive wrap>
        <EuiFlexItem grow>
          <p>
            Asignar un rol crea una solicitud: la aprueba otra persona (Acceso y, para Administrador
            de plataforma, también Seguridad) y todo queda en auditoría. Nadie aprueba lo que pidió.
          </p>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty size="s" iconType="refresh" onClick={requests.reload}>
            Actualizar
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>
      {canApproveSecurity && securityPending > 0 && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="iInCircle"
            title={`${securityPending} ${securityPending === 1 ? 'solicitud espera' : 'solicitudes esperan'} la aprobación de Seguridad.`}
          >
            <p>
              Esa etapa pide un inicio de sesión reciente. Si al aprobar aparece el aviso de inicio
              de sesión reciente, cierra sesión, vuelve a entrar y repite la aprobación desde esta
              pestaña.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {directoryState?.permissionMissing && (
        <>
          <PermissionMissingCallout
            nextAttemptAt={directoryState.nextAttemptAt}
            diagnostic={directoryState.diagnostic}
          />
          <EuiSpacer size="m" />
        </>
      )}
      {directoryState && !directoryState.permissionMissing && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="iInCircle"
            title={
              directoryState.status === 'pending'
                ? `El grupo Accesos_SOC aún no se pudo leer${directoryState.lastErrorClass ? ` (${directoryState.lastErrorClass})` : ''}; se reintenta solo.`
                : 'Sin sincronización con Microsoft Graph: no hay solicitudes de rol posibles.'
            }
          />
          <EuiSpacer size="m" />
        </>
      )}
      <div className="b89Segmented" role="group" aria-label="Mostrar solicitudes">
        <EuiButtonEmpty
          size="s"
          aria-pressed={filter === 'pending'}
          isSelected={filter === 'pending'}
          onClick={() => setFilter('pending')}
        >
          Pendientes ({pendingCount})
        </EuiButtonEmpty>
        <EuiButtonEmpty
          size="s"
          aria-pressed={filter === 'all'}
          isSelected={filter === 'all'}
          onClick={() => setFilter('all')}
        >
          Todas ({items.length})
        </EuiButtonEmpty>
      </div>
      <EuiSpacer size="s" />
      <EuiBasicTable<RoleRequestView>
        items={visible}
        columns={columns}
        loading={requests.loading}
        responsive
        tableLayout="auto"
        noItemsMessage={
          requests.loading
            ? 'Cargando solicitudes…'
            : filter === 'pending'
              ? 'No hay solicitudes pendientes.'
              : 'No hay solicitudes de rol.'
        }
      />
      {moreError != null && <ErrorCallout error={moreError} />}
      {cursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButtonEmpty size="s" isLoading={loadingMore} onClick={loadMore}>
            Cargar más
          </EuiButtonEmpty>
        </>
      )}
      {selected && (
        <RoleDecisionModal
          names={names}
          request={selected}
          onClose={() => setSelected(null)}
          onDecided={() => {
            setSelected(null);
            requests.reload();
          }}
        />
      )}
    </>
  );
}

function RoleChangeModal({
  user,
  onClose,
  onSubmitted,
}: {
  user: DirectoryUser;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const { api } = useConsole();
  const current = useAsync(
    () => api.get<RoleGrantView>(`/admin/users/${encodeURIComponent(user.oid)}/role-grant`),
    [api, user.oid],
  );
  const [action, setAction] = useState<RoleRequestAction>('grant');
  const [role, setRole] = useState<RequestableRole>('b89.soc.analyst');
  const [reason, setReason] = useState('');
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [created, setCreated] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);
  const length = reason.trim().length;
  const grantRoles = current.data?.grant.roles ?? [];
  const availableRoles = (current.data?.assignableRoles ?? []).filter((value) =>
    action === 'grant' ? !user.roles.includes(value) : grantRoles.includes(value),
  );
  const roleExists = availableRoles.includes(role);
  const optionsKey = availableRoles.join('|');
  // El rol elegido siempre es una opción visible: si cambia la lista, se toma la primera.
  useEffect(() => {
    if (!availableRoles.includes(role) && availableRoles.length > 0) setRole(availableRoles[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [optionsKey]);
  const blockedReason = !current.data
    ? null
    : !current.data.eligible
      ? 'La cuenta no es elegible: debe ser miembro vigente de Accesos_SOC y estar habilitada.'
      : availableRoles.length === 0
        ? 'No hay un rol que se pueda elegir para esta acción.'
        : length < REASON_MIN
          ? `Escribe un motivo de al menos ${REASON_MIN} caracteres (faltan ${REASON_MIN - length}).`
          : null;

  const submit = async () => {
    if (!current.data?.eligible || !roleExists || length < REASON_MIN) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ request: RoleRequestView | null; applied?: boolean }>(
        `/admin/users/${encodeURIComponent(user.oid)}/role-requests`,
        {
          action,
          role,
          reason: reason.trim(),
          ticket: ticket.trim() || null,
          expectedRevision: current.data.grant.revision,
        },
      );
      if (result.applied) {
        setApplied(true);
        current.reload();
      } else if (result.request) {
        setCreated(result.request.id);
      }
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiModal
      onClose={onClose}
      className="b89Modal"
      maxWidth={560}
      aria-labelledby="b89-role-change-title"
    >
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          <h2 id="b89-role-change-title">
            {user.roles.length === 0 ? 'Asignar rol' : 'Cambiar rol'} a{' '}
            {user.displayName ?? user.upn ?? 'esta persona'}
          </h2>
        </EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {error != null && <ErrorCallout error={error} />}
        {current.error && <ErrorCallout error={current.error} onRetry={current.reload} />}
        {applied ? (
          <EuiCallOut size="s" color="success" iconType="check" title="Rol aplicado">
            <p>
              El cambio ya está vigente. Si la persona tenía una sesión abierta, se cerró: el rol
              nuevo aplica al volver a iniciar sesión.
            </p>
          </EuiCallOut>
        ) : created ? (
          <EuiCallOut size="s" color="success" iconType="check" title="Solicitud registrada">
            <p>
              Quedó pendiente de aprobación por otra persona (referencia <Mono>{created}</Mono>).
              El rol no cambia hasta que se apruebe; puedes seguirla en «Solicitudes de rol».
            </p>
          </EuiCallOut>
        ) : current.data ? (
          <>
            {!current.data.eligible && (
              <EuiCallOut
                size="s"
                color="warning"
                iconType="alert"
                title="La cuenta no es elegible para cambios de rol."
              >
                <p>Se requiere pertenencia vigente a Accesos_SOC y cuenta habilitada en Entra.</p>
              </EuiCallOut>
            )}
            <EuiSpacer size="m" />
            <EuiFormRow label="Acción" fullWidth>
              <EuiSelect
                fullWidth
                value={action}
                onChange={(event) => {
                  const next = event.target.value as RoleRequestAction;
                  setAction(next);
                  const options = (current.data?.assignableRoles ?? []).filter((value) =>
                    next === 'grant' ? !user.roles.includes(value) : grantRoles.includes(value),
                  );
                  if (options[0]) setRole(options[0]);
                }}
                options={[
                  { value: 'grant', text: 'Conceder un rol' },
                  { value: 'revoke', text: 'Retirar un rol' },
                ]}
              />
            </EuiFormRow>
            <EuiFormRow label="Rol" fullWidth>
              <EuiSelect
                fullWidth
                value={role}
                onChange={(event) => setRole(event.target.value as RequestableRole)}
                options={availableRoles.map((value) => ({
                  value,
                  text: ROLE_LABEL[value] ?? value,
                }))}
                disabled={availableRoles.length === 0}
              />
            </EuiFormRow>
            {availableRoles.length === 0 && (
              <EuiCallOut
                size="s"
                color="primary"
                iconType="iInCircle"
                title="Sin cambios posibles"
              >
                <p>
                  {action === 'grant'
                    ? 'La persona ya tiene todos los roles solicitables.'
                    : 'La persona no tiene un rol B89 que pueda retirarse.'}
                </p>
              </EuiCallOut>
            )}
            <EuiFormRow
              label="Motivo"
              fullWidth
              helpText={`${length}/${REASON_MAX} · mínimo ${REASON_MIN}`}
            >
              <EuiTextArea
                fullWidth
                rows={3}
                maxLength={REASON_MAX}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
              />
            </EuiFormRow>
            <EuiFormRow label="Ticket o referencia (opcional)" fullWidth>
              <EuiFieldText
                fullWidth
                maxLength={120}
                value={ticket}
                onChange={(event) => setTicket(event.target.value)}
              />
            </EuiFormRow>
          </>
        ) : (
          <EuiLoadingContent lines={4} />
        )}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              onClick={() => (created || applied ? onSubmitted() : onClose())}
              disabled={busy}
            >
              {created || applied ? 'Cerrar' : 'Cancelar'}
            </EuiButtonEmpty>
          </EuiFlexItem>
          {!created && !applied && (
            <EuiFlexItem grow={false}>
              <EuiButton
                fill
                isLoading={busy}
                isDisabled={
                  !current.data?.eligible || current.loading || !roleExists || length < REASON_MIN
                }
                aria-describedby={blockedReason ? 'b89-role-change-blocked' : undefined}
                onClick={submit}
              >
                {current.data?.directGrant ? 'Aplicar rol' : 'Enviar solicitud'}
              </EuiButton>
            </EuiFlexItem>
          )}
          {!created && !applied && blockedReason && (
            <EuiFlexItem grow={false} style={{ flexBasis: '100%' }}>
              <p id="b89-role-change-blocked" className="b89CellMeta" style={{ textAlign: 'right' }}>
                {blockedReason}
              </p>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
      </EuiModalFooter>
    </EuiModal>
  );
}

function RoleDecisionModal({
  request,
  names,
  onClose,
  onDecided,
}: {
  request: RoleRequestView;
  names: ReadonlyMap<string, string>;
  onClose: () => void;
  onDecided: () => void;
}) {
  const { api, can, session, basePath, notifications } = useConsole();
  const [decision, setDecision] = useState<'approve' | 'reject'>('approve');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const length = reason.trim().length;
  const path = `/admin/role-requests/${encodeURIComponent(request.id)}/${decision}`;
  const securityStage = request.approvalStage === 'security';
  const stepUpMissing = error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED';
  const capabilityAllowed =
    request.approvalStage === 'access'
      ? can(CAPABILITIES.rolesApprove)
      : can(CAPABILITIES.rolesApprovePrivileged);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(path, { expectedRevision: request.revision, reason: reason.trim() });
      notifications.toasts.addSuccess({
        title:
          decision === 'approve'
            ? securityStage || request.approvalStage === null
              ? 'Solicitud aprobada'
              : 'Etapa de Accesos aprobada'
            : 'Solicitud rechazada',
      });
      onDecided();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiModal
      onClose={onClose}
      className="b89Modal"
      maxWidth={560}
      aria-labelledby="b89-role-decision-title"
    >
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          <h2 id="b89-role-decision-title">Revisar solicitud de rol</h2>
        </EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {error != null && !stepUpMissing && <ErrorCallout error={error} />}
        {stepUpMissing && (
          <EuiCallOut
            size="s"
            color="warning"
            iconType="lock"
            title="Para aprobar esta etapa necesitas un inicio de sesión reciente."
          >
            <p>
              Cierra sesión, vuelve a entrar y repite la aprobación desde Usuarios y sesiones ›
              Solicitudes de rol. La solicitud sigue pendiente.
            </p>
            <EuiButton size="s" href={`${basePath}${LOGOUT_PATH}`}>
              Cerrar sesión y volver a entrar
            </EuiButton>
          </EuiCallOut>
        )}
        <EuiCallOut size="s" color="primary" iconType="iInCircle" title="Cambio propuesto">
          <p>
            <RoleRequestSentence request={request} names={names} viewerId={session.subjectId} />.
          </p>
          <p>
            <strong>Motivo:</strong> {request.reason}
          </p>
          {request.ticket && <p>Ticket: {request.ticket}</p>}
        </EuiCallOut>
        <EuiSpacer size="m" />
        {securityStage && !stepUpMissing && (
          <p className="b89CellMeta">
            Etapa de Seguridad: pide un inicio de sesión reciente. Si al aprobar se te pide,
            cierra sesión, vuelve a entrar y repite la aprobación.
          </p>
        )}
        <EuiFormRow label="Decisión" fullWidth>
          <EuiSelect
            fullWidth
            value={decision}
            onChange={(event) => setDecision(event.target.value as 'approve' | 'reject')}
            options={[
              { value: 'approve', text: 'Aprobar etapa' },
              { value: 'reject', text: 'Rechazar solicitud' },
            ]}
          />
        </EuiFormRow>
        <EuiFormRow
          label="Motivo de la decisión"
          fullWidth
          helpText={`${length}/${REASON_MAX} · mínimo ${REASON_MIN}`}
        >
          <EuiTextArea
            fullWidth
            rows={3}
            maxLength={REASON_MAX}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </EuiFormRow>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose} disabled={busy}>
              Cancelar
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              color={decision === 'reject' ? 'danger' : 'primary'}
              isLoading={busy}
              isDisabled={!capabilityAllowed || length < REASON_MIN}
              aria-describedby={length < REASON_MIN ? 'b89-role-decision-blocked' : undefined}
              onClick={submit}
            >
              {decision === 'approve' ? 'Confirmar aprobación' : 'Rechazar solicitud'}
            </EuiButton>
          </EuiFlexItem>
          {(length < REASON_MIN || !capabilityAllowed) && (
            <EuiFlexItem grow={false} style={{ flexBasis: '100%' }}>
              <p id="b89-role-decision-blocked" className="b89CellMeta" style={{ textAlign: 'right' }}>
                {!capabilityAllowed
                  ? 'Tu rol no puede decidir esta etapa.'
                  : `Escribe el motivo de la decisión (al menos ${REASON_MIN} caracteres; faltan ${REASON_MIN - length}).`}
              </p>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
      </EuiModalFooter>
    </EuiModal>
  );
}

function SessionsPanel() {
  const { api, can } = useConsole();
  const sessions = useAsync(
    () => api.get<Page<AdminSession> & { windowDays: number }>('/admin/sessions'),
    [api],
  );
  const [revoking, setRevoking] = useState<AdminSession | null>(null);
  const [items, setItems] = useState<readonly AdminSession[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);
  useEffect(() => {
    if (sessions.data) {
      setItems(sessions.data.items);
      setCursor(sessions.data.nextCursor);
    }
  }, [sessions.data]);
  useChanges(['session'], () => sessions.reload(), 1000);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const next = await api.get<Page<AdminSession>>('/admin/sessions', { cursor });
      setItems((current) => [...current, ...next.items]);
      setCursor(next.nextCursor);
    } catch (error) {
      setMoreError(error);
    } finally {
      setLoadingMore(false);
    }
  };

  if (sessions.error) return <ErrorCallout error={sessions.error} onRetry={sessions.reload} />;

  const columns: Array<EuiBasicTableColumn<AdminSession>> = [
    {
      field: 'displayName',
      name: 'Persona',
      truncateText: false,
      render: (value: string | null, session: AdminSession) => (
        <span className="b89CellTitle">
          <span>
            {value ?? session.email ?? 'Sin nombre'}
            {session.current ? ' · esta sesión' : ''}
          </span>
          <span className="b89CellMeta">
            {amrText(session.amr)} · {session.clientIp ?? 'IP sin dato'}
          </span>
        </span>
      ),
      mobileOptions: { header: false },
    },
    {
      field: 'state',
      name: 'Estado',
      render: (value: AdminSession['state'], session: AdminSession) => (
        <HealthMark
          tone={value === 'active' ? 'ok' : value === 'revoked' ? 'fail' : 'neutral'}
          label={`${SESSION_STATE_LABEL[value]}${session.revocationReason ? ` · ${session.revocationReason}` : ''}`}
        />
      ),
    },
    { field: 'roles', name: 'Roles', render: (roles: string[]) => <Roles roles={roles} /> },
    {
      field: 'lastSeenAt',
      name: 'Última actividad',
      render: (value: string) => <Timestamp iso={value} />,
    },
    {
      name: 'Acciones',
      width: '120px',
      render: (session: AdminSession) =>
        can(CAPABILITIES.sessionsRevoke) && session.state === 'active' && !session.current ? (
          <EuiButtonEmpty
            size="xs"
            color="danger"
            onClick={() => setRevoking(session)}
            aria-label={`Revocar la sesión de ${session.displayName ?? session.email ?? 'esta persona'}`}
          >
            Revocar
          </EuiButtonEmpty>
        ) : null,
    },
  ];

  return (
    <>
      <EuiBasicTable<AdminSession>
        items={items as AdminSession[]}
        columns={columns}
        loading={sessions.loading}
        responsive
        tableLayout="auto"
        noItemsMessage={
          sessions.loading
            ? 'Cargando sesiones…'
            : `Sin sesiones en los últimos ${sessions.data?.windowDays ?? 7} días.`
        }
      />
      {moreError != null && <ErrorCallout error={moreError} onRetry={loadMore} />}
      {cursor && (
        <>
          <EuiSpacer size="s" />
          <EuiButtonEmpty size="s" isLoading={loadingMore} onClick={loadMore}>
            Cargar más
          </EuiButtonEmpty>
        </>
      )}
      {revoking && (
        <RevokeModal
          session={revoking}
          onClose={() => setRevoking(null)}
          onRevoked={() => {
            setRevoking(null);
            sessions.reload();
          }}
        />
      )}
    </>
  );
}

function RevokeModal({
  session,
  onClose,
  onRevoked,
}: {
  session: AdminSession;
  onClose: () => void;
  onRevoked: () => void;
}) {
  const { api, notifications } = useConsole();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const length = reason.trim().length;
  const who = session.displayName ?? session.email ?? 'esta persona';

  const revoke = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(`/admin/sessions/${encodeURIComponent(session.ref)}/revoke`, {
        reason: reason.trim(),
        expectedRevision: session.revision,
      });
      notifications.toasts.addSuccess({
        title: `Sesión revocada. ${who} tendrá que volver a iniciar sesión.`,
      });
      onRevoked();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <EuiModal
      onClose={onClose}
      className="b89Modal"
      maxWidth={520}
      aria-labelledby="b89-revoke-title"
    >
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          <h2 id="b89-revoke-title" data-b89-no-translate="">
            Revocar la sesión de {who}
          </h2>
        </EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        {error != null && <ErrorCallout error={error} />}
        <p>
          {who} ({session.clientIp ? `IP ${session.clientIp}` : 'IP sin dato'},{' '}
          {amrText(session.amr).toLowerCase()}) tendrá que volver a iniciar sesión. El motivo
          queda en Auditoría.
        </p>
        <EuiSpacer size="m" />
        <EuiFormRow
          label="Motivo"
          fullWidth
          helpText={
            length < REASON_MIN
              ? `Escribe al menos ${REASON_MIN} caracteres para poder revocar (faltan ${REASON_MIN - length}).`
              : `${length} de ${REASON_MAX} caracteres`
          }
        >
          <EuiFieldText
            fullWidth
            value={reason}
            maxLength={REASON_MAX}
            onChange={(event) => setReason(event.target.value)}
          />
        </EuiFormRow>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiFlexGroup gutterSize="s" justifyContent="flexEnd" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose} disabled={busy}>
              Cancelar
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              fill
              color="danger"
              isLoading={busy}
              isDisabled={length < REASON_MIN}
              onClick={revoke}
            >
              Revocar sesión
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiModalFooter>
    </EuiModal>
  );
}
