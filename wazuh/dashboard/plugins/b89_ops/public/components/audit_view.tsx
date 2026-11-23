/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSelect,
  EuiSpacer,
} from '@elastic/eui';
import {
  AUDIT_VIOLATION_LABEL,
  AuditEvent,
  AuditOutcome,
  AuditVerification,
  CAPABILITIES,
  Page,
  parseResource,
} from '../../common';
import { B89Page, useConsole } from './console_context';
import {
  AI_ANALYST_ACTOR,
  DataZone,
  EmptyLine,
  ErrorCallout,
  HealthMark,
  Mono,
  Person,
  Timestamp,
  useAsync,
} from './primitives';

const WINDOWS = [
  { value: '1', text: 'Últimas 24 h' },
  { value: '7', text: 'Últimos 7 días' },
  { value: '30', text: 'Últimos 30 días' },
  { value: '90', text: 'Últimos 90 días' },
];

const OUTCOME_LABEL: Record<AuditOutcome, string> = {
  allowed: 'Permitido',
  denied: 'Denegado',
  succeeded: 'Correcto',
  failed: 'Fallido',
};

/** Acciones de auditoría en palabras. Lo desconocido muestra el código (y queda en el filtro avanzado). */
export const AUDIT_ACTION_LABEL: Readonly<Record<string, string>> = {
  'access.sign_in': 'Inicio de sesión',
  'auth.sign_in.denied': 'Inicio de sesión rechazado',
  'access.session.revoked': 'Sesión revocada',
  'access.role_request.submitted': 'Solicitud de rol creada',
  'access.role_request.stage_approved': 'Etapa de solicitud de rol aprobada',
  'access.role_request.approved': 'Solicitud de rol aprobada',
  'access.role_request.rejected': 'Solicitud de rol rechazada',
  'access.role_request.cancelled': 'Solicitud de rol cancelada',
  'access.role_request.step_up_required': 'Aprobación pidió inicio de sesión reciente',
  'access.role_grant.owner_direct': 'Rol aplicado por el propietario del grupo',
  'access.role_grant.cleared': 'Rol retirado',
  'access.role_grant.sessions_revocation_incomplete': 'Cambio de rol sin cerrar todas las sesiones',
  'alert.linked': 'Alerta vinculada a incidente',
  'incident.opened': 'Incidente abierto',
  'incident.transition': 'Incidente cambió de estado',
  'incident.closed': 'Incidente cerrado',
  'notifications.channel.initialized': 'Canal de aviso creado',
  'notifications.channel.status': 'Canal de aviso activado o desactivado',
  'notifications.channel.tested': 'Prueba de canal de aviso',
  'notifications.channel.webhook_updated': 'Webhook de Teams cambiado',
  'notifications.channel.webhook_rejected': 'Webhook de Teams rechazado',
  'soar.notification.acknowledged': 'Aviso marcado como visto',
  'soar.notification.superseded': 'Aviso sustituido',
  'soar.dispatch.failed': 'Envío de aviso fallido',
  'source.health.changed': 'Cambio de salud de una fuente',
  'ai.analyst.investigation.requested': 'Análisis del Analista IA pedido',
  'ai.analyst.investigation.request_rejected': 'Análisis del Analista IA rechazado',
  'ai.analyst.settings.updated': 'Ajustes del Analista IA cambiados',
  'ai.analyst.settings.update_rejected': 'Cambio de ajustes del Analista IA rechazado',
  'assistant.ask': 'Pregunta a Bunny',
  'assistant.feedback': 'Valoración de una respuesta de Bunny',
  'assistant.conversation.delete': 'Conversación de Bunny borrada',
  'assistant.conversation.purge': 'Conversaciones de Bunny depuradas',
  'assistant.artifact.create': 'Documento creado por Bunny',
  'assistant.artifact.download': 'Documento de Bunny descargado',
  'dlp.policy.updated': 'Política DLP cambiada',
  'dlp.endpoint.enrolled': 'Equipo inscrito en DLP',
  'dlp.endpoint.revoked': 'Equipo retirado de DLP',
  'dlp.endpoint.enrollment_token_created': 'Código de inscripción DLP creado',
  'dlp.endpoint.enrollment_token_cancelled': 'Código de inscripción DLP cancelado',
};

export function auditActionLabel(action: string): string {
  return AUDIT_ACTION_LABEL[action] ?? action;
}

/** Resultado de la última verificación, en una frase (la respuesta de la página). */
export function integrityHeadline(verification: AuditVerification): string {
  return verification.ok
    ? `Cadena íntegra: ${verification.checked} eventos verificados, ninguno alterado.`
    : `Cadena rota: ${verification.violations.length} ${
        verification.violations.length === 1 ? 'anomalía' : 'anomalías'
      } en ${verification.checked} eventos. Avisa a plataforma y no borres nada.`;
}

const OUTCOME_TONE: Record<AuditOutcome, 'ok' | 'fail'> = {
  allowed: 'ok',
  succeeded: 'ok',
  denied: 'fail',
  failed: 'fail',
};

export function AuditView() {
  const { can } = useConsole();
  if (!can(CAPABILITIES.auditRead)) {
    return (
      <B89Page title="Auditoría e integridad">
        <EmptyLine>
          Tu rol no incluye la auditoría. Pídela a un Administrador de plataforma si la necesitas.
        </EmptyLine>
      </B89Page>
    );
  }
  return <AuditContent />;
}

function AuditContent() {
  const { api, can, session } = useConsole();
  const canVerify = can(CAPABILITIES.auditVerify);
  const [days, setDays] = useState('1');
  const [outcome, setOutcome] = useState<AuditOutcome | ''>('');
  const [actionInput, setActionInput] = useState('');
  const [action, setAction] = useState('');
  const [actorInput, setActorInput] = useState('');
  const [actorId, setActorId] = useState('');
  const [resourceInput, setResourceInput] = useState('');
  const [resource, setResource] = useState('');
  const [items, setItems] = useState<readonly AuditEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [verifyError, setVerifyError] = useState<unknown>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);

  // El rango es obligatorio en el BFF (≤ 365 días): se fija al cambiar el selector.
  const range = useMemo(() => {
    const to = new Date();
    const from = new Date(to.getTime() - Number(days) * 86400000);
    return { from: from.toISOString(), to: to.toISOString() };
  }, [days]);

  const query = {
    ...range,
    outcome: outcome || undefined,
    action: action || undefined,
    actorId: actorId || undefined,
    ...parseResource(resource),
    pageSize: 100,
  };
  const page = useAsync(
    () => api.get<Page<AuditEvent>>('/audit/events', query),
    [api, range, outcome, action, actorId, resource],
  );

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
    }
  }, [page.data]);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const next = await api.get<Page<AuditEvent>>('/audit/events', { ...query, cursor });
      setItems((current) => [...current, ...next.items]);
      setCursor(next.nextCursor);
    } catch (failure) {
      setMoreError(failure);
    } finally {
      setLoadingMore(false);
    }
  };

  const verify = async () => {
    setVerifying(true);
    setVerifyError(null);
    try {
      setVerification(await api.get<AuditVerification>('/audit/verify'));
      setVerifiedAt(new Date().toISOString());
    } catch (failure) {
      setVerifyError(failure);
    } finally {
      setVerifying(false);
    }
  };

  // La respuesta primero: la integridad se comprueba al abrir la página (si el rol puede).
  useEffect(() => {
    if (canVerify) void verify();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canVerify]);

  const columns: Array<EuiBasicTableColumn<AuditEvent>> = [
    {
      field: 'occurredAt',
      name: 'Cuándo',
      width: '120px',
      render: (value: string) => <Timestamp iso={value} />,
    },
    {
      field: 'actor',
      name: 'Quién',
      render: (actor: AuditEvent['actor']) =>
        actor.type === 'user' || actor.id === AI_ANALYST_ACTOR ? (
          <Person id={actor.id} viewerId={session.subjectId} emptyLabel="Sistema B89" />
        ) : (
          <span title={`Identificador: ${actor.id}`}>Sistema B89</span>
        ),
    },
    {
      field: 'action',
      name: 'Qué',
      render: (value: string, event: AuditEvent) => (
        <span className="b89CellTitle">
          <span>{auditActionLabel(value)}</span>
          <span className="b89CellMeta">
            {event.resource.type}
            {event.reason ? ` · ${event.reason}` : ''} ·{' '}
            <Mono title={`Acción ${value} · secuencia ${event.sequence} · hash ${event.hash}`}>
              #{event.sequence}
            </Mono>
          </span>
        </span>
      ),
    },
    {
      field: 'outcome',
      name: 'Resultado',
      width: '120px',
      render: (value: AuditOutcome) => (
        <HealthMark tone={OUTCOME_TONE[value]} label={OUTCOME_LABEL[value]} />
      ),
    },
  ];

  return (
    <B89Page
      title="Auditoría e integridad"
      description="Quién hizo qué y cuándo. Cada evento está encadenado al anterior: si alguien altera uno, la verificación lo detecta."
      actions={
        canVerify ? (
          <EuiButton size="s" onClick={verify} isLoading={verifying}>
            Verificar de nuevo
          </EuiButton>
        ) : undefined
      }
    >
      <div lang="es-PE" translate="no">
      {!canVerify && (
        <>
          <EmptyLine>
            Tu rol puede leer la auditoría, pero no verificar su integridad. Pide la verificación a
            un Auditor o a un Administrador de plataforma.
          </EmptyLine>
          <EuiSpacer size="m" />
        </>
      )}
      {canVerify && verifying && !verification && (
        <>
          <p role="status" className="b89Muted">
            Verificando la integridad de la auditoría…
          </p>
          <EuiSpacer size="m" />
        </>
      )}
      {verifyError != null && (
        <>
          <ErrorCallout error={verifyError} />
          <EuiSpacer size="m" />
        </>
      )}
      {verification && (
        <>
          <EuiCallOut
            size="s"
            color={verification.ok ? 'success' : 'danger'}
            iconType={verification.ok ? 'check' : 'alert'}
            title={integrityHeadline(verification)}
          >
            <p className="b89CellMeta">
              Verificado <Timestamp iso={verifiedAt} /> · hasta el evento #{verification.headSequence}
            </p>
            {!verification.ok && (
              <ul className="b89List">
                {verification.violations.map((violation) => (
                  <li key={`${violation.code}-${violation.sequence}`}>
                    {AUDIT_VIOLATION_LABEL[violation.code] ?? violation.code} en la secuencia{' '}
                    <Mono>{violation.sequence}</Mono>
                  </li>
                ))}
              </ul>
            )}
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      <EuiFlexGroup gutterSize="s" responsive wrap className="b89Filters">
        <EuiFlexItem grow={1}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Periodo"
            value={days}
            onChange={(event) => setDays(event.target.value)}
            options={WINDOWS}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Resultado"
            value={outcome}
            onChange={(event) => setOutcome(event.target.value as AuditOutcome | '')}
            options={[
              { value: '', text: 'Todos los resultados' },
              ...(Object.keys(OUTCOME_LABEL) as AuditOutcome[]).map((value) => ({
                value,
                text: OUTCOME_LABEL[value],
              })),
            ]}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={2}>
          <EuiSelect
            compressed
            fullWidth
            aria-label="Acción"
            value={AUDIT_ACTION_LABEL[action] ? action : ''}
            onChange={(event) => {
              setAction(event.target.value);
              setActionInput(event.target.value);
            }}
            options={[
              { value: '', text: action && !AUDIT_ACTION_LABEL[action] ? `Código: ${action}` : 'Todas las acciones' },
              ...Object.keys(AUDIT_ACTION_LABEL)
                .sort((a, b) => AUDIT_ACTION_LABEL[a].localeCompare(AUDIT_ACTION_LABEL[b], 'es'))
                .map((value) => ({ value, text: AUDIT_ACTION_LABEL[value] })),
            ]}
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <details className="b89Guide__details">
        <summary>Filtros avanzados (código de acción, persona o recurso)</summary>
        <EuiSpacer size="s" />
        <EuiFlexGroup gutterSize="s" responsive wrap className="b89Filters">
          <EuiFlexItem grow={2}>
            <EuiFieldSearch
              compressed
              fullWidth
              placeholder="Código de acción, p. ej. access.session.revoked"
              value={actionInput}
              onChange={(event) => setActionInput(event.target.value)}
              onSearch={(value) => setAction(value.trim())}
              aria-label="Filtrar por código de acción"
            />
          </EuiFlexItem>
          <EuiFlexItem grow={2}>
            <EuiFieldSearch
              compressed
              fullWidth
              placeholder="Identificador de la persona"
              value={actorInput}
              onChange={(event) => setActorInput(event.target.value)}
              onSearch={(value) => setActorId(value.trim())}
              aria-label="Filtrar por persona"
            />
          </EuiFlexItem>
          <EuiFlexItem grow={2}>
            <EuiFieldSearch
              compressed
              fullWidth
              placeholder="Recurso: tipo o tipo:id (p. ej. incident:…)"
              value={resourceInput}
              onChange={(event) => setResourceInput(event.target.value)}
              onSearch={(value) => setResource(value.trim())}
              aria-label="Filtrar por recurso"
            />
          </EuiFlexItem>
        </EuiFlexGroup>
      </details>
      <EuiSpacer size="m" />
      {page.error ? (
        <ErrorCallout error={page.error} onRetry={page.reload} />
      ) : (
        <DataZone>
          <EuiBasicTable<AuditEvent>
            items={items as AuditEvent[]}
            columns={columns}
            loading={page.loading}
            responsive
            compressed
            tableLayout="auto"
            noItemsMessage={
              page.loading ? 'Cargando auditoría…' : 'Sin eventos en el periodo y filtros elegidos.'
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
        </DataZone>
      )}
      </div>
    </B89Page>
  );
}
