/**
 * C-17/C-21 — superficie HTTP del flujo SOC.
 *
 * Cada endpoint resuelve la sesión, delega en el caso de uso y traduce el fallo al
 * catálogo de C-27. La autorización no se evalúa aquí: vive en el caso de uso, de modo
 * que un cliente que no sea esta API obtiene exactamente la misma decisión.
 *
 * Las mutaciones exigen además el token CSRF de la sesión (B-01) y los listados se
 * entregan por páginas con cursor (B-02).
 */

import { Body, Controller, Get, Inject, Param, Post, Query, Req } from '@nestjs/common';
import type { IncomingRequest } from '../http/http-contracts.js';

import { projectFields } from '@b89/access';
import {
  ALERT_STATUSES,
  executeAlertCommand,
  executeIncidentCommand,
  openIncidentFromAlert,
  INCIDENT_STATUSES,
  type Alert,
  type AlertStatus,
  type Incident,
  type IncidentStatus,
  isCollapsible,
  type AlertGroup,
  type ClosureInput,
  type TriageVerdict,
} from '@b89/soc';

import { ApiError, fromSocFailure } from '../http/api-error.js';
import { ENTITY_REF_PATTERN } from '../runtime/entity-refs.js';
import { paginate, type PageQuery } from '../http/pagination.js';
import { mutatingActor, readingActor } from './session-actor.js';
import { SECOPS_RUNTIME } from './tokens.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';
import { SOC_KNOWLEDGE } from '../assistant/soc-knowledge.generated.js';
import { explainAlertFromKnowledge } from './alert-explanation.js';

/** Aprendizaje SOC · etapa C: resumen del grupo por huella. Agrupar no oculta ni cierra nada. */
export function alertGroupView(group: AlertGroup) {
  return {
    id: group.id,
    status: group.status,
    level: group.level,
    ruleKey: group.ruleKey,
    // Huella gruesa: el grupo junta alertas que solo comparten regla y sujeto (sin proceso,
    // hash ni destino). La consola debe avisarlo; nunca es base para cerrar en bloque a ciegas.
    coarse: group.level === 'coarse',
    alertCount: group.alertCount,
    firstSeenAt: group.firstSeenAt.toISOString(),
    lastSeenAt: group.lastSeenAt.toISOString(),
    highestPriority: group.highestPriority,
    primaryAlertId: group.primaryAlertId,
  };
}

/** Máximo de alertas de un grupo que devuelve `GET /api/alerts/:id/group`. */
const GROUP_MEMBERS_LIMIT = 100;

export function alertView(alert: Alert, capabilities: ReadonlySet<string>) {
  return projectFields(
    {
      id: alert.id,
      // Conserva títulos nuevos y limpia proveedor/ID de registros anteriores.
      title: alert.title.replace(/\s+\([a-z0-9._-]+\s+\d+\)$/iu, '').trim(),
      // El título ya no lleva «(wazuh N)»: la regla viaja aparte para la guía y el detalle técnico.
      ruleId: alert.ruleId,
      priority: alert.priority,
      // Aprendizaje SOC · fase 3: la cola ordena por la efectiva y muestra la original.
      effectivePriority: alert.effectivePriority ?? alert.priority,
      demotedBy: alert.demotedBy ?? null,
      score: alert.score,
      status: alert.status,
      assigneeId: alert.assigneeId,
      verdict: alert.verdict,
      // Aprendizaje SOC · etapa A: último cierre vigente (null mientras está abierta).
      closureReason: alert.closureReason,
      closureOrigin: alert.closureOrigin,
      closedBy: alert.closedBy,
      closedAt: alert.closedAt?.toISOString() ?? null,
      incidentId: alert.incidentId,
      occurredAt: alert.occurredAt.toISOString(),
      revision: alert.revision,
      reasons: alert.reasons.map((reason) => ({ code: reason.code, detail: reason.detail })),
      // Correlación de C-16. `entities[].ref` es lo único apto para URLs y filtros (D-10b);
      // `label` (UPN o IP) solo viaja en este cuerpo. Las claves internas no se exponen.
      entities: alert.entityKeys.map((key, index) => {
        const separator = key.indexOf(':');
        return {
          ref: alert.entityRefs[index] ?? null,
          kind: key.slice(0, separator),
          label: key.slice(separator + 1),
        };
      }),
      signal: alert.signal,
      relatedAlertIds: alert.relatedAlertIds,
      // `rawRef` solo se proyecta a quien tiene events.read_raw (C-18).
      rawRef: `raw:${alert.eventRecordId}`,
    },
    capabilities as never,
  );
}

function incidentView(incident: Incident) {
  return {
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
    status: incident.status,
    ownerId: incident.ownerId,
    alertIds: incident.alertIds,
    summary: incident.summary,
    openedAt: incident.openedAt.toISOString(),
    closedAt: incident.closedAt?.toISOString() ?? null,
    // La conclusión del cierre: la consola la muestra en el resumen del incidente cerrado.
    closureReason: incident.closureReason,
    revision: incident.revision,
  };
}

/** Filtro de estado de alertas: `open` (y su alias histórico `active`) o un estado real. */
const ALERT_STATUS_FILTERS: readonly string[] = ['open', 'active', ...ALERT_STATUSES];
/** Tope de alertas vinculadas que se resuelven por incidente en una consulta. */
const LINKED_ALERT_LIMIT = 200;
/** Incidentes `active`: todo lo que todavía requiere trabajo. */
const ACTIVE_INCIDENT_STATUSES: readonly IncidentStatus[] = INCIDENT_STATUSES.filter(
  (status) => status !== 'resolved' && status !== 'closed',
);

@Controller('api')
export class SocController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  @Get('alerts')
  public async alerts(
    @Req() request: IncomingRequest,
    @Query()
    query: PageQuery & { status?: string; q?: string; priority?: string; entity?: string },
  ) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    if (!actor.capabilities.has('alerts.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const search = (query.q ?? '').trim().toLocaleLowerCase();
    if (search.length > 120) throw new ApiError('VALIDATION_FAILED', correlationId, ['q']);
    if (query.status && !ALERT_STATUS_FILTERS.includes(query.status)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['status']);
    }
    if (query.priority && !['P1', 'P2', 'P3', 'P4'].includes(query.priority)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['priority']);
    }
    // Solo referencias opacas: un UPN o una IP en la URL se rechazan (D-10b).
    const entity = query.entity?.trim();
    if (entity !== undefined && entity !== '' && !ENTITY_REF_PATTERN.test(entity)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['entity']);
    }
    const status =
      query.status === 'active' ? 'open' : (query.status as AlertStatus | 'open' | undefined);
    const result = await this.runtime.soc.listAlerts({
      tenantId: actor.tenantId,
      ...(status ? { status } : {}),
      ...(query.priority ? { priority: query.priority as Alert['priority'] } : {}),
      ...(search ? { search } : {}),
      ...(entity ? { entityRef: entity } : {}),
    });
    const page = paginate(
      result.items,
      (alert) => ({ sort: alert.priority, at: alert.occurredAt.getTime(), id: alert.id }),
      query,
      `alerts:status=${query.status ?? ''}:q=${search}:priority=${query.priority ?? ''}:entity=${entity ?? ''}`,
      correlationId,
    );
    const groups =
      (await this.runtime.soc.alertGroupsOf?.(
        actor.tenantId,
        page.items.map((alert) => alert.id),
      )) ?? new Map<string, AlertGroup>();
    return {
      correlationId,
      items: page.items.map((alert) => {
        const group = groups.get(alert.id);
        return {
          ...alertView(alert, actor.capabilities),
          // Etapa C: la consola agrupa filas con el mismo `group.id`; P1/P2 nunca se colapsan.
          // `collapsible: false` (P1/P2): la consola la muestra como fila propia siempre.
          group: group
            ? {
                id: group.id,
                alertCount: group.alertCount,
                coarse: group.level === 'coarse',
                collapsible: isCollapsible(alert.priority),
              }
            : null,
        };
      }),
      nextCursor: page.nextCursor,
      totalCount: result.total,
    };
  }

  @Get('alerts/:id')
  public async alert(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const alert = await this.runtime.soc.alertById(actor.tenantId, id);
    if (!alert || !actor.capabilities.has('alerts.read')) {
      // Mismo error para inexistente y no autorizado: la API no enumera.
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const group = await this.runtime.soc.alertGroupOf?.(actor.tenantId, alert.id);
    return {
      correlationId,
      alert: {
        ...alertView(alert, actor.capabilities),
        // Solo en el detalle: por qué salta esta regla, cuándo es falso positivo y qué hacer.
        explanation: explainAlertFromKnowledge(alert, SOC_KNOWLEDGE),
        group: group ? alertGroupView(group) : null,
      },
    };
  }

  /** Aprendizaje SOC · etapa C: grupo de la alerta y sus alertas (las más recientes primero). */
  @Get('alerts/:id/group')
  public async alertGroup(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const alert = await this.runtime.soc.alertById(actor.tenantId, id);
    if (!alert || !actor.capabilities.has('alerts.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const group = await this.runtime.soc.alertGroupOf?.(actor.tenantId, alert.id);
    if (!group) return { correlationId, group: null, alertIds: [] };
    const alertIds =
      (await this.runtime.soc.alertGroupMembers?.(actor.tenantId, group.id, GROUP_MEMBERS_LIMIT)) ??
      [];
    return { correlationId, group: alertGroupView(group), alertIds };
  }

  @Post('alerts/:id/commands')
  public async command(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body()
    body: {
      name?: string;
      expectedRevision?: number;
      verdict?: TriageVerdict;
      note?: string;
      assigneeId?: string;
      /** Cierre estructurado `{ reason, justification, evidenceRefs }`; lo valida el dominio. */
      closure?: unknown;
    },
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    const name = body.name as 'acknowledge' | 'assign' | 'triage' | 'escalate' | 'close' | 'reopen';
    if (!name || typeof body.expectedRevision !== 'number') {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['name', 'expectedRevision']);
    }
    const result = await executeAlertCommand(this.runtime.socDependencies(), {
      actor,
      alertId: id,
      correlationId,
      command: {
        name,
        expectedRevision: body.expectedRevision,
        ...(body.verdict === undefined ? {} : { verdict: body.verdict }),
        ...(body.note === undefined ? {} : { note: body.note }),
        ...(body.assigneeId === undefined ? {} : { assigneeId: body.assigneeId }),
        // La forma se valida en el dominio (`validateClosure`): aquí solo se reenvía.
        ...(body.closure === undefined ? {} : { closure: body.closure as ClosureInput }),
      },
    });
    if (!result.ok && result.reason.startsWith('CLOSURE_')) {
      // La consola necesita saber que falló el cierre y por qué (motivo, veredicto o triaje).
      throw new ApiError('VALIDATION_FAILED', correlationId, ['closure', result.reason]);
    }
    if (!result.ok) throw fromSocFailure(result.code, correlationId);
    this.runtime.dispatcher.kick();
    return { correlationId, alert: alertView(result.value, actor.capabilities) };
  }

  @Post('incidents')
  public async openIncident(
    @Req() request: IncomingRequest,
    @Body()
    body: {
      alertId?: string;
      title?: string;
      severity?: 'critical' | 'high' | 'medium' | 'low';
      summary?: string;
      expectedAlertRevision?: number;
    },
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    if (
      !body.alertId ||
      !body.title ||
      !body.severity ||
      !body.summary ||
      typeof body.expectedAlertRevision !== 'number'
    ) {
      throw new ApiError('VALIDATION_FAILED', correlationId, [
        'alertId',
        'title',
        'severity',
        'summary',
        'expectedAlertRevision',
      ]);
    }
    const result = await openIncidentFromAlert(this.runtime.socDependencies(), {
      actor,
      alertId: body.alertId,
      title: body.title,
      severity: body.severity,
      summary: body.summary,
      correlationId,
      expectedAlertRevision: body.expectedAlertRevision,
    });
    if (!result.ok) throw fromSocFailure(result.code, correlationId);
    this.runtime.dispatcher.kick();
    return { correlationId, incident: incidentView(result.value) };
  }

  @Get('incidents/:id')
  public async incident(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    const incident = await this.runtime.soc.incidentById(actor.tenantId, id);
    if (!incident || !actor.capabilities.has('incidents.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    return { correlationId, incident: incidentView(incident) };
  }

  /**
   * Alertas vinculadas a un incidente, con la misma proyección redactada que `GET /alerts`,
   * para que la consola no tenga que pedirlas una por una. Exige `incidents.read` y
   * `alerts.read`; sin alguna de las dos responde igual que un incidente inexistente.
   * Una sola consulta por tenant e incidente: las `LINKED_ALERT_LIMIT` más recientes y el
   * total real; `truncated` avisa si había más y `totalCount` es siempre el total real, no
   * el de la página. `unavailableCount` cuenta los ids que el incidente declara y que no se
   * pudieron leer en el tenant; nunca se describen.
   */
  @Get('incidents/:id/alerts')
  public async incidentAlerts(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Query() query: PageQuery,
  ) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    if (!actor.capabilities.has('incidents.read') || !actor.capabilities.has('alerts.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const incident = await this.runtime.soc.incidentById(actor.tenantId, id);
    if (!incident) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const linked = await this.runtime.soc.listIncidentAlerts(
      actor.tenantId,
      incident.id,
      LINKED_ALERT_LIMIT,
    );
    const declared = new Set(incident.alertIds).size;
    const page = paginate(
      linked.items,
      (alert) => ({ sort: alert.priority, at: alert.occurredAt.getTime(), id: alert.id }),
      query,
      `incident-alerts:${incident.id}`,
      correlationId,
    );
    return {
      correlationId,
      incidentId: incident.id,
      items: page.items.map((alert) => alertView(alert, actor.capabilities)),
      nextCursor: page.nextCursor,
      totalCount: linked.total,
      unavailableCount: Math.max(declared - linked.total, 0),
      truncated: linked.total > linked.items.length,
    };
  }

  @Get('incidents')
  public async incidents(
    @Req() request: IncomingRequest,
    @Query() query: PageQuery & { status?: string; q?: string },
  ) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    if (!actor.capabilities.has('incidents.read')) {
      throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    }
    const search = (query.q ?? '').trim().toLocaleLowerCase();
    if (search.length > 120) throw new ApiError('VALIDATION_FAILED', correlationId, ['q']);
    // Un estado desconocido no es error: devuelve un listado vacío, como antes.
    const statuses =
      query.status === 'active'
        ? ACTIVE_INCIDENT_STATUSES
        : query.status
          ? [query.status as IncidentStatus]
          : undefined;
    const result = await this.runtime.soc.listIncidents({
      tenantId: actor.tenantId,
      ...(statuses ? { statuses } : {}),
      ...(search ? { search } : {}),
    });
    const incidents = result.items;
    const page = paginate(
      incidents,
      (incident) => ({ at: incident.openedAt.getTime(), id: incident.id }),
      query,
      `incidents:status=${query.status ?? ''}:q=${search}`,
      correlationId,
    );
    return {
      correlationId,
      items: page.items.map(incidentView),
      nextCursor: page.nextCursor,
      totalCount: result.total,
    };
  }

  @Post('incidents/:id/commands')
  public async incidentCommand(
    @Req() request: IncomingRequest,
    @Param('id') id: string,
    @Body()
    body: {
      name?: 'contain' | 'eradicate' | 'resolve' | 'close' | 'reopen' | 'reassign';
      expectedRevision?: number;
      closureReason?: string;
      ownerId?: string;
    },
  ) {
    const { actor, correlationId } = await mutatingActor(this.runtime, request);
    if (!body.name || typeof body.expectedRevision !== 'number') {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['name', 'expectedRevision']);
    }
    const result = await executeIncidentCommand(this.runtime.socDependencies(), {
      actor,
      incidentId: id,
      correlationId,
      command: {
        name: body.name,
        expectedRevision: body.expectedRevision,
        ...(body.closureReason === undefined ? {} : { closureReason: body.closureReason }),
        ...(body.ownerId === undefined ? {} : { ownerId: body.ownerId }),
      },
    });
    if (!result.ok) throw fromSocFailure(result.code, correlationId);
    this.runtime.dispatcher.kick();
    return { correlationId, incident: incidentView(result.value) };
  }
}
