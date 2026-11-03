/**
 * Herramientas de Bunny: lecturas del SOC que se hacen **por la propia API de la persona**.
 *
 * Cada herramienta compone una URL `GET` de una lista cerrada y la ejecuta con la cookie de sesión
 * de quien pregunta (ver `internal-client.ts`). Así Bunny hereda sin excepciones la autorización,
 * la proyección de campos y las redacciones de la API: si la persona no puede ver algo en la
 * consola, Bunny tampoco. No hay herramientas con métodos distintos de `GET`.
 */

import type { AssistantTool, Citation, ToolInput, ToolOutcome } from '@b89/assistant';
import { ALERT_STATUSES, INCIDENT_STATUSES } from '@b89/soc';

import { ENTITY_REF_PATTERN } from '../runtime/entity-refs.js';

export interface InternalResponse {
  readonly status: number;
  readonly body: unknown;
}
export type InternalGet = (pathWithQuery: string) => Promise<InternalResponse>;

const ID = /^[A-Za-z0-9_-]{1,64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;
const LIST = /^[a-z_]{2,32}(?:,[a-z_]{2,32}){0,15}$/u;
const WORD = /^[A-Za-z0-9_.:-]{1,80}$/u;
/** Sin caracteres de control (se comprueba por código, no por regex). */
const NO_CONTROL = {
  test: (value: string) =>
    [...value].every((char) => char.charCodeAt(0) >= 0x20 && char.charCodeAt(0) !== 0x7f),
};

class InputError extends Error {}

function optionalString(
  input: ToolInput,
  key: string,
  pattern: { test(value: string): boolean },
  max = 120,
): string | undefined {
  const value = input[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || value.length > max || !pattern.test(value)) {
    throw new InputError(`El parámetro «${key}» no es válido.`);
  }
  return value;
}

function requiredId(input: ToolInput, key = 'id'): string {
  const value = optionalString(input, key, ID, 64);
  if (!value) throw new InputError(`Falta el parámetro «${key}».`);
  return value;
}

function optionalEnum(
  input: ToolInput,
  key: string,
  allowed: readonly string[],
): string | undefined {
  const value = input[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || !allowed.includes(value)) {
    throw new InputError(`«${key}» debe ser uno de: ${allowed.join(', ')}.`);
  }
  return value;
}

function pageSize(input: ToolInput, max = 25, fallback = 10): string {
  const value = input['pageSize'];
  if (value === undefined || value === null) return String(fallback);
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > max) {
    throw new InputError(`«pageSize» debe ser un entero entre 1 y ${max}.`);
  }
  return String(value);
}

function query(parts: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(parts)) if (value !== undefined) params.set(key, value);
  const text = params.toString();
  return text ? `?${text}` : '';
}

const PAGING = {
  pageSize: {
    type: 'integer',
    minimum: 1,
    maximum: 25,
    description: 'Resultados por página (por defecto 10).',
  },
  cursor: { type: 'string', description: 'Cursor `nextCursor` de la página anterior.' },
} as const;

interface ReadToolSpec {
  readonly name: string;
  readonly label: string;
  readonly description: string;
  /** Capacidades de las que basta tener una para ofrecer la herramienta. */
  readonly anyOf: readonly string[];
  readonly properties: Record<string, unknown>;
  readonly required?: readonly string[];
  build(input: ToolInput): string;
  cite?(body: Record<string, unknown>): readonly Citation[];
}

function itemsOf(body: Record<string, unknown>): Record<string, unknown>[] {
  const items = body['items'];
  return Array.isArray(items) ? (items as Record<string, unknown>[]) : [];
}

function citeList(kind: Citation['kind'], titleKey = 'title') {
  return (body: Record<string, unknown>): Citation[] =>
    itemsOf(body)
      .filter((item) => typeof item['id'] === 'string')
      .slice(0, 15)
      .map((item) => ({
        kind,
        id: String(item['id']),
        label: String(item[titleKey] ?? item['id']),
      }));
}

function citeOne(kind: Citation['kind'], key: string, titleKey = 'title') {
  return (body: Record<string, unknown>): Citation[] => {
    const item = body[key] as Record<string, unknown> | undefined;
    return item && typeof item['id'] === 'string'
      ? [{ kind, id: String(item['id']), label: String(item[titleKey] ?? item['id']) }]
      : [];
  };
}

function readTool(spec: ReadToolSpec, get: InternalGet): AssistantTool {
  return {
    name: spec.name,
    label: spec.label,
    description: spec.description,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: spec.properties,
      ...(spec.required ? { required: spec.required } : {}),
    },
    async run(input): Promise<ToolOutcome> {
      let path: string;
      try {
        path = spec.build(input);
      } catch (error) {
        return {
          ok: false,
          error: error instanceof InputError ? error.message : 'Parámetros no válidos.',
        };
      }
      let response: InternalResponse;
      try {
        response = await get(path);
      } catch {
        return { ok: false, error: 'El servicio del SOC no respondió.' };
      }
      if (response.status === 401) return { ok: false, error: 'La sesión de la persona expiró.' };
      if (response.status === 403 || response.status === 404) {
        return {
          ok: false,
          error: 'No disponible: el recurso no existe o tu rol no tiene acceso.',
        };
      }
      if (response.status >= 500)
        return { ok: false, error: 'La fuente de datos está degradada ahora mismo.' };
      if (response.status >= 400) return { ok: false, error: 'La consulta no es válida.' };
      const body = (response.body ?? {}) as Record<string, unknown>;
      const { correlationId: _omit, ...data } = body;
      const citations = spec.cite?.(body);
      return { ok: true, data, ...(citations && citations.length > 0 ? { citations } : {}) };
    },
  };
}

export interface ActorSummary {
  readonly roles: readonly string[];
  readonly capabilities: readonly string[];
}

export function buildSocTools(get: InternalGet, actor: ActorSummary): AssistantTool[] {
  const allowed = new Set(actor.capabilities);
  const alertStatuses = ['open', ...ALERT_STATUSES];
  const specs: ReadToolSpec[] = [
    {
      name: 'list_alerts',
      label: 'Buscando alertas',
      description:
        'Lista alertas del SOC (más recientes primero). Filtra por estado, prioridad (P1 es la más urgente), texto o entidad. Úsala para panoramas, colas y búsquedas.',
      anyOf: ['alerts.read'],
      properties: {
        status: {
          type: 'string',
          enum: alertStatuses,
          description: '`open` = todo lo pendiente de trabajo.',
        },
        priority: { type: 'string', enum: ['P1', 'P2', 'P3', 'P4'] },
        q: { type: 'string', maxLength: 120, description: 'Texto a buscar en título y razones.' },
        entity: {
          type: 'string',
          description: 'Referencia opaca de entidad (`entities[].ref` de otra alerta).',
        },
        ...PAGING,
      },
      build: (input) =>
        `/api/alerts${query({
          status: optionalEnum(input, 'status', alertStatuses),
          priority: optionalEnum(input, 'priority', ['P1', 'P2', 'P3', 'P4']),
          q: optionalString(input, 'q', NO_CONTROL),
          entity: optionalString(input, 'entity', ENTITY_REF_PATTERN, 80),
          pageSize: pageSize(input),
          cursor: optionalString(input, 'cursor', /^[A-Za-z0-9_.=-]+$/u, 1024),
        })}`,
      cite: citeList('alert'),
    },
    {
      name: 'get_alert',
      label: 'Abriendo una alerta',
      description:
        'Detalle de una alerta: razones de priorización, entidades, señal, alertas relacionadas e incidente vinculado.',
      anyOf: ['alerts.read'],
      properties: { id: { type: 'string', description: 'Identificador de la alerta.' } },
      required: ['id'],
      build: (input) => `/api/alerts/${requiredId(input)}`,
      cite: citeOne('alert', 'alert'),
    },
    {
      name: 'list_incidents',
      label: 'Buscando incidentes',
      description: 'Lista incidentes (casos). `active` = todo lo que aún requiere trabajo.',
      anyOf: ['incidents.read'],
      properties: {
        status: { type: 'string', enum: ['active', ...INCIDENT_STATUSES] },
        q: { type: 'string', maxLength: 120 },
        ...PAGING,
      },
      build: (input) =>
        `/api/incidents${query({
          status: optionalEnum(input, 'status', ['active', ...INCIDENT_STATUSES]),
          q: optionalString(input, 'q', NO_CONTROL),
          pageSize: pageSize(input),
          cursor: optionalString(input, 'cursor', /^[A-Za-z0-9_.=-]+$/u, 1024),
        })}`,
      cite: citeList('incident'),
    },
    {
      name: 'get_incident',
      label: 'Abriendo un incidente',
      description: 'Detalle de un incidente: estado, responsable, resumen y alertas vinculadas.',
      anyOf: ['incidents.read'],
      properties: { id: { type: 'string' } },
      required: ['id'],
      build: (input) => `/api/incidents/${requiredId(input)}`,
      cite: citeOne('incident', 'incident'),
    },
    {
      name: 'get_incident_alerts',
      label: 'Leyendo las alertas del incidente',
      description: 'Alertas vinculadas a un incidente.',
      anyOf: ['incidents.read'],
      properties: { id: { type: 'string' }, ...PAGING },
      required: ['id'],
      build: (input) =>
        `/api/incidents/${requiredId(input)}/alerts${query({ pageSize: pageSize(input) })}`,
      cite: citeList('alert'),
    },
    {
      name: 'get_incident_timeline',
      label: 'Leyendo la línea de tiempo',
      description: 'Línea de tiempo de un incidente (cambios de estado, tareas, notas).',
      anyOf: ['incidents.read'],
      properties: { id: { type: 'string' } },
      required: ['id'],
      build: (input) => `/api/incidents/${requiredId(input)}/timeline`,
    },
    {
      name: 'get_incident_tasks',
      label: 'Leyendo las tareas del incidente',
      description: 'Tareas de un incidente.',
      anyOf: ['incidents.read'],
      properties: { id: { type: 'string' } },
      required: ['id'],
      build: (input) => `/api/incidents/${requiredId(input)}/tasks`,
    },
    {
      name: 'get_incident_notes',
      label: 'Leyendo las notas del incidente',
      description: 'Notas de investigación de un incidente.',
      anyOf: ['incidents.read'],
      properties: { id: { type: 'string' } },
      required: ['id'],
      build: (input) => `/api/incidents/${requiredId(input)}/notes`,
    },
    {
      name: 'search_events',
      label: 'Buscando eventos',
      description:
        'Explorador de eventos de seguridad normalizados (Wazuh). Rango de hasta 31 días (por defecto 24 h) y filtros tipados. Para un inicio de sesión fallido usa category=authentication y outcome=failure.',
      anyOf: ['events.read'],
      properties: {
        from: {
          type: 'string',
          description: 'Inicio ISO 8601 en UTC, p. ej. 2026-11-02T00:00:00Z.',
        },
        to: { type: 'string', description: 'Fin ISO 8601 en UTC.' },
        severity: {
          type: 'string',
          description: 'Lista separada por comas: informational,low,medium,high,critical.',
        },
        category: {
          type: 'string',
          description: 'Lista separada por comas, p. ej. authentication,network.',
        },
        outcome: { type: 'string', enum: ['success', 'failure'] },
        ...PAGING,
      },
      build: (input) =>
        `/api/events${query({
          from: optionalString(input, 'from', ISO, 30),
          to: optionalString(input, 'to', ISO, 30),
          severity: optionalString(input, 'severity', LIST, 200),
          category: optionalString(input, 'category', LIST, 200),
          outcome: optionalEnum(input, 'outcome', ['success', 'failure']),
          pageSize: pageSize(input),
          cursor: optionalString(input, 'cursor', /^[A-Za-z0-9_.=-]+$/u, 1024),
        })}`,
    },
    {
      name: 'sources_health',
      label: 'Revisando la salud de las fuentes',
      description:
        'Estado de las fuentes de datos (¿llegan eventos?, fallas consecutivas, última recepción).',
      anyOf: ['sources.health.read'],
      properties: {},
      build: () => '/api/sources/health',
    },
    {
      name: 'operations_health',
      label: 'Revisando la salud operativa',
      description: 'Salud operativa del SOC y de la plataforma (colas, ingesta, procesos).',
      anyOf: ['observability.read_soc', 'observability.read_platform'],
      properties: {},
      build: () => '/api/operations/health',
    },
    {
      name: 'list_notifications',
      label: 'Revisando las notificaciones',
      description: 'Avisos enviados y su acuse (pendientes, entregados, fallidos).',
      anyOf: ['notifications.read'],
      properties: { ...PAGING },
      build: (input) =>
        `/api/notifications${query({
          pageSize: pageSize(input),
          cursor: optionalString(input, 'cursor', /^[A-Za-z0-9_.=-]+$/u, 1024),
        })}`,
    },
    {
      name: 'audit_events',
      label: 'Consultando la auditoría',
      description: 'Eventos de auditoría inmutable (quién hizo qué y cuándo).',
      anyOf: ['audit.read'],
      properties: {
        from: { type: 'string' },
        to: { type: 'string' },
        action: { type: 'string', description: 'Acción, p. ej. access.sign_in.' },
        resourceType: { type: 'string' },
        resourceId: { type: 'string' },
        outcome: { type: 'string', enum: ['succeeded', 'denied', 'failed'] },
        ...PAGING,
      },
      build: (input) =>
        `/api/audit/events${query({
          from: optionalString(input, 'from', ISO, 30),
          to: optionalString(input, 'to', ISO, 30),
          action: optionalString(input, 'action', WORD, 80),
          resourceType: optionalString(input, 'resourceType', WORD, 80),
          resourceId: optionalString(input, 'resourceId', WORD, 80),
          outcome: optionalEnum(input, 'outcome', ['succeeded', 'denied', 'failed']),
          pageSize: pageSize(input),
          cursor: optionalString(input, 'cursor', /^[A-Za-z0-9_.=-]+$/u, 1024),
        })}`,
    },
    {
      name: 'audit_verify',
      label: 'Verificando la cadena de auditoría',
      description: 'Verifica la integridad de la cadena hash de auditoría.',
      anyOf: ['audit.verify'],
      properties: {},
      build: () => '/api/audit/verify',
    },
    {
      name: 'list_users',
      label: 'Consultando usuarios',
      description: 'Usuarios del directorio con acceso al SOC y su estado.',
      anyOf: ['users.read'],
      properties: { ...PAGING },
      build: (input) => `/api/admin/users${query({ pageSize: pageSize(input) })}`,
    },
    {
      name: 'list_sessions',
      label: 'Consultando sesiones',
      description: 'Sesiones activas del SOC.',
      anyOf: ['sessions.read'],
      properties: { ...PAGING },
      build: (input) => `/api/admin/sessions${query({ pageSize: pageSize(input) })}`,
    },
    {
      name: 'list_role_requests',
      label: 'Consultando solicitudes de rol',
      description: 'Solicitudes de cambio de rol y su estado.',
      anyOf: ['roles.request', 'roles.approve'],
      properties: { ...PAGING },
      build: (input) => `/api/admin/role-requests${query({ pageSize: pageSize(input) })}`,
    },
  ];

  const tools = specs
    .filter((spec) => spec.anyOf.some((capability) => allowed.has(capability)))
    .map((spec) => readTool(spec, get));

  const whoami: AssistantTool = {
    name: 'whoami',
    label: 'Revisando tus permisos',
    description:
      'Roles y permisos de la persona que pregunta. Úsala para explicar por qué algo no está disponible.',
    inputSchema: { type: 'object', additionalProperties: false, properties: {} },
    async run() {
      return {
        ok: true,
        data: { roles: actor.roles, capabilities: [...actor.capabilities].sort() },
      };
    },
  };
  return [whoami, ...tools];
}
