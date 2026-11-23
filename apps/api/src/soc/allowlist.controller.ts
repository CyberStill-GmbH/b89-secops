/**
 * Lista blanca de la API de pagos (Cloudflare): clientes, proveedores e infraestructura con las IPs
 * desde las que pueden llamar a `apipayments.b89.io`.
 *
 * - `GET  /api/cloudflare/allowlist` (`allowlist.read`): la versión vigente (o la inicial importada).
 * - `PUT  /api/cloudflare/allowlist` (`allowlist.manage` + CSRF + sesión reciente salvo admin de
 *   plataforma): reemplaza la lista con compare-and-set sobre `expectedRevision`; auditado.
 * - `GET  /api/cloudflare/allowlist/feed` (Bearer `B89_ALLOWLIST_FEED_TOKEN`): lo que necesita el
 *   colector de Cloudflare para marcar cada petición (IPs y marcadores por entrada). Sin sesión.
 */

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { Body, Controller, Get, Header, Inject, Put, Req } from '@nestjs/common';

import { recordAudit } from '@b89/audit';
import { ApiError } from '../http/api-error.js';
import type { IncomingRequest } from '../http/http-contracts.js';
import { correlationIdOf } from '../http/request-context.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';
import { ALLOWLIST_SEED } from './allowlist.seed.js';
import { needsRecentAuth } from './notification-channels.controller.js';
import { mutatingActor, readingActor } from './session-actor.js';
import { SECOPS_RUNTIME } from './tokens.js';

export const ALLOWLIST_KINDS = ['client', 'provider', 'internal'] as const;
export const ALLOWLIST_STATUSES = ['with_ip', 'pending', 'not_contacted', 'not_required', 'to_validate'] as const;

const LIMITS = Object.freeze({ entries: 500, ips: 50, markers: 10, name: 120, text: 300 });
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(\/([89]|[12]\d|3[0-2]))?$/u;
const IPV6 = /^[0-9a-f:]{2,39}(\/(1[6-9]|[2-9]\d|1[01]\d|12[0-8]))?$/u;
const MARKER = /^[a-z0-9._~\-/]{3,64}$/u;
const ENTRY_ID = /^[a-z0-9][a-z0-9-]{0,63}$/u;

export interface AllowlistEntry {
  readonly id: string;
  readonly name: string;
  readonly kind: (typeof ALLOWLIST_KINDS)[number];
  readonly product: string | null;
  readonly country: string | null;
  readonly company: string | null;
  readonly status: (typeof ALLOWLIST_STATUSES)[number];
  readonly prodIps: readonly string[];
  readonly sandboxIps: readonly string[];
  readonly markers: readonly string[];
  readonly note: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function text(value: unknown, max: number, field: string, fail: (field: string) => never): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string' || value.length > max) return fail(field);
  const trimmed = value.trim();
  return trimmed || null;
}

function ipList(value: unknown, field: string, fail: (field: string) => never): string[] {
  if (!Array.isArray(value) || value.length > LIMITS.ips) return fail(field);
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item !== 'string') return fail(field);
    const ip = item.trim().toLowerCase();
    const valid = IPV4.test(ip) || (ip.includes(':') && IPV6.test(ip) && (ip.match(/::/gu) ?? []).length <= 1);
    if (!valid) return fail(field);
    seen.add(ip);
  }
  return [...seen];
}

/** Valida y normaliza la lista completa. `fail` decide el error (400 al guardar, 503 si lo guardado está corrupto). */
export function parseAllowlist(value: unknown, fail: (field: string) => never): AllowlistEntry[] {
  if (!Array.isArray(value) || value.length > LIMITS.entries) return fail('entries');
  const ids = new Set<string>();
  return value.map((raw, index) => {
    const at = (field: string) => `entries[${index}].${field}`;
    if (!isRecord(raw)) return fail(`entries[${index}]`);
    const id = raw['id'];
    if (typeof id !== 'string' || !ENTRY_ID.test(id) || ids.has(id)) return fail(at('id'));
    ids.add(id);
    const name = text(raw['name'], LIMITS.name, at('name'), fail);
    if (!name) return fail(at('name'));
    const kind = raw['kind'];
    if (!(ALLOWLIST_KINDS as readonly unknown[]).includes(kind)) return fail(at('kind'));
    const status = raw['status'];
    if (!(ALLOWLIST_STATUSES as readonly unknown[]).includes(status)) return fail(at('status'));
    const markersRaw = raw['markers'] ?? [];
    if (!Array.isArray(markersRaw) || markersRaw.length > LIMITS.markers) return fail(at('markers'));
    const markers = [...new Set(markersRaw.map((marker) => (typeof marker === 'string' ? marker.trim().toLowerCase() : '')))];
    if (markers.some((marker) => !MARKER.test(marker))) return fail(at('markers'));
    return {
      id,
      name,
      kind: kind as AllowlistEntry['kind'],
      product: text(raw['product'], LIMITS.name, at('product'), fail),
      country: text(raw['country'], LIMITS.name, at('country'), fail),
      company: text(raw['company'], LIMITS.name, at('company'), fail),
      status: status as AllowlistEntry['status'],
      prodIps: ipList(raw['prodIps'] ?? [], at('prodIps'), fail),
      sandboxIps: ipList(raw['sandboxIps'] ?? [], at('sandboxIps'), fail),
      markers,
      note: text(raw['note'], LIMITS.text, at('note'), fail),
    };
  });
}

function bearer(request: IncomingRequest): string | undefined {
  const value = request.headers.authorization;
  if (typeof value !== 'string') return undefined;
  return /^Bearer ([A-Za-z0-9_.~+/=-]{32,256})$/u.exec(value)?.[1];
}

function sameSecret(sent: string, expected: string): boolean {
  const a = createHash('sha256').update(sent, 'utf8').digest();
  const b = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(a, b);
}

@Controller('api/cloudflare/allowlist')
export class AllowlistController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  private async current(tenantId: string, correlationId: string) {
    const row = await this.runtime.allowlistStore.get(tenantId);
    const corrupt = (): never => {
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    };
    const entries = row ? parseAllowlist(isRecord(row.document) ? row.document['entries'] : undefined, corrupt) : parseAllowlist(ALLOWLIST_SEED, corrupt);
    return { revision: row?.revision ?? 0, updatedAt: row?.updatedAt.toISOString() ?? null, entries };
  }

  @Get()
  @Header('Cache-Control', 'no-store')
  public async get(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await readingActor(this.runtime, request);
    if (!actor.capabilities.has('allowlist.read')) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const current = await this.current(actor.tenantId, correlationId);
    return { correlationId, ...current, canManage: actor.capabilities.has('allowlist.manage') };
  }

  @Put()
  public async put(@Req() request: IncomingRequest, @Body() body: unknown) {
    const { actor, session, correlationId } = await mutatingActor(this.runtime, request);
    if (!actor.capabilities.has('allowlist.manage')) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    if (needsRecentAuth(actor, session, this.runtime.now())) throw new ApiError('STEP_UP_REQUIRED', correlationId);
    const invalid = (field: string): never => {
      throw new ApiError('VALIDATION_FAILED', correlationId, [field]);
    };
    if (!isRecord(body)) return invalid('body');
    const expected = body['expectedRevision'];
    if (typeof expected !== 'number' || !Number.isInteger(expected) || expected < 0) return invalid('expectedRevision');
    const entries = parseAllowlist(body['entries'], invalid);
    const now = this.runtime.now();
    const saved = await this.runtime.allowlistStore.put(actor.tenantId, { entries }, expected, actor.subjectId, now);
    if (!saved) throw new ApiError('STATE_CONFLICT', correlationId);
    const current = await this.current(actor.tenantId, correlationId);
    await recordAudit(this.runtime.audit, {
      id: randomUUID(),
      tenantId: actor.tenantId,
      occurredAt: now,
      actor: { id: actor.subjectId, type: 'user', sessionId: actor.sessionId },
      action: 'cloudflare.allowlist.updated',
      resource: { type: 'cloudflare_allowlist', id: actor.tenantId },
      outcome: 'succeeded',
      correlationId,
      metadata: {
        revision: current.revision,
        entries: entries.length,
        ips: entries.reduce((total, entry) => total + entry.prodIps.length + entry.sandboxIps.length, 0),
      },
    });
    return { correlationId, ...current, canManage: true };
  }

  /** Para el sincronizador del colector: sin sesión, solo con el token configurado. */
  @Get('feed')
  @Header('Cache-Control', 'no-store')
  public async feed(@Req() request: IncomingRequest) {
    const correlationId = correlationIdOf(request);
    const expected = this.runtime.allowlistFeedToken;
    const sent = bearer(request);
    if (!expected || !sent || !sameSecret(sent, expected)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const current = await this.current(this.runtime.tenantId, correlationId);
    return {
      revision: current.revision,
      entries: current.entries.map((entry) => ({
        id: entry.id,
        name: entry.name,
        kind: entry.kind,
        status: entry.status,
        ips: [...entry.prodIps, ...entry.sandboxIps],
        markers: entry.markers,
      })),
    };
  }
}
