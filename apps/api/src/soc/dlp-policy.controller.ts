import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Body, Controller, Get, Header, Inject, Param, Post, Put, Req, Res, StreamableFile } from '@nestjs/common';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { FastifyReply } from 'fastify';

import { recordAudit } from '@b89/audit';
import type { IncomingRequest } from '../http/http-contracts.js';
import { ApiError } from '../http/api-error.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';
import type { DlpEndpointRecord } from '../runtime/dlp-policy-store.js';
import { correlationIdOf } from '../http/request-context.js';
import { needsRecentAuth } from './notification-channels.controller.js';
import { mutatingActor, readingActor } from './session-actor.js';
import { SECOPS_RUNTIME } from './tokens.js';

export const DLP_RULE_IDS = Object.freeze([
  'B89_CRED_PRIVATE_KEY_PEM',
  'B89_CRED_GITHUB_TOKEN',
  'B89_CRED_SLACK_TOKEN',
  'B89_CRED_GOOGLE_API_KEY',
  'B89_CRED_AZURE_STORAGE_KEY',
  'B89_CRED_OPENAI_API_KEY',
  'B89_CRED_AWS_ACCESS_KEY_PAIR',
  'B89_SECRET_DATABASE_CONNECTION',
  'B89_SECRET_CREDENTIAL_ASSIGNMENT',
  'B89_PII_PERU_DNI_CONTEXTUAL',
  'B89_PII_PERU_RUC_CONTEXTUAL',
] as const);

/** This rule is always applied by the endpoint and is deliberately not user-toggleable. */
export const DLP_ALWAYS_ON_RULE_IDS = Object.freeze(['B89_DLP_EXACT_FILE_FINGERPRINT'] as const);
const DEFAULT_ENABLED_RULE_IDS = DLP_RULE_IDS.slice(0, 6);
const DEFAULT_POLICY_VERSION = '1.0.0';
const ENROLLMENT_TTL_MS = 30 * 60_000;
/** The agent polls every 30 s; two missed polls plus a long scan still count as online. */
export const DLP_ONLINE_WINDOW_MS = 2 * 60_000;
const ENDPOINT_ID = /^[0-9a-f-]{36}$/iu;
const MAX_FINGERPRINTS = 10_000;
const MAX_USB_GROUPS = 100;
const MAX_USB_IDENTITIES = 1_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const WINDOWS_SID = /^S-1-(?:\d+-){1,14}\d+$/iu;
const MAX_HOSTNAME = /^[A-Za-z0-9_.-]{1,128}$/u;
const AGENT_ID = /^[A-Za-z0-9_.-]{1,16}$/u;
const POLICY_VERSION = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]{1,32})?$/u;
const INSTALLER_PLATFORMS = new Set(['windows-x64', 'windows-arm64', 'macos-x64', 'macos-arm64', 'linux-x64', 'linux-arm64']);
const INSTALLER_DIR = '/app/ferrispector-packages';

interface DlpPolicyDocument {
  readonly policyVersion: string;
  readonly enabledRuleIds: readonly string[];
  readonly fingerprintsSha256: readonly string[];
  readonly quarantineExactFingerprints: boolean;
  readonly usbControl: {
    readonly enabled: boolean;
    readonly supportedPlanConfirmed: boolean;
    readonly allowedGroups: readonly {
      readonly id: string;
      readonly name: string;
      readonly identities: readonly string[];
    }[];
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function expectedRevisionOf(body: unknown, correlationId: string): number {
  const value = isRecord(body) ? body['expectedRevision'] : undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 2_000_000_000) {
    throw new ApiError('VALIDATION_FAILED', correlationId, ['expectedRevision']);
  }
  return value;
}

function documentOf(value: unknown, correlationId: string, updating = false): DlpPolicyDocument {
  const invalid = (field: string): never => {
    throw updating
      ? new ApiError('VALIDATION_FAILED', correlationId, [field])
      : new ApiError('DEPENDENCY_DEGRADED', correlationId);
  };
  if (!isRecord(value)) return invalid('policy');
  const policyVersion = value['policyVersion'];
  const enabledRuleIds = value['enabledRuleIds'];
  const fingerprintsSha256 = value['fingerprintsSha256'];
  const quarantineExactFingerprints = value['quarantineExactFingerprints'] ?? (updating ? undefined : false);
  const usbControl = value['usbControl'] ?? (updating
    ? undefined
    : { enabled: false, supportedPlanConfirmed: false, allowedGroups: [] });
  if (typeof policyVersion !== 'string' || !POLICY_VERSION.test(policyVersion)) {
    return invalid('policyVersion');
  }
  if (!Array.isArray(enabledRuleIds) || enabledRuleIds.length > DLP_RULE_IDS.length) {
    return invalid('enabledRuleIds');
  }
  const rules = new Set<string>();
  for (const id of enabledRuleIds) {
    if (typeof id !== 'string' || !(DLP_RULE_IDS as readonly string[]).includes(id) || rules.has(id)) {
      return invalid('enabledRuleIds');
    }
    rules.add(id);
  }
  if (!Array.isArray(fingerprintsSha256) || fingerprintsSha256.length > MAX_FINGERPRINTS) {
    return invalid('fingerprintsSha256');
  }
  const fingerprints = new Set<string>();
  for (const fingerprint of fingerprintsSha256) {
    if (typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/u.test(fingerprint) || fingerprints.has(fingerprint)) {
      return invalid('fingerprintsSha256');
    }
    fingerprints.add(fingerprint);
  }
  if (typeof quarantineExactFingerprints !== 'boolean') return invalid('quarantineExactFingerprints');
  if (quarantineExactFingerprints && fingerprints.size === 0) return invalid('quarantineExactFingerprints');
  if (!isRecord(usbControl) || typeof usbControl['enabled'] !== 'boolean' ||
      typeof usbControl['supportedPlanConfirmed'] !== 'boolean' ||
      !Array.isArray(usbControl['allowedGroups']) || usbControl['allowedGroups'].length > MAX_USB_GROUPS) {
    return invalid('usbControl');
  }
  const groupIds = new Set<string>();
  let identityCount = 0;
  const allowedGroups: { id: string; name: string; identities: string[] }[] = [];
  for (const candidate of usbControl['allowedGroups']) {
    if (!isRecord(candidate) || typeof candidate['id'] !== 'string' || !UUID.test(candidate['id']) ||
        groupIds.has(candidate['id'].toLowerCase()) || typeof candidate['name'] !== 'string' ||
        candidate['name'].trim().length < 1 || candidate['name'].trim().length > 64 ||
        !Array.isArray(candidate['identities']) || candidate['identities'].length > MAX_USB_IDENTITIES) {
      return invalid('usbControl.allowedGroups');
    }
    const identities = new Set<string>();
    for (const identity of candidate['identities']) {
      if (typeof identity !== 'string' || identity.length > 184 ||
          !WINDOWS_SID.test(identity) || identities.has(identity.toLowerCase())) {
        return invalid('usbControl.allowedGroups.identities');
      }
      identities.add(identity);
      identityCount += 1;
      if (identityCount > MAX_USB_IDENTITIES) return invalid('usbControl.allowedGroups.identities');
    }
    groupIds.add(candidate['id'].toLowerCase());
    allowedGroups.push({
      id: candidate['id'].toLowerCase(),
      name: candidate['name'].trim(),
      identities: [...identities].sort((a, b) => a.localeCompare(b)),
    });
  }
  if (usbControl['enabled'] && (!usbControl['supportedPlanConfirmed'] || allowedGroups.length === 0 ||
      allowedGroups.some((group) => group.identities.length === 0))) {
    return invalid('usbControl');
  }
  return {
    policyVersion,
    enabledRuleIds: [...rules].sort(),
    fingerprintsSha256: [...fingerprints].sort(),
    quarantineExactFingerprints,
    usbControl: {
      enabled: usbControl['enabled'],
      supportedPlanConfirmed: usbControl['supportedPlanConfirmed'],
      allowedGroups: allowedGroups.sort((a, b) => a.name.localeCompare(b.name)),
    },
  };
}

function parsePolicyUpdate(body: unknown, correlationId: string): {
  readonly expectedRevision: number;
  readonly document: DlpPolicyDocument;
} {
  if (!isRecord(body)) throw new ApiError('VALIDATION_FAILED', correlationId, ['body']);
  const expectedRevision = expectedRevisionOf(body, correlationId);
  const parsed = documentOf({
    policyVersion: body['policyVersion'],
    enabledRuleIds: body['enabledRuleIds'],
    fingerprintsSha256: body['fingerprintsSha256'],
    quarantineExactFingerprints: body['quarantineExactFingerprints'],
    usbControl: body['usbControl'],
  }, correlationId, true);
  return { expectedRevision, document: parsed };
}

function defaultPolicy(): DlpPolicyDocument {
  return {
    policyVersion: DEFAULT_POLICY_VERSION,
    enabledRuleIds: [...DEFAULT_ENABLED_RULE_IDS],
    fingerprintsSha256: [],
    quarantineExactFingerprints: false,
    usbControl: { enabled: false, supportedPlanConfirmed: false, allowedGroups: [] },
  };
}

function currentPolicy(row: { readonly revision: number; readonly document: unknown; readonly updatedAt: Date } | undefined,
  correlationId: string) {
  const policy = row ? documentOf(row.document, correlationId) : defaultPolicy();
  return {
    revision: row?.revision ?? 0,
    ...policy,
    alwaysOnRuleIds: DLP_ALWAYS_ON_RULE_IDS,
    updatedAt: row?.updatedAt.toISOString() ?? null,
  };
}

function bearer(request: IncomingRequest): string | undefined {
  const value = request.headers.authorization;
  if (typeof value !== 'string') return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{40,64})$/u.exec(value);
  return match?.[1];
}

function endpointView(endpoint: DlpEndpointRecord, currentRevision: number, now: Date) {
  const status = endpoint.revokedAt
    ? 'revoked'
    : endpoint.enrolledAt && endpoint.credentialVersion !== 1
      ? 're-enrollment-required'
    : !endpoint.lastSeenAt || now.getTime() - endpoint.lastSeenAt.getTime() > DLP_ONLINE_WINDOW_MS
      ? 'offline'
      : endpoint.appliedRevision < currentRevision
        ? 'updating'
        : 'current';
  return {
    id: endpoint.id,
    hostname: endpoint.hostname,
    agentId: endpoint.agentId,
    enrolledAt: endpoint.enrolledAt?.toISOString() ?? null,
    lastSeenAt: endpoint.lastSeenAt?.toISOString() ?? null,
    appliedRevision: endpoint.appliedRevision,
    policyVersion: endpoint.policyVersion,
    usbControlStatus: endpoint.usbControlStatus ?? 'unknown',
    usbControlCode: endpoint.usbControlCode,
    usbControlCheckedAt: endpoint.usbControlCheckedAt?.toISOString() ?? null,
    status,
    revokedAt: endpoint.revokedAt?.toISOString() ?? null,
  };
}

@Controller('api/dlp')
export class DlpPolicyController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  private store(correlationId: string) {
    const store = this.runtime.dlpPolicyStore;
    // Authorization is checked before the store is accessed, so an authorized operator
    // can distinguish a missing DLP service from an account that cannot use the module.
    if (!store) throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    return store;
  }

  private async authorized(
    request: IncomingRequest,
    capability: 'dlp.read' | 'dlp.configure',
    mutate = false,
    recentAuth = mutate,
  ) {
    const resolved = mutate
      ? await mutatingActor(this.runtime, request)
      : await readingActor(this.runtime, request);
    if (!resolved.actor.capabilities.has(capability) || resolved.actor.tenantId !== this.runtime.tenantId) {
      throw new ApiError('RESOURCE_UNAVAILABLE', resolved.correlationId);
    }
    // Misma regla que canales (decisión del dueño): la administración de plataforma usa su sesión
    // vigente; el resto de roles con dlp.configure necesita un inicio de sesión de < 30 min.
    if (recentAuth && needsRecentAuth(resolved.actor, resolved.session, this.runtime.now())) {
      throw new ApiError('STEP_UP_REQUIRED', resolved.correlationId);
    }
    return resolved;
  }

  private async agent(request: IncomingRequest) {
    const correlationId = correlationIdOf(request);
    const token = bearer(request);
    if (!token) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const endpoint = await this.store(correlationId).endpointByToken({
      tenantId: this.runtime.tenantId,
      tokenHash: createHash('sha256').update(token, 'utf8').digest('hex'),
      at: this.runtime.now(),
    });
    if (!endpoint) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    return { correlationId, endpoint };
  }

  private async audit(
    actor: { readonly subjectId: string; readonly sessionId: string; readonly tenantId: string },
    correlationId: string,
    action: string,
    resource: { readonly type: string; readonly id: string },
    metadata: Readonly<Record<string, string | number | boolean | null>>,
  ) {
    await recordAudit(this.runtime.audit, {
      id: randomUUID(),
      tenantId: actor.tenantId,
      occurredAt: this.runtime.now(),
      actor: { id: actor.subjectId, type: 'user', sessionId: actor.sessionId },
      action,
      resource,
      outcome: 'succeeded',
      correlationId,
      metadata,
    });
  }

  @Get('policy')
  @Header('Cache-Control', 'no-store')
  public async getPolicy(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.read');
    const store = this.store(correlationId);
    const [row, endpoints] = await Promise.all([
      store.policy(actor.tenantId),
      store.endpoints(actor.tenantId),
    ]);
    const policy = currentPolicy(row, correlationId);
    return {
      correlationId,
      ...policy,
      canManage: actor.capabilities.has('dlp.configure'),
      endpointCount: endpoints.filter((endpoint) => endpoint.revokedAt === null).length,
    };
  }

  @Put('policy')
  public async putPolicy(@Req() request: IncomingRequest, @Body() body: unknown) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure', true);
    const store = this.store(correlationId);
    let update: ReturnType<typeof parsePolicyUpdate>;
    try {
      update = parsePolicyUpdate(body, correlationId);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError('VALIDATION_FAILED', correlationId, ['policy']);
    }
    const saved = await store.putPolicy(
      actor.tenantId,
      update.document,
      update.expectedRevision,
      actor.subjectId,
      this.runtime.now(),
    );
    if (!saved) throw new ApiError('STATE_CONFLICT', correlationId);
    const row = await store.policy(actor.tenantId);
    const policy = currentPolicy(row, correlationId);
    await this.audit(actor, correlationId, 'dlp.policy.updated', { type: 'dlp_policy', id: actor.tenantId }, {
      revision: policy.revision,
      policyVersion: policy.policyVersion,
      enabledRuleIds: policy.enabledRuleIds.join(',').slice(0, 1_000),
      enabledRuleCount: policy.enabledRuleIds.length,
      fingerprintCount: policy.fingerprintsSha256.length,
      quarantineExactFingerprints: policy.quarantineExactFingerprints,
      usbControlEnabled: policy.usbControl.enabled,
      usbAllowedGroupCount: policy.usbControl.allowedGroups.length,
    });
    return { correlationId, ...policy, propagationIntervalSeconds: 30 };
  }

  @Get('endpoints')
  @Header('Cache-Control', 'no-store')
  public async listEndpoints(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.read');
    const store = this.store(correlationId);
    const [row, endpoints] = await Promise.all([
      store.policy(actor.tenantId),
      store.endpoints(actor.tenantId),
    ]);
    const policy = currentPolicy(row, correlationId);
    const now = this.runtime.now();
    return {
      correlationId,
      policyRevision: policy.revision,
      onlineWindowSeconds: DLP_ONLINE_WINDOW_MS / 1_000,
      items: endpoints.map((endpoint) => {
        const view = endpointView(endpoint, policy.revision, now);
        return {
          id: view.id,
          hostname: view.hostname,
          agentId: view.agentId,
          enrolledAt: view.enrolledAt,
          lastSeenAt: view.lastSeenAt,
          currentRevision: view.appliedRevision,
          currentPolicyVersion: view.policyVersion,
          status: view.status,
          usbControlStatus: view.usbControlStatus,
          usbControlCode: view.usbControlCode,
          usbControlCheckedAt: view.usbControlCheckedAt,
          revokedAt: view.revokedAt,
        };
      }),
    };
  }

  @Post('enrollment-tokens')
  @Header('Cache-Control', 'no-store')
  public async createEnrollmentToken(@Req() request: IncomingRequest) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure', true);
    const token = randomBytes(32).toString('base64url');
    const id = randomUUID();
    const now = this.runtime.now();
    const expiresAt = new Date(now.getTime() + ENROLLMENT_TTL_MS);
    const store = this.store(correlationId);
    let created: boolean;
    try {
      created = await store.issueEnrollmentToken({
        id,
        tenantId: actor.tenantId,
        tokenHash: createHash('sha256').update(token, 'utf8').digest('hex'),
        expiresAt,
        now,
      });
    } catch {
      // Keep database details private while returning a useful, correlatable service error.
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    }
    if (!created) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    try {
      await this.audit(actor, correlationId, 'dlp.endpoint.enrollment_token_created', { type: 'dlp_endpoint', id }, {
        expiresAt: expiresAt.toISOString(),
      });
    } catch {
      // Do not leave a valid, untracked enrollment secret if durable audit is unavailable.
      await store.cancelEnrollment({ tenantId: actor.tenantId, id, at: this.runtime.now() }).catch(() => false);
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    }
    return { correlationId, id, token, expiresAt: expiresAt.toISOString() };
  }

  @Get('installers/:platform')
  @Header('Cache-Control', 'private, no-store')
  public async downloadInstaller(
    @Req() request: IncomingRequest,
    @Param('platform') platform: string,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure');
    if (!INSTALLER_PLATFORMS.has(platform)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const filename = `RabbitDLP-${platform}.zip`;
    let bytes: Buffer;
    try {
      bytes = await readFile(join(INSTALLER_DIR, filename));
    } catch {
      throw new ApiError('DEPENDENCY_DEGRADED', correlationId);
    }
    reply.header('X-Content-SHA256', createHash('sha256').update(bytes).digest('hex'));
    await this.audit(actor, correlationId, 'dlp.installer.requested', { type: 'dlp_installer', id: platform }, {
      filename,
      bytes: bytes.byteLength,
    });
    return new StreamableFile(bytes, {
      type: 'application/zip',
      disposition: `attachment; filename="${filename}"`,
      length: bytes.byteLength,
    });
  }

  /**
   * Lets the connection wizard detect the endpoint without exposing other tokens. The row id is
   * shared by the token and the endpoint it becomes, so `connected` names the new endpoint.
   */
  @Get('enrollment-tokens/:id')
  @Header('Cache-Control', 'no-store')
  public async enrollmentStatus(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure');
    if (!ENDPOINT_ID.test(id)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const row = await this.store(correlationId).enrollment({ tenantId: actor.tenantId, id });
    if (!row) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const now = this.runtime.now();
    if (row.enrolledAt) {
      return {
        correlationId,
        id,
        state: row.revokedAt ? 'revoked' : 'connected',
        expiresAt: row.enrollmentExpiresAt.toISOString(),
        endpoint: {
          id: row.id,
          hostname: row.hostname,
          enrolledAt: row.enrolledAt.toISOString(),
          lastSeenAt: row.lastSeenAt?.toISOString() ?? null,
        },
      };
    }
    return {
      correlationId,
      id,
      state: row.enrollmentExpiresAt.getTime() <= now.getTime() ? 'expired' : 'waiting',
      expiresAt: row.enrollmentExpiresAt.toISOString(),
      endpoint: null,
    };
  }

  /**
   * Withdraws an unused installation key. No recent sign-in is required: cancelling only reduces
   * access, and blocking it would leave a valid key alive for up to 30 minutes.
   */
  @Post('enrollment-tokens/:id/cancel')
  public async cancelEnrollmentToken(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure', true, false);
    if (!ENDPOINT_ID.test(id)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const cancelled = await this.store(correlationId).cancelEnrollment({
      tenantId: actor.tenantId,
      id,
      at: this.runtime.now(),
    });
    if (!cancelled) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    await this.audit(actor, correlationId, 'dlp.endpoint.enrollment_token_cancelled', { type: 'dlp_endpoint', id }, {});
    return { correlationId, id, cancelled: true };
  }

  @Post('endpoints/:id/revoke')
  public async revokeEndpoint(@Req() request: IncomingRequest, @Param('id') id: string) {
    const { actor, correlationId } = await this.authorized(request, 'dlp.configure', true);
    if (!ENDPOINT_ID.test(id)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const revoked = await this.store(correlationId).revokeEndpoint({ tenantId: actor.tenantId, id, at: this.runtime.now() });
    if (!revoked) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    await this.audit(actor, correlationId, 'dlp.endpoint.revoked', { type: 'dlp_endpoint', id }, {});
    return { correlationId, id, revoked: true };
  }

  @Post('agent/enroll')
  public async enrollAgent(@Req() request: IncomingRequest, @Body() body: unknown) {
    const correlationId = correlationIdOf(request);
    const token = bearer(request);
    if (!token || !isRecord(body)) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    const hostname = body['hostname'];
    const agentId = body['agentId'];
    if (typeof hostname !== 'string' || !MAX_HOSTNAME.test(hostname) ||
        typeof agentId !== 'string' || !AGENT_ID.test(agentId)) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['hostname', 'agentId']);
    }
    const endpointCredential = randomBytes(32).toString('base64url');
    const endpoint = await this.store(correlationId).enrollEndpoint({
      tenantId: this.runtime.tenantId,
      tokenHash: createHash('sha256').update(token, 'utf8').digest('hex'),
      credentialHash: createHash('sha256').update(endpointCredential, 'utf8').digest('hex'),
      hostname,
      agentId,
      at: this.runtime.now(),
    });
    if (!endpoint) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    await recordAudit(this.runtime.audit, {
      id: randomUUID(),
      tenantId: this.runtime.tenantId,
      occurredAt: this.runtime.now(),
      actor: { id: 'system:ferrispector-agent', type: 'service' },
      action: 'dlp.endpoint.enrolled',
      resource: { type: 'dlp_endpoint', id: endpoint.id },
      outcome: 'succeeded',
      correlationId,
      metadata: { hostname, agentId },
    });
    return { correlationId, endpointId: endpoint.id, endpointCredential, enrolledAt: endpoint.enrolledAt?.toISOString() };
  }

  @Get('agent/policy')
  @Header('Cache-Control', 'no-store')
  public async getAgentPolicy(@Req() request: IncomingRequest) {
    const { correlationId } = await this.agent(request);
    const row = await this.store(correlationId).policy(this.runtime.tenantId);
    const policy = currentPolicy(row, correlationId);
    return { correlationId, ...policy };
  }

  @Post('agent/ack')
  public async acknowledgePolicy(@Req() request: IncomingRequest, @Body() body: unknown) {
    const { correlationId, endpoint } = await this.agent(request);
    const usb = isRecord(body) && isRecord(body['usbControl']) ? body['usbControl'] : undefined;
    const allowedUsbStatuses = ['disabled', 'active', 'pending', 'unsupported', 'conflict', 'error', 'not-applicable'] as const;
    const allowedUsbCodes = [
      'POLICY_DISABLED', 'POLICY_ACTIVE', 'POLICY_PENDING', 'WINDOWS_UNSUPPORTED',
      'DEFENDER_UNAVAILABLE', 'DEFENDER_POLICY_CONFLICT', 'DEFENDER_APPLY_FAILED', 'NOT_WINDOWS',
    ] as const;
    if (!isRecord(body) || typeof body['revision'] !== 'number' || !Number.isInteger(body['revision']) ||
        body['revision'] < 0 || typeof body['policyVersion'] !== 'string' || !POLICY_VERSION.test(body['policyVersion']) ||
        !usb || typeof usb['status'] !== 'string' || !(allowedUsbStatuses as readonly string[]).includes(usb['status']) ||
        !(usb['code'] === null || (typeof usb['code'] === 'string' && (allowedUsbCodes as readonly string[]).includes(usb['code'])))) {
      throw new ApiError('VALIDATION_FAILED', correlationId, ['revision', 'policyVersion', 'usbControl']);
    }
    const policy = currentPolicy(await this.store(correlationId).policy(this.runtime.tenantId), correlationId);
    if (body['revision'] !== policy.revision || body['policyVersion'] !== policy.policyVersion) {
      throw new ApiError('STATE_CONFLICT', correlationId);
    }
    const saved = await this.store(correlationId).acknowledgePolicy({
      endpointId: endpoint.id,
      tenantId: this.runtime.tenantId,
      revision: policy.revision,
      policyVersion: policy.policyVersion,
      usbControlStatus: usb['status'] as typeof allowedUsbStatuses[number],
      usbControlCode: usb['code'] as string | null,
      at: this.runtime.now(),
    });
    if (!saved) throw new ApiError('RESOURCE_UNAVAILABLE', correlationId);
    return {
      correlationId,
      appliedRevision: policy.revision,
      policyVersion: policy.policyVersion,
      usbControlStatus: usb['status'],
    };
  }
}
