/**
 * Registro vivo de los canales de aviso (Teams, correo, push) con su configuración y salud.
 *
 * - **Teams**: la URL del Workflow viene de `B89_TEAMS_WORKFLOW_URL` (arranque) y la puede
 *   reemplazar un administrador desde la consola; el valor de la base manda. Se guarda cifrada
 *   (AES-256-GCM con una clave derivada de `B89_ENTITY_REF_KEY`, AAD = tenant y canal) y el
 *   cambio aplica en caliente: el transporte lee la URL vigente en cada envío. Otras réplicas la
 *   recogen en la siguiente relectura (60 s).
 * - **Correo** y **push**: se configuran por despliegue (`B89_ALERT_MAIL_SENDER`, VAPID); aquí
 *   solo se encienden o apagan y se prueban.
 * - Cada envío actualiza la salud del canal (último éxito/fallo, HTTP, motivo), en memoria y
 *   en la base (sin bloquear el aviso si la base falla).
 *
 * Nunca se registra ni devuelve la URL: solo su máscara.
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

import {
  emptyChannel,
  maskWebhookUrl,
  RETRY_POLICY,
  TeamsWorkflowTransport,
  validateTeamsWebhookUrl,
  type ChannelId,
  type ChannelRecord,
  type ChannelStore,
  type DeliveryEvidence,
  type DeliveryOutcome,
  type FallbackChannel,
  type FallbackNotification,
  type MailChannel,
  type NotificationChannel,
  type NotificationTransport,
  type TeamsMessage,
} from '@b89/soar';

const REFRESH_MS = 60_000;

export function deriveChannelKey(masterKey: string | Buffer): Buffer {
  return createHmac('sha256', masterKey).update('b89.notification-channel.key.v1').digest();
}

export function encryptSecret(key: Buffer, plaintext: string, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64url')}:${cipher.getAuthTag().toString('base64url')}:${ciphertext.toString('base64url')}`;
}

export function decryptSecret(key: Buffer, value: string, aad: string): string {
  const [version, iv, tag, ciphertext] = value.split(':');
  if (version !== 'v1' || !iv || !tag || ciphertext === undefined) throw new Error('CHANNEL_SECRET_FORMAT');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]).toString('utf8');
}

export interface ChannelView {
  readonly id: ChannelId;
  readonly label: string;
  readonly enabled: boolean;
  readonly configured: boolean;
  /** `database` (consola), `environment` (despliegue) o `none`. */
  readonly source: 'database' | 'environment' | 'none';
  /** Máscara del destino; nunca la URL. */
  readonly destination: string | null;
  readonly status: 'ok' | 'degraded' | 'failing' | 'disabled' | 'not_configured' | 'unknown';
  readonly health: {
    readonly lastSuccessAt: string | null;
    readonly lastFailureAt: string | null;
    readonly lastHttpStatus: number | null;
    readonly lastFailureReason: string | null;
  };
  readonly lastTest: {
    readonly at: string | null;
    readonly outcome: 'accepted' | 'failed' | null;
    readonly httpStatus: number | null;
    readonly providerMessageId: string | null;
  };
  readonly updatedAt: string | null;
  readonly updatedBy: string | null;
  readonly note: string | null;
}

const LABELS: Readonly<Record<ChannelId, string>> = Object.freeze({
  teams: 'Microsoft Teams (Workflows)',
  email: 'Correo (Microsoft Graph)',
  push: 'Consola y avisos del navegador (Web Push)',
});

export interface RegistryOptions {
  readonly tenantId: string;
  readonly store: ChannelStore;
  /** Clave de cifrado; sin ella no se puede guardar un webhook desde la consola. */
  readonly key?: Buffer;
  readonly environmentTeamsUrl?: string;
  readonly emailConfigured: boolean;
  readonly pushConfigured: boolean;
  readonly clock: () => Date;
  readonly fetchImplementation?: typeof fetch;
  readonly onError?: (code: string) => void;
}

export class NotificationChannelRegistry {
  private records = new Map<ChannelId, ChannelRecord>();
  private databaseTeamsUrl: string | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;

  public constructor(private readonly options: RegistryOptions) {}

  private aad(channelId: ChannelId): string {
    return `${this.options.tenantId}|${channelId}`;
  }

  private record(channelId: ChannelId): ChannelRecord {
    return this.records.get(channelId) ?? emptyChannel(this.options.tenantId, channelId, this.options.clock());
  }

  /** Lee la base; un fallo deja la última configuración conocida (nunca vacía la URL). */
  public async refresh(): Promise<void> {
    try {
      const rows = await this.options.store.list(this.options.tenantId);
      const next = new Map<ChannelId, ChannelRecord>();
      for (const row of rows) next.set(row.channelId, row);
      const teams = next.get('teams');
      let url: string | undefined;
      if (teams?.secretCiphertext && this.options.key) {
        try {
          url = decryptSecret(this.options.key, teams.secretCiphertext, this.aad('teams'));
        } catch {
          this.options.onError?.('CHANNEL_SECRET_UNREADABLE');
          url = this.databaseTeamsUrl;
        }
      }
      this.records = next;
      this.databaseTeamsUrl = url;
    } catch {
      this.options.onError?.('CHANNEL_STORE_UNAVAILABLE');
    }
  }

  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.refresh(), REFRESH_MS);
    this.timer.unref?.();
  }

  public stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  public enabled(channelId: ChannelId): boolean {
    return this.record(channelId).enabled;
  }

  public teamsUrl(): { readonly url: string; readonly source: 'database' | 'environment' } | undefined {
    if (this.databaseTeamsUrl) return { url: this.databaseTeamsUrl, source: 'database' };
    if (this.options.environmentTeamsUrl) {
      return { url: this.options.environmentTeamsUrl, source: 'environment' };
    }
    return undefined;
  }

  /** Registra el resultado de un envío real o de prueba (memoria + base, sin bloquear). */
  public async recordOutcome(channelId: ChannelId, evidence: DeliveryEvidence, test = false): Promise<void> {
    const current = this.record(channelId);
    const at = new Date(evidence.at);
    const accepted = evidence.outcome === 'accepted';
    const next: ChannelRecord = {
      ...current,
      ...(accepted ? { lastSuccessAt: at } : { lastFailureAt: at, lastFailureReason: evidence.reason }),
      lastHttpStatus: evidence.httpStatus,
      ...(test
        ? {
            lastTestAt: at,
            lastTestOutcome: evidence.outcome,
            lastTestHttpStatus: evidence.httpStatus,
            lastTestProviderId: evidence.providerMessageId,
          }
        : {}),
    };
    this.records.set(channelId, next);
    try {
      await this.options.store.save(next);
    } catch {
      this.options.onError?.('CHANNEL_HEALTH_NOT_SAVED');
    }
  }

  /** Transporte de Teams que siempre usa la URL vigente y respeta `enabled`. */
  public readonly teamsTransport: NotificationTransport = {
    destinationRef: 'teams:canal-soc',
    send: async (message: TeamsMessage, clientRequestId: string): Promise<DeliveryOutcome> => {
      if (!this.enabled('teams')) {
        return {
          delivered: false,
          failure: { class: 'permanent', code: 'CHANNEL_DISABLED', detail: 'El canal Teams está desactivado.' },
        };
      }
      const target = this.teamsUrl();
      if (!target) {
        return {
          delivered: false,
          failure: { class: 'permanent', code: 'CHANNEL_NOT_CONFIGURED', detail: 'Sin webhook de Teams.' },
        };
      }
      const outcome = await new TeamsWorkflowTransport({
        workflowUrl: target.url,
        destinationRef: 'teams:canal-soc',
        timeoutMs: RETRY_POLICY.requestTimeoutMs,
        ...(this.options.fetchImplementation ? { fetchImplementation: this.options.fetchImplementation } : {}),
      }).send(message, clientRequestId);
      await this.recordOutcome('teams', {
        channel: 'teams',
        outcome: outcome.delivered ? 'accepted' : 'failed',
        at: this.options.clock().toISOString(),
        httpStatus: outcome.httpStatus ?? null,
        providerMessageId: outcome.providerMessageId ?? null,
        providerLink: null,
        reason: outcome.delivered ? null : (outcome.failure?.code ?? 'UNKNOWN'),
      });
      return outcome;
    },
  };

  /** Envuelve el correo: respeta `enabled` y registra la salud. */
  public mail(inner: MailChannel): MailChannel {
    return {
      send: async (input) => {
        if (!this.enabled('email')) {
          return {
            channel: 'email',
            outcome: 'failed',
            at: this.options.clock().toISOString(),
            httpStatus: null,
            providerMessageId: null,
            providerLink: null,
            reason: 'CHANNEL_DISABLED',
          };
        }
        const evidence = await inner.send(input);
        await this.recordOutcome('email', evidence);
        return evidence;
      },
    };
  }

  /** El respaldo por correo también respeta `enabled` (si está apagado, va a la consola). */
  public fallback(mailFallback: FallbackChannel, consoleFallback: FallbackChannel): FallbackChannel {
    return {
      notify: async (notification: FallbackNotification) => {
        const channel = this.enabled('email') ? mailFallback : consoleFallback;
        const result: {
          readonly channel: NotificationChannel;
          readonly reference: string;
          readonly evidence?: readonly DeliveryEvidence[];
        } = await channel.notify(notification);
        for (const item of result.evidence ?? []) {
          if (item.channel === 'email') await this.recordOutcome('email', item);
        }
        return result;
      },
    };
  }

  public async setTeamsUrl(raw: unknown, actorId: string): Promise<
    | { readonly ok: true; readonly view: ChannelView; readonly previous: string | null }
    | { readonly ok: false; readonly code: string }
  > {
    const validation = validateTeamsWebhookUrl(raw);
    if (!validation.ok) return { ok: false, code: validation.code };
    if (!this.options.key) return { ok: false, code: 'ENCRYPTION_KEY_MISSING' };
    const previous = this.teamsUrl();
    const current = this.record('teams');
    const next: ChannelRecord = {
      ...current,
      secretCiphertext: encryptSecret(this.options.key, validation.url, this.aad('teams')),
      secretHint: maskWebhookUrl(validation.url),
      updatedAt: this.options.clock(),
      updatedBy: actorId,
      // Destino nuevo: la salud anterior era de otro webhook.
      lastSuccessAt: null,
      lastFailureAt: null,
      lastHttpStatus: null,
      lastFailureReason: null,
      lastTestAt: null,
      lastTestOutcome: null,
      lastTestHttpStatus: null,
      lastTestProviderId: null,
    };
    await this.options.store.save(next);
    this.records.set('teams', next);
    this.databaseTeamsUrl = validation.url;
    return {
      ok: true,
      view: this.view('teams'),
      previous: previous ? maskWebhookUrl(previous.url) : null,
    };
  }

  public async setEnabled(channelId: ChannelId, enabled: boolean, actorId: string): Promise<ChannelView> {
    const next: ChannelRecord = {
      ...this.record(channelId),
      enabled,
      updatedAt: this.options.clock(),
      updatedBy: actorId,
    };
    await this.options.store.save(next);
    this.records.set(channelId, next);
    return this.view(channelId);
  }

  public configured(channelId: ChannelId): boolean {
    if (channelId === 'teams') return this.teamsUrl() !== undefined;
    if (channelId === 'email') return this.options.emailConfigured;
    return this.options.pushConfigured;
  }

  public view(channelId: ChannelId): ChannelView {
    const record = this.record(channelId);
    const configured = this.configured(channelId);
    const teams = channelId === 'teams' ? this.teamsUrl() : undefined;
    const lastSuccess = record.lastSuccessAt?.getTime() ?? 0;
    const lastFailure = record.lastFailureAt?.getTime() ?? 0;
    const status: ChannelView['status'] = !configured
      ? 'not_configured'
      : !record.enabled
        ? 'disabled'
        : lastSuccess === 0 && lastFailure === 0
          ? 'unknown'
          : lastFailure > lastSuccess
            ? lastSuccess === 0
              ? 'failing'
              : 'degraded'
            : 'ok';
    return {
      id: channelId,
      label: LABELS[channelId],
      enabled: record.enabled,
      configured,
      source: teams ? teams.source : configured ? 'environment' : 'none',
      destination: teams ? maskWebhookUrl(teams.url) : null,
      status,
      health: {
        lastSuccessAt: record.lastSuccessAt?.toISOString() ?? null,
        lastFailureAt: record.lastFailureAt?.toISOString() ?? null,
        lastHttpStatus: record.lastHttpStatus,
        lastFailureReason: record.lastFailureReason,
      },
      lastTest: {
        at: record.lastTestAt?.toISOString() ?? null,
        outcome: record.lastTestOutcome,
        httpStatus: record.lastTestHttpStatus,
        providerMessageId: record.lastTestProviderId,
      },
      updatedAt: record.secretHint || record.updatedBy ? record.updatedAt.toISOString() : null,
      updatedBy: record.updatedBy,
      note:
        channelId === 'teams'
          ? 'HTTP 202 = Microsoft aceptó el mensaje; la publicación en el canal la hace el Workflow (revisa su historial de ejecuciones si no aparece).'
          : channelId === 'email' && !configured
            ? 'Requiere B89_ALERT_MAIL_SENDER y el permiso de aplicación Mail.Send con consentimiento.'
            : null,
    };
  }

  public views(): readonly ChannelView[] {
    return (['teams', 'email', 'push'] as const).map((id) => this.view(id));
  }
}
