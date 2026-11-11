/**
 * Canales de aviso administrables: Teams (webhook de Workflows), correo (Graph `Mail.Send`) y
 * consola/Web Push. Cada canal tiene `enabled`, `configured`, salud (último éxito y fallo,
 * último HTTP, motivo) y resultado de la última prueba.
 *
 * El webhook de Teams **es** un secreto (quien lo tiene publica en el canal): solo se acepta
 * HTTPS hacia hosts de Microsoft, se guarda cifrado y nunca se devuelve; la API muestra una
 * máscara (`https://prod-xx…/…abc123`).
 */

export const CHANNEL_IDS = ['teams', 'email', 'push'] as const;
export type ChannelId = (typeof CHANNEL_IDS)[number];

export interface ChannelHealth {
  readonly lastSuccessAt: Date | null;
  readonly lastFailureAt: Date | null;
  readonly lastHttpStatus: number | null;
  readonly lastFailureReason: string | null;
  readonly lastTestAt: Date | null;
  readonly lastTestOutcome: 'accepted' | 'failed' | null;
  readonly lastTestHttpStatus: number | null;
  readonly lastTestProviderId: string | null;
}

/** Fila persistida de un canal. `secretCiphertext` nunca sale del runtime. */
export interface ChannelRecord extends ChannelHealth {
  readonly tenantId: string;
  readonly channelId: ChannelId;
  readonly enabled: boolean;
  readonly secretCiphertext: string | null;
  readonly secretHint: string | null;
  readonly updatedAt: Date;
  readonly updatedBy: string | null;
}

export interface ChannelStore {
  list(tenantId: string): Promise<readonly ChannelRecord[]>;
  get(tenantId: string, channelId: ChannelId): Promise<ChannelRecord | undefined>;
  save(record: ChannelRecord): Promise<void>;
}

export const EMPTY_HEALTH: ChannelHealth = Object.freeze({
  lastSuccessAt: null,
  lastFailureAt: null,
  lastHttpStatus: null,
  lastFailureReason: null,
  lastTestAt: null,
  lastTestOutcome: null,
  lastTestHttpStatus: null,
  lastTestProviderId: null,
});

export function emptyChannel(tenantId: string, channelId: ChannelId, at: Date): ChannelRecord {
  return {
    tenantId,
    channelId,
    enabled: true,
    secretCiphertext: null,
    secretHint: null,
    updatedAt: at,
    updatedBy: null,
    ...EMPTY_HEALTH,
  };
}

/**
 * Hosts de Microsoft que emiten URL de webhooks de Teams:
 * - Workflows de Power Automate (formato vigente):
 *   `https://<id>.<nn>.environment.api.powerplatform.com/powerautomate/automations/direct/…`
 *   y el formato previo `https://prod-NN.<región>.logic.azure.com/workflows/…/triggers/manual/paths/invoke?…`.
 * - Conectores heredados de Office 365 (`*.webhook.office.com/webhookb2/…`): Microsoft los
 *   retiró; se aceptan solo para migrar, la tarjeta adaptativa no siempre se publica.
 */
const ALLOWED_HOST_SUFFIXES = [
  '.environment.api.powerplatform.com',
  '.api.powerplatform.com',
  '.logic.azure.com',
  '.webhook.office.com',
] as const;

export const WEBHOOK_URL_MAXIMUM = 2_048;

export type WebhookValidation =
  | { readonly ok: true; readonly url: string; readonly kind: 'workflows' | 'logic_apps' | 'legacy_connector' }
  | { readonly ok: false; readonly code: string };

export function validateTeamsWebhookUrl(value: unknown): WebhookValidation {
  if (typeof value !== 'string' || value.length === 0) return { ok: false, code: 'URL_REQUIRED' };
  if (value.length > WEBHOOK_URL_MAXIMUM) return { ok: false, code: 'URL_TOO_LONG' };
  if (/[\s\u0000-\u001f\u007f]/u.test(value)) return { ok: false, code: 'URL_INVALID' };
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, code: 'URL_INVALID' };
  }
  if (url.protocol !== 'https:') return { ok: false, code: 'URL_NOT_HTTPS' };
  if (url.username || url.password) return { ok: false, code: 'URL_INVALID' };
  if (url.port && url.port !== '443') return { ok: false, code: 'URL_PORT_NOT_ALLOWED' };
  const host = url.hostname.toLowerCase();
  if (!ALLOWED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix) && host.length > suffix.length)) {
    return { ok: false, code: 'URL_HOST_NOT_ALLOWED' };
  }
  if (url.hash) return { ok: false, code: 'URL_INVALID' };
  if (host.endsWith('.webhook.office.com')) {
    if (!url.pathname.startsWith('/webhookb2/')) return { ok: false, code: 'URL_PATH_NOT_ALLOWED' };
    return { ok: true, url: url.toString(), kind: 'legacy_connector' };
  }
  if (host.endsWith('.logic.azure.com')) {
    if (!/^\/workflows\/[A-Za-z0-9]+\/triggers\/[^/]+\/paths\/invoke$/u.test(url.pathname)) {
      return { ok: false, code: 'URL_PATH_NOT_ALLOWED' };
    }
    if (!url.searchParams.get('sig')) return { ok: false, code: 'URL_SIGNATURE_MISSING' };
    return { ok: true, url: url.toString(), kind: 'logic_apps' };
  }
  if (!/^\/powerautomate\/automations\/direct\/.*\/workflows\/[A-Za-z0-9]+\/triggers\/[^/]+\/paths\/invoke$/u.test(url.pathname)) {
    return { ok: false, code: 'URL_PATH_NOT_ALLOWED' };
  }
  if (!url.searchParams.get('sig')) return { ok: false, code: 'URL_SIGNATURE_MISSING' };
  return { ok: true, url: url.toString(), kind: 'workflows' };
}

/** `https://<primeros 7 del host>…/…<últimos 6 de la firma>`; nunca la URL utilizable. */
export function maskWebhookUrl(value: string): string {
  try {
    const url = new URL(value);
    const signature = url.searchParams.get('sig') ?? url.pathname;
    const tail = signature.replace(/[^A-Za-z0-9]/gu, '').slice(-6);
    return `https://${url.hostname.slice(0, 7)}…/…${tail}`;
  } catch {
    return '(inválida)';
  }
}

export class InMemoryChannelStore implements ChannelStore {
  public readonly rows = new Map<string, ChannelRecord>();

  public list(tenantId: string): Promise<readonly ChannelRecord[]> {
    return Promise.resolve([...this.rows.values()].filter((row) => row.tenantId === tenantId));
  }

  public get(tenantId: string, channelId: ChannelId): Promise<ChannelRecord | undefined> {
    return Promise.resolve(this.rows.get(`${tenantId}|${channelId}`));
  }

  public save(record: ChannelRecord): Promise<void> {
    this.rows.set(`${record.tenantId}|${record.channelId}`, record);
    return Promise.resolve();
  }
}
