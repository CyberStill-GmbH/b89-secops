/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Lista blanca de la API de pagos (Cloudflare): clientes, proveedores e infraestructura propia con
 * las IPs desde las que pueden llamar a `apipayments.b89.io`.
 *
 * Regla del dueño (2026-11-23): un cliente CON IPs que llama desde otra IP es alerta crítica (sobre
 * todo login, pagos, payins y payouts); un cliente SIN IPs («No requiere», «Pendiente») no alerta,
 * venga de donde venga. Para reconocer al cliente cuando la IP no es suya, cada entrada puede tener
 * «identificadores»: un texto que aparece en sus peticiones (p. ej. su código de comercio en la ruta).
 *
 * Contrato con la API: `GET/PUT /api/cloudflare/allowlist` (apps/api/src/soc/allowlist.controller.ts).
 */

export const ALLOWLIST_KINDS = ['client', 'provider', 'internal'] as const;
export type AllowlistKind = (typeof ALLOWLIST_KINDS)[number];

export const ALLOWLIST_STATUSES = ['with_ip', 'pending', 'not_contacted', 'not_required', 'to_validate'] as const;
export type AllowlistStatus = (typeof ALLOWLIST_STATUSES)[number];

export const KIND_LABEL: Readonly<Record<AllowlistKind, string>> = {
  client: 'Cliente',
  provider: 'Proveedor',
  internal: 'Infraestructura B89',
};

export const STATUS_LABEL: Readonly<Record<AllowlistStatus, string>> = {
  with_ip: 'Con IP',
  pending: 'Pendiente (contactado)',
  not_contacted: 'No contactado',
  not_required: 'No requiere',
  to_validate: 'Por validar',
};

/** Qué significa cada estado para las alertas, en una frase. */
export const STATUS_EFFECT: Readonly<Record<AllowlistStatus, string>> = {
  with_ip: 'Alerta crítica si llama desde una IP que no es suya.',
  pending: 'Sin alerta hasta que comparta sus IPs.',
  not_contacted: 'Sin alerta: falta pedirle sus IPs.',
  not_required: 'Sin alerta: no necesita lista blanca.',
  to_validate: 'Sin alerta hasta confirmar si aplica.',
};

export interface AllowlistEntry {
  readonly id: string;
  readonly name: string;
  readonly kind: AllowlistKind;
  readonly product: string | null;
  readonly country: string | null;
  readonly company: string | null;
  readonly status: AllowlistStatus;
  /** IPv4/IPv6 o CIDR. */
  readonly prodIps: readonly string[];
  readonly sandboxIps: readonly string[];
  /** Textos que aparecen en las peticiones de este cliente (ruta, consulta o host). */
  readonly markers: readonly string[];
  readonly note: string | null;
}

export interface AllowlistResponse {
  readonly revision: number;
  readonly updatedAt: string | null;
  readonly entries: readonly AllowlistEntry[];
  readonly canManage: boolean;
}

export const ALLOWLIST_LIMITS = Object.freeze({
  entries: 500,
  ipsPerEntry: 50,
  markersPerEntry: 10,
  name: 120,
  text: 300,
  markerMin: 3,
  markerMax: 64,
});

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;

/** IPv4, IPv6 o CIDR válido (normalizado en minúsculas), o null. */
export function normalizeIp(value: string): string | null {
  const text = value.trim().toLowerCase();
  const [address, prefix, extra] = text.split('/');
  if (extra !== undefined || !address) return null;
  const v4 = IPV4.test(address);
  const v6 = !v4 && IPV6.test(address) && address.includes(':') && (address.match(/::/gu) ?? []).length <= 1;
  if (!v4 && !v6) return null;
  if (prefix === undefined) return address;
  if (!/^\d{1,3}$/u.test(prefix)) return null;
  const bits = Number(prefix);
  if (bits > (v4 ? 32 : 128) || bits < (v4 ? 8 : 16)) return null;
  return `${address}/${bits}`;
}

/**
 * Lee IPs de un texto libre (celda de Excel, campo del formulario): separa por `;`, `,`, espacios o
 * saltos, ignora rótulos («DR:», «Telefónica A:») y devuelve aparte lo que no es una IP válida
 * («4421486220 (sin puntos, reconfirmar)»), para que nadie lo pierda.
 */
export function parseIpText(text: string): { ips: string[]; invalid: string[] } {
  const ips: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/[;,\s]+/u)) {
    const token = raw.replace(/^[([]+|[)\].]+$/gu, '').trim();
    if (!token || /^[a-záéíóúñ]+:?$/iu.test(token) || /^(puertos?|ips?|dr|sin|puntos|reconfirmar|y|-)$/iu.test(token)) continue;
    const ip = normalizeIp(token);
    if (ip) {
      if (!seen.has(ip)) {
        seen.add(ip);
        ips.push(ip);
      }
    } else if (/\d/u.test(token) && token.length >= 7) {
      invalid.push(token);
    }
  }
  return { ips, invalid };
}

/** Un identificador debe ser específico: sin espacios, de 3 a 64 caracteres. */
export function normalizeMarker(value: string): string | null {
  const text = value.trim().toLowerCase();
  if (text.length < ALLOWLIST_LIMITS.markerMin || text.length > ALLOWLIST_LIMITS.markerMax) return null;
  return /^[a-z0-9._~\-/]+$/u.test(text) ? text : null;
}

export interface AllowlistSummary {
  readonly total: number;
  readonly withIp: number;
  readonly withoutIp: number;
  readonly pending: number;
  readonly ips: number;
  /** Entradas «Con IP» que no tienen ninguna IP válida: no se pueden vigilar. */
  readonly withIpButEmpty: number;
}

export function summarizeAllowlist(entries: readonly AllowlistEntry[]): AllowlistSummary {
  let ips = 0;
  let withIp = 0;
  let withIpButEmpty = 0;
  let pending = 0;
  for (const entry of entries) {
    const count = entry.prodIps.length + entry.sandboxIps.length;
    ips += count;
    if (entry.status === 'with_ip') {
      withIp += 1;
      if (count === 0) withIpButEmpty += 1;
    }
    if (entry.status === 'pending' || entry.status === 'not_contacted' || entry.status === 'to_validate') pending += 1;
  }
  return { total: entries.length, withIp, withoutIp: entries.length - withIp, pending, ips, withIpButEmpty };
}

/** Quién está detrás de una IP, para buscar rápido «¿esta IP es de alguien?». */
export function ownersOfIp(entries: readonly AllowlistEntry[], ip: string): AllowlistEntry[] {
  const target = ip.trim().toLowerCase();
  return entries.filter((entry) => [...entry.prodIps, ...entry.sandboxIps].some((value) => value === target));
}
