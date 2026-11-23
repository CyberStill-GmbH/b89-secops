/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Lógica pura de la pestaña «Lista blanca» (Tráfico de Cloudflare): resumen, filtros, búsqueda de
 * una IP, formulario de una entrada, borrador local y diferencia contra lo guardado. Sin React.
 */

import {
  ALLOWLIST_LIMITS,
  KIND_LABEL,
  normalizeIp,
  normalizeMarker,
  parseIpText,
  summarizeAllowlist,
} from '../../common/allowlist';
import type { AllowlistEntry, AllowlistKind, AllowlistStatus } from '../../common/allowlist';

// ------------------------------------------------------------------ texto

/** Minúsculas y sin tildes, para buscar «peru» y encontrar «Perú». */
export function fold(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[̀-ͯ]/gu, '')
    .toLowerCase();
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words.join('');
  return `${words.slice(0, -1).join(', ')} y ${words[words.length - 1]}`;
}

// ------------------------------------------------------------------ resumen

/** Estados que todavía esperan algo (IPs, contacto o validación). */
export function isPendingStatus(status: AllowlistStatus): boolean {
  return status === 'pending' || status === 'not_contacted' || status === 'to_validate';
}

/** Nota que pide reconfirmar IPs: esas IPs no se vigilan. */
export function mentionsReconfirm(note: string | null): boolean {
  return note !== null && fold(note).includes('reconfirmar');
}

/** «Con IP» pero no se puede vigilar bien: sin IPs válidas o con IPs por reconfirmar. */
export function reviewReason(entry: AllowlistEntry): string | null {
  if (entry.status === 'with_ip' && entry.prodIps.length + entry.sandboxIps.length === 0) {
    return 'Está «Con IP» pero no tiene IPs válidas: no se puede vigilar.';
  }
  if (mentionsReconfirm(entry.note)) return 'Tiene IPs por reconfirmar: esas IPs no se vigilan.';
  return null;
}

export interface AllowlistAnswer {
  /** «19 entradas vigiladas con 31 IPs · 30 sin IP (no alertan) · 1 pendiente». */
  readonly headline: string;
  /** Aviso cuando hay entradas que no se pueden vigilar bien; null si todo está en orden. */
  readonly warning: string | null;
  readonly reviewCount: number;
}

export function allowlistAnswer(entries: readonly AllowlistEntry[]): AllowlistAnswer {
  const summary = summarizeAllowlist(entries);
  const watchedIps = entries
    .filter((entry) => entry.status === 'with_ip')
    .reduce((total, entry) => total + entry.prodIps.length + entry.sandboxIps.length, 0);
  const parts = [
    `${plural(summary.withIp, 'entrada vigilada', 'entradas vigiladas')} con ${plural(watchedIps, 'IP', 'IPs')}`,
    `${summary.withoutIp} sin IP (no ${summary.withoutIp === 1 ? 'alerta' : 'alertan'})`,
  ];
  if (summary.pending > 0) parts.push(plural(summary.pending, 'pendiente', 'pendientes'));
  const empty = entries.filter((entry) => entry.status === 'with_ip' && entry.prodIps.length + entry.sandboxIps.length === 0).length;
  const reconfirm = entries.filter((entry) => mentionsReconfirm(entry.note) && !(entry.status === 'with_ip' && entry.prodIps.length + entry.sandboxIps.length === 0)).length;
  const reviewCount = empty + reconfirm;
  const reasons: string[] = [];
  if (empty > 0) reasons.push(`${empty} «Con IP» sin IPs válidas`);
  if (reconfirm > 0) reasons.push(`${reconfirm} con IPs por reconfirmar`);
  const warning =
    reviewCount > 0
      ? `${plural(reviewCount, 'entrada no se puede vigilar bien', 'entradas no se pueden vigilar bien')}: ${reasons.join(' · ')}`
      : null;
  return { headline: parts.join(' · '), warning, reviewCount };
}

// ------------------------------------------------------------------ filtros

export const STATUS_FILTERS = ['all', 'with_ip', 'without_ip', 'pending', 'review'] as const;
export type StatusFilter = (typeof STATUS_FILTERS)[number];

export const STATUS_FILTER_LABEL: Readonly<Record<StatusFilter, string>> = {
  all: 'Todas',
  with_ip: 'Con IP',
  without_ip: 'Sin IP',
  pending: 'Pendientes',
  review: 'Por revisar',
};

export const KIND_FILTERS = ['all', 'client', 'provider', 'internal'] as const;
export type KindFilter = (typeof KIND_FILTERS)[number];

export const KIND_FILTER_LABEL: Readonly<Record<KindFilter, string>> = {
  all: 'Todos',
  client: 'Clientes',
  provider: 'Proveedores',
  internal: 'Infraestructura',
};

export interface AllowlistFilter {
  readonly kind: KindFilter;
  readonly status: StatusFilter;
  readonly query: string;
}

export const DEFAULT_FILTER: AllowlistFilter = { kind: 'all', status: 'all', query: '' };

export function matchesStatus(entry: AllowlistEntry, status: StatusFilter): boolean {
  switch (status) {
    case 'all':
      return true;
    case 'with_ip':
      return entry.status === 'with_ip';
    case 'without_ip':
      return entry.status !== 'with_ip';
    case 'pending':
      return isPendingStatus(entry.status);
    case 'review':
      return reviewReason(entry) !== null;
  }
}

function matchesQuery(entry: AllowlistEntry, query: string): boolean {
  const needle = fold(query.trim());
  if (!needle) return true;
  const haystack = [
    entry.name,
    entry.product ?? '',
    entry.country ?? '',
    entry.company ?? '',
    ...entry.prodIps,
    ...entry.sandboxIps,
    ...entry.markers,
  ];
  return haystack.some((value) => fold(value).includes(needle));
}

const KIND_ORDER: Readonly<Record<AllowlistKind, number>> = { client: 0, provider: 1, internal: 2 };

/** Filtra y ordena: tipo, después «Con IP» primero y por nombre. */
export function filterEntries(entries: readonly AllowlistEntry[], filter: AllowlistFilter): AllowlistEntry[] {
  return entries
    .filter((entry) => filter.kind === 'all' || entry.kind === filter.kind)
    .filter((entry) => matchesStatus(entry, filter.status))
    .filter((entry) => matchesQuery(entry, filter.query))
    .sort(
      (a, b) =>
        KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
        Number(b.status === 'with_ip') - Number(a.status === 'with_ip') ||
        a.name.localeCompare(b.name, 'es'),
    );
}

/** Cuántas entradas hay por tipo y por estado (para los contadores de los filtros). */
export function filterCounts(entries: readonly AllowlistEntry[], filter: AllowlistFilter) {
  const kind = {} as Record<KindFilter, number>;
  for (const id of KIND_FILTERS) {
    kind[id] = entries.filter((entry) => (id === 'all' || entry.kind === id) && matchesStatus(entry, filter.status)).length;
  }
  const status = {} as Record<StatusFilter, number>;
  for (const id of STATUS_FILTERS) {
    status[id] = entries.filter((entry) => (filter.kind === 'all' || entry.kind === filter.kind) && matchesStatus(entry, id)).length;
  }
  return { kind, status };
}

// ------------------------------------------------------------------ «¿Esta IP es de alguien?»

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) value = value * 256 + Number(part);
  return value;
}

/** ¿`ip` es `listed` o cae dentro de su rango CIDR (solo IPv4)? */
export function ipCovers(listed: string, ip: string): boolean {
  if (listed === ip) return true;
  const [network, prefix] = listed.split('/');
  if (prefix === undefined || ip.includes('/')) return false;
  const base = ipv4ToNumber(network);
  const target = ipv4ToNumber(ip);
  if (base === null || target === null) return false;
  const size = 2 ** (32 - Number(prefix));
  return Math.floor(base / size) === Math.floor(target / size);
}

export interface IpOwner {
  readonly entry: AllowlistEntry;
  readonly environment: 'producción' | 'sandbox';
  /** La IP o el rango de la lista que coincide. */
  readonly listed: string;
}

export type IpLookup =
  | { readonly state: 'empty' }
  | { readonly state: 'invalid'; readonly text: string }
  | { readonly state: 'none'; readonly ip: string }
  | { readonly state: 'found'; readonly ip: string; readonly owners: readonly IpOwner[] };

export function lookupIp(entries: readonly AllowlistEntry[], text: string): IpLookup {
  const trimmed = text.trim();
  if (!trimmed) return { state: 'empty' };
  const ip = normalizeIp(trimmed);
  if (!ip) return { state: 'invalid', text: trimmed };
  const owners: IpOwner[] = [];
  for (const entry of entries) {
    const prod = entry.prodIps.find((listed) => ipCovers(listed, ip));
    if (prod) owners.push({ entry, environment: 'producción', listed: prod });
    const sandbox = entry.sandboxIps.find((listed) => ipCovers(listed, ip));
    if (sandbox) owners.push({ entry, environment: 'sandbox', listed: sandbox });
  }
  return owners.length > 0 ? { state: 'found', ip, owners } : { state: 'none', ip };
}

// ------------------------------------------------------------------ formulario

export interface EntryForm {
  readonly name: string;
  readonly kind: AllowlistKind;
  readonly product: string;
  readonly country: string;
  readonly company: string;
  readonly status: AllowlistStatus;
  readonly prodText: string;
  readonly sandboxText: string;
  readonly markersText: string;
  readonly note: string;
}

export const EMPTY_FORM: EntryForm = {
  name: '',
  kind: 'client',
  product: '',
  country: '',
  company: '',
  status: 'with_ip',
  prodText: '',
  sandboxText: '',
  markersText: '',
  note: '',
};

export function formFromEntry(entry: AllowlistEntry): EntryForm {
  return {
    name: entry.name,
    kind: entry.kind,
    product: entry.product ?? '',
    country: entry.country ?? '',
    company: entry.company ?? '',
    status: entry.status,
    prodText: entry.prodIps.join('\n'),
    sandboxText: entry.sandboxIps.join('\n'),
    markersText: entry.markers.join(', '),
    note: entry.note ?? '',
  };
}

export function parseMarkers(text: string): { markers: string[]; invalid: string[] } {
  const markers: string[] = [];
  const invalid: string[] = [];
  for (const raw of text.split(/[,;\n\r]+/u)) {
    const token = raw.trim();
    if (!token) continue;
    const marker = normalizeMarker(token);
    if (!marker) invalid.push(token);
    else if (!markers.includes(marker)) markers.push(marker);
  }
  return { markers, invalid };
}

export type FormField = 'name' | 'product' | 'country' | 'company' | 'prodText' | 'sandboxText' | 'markersText' | 'note';

export interface FormCheck {
  readonly prod: { ips: string[]; invalid: string[] };
  readonly sandbox: { ips: string[]; invalid: string[] };
  readonly markers: { markers: string[]; invalid: string[] };
  /** Errores que impiden aplicar el formulario. */
  readonly errors: Readonly<Partial<Record<FormField, string>>>;
  /** Avisos que no bloquean. */
  readonly warnings: readonly string[];
  /** La nota que se guardará (con las IPs no válidas anotadas para no perderlas). */
  readonly note: string;
}

const RECONFIRM_PREFIX = 'IPs por reconfirmar (no se vigilan):';

/** Agrega a la nota los textos que no son IP para que nadie los pierda (sin repetir los ya anotados). */
export function noteWithInvalid(note: string, invalid: readonly string[]): string {
  const missing = invalid.filter((token) => !note.includes(token));
  if (missing.length === 0) return note.trim();
  return [note.trim(), `${RECONFIRM_PREFIX} ${missing.join(', ')}`].filter(Boolean).join(' · ');
}

export function checkForm(form: EntryForm): FormCheck {
  const prod = parseIpText(form.prodText);
  const sandbox = parseIpText(form.sandboxText);
  const markers = parseMarkers(form.markersText);
  const note = noteWithInvalid(form.note, [...prod.invalid, ...sandbox.invalid]);
  const errors: Partial<Record<FormField, string>> = {};
  if (!form.name.trim()) errors.name = 'Escribe el nombre.';
  else if (form.name.trim().length > ALLOWLIST_LIMITS.name) errors.name = `Máximo ${ALLOWLIST_LIMITS.name} caracteres.`;
  for (const field of ['product', 'country', 'company'] as const) {
    if (form[field].trim().length > ALLOWLIST_LIMITS.name) errors[field] = `Máximo ${ALLOWLIST_LIMITS.name} caracteres.`;
  }
  if (prod.ips.length > ALLOWLIST_LIMITS.ipsPerEntry) errors.prodText = `Máximo ${ALLOWLIST_LIMITS.ipsPerEntry} IPs.`;
  if (sandbox.ips.length > ALLOWLIST_LIMITS.ipsPerEntry) errors.sandboxText = `Máximo ${ALLOWLIST_LIMITS.ipsPerEntry} IPs.`;
  if (markers.invalid.length > 0) {
    errors.markersText = `No válidos: ${markers.invalid.join(', ')}. Usa de ${ALLOWLIST_LIMITS.markerMin} a ${ALLOWLIST_LIMITS.markerMax} caracteres sin espacios (letras, números, . _ ~ - /).`;
  } else if (markers.markers.length > ALLOWLIST_LIMITS.markersPerEntry) {
    errors.markersText = `Máximo ${ALLOWLIST_LIMITS.markersPerEntry} identificadores.`;
  }
  if (note.length > ALLOWLIST_LIMITS.text) errors.note = `La nota no puede pasar de ${ALLOWLIST_LIMITS.text} caracteres.`;
  const warnings: string[] = [];
  if (form.status === 'with_ip' && prod.ips.length + sandbox.ips.length === 0) {
    warnings.push('Está «Con IP» pero sin IPs válidas: no se podrá vigilar.');
  }
  if (form.status !== 'with_ip' && prod.ips.length + sandbox.ips.length > 0) {
    warnings.push('Tiene IPs pero no está «Con IP»: no alertará hasta que cambies el estado.');
  }
  return { prod, sandbox, markers, errors, warnings, note };
}

export function formIsValid(check: FormCheck): boolean {
  return Object.keys(check.errors).length === 0;
}

function orNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function entryFromForm(form: EntryForm, id: string): AllowlistEntry {
  const check = checkForm(form);
  return {
    id,
    name: form.name.trim(),
    kind: form.kind,
    product: orNull(form.product),
    country: orNull(form.country),
    company: orNull(form.company),
    status: form.status,
    prodIps: check.prod.ips,
    sandboxIps: check.sandbox.ips,
    markers: check.markers.markers,
    note: orNull(check.note),
  };
}

const ID_MAX = 64;

/** Id estable: slug de nombre + producto + país, único (a-z0-9-, máx. 64). */
export function entryId(form: Pick<EntryForm, 'name' | 'product' | 'country'>, taken: ReadonlySet<string>): string {
  const base =
    fold([form.name, form.product, form.country].join(' '))
      .replace(/[^a-z0-9]+/gu, '-')
      .replace(/^-+|-+$/gu, '')
      .slice(0, ID_MAX)
      .replace(/-+$/u, '') || 'entrada';
  if (!taken.has(base)) return base;
  for (let n = 2; ; n += 1) {
    const suffix = `-${n}`;
    const candidate = `${base.slice(0, ID_MAX - suffix.length).replace(/-+$/u, '')}${suffix}`;
    if (!taken.has(candidate)) return candidate;
  }
}

// ------------------------------------------------------------------ borrador y diferencias

export function upsertEntry(entries: readonly AllowlistEntry[], entry: AllowlistEntry): AllowlistEntry[] {
  const index = entries.findIndex((item) => item.id === entry.id);
  if (index < 0) return [...entries, entry];
  return entries.map((item, at) => (at === index ? entry : item));
}

export function removeEntry(entries: readonly AllowlistEntry[], id: string): AllowlistEntry[] {
  return entries.filter((entry) => entry.id !== id);
}

export interface AllowlistChange {
  readonly type: 'add' | 'change' | 'remove';
  readonly id: string;
  readonly name: string;
  /** Solo en `change`: qué cambió, en palabras. */
  readonly what: readonly string[];
}

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((value, index) => value === b[index]);

const CHANGE_WORDS: readonly [string, (a: AllowlistEntry, b: AllowlistEntry) => boolean][] = [
  ['nombre', (a, b) => a.name === b.name],
  ['tipo', (a, b) => a.kind === b.kind],
  ['producto', (a, b) => a.product === b.product],
  ['país', (a, b) => a.country === b.country],
  ['empresa', (a, b) => a.company === b.company],
  ['estado', (a, b) => a.status === b.status],
  ['IPs', (a, b) => sameList(a.prodIps, b.prodIps) && sameList(a.sandboxIps, b.sandboxIps)],
  ['identificadores', (a, b) => sameList(a.markers, b.markers)],
  ['nota', (a, b) => a.note === b.note],
];

export function diffAllowlist(saved: readonly AllowlistEntry[], draft: readonly AllowlistEntry[]): AllowlistChange[] {
  const before = new Map(saved.map((entry) => [entry.id, entry]));
  const after = new Map(draft.map((entry) => [entry.id, entry]));
  const changes: AllowlistChange[] = [];
  for (const entry of draft) {
    const previous = before.get(entry.id);
    if (!previous) {
      changes.push({ type: 'add', id: entry.id, name: entry.name, what: [] });
      continue;
    }
    const what = CHANGE_WORDS.filter(([, same]) => !same(previous, entry)).map(([word]) => word);
    if (what.length > 0) changes.push({ type: 'change', id: entry.id, name: entry.name, what });
  }
  for (const entry of saved) {
    if (!after.has(entry.id)) changes.push({ type: 'remove', id: entry.id, name: entry.name, what: [] });
  }
  return changes;
}

/** «Agrega Terrapay», «Cambia IPs de Thunes», «Quita GMoney». */
export function describeChange(change: AllowlistChange): string {
  switch (change.type) {
    case 'add':
      return `Agrega ${change.name}`;
    case 'remove':
      return `Quita ${change.name}`;
    case 'change':
      return `Cambia ${joinWords(change.what)} de ${change.name}`;
  }
}

// ------------------------------------------------------------------ errores del guardado

const FIELD_WORDS: Readonly<Record<string, string>> = {
  id: 'el identificador interno',
  name: 'el nombre',
  kind: 'el tipo',
  product: 'el producto',
  country: 'el país',
  company: 'la empresa',
  status: 'el estado',
  prodIps: 'las IPs de producción',
  sandboxIps: 'las IPs de sandbox',
  markers: 'los identificadores',
  note: 'la nota',
};

/** `entries[3].prodIps` → «Revisa las IPs de producción de «Thunes».» */
export function validationMessage(fields: readonly string[], entries: readonly AllowlistEntry[]): string {
  const lines = fields.map((field) => {
    const match = /^entries\[(\d+)\](?:\.(\w+))?$/u.exec(field);
    if (!match) {
      return field === 'entries'
        ? `La lista tiene demasiadas entradas (máximo ${ALLOWLIST_LIMITS.entries}).`
        : 'La lista no se pudo validar. Recarga la página e inténtalo de nuevo.';
    }
    const entry = entries[Number(match[1])];
    const who = entry ? `«${entry.name}»` : `la entrada ${Number(match[1]) + 1}`;
    const what = match[2] ? FIELD_WORDS[match[2]] ?? 'los datos' : 'los datos';
    return `Revisa ${what} de ${who}.`;
  });
  return lines.length > 0 ? lines.join(' ') : 'Hay datos que no son válidos. Revisa las entradas editadas.';
}

export function kindLabel(kind: AllowlistKind): string {
  return KIND_LABEL[kind];
}
