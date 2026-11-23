/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { AllowlistEntry } from '../../common/allowlist';
import {
  allowlistAnswer,
  checkForm,
  DEFAULT_FILTER,
  describeChange,
  diffAllowlist,
  EMPTY_FORM,
  entryFromForm,
  entryId,
  filterCounts,
  filterEntries,
  formFromEntry,
  formIsValid,
  ipCovers,
  lookupIp,
  noteWithInvalid,
  parseMarkers,
  removeEntry,
  reviewReason,
  upsertEntry,
  validationMessage,
} from './allowlist_model';

function entry(partial: Partial<AllowlistEntry> & { id: string }): AllowlistEntry {
  return {
    name: partial.id,
    kind: 'client',
    product: null,
    country: null,
    company: null,
    status: 'not_required',
    prodIps: [],
    sandboxIps: [],
    markers: [],
    note: null,
    ...partial,
  };
}

const THUNES = entry({ id: 'thunes', name: 'Thunes', status: 'with_ip', country: 'Perú', prodIps: ['34.199.50.40', '10.0.0.0/8'], sandboxIps: ['3.126.133.76'] });
const BPC = entry({ id: 'bpc', name: 'BPC 1', status: 'with_ip', prodIps: ['34.199.50.40'], note: 'IPs por reconfirmar (no se vigilan): 4421486220' });
const EMPTY = entry({ id: 'vacio', name: 'Vacío', status: 'with_ip' });
const ORGANIC = entry({ id: 'organic', name: 'Organic & Fit' });
const GMONEY = entry({ id: 'gmoney', name: 'GMoney', kind: 'provider', status: 'pending', country: 'Chile' });
const ALL = [THUNES, BPC, EMPTY, ORGANIC, GMONEY];

describe('lista blanca · respuesta primero', () => {
  it('cuenta vigiladas, sin IP y pendientes', () => {
    const answer = allowlistAnswer(ALL);
    expect(answer.headline).toBe('3 entradas vigiladas con 4 IPs · 2 sin IP (no alertan) · 1 pendiente');
    expect(answer.warning).toBe('2 entradas no se pueden vigilar bien: 1 «Con IP» sin IPs válidas · 1 con IPs por reconfirmar');
    expect(answer.reviewCount).toBe(2);
  });

  it('sin avisos cuando todo se puede vigilar', () => {
    expect(allowlistAnswer([THUNES, ORGANIC]).warning).toBeNull();
    expect(allowlistAnswer([THUNES, ORGANIC]).headline).toBe('1 entrada vigilada con 3 IPs · 1 sin IP (no alerta)');
  });

  it('explica por qué una entrada no se puede vigilar', () => {
    expect(reviewReason(EMPTY)).toContain('no tiene IPs válidas');
    expect(reviewReason(BPC)).toContain('por reconfirmar');
    expect(reviewReason(THUNES)).toBeNull();
  });
});

describe('lista blanca · filtros', () => {
  it('filtra por tipo, estado y texto sin tildes', () => {
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, kind: 'provider' }).map((e) => e.id)).toEqual(['gmoney']);
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, status: 'without_ip' }).map((e) => e.id)).toEqual(['organic', 'gmoney']);
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, status: 'pending' }).map((e) => e.id)).toEqual(['gmoney']);
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, status: 'review' }).map((e) => e.id)).toEqual(['bpc', 'vacio']);
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, query: 'peru' }).map((e) => e.id)).toEqual(['thunes']);
    expect(filterEntries(ALL, { ...DEFAULT_FILTER, query: '3.126' }).map((e) => e.id)).toEqual(['thunes']);
  });

  it('ordena clientes «Con IP» primero', () => {
    expect(filterEntries(ALL, DEFAULT_FILTER).map((e) => e.id)).toEqual(['bpc', 'thunes', 'vacio', 'organic', 'gmoney']);
  });

  it('cuenta por tipo y por estado', () => {
    const counts = filterCounts(ALL, DEFAULT_FILTER);
    expect(counts.kind).toEqual({ all: 5, client: 4, provider: 1, internal: 0 });
    expect(counts.status).toEqual({ all: 5, with_ip: 3, without_ip: 2, pending: 1, review: 2 });
  });
});

describe('lista blanca · ¿esta IP es de alguien?', () => {
  it('encuentra a todos los dueños, también por rango', () => {
    const found = lookupIp(ALL, ' 34.199.50.40 ');
    expect(found.state).toBe('found');
    if (found.state === 'found') expect(found.owners.map((o) => o.entry.id)).toEqual(['thunes', 'bpc']);
    const range = lookupIp(ALL, '10.2.3.4');
    expect(range.state === 'found' && range.owners[0].listed).toBe('10.0.0.0/8');
  });

  it('distingue IP sin dueño de texto inválido', () => {
    expect(lookupIp(ALL, '8.8.8.8')).toEqual({ state: 'none', ip: '8.8.8.8' });
    expect(lookupIp(ALL, '4421486220').state).toBe('invalid');
    expect(lookupIp(ALL, '  ').state).toBe('empty');
  });

  it('CIDR solo cubre su rango', () => {
    expect(ipCovers('192.168.1.0/24', '192.168.1.200')).toBe(true);
    expect(ipCovers('192.168.1.0/24', '192.168.2.1')).toBe(false);
    expect(ipCovers('2001:db8::/32', '2001:db8::1')).toBe(false);
  });
});

describe('lista blanca · formulario', () => {
  it('lee IPs pegadas de Excel y no pierde lo que no es IP', () => {
    const check = checkForm({ ...EMPTY_FORM, name: 'Terrapay', prodText: 'DR: 1.2.3.4; 5.6.7.8\n4421486220 (sin puntos, reconfirmar)', note: 'Contacto: Ana' });
    expect(check.prod.ips).toEqual(['1.2.3.4', '5.6.7.8']);
    expect(check.prod.invalid).toEqual(['4421486220']);
    expect(check.note).toBe('Contacto: Ana · IPs por reconfirmar (no se vigilan): 4421486220');
    expect(formIsValid(check)).toBe(true);
  });

  it('no repite en la nota lo ya anotado', () => {
    expect(noteWithInvalid('IPs por reconfirmar (no se vigilan): 4421486220', ['4421486220'])).toBe('IPs por reconfirmar (no se vigilan): 4421486220');
  });

  it('exige nombre y valida identificadores', () => {
    const check = checkForm({ ...EMPTY_FORM, markersText: 'MERCH-001, a b, x' });
    expect(check.errors.name).toBe('Escribe el nombre.');
    expect(check.errors.markersText).toContain('a b, x');
    expect(parseMarkers('MERCH-001\nmerch-001, /pay/b89').markers).toEqual(['merch-001', '/pay/b89']);
  });

  it('avisa si está «Con IP» sin IPs', () => {
    expect(checkForm({ ...EMPTY_FORM, name: 'X' }).warnings[0]).toContain('no se podrá vigilar');
  });

  it('ida y vuelta entre entrada y formulario', () => {
    expect(entryFromForm(formFromEntry(THUNES), 'thunes')).toEqual(THUNES);
  });

  it('crea ids únicos y cortos', () => {
    expect(entryId({ name: 'Organic & Fit', product: 'Payouts', country: 'Perú' }, new Set())).toBe('organic-fit-payouts-peru');
    expect(entryId({ name: 'Organic & Fit', product: 'Payouts', country: 'Perú' }, new Set(['organic-fit-payouts-peru']))).toBe('organic-fit-payouts-peru-2');
    expect(entryId({ name: '¡¡!!', product: '', country: '' }, new Set())).toBe('entrada');
    const long = entryId({ name: 'a'.repeat(80), product: '', country: '' }, new Set(['a'.repeat(64)]));
    expect(long).toBe(`${'a'.repeat(62)}-2`);
    expect(long).toMatch(/^[a-z0-9][a-z0-9-]{0,63}$/u);
  });
});

describe('lista blanca · borrador y cambios', () => {
  it('describe qué cambia en palabras', () => {
    const terrapay = entry({ id: 'terrapay', name: 'Terrapay' });
    let draft = upsertEntry(ALL, terrapay);
    draft = upsertEntry(draft, { ...THUNES, prodIps: ['1.1.1.1'], status: 'pending' });
    draft = removeEntry(draft, 'gmoney');
    const lines = diffAllowlist(ALL, draft).map(describeChange);
    expect(lines).toEqual(['Cambia estado y IPs de Thunes', 'Agrega Terrapay', 'Quita GMoney']);
    expect(diffAllowlist(ALL, [...ALL])).toEqual([]);
  });

  it('traduce el error de validación a la entrada y el campo', () => {
    expect(validationMessage(['entries[0].prodIps'], ALL)).toBe('Revisa las IPs de producción de «Thunes».');
    expect(validationMessage(['entries[9].markers'], ALL)).toBe('Revisa los identificadores de la entrada 10.');
    expect(validationMessage(['entries'], ALL)).toContain('demasiadas entradas');
  });
});
