/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { AllowlistEntry } from '../../common/allowlist';
import { checkForm, diffAllowlist, EMPTY_FORM, lookupIp, removeEntry, upsertEntry } from './allowlist_model';
import {
  AllowlistAnswerLine,
  AllowlistFilters,
  AllowlistNoAccess,
  AllowlistSaveBar,
  AllowlistTable,
  EntryFormFields,
  IpLookupResult,
} from './cloudflare_allowlist_view';
import { activeTab, DEFAULT_STATE, parseViewState, TRAFFIC_TAB_LABEL, viewStateSearch } from './cloudflare_traffic_model';
import { DEFAULT_FILTER } from './allowlist_model';

const noop = () => undefined;

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

const THUNES = entry({
  id: 'thunes',
  name: 'Thunes',
  product: 'Payouts',
  country: 'Perú',
  status: 'with_ip',
  prodIps: ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'],
  sandboxIps: ['6.6.6.6'],
  markers: ['merch-001'],
});
const BPC = entry({ id: 'bpc', name: 'BPC 1', status: 'with_ip', prodIps: ['34.199.50.40'], note: 'IPs por reconfirmar (no se vigilan): 4421486220' });
const GMONEY = entry({ id: 'gmoney', name: 'GMoney', kind: 'provider', status: 'pending' });
const ALL = [THUNES, BPC, GMONEY];

describe('Lista blanca · pestaña y enlace', () => {
  it('tiene su pestaña y enlace directo', () => {
    expect(TRAFFIC_TAB_LABEL['lista-blanca']).toBe('Lista blanca');
    expect(activeTab(parseViewState('?tab=lista-blanca'))).toBe('lista-blanca');
    expect(viewStateSearch({ ...DEFAULT_STATE, tab: 'lista-blanca' })).toBe('tab=lista-blanca');
  });
});

describe('Lista blanca · la respuesta primero', () => {
  it('resume y avisa lo que no se puede vigilar', () => {
    const markup = renderToStaticMarkup(
      <AllowlistAnswerLine entries={ALL} revision={4} updatedAt="2026-11-23T10:00:00.000Z" canManage onAdd={noop} onReview={noop} />,
    );
    expect(markup).toContain('2 entradas vigiladas con 7 IPs · 1 sin IP (no alerta) · 1 pendiente');
    expect(markup).toContain('1 entrada no se puede vigilar bien: 1 con IPs por reconfirmar');
    expect(markup).toContain('revisión 4');
    expect(markup).toContain('Agregar cliente o proveedor');
    expect(markup).not.toContain('Solo lectura');
  });

  it('solo lectura: sin botón de agregar y con distintivo', () => {
    const markup = renderToStaticMarkup(
      <AllowlistAnswerLine entries={ALL} revision={0} updatedAt={null} canManage={false} onAdd={noop} />,
    );
    expect(markup).toContain('Solo lectura');
    expect(markup).not.toContain('Agregar cliente o proveedor');
    expect(markup).toContain('Lista inicial importada');
  });

  it('sin permiso: mensaje simple', () => {
    const markup = renderToStaticMarkup(<AllowlistNoAccess />);
    expect(markup).toContain('Tu rol no puede ver la lista blanca');
    expect(markup).toContain('lang="es-PE"');
  });
});

describe('Lista blanca · ¿esta IP es de alguien?', () => {
  it('muestra al dueño', () => {
    const markup = renderToStaticMarkup(<IpLookupResult lookup={lookupIp(ALL, '34.199.50.40')} />);
    expect(markup).toContain('BPC 1 (producción) · Con IP');
  });

  it('una IP ajena sería alerta', () => {
    const markup = renderToStaticMarkup(<IpLookupResult lookup={lookupIp(ALL, '8.8.8.8')} />);
    expect(markup).toContain('No está en la lista blanca');
    expect(markup).toContain('alerta');
  });
});

describe('Lista blanca · tabla', () => {
  it('estado con palabra, IPs compactas y efecto en palabras', () => {
    const markup = renderToStaticMarkup(<AllowlistTable entries={ALL} canManage={false} onEdit={noop} />);
    expect(markup).toContain('<th>Nombre</th>');
    expect(markup).toContain('Cliente · Payouts · Perú');
    expect(markup).toContain('Con IP');
    expect(markup).toContain('Alerta crítica si llama desde una IP que no es suya.');
    expect(markup).toContain('3.3.3.3');
    expect(markup).not.toContain('4.4.4.4</code>');
    expect(markup).toContain('+2');
    expect(markup).toContain('IPs por reconfirmar');
    expect(markup).not.toContain('Editar');
  });

  it('el administrador ve «Editar» por fila', () => {
    const markup = renderToStaticMarkup(<AllowlistTable entries={ALL} canManage onEdit={noop} />);
    expect(markup).toContain('aria-label="Editar Thunes"');
  });

  it('filtros con contadores y botones reales', () => {
    const markup = renderToStaticMarkup(<AllowlistFilters entries={ALL} filter={DEFAULT_FILTER} onChange={noop} />);
    expect(markup).toContain('aria-pressed="true"');
    expect(markup).toContain('Proveedores <span class="b89Allow__chipCount">1</span>');
    expect(markup).toContain('aria-label="Buscar en la lista blanca');
  });
});

describe('Lista blanca · edición', () => {
  it('cuenta IPs válidas y lista lo que no es IP', () => {
    const form = { ...EMPTY_FORM, name: 'Terrapay', prodText: '1.2.3.4; 4421486220' };
    const markup = renderToStaticMarkup(<EntryFormFields form={form} check={checkForm(form)} showErrors={false} onChange={noop} />);
    expect(markup).toContain('1 IP válida');
    expect(markup).toContain('«por reconfirmar»: 4421486220');
    expect(markup).toContain('Identificadores (opcional)');
    expect(markup).toContain('Alerta crítica si llama desde una IP que no es suya.');
  });

  it('muestra errores tras intentar aplicar', () => {
    const markup = renderToStaticMarkup(<EntryFormFields form={EMPTY_FORM} check={checkForm(EMPTY_FORM)} showErrors onChange={noop} />);
    expect(markup).toContain('Escribe el nombre.');
  });

  it('la barra dice qué cambia', () => {
    const draft = removeEntry(upsertEntry(ALL, { ...THUNES, prodIps: ['9.9.9.9'] }), 'gmoney');
    const markup = renderToStaticMarkup(
      <AllowlistSaveBar
        changes={diffAllowlist(ALL, draft)}
        saving={false}
        conflict={false}
        stepUp={false}
        validation={null}
        logoutHref="/b89/logout"
        onSave={noop}
        onDiscard={noop}
        onReload={noop}
      />,
    );
    expect(markup).toContain('2 cambios sin guardar');
    expect(markup).toContain('Cambia IPs de Thunes');
    expect(markup).toContain('Quita GMoney');
    expect(markup).toContain('Guardar lista blanca');
    expect(markup).toContain('Descartar');
  });

  it('sin cambios no hay barra', () => {
    const markup = renderToStaticMarkup(
      <AllowlistSaveBar changes={[]} saving={false} conflict={false} stepUp={false} validation={null} logoutHref="" onSave={noop} onDiscard={noop} onReload={noop} />,
    );
    expect(markup).toBe('');
  });

  it('conflicto, reautenticación y validación', () => {
    const conflict = renderToStaticMarkup(
      <AllowlistSaveBar changes={[]} saving={false} conflict stepUp={false} validation={null} logoutHref="" onSave={noop} onDiscard={noop} onReload={noop} />,
    );
    expect(conflict).toContain('Alguien guardó la lista blanca mientras editabas');
    expect(conflict).toContain('Tus cambios sin guardar se pierden');
    const changes = diffAllowlist(ALL, removeEntry(ALL, 'gmoney'));
    const stepUp = renderToStaticMarkup(
      <AllowlistSaveBar changes={changes} saving={false} conflict={false} stepUp validation="Revisa las IPs de producción de «Thunes»." logoutHref="/b89/logout" onSave={noop} onDiscard={noop} onReload={noop} />,
    );
    expect(stepUp).toContain('vuelve a iniciar sesión');
    expect(stepUp).toContain('Revisa las IPs de producción de «Thunes».');
  });
});
