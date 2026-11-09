/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  BRAND_ASSETS_PATH,
  IntegrationSpec,
  isVendorId,
  VendorId,
  vendorLogoUrl,
  VENDORS,
} from '../../common';
import { Monogram } from './overview_parts';

/**
 * Logotipo oficial de un proveedor sobre placa clara (conserva sus colores en tema claro y
 * oscuro). Decorativo cuando el nombre ya está al lado (`decorative`), si no lleva `alt`.
 */
export function VendorLogo({
  id,
  basePath,
  size = 'm',
  decorative = false,
}: {
  id: VendorId;
  basePath: string;
  size?: 's' | 'm' | 'l';
  decorative?: boolean;
}) {
  const mark = VENDORS[id];
  return (
    <span
      className={`b89Vendor b89Vendor--${size}`}
      style={{ ['--b89-vendor-color' as string]: mark.color } as React.CSSProperties}
      data-vendor={id}
    >
      <img
        src={vendorLogoUrl(basePath, id)}
        alt={decorative ? '' : mark.name}
        loading="lazy"
        draggable={false}
      />
    </span>
  );
}

/** Distintivo de origen para filas y cabeceras: logotipo + nombre del proveedor. */
export function SourceBadge({
  id,
  basePath,
  label,
}: {
  id: VendorId;
  basePath: string;
  label?: string;
}) {
  return (
    <span className="b89SourceBadge" title={`Origen: ${label ?? VENDORS[id].name}`}>
      <VendorLogo id={id} basePath={basePath} size="s" decorative />
      <span className="b89SourceBadge__label">{label ?? VENDORS[id].name}</span>
    </span>
  );
}

/** Imagen propia de B89 para servicios que no son de terceros (Respond, Bunny). */
const OWN_MARKS: Partial<Record<string, string>> = {
  respond: 'b89-respond.svg',
  bunny: 'b89-bunny.webp',
};

/** Marca de una integración: logotipo del proveedor, imagen B89 propia o monograma. */
export function ServiceMark({ spec, basePath }: { spec: IntegrationSpec; basePath: string }) {
  const vendor = spec.id === 'wazuh' ? 'wazuh' : spec.id;
  if (isVendorId(vendor)) return <VendorLogo id={vendor} basePath={basePath} size="l" decorative />;
  const own = OWN_MARKS[spec.id];
  if (own) {
    return (
      <span className="b89Vendor b89Vendor--l b89Vendor--own" data-vendor={spec.id}>
        <img src={`${basePath}${BRAND_ASSETS_PATH}/${own}`} alt="" draggable={false} />
      </span>
    );
  }
  return <Monogram text={spec.monogram} />;
}
