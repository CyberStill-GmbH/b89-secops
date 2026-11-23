/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

/**
 * Marca de Ferrispector: un cangrejo propio de B89, en el naranja de la comunidad Rust, como guiño
 * a Ferris (la mascota de Rust). Dibujo original en SVG, sin archivos externos; se adapta al tema
 * claro y oscuro porque el contorno usa `currentColor`.
 */
export function FerrispectorMark({ size = 32, title = 'Ferrispector' }: { size?: number; title?: string }) {
  return (
    <svg
      className="b89FerrisMark"
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label={title}
      focusable="false"
    >
      <title>{title}</title>
      {/* Pinzas */}
      <path d="M9 22c-5-3-6-10-2-13 2 3 5 4 8 3-1 3 0 6 2 8z" fill="#f74c00" />
      <path d="M55 22c5-3 6-10 2-13-2 3-5 4-8 3 1 3 0 6-2 8z" fill="#f74c00" />
      <path d="M15 22l6 9M49 22l-6 9" stroke="#c23c00" strokeWidth="3" strokeLinecap="round" />
      {/* Patas */}
      <path
        d="M14 40l-8 4M14 45l-7 7M50 40l8 4M50 45l7 7"
        stroke="#c23c00"
        strokeWidth="3"
        strokeLinecap="round"
      />
      {/* Caparazón */}
      <ellipse cx="32" cy="40" rx="20" ry="14" fill="#f74c00" />
      <path d="M14 38c6-6 30-6 36 0" stroke="#ffb27a" strokeWidth="2" fill="none" strokeLinecap="round" />
      {/* Ojos con lupa: inspecciona */}
      <path d="M26 28v-6M38 28v-6" stroke="#c23c00" strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="26" cy="20" r="4" fill="#fff" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="38" cy="20" r="4" fill="#fff" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="27" cy="20.5" r="1.8" fill="#1d1d1f" />
      <circle cx="39" cy="20.5" r="1.8" fill="#1d1d1f" />
      {/* Sonrisa */}
      <path d="M27 44c3 3 7 3 10 0" stroke="#6b1e00" strokeWidth="2" fill="none" strokeLinecap="round" />
    </svg>
  );
}
