/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

/** Marca de RabbitDLP: el conejo detective entregado para el instalador de Windows. */
export function FerrispectorMark({
  size = 32,
  title = 'RabbitDLP',
  basePath = '',
}: {
  size?: number;
  title?: string;
  basePath?: string;
}) {
  return (
    <img
      className="b89FerrisMark"
      src={`${basePath}/ui/b89/rabbitdlp.png`}
      width={size}
      height={size}
      alt={title}
      loading="lazy"
      decoding="async"
    />
  );
}
