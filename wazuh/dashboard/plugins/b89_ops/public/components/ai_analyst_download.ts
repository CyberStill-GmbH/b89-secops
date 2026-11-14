/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { safeMarkdownFilename } from '../../common';

/**
 * Descarga local de un informe en Markdown. El texto ya llegó con el GET autorizado: aquí solo
 * se arma un Blob en el navegador, sin otra petición al servidor.
 */
export function downloadMarkdown(filename: string, markdown: string): void {
  const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = safeMarkdownFilename(filename, 'analista-ia-informe');
  link.rel = 'noopener';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function digestFilename(from: string, to: string): string {
  return safeMarkdownFilename(`analista-ia-resumen-${from}_${to}`, 'analista-ia-resumen');
}
