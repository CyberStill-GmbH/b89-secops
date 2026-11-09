/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { BUNNY_ASK_EVENT, BunnyAskDetail } from '../common';

const LAUNCHER = '[data-test-subj="b89BunnyLauncher"]';
const INPUT = '#b89-bunny-panel textarea';

function fillDraft(prompt: string, attempts = 20): void {
  const input = document.querySelector<HTMLTextAreaElement>(INPUT);
  if (!input) {
    if (attempts > 0) window.setTimeout(() => fillDraft(prompt, attempts - 1), 100);
    return;
  }
  // React controla el <textarea>: se usa el setter nativo y un evento `input` para que lo vea.
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
  setter?.call(input, prompt);
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.focus();
}

/**
 * Abre Bunny con `prompt` como borrador (no lo envía). Primero ofrece el evento público
 * `BUNNY_ASK_EVENT` al panel; si nadie lo atiende, abre el panel con su botón de la cabecera y
 * escribe el borrador. Devuelve `false` si Bunny no está montado en esta página.
 */
export function askBunny(detail: BunnyAskDetail): boolean {
  const event = new CustomEvent<BunnyAskDetail>(BUNNY_ASK_EVENT, { detail, cancelable: true });
  const handled = !window.dispatchEvent(event);
  if (handled) return true;
  const launcher = document.querySelector<HTMLButtonElement>(LAUNCHER);
  if (!launcher) return false;
  if (launcher.getAttribute('aria-expanded') !== 'true') launcher.click();
  fillDraft(detail.prompt);
  return true;
}
