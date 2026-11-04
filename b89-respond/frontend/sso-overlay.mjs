#!/usr/bin/env node
/*
 * Copyright B89. B89 Respond — overlay de SSO y navegación (decisión B11, docs/14 §8.1).
 *
 *   node b89-respond/frontend/sso-overlay.mjs <shuffle-frontend-dir>
 *
 * Codemod y no parche: App.jsx e index.html de Shuffle v2.3.0 vienen con CRLF y un parche con
 * contexto se rompe según core.autocrlf. Cada cambio busca su ancla exacta (tolerando \r) y falla si
 * no la encuentra, así que una versión nueva de Shuffle no pasa en silencio.
 *  1. App.jsx: no copiar el token de sesión a una cookie legible por JavaScript (Path=/); la sesión
 *     la emite el puente SSO como cookie HttpOnly acotada a /b89-respond.
 *  2. index.html: botón «Volver al SIEM» (target _top) y carga de la capa de español (b89-i18n.js).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const COOKIE_LOOP =
  /( *)for \(var key in responseJson\["cookies"\]\) \{\r?\n\s*setCookie\(\r?\n\s*responseJson\["cookies"\]\[key\]\.key,\r?\n\s*responseJson\["cookies"\]\[key\]\.value,\r?\n\s*\{ path: "\/" \}\r?\n\s*\);\r?\n\s*\}/u;

export const BACK_BUTTON_STYLE = `
      /* B89: «Volver al SIEM», fijo sobre la UI de B89 Respond, embebido o en pestaña aparte. */
      #b89-back-to-siem {
        position: fixed; top: 10px; right: 64px; z-index: 2147483000;
        display: inline-flex; align-items: center; gap: 8px; height: 32px; padding: 0 14px;
        border-radius: 8px; border: 1px solid rgba(255, 88, 65, 0.55);
        background: #141414; color: #f4f4f5; font: 700 13px/1 "Satoshi", "Helvetica", "Arial", sans-serif;
        text-decoration: none; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.45);
      }
      #b89-back-to-siem:hover { background: #ff5841; border-color: #ff5841; color: #080808; }
      #b89-back-to-siem:focus-visible { outline: 2px solid #ff5899; outline-offset: 2px; }
      #b89-back-to-siem svg { width: 14px; height: 14px; }
`;
// Comillas simples a propósito: el sub_filter del edge solo antepone /b89-respond a href/src con
// comillas dobles, y este enlace debe ir al SIEM (/app/…), no dentro de B89 Respond.
export const BACK_BUTTON =
  "<a id='b89-back-to-siem' href='/app/b89-alerts' target='_top' title='Volver a B89 SOC (SIEM)'>" +
  "<svg aria-hidden='true' viewBox='0 0 16 16' fill='none' stroke='currentColor' stroke-width='2' " +
  "stroke-linecap='round' stroke-linejoin='round'><path d='M10 3 5 8l5 5'/></svg>Volver al SIEM</a>";
export const I18N_SCRIPT = "<script src='/b89-respond/b89-i18n.js' defer></script>";

export function patchApp(source) {
  if (source.includes('B89: la sesión de B89 Respond la emite el puente SSO')) return source;
  if (!COOKIE_LOOP.test(source)) throw new Error('SSO_OVERLAY_ANCHOR_MISSING: App.jsx cookies');
  return source.replace(
    COOKIE_LOOP,
    '$1// B89: la sesión de B89 Respond la emite el puente SSO del edge como cookie HttpOnly acotada\n' +
      '$1// a /b89-respond; no se copia el token a una cookie legible por JavaScript.',
  );
}

export function patchIndex(source) {
  if (source.includes("id='b89-back-to-siem'")) return source;
  if (!/<\/style>/u.test(source) || !/<div id="root"><\/div>/u.test(source) || !/<\/title>/u.test(source)) {
    throw new Error('SSO_OVERLAY_ANCHOR_MISSING: index.html');
  }
  return source
    .replace(/<\/title>/u, `</title>\n    ${I18N_SCRIPT}`)
    .replace(/<\/style>/u, `${BACK_BUTTON_STYLE}    </style>`)
    .replace(/<div id="root"><\/div>/u, `${BACK_BUTTON}\n    <div id="root"></div>`);
}

export function applyOverlay(frontendDirectory) {
  const app = join(frontendDirectory, 'src', 'App.jsx');
  const index = join(frontendDirectory, 'index.html');
  writeFileSync(app, patchApp(readFileSync(app, 'utf8')));
  writeFileSync(index, patchIndex(readFileSync(index, 'utf8')));
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  if (!process.argv[2]) {
    process.stderr.write('uso: node sso-overlay.mjs <shuffle-frontend-dir>\n');
    process.exit(2);
  }
  applyOverlay(process.argv[2]);
  process.stdout.write('overlay SSO aplicado: cookie de sesión, Volver al SIEM, b89-i18n.js\n');
}
