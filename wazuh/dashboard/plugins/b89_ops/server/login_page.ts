/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Login B89 SOC servido por el dashboard (sustituye al formulario de Wazuh).
 *
 * Dos formas de entrar, ambas por el BFF de B89 y ambas con la misma admisión (red, bloqueo,
 * MFA/passkey y rol Accesos_SOC):
 *
 * - **Microsoft Entra ID**: enlace a `/api/auth/start` (PKCE, nonce).
 * - **Usuario y contraseña**: formulario `POST /api/auth/password`, que funciona sin
 *   JavaScript y se puede desactivar con `b89_ops.login.passwordEnabled`.
 *
 * El dashboard nunca guarda credenciales ni tokens: el formulario las envía directamente a la API.
 */

import {
  API_ERROR_CODES,
  API_ERROR_MESSAGE,
  ApiErrorCode,
  ATTRIBUTION,
  BRAND_ASSETS_PATH,
  LOGIN_PATH,
} from '../common';
import { LOGIN_THEME } from './login_theme';

const MAX_NEXT_URL_LENGTH = 512;
const PROBE_ORIGIN = 'https://next-url.b89.invalid';

/**
 * Mismas reglas que `safeReturnTo` del BFF: solo rutas relativas del mismo origen; nada de
 * `//host`, barras invertidas, caracteres de control ni rutas de la API. Evita el *open
 * redirect* clásico en `nextUrl`.
 */
export function safeNextUrl(value: unknown, fallback: string, apiPrefix = '/api'): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_NEXT_URL_LENGTH) {
    return fallback;
  }
  const hasControl = [...value].some((char) => {
    const code = char.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || hasControl) {
    return fallback;
  }
  let url: URL;
  try {
    url = new URL(value, PROBE_ORIGIN);
  } catch {
    return fallback;
  }
  if (url.origin !== PROBE_ORIGIN) return fallback;
  if (url.pathname === apiPrefix || url.pathname.startsWith(`${apiPrefix}/`)) return fallback;
  if (url.pathname.startsWith('/b89/')) return fallback; // nunca volver al propio login
  return `${url.pathname}${url.search}${url.hash}`;
}

/**
 * `nextUrl` tal como lo pone el proxy (`/b89/login?nextUrl=$request_uri`): nginx no puede
 * codificarlo, así que es el último parámetro y llega en crudo, con sus propios `?` y `&`.
 * Se toma todo lo que sigue a `nextUrl=`; si venía codificado, se decodifica. El resultado
 * pasa igualmente por `safeNextUrl`.
 */
export function rawNextUrl(search: string): string | undefined {
  const marker = search.search(/[?&]nextUrl=/u);
  if (marker === -1) return undefined;
  const raw = search.slice(search.indexOf('=', marker) + 1);
  if (!raw.startsWith('%2F') && !raw.startsWith('%2f')) return raw;
  try {
    return decodeURIComponent(raw);
  } catch {
    return undefined;
  }
}

export interface SignInNotice {
  readonly code: ApiErrorCode | null;
  readonly correlationId: string | null;
  readonly superseded: boolean;
  readonly loggedOut: boolean;
}

const CORRELATION_PATTERN = /^[0-9a-f-]{36}$/u;

function isApiErrorCode(value: string | null): value is ApiErrorCode {
  return value !== null && (API_ERROR_CODES as readonly string[]).includes(value);
}

/**
 * El BFF devuelve los fallos al `returnTo` con `?authError=&correlationId=`; el proxy, al no
 * haber sesión, reenvía esa URL aquí como `nextUrl`. Se leen ambos sitios y se limpian del
 * destino para no repetir el error tras un acceso correcto.
 */
export function readSignInNotice(
  query: Record<string, unknown>,
  fallback: string,
  apiPrefix = '/api',
): { readonly nextUrl: string; readonly notice: SignInNotice } {
  const nextUrl = safeNextUrl(query.nextUrl, fallback, apiPrefix);
  const next = new URL(nextUrl, PROBE_ORIGIN);
  const pick = (name: string): string | null => {
    const own = query[name];
    if (typeof own === 'string') return own;
    return next.searchParams.get(name);
  };
  const code = pick('authError');
  const correlationId = pick('correlationId');
  const superseded = pick('sessionNotice') === 'superseded';
  for (const name of ['authError', 'correlationId', 'sessionNotice'])
    next.searchParams.delete(name);
  return {
    nextUrl: `${next.pathname}${next.search}${next.hash}`,
    notice: {
      code: isApiErrorCode(code) ? code : null,
      correlationId:
        correlationId && CORRELATION_PATTERN.test(correlationId) ? correlationId : null,
      superseded,
      loggedOut: query.loggedOut === '1',
    },
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

export interface LoginPageOptions {
  readonly basePath: string;
  readonly apiPrefix: string;
  readonly nextUrl: string;
  readonly notice: SignInNotice;
  readonly nonce: string;
  readonly destinationLabel: string;
  /** Muestra el formulario de usuario y contraseña (por defecto, sí). */
  readonly passwordEnabled?: boolean;
}

/**
 * CSP del login: un único script inline con nonce (estado «Conectando…» y aviso de cookies),
 * estilos con el mismo nonce e imágenes propias más el grano `data:` del panel de marca.
 */
export function loginContentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

function message(notice: SignInNotice): { readonly text: string; readonly alert: boolean } {
  if (notice.code) {
    const reference = notice.correlationId ? ` Referencia: ${notice.correlationId}.` : '';
    return { text: `${API_ERROR_MESSAGE[notice.code]}${reference}`, alert: true };
  }
  if (notice.superseded) {
    return {
      text: 'Tu sesión se cerró porque iniciaste sesión en otro dispositivo.',
      alert: false,
    };
  }
  if (notice.loggedOut) return { text: 'Sesión cerrada.', alert: false };
  return { text: '', alert: false };
}

const MICROSOFT_MARK =
  '<svg aria-hidden="true" class="microsoft-mark" viewBox="0 0 18 18">' +
  '<path fill="#f25022" d="M0 0h8v8H0z"/><path fill="#7fba00" d="M10 0h8v8h-8z"/>' +
  '<path fill="#00a4ef" d="M0 10h8v8H0z"/><path fill="#ffb900" d="M10 10h8v8h-8z"/></svg>';

const EYE_ICON =
  '<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';

/** Icono Cookie (Phosphor, duotone) del aviso de cookies de b89-secops. */
const COOKIE_ICON =
  '<svg aria-hidden="true" viewBox="0 0 256 256" fill="currentColor">' +
  '<path opacity="0.2" d="M224,128a96,96,0,1,1-96-96,48,48,0,0,0,48,48A48,48,0,0,0,224,128Z"/>' +
  '<path d="M164.49,163.51a12,12,0,1,1-17,0A12,12,0,0,1,164.49,163.51Zm-81-8a12,12,0,1,0,17,0A12,12,0,0,0,83.51,155.51Zm9-39a12,12,0,1,0-17,0A12,12,0,0,0,92.49,116.49Zm48-1a12,12,0,1,0,0,17A12,12,0,0,0,140.49,115.51ZM232,128A104,104,0,1,1,128,24a8,8,0,0,1,8,8,40,40,0,0,0,40,40,8,8,0,0,1,8,8,40,40,0,0,0,40,40A8,8,0,0,1,232,128Zm-16.31,7.39A56.13,56.13,0,0,1,168.5,87.5a56.13,56.13,0,0,1-47.89-47.19,88,88,0,1,0,95.08,95.08Z"/></svg>';

const CLOSE_ICON =
  '<svg aria-hidden="true" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round"><path d="M4 4l8 8M12 4l-8 8"/></svg>';

/** Clave de reconocimiento del aviso; la misma que `CookieNotice.tsx` de b89-secops. */
const COOKIE_ACK_KEY = 'b89.cookie-notice.technical.v1';

/**
 * Aviso de cookies como barra inferior a lo ancho (formato clásico), con «Aceptar» y cierre
 * (×). Solo hay cookies técnicas necesarias, así que cerrar equivale a darse por enterado.
 * Entra y sale deslizándose; sin movimiento con `prefers-reduced-motion`.
 */
const COOKIE_BAR_CSS = `
.auth-footer span{display:block}
.auth-footer .auth-attribution{margin-top:2px;color:#6f6f75;font-size:11px}
.b89-cookie-notice.b89-cookie-bar{position:fixed;z-index:110;right:0;bottom:0;left:0;display:flex;width:100%;max-width:none;align-items:center;gap:16px;
padding:14px max(24px,env(safe-area-inset-right)) calc(14px + env(safe-area-inset-bottom)) max(24px,env(safe-area-inset-left));
border:0;border-top:1px solid #29292d;border-radius:0;background:#0d0d0f;box-shadow:0 -8px 24px rgb(0 0 0 / 45%);
transform:translateY(100%);opacity:0;transition:transform 320ms cubic-bezier(0.16,1,0.3,1),opacity 220ms ease}
.b89-cookie-bar.is-visible{transform:translateY(0);opacity:1}
.b89-cookie-bar.is-leaving{transform:translateY(100%);opacity:0;transition:transform 280ms cubic-bezier(0.4,0,1,1),opacity 240ms ease}
.b89-cookie-bar .b89-cookie-notice__mark{flex:0 0 auto}
.b89-cookie-bar .b89-cookie-notice__content{display:flex;min-width:0;flex:1 1 auto;align-items:center;gap:8px 24px;flex-wrap:wrap}
.b89-cookie-bar .b89-cookie-notice__text{min-width:0;flex:1 1 420px}
.b89-cookie-bar .b89-cookie-notice__content p{margin:2px 0 0}
.b89-cookie-bar .b89-cookie-notice__content details{margin:4px 0 0}
.b89-cookie-bar .b89-cookie-notice__actions{display:flex;flex:0 0 auto;align-items:center;gap:8px}
.b89-cookie-bar .b89-cookie-notice__content .b89-cookie-accept{border-radius:999px;padding:0 16px}
.b89-cookie-bar .b89-cookie-close{display:grid;width:38px;height:38px;flex:0 0 auto;place-items:center;padding:0;border:1px solid #49494e;border-radius:999px;background:transparent;color:#b0b0b5;cursor:pointer;transition:border-color 160ms ease,color 160ms ease,background-color 160ms ease}
.b89-cookie-bar .b89-cookie-close:hover{border-color:#85858b;background:#131315;color:#f4f4f5}
.b89-cookie-bar .b89-cookie-close:focus-visible{outline:2px solid #f5f5f5;outline-offset:3px}
.b89-cookie-bar .b89-cookie-close svg{width:14px;height:14px}
@media (max-width:600px){
.b89-cookie-notice.b89-cookie-bar{align-items:flex-start;gap:10px;padding:12px 12px calc(12px + env(safe-area-inset-bottom))}
.b89-cookie-bar .b89-cookie-notice__actions{width:100%}
.b89-cookie-bar .b89-cookie-notice__content .b89-cookie-accept{flex:1;min-height:44px}
.b89-cookie-bar .b89-cookie-close{position:absolute;top:8px;right:8px;width:44px;height:44px;border-color:transparent}
.b89-cookie-bar .b89-cookie-notice__text{padding-right:40px}
}
@media (prefers-reduced-motion:reduce){.b89-cookie-notice.b89-cookie-bar,.b89-cookie-bar.is-leaving{transition:none}}
`;

function passwordScript(): string {
  return `  var form = document.getElementById('b89-password-form');
  if (form) {
    var input = document.getElementById('b89-password');
    var toggle = document.getElementById('b89-password-toggle');
    toggle.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
      toggle.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
    });
    form.addEventListener('submit', function () {
      var submit = document.getElementById('b89-password-submit');
      submit.disabled = true;
      submit.textContent = 'Verificando…';
      pending('Verificando tus credenciales…');
    });
  }`;
}

function loginScript(passwordEnabled: boolean): string {
  return `(function () {
  var status = document.getElementById('b89-auth-message');
  function pending(text) {
    if (status && status.getAttribute('role') !== 'alert') status.textContent = text;
  }
  var link = document.getElementById('b89-entra');
  if (link) {
    var label = document.getElementById('b89-entra-label');
    link.addEventListener('click', function () {
      link.setAttribute('aria-disabled', 'true');
      label.textContent = 'Conectando con Microsoft Entra…';
      pending('Conectando de forma segura…');
    });
  }
${passwordEnabled ? passwordScript() : ''}
  var key = ${JSON.stringify(COOKIE_ACK_KEY)};
  var bar = document.getElementById('b89-cookie-notice');
  var accepted = false;
  try { accepted = window.localStorage.getItem(key) === 'accepted'; } catch (e) {}
  if (accepted) { bar.remove(); return; }
  bar.hidden = false;
  requestAnimationFrame(function () { requestAnimationFrame(function () { bar.classList.add('is-visible'); }); });
  var closed = false;
  function dismiss() {
    if (closed) return;
    closed = true;
    try { window.localStorage.setItem(key, 'accepted'); } catch (e) {}
    bar.classList.remove('is-visible');
    bar.classList.add('is-leaving');
    var done = function () { if (bar.parentNode) bar.remove(); };
    bar.addEventListener('transitionend', done, { once: true });
    window.setTimeout(done, 400);
  }
  document.getElementById('b89-cookie-accept').addEventListener('click', dismiss);
  document.getElementById('b89-cookie-close').addEventListener('click', dismiss);
  document.addEventListener('keydown', function (event) { if (event.key === 'Escape') dismiss(); });
})();`;
}

/** Pantalla de acceso: formulario a la izquierda y la ilustración de marca como panel. */
export function renderLoginPage(options: LoginPageOptions): string {
  const { basePath, apiPrefix, nextUrl, notice, nonce, destinationLabel } = options;
  const passwordEnabled = options.passwordEnabled ?? true;
  const start = `${apiPrefix}/auth/start?returnTo=${encodeURIComponent(nextUrl)}`;
  const status = message(notice);
  const ui = `${basePath}/ui`;
  const brand = `${basePath}${BRAND_ASSETS_PATH}`;
  const css = LOGIN_THEME.split('__UI__').join(brand) + COOKIE_BAR_CSS;
  const entraButton = `<a id="b89-entra" class="btn btn-entra" href="${escapeHtml(start)}">${MICROSOFT_MARK}<span id="b89-entra-label">Continuar con Microsoft Entra</span></a>`;
  const passwordForm = `<form id="b89-password-form" class="login-form" method="post" action="${escapeHtml(`${apiPrefix}/auth/password`)}" autocomplete="on">
      <input type="hidden" name="returnTo" value="${escapeHtml(nextUrl)}">
      <div class="field">
        <label for="b89-username">Usuario</label>
        <input id="b89-username" name="username" type="text" inputmode="email" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="nombre@b89.example" maxlength="254" required>
      </div>
      <div class="field">
        <label for="b89-password">Contraseña</label>
        <div class="password-field">
          <input id="b89-password" name="password" type="password" autocomplete="current-password" placeholder="Tu contraseña" maxlength="256" required>
          <button id="b89-password-toggle" class="password-toggle" type="button" aria-label="Mostrar contraseña" aria-pressed="false">${EYE_ICON}</button>
        </div>
      </div>
      <button id="b89-password-submit" class="btn btn-primary" type="submit">Iniciar sesión</button>
    </form>
    <div class="login-divider" role="separator"><span>o</span></div>
    ${entraButton}`;
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#fb38a2">
<meta name="referrer" content="no-referrer">
<link rel="icon" type="image/png" sizes="32x32" href="${ui}/favicons/favicon-32x32.png">
<link rel="apple-touch-icon" sizes="180x180" href="${ui}/favicons/apple-touch-icon.png">
<link rel="manifest" href="${ui}/favicons/manifest.json">
<link rel="preload" as="image" type="image/webp" href="${brand}/b89_login_hero.webp" media="(min-width: 1001px)">
<link rel="preload" as="image" type="image/webp" href="${brand}/b89_login_hero_sm.webp" media="(max-width: 1000px)">
<title>Iniciar sesión · B89 SOC</title>
<style nonce="${nonce}">${css}</style>
</head>
<body>
<main class="login-shell">
  <section class="login-side">
    <header class="login-brand">
      <span class="brand-badge" aria-hidden="true">B89</span>
      <span class="brand-name">SOC</span>
      <span class="login-destination">Estás iniciando sesión en ${escapeHtml(destinationLabel)}</span>
    </header>
    <div class="login-core" aria-labelledby="login-title">
      <h1 id="login-title">Bienvenido a B89 SOC</h1>
      <p class="login-subtitle">${
        passwordEnabled
          ? 'Ingresa con tu usuario o con tu cuenta institucional.'
          : 'Ingresa con tu cuenta institucional.'
      }</p>
      ${passwordEnabled ? passwordForm : `<div class="login-only-entra">${entraButton}</div>`}
      <p id="b89-auth-message" class="auth-message${status.alert ? ' auth-message-error' : ''}" role="${
        status.alert ? 'alert' : 'status'
      }">${escapeHtml(status.text)}</p>
    </div>
    <footer class="auth-footer">
      <span>El acceso requiere una identidad autorizada y verificación multifactor.</span>
      <span class="auth-attribution">${escapeHtml(ATTRIBUTION)}</span>
    </footer>
  </section>
  <aside class="login-hero" role="img" aria-label="Ilustración de B89: el conejo analista y el planeta vigilan el panel de seguridad"></aside>
</main>
<aside id="b89-cookie-notice" class="b89-cookie-notice b89-cookie-bar" aria-labelledby="cookie-notice-title" hidden>
  <div class="b89-cookie-notice__mark" aria-hidden="true">${COOKIE_ICON}</div>
  <div class="b89-cookie-notice__content">
    <div class="b89-cookie-notice__text">
      <h2 id="cookie-notice-title">Cookies necesarias</h2>
      <p>B89 usa cookies técnicas para mantener tu sesión institucional y proteger el inicio de sesión.</p>
      <details>
        <summary>Ver para qué se usan</summary>
        <ul>
          <li><code>b89_session</code>: mantiene la sesión autenticada.</li>
          <li><code>b89_oidc_flow_…</code>: vincula temporalmente el inicio de sesión con este navegador.</li>
        </ul>
      </details>
    </div>
    <div class="b89-cookie-notice__actions">
      <button id="b89-cookie-accept" class="b89-cookie-accept" type="button">Aceptar cookies necesarias</button>
    </div>
  </div>
  <button id="b89-cookie-close" class="b89-cookie-close" type="button" aria-label="Cerrar aviso de cookies">${CLOSE_ICON}</button>
</aside>
<script nonce="${nonce}">${loginScript(passwordEnabled)}</script>
</body>
</html>`;
}

export interface LogoutPageOptions {
  readonly basePath: string;
  readonly apiPrefix: string;
  readonly nonce: string;
}

/** CSP del cierre de sesión: un único script inline identificado por nonce. */
export function logoutContentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

/**
 * Cierre de sesión: el BFF exige el token CSRF de la sesión para cerrarla (otro sitio no
 * puede expulsar a la persona), así que se obtiene de `/auth/session` y se envía en
 * `x-csrf-token`. Sin sesión vigente, el BFF limpia la cookie igualmente.
 */
export function renderLogoutPage({ basePath, apiPrefix, nonce }: LogoutPageOptions): string {
  const login = `${basePath}${LOGIN_PATH}?loggedOut=1`;
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Cerrando sesión · B89 SOC</title>
<style nonce="${nonce}">html,body{margin:0;height:100%;background:#080808;color:#8f8f95;font:13px/20px 'Segoe UI',Inter,ui-sans-serif,system-ui,sans-serif}main{display:grid;height:100%;place-items:center}</style>
</head>
<body>
<main><p role="status">Cerrando sesión…</p></main>
<script nonce="${nonce}">
(function () {
  var api = ${JSON.stringify(apiPrefix)};
  var done = function () { window.location.replace(${JSON.stringify(login)}); };
  fetch(api + '/auth/session', { credentials: 'same-origin', headers: { accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (s) {
      return fetch(api + '/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        headers: s && s.csrfToken ? { 'x-csrf-token': s.csrfToken } : {}
      });
    })
    .then(done, done);
})();
</script>
</body>
</html>`;
}
