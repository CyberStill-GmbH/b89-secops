/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Tema del login B89 SOC con la paleta oficial y las mascotas extraídas del manual de marca.
 */
export const LOGIN_THEME = `:root{
  --b89-pink:#ff5899;
  --b89-rose:#ff5841;
  --b89-coral:#ff5841;
  --b89-orange:#ffc136;
  --b89-blue:#119cff;
  --b89-lime:#d0e870;
  --b89-ink:#1b1220;
  --b89-ink-soft:#5d5266;
  --b89-line:#eadfe6;
  --b89-surface:#ffffff;
  --b89-bg:#fff7f9;
  --b89-danger:#b0123f;
  --font-sans:'Satoshi',ui-sans-serif,system-ui,sans-serif;
  color-scheme:light;
}
*{box-sizing:border-box}
html,body{min-height:100%;margin:0}
body{background:var(--b89-bg);color:var(--b89-ink);font-family:var(--font-sans);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
h1,h2,p{margin:0}
a{color:inherit}
img,svg{display:block;max-width:100%}

.login-shell{display:grid;min-height:100vh;grid-template-columns:minmax(380px,540px) minmax(0,1fr)}

/* --- Columna del formulario --- */
.login-side{position:relative;display:flex;min-width:0;flex-direction:column;justify-content:space-between;gap:32px;padding:32px clamp(24px,5vw,64px);background:var(--b89-surface)}
.login-brand{display:flex;align-items:center;gap:10px}
.brand-badge{display:block;width:42px;height:42px;object-fit:contain;border-radius:50%}
.brand-name{font-size:14px;font-weight:700;letter-spacing:3px;color:var(--b89-ink-soft)}
.login-destination{min-width:0;margin-left:auto;max-width:48%;overflow:hidden;color:var(--b89-ink-soft);font-size:12px;text-overflow:ellipsis;white-space:nowrap}

.login-core{width:100%;max-width:400px;margin:0 auto}
.login-core h1{font-size:clamp(26px,3.2vw,32px);font-weight:800;line-height:1.15;letter-spacing:-.5px}
.login-subtitle{margin-top:8px;color:var(--b89-ink-soft)}

.login-form{display:grid;gap:16px;margin-top:28px}
.field{display:grid;gap:6px}
.field label{font-size:13px;font-weight:600}
.field input{width:100%;height:48px;padding:0 14px;border:1.5px solid var(--b89-line);border-radius:12px;background:#fff;color:var(--b89-ink);font:inherit;transition:border-color 140ms ease,box-shadow 140ms ease}
.field input::placeholder{color:#a89cb0}
.field input:hover{border-color:#d9c6d3}
.field input:focus-visible{outline:none;border-color:var(--b89-pink);box-shadow:0 0 0 4px rgb(255 88 153 / 20%)}
.password-field{position:relative}
.password-field input{padding-right:48px}
.password-toggle{position:absolute;top:50%;right:6px;display:grid;width:36px;height:36px;place-items:center;padding:0;border:0;border-radius:8px;background:transparent;color:var(--b89-ink-soft);cursor:pointer;transform:translateY(-50%)}
.password-toggle:hover{background:var(--b89-bg);color:var(--b89-ink)}
.password-toggle:focus-visible{outline:2px solid var(--b89-pink);outline-offset:1px}
.password-toggle svg{width:20px;height:20px}

.btn{display:flex;width:100%;height:50px;align-items:center;justify-content:center;gap:10px;border:0;border-radius:12px;font:inherit;font-size:15px;font-weight:700;text-decoration:none;cursor:pointer;transition:transform 140ms ease,box-shadow 140ms ease,background-color 140ms ease,opacity 140ms ease}
.btn:focus-visible{outline:3px solid var(--b89-blue);outline-offset:2px}
.btn[aria-disabled="true"],.btn:disabled{cursor:progress;opacity:.7;pointer-events:none}
.btn-primary{background:linear-gradient(100deg,var(--b89-pink),var(--b89-coral) 55%,var(--b89-orange));color:#21141b;box-shadow:0 8px 20px -8px rgb(255 88 153 / 40%)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 12px 24px -8px rgb(255 88 153 / 46%)}
.btn-primary:active{transform:translateY(0)}
.btn-entra{border:1.5px solid var(--b89-line);background:#fff;color:var(--b89-ink)}
.btn-entra:hover{border-color:#d9c6d3;background:var(--b89-bg)}
.microsoft-mark{width:18px;height:18px}

.login-divider{display:flex;align-items:center;gap:14px;margin:22px 0;color:var(--b89-ink-soft);font-size:12px;text-transform:uppercase;letter-spacing:1.5px}
.login-divider::before,.login-divider::after{height:1px;flex:1;background:var(--b89-line);content:''}
.login-only-entra{margin-top:28px}

.auth-message{min-height:20px;margin-top:16px;color:var(--b89-ink-soft);font-size:13px}
.auth-message-error{padding:10px 12px;border:1px solid #f4b5c8;border-radius:10px;background:#fff1f5;color:var(--b89-danger);font-weight:600}

.auth-footer{max-width:400px;margin:0 auto;color:var(--b89-ink-soft);font-size:12px}
.auth-footer span{display:block}
.auth-footer .auth-attribution{margin-top:2px;color:#8b7f93;font-size:11px}

/* --- Panel de marca: la ilustración es el fondo --- */
.login-hero{position:relative;display:flex;min-height:320px;align-items:center;justify-content:center;gap:clamp(8px,3vw,36px);overflow:hidden;padding:28px;background:linear-gradient(130deg,var(--b89-pink),var(--b89-rose) 54%,var(--b89-orange))}
.login-hero::before{position:absolute;width:min(70vw,520px);aspect-ratio:1;border:1px solid rgb(255 255 255 / 30%);border-radius:50%;content:''}
.login-mascot{position:relative;width:min(36vw,300px);max-height:82%;object-fit:contain}
.login-mascot-mundi{width:min(33vw,270px)}

@media (max-width:1000px){
  .login-shell{grid-template-columns:minmax(0,1fr);grid-template-rows:auto 1fr}
  .login-hero{order:-1;min-height:220px}
  .login-mascot{width:min(30vw,220px);max-height:200px}
  .login-mascot-mundi{width:min(27vw,200px)}
  .login-side{padding:28px 24px 32px}
}
@media (max-width:600px){
  .login-destination{display:none}
}
@media (max-width:480px){
  .login-hero{min-height:170px;padding:12px}
  .login-mascot{width:min(42vw,180px);max-height:150px}
  .login-mascot-mundi{width:min(38vw,160px)}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
`;
