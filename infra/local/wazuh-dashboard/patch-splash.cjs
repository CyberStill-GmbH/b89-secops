// Equivalente compilado de wazuh/dashboard/patches/wazuh-dashboard/0001-loading-splash-b89.patch
// para la imagen local (repack, sin build desde fuente). Falla si un patrón no aparece
// exactamente una vez: así un cambio de Wazuh rompe el build en vez de dejar la pantalla a medias.
//   node patch-splash.cjs /usr/share/wazuh-dashboard/src/core/server/rendering/views
'use strict';
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];

function patch(file, edits) {
  const p = path.join(dir, file);
  let s = fs.readFileSync(p, 'utf8');
  for (const [name, from, to] of edits) {
    const n = typeof from === 'string' ? s.split(from).length - 1 : (s.match(new RegExp(from.source, 'g')) || []).length;
    if (n !== 1) throw new Error(`${file}: patrón «${name}» aparece ${n} veces (se esperaba 1)`);
    s = s.replace(from, to);
  }
  fs.writeFileSync(p, s);
  console.log(`splash B89: ${file} parcheado (${edits.length} cambios)`);
}

patch('styles.js', [
  [
    'fondo blanco',
    /(\.osdWelcomeView \{\s*line-height: 1\.5;\s*)background-color: \$\{themeDefinition\.ouiHeaderBackgroundColor\};/,
    '$1/* B89: la pantalla de carga siempre es blanca */\n            background: #ffffff;\n            background-color: #ffffff;',
  ],
  [
    'contenedor grande',
    /\.loadingLogoContainer \{\s*height: 100px; \/\* Wazuh \*\/\s*padding: 10px 10px 10px 10px;/,
    '.loadingLogoContainer {\n            height: min(52vh, 400px);\n            padding: 0;',
  ],
  [
    'logo ancho',
    /(\.loadingLogo \{\s*height: 100%;\s*)max-width: 100%;/,
    '$1max-width: 90vw;\n            width: auto;',
  ],
  [
    'barra de progreso B89',
    "background-color: ${darkMode ? '#1BA9F5' : '#006DE4'};",
    'background: linear-gradient(90deg, #ff5899, #ff5841 55%, #ffc136);',
  ],
]);

patch('template.js', [
  [
    'sin texto Loading',
    /, i18n\('core\.ui\.welcomeMessage', \{[\s\S]*?defaultMessage: 'Loading \.\.\.'\s*\}\)/,
    '',
  ],
  ['mask-icon', 'color: "#003553"', 'color: "#101014"'],
]);
