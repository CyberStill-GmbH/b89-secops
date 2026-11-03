# wazuh/dashboard — B89 SecOps sobre Wazuh 4.14.8 (OSD 2.19.6)

Fork **como overlay**: no se versiona código de Wazuh. Se fija upstream por SHA
([`upstream.lock`](upstream.lock)), se aplican parches pequeños y numerados, se sustituyen
activos de marca conservando sus nombres y se añaden plugins propios. Subir a un tag nuevo
de Wazuh = cambiar el lock y rebasar unos pocos parches.

| Pieza                              | Qué es                                                                                                                               |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `upstream.lock`                    | Repos, tags, SHA, OSD 2.19.6, Node 18.19.0, SHA256 del .deb oficial, revisión `1b891`                                                |
| `patches/wazuh-dashboard/`         | Parches del core OSD de Wazuh (`git diff` contra el tag)                                                                             |
| `patches/wazuh-dashboard-plugins/` | Parches de la app de Wazuh                                                                                                           |
| `assets/`                          | Arte B89 (SVG generados por `assets/tools/build-brand.mjs`, favicons PNG/ICO, imágenes del login) y `targets.tsv` (origen → destino) |
| `plugins/b89_ops/`                 | Plugin OSD 2.19.6: login/logout B89 y consola SOC                                                                                    |
| `plugins/b89_i18n/`                | Traducción al español y marca en texto (lo mantiene otro agente; build.sh lo empaqueta)                                              |
| `build.sh`                         | Build de CI → un `.deb` + `SHA256SUMS`                                                                                               |
| `opensearch_dashboards.b89.yml`    | Bloque de configuración del host (lo escribe `edge/apply-edge.sh`)                                                                   |

## Parches

Todos aplican con `git apply --check` sobre un clon limpio del tag (verificado).

**wazuh-dashboard v4.14.8 (`42db785`)**

| Parche                       | Ficheros                                                           | Qué hace                                                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0001-loading-splash-b89`    | `rendering/views/styles.tsx`, `template.tsx`                       | Pantalla de carga: fondo `#080808` en oscuro, texto gris 13 px, barra ámbar, entrada 240 ms (opacidad + 6 px) desactivada con `prefers-reduced-motion`; `theme-color` y `mask-icon` en negro B89 |
| `0002-help-menu-b89`         | `chrome/ui/header/header_help_menu.tsx`                            | Menú de ayuda: «Mi sesión», «Salud de fuentes», «Cerrar sesión» y la atribución de licencias en lugar de documentación, Slack, GitHub y Google Groups de Wazuh                                   |
| `0003-branding-defaults-b89` | `opensearch_dashboards_config.ts`, `home_icon.tsx`, `template.tsx` | Título por defecto `B89 SecOps` (si falta `branding.applicationTitle`)                                                                                                                           |

**wazuh-dashboard-plugins v4.14.8 (`505c58f`)**

| Parche                       | Fichero                                                         | Qué hace                                                                                                                                                                    |
| ---------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0001-about-b89-attribution` | `plugins/main/public/components/settings/about/generalInfo.tsx` | «Acerca de» de la app: la sección «Community» (Slack/Google Groups/GitHub de Wazuh) pasa a ser la atribución «Basado en Wazuh (GPLv2) y OpenSearch Dashboards (Apache-2.0)» |

Lo demás de la marca **no necesita parches**:

- **Logos, marca, favicons, pantalla de carga**: el core los lee de ficheros con nombre fijo
  (`ui/logos/wazuh_*.svg`, `spinner_on_*.svg`, `favicons/*`, `get_logos.ts`); `targets.tsv`
  los sobrescribe con el arte B89. Lo mismo en la app de Wazuh (`themes/{dark,light}/logo.svg`
  del health-check y la carga, `icon.svg`, `logo_reports.png` de los PDF).
- **Texto «Wazuh» → «B89 SecOps»** en la UI: lo hace en tiempo de ejecución el glosario de
  marca de `b89_i18n` (`brand` en `glossary.es.json`). No se renombra ningún identificador, ruta
  de API, índice (`wazuh-alerts-*`), clave de configuración ni id de plugin.
- **Tema**: `b89_ops/public/theme.scss` (global, contenido) sobre OUI v7 oscuro.

Los LICENSE/NOTICE originales no se tocan. La atribución es visible en el login, el menú de
ayuda, «Mi sesión» y el «Acerca de» de la app (marcada `data-b89-no-translate` para que el
glosario de marca no la reescriba).

## Plugin `b89_ops`

Id `b89Ops`, config `b89_ops.*`, sin dependencias de otros plugins ni importaciones de valores
del core (solo tipos): sobrevive a cambios de Wazuh. React 16 (`ReactDOM.render`), OUI 1.19.

- Servidor: `GET /b89/login` (sin sesión de OSD; enlace a `/api/auth/start?returnTo=`; avisos
  `authError`+`correlationId`, `sessionNotice=superseded`, `loggedOut`; CSP con nonce),
  `GET /b89/logout` (CSRF de `/api/auth/session` → `POST /api/auth/logout`), y reescritura de
  `/app/login` y `/login` → `/b89/login`. Activos del login en `/ui/b89/` (público en el edge).
- Navegación: categoría «Observabilidad de la aplicación» primera (`order: -1000`), con marca
  B89 y pictogramas SVG propios para Cola de alertas, Incidentes, Notificaciones, Auditoría e
  integridad, Usuarios y sesiones, Salud de fuentes (incluye la salud operativa) y Mi sesión.
  Las vistas SIEM nativas de Wazuh conservan sus iconos funcionales y siguen debajo.
- Un único cliente y **un único long-poll** de `/api/changes` por página (plugin singleton,
  compartido por todas las apps B89 y el aviso P1), con backoff 2 s→30 s y pausa con la
  pestaña oculta. Aviso P1 en la cabecera (todo el dashboard) + toast.
- Alerta → «Ver eventos en Discover (±1 h)» por entidad (`data.office365.UserId`,
  `data.office365.ClientIP`/`data.srcip`, `agent.name`) sobre `wazuh-alerts-*`.
- Las zonas de datos llevan `data-b89-no-translate`.

Verificación local (sin bootstrap de OSD):

```sh
# deps en un directorio temporal, fuera del repo
npm i --legacy-peer-deps typescript@4.0.2 @opensearch-project/oui@1.19.0 @types/react@16.14.60 \
  @types/react-dom@16.9.24 @types/node@14.18.63 @types/jest@26.0.24 rxjs@6.6.7 vitest@1.6.0 sass@1.69.5
B89_TOOLS_DIR=<ese dir> node plugins/b89_ops/tools/typecheck.mjs
```

## Build

```sh
bash wazuh/dashboard/build.sh <OUT_DIR>                         # modo source (por defecto)
B89_BUILD_MODE=repack bash wazuh/dashboard/build.sh <OUT_DIR> # reempaqueta el .deb oficial
```

Node **18.19.0** (`.nvmrc` de wazuh-dashboard v4.14.8; `engines: >=14.20.1 <19`) y Yarn 1.22.x;
build.sh los instala en el directorio de trabajo si no coinciden.

- **source** (recomendado): clona en los SHA fijados, aplica parches y activos,
  `yarn osd bootstrap`, `yarn build-platform --linux --skip-os-packages --release`, compila la app
  de Wazuh, `b89_ops`, `b89_i18n` y el security plugin con `plugin_helpers` de OSD 2.19.6 y
  empaqueta con `dev-tools/build-packages/build-packages.sh --deb --production -r 1b891`
  (Docker). Mismo paquete `wazuh-dashboard`, rutas, usuario y servicio que el oficial.
  Estimado en ubuntu-latest (4 vCPU, 16 GB, sin caché): 75–110 min.
- **repack**: descarga el .deb oficial, verifica el SHA256 del índice APT, sustituye activos y
  plugins y lo reconstruye con `dpkg-deb`. ~25–40 min (solo bootstrap + plugins). **No aplica los
  parches del core** (pantalla de carga, ayuda, títulos por defecto); el resto de la marca sí.

Instalación en el host: `dpkg -i --force-confold wazuh-dashboard_4.14.8-1b891_amd64.deb`
(los ficheros de `/etc/wazuh-dashboard` son conffiles y se conservan).

## Configuración requerida (`opensearch_dashboards.yml` del host)

```yaml
opensearch_security.auth.logout_url: '/b89/logout'
b89_ops.enabled: true
b89_ops.apiPrefix: '/api'
b89_ops.login.defaultNextUrl: '/app/b89-alerts'
opensearchDashboards.branding.applicationTitle: 'B89 SecOps'
uiSettings.overrides.defaultRoute: /app/b89-alerts # sustituye /app/wz-home del yml oficial
uiSettings.overrides.theme:darkMode: true
uiSettings.overrides.theme:version: v7 # el tema B89 está probado sobre v7
```

`opensearchDashboards.branding.helpMenuLinks` **no existe en OSD 2.19** (el esquema de config lo
rechaza y el servicio no arranca): el menú de ayuda B89 lo aporta el parche 0002.

## Subir a un tag nuevo de Wazuh

1. `git ls-remote --tags` de los tres repos; actualizar tags, SHA, `OSD_VERSION`,
   `NODE_VERSION` (`.nvmrc`) y, para repack, URL + SHA256 del índice APT en `upstream.lock`.
2. Clonar cada repo en el tag nuevo y `git apply --check patches/<repo>/*.patch`. Si un parche no
   aplica, aplicarlo a mano en el clon, regenerarlo con `git diff > NNNN-….patch` y mantenerlo igual
   de pequeño.
3. Comprobar que cada destino de `assets/targets.tsv` sigue existiendo (si Wazuh renombra un logo,
   ajustar la línea; `get_logos.ts` y `utils/assets.ts` dicen qué ficheros se leen).
4. Subir `version`/`opensearchDashboardsVersion` de `plugins/*/opensearch_dashboards.json` y
   `package.json` a la nueva versión de OSD; repasar las firmas de `b89_ops/tools/shims`.
5. Ejecutar `build.sh` y revisar la pantalla de carga, el login, el menú y Discover.

## Huecos conocidos

- No se ha ejecutado un build completo (sin Linux/Docker en la máquina de desarrollo): `build.sh`
  pasó `bash -n` y sus pasos de clonado/parcheo/activos se probaron por separado.
- Textos «Wazuh» en la app: los resuelve `b89_i18n` en tiempo de ejecución; sin ese plugin, la app
  conserva su texto original. Los enlaces de ayuda contextual a documentation.wazuh.com dentro de los
  módulos (≈15) siguen apuntando a la documentación de Wazuh.
- El texto «Loading ...» de la pantalla de carga no se traduce (se pinta antes de cargar plugins).
- Snapshots de tests de upstream afectados por los parches (help menu, about, template) no se
  actualizan: el build no ejecuta los tests de Jest de upstream.
- Los enlaces del menú de ayuda son absolutos (`/app/…`, `/b89/logout`): sin `server.basePath`.
