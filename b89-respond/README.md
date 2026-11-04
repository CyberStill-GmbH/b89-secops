# b89-respond/ — overlay de frontend Shuffle (B89 Respond heredado)

> **Nota (heredado):** Shuffle y su webhook son el estado heredado de B89 Respond. El diseño vigente es
> Step Functions ([13](../docs/13-b89-respond.md), [14](../docs/14-b89-respond-conexion-b89.md)); este material se reemplaza (fase M5).

El frontend se construye para alojarse en la ruta `/b89-respond/` detrás de la sesión B89. Se entra con la sesión de B89 SOC, sin segundo login: el puente `sso/` abre la sesión de Shuffle con el rol mapeado desde B89 (decisión B11, [14 §8.1](../docs/14-b89-respond-conexion-b89.md)). `frontend/i18n/b89-i18n.js` pone la interfaz en español y `frontend/sso-overlay.mjs` añade «Volver al SIEM».

Overlay versionado sobre **Shuffle v2.3.0** ([`upstream.lock`](upstream.lock)). Diseño vigente (Step Functions) y plan de migración en [`docs/13-b89-respond.md`](../docs/13-b89-respond.md).

| Ruta                                                               | Qué cambia de Shuffle                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `frontend/patches/0001-b89-respond-tema-y-marca-por-defecto.patch` | Superficies oscuras neutras (`#080808`) y nombre de marca por defecto «B89 Respond» (white-label nativo de Shuffle)                                                                                                                                                                                                     |
| `frontend/patches/0002-b89-respond-html-y-manifest.patch`          | Título, `theme-color` y manifest PWA (`lang` sigue en `en` hasta traducir la UI de B89 Respond)                                                                                                                                                                                                                         |
| `frontend/patches/0003-b89-respond-csp-mismo-origen.patch`         | CSP de mismo origen: el frontend no puede llamar a la nube de Shuffle, Algolia ni otros terceros (N1)                                                                                                                                                                                                                   |
| `frontend/assets/`                                                 | Arte B89 Respond: el monograma oficial de B89 (sin redibujar; ver [identidad visual](../docs/brand/b89-visual-identity.md)). Reemplaza los logos con los mismos nombres de archivo (`targets.tsv`). Se regenera con `python assets/tools/build-brand.py`                                                                |
| `frontend/patches/0004-b89-respond-tipografia-satoshi.patch`       | `@font-face` de Satoshi Medium/Bold (los archivos los copia `build.sh` a `public/fonts/`)                                                                                                                                                                                                                               |
| `frontend/rebrand.mjs`                                             | Codemod con AST de TypeScript: colores naranja de Shuffle → Coral `#FF5841` y Fucsia `#FF5899` de la paleta oficial en todo el código, y «Shuffle» → «B89 Respond» **solo en texto visible**. No toca la lógica, los datos, los nombres de apps del backend (Shuffle Tools, DB, AI) ni los textos que el código compara |
| `build.sh`                                                         | Clona el tag, verifica el SHA, aplica parches, arte y codemod, publica el código fuente en `/source/` (AGPL §13) y construye la imagen                                                                                                                                                                                  |

El workflow [`.github/workflows/b89-respond-azure.yml`](../.github/workflows/b89-respond-azure.yml)
construye y verifica la imagen en PR sin credenciales cloud. La publicación a ACR
requiere `workflow_dispatch`, `main`, `publish_to_acr=true` y el environment
`azure-demo`; el workflow conserva la imagen del mismo run, valida su SHA-256 y
registra el digest OCI. Publicar la imagen no despliega Shuffle ni habilita una
ruta pública.

## Identidad visual

Sigue [Identidad visual B89 · Frontend](../docs/brand/b89-visual-identity.md): paleta oficial de siete
colores, monograma sin modificar y ninguna imagen de otras marcas. Se usa el Coral como acento (el naranja de
Shuffle), pero **la paleta de marca no codifica severidad ni estado**: los colores semánticos de Shuffle
(éxito, error, advertencia) se conservan.

**Tipografía.** Satoshi Medium y Bold (`frontend/assets/fonts/`, con su licencia ITF FFL) se declaran en el
patch 0004 y el codemod cambia la pila de Inter/Roboto de Shuffle por Satoshi. La licencia permite
autoalojarla en las propias aplicaciones, pero **no redistribuirla**: este repositorio debe seguir privado.

## Uso

```bash
pnpm install                                    # el codemod usa el TypeScript del monorepo
bash b89-respond/build.sh out/ b89-respond-frontend:dev
node --test b89-respond/frontend/rebrand.test.mjs b89-respond/frontend/subpath.test.mjs
```

## Subir de versión de Shuffle

1. Cambiar `SHUFFLE_TAG` y `SHUFFLE_SHA` en `upstream.lock`.
2. Correr `bash b89-respond/build.sh out/`. Si un parche no aplica, regenerarlo con `git diff` sobre el tag nuevo.
3. Revisar en la salida del codemod las «apariciones restantes» y si apareció algún logo nuevo que
   agregar a `targets.tsv`.

## Licencia

Shuffle es AGPL-3.0. B89 Respond es una versión modificada: la imagen sirve en `/source/` el código fuente
correspondiente y la licencia. Los avisos de copyright de Shuffle se conservan. Pendiente: dictamen de
Legal (U-022).
