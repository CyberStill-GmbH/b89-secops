#!/usr/bin/env bash
# B89 Respond — build del frontend de Shuffle rebrandeado (docs/13).
#
#   bash b89-respond/build.sh <OUT_DIR> [IMAGE_REF]
#
# Desde la raíz de b89-secops, con `pnpm install` hecho (el codemod usa el TypeScript del monorepo).
#   1. Clona Shuffle en el tag fijado y verifica el SHA (b89-respond/upstream.lock).
#   2. Aplica los parches de b89-respond/frontend/patches (falla ante cualquier rechazo).
#   3. Reemplaza el arte según b89-respond/frontend/assets/targets.tsv (mismos nombres de archivo).
#   4. Corre el codemod b89-respond/frontend/rebrand.mjs (texto visible y colores).
#   5. AGPL-3.0 §13: empaqueta el código fuente modificado del frontend y lo publica DENTRO de la imagen
#      en /source/, con la licencia, para cualquier persona que use B89 Respond por red.
#   6. docker build con el Dockerfile oficial de Shuffle. Etiqueta IMAGE_REF (por defecto
#      b89-respond-frontend:<sha-b89>) y deja el código fuente también en OUT_DIR.
set -euo pipefail
OUT_DIR="${1:?uso: build.sh <OUT_DIR> [IMAGE_REF]}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/b89-respond"
# shellcheck source=upstream.lock
source "$HERE/upstream.lock"
B89_SHA="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
IMAGE_REF="${2:-b89-respond-frontend:${B89_SHA}}"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$OUT_DIR"

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$SHUFFLE_TAG" "$SHUFFLE_REPO" "$work/shuffle"
actual="$(git -C "$work/shuffle" rev-parse HEAD)"
[[ "$actual" == "$SHUFFLE_SHA" ]] || { echo "SHA de Shuffle inesperado: $actual (lock: $SHUFFLE_SHA)" >&2; exit 1; }
FE="$work/shuffle/frontend"

for patch in "$HERE"/frontend/patches/*.patch; do
  git -C "$work/shuffle" apply --whitespace=nowarn "$patch"
  echo "parche aplicado: $(basename "$patch")"
done

# Shuffle v2.3.0 provides this supported source-level subpathing pattern for reverse proxies.
# Keep the frontend deployable under the B89 edge's protected /b89-respond/ prefix.
# SSO B89 (decisión B11): sin cookie de sesión legible por JS, «Volver al SIEM» y capa de español.
node "$HERE/frontend/sso-overlay.mjs" "$FE"
node "$HERE/frontend/subpath.mjs" "$FE"

grep -v '^#' "$HERE/frontend/assets/targets.tsv" | while IFS=$'\t' read -r src dst _; do
  [[ -n "$src" ]] || continue
  [[ -f "$FE/$dst" ]] || { echo "destino de arte inexistente en upstream: $dst" >&2; exit 1; }
  cp "$HERE/frontend/assets/$src" "$FE/$dst"
done

# Tipografía oficial (Satoshi Medium/Bold, licencia ITF FFL): el patch 0004 declara el @font-face.
mkdir -p "$FE/public/fonts"
cp "$HERE"/frontend/assets/fonts/* "$FE/public/fonts/"

# Capa de español y marca en el DOM (sso-overlay.mjs la carga desde index.html).
cp "$HERE/frontend/i18n/b89-i18n.js" "$FE/public/b89-i18n.js"

node "$HERE/frontend/rebrand.mjs" "$FE"

# AGPL-3.0 §13: el código fuente correspondiente, servido por la propia aplicación.
src_name="b89-respond-frontend-source-${B89_SHA}.tar.gz"
tar -C "$work/shuffle" --exclude=node_modules -czf "$OUT_DIR/$src_name" frontend LICENSE
mkdir -p "$FE/public/source"
cp "$OUT_DIR/$src_name" "$work/shuffle/LICENSE" "$FE/public/source/"
cat >"$FE/public/source/index.html" <<HTML
<!doctype html><html lang="es"><head><meta charset="utf-8"><title>B89 Respond · código fuente</title></head>
<body style="background:#080808;color:#f4f4f5;font-family:system-ui;max-width:640px;margin:48px auto;line-height:1.6">
<h1>B89 Respond · código fuente</h1>
<p>B89 Respond es una versión modificada de Shuffle ${SHUFFLE_TAG} (commit ${SHUFFLE_SHA}), distribuida bajo la
<a style="color:#ff5841" href="LICENSE">GNU Affero General Public License v3.0</a>.</p>
<p>Código fuente correspondiente de esta versión: <a style="color:#ff5841" href="${src_name}">${src_name}</a>.</p>
<p>Modificaciones de B89: tema, marca y textos (overlay <code>b89-respond/</code> de b89-secops, ${B89_SHA}).</p>
</body></html>
HTML

if command -v docker >/dev/null 2>&1; then
  docker build --pull -t "$IMAGE_REF" "$FE"
  echo "imagen lista: $IMAGE_REF"
else
  echo "docker no disponible: se omite la imagen (fuente en $OUT_DIR/$src_name)"
fi
