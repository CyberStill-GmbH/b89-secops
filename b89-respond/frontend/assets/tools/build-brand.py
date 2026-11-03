#!/usr/bin/env python3
"""
Arte de B89 Respond (Shuffle rebrandeado) a partir del monograma oficial de B89.

    python b89-respond/frontend/assets/tools/build-brand.py

Fuente: docs/brand/assets/logo/b89-mark-gradient.png (recorte de la página 35 de «Formato
presentación B89 2026»). Según docs/brand/b89-visual-identity.md el monograma no se redibuja,
recolorea ni deforma: aquí solo se escala. El nombre del producto no se compone dentro del
monograma ni se simula con una tipografía sustituta (Satoshi aún no está empaquetada), así que
el «logotipo» del encabezado es el monograma y el texto «B89 Respond» lo pone la interfaz.

Genera (mismos nombres que `targets.tsv`):
  raster/b89_respond_icon_540.png  raster/b89_respond_icon_174.png  raster/b89_respond_icon_144.png  raster/favicon.ico
  svg/b89_respond_mark.svg (22x22)  svg/b89_respond_wordmark.svg (131x28)  svg/b89_respond_app_icon.svg
Los SVG incrustan el PNG escalado a 4x (nítido en pantallas densas).
"""

import base64
import io
import pathlib

from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE.parent
SOURCE = HERE.parents[3] / 'docs' / 'brand' / 'assets' / 'logo' / 'b89-mark-gradient.png'
TITLE = 'B89 Respond'


def scaled(im, size):
    return im.resize((size, size), Image.LANCZOS)


def png_b64(im):
    buf = io.BytesIO()
    im.save(buf, 'PNG', optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


def svg(width, height, image_x, image_size, b64):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{TITLE}"><title>{TITLE}</title>'
        f'<image href="data:image/png;base64,{b64}" x="{image_x}" y="{(height - image_size) / 2:g}" '
        f'width="{image_size}" height="{image_size}"/></svg>\n'
    )


def main():
    mark = Image.open(SOURCE).convert('RGBA')
    (ASSETS / 'raster').mkdir(parents=True, exist_ok=True)
    (ASSETS / 'svg').mkdir(parents=True, exist_ok=True)
    scaled(mark, 540).save(ASSETS / 'raster' / 'b89_respond_icon_540.png', optimize=True)
    scaled(mark, 174).save(ASSETS / 'raster' / 'b89_respond_icon_174.png', optimize=True)
    scaled(mark, 144).save(ASSETS / 'raster' / 'b89_respond_icon_144.png', optimize=True)
    mark.save(ASSETS / 'raster' / 'favicon.ico', sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    (ASSETS / 'svg' / 'b89_respond_mark.svg').write_text(svg(22, 22, 0, 22, png_b64(scaled(mark, 88))), encoding='utf-8')
    (ASSETS / 'svg' / 'b89_respond_wordmark.svg').write_text(svg(131, 28, 0, 28, png_b64(scaled(mark, 112))), encoding='utf-8')
    (ASSETS / 'svg' / 'b89_respond_app_icon.svg').write_text(svg(512, 512, 0, 512, png_b64(scaled(mark, 512))), encoding='utf-8')
    for path in sorted(ASSETS.glob('raster/*')) + sorted(ASSETS.glob('svg/*')):
        print(f'{path.relative_to(ASSETS)}: {path.stat().st_size} B')


if __name__ == '__main__':
    main()
