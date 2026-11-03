#!/usr/bin/env python3
"""
Arte de marca del dashboard B89 SOC a partir de los recursos oficiales de B89.

    python wazuh/dashboard/assets/tools/build-brand.py

Fuentes (ver docs/brand/b89-visual-identity.md):
  - Monograma oficial: docs/brand/assets/logo/b89-mark-{gradient,dark,light}.png. Solo se escala; no se
    redibuja, recolorea ni deforma.
  - Tipografía: Satoshi Bold (assets/fonts/satoshi-bold.woff2, licencia ITF FFL). El texto «SOC»/«B89 SOC»
    del logotipo se convierte a trazos con fontTools para que el SVG no dependa de la fuente instalada
    (uso normal de la fuente para un logotipo; no se modifica la fuente).
  - Paleta: Coral #FF5841, Fucsia #FF5899, Amarillo #FFC136, Lima #D0E870, Turquesa #00DFC2,
    Azul #119CFF, Lavanda #CDCCED.

Requiere: pillow, fonttools, brotli.

Genera en assets/: images/b89-mark-gradient-256.png, svg/b89_mark_on_{dark,light}.svg, svg/b89_wordmark_on_{dark,light}.svg,
svg/b89_app_icon.svg, svg/b89_safari_pinned_tab.svg, svg/b89_login_bg.svg, favicons/*.png|ico y
wazuh-app/logo_reports.png. Los PNG se versionan para que CI no necesite regenerarlos.
"""

import base64
import io
import pathlib

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE.parent
LOGOS = HERE.parents[3] / 'docs' / 'brand' / 'assets' / 'logo'
FONT = ASSETS / 'fonts' / 'satoshi-bold.woff2'

CORAL, FUCHSIA, YELLOW = '#FF5841', '#FF5899', '#FFC136'
INK_ON_LIGHT = '#000000'
INK_ON_DARK = '#FFFFFF'


def mark(name):
    return Image.open(LOGOS / f'b89-mark-{name}.png').convert('RGBA')


def scaled(im, size):
    return im.resize((size, size), Image.LANCZOS)


def b64(im):
    buf = io.BytesIO()
    im.save(buf, 'PNG', optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


def text_path(text, size, x, baseline, fill, tracking=0.0):
    """Texto de Satoshi Bold como `<path>` (sin depender de la fuente instalada)."""
    font = TTFont(FONT)
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    scale = size / font['head'].unitsPerEm
    d, cursor = [], x
    for char in text:
        name = cmap[ord(char)]
        pen = SVGPathPen(glyphs)
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, cursor, baseline)))
        d.append(pen.getCommands())
        cursor += glyphs[name].width * scale + tracking
    return f'<path fill="{fill}" d="{" ".join(d)}"/>', cursor - x


def svg(width, height, label, body):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{label}"><title>{label}</title>{body}</svg>\n'
    )


def image(im, x, y, size):
    return f'<image href="data:image/png;base64,{b64(scaled(im, size * 4))}" x="{x}" y="{y}" width="{size}" height="{size}"/>'


def wordmark(logo, ink):
    height = 64
    text, advance = text_path('B89 SOC', 30, 74, 41, ink, tracking=0.6)
    return svg(round(74 + advance + 6), height, 'B89 SOC', image(logo, 0, 0, height) + text)


def write(path, content):
    path = ASSETS / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def raster():
    gradient = mark('gradient')
    fav = ASSETS / 'favicons'
    fav.mkdir(parents=True, exist_ok=True)
    for name, size in {
        'android-chrome-192x192.png': 192,
        'android-chrome-512x512.png': 512,
        'apple-touch-icon.png': 180,
        'favicon-16x16.png': 16,
        'favicon-32x32.png': 32,
        'mstile-70x70.png': 70,
        'mstile-144x144.png': 144,
        'mstile-150x150.png': 150,
        'mstile-310x310.png': 310,
    }.items():
        scaled(gradient, size).save(fav / name, optimize=True)
    wide = Image.new('RGBA', (310, 150), (0, 0, 0, 0))
    wide.alpha_composite(scaled(gradient, 130), (90, 10))
    wide.save(fav / 'mstile-310x150.png', optimize=True)
    gradient.save(fav / 'favicon.ico', sizes=[(16, 16), (32, 32), (48, 48)])
    # Logo de los PDF de reportes de la app (369×74): monograma + «B89 SOC» sobre blanco.
    report = Image.new('RGBA', (369, 74), (255, 255, 255, 255))
    report.alpha_composite(scaled(gradient, 66), (4, 4))
    path_markup, _ = text_path('B89 SOC', 34, 84, 50, '#000000', tracking=0.6)
    report_svg = svg(369, 74, 'B89 SOC', '<rect width="369" height="74" fill="#fff"/>' + image(gradient, 4, 4, 66) + path_markup)
    try:
        import cairosvg  # type: ignore

        cairosvg.svg2png(bytestring=report_svg.encode(), write_to=str(ASSETS / 'wazuh-app' / 'logo_reports.png'))
    except ImportError:
        # Sin cairosvg: solo monograma (el texto se dibuja con la fuente vía PIL).
        from PIL import ImageDraw, ImageFont

        ttf = HERE / '_satoshi-bold.ttf'
        font = TTFont(FONT)
        font.flavor = None
        font.save(ttf)
        draw = ImageDraw.Draw(report)
        draw.text((84, 37), 'B89 SOC', font=ImageFont.truetype(str(ttf), 34), fill=(0, 0, 0, 255), anchor='lm')
        ttf.unlink()
        (ASSETS / 'wazuh-app').mkdir(exist_ok=True)
        report.save(ASSETS / 'wazuh-app' / 'logo_reports.png', optimize=True)


def main():
    dark, gradient = mark('dark'), mark('gradient')
    write('svg/b89_mark_on_dark.svg', svg(64, 64, 'B89', image(dark, 0, 0, 64)))
    write('svg/b89_mark_on_light.svg', svg(64, 64, 'B89', image(gradient, 0, 0, 64)))
    write('svg/b89_wordmark_on_dark.svg', wordmark(dark, INK_ON_DARK))
    write('svg/b89_wordmark_on_light.svg', wordmark(gradient, INK_ON_LIGHT))
    write('svg/b89_app_icon.svg', svg(512, 512, 'B89', image(gradient, 0, 0, 512)))
    write('svg/b89_safari_pinned_tab.svg', svg(64, 64, 'B89', image(mark('light'), 0, 0, 64)))
    write(
        'svg/b89_login_bg.svg',
        svg(
            1119,
            539,
            '',
            '<defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="#FF5899"/>'
            '<stop offset=".55" stop-color="#FF5841"/><stop offset="1" stop-color="#FFC136"/></linearGradient></defs>'
            '<rect width="1119" height="539" fill="url(#g)"/>',
        ),
    )
    scaled(gradient, 256).save(ASSETS / 'images' / 'b89-mark-gradient-256.png', optimize=True)  # insignia del login
    raster()
    for path in sorted(ASSETS.glob('svg/b89_*')) + sorted(ASSETS.glob('favicons/*')):
        print(f'{path.relative_to(ASSETS)}: {path.stat().st_size} B')


if __name__ == '__main__':
    main()
