#!/usr/bin/env node
/* Copyright B89. SPDX-License-Identifier: Apache-2.0
 * Regenera envoltorios SVG y favicons desde el logotipo oficial extraído del PDF B89 2026.
 * El monograma raster original se incrusta sin redibujar ni alterar sus colores.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const svgDir = join(root, 'svg');
const favDir = join(root, 'favicons');
const appDir = join(root, 'wazuh-app');
const imagesDir = join(root, 'images');
const gradient = readFileSync(join(imagesDir, 'b89-mark-gradient.png'));
const light = readFileSync(join(imagesDir, 'b89-mark-light.png'));
const b64 = (bytes) => bytes.toString('base64');
const svg = (w, h, label, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${label}">${body}</svg>\n`;
const image = (bytes, x, y, size) => `<image href="data:image/png;base64,${b64(bytes)}" x="${x}" y="${y}" width="${size}" height="${size}" preserveAspectRatio="xMidYMid meet"/>`;
const wordmark = (bytes, color, secondary) => svg(480, 96, 'B89 SOC', image(bytes, 8, 8, 80) + `<text x="108" y="59" fill="${color}" font-family="Satoshi,Arial,sans-serif" font-size="42" font-weight="700">B89 SOC</text><text x="110" y="82" fill="${secondary}" font-family="Satoshi,Arial,sans-serif" font-size="13" font-weight="500" letter-spacing="2.5">SECURITY OPERATIONS</text>`);
const darkWordmark = wordmark(gradient, '#f7f5fb', '#cdcced');
const lightWordmark = wordmark(light, '#17171d', '#555560');
const files = {
  'b89_mark_on_dark.svg': svg(64,64,'B89 SOC',image(gradient,0,0,64)),
  'b89_mark_on_light.svg': svg(64,64,'B89 SOC',image(light,0,0,64)),
  'b89_wordmark_on_dark.svg': darkWordmark,
  'b89_wordmark_on_light.svg': lightWordmark,
  'b89_login_bg.svg': svg(1119,539,'B89 SOC','<defs><linearGradient id="g"><stop stop-color="#ff5899"/><stop offset=".55" stop-color="#ff5841"/><stop offset="1" stop-color="#ffc136"/></linearGradient></defs><rect width="1119" height="539" fill="#101014"/><circle cx="910" cy="260" r="205" fill="url(#g)" opacity=".12"/>'),
  'b89_app_icon.svg': svg(512,512,'B89 SOC',image(gradient,0,0,512)),
  'b89_safari_pinned_tab.svg': svg(64,64,'B89 SOC',image(light,0,0,64)),
};
mkdirSync(svgDir,{recursive:true}); mkdirSync(favDir,{recursive:true}); mkdirSync(appDir,{recursive:true});
for (const [name, content] of Object.entries(files)) writeFileSync(join(svgDir,name),content);
writeFileSync(join(favDir,'manifest.json'),JSON.stringify({name:'B89 SOC',short_name:'B89 SOC',icons:[{src:'android-chrome-192x192.png',sizes:'192x192',type:'image/png'},{src:'android-chrome-512x512.png',sizes:'512x512',type:'image/png',purpose:'any maskable'}],theme_color:'#101014',background_color:'#101014',display:'standalone'},null,2)+'\n');
writeFileSync(join(favDir,'browserconfig.xml'),'<?xml version="1.0" encoding="utf-8"?>\n<browserconfig><msapplication><tile><square150x150logo src="/ui/favicons/mstile-150x150.png"/><TileColor>#101014</TileColor></tile></msapplication></browserconfig>\n');
if (process.argv.includes('--raster')) {
  const require=createRequire(join(process.cwd(),'noop.js')); const sharp=require('sharp');
  const sizes=new Map([[16,'favicon-16x16.png'],[32,'favicon-32x32.png'],[70,'mstile-70x70.png'],[144,'mstile-144x144.png'],[150,'mstile-150x150.png'],[180,'apple-touch-icon.png'],[192,'android-chrome-192x192.png'],[310,'mstile-310x310.png'],[512,'android-chrome-512x512.png']]);
  const png=async(size)=>sharp(gradient).resize(size,size,{fit:'contain'}).png().toBuffer();
  for(const [size,name] of sizes) writeFileSync(join(favDir,name),await png(size));
  writeFileSync(join(favDir,'mstile-310x150.png'),await sharp({create:{width:310,height:150,channels:4,background:'#101014'}}).composite([{input:await png(128),top:11,left:91}]).png().toBuffer());
  const imgs=await Promise.all([16,32,48].map(async(size)=>({size,data:await png(size)}))); const head=Buffer.alloc(6); head.writeUInt16LE(1,2); head.writeUInt16LE(imgs.length,4); let offset=6+16*imgs.length; const entries=[];
  for(const img of imgs){const e=Buffer.alloc(16);e.writeUInt8(img.size,0);e.writeUInt8(img.size,1);e.writeUInt16LE(1,4);e.writeUInt16LE(32,6);e.writeUInt32LE(img.data.length,8);e.writeUInt32LE(offset,12);offset+=img.data.length;entries.push(e);}
  writeFileSync(join(favDir,'favicon.ico'),Buffer.concat([head,...entries,...imgs.map((x)=>x.data)]));
  writeFileSync(join(appDir,'logo_reports.png'),await sharp(light).resize(74,74,{fit:'contain'}).png().toBuffer());
}
console.log('Assets B89 generados desde los logos oficiales.');