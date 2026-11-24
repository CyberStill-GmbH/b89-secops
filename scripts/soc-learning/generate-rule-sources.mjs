#!/usr/bin/env node
// Aprendizaje SOC · fuente única de los rangos de regla para la clave `fuente:rule_id`.
//
// Lee `detections/catalog.yaml#id_ranges` (única fuente de verdad) y genera
// `modules/detection/src/rule-sources.generated.ts`. Una spec de `modules/detection` falla con
// un mensaje claro si el archivo generado no coincide con el catálogo.
//
//   node scripts/soc-learning/generate-rule-sources.mjs          # regenera
//   node scripts/soc-learning/generate-rule-sources.mjs --check  # solo comprueba (CI)
//
// Sin dependencias: `id_ranges` usa mapas en línea `{from: N, to: N, source: x, ...}`. Una línea
// del bloque con otra forma es un error, no se ignora.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));
export const CATALOG_PATH = `${repo}detections/catalog.yaml`;
export const GENERATED_PATH = `${repo}modules/detection/src/rule-sources.generated.ts`;

/** Rangos del catálogo en orden de aparición. Lanza si el bloque no tiene la forma esperada. */
export function parseIdRanges(catalog) {
  const start = catalog.indexOf('\nid_ranges:');
  if (start === -1) throw new Error('catalog.yaml no tiene id_ranges');
  const lines = catalog
    .slice(start + 1)
    .split('\n')
    .slice(1);
  const ranges = [];
  for (const line of lines) {
    if (/^\S/u.test(line)) break; // siguiente clave de primer nivel
    if (/^\s*(#.*)?$/u.test(line)) continue; // vacía o comentario
    const match = /^\s+-\s*\{from:\s*(\d+),\s*to:\s*(\d+),\s*source:\s*([a-z0-9-]+)\s*,/u.exec(
      line,
    );
    if (!match) throw new Error(`Línea de id_ranges con forma inesperada: ${line.trim()}`);
    ranges.push({ from: Number(match[1]), to: Number(match[2]), source: match[3] });
  }
  if (ranges.length === 0) throw new Error('id_ranges está vacío');
  return ranges;
}

export function renderGenerated(ranges) {
  const rows = ranges
    .map((range) => `  { from: ${range.from}, to: ${range.to}, source: '${range.source}' },`)
    .join('\n');
  return `/* Generado por scripts/soc-learning/generate-rule-sources.mjs desde detections/catalog.yaml#id_ranges. No editar a mano. */

import type { RuleSourceRange } from './rule-key.js';

export const RULE_SOURCE_RANGES: readonly RuleSourceRange[] = Object.freeze([
${rows}
]);
`;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const expected = renderGenerated(parseIdRanges(readFileSync(CATALOG_PATH, 'utf8')));
  if (process.argv.includes('--check')) {
    const current = readFileSync(GENERATED_PATH, 'utf8').replace(/\r\n/gu, '\n');
    if (current !== expected) {
      console.error(
        'rule-sources.generated.ts no coincide con detections/catalog.yaml#id_ranges.\n' +
          'Ejecute: node scripts/soc-learning/generate-rule-sources.mjs',
      );
      process.exit(1);
    }
    console.log('rule-sources.generated.ts está al día.');
  } else {
    writeFileSync(GENERATED_PATH, expected);
    console.log(`Generado ${GENERATED_PATH}`);
  }
}
