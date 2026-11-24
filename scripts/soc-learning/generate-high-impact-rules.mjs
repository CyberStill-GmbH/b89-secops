#!/usr/bin/env node
// Aprendizaje SOC · fase 3 — piso de impacto inconfigurable.
//
// Lee cada `detections/**/metadata.yaml` (ids de regla, tácticas MITRE y `priority_hint`) y genera
// `modules/detection/src/high-impact-rules.generated.ts`: los IDs de regla de alto impacto, que el
// motor NUNCA puede autocerrar y que la configuración rechaza en `B89_LEARNING_ACTIVE_RULES`.
//
// Alto impacto (conservador): alguna táctica en la lista de exclusión del diseño (§6.1) o un
// `priority_hint` que menciona P1 o P2.
//
//   node scripts/soc-learning/generate-high-impact-rules.mjs          # regenera
//   node scripts/soc-learning/generate-high-impact-rules.mjs --check  # solo comprueba (CI)
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));
const DETECTIONS = join(repo, 'detections');
export const GENERATED_PATH = join(repo, 'modules/detection/src/high-impact-rules.generated.ts');

export const HIGH_IMPACT_TACTICS = [
  'command-and-control',
  'credential-access',
  'defense-evasion',
  'exfiltration',
  'impact',
  'lateral-movement',
  'persistence',
  'privilege-escalation',
];

function metadataFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) found.push(...metadataFiles(path));
    else if (entry === 'metadata.yaml') found.push(path);
  }
  return found.sort();
}

/** Lectura mínima y estricta de los tres campos que importan. */
export function parseMetadata(text, path) {
  const lines = text.split(/\r?\n/u);
  const ids = [];
  // Forma en línea: `ids: [101800, 101801, …]`, posiblemente partida en varias líneas.
  const inline = /^\s{2}ids:\s*\[([^\]]*)\]/mu.exec(text);
  if (inline) {
    for (const item of inline[1].split(',')) {
      const value = item.trim();
      if (value === '') continue;
      if (!/^\d+$/u.test(value)) throw new Error(`id no numérico «${value}» en ${path}`);
      ids.push(Number(value));
    }
  }
  let inIds = false;
  for (const line of lines) {
    if (/^\s{2}ids:\s*$/u.test(line)) {
      inIds = true;
      continue;
    }
    if (inIds) {
      const match = /^\s{2}-\s*(\d+)\s*$/u.exec(line);
      if (match) ids.push(Number(match[1]));
      else if (line.trim() !== '') inIds = false;
    }
  }
  const tactics = [...text.matchAll(/^\s+tactic:\s*([a-z-]+)\s*$/gmu)].map((match) => match[1]);
  const hint = /^\s+priority_hint:\s*(.+)$/mu.exec(text)?.[1] ?? '';
  if (ids.length === 0 && /\n\s{2}ids:/u.test(text)) throw new Error(`ids sin números en ${path}`);
  return { ids, tactics, hint };
}

export function collect() {
  const rules = new Map();
  for (const path of metadataFiles(DETECTIONS)) {
    const { ids, tactics, hint } = parseMetadata(readFileSync(path, 'utf8'), path);
    const reasons = [
      ...new Set([
        ...tactics.filter((tactic) => HIGH_IMPACT_TACTICS.includes(tactic)).map((tactic) => `tactic:${tactic}`),
        ...(/\bP[12]\b/u.test(hint) ? ['priority_hint:P1-P2'] : []),
      ]),
    ].sort();
    if (reasons.length === 0) continue;
    for (const id of ids) rules.set(id, [...new Set([...(rules.get(id) ?? []), ...reasons])].sort());
  }
  return [...rules.entries()].sort((left, right) => left[0] - right[0]);
}

export function renderGenerated(rules) {
  const rows = rules.map(([id, reasons]) => `  [${id}, '${reasons.join(',')}'],`).join('\n');
  return `/* Generado por scripts/soc-learning/generate-high-impact-rules.mjs desde los metadata.yaml de detections. No editar a mano. */

/** IDs de regla de alto impacto y por qué (táctica MITRE o \`priority_hint\` P1/P2). */
export const HIGH_IMPACT_RULES: ReadonlyMap<number, string> = new Map<number, string>([
${rows}
]);
`;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const expected = renderGenerated(collect());
  if (process.argv.includes('--check')) {
    const current = readFileSync(GENERATED_PATH, 'utf8').replace(/\r\n/gu, '\n');
    if (current !== expected) {
      process.stderr.write('high-impact-rules.generated.ts desactualizado: ejecute el generador.\n');
      process.exit(1);
    }
  } else {
    writeFileSync(GENERATED_PATH, expected);
  }
}
