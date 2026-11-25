/**
 * Aprendizaje SOC · T5 — integridad de los IDs de regla que alimentan la clave `fuente:rule_id`.
 *
 * 1. `detections/catalog.yaml#id_ranges` no tiene rangos solapados ni invertidos.
 * 2. `modules/detection/src/rule-sources.generated.ts` está al día con el catálogo.
 * 3. Ningún ID de regla B89 (≥ 100000) se define en dos archivos de reglas distintos.
 *
 * El punto 3 tuvo una deuda conocida: el monitor de plataforma reutilizaba el rango 1018xx de las
 * detecciones de red (42 IDs). Se corrigió el 2026-11-25 renumerando el monitor a 102100-102179;
 * KNOWN_COLLISIONS queda vacío y cualquier colisión nueva falla.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { COLLIDING_RULE_IDS, RULE_SOURCE_RANGES } from '../../modules/detection/src/rule-key.js';

const ROOT = resolve(import.meta.dirname, '../..');

/**
 * Colisiones aceptadas: ninguna. Hasta 2026-11-25 `wazuh/platform-monitoring` usaba 42 IDs del
 * rango `network` (101800–101875); se renumeró a 102100–102179 (catalog.yaml#id_ranges).
 * Una colisión nueva se corrige renumerando en el dueño, no añadiéndola aquí.
 */
const KNOWN_COLLISIONS: Readonly<Record<string, readonly number[]>> = Object.freeze({});

function ruleFiles(): readonly string[] {
  return execFileSync('git', ['ls-files', '*.xml'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

/** IDs B89 definidos por archivo; ignora comentarios y `overwrite="yes"` (redefinición deliberada). */
function definedIds(file: string): readonly number[] {
  const text = readFileSync(resolve(ROOT, file), 'utf8').replace(/<!--[\s\S]*?-->/gu, '');
  const ids: number[] = [];
  for (const match of text.matchAll(/<rule\s+id="(\d+)"([^>]*)>/gu)) {
    if (/overwrite="yes"/u.test(match[2] ?? '')) continue;
    const id = Number(match[1]);
    if (id >= 100_000) ids.push(id);
  }
  return ids;
}

describe('T5 · rangos e IDs de regla', () => {
  it('COLLIDING_RULE_IDS (usada por la etapa D) es exactamente la deuda conocida', () => {
    const known = Object.values(KNOWN_COLLISIONS)
      .flat()
      .sort((a, b) => a - b);
    expect([...COLLIDING_RULE_IDS].sort((a, b) => a - b)).toEqual(known);
  });

  it('los rangos del catálogo no se solapan ni están invertidos', () => {
    const sorted = [...RULE_SOURCE_RANGES].sort((left, right) => left.from - right.from);
    const problems: string[] = [];
    for (const [index, range] of sorted.entries()) {
      if (range.from > range.to)
        problems.push(`${range.source} ${range.from}-${range.to} invertido`);
      const previous = sorted[index - 1];
      if (previous && range.from <= previous.to) {
        problems.push(
          `${previous.source} ${previous.from}-${previous.to} se solapa con ${range.source} ${range.from}-${range.to}`,
        );
      }
    }
    expect(problems, 'detections/catalog.yaml#id_ranges').toEqual([]);
  });

  it('rule-sources.generated.ts está al día con detections/catalog.yaml', () => {
    try {
      execFileSync('node', ['scripts/soc-learning/generate-rule-sources.mjs', '--check'], {
        cwd: ROOT,
        encoding: 'utf8',
        stdio: 'pipe',
      });
    } catch (error) {
      const output = (error as { stderr?: string }).stderr ?? String(error);
      throw new Error(`Rangos desalineados con el catálogo.\n${output}`, { cause: error });
    }
  });

  it('ningún ID B89 se define en dos archivos de reglas (salvo la deuda conocida, exacta)', () => {
    const owners = new Map<number, Set<string>>();
    for (const file of ruleFiles()) {
      for (const id of definedIds(file)) {
        const files = owners.get(id) ?? new Set<string>();
        files.add(file);
        owners.set(id, files);
      }
    }
    const collisions: Record<string, number[]> = {};
    for (const [id, files] of owners) {
      if (files.size < 2) continue;
      const key = [...files].sort().join('|');
      (collisions[key] ??= []).push(id);
    }
    for (const ids of Object.values(collisions)) ids.sort((left, right) => left - right);
    expect(
      collisions,
      'IDs de regla B89 repetidos entre archivos. Una colisión nueva debe resolverse renumerando; ' +
        'si se corrigió la deuda conocida, retírela de KNOWN_COLLISIONS.',
    ).toEqual(KNOWN_COLLISIONS);
  });
});
