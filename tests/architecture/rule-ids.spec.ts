/**
 * Aprendizaje SOC · T5 — integridad de los IDs de regla que alimentan la clave `fuente:rule_id`.
 *
 * 1. `detections/catalog.yaml#id_ranges` no tiene rangos solapados ni invertidos.
 * 2. `modules/detection/src/rule-sources.generated.ts` está al día con el catálogo.
 * 3. Ningún ID de regla B89 (≥ 100000) se define en dos archivos de reglas distintos.
 *
 * El punto 3 tiene una deuda conocida y explícita: el monitor de plataforma reutiliza el rango
 * 1018xx de las detecciones de red (42 IDs). Se lista exacta: cualquier colisión NUEVA falla, y
 * cuando los dueños la corrijan esta spec también falla para que se retire la excepción.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { COLLIDING_RULE_IDS, RULE_SOURCE_RANGES } from '../../modules/detection/src/rule-key.js';

const ROOT = resolve(import.meta.dirname, '../..');

/**
 * Colisión conocida (2026-11-24): `wazuh/platform-monitoring` (owner: monitoreo de plataforma)
 * usa IDs del rango `network` (owner: network-visibility). Afecta a `notification-enricher`
 * (asume 101800–101849 = plataforma) y a la clave de regla, que los marca como `network:`.
 * Corregir renumerando en el dueño correspondiente; no se renumera desde aquí.
 */
const KNOWN_COLLISIONS: Readonly<Record<string, readonly number[]>> = Object.freeze({
  'detections/linux/network-connections/rule.xml|wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml':
    [101800, 101801, 101802, 101804, 101805, 101806, 101807, 101808, 101809],
  'detections/linux/network-auditd/rule.xml|wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml':
    [101810, 101811, 101812, 101814, 101815, 101816, 101817, 101818],
  'detections/linux/ssh-session-tracking/rule.xml|wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml':
    [101820, 101821],
  'detections/edge/http-attacks/rule.xml|wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml':
    [101830, 101831, 101832, 101833, 101834, 101835],
  'detections/linux/docker-runtime/rule.xml|wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml':
    [101850, 101851, 101852],
  'detections/network/threat-intel/rule.xml|wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml':
    [101860, 101861, 101862, 101863, 101864, 101865, 101866, 101867],
  'detections/network/cross-source-correlation/rule.xml|wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml':
    [101870, 101871, 101872, 101873, 101874, 101875],
});

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
