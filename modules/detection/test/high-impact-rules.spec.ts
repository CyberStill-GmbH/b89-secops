/**
 * Aprendizaje SOC · fase 3 — piso de impacto: la lista generada está al día y se interpreta bien.
 */

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { HIGH_IMPACT_RULES } from '../src/high-impact-rules.generated.js';
import { isHighImpactRuleKey } from '../src/rule-key.js';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

describe('piso de impacto (reglas de alto impacto)', () => {
  it('high-impact-rules.generated.ts está al día con detections/**/metadata.yaml', () => {
    expect(() =>
      execFileSync('node', ['scripts/soc-learning/generate-high-impact-rules.mjs', '--check'], {
        cwd: ROOT,
        stdio: 'pipe',
      }),
    ).not.toThrow();
  });

  it('reconoce la regla por su ID numérico con cualquier prefijo de fuente', () => {
    const [id] = [...HIGH_IMPACT_RULES.keys()];
    expect(isHighImpactRuleKey(`cloudflare:${id}`)).toBe(true);
    expect(isHighImpactRuleKey(`otra-fuente:${id}`)).toBe(true);
    expect(isHighImpactRuleKey('linux-process:100200')).toBe(false);
    expect(isHighImpactRuleKey('b89-correlator:edge-to-ssh')).toBe(false);
    expect(isHighImpactRuleKey(null)).toBe(false);
  });

  it('la lista no está vacía y cada entrada dice por qué', () => {
    expect(HIGH_IMPACT_RULES.size).toBeGreaterThan(100);
    for (const reasons of HIGH_IMPACT_RULES.values())
      expect(reasons).toMatch(/^(tactic:|priority_hint:)/u);
  });
});
