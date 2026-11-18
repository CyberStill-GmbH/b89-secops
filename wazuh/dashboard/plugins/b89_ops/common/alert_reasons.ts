/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Agrupa las razones de una alerta para leerlas como un expediente. Las alertas del correlador
 * llegan con razones prefijadas por la API (`apps/api/src/soc/correlator.controller.ts`):
 * «Explicación:», «Etapa N:», «Regla:», «Umbral …:», «Contradicción:», «Dato faltante:»,
 * «Evidencia (alertas Wazuh):», «Siguiente paso:» y «Alcance:». El texto se muestra tal cual,
 * sin el prefijo ya expresado por el título del grupo; nada se infiere ni se reescribe.
 */

export type ReasonGroupId =
  'priority' | 'chain' | 'thresholds' | 'contradictions' | 'missing' | 'evidence' | 'nextSteps';

export interface ReasonItem {
  readonly code: string;
  readonly text: string;
  /** Solo en umbrales: si la evidencia alcanzó el umbral. */
  readonly met?: boolean;
}

export interface ReasonGroup {
  readonly id: ReasonGroupId;
  readonly title: string;
  readonly hint?: string;
  readonly items: readonly ReasonItem[];
}

export interface GroupedReasons {
  /** Texto de «Alcance:» (candidato, no incidente), si la alerta vino del correlador. */
  readonly scope: string | null;
  readonly groups: readonly ReasonGroup[];
}

const GROUPS: ReadonlyArray<{ id: ReasonGroupId; title: string; hint?: string }> = [
  { id: 'priority', title: 'Motivos de la prioridad' },
  {
    id: 'chain',
    title: 'Secuencia observada',
    hint: 'El orden temporal eleva la sospecha; no demuestra causalidad por sí solo.',
  },
  { id: 'thresholds', title: 'Umbrales de la regla' },
  {
    id: 'contradictions',
    title: 'Contradicciones',
    hint: 'Evidencia que debilita la correlación. Revísela antes de escalar.',
  },
  {
    id: 'missing',
    title: 'Datos faltantes',
    hint: 'Lo que no se pudo verificar. Una cobertura incompleta no equivale a ausencia de actividad.',
  },
  { id: 'evidence', title: 'Evidencia citada' },
  { id: 'nextSteps', title: 'Siguientes pasos' },
];

const PREFIXES: ReadonlyArray<{ re: RegExp; group: ReasonGroupId; keep?: boolean }> = [
  { re: /^Explicación:\s*/u, group: 'chain' },
  { re: /^Etapa \d+:\s*/u, group: 'chain', keep: true },
  { re: /^Regla:\s*/u, group: 'thresholds', keep: true },
  { re: /^Umbral\s+/u, group: 'thresholds' },
  { re: /^Contradicción:\s*/u, group: 'contradictions' },
  { re: /^Dato faltante:\s*/u, group: 'missing' },
  { re: /^Evidencia \(alertas Wazuh\):\s*/u, group: 'evidence', keep: true },
  { re: /^Siguiente paso:\s*/u, group: 'nextSteps' },
];

const THRESHOLD = /\s·\s(cumplido|no cumplido)$/u;

export function groupAlertReasons(
  reasons: ReadonlyArray<{ readonly code: string; readonly detail: string }>,
): GroupedReasons {
  const buckets = new Map<ReasonGroupId, ReasonItem[]>();
  let scope: string | null = null;
  for (const reason of reasons) {
    const detail = reason.detail.trim();
    const scopeMatch = /^Alcance:\s*/u.exec(detail);
    if (scopeMatch) {
      scope = detail.slice(scopeMatch[0].length);
      continue;
    }
    const rule = PREFIXES.find((prefix) => prefix.re.test(detail));
    const group = rule?.group ?? 'priority';
    let text = rule && !rule.keep ? detail.replace(rule.re, '') : detail;
    let met: boolean | undefined;
    if (rule?.group === 'thresholds' && rule.re.source.startsWith('^Umbral')) {
      const match = THRESHOLD.exec(text);
      if (match) {
        met = match[1] === 'cumplido';
        text = text.slice(0, match.index);
      }
    }
    const list = buckets.get(group) ?? [];
    list.push(met === undefined ? { code: reason.code, text } : { code: reason.code, text, met });
    buckets.set(group, list);
  }
  return {
    scope,
    groups: GROUPS.filter((group) => buckets.has(group.id)).map((group) => ({
      ...group,
      items: buckets.get(group.id) ?? [],
    })),
  };
}
