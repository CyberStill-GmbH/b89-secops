/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { Alert, Priority } from '../../common';

/** Contexto del correlador que la API agrega a cada alerta de «requieren atención». */
export interface AttentionInfo {
  readonly score: number;
  readonly why: string | null;
  readonly entityRisk: number | null;
}

export type AttentionAlert = Alert & { readonly attention?: AttentionInfo };

const PRIORITY_RANK: Record<Priority, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

/** Orden histórico (prioridad y luego más reciente): el de respaldo sin correlador. */
export function sortByPriorityThenRecency(items: readonly Alert[], limit: number): AttentionAlert[] {
  return [...items]
    .sort(
      (a, b) =>
        PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
        b.occurredAt.localeCompare(a.occurredAt),
    )
    .slice(0, limit);
}

interface AttentionApi {
  get<T>(path: string, query?: Record<string, string | number | undefined>): Promise<T>;
}

/**
 * Alertas abiertas por atención (prioridad + riesgo de entidad + cadena, según la API). Si la
 * ruta falla, no existe (API anterior) o devuelve algo inesperado, usa el orden histórico sobre
 * `fallback`: la vista general nunca muestra un error por esto.
 */
export async function loadAttentionTop(
  api: AttentionApi,
  fallback: readonly Alert[],
  limit: number,
): Promise<AttentionAlert[]> {
  try {
    const response = await api.get<{ items?: unknown }>('/risk/attention', { limit });
    if (Array.isArray(response.items) && response.items.length > 0) {
      return (response.items as AttentionAlert[]).slice(0, limit);
    }
  } catch {
    // degradar al orden histórico
  }
  return sortByPriorityThenRecency(fallback, limit);
}

/** Une en castellano: «a», «a y b», «a, b y c». */
function joinSpanish(parts: readonly string[]): string {
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} y ${parts[parts.length - 1]}`;
}

/** Cada fragmento del correlador (`apps/api/src/soc/attention-ranking.ts`), en palabras llanas. */
function plainFragment(fragment: string): string {
  const text = fragment.trim();
  let match = /^Riesgo de entidad (\d+)\/100$/u.exec(text);
  if (match) return `el usuario o la IP acumula un riesgo de ${match[1]} sobre 100`;
  match = /^cadena (\d+) etapas?$/u.exec(text);
  if (match) return `encadena ${match[1]} pasos de un posible ataque`;
  if (text === 'en cadena correlada') return 'forma parte de una posible cadena de ataque';
  match = /^(\d+) fuentes$/u.exec(text);
  if (match) return `lo vieron ${match[1]} fuentes distintas`;
  match = /^(\d+) relacionadas?$/u.exec(text);
  if (match) {
    const count = Number(match[1]);
    return count === 1 ? 'tiene 1 alerta relacionada' : `tiene ${count} alertas relacionadas`;
  }
  return text;
}

/**
 * Por qué el correlador la puso arriba, sin jerga: «Arriba porque: el usuario o la IP acumula un
 * riesgo de 72 sobre 100 y lo vieron 3 fuentes distintas.» Null si no hay motivo.
 */
export function plainAttentionWhy(why: string | null | undefined): string | null {
  const parts = (why ?? '')
    .split('·')
    .map((part) => part.trim())
    .filter(Boolean)
    .map(plainFragment);
  return parts.length ? `Arriba porque: ${joinSpanish(parts)}.` : null;
}

/** Alertas sin responsable entre las cargadas; `partial` si la cola tiene más de las que se leyeron. */
export function countUnassigned(
  items: readonly Pick<Alert, 'assigneeId'>[],
  total: number,
): { readonly count: number; readonly partial: boolean } {
  return {
    count: items.filter((item) => !item.assigneeId).length,
    partial: total > items.length,
  };
}

/**
 * La línea del why sin repetir el título: si empieza por él, queda solo lo que agrega
 * (involucrados y agravante). Null si no agrega nada.
 */
export function whyBelowTitle(title: string, line: string): string | null {
  const plain = title.trim().replace(/[.;:\s]+$/u, '');
  if (!line.startsWith(plain)) return line || null;
  const rest = line.slice(plain.length).replace(/^\s*·\s*/u, '').trim();
  return rest || null;
}
