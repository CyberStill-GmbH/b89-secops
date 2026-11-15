/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 *
 * Lógica pura de la pantalla «Analista IA»: textos de códigos, lo que necesita atención,
 * filtros de la lista y uso del presupuesto. Sin React, para probarla sin montar nada.
 */

import {
  actionReasonLabel,
  AI_INFERENCE_LABEL,
  AI_RUN_STATUSES,
  AI_VERDICTS,
  AiActivityFeedItem,
  AiBudget,
  AiRunStatus,
  AiRunSummary,
  AiVerdict,
  HealthTone,
  PRIORITIES,
  Priority,
} from '../../common';

// ------------------------------------------------------------------ Códigos → texto

/**
 * Códigos que el backend escribe en motivos, etapas y errores y que el catálogo común no rotula
 * (enrutamiento del triaje, decisiones del runner, validación de la salida y errores).
 * Fuente: `modules/assistant/src/investigations/{policy,runner,analyst-output}.ts`.
 */
const EXTRA_REASON_TEXT: Readonly<Record<string, string>> = {
  // Enrutamiento del triaje
  P1_ALWAYS_ANALYZED: 'Las alertas P1 siempre se analizan con el modelo avanzado',
  P2_ROUTINE: 'P2 sin señales de ambigüedad: análisis con el modelo económico',
  P2_MULTI_SOURCE: 'P2 con señales de varias fuentes',
  P2_MULTI_TACTIC: 'P2 con varias tácticas de ataque',
  P2_CONTRADICTORY_HISTORY: 'El patrón tiene historial contradictorio (positivos y falsos positivos)',
  P3_CORRELATED: 'P3 correlacionada con otras alertas',
  BELOW_INFERENCE_PRIORITY: 'La prioridad está por debajo del umbral para usar IA',
  RULE_ASSESSMENT_BENIGN:
    'La valoración por reglas concluyó actividad habitual sin señales de riesgo',
  RULE_ASSESSMENT_RISK: 'La valoración por reglas encontró señales de riesgo o urgencia',
  // Decisiones del runner
  INFERENCE_DISABLED: 'La IA está desactivada (sin techo diario)',
  MODEL_UNAVAILABLE: 'El modelo no estaba disponible',
  TIER_DOWNGRADED: 'Se usó el modelo económico porque el avanzado no está permitido',
  EVIDENCE_PACK_OVER_BUDGET: 'La evidencia excede el tamaño permitido para el modelo',
  EVIDENCE_SAMPLED_FOR_MODEL:
    'El modelo vio una muestra de los eventos; los conteos totales sí se consideraron',
  REUSED_PRIOR_RESULT: 'Se reutilizó un resultado verificado anterior, sin costo adicional',
  PRIOR_INFERENCE_SETTLED: 'Ya hubo una llamada al modelo para esta investigación',
  DAILY_CAP: 'Se alcanzó el techo diario de gasto en IA',
  RUN_CAP: 'Se alcanzó el máximo de llamadas al modelo por investigación',
  USAGE_UNRECONCILED: 'Hay una llamada al modelo cuyo consumo no se confirmó',
  MODEL_REFUSED: 'El modelo se negó a responder',
  INVALID_MODEL_OUTPUT: 'La respuesta del modelo no tenía el formato esperado',
  UNVERIFIED_OUTPUT: 'Las afirmaciones no se pudieron verificar contra la evidencia',
  // Validación de la salida
  UNKNOWN_CITATION: 'Cita a evidencia que no existe',
  UNCITED_FACT: 'Hay hechos sin cita a la evidencia',
  FORBIDDEN_RECOMMENDATION: 'Recomendó algo que la política no permite',
  TRUNCATED_FIELD: 'Parte de la respuesta se recortó por exceder el tamaño',
  MALFORMED_JSON: 'La respuesta del modelo no se pudo leer',
  SCHEMA_VIOLATION: 'La respuesta del modelo no cumple el formato esperado',
  EMPTY_OUTPUT: 'El modelo devolvió una respuesta vacía',
  // Errores de la corrida o de una acción
  MODEL_NOT_SENT: 'La llamada al modelo no llegó a enviarse',
  MODEL_TIMEOUT: 'El modelo tardó demasiado en responder',
  MODEL_OUTCOME_UNKNOWN: 'No se sabe si el modelo respondió',
  EVIDENCE_UNAVAILABLE: 'No se pudo obtener la evidencia',
  LEASE_LOST: 'Otro proceso tomó la investigación',
  LEASE_EXPIRED_MAX_ATTEMPTS: 'Se agotaron los reintentos automáticos',
  STALE_LEASE: 'La investigación quedó sin dueño y se retomó',
  HOST_SHUTDOWN: 'El servicio se reinició durante la investigación',
  INTERNAL_ERROR: 'Error interno del servicio',
  UNKNOWN_ERROR: 'Error no identificado',
  INVALID_SETTINGS: 'La configuración guardada no es válida',
  INVALID_JOB: 'La investigación tenía datos no válidos',
  CANCELLED: 'Detenida a pedido de una persona',
  ACTION_FAILED: 'La acción no se pudo aplicar',
  NO_ACTION_PORT: 'Este entorno no permite ejecutar la acción',
  NO_REPORT_PORT: 'Este entorno no permite adjuntar informes',
  NO_RESULT: 'No había resultado sobre el que actuar',
  ESCALATED: 'Escalada a incidente',
};

/** Texto en español de un código del backend; `null` si esta consola no lo conoce. */
export function reasonText(code: string | null | undefined): string | null {
  if (!code) return null;
  const known = actionReasonLabel(code);
  if (known) return known;
  return Object.prototype.hasOwnProperty.call(EXTRA_REASON_TEXT, code)
    ? EXTRA_REASON_TEXT[code]
    : null;
}

/** Claves de detalle de una etapa que se pueden contar en lenguaje llano. */
const DETAIL_KEY_TEXT: Readonly<Record<string, string>> = {
  reason: 'Motivo',
  verified: 'Verificado',
  issues: 'Observaciones',
  facts: 'Hechos',
  citations: 'Citas',
  tier: 'Nivel',
  alerts: 'Alertas',
  events: 'Eventos',
  sources: 'Fuentes',
  truncated: 'Evidencia recortada',
  complete: 'Evidencia completa',
  estimatedInputTokens: 'Tokens estimados de entrada',
};

export interface DetailEntry {
  readonly key: string;
  /** Rótulo legible; `null` si la clave no se conoce (va solo en «Detalles técnicos»). */
  readonly label: string | null;
  readonly text: string;
  /** Códigos sin rótulo propio, para mostrarlos como etiqueta pequeña. */
  readonly codes: readonly string[];
}

/** Detalle de una etapa en lenguaje llano: booleanos en sí/no y códigos con su texto. */
export function describeDetail(
  detail: Readonly<Record<string, string | number | boolean>>,
): DetailEntry[] {
  return Object.keys(detail).map((key) => {
    const value = detail[key];
    const label = Object.prototype.hasOwnProperty.call(DETAIL_KEY_TEXT, key)
      ? DETAIL_KEY_TEXT[key]
      : null;
    if (typeof value === 'boolean') return { key, label, text: value ? 'Sí' : 'No', codes: [] };
    if (typeof value === 'number') return { key, label, text: value.toLocaleString('es-PE'), codes: [] };
    if (key === 'tier' && (value === 'none' || value === 'economy' || value === 'advanced')) {
      return { key, label, text: AI_INFERENCE_LABEL[value], codes: [] };
    }
    const parts = value
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.length > 0);
    const looksLikeCodes = parts.length > 0 && parts.every((part) => /^[A-Z][A-Z0-9_]+$/u.test(part));
    if (!looksLikeCodes) return { key, label, text: value, codes: [] };
    const texts: string[] = [];
    const codes: string[] = [];
    for (const part of parts) {
      const human = reasonText(part);
      if (human) texts.push(human);
      else codes.push(part);
    }
    return { key, label, text: texts.join('; '), codes };
  });
}

// ------------------------------------------------------------------ Atención

/** Estados terminados que piden que una persona mire el expediente. */
export const ATTENTION_STATUSES: readonly AiRunStatus[] = [
  'requires_review',
  'failed',
  'partial',
  'budget_exhausted',
  'usage_unreconciled',
];

export function needsAttention(run: Pick<AiRunSummary, 'status'>): boolean {
  return (ATTENTION_STATUSES as readonly string[]).includes(run.status);
}

const PRIORITY_RANK: Readonly<Record<Priority, number>> = { P1: 0, P2: 1, P3: 2, P4: 3 };

function rank(priority: Priority | null): number {
  return priority ? PRIORITY_RANK[priority] : 4;
}

function timeOf(iso: string | null): number {
  if (!iso) return 0;
  const value = new Date(iso).getTime();
  return Number.isNaN(value) ? 0 : value;
}

export interface AttentionItem {
  readonly key: string;
  readonly jobId: string;
  readonly title: string;
  readonly priority: Priority | null;
  readonly kind: 'review' | 'failed' | 'escalated';
  readonly at: string | null;
}

export interface AttentionSummary {
  /** Investigaciones que terminaron en «Requiere revisión» en la ventana. */
  readonly review: number;
  /** Fallidas, parciales, sin presupuesto o con uso por conciliar en la ventana. */
  readonly failed: number;
  /** Escaladas a incidente en la ventana (acciones ejecutadas del feed). */
  readonly escalated: number;
  /** Alguna lista llegó llena: el conteo puede ser mayor. */
  readonly capped: boolean;
  /** Lo más urgente primero: prioridad y luego lo más reciente. */
  readonly items: readonly AttentionItem[];
}

export const ATTENTION_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Qué necesita a una persona en las últimas 24 h. Las corridas vienen de la lista (estado) y las
 * escalaciones del feed de actividad (acción ejecutada); una corrida cuenta una sola vez por tipo.
 */
export function attentionSummary(input: {
  readonly runs: readonly AiRunSummary[];
  readonly feed?: readonly AiActivityFeedItem[];
  readonly now: number;
  readonly capped?: boolean;
  readonly limit?: number;
}): AttentionSummary {
  const since = input.now - ATTENTION_WINDOW_MS;
  const items: AttentionItem[] = [];
  const seen = new Set<string>();
  let review = 0;
  let failed = 0;
  for (const run of input.runs) {
    if (!needsAttention(run) || seen.has(run.id)) continue;
    const at = run.finishedAt ?? run.updatedAt ?? run.createdAt;
    if (timeOf(at) < since) continue;
    seen.add(run.id);
    const kind = run.status === 'requires_review' ? 'review' : 'failed';
    if (kind === 'review') review += 1;
    else failed += 1;
    items.push({
      key: `${kind}:${run.id}`,
      jobId: run.id,
      title: run.subject.title,
      priority: run.priority,
      kind,
      at,
    });
  }
  const escalatedJobs = new Set<string>();
  for (const item of input.feed ?? []) {
    if (item.kind !== 'action' || item.actionKind !== 'escalate' || item.actionState !== 'executed') {
      continue;
    }
    if (timeOf(item.at) < since || escalatedJobs.has(item.jobId)) continue;
    escalatedJobs.add(item.jobId);
    items.push({
      key: `escalated:${item.jobId}`,
      jobId: item.jobId,
      title: item.subjectTitle,
      priority: item.priority,
      kind: 'escalated',
      at: item.at,
    });
  }
  items.sort((a, b) => rank(a.priority) - rank(b.priority) || timeOf(b.at) - timeOf(a.at));
  return {
    review,
    failed,
    escalated: escalatedJobs.size,
    capped: input.capped === true,
    items: items.slice(0, input.limit ?? 6),
  };
}

// ------------------------------------------------------------------ Filtros de la lista

export type RunView = 'all' | 'attention' | 'escalated' | 'active';

export interface RunFilters {
  /** Filtro del servidor (`?status=`); vacío = todos. */
  readonly status: AiRunStatus | '';
  readonly view: RunView;
  readonly verdict: AiVerdict | 'none' | '';
  readonly priorities: readonly Priority[];
  readonly query: string;
}

export const EMPTY_FILTERS: RunFilters = {
  status: '',
  view: 'all',
  verdict: '',
  priorities: [],
  query: '',
};

export const RUN_VIEW_LABEL: Readonly<Record<RunView, string>> = {
  all: 'Todas',
  attention: 'Requieren atención',
  escalated: 'Escaladas',
  active: 'En curso',
};

export function parseRunStatus(value: string): AiRunStatus | '' {
  return (AI_RUN_STATUSES as readonly string[]).includes(value) ? (value as AiRunStatus) : '';
}

export function parseVerdictFilter(value: string): RunFilters['verdict'] {
  if (value === 'none') return 'none';
  return (AI_VERDICTS as readonly string[]).includes(value) ? (value as AiVerdict) : '';
}

/** Filtros que se aplican en el navegador sobre lo ya cargado (el estado lo filtra el servicio). */
export function filterRuns(items: readonly AiRunSummary[], filters: RunFilters): AiRunSummary[] {
  const term = filters.query.trim().toLocaleLowerCase('es');
  return items.filter((run) => {
    if (filters.view === 'attention' && !needsAttention(run)) return false;
    if (filters.view === 'escalated' && !run.actionKinds.includes('escalate')) return false;
    if (filters.view === 'active' && run.status !== 'queued' && run.status !== 'running') return false;
    if (filters.verdict === 'none' && run.verdict !== null) return false;
    if (filters.verdict && filters.verdict !== 'none' && run.verdict !== filters.verdict) return false;
    if (filters.priorities.length > 0 && (!run.priority || !filters.priorities.includes(run.priority))) {
      return false;
    }
    if (term) {
      const haystack = `${run.subject.title} ${run.subject.id} ${run.id}`.toLocaleLowerCase('es');
      if (!haystack.includes(term)) return false;
    }
    return true;
  });
}

/** Hay algún filtro aplicado (para ofrecer «Quitar filtros» y explicar una lista vacía). */
export function hasFilters(filters: RunFilters): boolean {
  return (
    filters.status !== '' ||
    filters.view !== 'all' ||
    filters.verdict !== '' ||
    filters.priorities.length > 0 ||
    filters.query.trim() !== ''
  );
}

export function togglePriority(list: readonly Priority[], priority: Priority): Priority[] {
  return list.includes(priority)
    ? list.filter((value) => value !== priority)
    : PRIORITIES.filter((value) => value === priority || list.includes(value));
}

// ------------------------------------------------------------------ Veredicto

export const VERDICT_TONE: Readonly<Record<AiVerdict | 'unknown', HealthTone>> = {
  likely_true_positive: 'fail',
  likely_false_positive: 'ok',
  inconclusive: 'warn',
  unknown: 'neutral',
};

export function verdictTone(verdict: AiRunSummary['verdict']): HealthTone {
  return verdict === null ? 'neutral' : VERDICT_TONE[verdict];
}

/** Escalón de confianza 0–3 para el medidor (0 = sin dato). */
export function confidenceStep(confidence: AiRunSummary['confidence']): 0 | 1 | 2 | 3 {
  switch (confidence) {
    case 'low':
      return 1;
    case 'medium':
      return 2;
    case 'high':
      return 3;
    default:
      return 0;
  }
}

// ------------------------------------------------------------------ Presupuesto

export interface BudgetUsage {
  /** Uso confirmado + reservado, en micro-USD; `null` si no llegó ninguno. */
  readonly usedMicroUsd: number | null;
  readonly limitMicroUsd: number | null;
  /** Porción del techo (0–1, puede pasar de 1); `null` sin techo o sin uso. */
  readonly share: number | null;
  /** Escalón para el medidor: 0–20 (5 % cada uno), sin estilos en línea. */
  readonly step: number;
  readonly tone: HealthTone;
}

export function budgetUsage(budget: AiBudget): BudgetUsage {
  const { settledMicroUsd, reservedMicroUsd, limitMicroUsd } = budget.day;
  const used =
    settledMicroUsd === null && reservedMicroUsd === null
      ? null
      : (settledMicroUsd ?? 0) + (reservedMicroUsd ?? 0);
  const share =
    used === null || limitMicroUsd === null || limitMicroUsd <= 0 ? null : used / limitMicroUsd;
  const step = share === null ? 0 : Math.max(used! > 0 ? 1 : 0, Math.min(20, Math.round(share * 20)));
  const tone: HealthTone =
    share === null ? 'neutral' : share >= 1 ? 'fail' : share >= 0.8 ? 'warn' : 'ok';
  return { usedMicroUsd: used, limitMicroUsd, share, step, tone };
}

/** «32 %» sin decimales para el medidor; `null` sin dato. */
export function percentText(share: number | null): string | null {
  if (share === null) return null;
  return `${Math.round(share * 100)} %`;
}
