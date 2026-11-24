/**
 * Aprendizaje SOC · etapa A — cierre estructurado de alertas (docs/soc-learning/01-diseno.md §3).
 *
 * Un cierre deja de ser solo «veredicto + nota libre»: lleva un motivo de catálogo, una
 * justificación con el dato que demuestra la decisión y al menos una referencia a evidencia.
 * Es la materia prima del aprendizaje; un motivo ambiguo no se puede aprender sin riesgo.
 *
 * El origen del cierre (`ClosureOrigin`) no lo declara el cliente: se deriva del actor
 * autenticado. Solo los cierres `human` con un motivo de `LEARNABLE_CLOSURE_REASONS` podrán
 * alimentar patrones; los del Analista IA, de scripts o del propio motor no cuentan, para que
 * un patrón no pueda sostenerse solo.
 */

import type { TriageVerdict } from './alert.js';

export const CLOSURE_REASONS = [
  'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
  'FP_REGLA_MAL_AFINADA',
  'FP_DATOS_ERRONEOS',
  'TP_BENIGNO_PRUEBA_O_PENTEST',
  'TP_RIESGO_ACEPTADO',
  'DUPLICADA',
  'TP_REAL',
] as const;
export type ClosureReason = (typeof CLOSURE_REASONS)[number];

/**
 * Veredictos compatibles con cada motivo. «Actividad legítima conocida» admite los dos
 * veredictos que la consola ya ofrece («No es real» y «Real pero esperada») porque los
 * analistas los usan de forma intercambiable para el mismo hecho.
 */
export const CLOSURE_REASON_VERDICTS: Readonly<Record<ClosureReason, readonly TriageVerdict[]>> =
  Object.freeze({
    FP_ACTIVIDAD_LEGITIMA_CONOCIDA: ['false_positive', 'benign'],
    FP_REGLA_MAL_AFINADA: ['false_positive'],
    FP_DATOS_ERRONEOS: ['false_positive'],
    TP_BENIGNO_PRUEBA_O_PENTEST: ['benign'],
    TP_RIESGO_ACEPTADO: ['benign'],
    DUPLICADA: ['duplicate'],
    TP_REAL: ['true_positive'],
  });

/** Motivos que podrán alimentar patrones de falso positivo (siempre que el origen sea humano). */
export const LEARNABLE_CLOSURE_REASONS: readonly ClosureReason[] = Object.freeze([
  'FP_ACTIVIDAD_LEGITIMA_CONOCIDA',
  'FP_REGLA_MAL_AFINADA',
]);

export const CLOSURE_ORIGINS = [
  'human',
  'ai_analyst',
  'bulk_script',
  'learning_engine',
  'service_other',
  'legacy_unknown',
] as const;
export type ClosureOrigin = (typeof CLOSURE_ORIGINS)[number];

/** Identidades de servicio conocidas. Cualquier otra `svc:` es `service_other`: nunca humana. */
const SERVICE_ORIGINS: Readonly<Record<string, ClosureOrigin>> = Object.freeze({
  'svc:b89-ai-analyst': 'ai_analyst',
  'svc:b89-detection-engineering': 'bulk_script',
  'svc:b89-soc-learning': 'learning_engine',
});

export function closureOriginFor(subjectId: string): ClosureOrigin {
  if (!subjectId.startsWith('svc:')) return 'human';
  return SERVICE_ORIGINS[subjectId] ?? 'service_other';
}

export const EVIDENCE_TYPES = [
  'change_ticket',
  'owner_confirmation',
  'signed_known_binary',
  'documented_service_account',
  'vendor_documentation',
  'log_correlation',
  'scheduled_job',
  'other',
] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

export const EVIDENCE_REF_KINDS = [
  'ticket',
  'url',
  'alert',
  'incident',
  'attachment',
  'investigation',
] as const;
export type EvidenceRefKind = (typeof EVIDENCE_REF_KINDS)[number];

export interface EvidenceRef {
  readonly kind: EvidenceRefKind;
  readonly ref: string;
}

export interface ClosureJustification {
  readonly evidenceType: EvidenceType;
  /** Qué demuestra la decisión, en palabras del analista. */
  readonly statement: string;
  /** Dato observable que prueba la legitimidad (p. ej. `process.sha256`). */
  readonly legitimacyField?: string;
  readonly legitimacyValue?: string;
}

/** Lo que el cliente envía al cerrar. El origen no viaja: lo fija el backend. */
export interface ClosureInput {
  readonly reason: ClosureReason;
  readonly justification: ClosureJustification;
  readonly evidenceRefs: readonly EvidenceRef[];
}

export const CLOSURE_LIMITS = Object.freeze({
  statementMinimum: 20,
  statementMaximum: 2000,
  legitimacyFieldMaximum: 128,
  legitimacyValueMaximum: 256,
  evidenceRefsMaximum: 10,
  evidenceRefMaximum: 512,
});

export const CLOSURE_ERROR_CODES = [
  'CLOSURE_REASON_REQUIRED',
  'CLOSURE_INVALID',
  'CLOSURE_VERDICT_MISMATCH',
  'CLOSURE_REQUIRES_TRIAGE',
] as const;
export type ClosureErrorCode = (typeof CLOSURE_ERROR_CODES)[number];

export type ClosureValidation =
  | { readonly ok: true; readonly closure: ClosureInput }
  | { readonly ok: false; readonly code: ClosureErrorCode; readonly detail: string };

// Sin caracteres de control: la referencia termina en auditoría, reportes y URLs.
// oxlint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const FIELD_PATTERN = /^[A-Za-z0-9_.:-]+$/u;

function invalid(detail: string): ClosureValidation {
  return { ok: false, code: 'CLOSURE_INVALID', detail };
}

function isOneOf<T extends string>(catalog: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (catalog as readonly string[]).includes(value);
}

/**
 * Valida la forma del cierre recibido (de un cliente no confiable) y las exigencias propias de
 * cada motivo. Devuelve una copia normalizada (recortada y congelada) o el primer error.
 */
export function validateClosure(input: unknown): ClosureValidation {
  if (typeof input !== 'object' || input === null) return invalid('Falta el cierre.');
  const raw = input as Record<string, unknown>;
  if (!isOneOf(CLOSURE_REASONS, raw['reason'])) {
    return { ok: false, code: 'CLOSURE_REASON_REQUIRED', detail: 'Motivo fuera del catálogo.' };
  }
  const reason = raw['reason'];

  const justification = raw['justification'];
  if (typeof justification !== 'object' || justification === null) {
    return invalid('Falta la justificación.');
  }
  const j = justification as Record<string, unknown>;
  if (!isOneOf(EVIDENCE_TYPES, j['evidenceType'])) return invalid('Tipo de evidencia inválido.');
  const statement = typeof j['statement'] === 'string' ? j['statement'].trim() : '';
  if (
    statement.length < CLOSURE_LIMITS.statementMinimum ||
    statement.length > CLOSURE_LIMITS.statementMaximum
  ) {
    return invalid(
      `La justificación debe tener entre ${CLOSURE_LIMITS.statementMinimum} y ` +
        `${CLOSURE_LIMITS.statementMaximum} caracteres.`,
    );
  }
  const legitimacyField =
    typeof j['legitimacyField'] === 'string' ? j['legitimacyField'].trim() : undefined;
  if (
    legitimacyField !== undefined &&
    (legitimacyField.length === 0 ||
      legitimacyField.length > CLOSURE_LIMITS.legitimacyFieldMaximum ||
      !FIELD_PATTERN.test(legitimacyField))
  ) {
    return invalid('Campo de legitimidad inválido.');
  }
  const legitimacyValue =
    typeof j['legitimacyValue'] === 'string' ? j['legitimacyValue'].trim() : undefined;
  if (
    legitimacyValue !== undefined &&
    (legitimacyValue.length > CLOSURE_LIMITS.legitimacyValueMaximum ||
      CONTROL_CHARACTERS.test(legitimacyValue))
  ) {
    return invalid('Valor de legitimidad inválido.');
  }

  const refsRaw = raw['evidenceRefs'];
  if (!Array.isArray(refsRaw) || refsRaw.length === 0) {
    return invalid('El cierre exige al menos una referencia a evidencia.');
  }
  if (refsRaw.length > CLOSURE_LIMITS.evidenceRefsMaximum) {
    return invalid('Demasiadas referencias a evidencia.');
  }
  const evidenceRefs: EvidenceRef[] = [];
  for (const item of refsRaw as unknown[]) {
    if (typeof item !== 'object' || item === null) return invalid('Referencia inválida.');
    const entry = item as Record<string, unknown>;
    const ref = typeof entry['ref'] === 'string' ? entry['ref'].trim() : '';
    if (
      !isOneOf(EVIDENCE_REF_KINDS, entry['kind']) ||
      ref.length === 0 ||
      ref.length > CLOSURE_LIMITS.evidenceRefMaximum ||
      CONTROL_CHARACTERS.test(ref)
    ) {
      return invalid('Referencia inválida.');
    }
    evidenceRefs.push(Object.freeze({ kind: entry['kind'], ref }));
  }

  // Exigencias por motivo: sin ellas el cierre no sirve como evidencia.
  if (reason === 'FP_ACTIVIDAD_LEGITIMA_CONOCIDA') {
    if (j['evidenceType'] === 'other' || legitimacyField === undefined) {
      return invalid(
        'Actividad legítima conocida exige el tipo de evidencia y el dato que la demuestra.',
      );
    }
  }
  if (
    reason === 'DUPLICADA' &&
    !evidenceRefs.some((entry) => entry.kind === 'alert' || entry.kind === 'incident')
  ) {
    return invalid('Una duplicada exige la alerta o el incidente original.');
  }
  if (
    (reason === 'TP_BENIGNO_PRUEBA_O_PENTEST' || reason === 'TP_RIESGO_ACEPTADO') &&
    !evidenceRefs.some((entry) => entry.kind === 'ticket' || entry.kind === 'url')
  ) {
    return invalid('Este motivo exige el ticket o documento que lo autoriza.');
  }

  return {
    ok: true,
    closure: Object.freeze({
      reason,
      justification: Object.freeze({
        evidenceType: j['evidenceType'],
        statement,
        ...(legitimacyField === undefined ? {} : { legitimacyField }),
        ...(legitimacyValue === undefined ? {} : { legitimacyValue }),
      }),
      evidenceRefs: Object.freeze(evidenceRefs),
    }),
  };
}

/**
 * Registro append-only de un cierre o una reapertura (`soc_alert_closures`). La alerta solo
 * guarda el último estado; esta bitácora conserva la historia completa aunque se reabra.
 */
export interface AlertClosureRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly alertId: string;
  readonly kind: 'close' | 'reopen';
  readonly verdict: TriageVerdict | null;
  readonly closureReason: ClosureReason | null;
  readonly origin: ClosureOrigin;
  readonly actorId: string;
  readonly justification: ClosureJustification | null;
  readonly evidenceRefs: readonly EvidenceRef[];
  /** Cierres en bloque comparten este id y cuentan como una sola decisión. */
  readonly decisionGroupId: string | null;
  readonly correlationId: string;
  readonly at: Date;
}
