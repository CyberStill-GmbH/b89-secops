/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * «Por qué saltó» para CUALQUIER alerta, en lenguaje llano y sin códigos del motor.
 *
 * Fuentes, en orden: la explicación del correlador, la guía por regla (`alert_guide.ts`) y, si no
 * hay ninguna, la descripción de la regla (el título sin el prefijo «B89 X:» ni el sufijo
 * «(wazuh N)», igual que `apps/api/src/runtime/notification-enricher.ts`). A eso se suman quién o
 * qué está involucrado (entidades) y los agravantes que el motor de priorización registró
 * (`modules/detection/src/prioritization.ts`). Nada se infiere: si un dato falta, se omite.
 */

import type { Alert, AlertEntity, Priority } from './api_contract';
import { guideForAlertTitle, guideForRule } from './alert_guide';
import type { AlertGuide } from './alert_guide';
import { VENDORS, vendorOfTitle, wazuhRuleIdOfTitle } from './vendors';

type ExplainableAlert = Pick<Alert, 'title' | 'priority' | 'reasons' | 'entities'> &
  Partial<Pick<Alert, 'ruleId' | 'explanation'>>;

export interface AlertWhy {
  /** Título visible: la descripción de la regla, sin prefijo de fuente ni ID técnico. */
  readonly title: string;
  /** Una línea para la cola y el inicio: qué pasó + hasta 2 involucrados + agravante principal. */
  readonly line: string;
  /** La misma línea sin repetir el título (para mostrarla debajo de él), o '' si no añade nada. */
  readonly detailLine: string;
  /** Frase completa para el detalle: qué pasó, involucrados, agravantes y quién lo detectó. */
  readonly sentence: string;
  /** «Es P2 porque …», o null si el motor no registró motivos. */
  readonly priorityLine: string | null;
  /** Si la prioridad bajó (mantenimiento, regla benigna, informativa), por qué. */
  readonly loweredLine: string | null;
  /** Quién lo detectó («Cloudflare», «Microsoft 365»…), o null. */
  readonly source: string | null;
  /** ID de regla del SIEM, para el detalle técnico. */
  readonly ruleId: string | null;
  /** Guía específica de la regla, si existe. */
  readonly guide: AlertGuide | null;
  /** Qué hacer: guía, correlador o runbook del catálogo; si no hay, tres pasos genéricos. */
  readonly nextSteps: readonly string[];
  /** Cuándo suele ser normal (catálogo de detección), si se conoce. */
  readonly commonFalsePositives: readonly string[];
  /** Cuándo tratarla como real y escalar (catálogo de detección), si se conoce. */
  readonly escalateWhen: readonly string[];
  /** Caso de uso del catálogo («Rootcheck…»), si se conoce. */
  readonly useCase: string | null;
}

const RULE_SUFFIX = /\s*\(wazuh \d{1,7}\)\s*$/u;
const SOURCE_PREFIX = /^B89 ([^:]{2,40}):\s*/u;

function capitalize(text: string): string {
  return text ? `${text.charAt(0).toUpperCase()}${text.slice(1)}` : text;
}

function stripPeriod(text: string): string {
  return text.trim().replace(/[.;:\s]+$/u, '');
}

/** Título visible de una alerta: sin «B89 Cloudflare:» ni «(wazuh 101531)». */
export function cleanAlertTitle(title: string): string {
  const clean = title.replace(RULE_SUFFIX, '').replace(SOURCE_PREFIX, '').trim();
  return capitalize(clean) || 'Alerta del SIEM sin descripción';
}

/** Prefijos «B89 X:» cuyo nombre visible es otro. */
const SOURCE_NAME: Readonly<Record<string, string>> = {
  DLP: 'Ferrispector (DLP de endpoints)',
};

function sourceOf(title: string): string | null {
  const prefix = SOURCE_PREFIX.exec(title)?.[1]?.trim();
  if (prefix) return SOURCE_NAME[prefix] ?? prefix;
  const vendor = vendorOfTitle(title);
  return vendor === 'wazuh' ? null : VENDORS[vendor].name;
}

const ENTITY_PHRASE: Readonly<Record<string, (label: string) => string>> = {
  user: (label) => `usuario ${label}`,
  ip: (label) => `IP ${label}`,
  host: (label) => `equipo ${label}`,
};

function entityPhrase(entity: AlertEntity): string {
  const phrase = ENTITY_PHRASE[entity.kind];
  return phrase ? phrase(entity.label) : entity.label;
}

/** Con artículo, para frases: «el usuario ana», «la IP 1.2.3.4», «el equipo PC-01». */
function entityWithArticle(entity: AlertEntity): string {
  const phrase = entityPhrase(entity);
  if (entity.kind === 'ip') return `la ${phrase}`;
  if (entity.kind === 'user' || entity.kind === 'host') return `el ${phrase}`;
  return phrase;
}

const SEVERITY_WORD: Readonly<Record<string, string>> = {
  critical: 'muy grave',
  high: 'grave',
  medium: 'moderada',
  low: 'leve',
  informational: 'informativa',
  info: 'informativa',
};

function firstNumber(text: string): number | null {
  const match = /(\d+)/u.exec(text);
  return match ? Number(match[1]) : null;
}

function afterColon(text: string): string | null {
  const index = text.indexOf(':');
  if (index < 0) return null;
  const value = stripPeriod(text.slice(index + 1));
  return value || null;
}

interface ReadReason {
  /** Agravante para la frase «Por qué saltó». */
  readonly aggravator?: string;
  /** Motivo para «Es Px porque …». */
  readonly because?: string;
  /** Motivo de una prioridad más baja. */
  readonly lowered?: string;
}

/** Cada código del motor, en palabras. Un código desconocido no se muestra aquí (sigue en el detalle técnico). */
function readReason(code: string, detail: string): ReadReason {
  switch (code) {
    case 'BASE_SEVERITY': {
      const level = /normalizada\s+([a-z]+)/iu.exec(detail)?.[1]?.toLowerCase();
      const word = level ? SEVERITY_WORD[level] : undefined;
      return { because: word ? `la regla la marca como ${word}` : 'la gravedad de la regla' };
    }
    case 'BREAK_GLASS_IDENTITY': {
      const id = afterColon(detail);
      return {
        aggravator: id ? `con la cuenta de emergencia ${id}` : 'con una cuenta de emergencia',
        because: 'usa una cuenta de emergencia',
      };
    }
    case 'PRIVILEGED_IDENTITY': {
      const id = afterColon(detail);
      return {
        aggravator: id ? `con una cuenta con privilegios (${id})` : 'con una cuenta con privilegios',
        because: 'la cuenta tiene privilegios',
      };
    }
    case 'CRITICAL_ASSET': {
      const asset = afterColon(detail);
      return {
        aggravator: asset ? `en un sistema crítico (${asset})` : 'en un sistema crítico',
        because: 'afecta un sistema crítico',
      };
    }
    case 'EXTERNAL_EXPOSURE':
      return { aggravator: 'en un sistema expuesto a Internet', because: 'el sistema está expuesto a Internet' };
    case 'SUCCESSFUL_INTRUSION':
      return { aggravator: 'y tuvo éxito', because: 'la acción tuvo éxito' };
    case 'REPEATED_ACTIVITY': {
      const count = firstNumber(detail);
      return {
        aggravator: count ? `se repitió ${count} veces` : 'se repitió varias veces',
        because: 'se repitió',
      };
    }
    case 'CORRELATED_ENTITY': {
      const count = firstNumber(detail);
      return {
        aggravator: count
          ? `hay ${count} ${count === 1 ? 'alerta' : 'alertas'} más del mismo usuario o IP`
          : 'hay más alertas del mismo usuario o IP',
        because: 'hay otras alertas del mismo usuario o IP',
      };
    }
    case 'ATTACK_CHAIN':
      return { aggravator: 'forma parte de una posible cadena de ataque', because: 'encaja en una cadena de ataque' };
    case 'MAINTENANCE_WINDOW':
      return { lowered: 'ocurrió en una ventana de mantenimiento' };
    case 'KNOWN_BENIGN':
      return { lowered: 'la regla está acordada como benigna' };
    case 'INFORMATIONAL_ONLY':
      return { lowered: 'es solo informativa' };
    default:
      return {};
  }
}

function joinSpanish(parts: readonly string[]): string {
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} y ${parts[parts.length - 1]}`;
}

/** Primera oración de la «Explicación:» del correlador, si la hay. */
function correlatorExplanation(reasons: ExplainableAlert['reasons']): string | null {
  const explanation = reasons.find((reason) => /^Explicación:/u.test(reason.detail));
  if (!explanation) return null;
  const text = explanation.detail.replace(/^Explicación:\s*/u, '').trim();
  const first = /^(.+?[.!?])(\s|$)/u.exec(text)?.[1] ?? text;
  return stripPeriod(first) || null;
}

function correlatorNextSteps(reasons: ExplainableAlert['reasons']): string[] {
  return reasons
    .filter((reason) => /^Siguiente paso:/u.test(reason.detail))
    .map((reason) => reason.detail.replace(/^Siguiente paso:\s*/u, '').trim())
    .filter(Boolean);
}

function genericSteps(main: string | null): string[] {
  return [
    main
      ? `Abre «Investigar» y revisa qué más pasó con ${main} una hora antes y después.`
      : 'Abre «Investigar» y revisa qué más pasó una hora antes y después.',
    main
      ? `Pregunta a quien usa o administra ${main} si reconoce la actividad.`
      : 'Pregunta a la persona dueña de la cuenta o del equipo si reconoce la actividad.',
    'Registra la conclusión: si no es real, ciérrala como falso positivo; si es real, abre un incidente.',
  ];
}

export function explainAlert(alert: ExplainableAlert): AlertWhy {
  const ruleId = alert.ruleId ?? wazuhRuleIdOfTitle(alert.title);
  const guide = guideForRule(ruleId) ?? guideForAlertTitle(alert.title);
  const knowledge = alert.explanation ?? null;
  const title = cleanAlertTitle(alert.title);
  const source = sourceOf(alert.title);
  const what = correlatorExplanation(alert.reasons) ?? (guide ? stripPeriod(guide.headline) : stripPeriod(title));

  const read = alert.reasons.map((reason) => readReason(reason.code, reason.detail));
  const aggravators = [...new Set(read.map((item) => item.aggravator).filter((v): v is string => Boolean(v)))];
  const because = [...new Set(read.map((item) => item.because).filter((v): v is string => Boolean(v)))];
  const lowered = [...new Set(read.map((item) => item.lowered).filter((v): v is string => Boolean(v)))];

  const people = alert.entities.map(entityPhrase);
  const main = alert.entities[0] ? entityWithArticle(alert.entities[0]) : null;

  const lineParts = [what];
  if (people.length) lineParts.push(people.slice(0, 2).join(', '));
  if (aggravators[0]) lineParts.push(aggravators[0]);
  const line = lineParts.join(' · ');

  let sentence = what;
  if (people.length) sentence += ` (${joinSpanish(people)})`;
  if (aggravators.length) sentence += `; ${joinSpanish(aggravators)}`;
  sentence += '.';
  if (source) sentence += ` Lo detectó ${source}.`;

  const priority: Priority = alert.priority;
  const priorityLine = because.length ? `Es ${priority} porque ${joinSpanish(because)}.` : null;
  const loweredLine = lowered.length ? `Tiene menos prioridad porque ${joinSpanish(lowered)}.` : null;

  const correlatorSteps = correlatorNextSteps(alert.reasons);
  const runbookStep = knowledge?.runbook?.firstStep;
  const nextSteps = guide
    ? guide.whatToDo
    : correlatorSteps.length
      ? correlatorSteps
      : runbookStep
        ? [runbookStep, ...genericSteps(main).slice(1)]
        : genericSteps(main);
  const detailLine = line.startsWith(title) ? line.slice(title.length).replace(/^ · /u, '') : line;

  return {
    title,
    line,
    detailLine,
    sentence,
    priorityLine,
    loweredLine,
    source,
    ruleId,
    guide,
    nextSteps,
    commonFalsePositives: knowledge?.falsePositives ?? [],
    escalateWhen: knowledge?.escalateWhen ?? [],
    useCase: knowledge?.useCase ?? null,
  };
}
