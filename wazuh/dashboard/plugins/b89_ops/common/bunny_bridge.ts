/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * Puente «Preguntar a Bunny»: cualquier vista abre el panel de Bunny con una pregunta ya escrita.
 *
 * Contrato (evento DOM, sin acoplar las vistas al panel):
 *   window.dispatchEvent(new CustomEvent(BUNNY_ASK_EVENT, { detail, cancelable: true }))
 * El panel, si lo implementa, escucha el evento, abre el panel, rellena el borrador con
 * `detail.prompt` (sin enviarlo) y llama a `event.preventDefault()` para indicar que lo atendió.
 * Si nadie lo atiende, `public/bunny_bridge.ts` abre el panel con su botón y escribe el
 * borrador en el cuadro de texto (la persona revisa y envía).
 */
export const BUNNY_ASK_EVENT = 'b89:bunny:ask';

export interface BunnyAskDetail {
  /** Texto propuesto para el borrador; la persona lo revisa antes de enviarlo. */
  readonly prompt: string;
  /**
   * Contexto estructurado opcional. El panel usa `alertId` o `incidentId` como página de contexto
   * de la pregunta (Bunny la ve como «Página actual: /app/b89-alerts?id=…»).
   */
  readonly context?: Readonly<Record<string, string>>;
  /** `true` envía la pregunta directamente; por defecto queda como borrador para revisarla. */
  readonly autoSend?: boolean;
}

/** Pregunta inicial sobre una alerta: lo justo para que Bunny busque el resto con sus herramientas. */
export function alertQuestion(alert: {
  id: string;
  title: string;
  priority: string;
  occurredAt: string;
  ruleId?: string | null;
  entities?: ReadonlyArray<{ kind: string; value: string }>;
  mitre?: readonly string[];
}): string {
  const lines = [
    `Ayúdame a investigar esta alerta: «${alert.title}» (${alert.priority}, ${alert.occurredAt}, id ${alert.id}).`,
  ];
  if (alert.ruleId) lines.push(`Regla de Wazuh: ${alert.ruleId}.`);
  if (alert.mitre && alert.mitre.length > 0) lines.push(`MITRE ATT&CK: ${alert.mitre.join(', ')}.`);
  if (alert.entities && alert.entities.length > 0) {
    lines.push(
      `Entidades: ${alert.entities
        .slice(0, 6)
        .map((entity) => `${entity.kind} ${entity.value}`)
        .join('; ')}.`,
    );
  }
  lines.push('¿Qué significa, qué tan grave es, qué más reviso y qué acción recomiendas?');
  return lines.join('\n');
}
