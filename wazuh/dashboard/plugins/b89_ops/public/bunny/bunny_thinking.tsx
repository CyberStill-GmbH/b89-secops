/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import type { BunnyProgressEvent } from './chat_client';

export type BunnyProgressStatus = 'running' | 'complete' | 'no-result';

export interface BunnyProgressStep {
  readonly key: string;
  readonly label: string;
  readonly status: BunnyProgressStatus;
}

function findLastIndex<T>(items: readonly T[], matches: (item: T) => boolean): number {
  for (let index = items.length - 1; index >= 0; index -= 1) {
    if (matches(items[index]!)) return index;
  }
  return -1;
}

/** Projects the SSE stream into a timeline; it does not synthesize omitted server actions. */
export function bunnyProgressTimeline(events: readonly BunnyProgressEvent[]): BunnyProgressStep[] {
  const steps: BunnyProgressStep[] = [];
  const setStatus = (index: number, status: BunnyProgressStatus) => {
    const step = steps[index];
    if (step) steps[index] = { ...step, status };
  };

  events.forEach((event, index) => {
    if (event.type === 'model_started') {
      const activeModel = findLastIndex(steps, (step) => step.key.startsWith('model:') && step.status === 'running');
      if (activeModel >= 0) setStatus(activeModel, 'complete');
      steps.push({ key: `model:${event.round}:${index}`, label: `Consulta al modelo · ronda ${event.round}`, status: 'running' });
      return;
    }
    if (event.type === 'tool_started') {
      const activeModel = findLastIndex(steps, (step) => step.key.startsWith('model:') && step.status === 'running');
      if (activeModel >= 0) setStatus(activeModel, 'complete');
      steps.push({ key: `tool:${event.label}:${index}`, label: event.label, status: 'running' });
      return;
    }
    const activeTool = findLastIndex(steps,
      (step) => step.key.startsWith(`tool:${event.label}:`) && step.status === 'running',
    );
    if (activeTool >= 0) setStatus(activeTool, event.ok ? 'complete' : 'no-result');
    else steps.push({
      key: `tool:${event.label}:${index}`,
      label: event.label,
      status: event.ok ? 'complete' : 'no-result',
    });
  });
  return steps;
}

export function elapsedLabel(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(safeSeconds / 60);
  const remainder = safeSeconds % 60;
  return minutes > 0 ? `${minutes} min ${String(remainder).padStart(2, '0')} s` : `${remainder} s`;
}

const STATUS_LABEL: Record<BunnyProgressStatus, string> = {
  running: 'En curso',
  complete: 'Completo',
  'no-result': 'Sin resultado',
};

export function BunnyThinking({ events, elapsedSeconds }: {
  readonly events: readonly BunnyProgressEvent[];
  readonly elapsedSeconds: number;
}) {
  const steps = bunnyProgressTimeline(events);
  return (
    <div className="b89Bunny__thinking" aria-live="off">
      <div className="b89Bunny__thinkingHead">
        <span className="b89Bunny__thinkingPulse" aria-hidden="true" />
        <div>
          <strong>Análisis en curso</strong>
          <span aria-label={`Tiempo transcurrido: ${elapsedLabel(elapsedSeconds)}`}>
            {elapsedLabel(elapsedSeconds)} transcurridos
          </span>
        </div>
      </div>
      {steps.length === 0 ? (
        <p className="b89Bunny__thinkingWaiting" role="status" aria-live="polite">
          Esperando la primera actualización de actividad del servidor…
        </p>
      ) : (
        <ol className="b89Bunny__timeline" aria-label="Actividad recibida del servidor" role="log" aria-live="polite" aria-relevant="additions text">
          {steps.map((step) => (
            <li key={step.key} data-status={step.status}>
              <span className="b89Bunny__timelineMark" aria-hidden="true" />
              <span className="b89Bunny__timelineLabel">{step.label}</span>
              <span className="b89Bunny__timelineStatus">{STATUS_LABEL[step.status]}</span>
            </li>
          ))}
        </ol>
      )}
      <p className="b89Bunny__thinkingNote">La consola muestra las actualizaciones que envía Bunny; no estima porcentaje ni pasos pendientes.</p>
    </div>
  );
}
