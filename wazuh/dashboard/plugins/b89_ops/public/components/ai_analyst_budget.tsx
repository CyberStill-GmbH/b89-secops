/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiCallOut } from '@elastic/eui';
import {
  AI_MODE_LABEL,
  AI_MODE_SUMMARY,
  AiBudget,
  formatCount,
  formatMicroUsd,
  formatShare,
  inferenceOff,
  NO_DATA,
  parseMode,
  shareWithoutInference,
} from '../../common';
import { Mono } from './primitives';

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
}) {
  return (
    <div className="b89Ai__stat">
      <dt>{label}</dt>
      <dd>
        <span className="b89Ai__statValue">{value}</span>
        {hint && <span className="b89CellMeta">{hint}</span>}
      </dd>
    </div>
  );
}

/** Franja de modo: refleja el modo real que informa el servicio; nunca lo supone. */
export function AiModeLine({ mode }: { mode: string | null }) {
  const known = parseMode(mode);
  if (known) {
    return (
      <p className="b89Ai__mode" data-mode={known}>
        <strong>{AI_MODE_LABEL[known]}:</strong> {AI_MODE_SUMMARY[known]}.
      </p>
    );
  }
  return (
    <p className="b89Ai__mode" data-mode="unknown">
      <strong>Modo de operación:</strong>{' '}
      {mode ? (
        <>
          <Mono>{mode}</Mono> (no reconocido por esta consola)
        </>
      ) : (
        'sin dato. No se puede afirmar qué acciones ejecuta el analista.'
      )}
    </p>
  );
}

/**
 * Presupuesto y uso del día. El relato de costo es la porción resuelta sin llamar al modelo.
 * Todo monto es una estimación del tarifario; la facturación real no está conectada.
 */
export function AiBudgetPanel({ budget }: { budget: AiBudget }) {
  const off = inferenceOff(budget);
  const share = shareWithoutInference(budget);
  const unknown = budget.day.unknownInvocations;
  return (
    <section className="b89Ai__budget" aria-label="Presupuesto y uso del día">
      <AiModeLine mode={budget.mode} />
      {budget.enabled === false && (
        <p className="b89Ai__note" role="status">
          El analista está deshabilitado en este entorno: no se inician investigaciones nuevas.
        </p>
      )}
      {off && (
        <p className="b89Ai__note" role="status">
          {budget.inferenceEnabled === false
            ? 'La inferencia está apagada'
            : 'No hay techo diario configurado, así que la inferencia está apagada'}
          : las investigaciones se resuelven solo con reglas deterministas, sin llamada al modelo.
        </p>
      )}
      <dl className="b89Ai__stats">
        <Stat
          label="Techo diario"
          value={
            budget.day.limitMicroUsd === null
              ? 'Sin techo configurado'
              : formatMicroUsd(budget.day.limitMicroUsd)
          }
          hint={budget.day.date ? <Mono>{budget.day.date}</Mono> : undefined}
        />
        <Stat label="Reservado" value={formatMicroUsd(budget.day.reservedMicroUsd)} />
        <Stat label="Uso confirmado" value={formatMicroUsd(budget.day.settledMicroUsd)} />
        <Stat label="Investigaciones hoy" value={formatCount(budget.runs.today)} />
        <Stat
          label="Resueltas sin IA"
          value={formatCount(budget.runs.withoutInference)}
          hint={share === null ? undefined : `${formatShare(share)} del día, sin costo de modelo`}
        />
        <Stat
          label="Con modelo"
          value={`${formatCount(budget.runs.economy)} / ${formatCount(budget.runs.advanced)}`}
          hint="económico / avanzado"
        />
        <Stat
          label="Tokens"
          value={`${formatCount(budget.tokens.input)} / ${formatCount(budget.tokens.output)}`}
          hint="entrada / salida"
        />
        <Stat
          label="Tokens de caché"
          value={`${formatCount(budget.tokens.cacheRead)} / ${formatCount(budget.tokens.cacheWrite)}`}
          hint="lectura / escritura"
        />
      </dl>
      {unknown !== null && unknown > 0 && (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="alert"
          title={`Uso por conciliar: ${formatCount(unknown)} ${
            unknown === 1 ? 'llamada' : 'llamadas'
          } al modelo sin consumo confirmado`}
        >
          <p>El gasto real del día puede ser mayor que el uso confirmado que se muestra.</p>
        </EuiCallOut>
      )}
      <p className="b89Ai__note">
        Costo estimado; facturación no conectada. Tarifario:{' '}
        {budget.rateCardVersion ? <Mono>{budget.rateCardVersion}</Mono> : NO_DATA}.
      </p>
    </section>
  );
}
