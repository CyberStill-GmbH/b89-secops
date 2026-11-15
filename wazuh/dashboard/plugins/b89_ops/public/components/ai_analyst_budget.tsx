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
  microUsdAmount,
  NO_DATA,
  parseMode,
  shareWithoutInference,
} from '../../common';
import { budgetUsage, percentText } from './ai_analyst_model';
import { AiTile } from './ai_analyst_parts';
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

/** Barra de uso del techo diario: escalones de 5 %, color + texto (nunca solo color). */
export function BudgetMeter({ budget }: { budget: AiBudget }) {
  const usage = budgetUsage(budget);
  const used = microUsdAmount(usage.usedMicroUsd);
  const limit = microUsdAmount(usage.limitMicroUsd);
  const percent = percentText(usage.share);
  return (
    <div className="b89AiMeter" data-tone={usage.tone}>
      <p className="b89AiMeter__text">
        {usage.limitMicroUsd === null ? (
          <>
            <strong>Sin techo configurado</strong>
            <span className="b89CellMeta"> · la IA no se usa sin un techo diario</span>
          </>
        ) : (
          <>
            <strong className="b89Tabular">{used ?? NO_DATA}</strong>
            <span className="b89CellMeta"> de {limit} usados hoy (estimado)</span>
            {percent && <strong className="b89AiMeter__percent b89Tabular">{percent}</strong>}
          </>
        )}
      </p>
      {usage.limitMicroUsd !== null && (
        <span
          className="b89AiMeter__track"
          role="img"
          aria-label={percent ? `${percent} del techo diario usado` : 'Uso del techo sin dato'}
        >
          <span className="b89AiMeter__fill" data-step={usage.step} />
        </span>
      )}
    </div>
  );
}

/** Cifra compacta para la fila de indicadores de «Resumen». */
export function AiBudgetTile({ budget }: { budget: AiBudget | null }) {
  if (!budget) {
    return <AiTile label="Presupuesto de IA hoy" value={NO_DATA} hint="Sin lectura del presupuesto" />;
  }
  const usage = budgetUsage(budget);
  const off = inferenceOff(budget);
  const used = microUsdAmount(usage.usedMicroUsd);
  const limit = microUsdAmount(usage.limitMicroUsd);
  return (
    <AiTile
      label="Presupuesto de IA hoy"
      tone={off ? 'neutral' : usage.tone}
      value={off ? 'IA apagada' : percentText(usage.share) ?? NO_DATA}
      hint={
        off
          ? 'Solo reglas deterministas, sin costo de modelo'
          : `${used ?? NO_DATA} de ${limit ?? NO_DATA} (estimado)`
      }
    >
      {!off && usage.limitMicroUsd !== null && (
        <span className="b89AiMeter" data-tone={usage.tone}>
          <span className="b89AiMeter__track" aria-hidden="true">
            <span className="b89AiMeter__fill" data-step={usage.step} />
          </span>
        </span>
      )}
    </AiTile>
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
    <section className="b89Panel b89AiBudget" aria-labelledby="b89AiBudgetTitle">
      <div className="b89Panel__header">
        <h2 id="b89AiBudgetTitle">Presupuesto de IA</h2>
        <span className="b89Panel__meta">
          Hoy{budget.day.date ? <> · <Mono>{budget.day.date}</Mono></> : null}
        </span>
      </div>
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
      <BudgetMeter budget={budget} />
      <dl className="b89Ai__stats">
        <Stat
          label="Techo diario"
          value={
            budget.day.limitMicroUsd === null
              ? 'Sin techo configurado'
              : formatMicroUsd(budget.day.limitMicroUsd)
          }
        />
        <Stat label="Uso confirmado" value={formatMicroUsd(budget.day.settledMicroUsd)} />
        <Stat
          label="Reservado"
          value={formatMicroUsd(budget.day.reservedMicroUsd)}
          hint="llamadas en curso"
        />
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
      </dl>
      <details className="b89AiDetails">
        <summary>Tokens del día</summary>
        <dl className="b89Ai__stats">
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
      </details>
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
