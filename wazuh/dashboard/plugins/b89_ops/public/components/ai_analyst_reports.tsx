/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { EuiButton, EuiCallOut, EuiFieldText, EuiFormRow, EuiSpacer } from '@elastic/eui';
import {
  AiDigest,
  digestRangeError,
  formatCount,
  formatMicroUsd,
  localDay,
  PRIORITIES,
} from '../../common';
import { getAiDigest, isAnalystUnavailable } from '../api/ai_investigations';
import { digestFilename, printAnalystReport } from './ai_analyst_download';
import { useConsole } from './console_context';
import { ErrorCallout, Mono, PriorityMark } from './primitives';

function Total({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="b89Ai__stat">
      <dt>{label}</dt>
      <dd>
        <span className="b89Ai__statValue">{formatCount(value)}</span>
      </dd>
    </div>
  );
}

/** Totales del periodo. Un conteo que no llegó es «Sin dato», no cero. */
export function AiDigestView({
  digest,
  onDownload,
}: {
  digest: AiDigest;
  onDownload?: () => void;
}) {
  const hasText = digest.markdown.trim().length > 0;
  return (
    <section className="b89Ai__digest" aria-label="Resumen del periodo">
      <p className="b89CellMeta">
        Periodo: <Mono>{digest.from ?? 'Sin dato'}</Mono> a <Mono>{digest.to ?? 'Sin dato'}</Mono>
      </p>
      <dl className="b89Ai__stats">
        <Total label="Investigaciones" value={digest.totals.runs} />
        <Total label="Escaladas" value={digest.totals.escalated} />
        <Total label="Cerradas como benignas" value={digest.totals.closedBenign} />
        <Total label="Requieren revisión" value={digest.totals.requiresReview} />
        <Total label="Resueltas sin IA" value={digest.totals.withoutInference} />
        <Total label="Fallidas" value={digest.totals.failed} />
        <div className="b89Ai__stat">
          <dt>Costo del periodo</dt>
          <dd>
            <span className="b89Ai__statValue">{formatMicroUsd(digest.estimatedMicroUsd)}</span>
            <span className="b89CellMeta">facturación no conectada</span>
          </dd>
        </div>
      </dl>
      <h3 className="b89Ai__sectionTitle">Por prioridad</h3>
      <ul className="b89Ai__byPriority">
        {PRIORITIES.map((priority) => (
          <li key={priority}>
            <PriorityMark priority={priority} />
            <span className="b89Tabular">{formatCount(digest.byPriority[priority])}</span>
          </li>
        ))}
      </ul>
      <h3 className="b89Ai__sectionTitle">Reglas con más investigaciones</h3>
      {digest.topRules.length === 0 ? (
        <p className="b89Muted">El resumen no incluye reglas para este periodo.</p>
      ) : (
        <div className="b89Ai__tableWrap">
          <table className="b89Ai__invocations">
            <thead>
              <tr>
                <th scope="col">Regla</th>
                <th scope="col">Investigaciones</th>
              </tr>
            </thead>
            <tbody>
              {digest.topRules.map((rule) => (
                <tr key={rule.ruleId}>
                  <td>
                    <Mono>{rule.ruleId}</Mono>
                  </td>
                  <td className="b89Tabular">{formatCount(rule.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <EuiSpacer size="m" />
      {hasText ? (
        onDownload && (
          <EuiButton size="s" iconType="download" onClick={onDownload}>
            Guardar resumen como PDF
          </EuiButton>
        )
      ) : (
        <p className="b89Muted">El servicio no entregó el texto del resumen para descargar.</p>
      )}
    </section>
  );
}

export function AiReportsTab() {
  const { api, basePath } = useConsole();
  const [from, setFrom] = useState(() => localDay(new Date(), -6));
  const [to, setTo] = useState(() => localDay(new Date()));
  const [digest, setDigest] = useState<AiDigest | null>(null);
  const [loaded, setLoaded] = useState<{ from: string; to: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const rangeError = digestRangeError(from, to);

  const load = async () => {
    if (rangeError || busy) return;
    setBusy(true);
    setError(null);
    try {
      setDigest(await getAiDigest(api, from, to));
      setLoaded({ from, to });
    } catch (failure) {
      setDigest(null);
      setLoaded(null);
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <form
        className="b89Ai__range"
        onSubmit={(event) => {
          event.preventDefault();
          void load();
        }}
      >
        <EuiFormRow label="Desde" display="rowCompressed">
          <EuiFieldText
            compressed
            type="date"
            value={from}
            max={to || undefined}
            onChange={(event) => setFrom(event.target.value)}
          />
        </EuiFormRow>
        <EuiFormRow
          label="Hasta"
          display="rowCompressed"
          isInvalid={rangeError !== null}
          error={rangeError ?? undefined}
        >
          <EuiFieldText
            compressed
            type="date"
            value={to}
            min={from || undefined}
            isInvalid={rangeError !== null}
            onChange={(event) => setTo(event.target.value)}
          />
        </EuiFormRow>
        <EuiButton size="s" type="submit" isLoading={busy} isDisabled={rangeError !== null}>
          Generar resumen
        </EuiButton>
      </form>
      <p className="b89Ai__note">
        Guarda el informe desde su expediente («Guardar informe como PDF»). El navegador permite
        revisar el documento y guardarlo como PDF.
      </p>
      <EuiSpacer size="m" />
      {error != null &&
        (isAnalystUnavailable(error) ? (
          <EuiCallOut
            size="s"
            color="warning"
            iconType="offline"
            title="Los informes del analista no están publicados en este entorno"
          />
        ) : (
          <ErrorCallout error={error} onRetry={load} />
        ))}
      {digest && loaded && (
        <AiDigestView
          digest={digest}
          onDownload={() => {
            setError(null);
            try {
              printAnalystReport(digestFilename(loaded.from, loaded.to), digest.markdown, basePath);
            } catch (failure) {
              setError(failure);
            }
          }}
        />
      )}
      {!digest && error == null && !busy && (
        <p className="b89Muted">Elige un periodo y genera el resumen.</p>
      )}
    </>
  );
}
