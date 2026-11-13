/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState } from 'react';
import type { Alert } from '../../common';
import type { InvestigationEntity, RelatedWindow } from '../../common/investigation';
import { fetchRelated } from '../api/investigation';
import { investigationCsvWithProgress } from './investigation_export';
import type {
  ReportProgress,
  ReportEventSummary,
  InvestigationReportQuery,
  RelatedPageLoader,
} from './investigation_report';
import {
  collectInvestigationReport,
  createInvestigationXlsx,
  ReportCollectionError,
  writeInvestigationPrintWindowWithProgress,
} from './investigation_report';
import './investigation_report.scss';

type ReportAction = 'csv' | 'xlsx' | 'print';

function progressPercent(progress: ReportProgress): number {
  if (progress.percent !== undefined) return Math.max(0, Math.min(100, progress.percent));
  if (progress.total <= 0) return progress.phase === 'query' ? 0 : 100;
  return Math.max(0, Math.min(100, Math.floor((progress.completed / progress.total) * 100)));
}

/** A user-scoped export that reports completed query pages and artifact rows as they finish. */
export function InvestigationReportActions({
  basePath,
  alert,
  title,
  entities,
  at,
  relatedWindow,
  excludeId,
  sourceEvent,
  onLoadPage,
}: {
  readonly basePath: string;
  readonly alert: Alert | null;
  readonly title: string;
  readonly entities: readonly InvestigationEntity[];
  readonly at: string;
  readonly relatedWindow: RelatedWindow;
  readonly excludeId?: string;
  readonly sourceEvent?: ReportEventSummary | null;
  readonly onLoadPage?: RelatedPageLoader;
}) {
  const [busy, setBusy] = useState<ReportAction | null>(null);
  const [progress, setProgress] = useState<ReportProgress | null>(null);
  const [message, setMessage] = useState('');
  const cancel = useRef<AbortController | null>(null);
  const printWindow = useRef<Window | null>(null);
  const highestProgress = useRef(0);

  const start = async (action: ReportAction) => {
    if (busy || entities.length === 0) return;
    // Open synchronously in the click handler to preserve the browser's popup permission while
    // the authorized pages are collected. It is closed on cancel/failure.
    const opened = action === 'print' ? windowOpen() : null;
    if (action === 'print' && !opened) {
      setMessage('Permite la ventana emergente para preparar el PDF imprimible.');
      return;
    }
    printWindow.current = opened;
    if (opened) {
      opened.document.open();
      opened.document.write(
        '<!doctype html><html lang="es"><meta charset="utf-8"><title>B89 SOC · Preparando informe</title><body style="font:16px Arial;padding:32px;color:#263444"><h1>B89 SOC · Preparando informe</h1><p>Consultando el historial autorizado de la investigación…</p><p>Esta ventana mostrará la opción de imprimir o guardar como PDF cuando termine.</p></body></html>',
      );
      opened.document.close();
    }
    const controller = new AbortController();
    cancel.current = controller;
    highestProgress.current = 0;
    setBusy(action);
    setProgress(null);
    setMessage('');
    const query: InvestigationReportQuery = {
      entities: entities.map(({ kind, value }) => ({ kind, value })),
      at,
      window: relatedWindow,
      ...(excludeId ? { excludeId } : {}),
    };
    const loadPage: RelatedPageLoader =
      onLoadPage ??
      ((params, cursor, signal) => {
        const { excludeId: exclude, ...rest } = params;
        return fetchRelated(
          basePath,
          { ...rest, ...(exclude ? { exclude } : {}), ...(cursor ? { cursor } : {}) },
          globalThis.fetch.bind(globalThis),
          signal,
        );
      });
    try {
      const report = await collectInvestigationReport({
        query,
        alert,
        sourceEvent,
        title,
        entities: entities.map((entity) => `${entity.kind}: ${entity.value}`),
        loadPage,
        signal: controller.signal,
        onProgress: (next) => {
          const percent = Math.max(highestProgress.current, progressPercent(next));
          highestProgress.current = percent;
          setProgress({ ...next, percent });
          if (next.phase === 'query' && printWindow.current && !printWindow.current.closed) {
            printWindow.current.document.body.innerHTML = `<h1>B89 SOC · Preparando informe</h1><p>${escapeHtml(next.message)}</p>`;
          }
        },
      });
      if (controller.signal.aborted) {
        setMessage('Preparación cancelada.');
        return;
      }
      if (action === 'xlsx') {
        const blob = await createInvestigationXlsx(
          report,
          (next) => {
            const percent = Math.max(highestProgress.current, progressPercent(next));
            highestProgress.current = percent;
            setProgress({ ...next, percent });
          },
          controller.signal,
        );
        if (controller.signal.aborted) {
          setMessage('Preparación cancelada.');
          return;
        }
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `b89-investigacion-${(alert?.id ?? 'grupo').replace(/[^A-Za-z0-9_-]/gu, '_')}.xlsx`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        globalThis.window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      } else if (action === 'csv') {
        const csv = await investigationCsvWithProgress(report, controller.signal, (next) => {
          const percent = Math.max(
            highestProgress.current,
            65 + Math.floor((next.completed / Math.max(1, next.total)) * 25),
          );
          highestProgress.current = percent;
          setProgress({
            phase: 'render',
            ...next,
            percent,
            message: `Preparando CSV: ${next.completed.toLocaleString('es-PE')} de ${next.total.toLocaleString('es-PE')} filas`,
          });
        });
        if (controller.signal.aborted) {
          setMessage('Preparación cancelada.');
          return;
        }
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `b89-investigacion-${(alert?.id ?? 'grupo').replace(/[^A-Za-z0-9_-]/gu, '_')}.csv`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        globalThis.window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      } else if (printWindow.current && !printWindow.current.closed) {
        await writeInvestigationPrintWindowWithProgress(
          printWindow.current,
          report,
          controller.signal,
          (next) => {
            const percent = Math.max(highestProgress.current, progressPercent(next));
            highestProgress.current = percent;
            setProgress({ ...next, percent });
          },
        );
      }
      highestProgress.current = 100;
      const completionMessage =
        action === 'print'
          ? 'Vista imprimible lista; revisa el contenido y elige Guardar como PDF en el navegador.'
          : action === 'xlsx'
            ? 'Libro Excel listo para revisar y compartir.'
            : 'Archivo CSV listo para revisar y compartir.';
      setProgress({
        phase: 'package',
        completed: 1,
        total: 1,
        percent: 100,
        message: completionMessage,
      });
      const rowSummary = report.truncated
        ? `Incluye ${report.events.length.toLocaleString('es-PE')} de ${report.totalEvents.toLocaleString('es-PE')} eventos (límite de seguridad). Refina los filtros para completar.`
        : `${report.events.length.toLocaleString('es-PE')} eventos incluidos.`;
      setMessage(`${completionMessage} ${rowSummary}`);
    } catch (error) {
      if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
        setMessage('Preparación cancelada.');
      } else {
        const failure =
          error instanceof ReportCollectionError
            ? error.kind
            : error instanceof Error && error.message.includes('forbidden')
              ? 'forbidden'
              : null;
        setMessage(
          failure === 'forbidden'
            ? 'Tu sesión no puede consultar toda la evidencia; no se generó un informe parcial. Revisa los permisos de la alerta e inténtalo de nuevo.'
            : failure === 'unavailable'
              ? 'Wazuh Indexer no respondió a la consulta. No se generó el archivo; reintenta y, si persiste, revisa Salud de fuentes.'
              : failure === 'invalid'
                ? 'Wazuh Indexer devolvió páginas inconsistentes. No se generó un informe parcial; vuelve a intentarlo con una ventana menor.'
                : 'No se pudo completar el informe. No se generó un archivo parcial; revisa la conexión e inténtalo de nuevo.',
        );
      }
      if (printWindow.current && !printWindow.current.closed) printWindow.current.close();
    } finally {
      cancel.current = null;
      printWindow.current = null;
      setBusy(null);
    }
  };

  const stop = () => cancel.current?.abort();

  return (
    <section className="b89ReportActions" aria-labelledby="b89ReportActionsTitle">
      <div className="b89ReportActions__copy">
        <h3 id="b89ReportActionsTitle">Informe de investigación con eventos relacionados</h3>
        <p>
          Incluye todos los eventos de la ventana y grupos por entidad/tiempo. La correlación
          temporal no demuestra causalidad ni hilo de correo.
        </p>
      </div>
      <div className="b89ReportActions__buttons">
        <button
          type="button"
          disabled={Boolean(busy) || entities.length === 0}
          onClick={() => void start('csv')}
        >
          {busy === 'csv' ? 'Preparando CSV…' : 'Descargar CSV completo'}
        </button>
        <button
          type="button"
          disabled={Boolean(busy) || entities.length === 0}
          onClick={() => void start('xlsx')}
        >
          {busy === 'xlsx' ? 'Preparando Excel…' : 'Descargar Excel (.xlsx)'}
        </button>
        <button
          type="button"
          disabled={Boolean(busy) || entities.length === 0}
          onClick={() => void start('print')}
        >
          {busy === 'print' ? 'Preparando PDF…' : 'Imprimir / guardar PDF'}
        </button>
        {busy && (
          <button type="button" className="b89ReportActions__cancel" onClick={stop}>
            Cancelar
          </button>
        )}
      </div>
      {busy && progress && (
        <div className="b89ReportActions__progress" aria-live="polite" aria-atomic="true">
          <label htmlFor="b89ReportProgress">{progress.message}</label>
          <progress id="b89ReportProgress" max={100} value={progressPercent(progress)} />
          <span>
            {progress.phase === 'query' ? 'Consulta de páginas' : 'Generación del archivo'}
          </span>
        </div>
      )}
      {message && (
        <p className="b89ReportActions__message" role="status">
          {message}
        </p>
      )}
      {entities.length === 0 && (
        <p className="b89ReportActions__message">
          Añade una entidad a la investigación antes de exportar.
        </p>
      )}
    </section>
  );
}

function windowOpen(): Window | null {
  return globalThis.window.open('', '_blank');
}

function escapeHtml(value: string): string {
  return value.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;');
}
