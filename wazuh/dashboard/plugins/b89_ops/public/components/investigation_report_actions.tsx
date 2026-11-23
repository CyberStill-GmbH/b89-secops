/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiContextMenu, EuiPopover } from '@elastic/eui';
import type { EuiContextMenuPanelDescriptor } from '@elastic/eui';
import type { Alert, BunnyReportFormat } from '../../common';
import { BUNNY_REPORT_FORMAT_LABEL, bunnyReportPrompt } from '../../common';
import { askBunny } from '../bunny_bridge';
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
  writeInvestigationXlsx,
} from './investigation_report';
import './investigation_report.scss';

type ReportAction = 'csv' | 'xlsx' | 'print';

type ReportFileWritable = {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
};

type ReportFileHandle = { createWritable(): Promise<ReportFileWritable> };

type SavePickerWindow = Window & {
  showSaveFilePicker?: (options: {
    suggestedName: string;
    types: Array<{ description: string; accept: Record<string, string[]> }>;
  }) => Promise<ReportFileHandle>;
};

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
  const startingExport = useRef(false);
  const highestProgress = useRef(0);
  const [menuOpen, setMenuOpen] = useState(false);

  /** Informe profesional con Bunny (PDF/Excel/CSV): abre el panel y envía la petición. */
  const askForReport = (format: BunnyReportFormat) => {
    if (entities.length === 0) return;
    const opened = askBunny({
      prompt: bunnyReportPrompt({
        format,
        window: relatedWindow,
        alertId: alert?.id ?? null,
        subject: title,
      }),
      ...(alert ? { context: { alertId: alert.id } } : {}),
      autoSend: true,
    });
    setMessage(
      opened
        ? `Pedido a Bunny el informe en ${BUNNY_REPORT_FORMAT_LABEL[format]}. Se descargará cuando esté listo.`
        : 'Bunny no está activo para tu cuenta. Usa «Solo datos» o pide a un administrador que lo active.',
    );
  };

  const start = async (action: ReportAction) => {
    if (busy || startingExport.current || entities.length === 0) return;
    startingExport.current = true;
    setBusy(action);
    setProgress(null);
    setMessage('');
    const filename = `b89-investigacion-${(alert?.id ?? 'entidad').replace(/[^A-Za-z0-9_-]/gu, '_')}.xlsx`;
    let outputHandle: ReportFileHandle | null = null;
    const picker =
      action === 'xlsx' && typeof (window as SavePickerWindow).showSaveFilePicker === 'function';
    if (picker) {
      try {
        outputHandle = await (window as SavePickerWindow).showSaveFilePicker!({
          suggestedName: filename,
          types: [
            {
              description: 'Libro Excel de B89 SOC',
              accept: {
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
              },
            },
          ],
        });
      } catch (error) {
        setMessage(
          error instanceof Error && error.name === 'AbortError'
            ? 'Exportación cancelada: no elegiste dónde guardar el archivo.'
            : 'No se pudo abrir el selector de archivos del navegador.',
        );
        startingExport.current = false;
        setBusy(null);
        return;
      }
    }
    // Open synchronously in the click handler to preserve the browser's popup permission while
    // the authorized pages are collected. It is closed on cancel/failure.
    const opened = action === 'print' ? windowOpen() : null;
    if (action === 'print' && !opened) {
      setMessage('El navegador bloqueó la pestaña nueva. Permite ventanas emergentes para este sitio y vuelve a intentarlo.');
      startingExport.current = false;
      setBusy(null);
      return;
    }
    printWindow.current = opened;
    if (opened) {
      opened.document.open();
      opened.document.write(
        '<!doctype html><html lang="es"><meta charset="utf-8"><title>B89 SOC · Preparando informe</title><body style="font:16px Arial;padding:32px;color:#263444"><h1>B89 SOC · Preparando informe</h1><p>Buscando los eventos de la investigación…</p><p>Esta ventana mostrará la opción de imprimir o guardar como PDF cuando termine.</p></body></html>',
      );
      opened.document.close();
    }
    const controller = new AbortController();
    cancel.current = controller;
    highestProgress.current = 0;
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
            printWindow.current.document.body.innerHTML = `<h1>B89 SOC · Preparando informe</h1><p>Buscando eventos… ${escapeHtml(String(percent))} %</p>`;
          }
        },
      });
      if (controller.signal.aborted) {
        setMessage('Exportación cancelada.');
        return;
      }
      if (action === 'xlsx' && outputHandle) {
        const writable = await outputHandle.createWritable();
        await writeInvestigationXlsx(
          report,
          writable,
          (next) => {
            const percent = Math.max(highestProgress.current, progressPercent(next));
            highestProgress.current = percent;
            setProgress({ ...next, percent });
          },
          controller.signal,
        );
      } else if (action === 'xlsx') {
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
          setMessage('Exportación cancelada.');
          return;
        }
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
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
          setMessage('Exportación cancelada.');
          return;
        }
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `b89-investigacion-${(alert?.id ?? 'entidad').replace(/[^A-Za-z0-9_-]/gu, '_')}.csv`;
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
          ? 'Vista imprimible lista en otra pestaña: elige «Guardar como PDF» al imprimir.'
          : action === 'xlsx'
            ? outputHandle
              ? 'Libro Excel guardado en el archivo elegido.'
              : 'Libro Excel descargado.'
            : 'CSV descargado.';
      setProgress({
        phase: 'package',
        completed: 1,
        total: 1,
        percent: 100,
        message: completionMessage,
      });
      const rowSummary = report.truncated
        ? `Incluye ${report.events.length.toLocaleString('es-PE')} de ${report.totalEvents.toLocaleString('es-PE')} eventos (máximo por archivo). Acorta la ventana o quita entidades para incluir el resto.`
        : `${report.events.length.toLocaleString('es-PE')} eventos incluidos.`;
      setMessage(`${completionMessage} ${rowSummary}`);
    } catch (error) {
      if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
        setMessage('Exportación cancelada.');
      } else {
        const failure =
          error instanceof ReportCollectionError
            ? error.kind
            : error instanceof Error && error.message.includes('forbidden')
              ? 'forbidden'
              : null;
        setMessage(
          failure === 'forbidden'
            ? 'Tu cuenta no puede ver todos los eventos de esta investigación, así que no se creó el archivo. Pide acceso a un administrador del SOC.'
            : failure === 'unavailable'
              ? 'El SIEM no respondió y no se creó el archivo. Reintenta; si sigue fallando, revisa Salud de fuentes.'
              : failure === 'invalid'
                ? 'Los datos cambiaron mientras se preparaba el informe. Vuelve a intentarlo con una ventana más corta.'
                : failure === 'rejected'
                  ? 'El servidor rechazó el informe. Reduce la ventana de tiempo o las entidades y reintenta; si sigue, avisa al administrador.'
                  : 'No se pudo crear el archivo. Revisa la conexión y vuelve a intentarlo.',
        );
      }
      if (printWindow.current && !printWindow.current.closed) printWindow.current.close();
    } finally {
      cancel.current = null;
      printWindow.current = null;
      startingExport.current = false;
      setBusy(null);
    }
  };

  const stop = () => cancel.current?.abort();

  const noEntities = entities.length === 0;
  const blockedTip = noEntities
    ? 'Activa al menos una entidad en «Quiénes están involucrados» para exportar.'
    : undefined;
  const pick = (run: () => void) => () => {
    setMenuOpen(false);
    run();
  };
  const panels: EuiContextMenuPanelDescriptor[] = [
    {
      id: 0,
      title: 'Exportar la investigación',
      items: [
        ...(['pdf', 'xlsx', 'csv'] as const).map((format) => ({
          key: `bunny-${format}`,
          name: `Informe redactado por Bunny · ${BUNNY_REPORT_FORMAT_LABEL[format]}`,
          icon: 'discuss',
          disabled: Boolean(busy) || noEntities,
          toolTipContent: blockedTip,
          onClick: pick(() => askForReport(format)),
        })),
        { key: 'sep', isSeparator: true as const },
        {
          key: 'csv',
          name: 'Solo datos · CSV',
          icon: 'document',
          disabled: Boolean(busy) || noEntities,
          toolTipContent: blockedTip,
          onClick: pick(() => void start('csv')),
        },
        {
          key: 'xlsx',
          name: 'Solo datos · Excel (.xlsx)',
          icon: 'visTable',
          disabled: Boolean(busy) || noEntities,
          toolTipContent: blockedTip,
          onClick: pick(() => void start('xlsx')),
        },
        {
          key: 'print',
          name: 'Solo datos · Imprimir o guardar PDF',
          icon: 'printer',
          disabled: Boolean(busy) || noEntities,
          toolTipContent: blockedTip,
          onClick: pick(() => void start('print')),
        },
      ],
    },
  ];

  return (
    <>
      <EuiPopover
        id="b89ExportMenu"
        isOpen={menuOpen}
        closePopover={() => setMenuOpen(false)}
        panelPaddingSize="none"
        anchorPosition="downRight"
        button={
          <EuiButton
            size="s"
            iconType="arrowDown"
            iconSide="right"
            isLoading={Boolean(busy)}
            aria-haspopup="true"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((value) => !value)}
            data-test-subj="b89ExportMenuButton"
          >
            {busy ? 'Exportando…' : 'Exportar'}
          </EuiButton>
        }
      >
        <EuiContextMenu initialPanelId={0} panels={panels} />
        <p className="b89ExportMenu__hint">Bunny redacta el resumen; B89 añade los eventos.</p>
      </EuiPopover>
      {/* Siempre montado para que el lector de pantalla anuncie también el primer mensaje. */}
      <div className="b89ExportStatus" role="status" aria-live="polite" aria-atomic="true">
        {busy ? (
          <>
            <span>
              {!progress
                ? 'Preparando la exportación…'
                : progress.phase === 'query'
                  ? 'Buscando eventos…'
                  : 'Creando el archivo…'}
            </span>
            {progress && (
              <progress
                max={100}
                value={progressPercent(progress)}
                aria-label="Progreso de la exportación"
              />
            )}
            <EuiButtonEmpty size="xs" onClick={stop}>
              Cancelar exportación
            </EuiButtonEmpty>
          </>
        ) : message ? (
          <span>{message}</span>
        ) : null}
      </div>
    </>
  );
}

function windowOpen(): Window | null {
  return globalThis.window.open('', '_blank');
}

function escapeHtml(value: string): string {
  return value.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;');
}
