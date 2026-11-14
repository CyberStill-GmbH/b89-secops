/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiBasicTable } from '@elastic/eui';
import type { EuiBasicTableColumn } from '@elastic/eui';
import {
  actionKindShort,
  AI_RUN_STATUS_LABEL,
  AI_RUN_STATUS_TONE,
  AI_TRIGGER_LABEL,
  AiRunStatusView,
  AiRunSummary,
  confidenceLabel,
  formatCount,
  formatMicroUsd,
  inferenceLabel,
  isActive,
  NO_DATA,
  stageLabel,
  verdictLabel,
} from '../../common';
import { HealthMark, Mono, PriorityMark, Timestamp } from './primitives';

export function RunStatusMark({ status }: { status: AiRunStatusView }) {
  return <HealthMark tone={AI_RUN_STATUS_TONE[status]} label={AI_RUN_STATUS_LABEL[status]} />;
}

/**
 * Costo de una corrida. Sin llamada al modelo no hay costo que estimar (se dice así, no «US$ 0»);
 * con modelo y sin cifra queda «Sin dato».
 */
export function runCostText(
  run: Pick<AiRunSummary, 'inference' | 'estimatedCostMicroUsd'>,
): string {
  const cost = run.estimatedCostMicroUsd;
  if (run.inference === 'none' && (cost === null || cost === 0)) return 'Sin llamada al modelo';
  return formatMicroUsd(cost);
}

export function RunStage({ stage }: { stage: string | null }) {
  if (!stage) return null;
  const label = stageLabel(stage);
  return <span className="b89CellMeta">{label ?? <Mono>{stage}</Mono>}</span>;
}

export function AiRunsTable({
  items,
  loading,
  selectedId,
  onSelect,
  emptyMessage,
}: {
  items: readonly AiRunSummary[];
  loading: boolean;
  selectedId: string | null;
  onSelect: (id: string) => void;
  emptyMessage: string;
}) {
  const columns: Array<EuiBasicTableColumn<AiRunSummary>> = [
    {
      field: 'status',
      name: 'Estado',
      width: '170px',
      render: (value: AiRunStatusView, run: AiRunSummary) => (
        <span className="b89CellTitle">
          <RunStatusMark status={value} />
          {isActive(value) && <RunStage stage={run.stage} />}
        </span>
      ),
    },
    {
      field: 'priority',
      name: 'Prioridad',
      width: '96px',
      render: (value: AiRunSummary['priority']) =>
        value ? <PriorityMark priority={value} /> : <span className="b89Muted">{NO_DATA}</span>,
    },
    {
      field: 'subject',
      name: 'Investigación',
      truncateText: false,
      render: (subject: AiRunSummary['subject'], run: AiRunSummary) => (
        <span className="b89CellTitle">
          <button
            type="button"
            className="b89Ai__open"
            data-b89-no-translate=""
            onClick={(event) => {
              event.stopPropagation();
              onSelect(run.id);
            }}
          >
            {subject.title || 'Sin título'}
          </button>
          <span className="b89CellMeta">
            {AI_TRIGGER_LABEL[run.trigger]}
            {run.alertCount !== null &&
              ` · ${formatCount(run.alertCount)} ${run.alertCount === 1 ? 'alerta' : 'alertas'}`}
            {run.initiatedBy && (
              <>
                {' · '}
                <span data-b89-no-translate="">{run.initiatedBy}</span>
              </>
            )}
          </span>
        </span>
      ),
      mobileOptions: { header: false },
    },
    {
      field: 'inference',
      name: 'Inferencia',
      width: '110px',
      render: (value: AiRunSummary['inference']) =>
        value === null ? (
          <span className="b89Muted">{NO_DATA}</span>
        ) : (
          <span className="b89Ai__tier" data-tier={value}>
            {inferenceLabel(value)}
          </span>
        ),
    },
    {
      field: 'verdict',
      name: 'Recomendación',
      width: '200px',
      render: (value: AiRunSummary['verdict'], run: AiRunSummary) =>
        value === null ? (
          <span className="b89Muted">Sin veredicto</span>
        ) : (
          <span className="b89CellTitle">
            <span>{verdictLabel(value)}</span>
            <span className="b89CellMeta">{confidenceLabel(run.confidence)}</span>
          </span>
        ),
    },
    {
      field: 'actionKinds',
      name: 'Acciones',
      width: '150px',
      render: (kinds: readonly string[]) =>
        kinds.length === 0 ? (
          <span className="b89Muted">Ninguna</span>
        ) : (
          <span className="b89Ai__actionKinds">
            {kinds.map((kind) => (
              <span key={kind} className="b89Ai__actionKind">
                {actionKindShort(kind) ?? <Mono>{kind}</Mono>}
              </span>
            ))}
          </span>
        ),
    },
    {
      field: 'estimatedCostMicroUsd',
      name: 'Costo estimado',
      width: '170px',
      render: (_value: number | null, run: AiRunSummary) => (
        <span className="b89Tabular">{runCostText(run)}</span>
      ),
    },
    {
      field: 'updatedAt',
      name: 'Actualizada',
      width: '120px',
      render: (value: string | null) => <Timestamp iso={value} />,
    },
  ];

  return (
    <EuiBasicTable<AiRunSummary>
      items={items as AiRunSummary[]}
      columns={columns}
      loading={loading}
      responsive
      tableLayout="auto"
      rowProps={(run) => ({
        onClick: () => onSelect(run.id),
        className: `b89Row${run.priority ? ` b89Row--${run.priority.toLowerCase()}` : ''}${
          run.id === selectedId ? ' euiTableRow-isSelected' : ''
        }`,
      })}
      noItemsMessage={emptyMessage}
    />
  );
}
