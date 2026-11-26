/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * DLP de endpoints en el «Resumen del SOC»: una línea que responde «¿los equipos están protegidos y
 * encontró algo?», con enlace a la pantalla DLP. Solo para quien tiene `dlp.read`.
 */

import React, { useEffect, useState } from 'react';
import type { DlpFindings } from '../../common/dlp_findings';
import type { DlpEndpoint } from '../api/dlp';
import { getDlpEndpoints, getDlpFindings } from '../api/dlp';
import { useConsole } from './console_context';
import { summarizeFleet } from './dlp_model';
import { FerrispectorMark } from './ferrispector_mark';

export interface DlpOverviewModel {
  readonly tone: 'ok' | 'warn' | 'unknown';
  readonly text: string;
}

export function dlpOverviewModel(
  endpoints: readonly DlpEndpoint[] | null,
  findings: DlpFindings | null,
): DlpOverviewModel {
  if (!endpoints) return { tone: 'unknown', text: 'No se pudo consultar el estado de los equipos.' };
  const fleet = summarizeFleet(endpoints);
  const parts: string[] = [];
  if (fleet.total === 0) parts.push('Ningún equipo conectado todavía');
  else if (fleet.attention > 0) parts.push(fleet.headline);
  else parts.push(`${fleet.counts.ok + fleet.counts.updating} de ${fleet.total} ${fleet.total === 1 ? 'equipo protegido' : 'equipos protegidos'}`);
  let found = 0;
  if (findings && findings.readable === 'ok') {
    found = findings.total;
    parts.push(found === 0 ? 'sin hallazgos en 24 h' : `${found} ${found === 1 ? 'hallazgo' : 'hallazgos'} en 24 h`);
    if (findings.agentIssues.length) {
      parts.push(`${findings.agentIssues.length} con fallas del agente`);
    }
  }
  const warn = fleet.attention > 0 || found > 0 || (findings?.agentIssues.length ?? 0) > 0;
  return { tone: warn ? 'warn' : 'ok', text: parts.join(' · ') };
}

export function DlpOverviewLineView({ model, basePath }: { model: DlpOverviewModel; basePath: string }) {
  return (
    <section className="b89DlpLine" data-tone={model.tone} aria-labelledby="b89-dlp-line">
      <FerrispectorMark size={24} basePath={basePath} />
      <p>
        <strong id="b89-dlp-line">DLP de endpoints:</strong> <span>{model.text}</span>
      </p>
      <a href={`${basePath}/app/b89-dlp`}>Ver DLP</a>
    </section>
  );
}

export function DlpOverviewLine({ basePath }: { basePath: string }) {
  const { api } = useConsole();
  const [model, setModel] = useState<DlpOverviewModel | null>(null);
  useEffect(() => {
    let active = true;
    const load = async () => {
      const [endpoints, findings] = await Promise.all([
        getDlpEndpoints(api).then((result) => result.items, () => null),
        getDlpFindings(basePath, '24h'),
      ]);
      if (active) setModel(dlpOverviewModel(endpoints, findings));
    };
    void load();
    const timer = globalThis.setInterval(() => void load(), 60_000);
    return () => {
      active = false;
      globalThis.clearInterval(timer);
    };
  }, [api, basePath]);
  return model ? <DlpOverviewLineView model={model} basePath={basePath} /> : null;
}
