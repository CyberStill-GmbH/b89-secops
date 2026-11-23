/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButtonEmpty, EuiLoadingContent } from '@elastic/eui';
import {
  AGENT_GROUP_POLICIES,
  MANAGER_POLICIES,
  PolicyFact,
  RETENTION_POLICIES,
} from '../../common';
import { fetchOverview } from '../api/overview';
import { formatNumber } from './overview_parts';
import { B89Page } from './console_context';
import { ErrorCallout, useAsync } from './primitives';

/**
 * «Políticas»: resumen de lo aplicado como código (docs/16-politicas.md). Los conteos de agentes
 * por grupo salen del último muestreo de wazuh-monitoring-* con la identidad de quien mira.
 */
export function PoliciesView({ basePath }: { basePath: string }) {
  const overview = useAsync(() => fetchOverview(basePath), [basePath]);
  const agents = overview.data?.agents ?? null;
  const counted = overview.data?.monitoringAccess === 'ok';
  return (
    <B89Page
      title="Políticas"
      description="Reglas de seguridad aplicadas a los agentes, al servidor Wazuh y a la retención de datos."
      actions={
        <EuiButtonEmpty size="s" href={`${basePath}/app/b89-integrations`}>
          Ver integraciones
        </EuiButtonEmpty>
      }
    >
      <div className="b89Overview" lang="es-PE" translate="no">
      {overview.error != null && (
        <ErrorCallout error={overview.error} onRetry={overview.reload} />
      )}
      <section className="b89Panel" aria-labelledby="b89-policy-manager">
        <div className="b89Panel__header">
          <h2 id="b89-policy-manager">Servidor Wazuh y detección</h2>
        </div>
        <FactGrid facts={MANAGER_POLICIES} />
      </section>

      <section className="b89Panel" aria-labelledby="b89-policy-groups">
        <div className="b89Panel__header">
          <h2 id="b89-policy-groups">Grupos de agentes</h2>
          <span className="b89Panel__meta">
            {agents?.measuredAt
              ? 'Agentes según el último muestreo'
              : 'FIM · SCA · inventario · logs'}
          </span>
        </div>
        {overview.loading && !overview.data ? (
          <EuiLoadingContent lines={4} />
        ) : (
          <div className="b89TableScroll">
            <table className="b89PolicyTable">
              <thead>
                <tr>
                  <th scope="col">Grupo</th>
                  <th scope="col">Agentes</th>
                  <th scope="col">Integridad (FIM)</th>
                  <th scope="col">SCA</th>
                  <th scope="col">Inventario y vulnerabilidades</th>
                  <th scope="col">Logs</th>
                </tr>
              </thead>
              <tbody>
                {AGENT_GROUP_POLICIES.map((group) => (
                  <tr key={group.name}>
                    <th scope="row">
                      <code>{group.name}</code>
                    </th>
                    <td className="b89Tabular">
                      {counted ? (
                        formatNumber(agents?.groups[group.name] ?? 0)
                      ) : (
                        <span className="b89Muted" title="Sin dato">
                          Sin dato
                        </span>
                      )}
                    </td>
                    <td>{group.fim}</td>
                    <td>{group.sca}</td>
                    <td>{group.inventory}</td>
                    <td>{group.logs}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!counted && overview.data && (
          <p className="b89Panel__empty">
            Tu rol no incluye el conteo de agentes por grupo. Pídelo a un Administrador de
            plataforma si lo necesitas.
          </p>
        )}
      </section>

      <section className="b89Panel" aria-labelledby="b89-policy-retention">
        <div className="b89Panel__header">
          <h2 id="b89-policy-retention">Retención de datos del SIEM</h2>
          <span className="b89Panel__meta">Sin copias externas: lo que vence se borra</span>
        </div>
        <FactGrid facts={RETENTION_POLICIES} />
      </section>

      <details className="b89Guide__details">
        <summary>Cómo se aplican (para plataforma)</summary>
        <p>
          Las políticas viven como código y se vuelven a aplicar con{' '}
          <code>infra/wazuh/policies/apply-policies.sh</code>. La retención la gestiona ISM en el
          SIEM; este nodo no tiene copias en S3.
        </p>
      </details>
      </div>
    </B89Page>
  );
}

function FactGrid({ facts }: { facts: readonly PolicyFact[] }) {
  return (
    <dl className="b89FactGrid">
      {facts.map((fact) => (
        <div key={fact.title} className="b89FactGrid__item">
          <dt>{fact.title}</dt>
          <dd>
            <strong>{fact.value}</strong>
            <span>{fact.detail}</span>
          </dd>
        </div>
      ))}
    </dl>
  );
}
