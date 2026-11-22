/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButtonEmpty, EuiCallOut } from '@elastic/eui';
import { PROVIDER_IDS, ServiceId } from '../../common';
import {
  formatNumber,
  integrationLinks,
  LastEvent,
  MetricList,
  SkeletonCard,
  StatusPill,
  usePlatformData,
} from './overview_parts';
import { STATUS_LABEL } from './service_status';
import { ServiceMark } from './vendor_logo';
import { ErrorCallout } from './primitives';
import { linkedMetrics, ProviderSeverity, ServiceModel, serviceModels } from './service_cards';

/**
 * «Integraciones»: cada servicio con su estado, qué recoge, cada cuánto, con qué reglas, la
 * política aplicada y los permisos que faltan con el siguiente paso.
 */
export function IntegrationsView({ basePath }: { basePath: string }) {
  const data = usePlatformData(basePath);
  const models = serviceModels(data);
  // Solo lo que hoy reporta un error de permisos (monitor, collector o override explícito).
  const blocked = models.filter((model) => model.status.label === STATUS_LABEL.permission);
  return (
    <main className="b89Page b89Overview">
      <header className="b89Hero">
        <div className="b89Hero__text">
          <span className="b89Hero__eyebrow">B89 SOC</span>
          <h1>Integraciones</h1>
          <p>
            Servicios conectados al SIEM, qué recoge cada uno, la política que se les aplica y los
            permisos pendientes.
          </p>
        </div>
        <div className="b89Hero__actions">
          <EuiButtonEmpty size="s" href={`${basePath}/app/b89-policies`}>
            Ver políticas
          </EuiButtonEmpty>
          <EuiButtonEmpty
            size="s"
            iconType="refresh"
            onClick={data.reload}
            isLoading={data.overview.loading}
          >
            Actualizar
          </EuiButtonEmpty>
        </div>
      </header>
      {data.overview.error != null && !data.overview.data && (
        <ErrorCallout error={data.overview.error} onRetry={data.overview.reload} />
      )}
      {blocked.length > 0 && (
        <EuiCallOut
          size="s"
          color="warning"
          iconType="alert"
          title={`${blocked.length} integración${blocked.length === 1 ? '' : 'es'} bloqueada${
            blocked.length === 1 ? '' : 's'
          } por permisos: ${blocked.map((model) => model.spec.name).join(', ')}.`}
        />
      )}
      <div className="b89IntegrationList">
        {models.map((model) =>
          model.loading ? (
            <SkeletonCard key={model.spec.id} />
          ) : (
            <IntegrationRow
              key={model.spec.id}
              model={model}
              basePath={basePath}
              severity={<ProviderSeverity model={model} data={data} basePath={basePath} />}
              missing={
                model.status.label === STATUS_LABEL.permission
                  ? (data.overview.data?.integrations[model.spec.id]?.missingPermissions ?? [])
                  : []
              }
            />
          ),
        )}
      </div>
    </main>
  );
}

function IntegrationRow({
  model,
  basePath,
  severity,
  missing,
}: {
  model: ServiceModel;
  basePath: string;
  severity: React.ReactNode;
  missing: readonly string[];
}) {
  const { spec, status } = model;
  const id = `b89-integration-${spec.id}`;
  const isProvider = (PROVIDER_IDS as readonly ServiceId[]).includes(spec.id);
  return (
    <article className="b89Integration" data-tone={status.tone} aria-labelledby={id}>
      <div className="b89Integration__lead">
        <ServiceMark spec={spec} basePath={basePath} />
        <div>
          <h2 id={id}>{spec.name}</h2>
          <p className="b89Integration__summary">{spec.summary}</p>
          <StatusPill status={status} />
          {status.detail && <p className="b89Integration__detail">{status.detail}</p>}
        </div>
      </div>
      <div className="b89Integration__numbers">
        {isProvider && (
          <div className="b89Integration__big">
            <span className="b89Tabular">
              {model.events24h === null ? '—' : formatNumber(model.events24h)}
            </span>
            <small>eventos 24 h</small>
          </div>
        )}
        {severity}
        <MetricList metrics={linkedMetrics(model.metrics, basePath)} />
        {model.lastEventAt !== undefined && <LastEvent iso={model.lastEventAt} />}
      </div>
      <dl className="b89Integration__facts">
        <div>
          <dt>Qué recoge</dt>
          <dd>
            <ul>
              {spec.collects.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </dd>
        </div>
        <div>
          <dt>Intervalo</dt>
          <dd>{spec.interval}</dd>
        </div>
        {spec.ruleRange && (
          <div>
            <dt>Reglas Wazuh</dt>
            <dd className="b89Tabular">{spec.ruleRange}</dd>
          </div>
        )}
        <div>
          <dt>Política aplicada</dt>
          <dd>{spec.policy}</dd>
        </div>
        {(status.tone !== 'ok' || missing.length > 0) && spec.nextSteps.length > 0 && (
          <div>
            <dt>Siguiente paso</dt>
            <dd>
              <ol>
                {spec.nextSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </dd>
          </div>
        )}
      </dl>
      {spec.flow && (
        <section className="b89Integration__flow" aria-label={`Recorrido de ${spec.name}`}>
          <h3>Cómo llegan los eventos a B89</h3>
          <ol>
            {spec.flow.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <p>{spec.flow.coverageNote}</p>
        </section>
      )}
      <details className="b89Integration__technical">
        <summary>Detalles técnicos para soporte</summary>
        <dl className="b89Integration__facts">
          {spec.ruleRange && (
            <div>
              <dt>Reglas Wazuh</dt>
              <dd className="b89Tabular">{spec.ruleRange}</dd>
            </div>
          )}
          <div>
            <dt>Permisos requeridos</dt>
            <dd>
              <ul>
                {spec.permissions.map((permission) => (
                  <li key={permission}>{permission}</li>
                ))}
                {missing.map((permission) => (
                  <li key={`missing-${permission}`} className="b89Integration__missing">
                    Falta: {permission}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        </dl>
      </details>
      <footer className="b89Integration__links">
        {integrationLinks(spec, basePath).map((link) => (
          <EuiButtonEmpty key={link.href} size="xs" href={link.href} flush="left">
            {link.label}
          </EuiButtonEmpty>
        ))}
      </footer>
    </article>
  );
}
