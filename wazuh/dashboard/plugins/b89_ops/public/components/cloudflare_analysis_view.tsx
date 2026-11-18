/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiButtonEmpty,
  EuiCallOut,
  EuiLoadingContent,
  EuiSpacer,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  AnomalySection,
  BackofficeSession,
  BASELINE_DAYS,
  Caller,
  CHANNEL_LABEL,
  CloudflareAnalysis,
  Finding,
  LIMA_LABEL,
  limaTime,
  minuteTimeline,
  MoneyCaller,
  RecordsLink,
  RISK_LABEL,
  RISK_POINTS,
  RiskLevel,
  TimelineMinute,
} from '../../common';
import { fetchTraffic, fetchTrafficAnalysis } from '../api/cloudflare_traffic';
import {
  anomalyRecords,
  CHANNEL_COLOR,
  errorMessage,
  formatCount,
  intervalLabel,
  moneyColumns,
  percent,
  truncate,
} from './cloudflare_traffic_model';
import { DataZone, Mono } from './primitives';

type OpenRecords = (link: RecordsLink) => void;

const RISK_COLOR: Readonly<Record<RiskLevel, string>> = {
  critical: 'danger',
  high: 'warning',
  medium: 'accent',
  low: 'hollow',
};

const SESSIONS_VISIBLE = 25;

/**
 * Pestaña «Análisis» de «Tráfico de Cloudflare»: primero los hallazgos del periodo, luego el
 * detalle (sesiones del backoffice, dinero, lecturas sensibles y anomalías de ML).
 */
export function CloudflareAnalysisPanel({
  basePath,
  from,
  to,
  zone,
  reloadKey,
  onOpenRecords,
}: {
  basePath: string;
  from: string;
  to: string;
  zone?: string;
  reloadKey: number;
  onOpenRecords: OpenRecords;
}) {
  const [data, setData] = useState<CloudflareAnalysis | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    fetchTrafficAnalysis(
      basePath,
      { from, to, zones: zone ? [zone] : [] },
      { signal: controller.signal },
    ).then(
      (response) => {
        setData(response);
        setLoading(false);
      },
      (failure: unknown) => {
        if (controller.signal.aborted) return;
        setError(failure);
        setData(null);
        setLoading(false);
      },
    );
    return () => controller.abort();
  }, [basePath, from, to, zone, reloadKey]);

  if (error) {
    const message = errorMessage(error);
    return <EuiCallOut color={message.tone} iconType="alert" size="s" title={message.title} />;
  }
  if (loading && !data) {
    return (
      <div aria-busy="true">
        <SamplingNote />
        <EuiSpacer size="m" />
        <EuiLoadingContent lines={10} />
      </div>
    );
  }
  if (!data) return null;
  return <AnalysisContent data={data} basePath={basePath} onOpenRecords={onOpenRecords} />;
}

export function AnalysisContent({
  data,
  basePath,
  onOpenRecords,
}: {
  data: CloudflareAnalysis;
  basePath: string;
  onOpenRecords: OpenRecords;
}) {
  return (
    <div className="b89Analysis">
      <SamplingNote data={data} />
      {data.partial && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            color="warning"
            iconType="alert"
            size="s"
            title="Respuesta parcial del Indexer: algunos datos pueden faltar. Reintente en unos segundos."
          />
        </>
      )}
      {!data.baseline.available && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            color="warning"
            iconType="clock"
            size="s"
            title={`Sin línea base de ${BASELINE_DAYS} días: no se puede marcar «IP nueva» ni «país nuevo».`}
          />
        </>
      )}
      <EuiSpacer size="m" />
      <FindingsSection
        findings={data.findings}
        httpRecords={data.httpRecords}
        onOpenRecords={onOpenRecords}
      />
      <EuiSpacer size="l" />
      <SessionsSection data={data} basePath={basePath} onOpenRecords={onOpenRecords} />
      <EuiSpacer size="l" />
      <MoneySection data={data} onOpenRecords={onOpenRecords} />
      <EuiSpacer size="l" />
      <SensitiveSection data={data} onOpenRecords={onOpenRecords} />
      <EuiSpacer size="l" />
      <AnomaliesSection anomalies={data.anomalies} onOpenRecords={onOpenRecords} />
    </div>
  );
}

export function SamplingNote({ data }: { data?: CloudflareAnalysis }) {
  return (
    <p className="b89Analysis__sampling" role="note">
      <strong>Datos muestreados.</strong> Cloudflare entrega el tráfico HTTP de b89.io muestreado
      (~1 de cada 11 peticiones): todos los conteos son <em>registros muestreados</em>, no
      peticiones reales; una sola aparición puede representar varias.
      {data
        ? ` En este rango: ${formatCount(data.httpRecords)} registros HTTP, ${formatCount(
            data.sampledRecords,
          )} marcados como muestreados.`
        : ''}{' '}
      Horas en {LIMA_LABEL}.
    </p>
  );
}

function SectionTitle({ id, title, meta }: { id: string; title: string; meta?: React.ReactNode }) {
  return (
    <div className="b89Analysis__sectionHeader">
      <EuiTitle size="xs">
        <h2 id={id}>{title}</h2>
      </EuiTitle>
      {meta && <span className="b89Analysis__meta">{meta}</span>}
    </div>
  );
}

function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return (
    <EuiBadge color={RISK_COLOR[level]} data-level={level}>
      {RISK_LABEL[level]}
      {score !== undefined ? ` · ${score}` : ''}
    </EuiBadge>
  );
}

function HostingBadge({ hosting }: { hosting: string | null }) {
  if (!hosting) return null;
  return (
    <EuiToolTip content="ASN de hosting, nube o VPN: una persona del backoffice no debería salir de aquí.">
      <EuiBadge color="warning">VPN/hosting · {hosting}</EuiBadge>
    </EuiToolTip>
  );
}

function RecordsButton({
  link,
  onOpenRecords,
  label = 'Ver registros',
}: {
  link: RecordsLink | null;
  onOpenRecords: OpenRecords;
  label?: string;
}) {
  if (!link) return null;
  return (
    <EuiButtonEmpty size="xs" iconType="list" flush="left" onClick={() => onOpenRecords(link)}>
      {label}
    </EuiButtonEmpty>
  );
}

/* ------------------------------------------------------------ Hallazgos */

export function FindingsSection({
  findings,
  httpRecords,
  onOpenRecords,
}: {
  findings: readonly Finding[];
  httpRecords: number;
  onOpenRecords: OpenRecords;
}) {
  return (
    <section className="b89Analysis__section" aria-labelledby="b89-an-findings">
      <SectionTitle
        id="b89-an-findings"
        title="Resumen del periodo"
        meta={`${formatCount(findings.length)} hallazgo${findings.length === 1 ? '' : 's'}, de mayor a menor gravedad`}
      />
      {findings.length === 0 ? (
        <p className="b89Analysis__empty">
          {httpRecords === 0
            ? 'Sin tráfico HTTP en el rango: no hay nada que analizar.'
            : 'Sin hallazgos en el periodo: ninguna sesión desde VPN/hosting, exportación desde fuera de Perú, login desde país nuevo ni movimiento de dinero desde IP nueva o fuera de horario.'}
        </p>
      ) : (
        <ol className="b89Analysis__findings">
          {findings.map((finding) => (
            <li key={finding.id} className="b89Finding" data-severity={finding.severity}>
              <div className="b89Finding__head">
                <RiskBadge level={finding.severity} />
                <strong className="b89Finding__title">{finding.title}</strong>
              </div>
              <DataZone>
                <p className="b89Finding__summary">{finding.summary}</p>
              </DataZone>
              <dl className="b89Finding__evidence">
                {finding.evidence
                  .filter((item) => item.value !== '' && item.value !== '0')
                  .map((item) => (
                    <div key={item.label}>
                      <dt>{item.label}</dt>
                      <dd className="b89Tabular">
                        <DataZone>{item.value}</DataZone>
                      </dd>
                    </div>
                  ))}
              </dl>
              <RecordsButton
                link={finding.records}
                onOpenRecords={onOpenRecords}
                label="Ver los registros de este hallazgo"
              />
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/* -------------------------------------------------------------- Sesiones */

function SessionsSection({
  data,
  basePath,
  onOpenRecords,
}: {
  data: CloudflareAnalysis;
  basePath: string;
  onOpenRecords: OpenRecords;
}) {
  const [showAll, setShowAll] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const sessions = showAll ? data.sessions : data.sessions.slice(0, SESSIONS_VISIBLE);
  return (
    <section className="b89Analysis__section" aria-labelledby="b89-an-sessions">
      <SectionTitle
        id="b89-an-sessions"
        title="Sesiones del backoffice"
        meta="paymentsv2 + prodv2-apipayments (y staging) · una fila por IP, ordenadas por riesgo"
      />
      <details className="b89Analysis__how">
        <summary>¿Cómo se calcula el riesgo?</summary>
        <p>
          Suma de motivos, tope 100 (Crítico ≥ 70, Alto ≥ 45, Medio ≥ 20). VPN/hosting +
          {RISK_POINTS.hosting}, renovar token sin iniciar sesión en el rango +
          {RISK_POINTS.refreshWithoutLogin}, exportaciones +{RISK_POINTS.exports}, fuera de Perú +
          {RISK_POINTS.outsidePeru}, mover dinero o escribir en el backoffice +{RISK_POINTS.money},
          login desde país nuevo +{RISK_POINTS.newCountry}, 3 o más User-Agents +
          {RISK_POINTS.manyUserAgents}, 3 o más 403 de staff +{RISK_POINTS.staffDenied}, 5 o más
          logins fallidos +{RISK_POINTS.failedLogins}, IP no vista en {BASELINE_DAYS} días +
          {RISK_POINTS.newIp}.
        </p>
      </details>
      {data.sessions.length === 0 ? (
        <p className="b89Analysis__empty">Sin tráfico del backoffice en el rango.</p>
      ) : (
        <div className="b89Analysis__tableWrap">
          <table className="b89Analysis__table">
            <thead>
              <tr>
                <th scope="col">Riesgo</th>
                <th scope="col">IP · red</th>
                <th scope="col">Primera / última (Lima)</th>
                <th scope="col" className="b89Analysis__num">
                  Logins
                </th>
                <th scope="col" className="b89Analysis__num">
                  Renov.
                </th>
                <th scope="col" className="b89Analysis__num">
                  Staff 2xx / 403
                </th>
                <th scope="col" className="b89Analysis__num">
                  Escrit.
                </th>
                <th scope="col" className="b89Analysis__num">
                  Export.
                </th>
                <th scope="col" className="b89Analysis__num">
                  UAs
                </th>
                <th scope="col" className="b89Analysis__num">
                  Hosts
                </th>
                <th scope="col">Motivos</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <SessionRow
                  key={session.ip}
                  session={session}
                  expanded={expanded === session.ip}
                  onToggle={() => setExpanded(expanded === session.ip ? null : session.ip)}
                  data={data}
                  basePath={basePath}
                  onOpenRecords={onOpenRecords}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data.sessions.length > SESSIONS_VISIBLE && (
        <EuiButtonEmpty size="xs" onClick={() => setShowAll(!showAll)}>
          {showAll
            ? 'Mostrar las primeras'
            : `Mostrar todas (${formatCount(data.sessions.length)})`}
        </EuiButtonEmpty>
      )}
    </section>
  );
}

export function SessionRow({
  session,
  expanded,
  onToggle,
  data,
  basePath,
  onOpenRecords,
}: {
  session: BackofficeSession;
  expanded: boolean;
  onToggle: () => void;
  data: CloudflareAnalysis;
  basePath: string;
  onOpenRecords: OpenRecords;
}) {
  const link: RecordsLink = { from: data.from, to: data.to, ip: session.ip };
  return (
    <>
      <tr className="b89Analysis__row" data-level={session.risk.level}>
        <td>
          <RiskBadge level={session.risk.level} score={session.risk.score} />
        </td>
        <td>
          <button
            type="button"
            className="b89Analysis__expand"
            aria-expanded={expanded}
            onClick={onToggle}
            title="Ver la línea de tiempo minuto a minuto de esta IP"
          >
            <span aria-hidden="true">{expanded ? '▾' : '▸'}</span> <Mono>{session.ip}</Mono>
          </button>
          <div className="b89Analysis__net">
            <DataZone>
              {session.country ?? '??'} · {session.asn ? `AS${session.asn} ` : ''}
              {session.asnName ?? 'ASN desconocido'}
            </DataZone>{' '}
            <HostingBadge hosting={session.hosting} />
            {session.newIp && <EuiBadge color="hollow">IP nueva</EuiBadge>}
          </div>
        </td>
        <td className="b89Analysis__time">
          {limaTime(session.firstSeen)}
          <br />
          {limaTime(session.lastSeen)}
        </td>
        <td className="b89Analysis__num">
          {formatCount(session.logins)}
          {session.loginsFailed > 0 && (
            <span className="b89Analysis__sub">
              {' '}
              ({formatCount(session.loginsFailed)} fallidos)
            </span>
          )}
        </td>
        <td className="b89Analysis__num">{formatCount(session.refreshes)}</td>
        <td className="b89Analysis__num">
          {formatCount(session.staffOk)} / {formatCount(session.staffDenied)}
        </td>
        <td className="b89Analysis__num">{formatCount(session.writes)}</td>
        <td className="b89Analysis__num">{formatCount(session.exports)}</td>
        <td className="b89Analysis__num">{formatCount(session.userAgents)}</td>
        <td className="b89Analysis__num" title={session.hosts.join(', ')}>
          {formatCount(session.hosts.length)}
        </td>
        <td>
          {session.risk.reasons.length === 0 ? (
            <span className="b89Analysis__sub">Sin motivos</span>
          ) : (
            <ul className="b89Analysis__reasons">
              {session.risk.reasons.map((reason) => (
                <li key={reason.code}>
                  {reason.label} <span className="b89Analysis__sub">+{reason.points}</span>
                </li>
              ))}
            </ul>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="b89Analysis__detail">
          <td colSpan={11}>
            <div className="b89Analysis__detailMeta">
              <span>
                Hosts: <DataZone>{session.hosts.join(', ') || '—'}</DataZone>
              </span>
              <span>
                User-Agents:{' '}
                <DataZone>
                  {session.topUserAgents.map((ua) => truncate(ua, 70)).join(' | ') || '—'}
                </DataZone>
              </span>
              <RecordsButton
                link={link}
                onOpenRecords={onOpenRecords}
                label="Ver todos sus registros"
              />
            </div>
            <IpTimeline basePath={basePath} data={data} ip={session.ip} />
          </td>
        </tr>
      )}
    </>
  );
}

/** Línea de tiempo minuto a minuto de una IP (hasta 200 registros HTTP del rango). */
function IpTimeline({
  basePath,
  data,
  ip,
}: {
  basePath: string;
  data: CloudflareAnalysis;
  ip: string;
}) {
  const [minutes, setMinutes] = useState<TimelineMinute[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    const controller = new AbortController();
    fetchTraffic(
      basePath,
      { from: data.from, to: data.to, datasets: ['http'], zones: data.zones, ip },
      { size: 200, signal: controller.signal },
    ).then(
      (response) => {
        setMinutes(minuteTimeline(response.events));
        setTruncated(response.nextCursor !== null);
      },
      (failure: unknown) => {
        if (!controller.signal.aborted) setError(failure);
      },
    );
    return () => controller.abort();
  }, [basePath, data.from, data.to, data.zones, ip]);
  if (error) {
    return <EuiCallOut color="warning" size="s" title={errorMessage(error).title} />;
  }
  if (!minutes) return <EuiLoadingContent lines={3} />;
  return <TimelineList minutes={minutes} truncated={truncated} />;
}

export function TimelineList({
  minutes,
  truncated,
}: {
  minutes: readonly TimelineMinute[];
  truncated: boolean;
}) {
  if (minutes.length === 0)
    return <p className="b89Analysis__empty">Sin registros HTTP de esta IP.</p>;
  return (
    <>
      {truncated && (
        <p className="b89Analysis__sub">
          Se muestran los 200 registros más recientes; «Ver todos sus registros» abre el resto.
        </p>
      )}
      <ol className="b89Timeline" aria-label="Línea de tiempo minuto a minuto (Lima)">
        {minutes.map((minute) => (
          <li key={minute.minute}>
            <span className="b89Timeline__minute b89Tabular">{minute.minute.slice(5)}</span>
            <ul>
              {minute.lines.map((line) => (
                <li key={line.text} data-money={line.money}>
                  <DataZone>
                    <Mono>{line.text}</Mono>
                  </DataZone>
                  {line.count > 1 && <span className="b89Analysis__sub"> ×{line.count}</span>}
                  {line.money && <EuiBadge color="danger">dinero</EuiBadge>}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>
    </>
  );
}

/* --------------------------------------------------------------- Dinero */

function CallerNet({ caller }: { caller: Caller }) {
  return (
    <>
      <Mono>{caller.ip}</Mono>
      <div className="b89Analysis__net">
        <DataZone>
          {caller.country ?? '??'} · {caller.asn ? `AS${caller.asn} ` : ''}
          {caller.asnName ?? 'ASN desconocido'}
        </DataZone>{' '}
        <HostingBadge hosting={caller.hosting} />
      </div>
    </>
  );
}

const keys = (buckets: ReadonlyArray<{ key: string; count: number }>) =>
  buckets.map((bucket) => `${bucket.key} (${formatCount(bucket.count)})`).join(', ');

function MoneySection({
  data,
  onOpenRecords,
}: {
  data: CloudflareAnalysis;
  onOpenRecords: OpenRecords;
}) {
  const columns = moneyColumns(data.money.histogram, data.money.interval);
  const labelEvery = Math.max(1, Math.ceil(columns.length / 8));
  const total = data.money.totals.backoffice + data.money.totals.integration;
  return (
    <section className="b89Analysis__section" aria-labelledby="b89-an-money">
      <SectionTitle
        id="b89-an-money"
        title="Movimientos de dinero"
        meta={`${formatCount(total)} registros · backoffice ${formatCount(
          data.money.totals.backoffice,
        )} · integración ${formatCount(data.money.totals.integration)}`}
      />
      <p className="b89Analysis__sub">
        Llamadas que mueven dinero o cambian estado: aceptar cotizaciones (payouts, remesas),
        transacciones de saldo, operaciones MTC, cambio masivo de órdenes, payin, tipo de cambio
        manual y cualquier POST/PUT/PATCH/DELETE en /backoffice/. Sombreado: 22:00–06:00 (Lima).
      </p>
      {total === 0 ? (
        <p className="b89Analysis__empty">Ninguna llamada de dinero en el rango.</p>
      ) : (
        <div className="b89Traffic__panel">
          <div className="b89Trend__toolbar">
            <span className="b89Analysis__sub">
              Cada {intervalLabel(data.money.interval) ?? data.money.interval}
            </span>
            <ul className="b89Legend">
              {(['backoffice', 'integration'] as const).map((channel) => (
                <li key={channel}>
                  <span
                    aria-hidden="true"
                    className="b89Legend__swatch"
                    style={{ backgroundColor: CHANNEL_COLOR[channel] }}
                  />
                  <span>{CHANNEL_LABEL[channel]}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="b89Trend__plot" role="list" aria-label="Llamadas de dinero por intervalo">
            {columns.map((column, index) => (
              <div
                key={column.at}
                className="b89Trend__column"
                role="listitem"
                data-off-hours={column.offHours}
              >
                <EuiToolTip content={column.summary} position="top" display="block">
                  <div
                    className="b89Trend__stack"
                    tabIndex={0}
                    aria-label={column.summary}
                    style={{ height: `${column.height}%` }}
                  >
                    {column.integration > 0 && (
                      <span
                        style={{
                          flexGrow: column.integration,
                          backgroundColor: CHANNEL_COLOR.integration,
                        }}
                      />
                    )}
                    {column.backoffice > 0 && (
                      <span
                        style={{
                          flexGrow: column.backoffice,
                          backgroundColor: CHANNEL_COLOR.backoffice,
                        }}
                      />
                    )}
                  </div>
                </EuiToolTip>
                <span className="b89Trend__tick" aria-hidden="true">
                  {index % labelEvery === 0 ? column.label.slice(5) : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      {data.money.callers.length > 0 && (
        <div className="b89Analysis__tableWrap">
          <table className="b89Analysis__table">
            <thead>
              <tr>
                <th scope="col">Quién llama</th>
                <th scope="col">Canal</th>
                <th scope="col">Endpoints</th>
                <th scope="col" className="b89Analysis__num">
                  Registros
                </th>
                <th scope="col">Estados</th>
                <th scope="col">User-Agent</th>
                <th scope="col">Señales</th>
                <th scope="col" />
              </tr>
            </thead>
            <tbody>
              {data.money.callers.map((caller) => (
                <MoneyCallerRow
                  key={caller.ip}
                  caller={caller}
                  data={data}
                  onOpenRecords={onOpenRecords}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function MoneyCallerRow({
  caller,
  data,
  onOpenRecords,
}: {
  caller: MoneyCaller;
  data: CloudflareAnalysis;
  onOpenRecords: OpenRecords;
}) {
  return (
    <tr className="b89Analysis__row" data-new={caller.newCaller === true}>
      <td>
        <CallerNet caller={caller} />
      </td>
      <td>{caller.channel === 'mixed' ? 'Mixto' : CHANNEL_LABEL[caller.channel]}</td>
      <td>
        <DataZone>{keys(caller.endpoints)}</DataZone>
      </td>
      <td className="b89Analysis__num">{formatCount(caller.count)}</td>
      <td>{keys(caller.statuses)}</td>
      <td>
        <DataZone>{truncate(caller.userAgents[0]?.key ?? null, 48)}</DataZone>
      </td>
      <td>
        {caller.newCaller && <EuiBadge color="danger">Nueva en {BASELINE_DAYS} días</EuiBadge>}
        {caller.offHours > 0 && (
          <EuiBadge color="warning">Fuera de horario · {formatCount(caller.offHours)}</EuiBadge>
        )}
        {caller.newCaller === false && caller.offHours === 0 && (
          <span className="b89Analysis__sub">Habitual</span>
        )}
      </td>
      <td>
        <RecordsButton
          link={{ from: data.from, to: data.to, ip: caller.ip }}
          onOpenRecords={onOpenRecords}
        />
      </td>
    </tr>
  );
}

function SensitiveSection({
  data,
  onOpenRecords,
}: {
  data: CloudflareAnalysis;
  onOpenRecords: OpenRecords;
}) {
  return (
    <section className="b89Analysis__section" aria-labelledby="b89-an-sensitive">
      <SectionTitle
        id="b89-an-sensitive"
        title="Exportaciones y lecturas sensibles"
        meta="*/export*, GET balances/transactions, balances/merchants"
      />
      {data.sensitiveReads.length === 0 ? (
        <p className="b89Analysis__empty">Ninguna exportación ni lectura sensible en el rango.</p>
      ) : (
        <div className="b89Analysis__tableWrap">
          <table className="b89Analysis__table">
            <thead>
              <tr>
                <th scope="col">Quién</th>
                <th scope="col">Rutas</th>
                <th scope="col" className="b89Analysis__num">
                  Registros
                </th>
                <th scope="col">Estados</th>
                <th scope="col">Primera / última (Lima)</th>
                <th scope="col" />
              </tr>
            </thead>
            <tbody>
              {data.sensitiveReads.map((caller) => (
                <tr
                  key={caller.ip}
                  className="b89Analysis__row"
                  data-abroad={caller.country !== null && caller.country !== 'PE'}
                >
                  <td>
                    <CallerNet caller={caller} />
                  </td>
                  <td>
                    <DataZone>{keys(caller.endpoints)}</DataZone>
                  </td>
                  <td className="b89Analysis__num">{formatCount(caller.count)}</td>
                  <td>{keys(caller.statuses)}</td>
                  <td className="b89Analysis__time">
                    {limaTime(caller.firstSeen)}
                    <br />
                    {limaTime(caller.lastSeen)}
                  </td>
                  <td>
                    <RecordsButton
                      link={{ from: data.from, to: data.to, ip: caller.ip }}
                      onOpenRecords={onOpenRecords}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------- Anomalías */

export function AnomaliesSection({
  anomalies,
  onOpenRecords,
}: {
  anomalies: AnomalySection;
  onOpenRecords: OpenRecords;
}) {
  return (
    <section className="b89Analysis__section" aria-labelledby="b89-an-anomalies">
      <SectionTitle
        id="b89-an-anomalies"
        title="Anomalías (ML)"
        meta="OpenSearch Anomaly Detection · detectores b89-cf-*"
      />
      {anomalies.status === 'forbidden' ? (
        <EuiCallOut color="warning" iconType="lock" size="s" title={anomalies.message ?? ''} />
      ) : anomalies.status !== 'ok' ? (
        <EuiCallOut color="warning" iconType="alert" size="s" title={anomalies.message ?? ''} />
      ) : null}
      {anomalies.status === 'ok' && !anomalies.detectorsResolved && (
        <p className="b89Analysis__sub">
          Tu rol no puede listar los detectores: se muestran sus identificadores.
        </p>
      )}
      {anomalies.status === 'ok' && anomalies.detectors.length > 0 && (
        <p className="b89Analysis__sub">
          Detectores: {anomalies.detectors.map((detector) => detector.name).join(', ')}.
        </p>
      )}
      {anomalies.status === 'ok' &&
        (anomalies.rows.length === 0 ? (
          <p className="b89Analysis__empty">
            {anomalies.message ?? 'Ninguna anomalía en el rango.'}
          </p>
        ) : (
          <div className="b89Analysis__tableWrap">
            <table className="b89Analysis__table">
              <thead>
                <tr>
                  <th scope="col">Hora (Lima)</th>
                  <th scope="col">Detector</th>
                  <th scope="col">Entidad</th>
                  <th scope="col" className="b89Analysis__num">
                    Grado
                  </th>
                  <th scope="col" className="b89Analysis__num">
                    Confianza
                  </th>
                  <th scope="col">Valores</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {anomalies.rows.map((row) => (
                  <tr key={row.id || `${row.detectorId}-${row.end}`} className="b89Analysis__row">
                    <td className="b89Analysis__time">
                      {limaTime(row.start, false)} → {limaTime(row.end, false).slice(11)}
                    </td>
                    <td>{row.detectorName ?? <Mono>{row.detectorId}</Mono>}</td>
                    <td>
                      <DataZone>
                        {row.entity.map((entity) => `${entity.value}`).join(' · ') || '—'}
                      </DataZone>
                    </td>
                    <td className="b89Analysis__num">{percent(row.grade)}</td>
                    <td className="b89Analysis__num">{percent(row.confidence)}</td>
                    <td>
                      {row.features
                        .map(
                          (feature) =>
                            `${feature.name} = ${feature.value === null ? '—' : formatCount(Math.round(feature.value * 100) / 100)}`,
                        )
                        .join(' · ')}
                    </td>
                    <td>
                      <RecordsButton
                        link={anomalyRecords(row)}
                        onOpenRecords={onOpenRecords}
                        label="Registros ±30 min"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </section>
  );
}
