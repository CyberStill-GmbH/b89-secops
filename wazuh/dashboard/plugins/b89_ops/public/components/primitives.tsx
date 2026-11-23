/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiText, EuiToolTip } from '@elastic/eui';
import {
  HEALTH_TONE,
  HealthTone,
  IncidentSeverity,
  Priority,
  PRIORITY_STEP,
  SEVERITY_LABEL,
  SEVERITY_STEP,
} from '../../common';
import { B89ApiError } from '../api/client';

/** Prioridad de alerta: glifo + color + rótulo del backend (doc 02 §2.5). */
export function PriorityMark({ priority }: { priority: Priority }) {
  const step = PRIORITY_STEP[priority];
  return (
    <span className="b89Severity" data-step={step.step}>
      <span aria-hidden="true" className="b89Severity__glyph" style={{ color: step.color }}>
        {step.glyph}
      </span>
      <span className="b89Severity__label">{priority}</span>
    </span>
  );
}

export function SeverityMark({ severity }: { severity: IncidentSeverity }) {
  const step = SEVERITY_STEP[severity];
  return (
    <span className="b89Severity" data-step={step.step}>
      <span aria-hidden="true" className="b89Severity__glyph" style={{ color: step.color }}>
        {step.glyph}
      </span>
      <span className="b89Severity__label">{SEVERITY_LABEL[severity]}</span>
    </span>
  );
}

/** HealthMark del login: círculo de 15 px con símbolo; único idioma de salud. */
export function HealthMark({ tone, label }: { tone: HealthTone; label: string }) {
  const mark = HEALTH_TONE[tone];
  return (
    <span className="b89Health">
      <span
        aria-hidden="true"
        className="b89Health__mark"
        style={{ color: mark.color, borderColor: mark.color }}
      >
        {mark.glyph}
      </span>
      <span>{label}</span>
    </span>
  );
}

/** Lo que se copia (IDs, hashes, IPs) va en mono. */
export function Mono({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <code className="b89Mono" title={title} data-b89-no-translate="">
      {children}
    </code>
  );
}

// `dateStyle`/`timeStyle` no se combinan con `timeZoneName`: campos explícitos.
const ABSOLUTE = new Intl.DateTimeFormat('es-PE', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZoneName: 'short',
});
const RELATIVE = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });

export function relativeTime(iso: string, now: number = Date.now()): string {
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 60) return RELATIVE.format(seconds, 'second');
  if (abs < 3600) return RELATIVE.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return RELATIVE.format(Math.round(seconds / 3600), 'hour');
  return RELATIVE.format(Math.round(seconds / 86400), 'day');
}

/** Instante relativo con la marca absoluta y la zona horaria siempre disponibles. */
export function Timestamp({
  iso,
  focusable = true,
  emptyLabel = 'Sin dato',
}: {
  iso: string | null | undefined;
  /** `false` en filas de tablas y listas: la fecha absoluta va en `title` y no suma una parada de Tab por fila. */
  focusable?: boolean;
  emptyLabel?: string;
}) {
  if (!iso) return <span className="b89Muted">{emptyLabel}</span>;
  const absolute = ABSOLUTE.format(new Date(iso));
  if (!focusable) {
    return (
      <time dateTime={iso} className="b89Tabular" title={absolute} data-b89-no-translate="">
        {relativeTime(iso)}
      </time>
    );
  }
  return (
    <EuiToolTip content={absolute}>
      <time dateTime={iso} className="b89Tabular" tabIndex={0} data-b89-no-translate="">
        {relativeTime(iso)}
      </time>
    </EuiToolTip>
  );
}

/** Fecha y hora absolutas, legibles («22 nov 2026, 14:32:05 GMT-5»). */
export function absoluteTime(iso: string): string {
  return ABSOLUTE.format(new Date(iso));
}

/** Estado vacío: una línea que explica por qué y qué hacer (A10, sin ilustraciones). */
export function EmptyLine({ children }: { children: React.ReactNode }) {
  return (
    <EuiText size="s" color="subdued" className="b89Empty">
      <p>{children}</p>
    </EuiText>
  );
}

export function ErrorCallout({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const apiError = error instanceof B89ApiError ? error : null;
  const degraded = apiError?.code === 'DEPENDENCY_DEGRADED';
  return (
    <EuiCallOut
      color={degraded ? 'warning' : 'danger'}
      iconType={degraded ? 'alert' : 'cross'}
      title={apiError?.message ?? 'Algo falló de forma inesperada. Reintenta; si se repite, avisa al equipo de plataforma con la referencia.'}
      size="s"
    >
      {apiError?.correlationId && (
        <p>
          Referencia: <Mono>{apiError.correlationId}</Mono>
        </p>
      )}
      {onRetry && (
        <EuiButtonEmpty size="xs" onClick={onRetry} flush="left">
          Reintentar
        </EuiButtonEmpty>
      )}
    </EuiCallOut>
  );
}

export interface AsyncState<T> {
  readonly data: T | null;
  readonly error: unknown;
  readonly loading: boolean;
  readonly reload: () => void;
}

/** Carga con cancelación: una respuesta tardía de una consulta anterior no pisa la nueva. */
export function useAsync<T>(load: () => Promise<T>, deps: React.DependencyList): AsyncState<T> {
  const [state, setState] = useState<{ data: T | null; error: unknown; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [tick, setTick] = useState(0);
  const generation = useRef(0);
  const reloading = useRef(false);
  const reload = useCallback(() => {
    reloading.current = true;
    setTick((value) => value + 1);
  }, []);

  useEffect(() => {
    const current = ++generation.current;
    // Una recarga (refresco en vivo, «Reintentar») que falla conserva los datos que ya se veían:
    // la vista muestra el error sin vaciarse. Una consulta nueva (otros filtros) no los conserva.
    const keepOnError = reloading.current;
    reloading.current = false;
    setState((previous) => ({ ...previous, loading: true, error: null }));
    load().then(
      (data) => {
        if (generation.current === current) setState({ data, error: null, loading: false });
      },
      (error) => {
        if (generation.current === current)
          setState((previous) => ({ data: keepOnError ? previous.data : null, error, loading: false }));
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return { ...state, reload };
}

/**
 * Zona de datos (títulos de alertas, entidades, notas, JSON): el traductor de `b89_i18n`
 * no la toca. Los textos propios de B89 ya están en español.
 */
export function DataZone({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={className} data-b89-no-translate="">
      {children}
    </div>
  );
}

/** Actor de servicio del Analista IA (`apps/api`), que también asigna y comenta. */
export const AI_ANALYST_ACTOR = 'svc:b89-ai-analyst';

/**
 * Persona detrás de un id de sujeto, en palabras: «Tú», «Analista IA» u «Otro analista». Nunca un
 * id cortado: el id completo queda en el tooltip para quien necesite rastrearlo en Auditoría.
 * (La API no expone hoy nombres de otras personas a un analista.)
 */
export function Person({
  id,
  viewerId,
  emptyLabel = 'Sin responsable',
}: {
  id: string | null | undefined;
  viewerId: string;
  emptyLabel?: string;
}) {
  if (!id) return <span className="b89Muted">{emptyLabel}</span>;
  if (id === viewerId) return <strong>Tú</strong>;
  if (id === AI_ANALYST_ACTOR) return <span>Analista IA</span>;
  return (
    <EuiToolTip content={`Identificador: ${id}`}>
      <span tabIndex={0} className="b89Person" data-b89-no-translate="">
        Otro analista
      </span>
    </EuiToolTip>
  );
}

/** Ancho de pantalla móvil (≤ 767 px, breakpoint `s` de OUI): flyouts y formularios a pantalla completa. */
export function useIsMobile(): boolean {
  const query = '(max-width: 767px)';
  const [mobile, setMobile] = useState(
    () => typeof window !== 'undefined' && window.matchMedia(query).matches,
  );
  useEffect(() => {
    const media = window.matchMedia(query);
    const listener = (event: MediaQueryListEvent) => setMobile(event.matches);
    // Safari < 14 solo conoce addListener/removeListener.
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', listener);
      return () => media.removeEventListener('change', listener);
    }
    media.addListener(listener);
    return () => media.removeListener(listener);
  }, []);
  return mobile;
}
