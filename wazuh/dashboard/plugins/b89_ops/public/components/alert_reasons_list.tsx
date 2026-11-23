/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiCallOut, EuiSpacer, EuiText } from '@elastic/eui';
import { groupAlertReasons } from '../../common/alert_reasons';
import { EmptyLine, HealthMark, Mono } from './primitives';

/**
 * Razones de una alerta agrupadas como expediente. Para alertas comunes solo hay «Motivos de la
 * prioridad»; las del correlador muestran secuencia, umbrales, contradicciones y datos faltantes.
 */
export function AlertReasonsList({
  reasons,
}: {
  reasons: ReadonlyArray<{ readonly code: string; readonly detail: string }>;
}) {
  if (reasons.length === 0) {
    return <EmptyLine>No hay más detalle sobre la prioridad.</EmptyLine>;
  }
  const { scope, groups } = groupAlertReasons(reasons);
  const single = groups.length === 1 && groups[0]?.id === 'priority' && !scope;
  return (
    <div data-b89-no-translate="">
      {scope && (
        <>
          <EuiCallOut
            size="s"
            color="primary"
            iconType="iInCircle"
            title="Posible ataque en varios pasos (por confirmar)"
          >
            <p>{scope}</p>
          </EuiCallOut>
          <EuiSpacer size="s" />
        </>
      )}
      {groups.map((group) => (
        <section key={group.id} className="b89Reasons__group">
          {!single && (
            <EuiText size="xs">
              <h4>{group.title}</h4>
            </EuiText>
          )}
          {group.hint && (
            <EuiText size="xs" color="subdued">
              <p>{group.hint}</p>
            </EuiText>
          )}
          <ul className="b89List">
            {group.items.map((item, index) => (
              <li key={`${group.id}-${index}`}>
                {item.met !== undefined && (
                  <>
                    <HealthMark
                      tone={item.met ? 'ok' : 'warn'}
                      label={item.met ? 'Cumplido' : 'No cumplido'}
                    />{' '}
                  </>
                )}
                <span>{item.text}</span>
                {group.id === 'priority' && (
                  <>
                    {' '}
                    <Mono title="Código interno del motor de priorización">{item.code}</Mono>
                  </>
                )}
              </li>
            ))}
          </ul>
          <EuiSpacer size="s" />
        </section>
      ))}
    </div>
  );
}
