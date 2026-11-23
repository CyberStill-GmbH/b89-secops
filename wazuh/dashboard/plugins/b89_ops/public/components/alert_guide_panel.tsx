/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiText, EuiTitle } from '@elastic/eui';
import type { AlertEntity, AlertExplanation, Priority } from '../../common';
import type { AlertGuide } from '../../common/alert_guide';
import { explainAlert } from '../../common/alert_why';
import { AlertReasonsList } from './alert_reasons_list';

/** La urgencia de la guía se dice junto a «Qué hacer», no como una tercera escala de gravedad. */
const WHEN: Readonly<Record<AlertGuide['urgency'], string>> = {
  act: 'ahora',
  review: 'hoy',
  info: 'cuando puedas',
};

/**
 * Lo primero que ve cualquier persona al abrir una alerta, con o sin guía para la regla:
 * «Por qué saltó» (qué pasó, a quién y qué la agrava, en una frase), «¿Es real?» si hay guía y
 * «Qué hacer». Los motivos del motor, la regla y la puntuación quedan en «Detalle técnico».
 */
export function AlertGuidePanel({
  title,
  reasons,
  priority = 'P3',
  entities = [],
  score,
  ruleId,
  explanation,
  framed = true,
}: {
  title: string;
  reasons: ReadonlyArray<{ readonly code: string; readonly detail: string }>;
  priority?: Priority;
  entities?: readonly AlertEntity[];
  score?: number;
  ruleId?: string | null;
  /** Lo que el catálogo de detección sabe de la regla (`GET /alerts/:id`). */
  explanation?: AlertExplanation | null;
  /** `false` dentro de un flyout (sin tarjeta alrededor). */
  framed?: boolean;
}) {
  const why = explainAlert({ title, priority, reasons, entities, ruleId, explanation });
  const { guide } = why;
  const body = (
    <section
      className="b89Guide"
      aria-labelledby="b89GuideWhy"
      data-test-subj="b89AlertGuide"
      lang="es-PE"
      translate="no"
    >
      <EuiTitle size="xs">
        <h2 id="b89GuideWhy">Por qué saltó</h2>
      </EuiTitle>
      <EuiText size="s" className="b89Guide__why">
        <p data-b89-no-translate="">{why.sentence}</p>
        {why.priorityLine && <p className="b89Guide__priority">{why.priorityLine}</p>}
        {why.loweredLine && <p className="b89Guide__priority">{why.loweredLine}</p>}
      </EuiText>
      <EuiText size="s">
        <dl className="b89KeyValues b89Guide__list">
          {guide ? (
            <>
              <dt>Qué significa</dt>
              <dd>{guide.whatHappened}</dd>
              <dt>¿Es real? Cómo confirmarlo</dt>
              <dd>
                <ul>
                  {guide.isItReal.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </dd>
            </>
          ) : (
            (why.commonFalsePositives.length > 0 || why.escalateWhen.length > 0) && (
              <>
                <dt>¿Es real?</dt>
                <dd>
                  {why.commonFalsePositives.length > 0 && (
                    <>
                      <p className="b89Guide__sub">Suele ser normal cuando:</p>
                      <ul>
                        {why.commonFalsePositives.map((line) => (
                          <li key={line}>{line}</li>
                        ))}
                      </ul>
                    </>
                  )}
                  {why.escalateWhen.length > 0 && (
                    <>
                      <p className="b89Guide__sub">Trátala como real y escala si:</p>
                      <ul>
                        {why.escalateWhen.map((line) => (
                          <li key={line}>{line}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </dd>
              </>
            )
          )}
          <dt>{guide ? `Qué hacer · ${WHEN[guide.urgency]}` : 'Qué hacer'}</dt>
          <dd>
            <ol>
              {why.nextSteps.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ol>
          </dd>
        </dl>
      </EuiText>
      <details className="b89Guide__details">
        <summary>Detalle técnico</summary>
        <EuiText size="xs" color="subdued">
          <p>
            {why.ruleId ? `Regla del SIEM ${why.ruleId}` : 'Regla sin identificar'}
            {explanation?.level != null ? ` · nivel ${explanation.level} de 15` : ''}
            {why.source ? ` · fuente: ${why.source}` : ''}
            {score !== undefined ? ` · puntuación de prioridad ${score}` : ''}
          </p>
          {why.useCase && <p>Caso de uso: {why.useCase}</p>}
          {explanation && explanation.mitre.length > 0 && (
            <p>
              MITRE ATT&amp;CK:{' '}
              {explanation.mitre.map((technique, index) => (
                <React.Fragment key={technique.id}>
                  {index > 0 ? ', ' : ''}
                  <a
                    href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {technique.id}
                  </a>
                  {technique.name ? ` ${technique.name}` : ''}
                </React.Fragment>
              ))}
            </p>
          )}
          {explanation?.runbook && <p>Runbook: {explanation.runbook.title}</p>}
        </EuiText>
        <AlertReasonsList reasons={reasons} />
      </details>
    </section>
  );
  return framed ? (
    <EuiPanel paddingSize="m" className="b89Card">
      {body}
    </EuiPanel>
  ) : (
    body
  );
}
