/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiButton, EuiDescriptionList, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { amrText, ATTRIBUTION, CAPABILITY_LABEL, LOGOUT_PATH, ROLE_LABEL } from '../../common';
import { B89Page, useConsole } from './console_context';
import { EmptyLine, Mono } from './primitives';

/** «Puedes: ver alertas, clasificar alertas…» en el orden del catálogo; lo desconocido al final. */
export function capabilitySentence(capabilities: readonly string[]): string | null {
  const known = Object.keys(CAPABILITY_LABEL).filter((code) => capabilities.includes(code));
  const unknown = capabilities.filter((code) => !CAPABILITY_LABEL[code]);
  const words = known.map((code) => CAPABILITY_LABEL[code]);
  if (unknown.length > 0) {
    words.push(`${unknown.length} permiso${unknown.length === 1 ? '' : 's'} más (ver datos técnicos)`);
  }
  if (words.length === 0) return null;
  return `Puedes: ${words.join(', ')}.`;
}

/** «Mi sesión» (doc 11): quién soy para B89, con qué método entré y qué puedo hacer. */
export function SessionView({ basePath }: { basePath: string }) {
  const { session } = useConsole();
  const capabilities = [...session.capabilities].sort();
  const sentence = capabilitySentence(session.capabilities);

  return (
    <B89Page
      title="Mi sesión"
      description="Quién eres para B89, cómo entraste y qué puedes hacer."
      actions={
        <EuiButton size="s" href={`${basePath}${LOGOUT_PATH}`}>
          Cerrar sesión
        </EuiButton>
      }
    >
      <div className="b89Readable" lang="es-PE" translate="no">
        <EuiPanel hasBorder paddingSize="m">
          <EuiDescriptionList
            type="responsiveColumn"
            compressed
            className="b89Facts"
            listItems={[
              { title: 'Nombre', description: session.displayName ?? 'Sin dato' },
              { title: 'Correo', description: session.email ?? 'Sin dato' },
              {
                title: 'Rol',
                description:
                  session.roles.length === 0
                    ? 'Sin rol: pide uno a un Administrador de plataforma.'
                    : session.roles.map((role) => ROLE_LABEL[role] ?? role).join(', '),
              },
              { title: 'Cómo entraste', description: amrText(session.amr, 'Sin dato') },
            ]}
          />
        </EuiPanel>
        <EuiSpacer size="l" />
        <EuiTitle size="xs">
          <h2>Qué puedes hacer</h2>
        </EuiTitle>
        <EuiSpacer size="s" />
        {sentence ? (
          <EuiText size="s">
            <p>{sentence}</p>
          </EuiText>
        ) : (
          <EmptyLine>
            Tu rol todavía no incluye ninguna acción. Pide un rol a un Administrador de plataforma.
          </EmptyLine>
        )}
        <EuiSpacer size="m" />
        <details className="b89Guide__details">
          <summary>Datos técnicos de la sesión</summary>
          <EuiSpacer size="s" />
          <EuiDescriptionList
            type="responsiveColumn"
            compressed
            className="b89Facts"
            listItems={[
              { title: 'Identificador', description: <Mono>{session.subjectId}</Mono> },
              { title: 'Organización (tenant)', description: <Mono>{session.tenantId}</Mono> },
              {
                title: 'Métodos (amr)',
                description: session.amr.length ? <Mono>{session.amr.join(' + ')}</Mono> : 'Sin dato',
              },
            ]}
          />
          <EuiSpacer size="s" />
          <p className="b89Muted">
            Permisos tal como los envía el servidor; cada acción se vuelve a autorizar al usarla.
          </p>
          {capabilities.length === 0 ? (
            <EmptyLine>Sin permisos asignados.</EmptyLine>
          ) : (
            <ul className="b89Capabilities">
              {capabilities.map((capability) => (
                <li key={capability}>
                  <Mono>{capability}</Mono>
                </li>
              ))}
            </ul>
          )}
        </details>
        <EuiSpacer size="xl" />
        <EuiTitle size="xs">
          <h2>Acerca de B89 SecOps</h2>
        </EuiTitle>
        <EuiSpacer size="s" />
        {/* Aviso de licencias: no se traduce ni se rebrandea (NOTICE). */}
        <EuiText size="xs" color="subdued" data-b89-no-translate="">
          <p>{ATTRIBUTION}</p>
          <p>
            Los avisos y licencias originales se conservan en el paquete instalado (LICENSE.txt y
            NOTICE.txt).
          </p>
        </EuiText>
      </div>
    </B89Page>
  );
}
