/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  artifactDownloadUrl,
  expiryLabel,
  FORMAT_GLYPH,
  FORMAT_LABEL,
  formatBytes,
  isArtifactExpired,
} from './bunny_artifacts';
import { Icon } from './bunny_icons';
import type { ArtifactRef } from './chat_client';

/** Tarjeta de archivo (PDF/Excel/CSV) generado por Bunny, con descarga manual. */
export function BunnyArtifactCard({
  artifact,
  apiPrefix,
  now,
}: {
  artifact: ArtifactRef;
  apiPrefix: string;
  now?: number;
}) {
  const expired = isArtifactExpired(artifact, now);
  return (
    <div
      className={`b89Bunny__file${expired ? ' is-expired' : ''}`}
      data-test-subj="b89BunnyArtifact"
    >
      <span className="b89Bunny__fileIcon" data-format={artifact.format} aria-hidden="true">
        {FORMAT_GLYPH[artifact.format]}
      </span>
      <span className="b89Bunny__fileMeta">
        <strong title={artifact.title}>{artifact.title}</strong>
        <span title={artifact.filename}>{artifact.filename}</span>
        <small>
          {FORMAT_LABEL[artifact.format]} · {formatBytes(artifact.size)} ·{' '}
          {expiryLabel(artifact, now)}
        </small>
      </span>
      {expired ? (
        <button type="button" className="b89Bunny__fileButton" disabled>
          Expirado
        </button>
      ) : (
        <a
          className="b89Bunny__fileButton"
          href={artifactDownloadUrl(apiPrefix, artifact)}
          download={artifact.filename}
          aria-label={`Descargar ${artifact.filename}`}
        >
          <Icon name="download" size={14} /> Descargar
        </a>
      )}
    </div>
  );
}

export function BunnyArtifactList({
  artifacts,
  apiPrefix,
}: {
  artifacts: readonly ArtifactRef[];
  apiPrefix: string;
}) {
  if (artifacts.length === 0) return null;
  return (
    <div className="b89Bunny__files" aria-label="Archivos generados">
      {artifacts.map((artifact) => (
        <BunnyArtifactCard key={artifact.id} artifact={artifact} apiPrefix={apiPrefix} />
      ))}
    </div>
  );
}
