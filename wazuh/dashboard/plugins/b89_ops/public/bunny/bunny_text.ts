/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 *
 * Textos de Bunny sin dependencias de DOM: anuncios para lector de pantalla, nombres de las
 * fuentes y la nota que se guarda en un incidente.
 */

import type { BunnyCitation } from './chat_client';

const NAME = 'Bunny';

interface NoteSource {
  readonly text: string;
  readonly citations?: readonly BunnyCitation[];
}

/** Tipo de una fuente en palabras (para chips, notas y nombres accesibles). */
export function citationKindLabel(kind: BunnyCitation['kind']): string {
  switch (kind) {
    case 'alert':
      return 'Alerta';
    case 'incident':
      return 'Incidente';
    case 'event':
      return 'Evento';
    case 'audit':
      return 'Auditoría';
    default:
      return 'Fuente';
  }
}

const NOTE_DATE = new Intl.DateTimeFormat('es-PE', {
  day: '2-digit',
  month: 'long',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'America/Lima',
  timeZoneName: 'short',
});

/** Texto de la región viva al terminar: «Respuesta de Bunny lista» y el comienzo de la respuesta. */
export function finishedAnnouncement(text: string): string {
  const plain = text
    .replace(/[`*_#>|[\]]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
  const start = plain.length > 200 ? `${plain.slice(0, 199)}…` : plain;
  return start ? `Respuesta de ${NAME} lista: ${start}` : `Respuesta de ${NAME} lista.`;
}

export function reportNoteBody(message: NoteSource, now: Date = new Date()): string {
  const citations = (message.citations ?? [])
    .map((citation) => `- ${citationKindLabel(citation.kind)}: ${citation.label} (ID ${citation.id})`)
    .join('\n');
  const body = [
    'BORRADOR PRELIMINAR ASISTIDO POR IA. Requiere revisión humana antes de compartir o decidir.',
    `Generado: ${NOTE_DATE.format(now)}`,
    '',
    message.text,
    '',
    'Fuentes citadas',
    citations || 'Sin fuentes citadas; verificar antes de utilizar.',
  ].join('\n');
  return body.length <= 10000
    ? body
    : `${body.slice(0, 9950)}\n[Truncado al límite de notas del incidente]`;
}
