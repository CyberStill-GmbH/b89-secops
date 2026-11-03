/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

/**
 * Markdown mínimo y seguro para las respuestas de Bunny: párrafos, listas (con y sin número),
 * tablas simples, **negrita**, *énfasis* y `código`. Todo se construye como elementos de React:
 * nunca se inserta HTML y los enlaces no se interpretan (el modelo no puede inyectar URLs).
 */

function inline(text: string, keyPrefix: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/gu;
  let last = 0;
  let index = 0;
  for (const match of text.matchAll(pattern)) {
    const start = match.index ?? 0;
    if (start > last) nodes.push(text.slice(last, start));
    const token = match[0];
    const key = `${keyPrefix}-${index++}`;
    if (token.startsWith('`')) nodes.push(<code key={key}>{token.slice(1, -1)}</code>);
    else if (token.startsWith('**')) nodes.push(<strong key={key}>{token.slice(2, -2)}</strong>);
    else nodes.push(<em key={key}>{token.slice(1, -1)}</em>);
    last = start + token.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

const BULLET = /^\s*[-*•]\s+(.*)$/u;
const NUMBERED = /^\s*\d+[.)]\s+(.*)$/u;
const TABLE_ROW = /^\s*\|.*\|\s*$/u;
const TABLE_RULE = /^\s*\|[\s:|-]+\|\s*$/u;

function cells(row: string): string[] {
  return row
    .trim()
    .replace(/^\||\|$/gu, '')
    .split('|')
    .map((cell) => cell.trim());
}

export function renderMarkdown(source: string): React.ReactNode[] {
  const lines = source.replace(/\r\n/gu, '\n').split('\n');
  const blocks: React.ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const line = lines[i] ?? '';
    if (line.trim() === '') {
      i += 1;
      continue;
    }
    if (TABLE_ROW.test(line) && TABLE_RULE.test(lines[i + 1] ?? '')) {
      const header = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && TABLE_ROW.test(lines[i] ?? '')) {
        rows.push(cells(lines[i] ?? ''));
        i += 1;
      }
      blocks.push(
        <div className="b89Bunny__tableWrap" key={`b${key++}`}>
          <table className="b89Bunny__table">
            <thead>
              <tr>
                {header.map((cell, c) => (
                  <th key={c}>{inline(cell, `h${c}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => (
                    <td key={c}>{inline(cell, `r${r}c${c}`)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }
    const ordered = NUMBERED.test(line);
    if (ordered || BULLET.test(line)) {
      const pattern = ordered ? NUMBERED : BULLET;
      const items: string[] = [];
      while (i < lines.length && pattern.test(lines[i] ?? '')) {
        items.push((pattern.exec(lines[i] ?? '') ?? [])[1] ?? '');
        i += 1;
      }
      const Tag = ordered ? 'ol' : 'ul';
      blocks.push(
        <Tag key={`b${key++}`}>
          {items.map((item, n) => (
            <li key={n}>{inline(item, `li${n}`)}</li>
          ))}
        </Tag>,
      );
      continue;
    }
    const paragraph: string[] = [];
    while (
      i < lines.length &&
      (lines[i] ?? '').trim() !== '' &&
      !BULLET.test(lines[i] ?? '') &&
      !NUMBERED.test(lines[i] ?? '') &&
      !TABLE_ROW.test(lines[i] ?? '')
    ) {
      paragraph.push(lines[i] ?? '');
      i += 1;
    }
    blocks.push(
      <p key={`b${key++}`}>
        {paragraph.map((text, n) => (
          <React.Fragment key={n}>
            {n > 0 && <br />}
            {inline(text, `p${n}`)}
          </React.Fragment>
        ))}
      </p>,
    );
  }
  return blocks;
}
