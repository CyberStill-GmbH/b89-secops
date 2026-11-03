#!/usr/bin/env node
/*
 * B89 overlay for the upstream Shuffle v2.3.0 `enable_subpathing.sh.tpl` contract.
 * The upstream script rewrites React route literals so the frontend can be hosted at /b89-respond/.
 * This equivalent is deterministic, idempotent, and deliberately limited to App.jsx, views and
 * components. The B89 edge strips /b89-respond/ before forwarding static/API requests upstream.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SUBPATH = '/b89-respond';

const REPLACEMENTS = [
  [/startsWith\("\/(?!b89-respond\/)/gu, 'startsWith("/b89-respond/'],
  [/path="\/(?!b89-respond\/)/gu, 'path="/b89-respond/'],
  [/location = "\/(?!b89-respond\/)/gu, 'location = "/b89-respond/'],
  [/window\.location\.origin;/gu, '"/b89-respond";'],
  [/pathname = "\/(?!b89-respond\/)/gu, 'pathname = "/b89-respond/'],
  [/navigate\("\/(?!b89-respond\/)/gu, 'navigate("/b89-respond/'],
  [/navigate\(`\/(?!b89-respond\/)/gu, 'navigate(`/b89-respond/'],
  [/href="\/(?!b89-respond\/)/gu, 'href="/b89-respond/'],
  [/path = "\/(?!b89-respond\/)/gu, 'path = "/b89-respond/'],
  [/link=\{"\/(?!b89-respond\/)/gu, 'link={"/b89-respond/'],
  [/to="\/(?!b89-respond\/)/gu, 'to="/b89-respond/'],
  [/to=\{"\/(?!b89-respond\/)/gu, 'to={"/b89-respond/'],
  [/\$\{window\.location\.origin\}/gu, SUBPATH],
];

export function prefixSource(source) {
  return REPLACEMENTS.reduce(
    (result, [pattern, replacement]) => result.replace(pattern, replacement),
    source,
  );
}

function prefixFiles(directory) {
  let changed = 0;
  for (const name of readdirSync(directory)
    .filter((entry) => entry.endsWith('.jsx'))
    .sort()) {
    const path = join(directory, name);
    const original = readFileSync(path, 'utf8');
    const prefixed = prefixSource(original);
    if (prefixed !== original) {
      writeFileSync(path, prefixed);
      changed += 1;
    }
  }
  return changed;
}

export function enableSubpath(frontendDirectory) {
  const appPath = join(frontendDirectory, 'src', 'App.jsx');
  const original = readFileSync(appPath, 'utf8');
  const prefixed = prefixSource(original);
  if (prefixed === original && !original.includes('"/b89-respond"')) {
    throw new Error('UPSTREAM_SUBPATH_CONTRACT_MISMATCH: App.jsx');
  }
  writeFileSync(appPath, prefixed);
  const views = prefixFiles(join(frontendDirectory, 'src', 'views'));
  const components = prefixFiles(join(frontendDirectory, 'src', 'components'));
  return { app: prefixed === original ? 0 : 1, views, components };
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  const frontendDirectory = process.argv[2];
  if (!frontendDirectory) {
    process.stderr.write('uso: node subpath.mjs <shuffle-frontend-dir>\n');
    process.exit(2);
  }
  const result = enableSubpath(frontendDirectory);
  process.stdout.write(
    `subruta /b89-respond aplicada: App.jsx=${result.app}, views=${result.views}, components=${result.components}\n`,
  );
}
