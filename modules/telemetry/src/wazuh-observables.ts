/**
 * Aprendizaje SOC · etapa B — proyección de observables de una alerta Wazuh a la extensión
 * `b89.observables` v1 (mapping `wazuh.alerts` 1.4.0, docs/soc-learning/01-diseno.md §4.2).
 *
 * Solo lee campos conocidos y nunca inventa: si un decoder no trae el campo, queda ausente y la
 * huella cae a nivel grueso, que nunca autocierra. La normalización y la redacción de secretos
 * viven en el contrato (`@b89/contracts`) para que productor y huella apliquen las mismas reglas.
 */

import { createHash } from 'node:crypto';

import { buildObservables, type ObservablesV1 } from '@b89/contracts';

type RawObject = Readonly<Record<string, unknown>>;

function readObject(value: unknown): RawObject | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as RawObject;
}

function first(...values: unknown[]): unknown {
  return (
    values.find((value) => typeof value === 'string' && value.trim().length > 0) ??
    values.find((value) => typeof value === 'number')
  );
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** `execve` de auditd: `{ a0: "/usr/bin/curl", a1: "-s", … }` en orden de argumento. */
function auditCommandLine(audit: RawObject | undefined): string | undefined {
  const execve = readObject(audit?.['execve']);
  if (!execve) return typeof audit?.['command'] === 'string' ? audit['command'] : undefined;
  const parts: string[] = [];
  for (let index = 0; index < 64; index += 1) {
    const value = execve[`a${index}`];
    if (typeof value !== 'string') break;
    parts.push(value);
  }
  return parts.length > 0 ? parts.join(' ') : undefined;
}

function stringList(value: unknown): readonly unknown[] {
  if (Array.isArray(value)) return value;
  return typeof value === 'string' ? [value] : [];
}

export function projectWazuhObservables(source: RawObject): ObservablesV1 | undefined {
  const data = readObject(source['data']);
  const win = readObject(readObject(data?.['win'])?.['eventdata']);
  const audit = readObject(data?.['audit']);
  const syscheck = readObject(source['syscheck']);
  const cloudflare = readObject(data?.['cloudflare']);
  const mitre = readObject(readObject(source['rule'])?.['mitre']);

  return buildObservables(
    {
      agentId: readObject(source['agent'])?.['id'],
      processImage: first(win?.['image'], audit?.['exe']),
      commandLine: first(win?.['commandLine'], auditCommandLine(audit)),
      processSha256: first(win?.['hashes'], win?.['sha256']),
      parentImage: win?.['parentImage'],
      filePath: first(win?.['targetFilename'], syscheck?.['path']),
      fileSha256: syscheck?.['sha256_after'],
      destinationIp: first(win?.['destinationIp'], data?.['dstip']),
      destinationPort: first(win?.['destinationPort'], data?.['dstport']),
      destinationDomain: first(
        win?.['destinationHostname'],
        win?.['queryName'],
        readObject(cloudflare?.['http'])?.['host'],
        readObject(cloudflare?.['firewall'])?.['host'],
      ),
      techniques: stringList(mitre?.['id']),
      tactics: stringList(mitre?.['tactic']),
    },
    sha256Hex,
  );
}
