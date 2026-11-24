/**
 * Aprendizaje SOC · T6 — cobertura de huella fina vs gruesa (precondición de la etapa D).
 *
 * Solo lectura. Pasa cada alerta por el normalizador Wazuh y la huella REALES del repo y agrega:
 * % fina por regla y por fuente, top de reglas gruesas, qué les falta (sujeto/comportamiento) y
 * qué campos del documento parecen útiles pero el extractor no lee.
 *
 * Entradas:
 *   --alerts <archivo.jsonl>   Documentos `wazuh-alerts-*` (p. ej. el volcado anonimizado).
 *   (sin --alerts)             Fixtures del repo: alertas sintéticas del correlador y las fixtures
 *                              JSON de detections/* convertidas a alerta con la regla declarada
 *                              en su metadata.yaml. Las líneas de texto que requieren un decoder
 *                              se cuentan como «no evaluables sin wazuh-logtest», salvo b89-netconn
 *                              (su decoder es un regex simple y se replica aquí).
 *
 *   pnpm exec tsx --conditions=development scripts/soc-learning/fingerprint-coverage.ts [--alerts f] [--out f.md]
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { OBSERVABLES_NORMALIZER_VERSION } from '../../packages/contracts/src/index.js';
import { computeFingerprint, type AlertFingerprint } from '../../modules/detection/src/index.js';
import {
  normalizeWazuhAlert,
  type WazuhAlertInput,
} from '../../modules/telemetry/src/wazuh-normalization.js';

const ROOT = resolve(import.meta.dirname, '../..');
const args = process.argv.slice(2);
const option = (name: string) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

type Raw = Record<string, unknown>;
interface Sample {
  readonly origin: string;
  readonly alert: Raw;
}

/** Nombres de campo que suelen describir comportamiento (proceso, archivo, destino, comando). */
const BEHAVIOR_HINT =
  /^(application|image|exe|process|proc|program|command|cmd|commandline|parentimage|parent|hash|hashes|sha256|md5|file|path|targetfilename|url|uri|host|hostname|domain|dst|dstip|dstport|destaddress|destport|destinationip|destinationport|destinationhostname|queryname)$/iu;

/** Campos que el extractor `wazuh-observables.ts` sí lee (ruta completa dentro del documento). */
const CONSUMED = new Set([
  'data.win.eventdata.image',
  'data.win.eventdata.parentImage',
  'data.win.eventdata.commandLine',
  'data.win.eventdata.hashes',
  'data.win.eventdata.sha256',
  'data.win.eventdata.targetFilename',
  'data.win.eventdata.destinationIp',
  'data.win.eventdata.destinationPort',
  'data.win.eventdata.destinationHostname',
  'data.win.eventdata.queryName',
  'data.audit.exe',
  'data.audit.execve',
  'data.audit.command',
  'syscheck.path',
  'syscheck.sha256_after',
  'data.dstip',
  'data.dstport',
  'data.cloudflare.http.host',
  'data.cloudflare.firewall.host',
]);

function leafPaths(value: unknown, prefix: string, out: string[]): string[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value as Raw)) {
      leafPaths(child, prefix ? `${prefix}.${key}` : key, out);
    }
  } else if (value !== undefined && value !== null && value !== '') {
    out.push(prefix);
  }
  return out;
}

function unmappedHints(alert: Raw): string[] {
  return (
    leafPaths(alert['data'], 'data', [])
      .concat(leafPaths(alert['syscheck'], 'syscheck', []))
      .filter((path) => !CONSUMED.has(path) && BEHAVIOR_HINT.test(path.split('.').at(-1) ?? ''))
      // `srcip`/`client_ip` son sujeto, no comportamiento.
      .filter((path) => !/client_ip|srcip/iu.test(path))
  );
}

/* ------------------------------------------------------------------ Entradas */

function fromDump(file: string): { samples: Sample[]; skipped: Record<string, number> } {
  const samples = readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.trim().startsWith('{'))
    .map((line) => ({ origin: relative(ROOT, file), alert: JSON.parse(line) as Raw }));
  return { samples, skipped: {} };
}

interface UseCase {
  readonly dir: string;
  readonly title: string;
  readonly ruleId: string | undefined;
  readonly source: string;
}

function useCaseOf(dir: string): UseCase {
  const metadata = readFileSync(join(dir, 'metadata.yaml'), 'utf8');
  const title = /^title:\s*(.+)$/mu.exec(metadata)?.[1]?.trim() ?? relative(ROOT, dir);
  const ruleId = /\n\s+ids:\s*\n\s+-\s*(\d+)/u.exec(metadata)?.[1];
  const source = /^source:\s*(\S+)/mu.exec(metadata)?.[1] ?? 'unknown';
  return { dir, title, ruleId, source };
}

/** Réplica del decoder `b89-netconn` (infra/wazuh/network/decoders/b89_network_decoders.xml). */
function decodeNetconn(line: string): Raw | undefined {
  const match =
    /'b89-netconn': type=(\S+) dir=(\S+) proto=(\S+) src=(\S+) sport=(\S+) dst=(\S+) dport=(\S+) proc=(\S+) uid=(\S+)/u.exec(
      line,
    );
  if (!match) return undefined;
  return {
    b89: { net: { type: match[1], direction: match[2], process: match[8], uid: match[9] } },
    protocol: match[3],
    srcip: match[4],
    srcport: match[5],
    dstip: match[6],
    dstport: match[7],
  };
}

function fromFixtures(): { samples: Sample[]; skipped: Record<string, number> } {
  const samples: Sample[] = [];
  const skipped: Record<string, number> = {};
  const correlator = join(ROOT, 'services/b89-correlator/testdata/wazuh-alerts.jsonl');
  samples.push(...fromDump(correlator).samples);

  const detections = join(ROOT, 'detections');
  for (const source of readdirSync(detections, { withFileTypes: true })) {
    if (!source.isDirectory()) continue;
    for (const useCaseDir of readdirSync(join(detections, source.name), { withFileTypes: true })) {
      const dir = join(detections, source.name, useCaseDir.name);
      let fixtures: string;
      try {
        fixtures = readFileSync(join(dir, 'fixtures.jsonl'), 'utf8');
      } catch {
        continue;
      }
      const useCase = useCaseOf(dir);
      if (!useCase.ruleId) continue;
      for (const [index, line] of fixtures.split('\n').entries()) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const data = trimmed.startsWith('{')
          ? (JSON.parse(trimmed) as Raw)
          : decodeNetconn(trimmed);
        if (!data) {
          const key = relative(ROOT, dir).replaceAll('\\', '/');
          skipped[key] = (skipped[key] ?? 0) + 1;
          continue;
        }
        samples.push({
          origin: `${relative(ROOT, dir).replaceAll('\\', '/')}#${index + 1}`,
          alert: {
            timestamp: '2026-11-24T12:00:00.000+0000',
            rule: {
              id: useCase.ruleId,
              level: 7,
              description: useCase.title,
              groups: [useCase.source],
            },
            agent: { id: '017', name: 'fixture-host' },
            data,
          },
        });
      }
    }
  }
  return { samples, skipped };
}

/* ------------------------------------------------------------- Evaluación */

interface Bucket {
  total: number;
  fine: number;
  noSubject: number;
  noBehavior: number;
  noRule: number;
  hints: Map<string, number>;
}

const bucket = (): Bucket => ({
  total: 0,
  fine: 0,
  noSubject: 0,
  noBehavior: 0,
  noRule: 0,
  hints: new Map(),
});

function record(target: Bucket, fingerprint: AlertFingerprint, hints: readonly string[]) {
  target.total += 1;
  if (fingerprint.level === 'fine') target.fine += 1;
  const c = fingerprint.components;
  if (c.ruleKey === null) target.noRule += 1;
  if (c.user === null && c.host === null && c.srcIp === null) target.noSubject += 1;
  const behavior = [
    c.processImage,
    c.parentImage,
    c.commandLine,
    c.sha256,
    c.filePath,
    c.destination,
    c.destinationPort,
  ];
  if (behavior.every((value) => value === null)) target.noBehavior += 1;
  for (const hint of hints) target.hints.set(hint, (target.hints.get(hint) ?? 0) + 1);
}

const dump = option('alerts');
const { samples, skipped } = dump ? fromDump(resolve(dump)) : fromFixtures();
const byRule = new Map<string, Bucket>();
const bySource = new Map<string, Bucket>();
const quarantined: string[] = [];
const all = bucket();
/** Huellas distintas: número de grupos si la ventana de agrupación no cortara nunca. */
const distinct = new Set<string>();
const distinctFine = new Set<string>();

for (const [index, sample] of samples.entries()) {
  const raw = JSON.stringify(sample.alert);
  const sha = createHash('sha256').update(raw).digest('hex');
  const input: WazuhAlertInput = {
    record: {
      sourceRecordId: `coverage-${index}`,
      dataset: 'alerts',
      collectedAt: '2026-11-24T12:00:01.000Z',
      raw: sample.alert,
    },
    raw: {
      ref: `raw:coverage/${index}`,
      sha256: sha,
      mediaType: 'application/json',
      sizeBytes: Buffer.byteLength(raw),
    },
  };
  const outcome = normalizeWazuhAlert(input, {
    tenantId: 'tenant-coverage',
    instanceId: 'coverage',
    connector: 'coverage',
    connectorVersion: '1',
    receivedAt: new Date('2026-11-24T12:00:02.000Z'),
  });
  if (outcome.status !== 'normalized') {
    quarantined.push(`${sample.origin}: ${outcome.quarantined.reason.code}`);
    continue;
  }
  const fingerprint = computeFingerprint(outcome.event);
  distinct.add(fingerprint.fingerprint);
  if (fingerprint.level === 'fine') distinctFine.add(fingerprint.fingerprint);
  const ruleKey = fingerprint.ruleKey ?? '(sin regla)';
  const source = ruleKey.split(':')[0] ?? 'unknown';
  const hints = unmappedHints(sample.alert);
  for (const target of [
    all,
    byRule.get(ruleKey) ?? byRule.set(ruleKey, bucket()).get(ruleKey)!,
    bySource.get(source) ?? bySource.set(source, bucket()).get(source)!,
  ]) {
    record(target, fingerprint, hints);
  }
}

/* ----------------------------------------------------------------- Informe */

const pct = (part: number, total: number) =>
  total === 0 ? '—' : `${Math.round((100 * part) / total)} %`;
const hintList = (target: Bucket) =>
  [...target.hints.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 4)
    .map(([path]) => `\`${path}\``)
    .join(', ') || '—';

const lines: string[] = [];
lines.push(`Entrada: ${dump ? `volcado \`${dump}\`` : 'fixtures del repo (sin volcado)'}`);
lines.push(
  `Normalizador v${OBSERVABLES_NORMALIZER_VERSION} · huellas distintas (grupos sin corte de ventana): ${distinct.size} · de ellas finas: ${distinctFine.size}`,
);
lines.push(
  `Alertas evaluadas: ${all.total} · huella fina: ${all.fine} (${pct(all.fine, all.total)}) · cuarentena: ${quarantined.length} · líneas no evaluables sin logtest: ${Object.values(skipped).reduce((a, b) => a + b, 0)}`,
);
lines.push(
  '',
  '### Por fuente',
  '',
  '| Fuente | Alertas | Fina | Sin sujeto | Sin comportamiento | Campos presentes sin mapear |',
  '|---|---:|---:|---:|---:|---|',
);
for (const [source, target] of [...bySource.entries()].sort()) {
  lines.push(
    `| ${source} | ${target.total} | ${pct(target.fine, target.total)} | ${target.noSubject} | ${target.noBehavior} | ${hintList(target)} |`,
  );
}
lines.push(
  '',
  '### Reglas con huella gruesa (más alertas primero)',
  '',
  '| Regla | Alertas | Fina | Falta | Campos presentes sin mapear |',
  '|---|---:|---:|---|---|',
);
const coarse = [...byRule.entries()]
  .filter(([, target]) => target.fine < target.total)
  .sort((left, right) => right[1].total - left[1].total);
for (const [rule, target] of coarse.slice(0, 25)) {
  const missing = [
    target.noRule ? 'regla' : '',
    target.noSubject ? 'sujeto' : '',
    target.noBehavior ? 'comportamiento' : '',
  ]
    .filter(Boolean)
    .join(', ');
  lines.push(
    `| \`${rule}\` | ${target.total} | ${pct(target.fine, target.total)} | ${missing || '—'} | ${hintList(target)} |`,
  );
}
if (Object.keys(skipped).length > 0) {
  lines.push('', '### Fixtures de texto no evaluables sin wazuh-logtest', '');
  for (const [dir, count] of Object.entries(skipped).sort())
    lines.push(`- \`${dir}\`: ${count} líneas`);
}
if (quarantined.length > 0) {
  lines.push('', '### En cuarentena (el normalizador las rechazó)', '');
  for (const entry of quarantined.slice(0, 20)) lines.push(`- ${entry}`);
}

const report = `${lines.join('\n')}\n`;
const out = option('out');
if (out) writeFileSync(resolve(out), report);
process.stdout.write(report);
