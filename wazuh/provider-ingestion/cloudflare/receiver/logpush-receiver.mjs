#!/usr/bin/env node
// B89 SOC · receptor HTTPS de Cloudflare Logpush → spool local (lo consume logpush_spool.py).
//
// Cloudflare (job Logpush, destino HTTP) → HTTPS → edge nginx → este servicio → spool/incoming.
// Ruta: POST /hooks/cloudflare-logpush/<dataset>/<scope_id>
//
// Controles:
//   - Autenticación por cabecera X-B89-Logpush-Token (Cloudflare la envía con `header_...` en el
//     destination_conf), comparada en tiempo constante contra el secreto montado en un archivo.
//   - dataset y scope_id con lista blanca de formato; solo los datasets permitidos.
//   - Cuerpo acotado (gzip o NDJSON tal cual llega); nunca se descomprime ni se registra el contenido.
//   - Publicación atómica: tmp/ → rename a incoming/ (el consumidor jamás ve un objeto a medias).
//   - Contrapresión: si el spool supera el máximo de objetos pendientes responde 503 y Cloudflare
//     reintenta; no se descarta nada en silencio.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const HOOK_PREFIX = '/hooks/cloudflare-logpush/';
export const DEFAULT_DATASETS = new Set([
  'http_requests',
  'dns_logs',
  'firewall_events',
  'audit_logs',
]);
const ROUTE_RE = /^\/hooks\/cloudflare-logpush\/([a-z][a-z0-9_]{0,99})\/([A-Za-z0-9_-]{1,128})\/?$/;

export function log(level, msg, extra = {}) {
  process.stdout.write(
    `${JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra })}\n`,
  );
}

export function parseRoute(url) {
  let pathname;
  try {
    pathname = new URL(url, 'http://local').pathname;
  } catch {
    return null;
  }
  const m = ROUTE_RE.exec(pathname);
  return m ? { dataset: m[1], scope: m[2] } : null;
}

export function tokenMatches(presented, expected) {
  if (typeof presented !== 'string' || !presented || !expected) return false;
  const a = crypto.createHash('sha256').update(presented).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export class Spool {
  constructor(dir, maxPending) {
    this.dir = dir;
    this.maxPending = maxPending;
    this.tmp = path.join(dir, 'tmp');
    this.incoming = path.join(dir, 'incoming');
  }

  pending() {
    return fs.readdirSync(this.incoming).length;
  }

  publish(dataset, scope, body) {
    const id = crypto.randomBytes(12).toString('hex');
    const name = `${Date.now()}-${id}.${dataset}.${scope}.ndjson`;
    const tmp = path.join(this.tmp, name);
    const fd = fs.openSync(tmp, 'wx', 0o640);
    try {
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, path.join(this.incoming, name));
    return name;
  }
}

export function createHandler({
  token,
  spool,
  datasets = DEFAULT_DATASETS,
  maxBody = 32 * 1024 * 1024,
}) {
  const stats = { accepted: 0, rejected: 0, bytes: 0 };
  async function handle(req, res) {
    const reply = (status, body = '') => {
      res.writeHead(status, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
      });
      res.end(body);
    };
    const reject = (status, reason, extra = {}) => {
      stats.rejected += 1;
      log('warn', 'rechazado', { status, reason, ...extra });
      req.resume();
      return reply(status, `${reason}\n`);
    };
    if (req.method === 'GET' && req.url === '/healthz') return reply(200, 'ok\n');
    const route = parseRoute(req.url);
    if (!route) return reject(404, 'ruta no encontrada');
    if (req.method !== 'POST') return reject(405, 'solo POST');
    if (!tokenMatches(req.headers['x-b89-logpush-token'], token))
      return reject(401, 'no autorizado');
    if (!datasets.has(route.dataset))
      return reject(403, 'dataset no permitido', { dataset: route.dataset });
    let pendingCount;
    try {
      pendingCount = spool.pending();
    } catch (err) {
      log('error', 'spool no disponible', { error: err.code ?? err.message });
      return reply(503, 'spool no disponible\n');
    }
    if (pendingCount >= spool.maxPending)
      return reject(503, 'spool lleno; reintentar', { pending: pendingCount });

    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > maxBody) return reject(413, 'cuerpo demasiado grande');
      chunks.push(chunk);
    }
    if (size === 0) return reject(400, 'cuerpo vacío');
    try {
      spool.publish(route.dataset, route.scope, Buffer.concat(chunks));
    } catch (err) {
      log('error', 'no se pudo escribir en el spool', { error: err.code ?? err.message });
      return reply(503, 'error de escritura; reintentar\n');
    }
    stats.accepted += 1;
    stats.bytes += size;
    log('info', 'lote', { dataset: route.dataset, scope: route.scope, bytes: size });
    return reply(200, 'ok\n');
  }
  return { handle, stats };
}

export function readToken(file) {
  const value = fs.readFileSync(file, 'utf8').trim();
  if (value.length < 32) throw new Error('el secreto de Logpush es demasiado corto');
  return value;
}

function main() {
  const token = readToken(process.env.B89_LOGPUSH_TOKEN_FILE ?? '/run/secrets/logpush-token');
  const spool = new Spool(
    process.env.B89_LOGPUSH_SPOOL ?? '/spool',
    Number(process.env.B89_LOGPUSH_MAX_PENDING ?? 5000),
  );
  fs.accessSync(spool.tmp, fs.constants.W_OK);
  fs.accessSync(spool.incoming, fs.constants.W_OK);
  const { handle } = createHandler({ token, spool });
  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log('error', 'error no controlado', { error: err.message });
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  server.requestTimeout = 60000;
  server.headersTimeout = 10000;
  server.maxHeadersCount = 60;
  const port = Number(process.env.PORT ?? 8080);
  server.listen(port, '0.0.0.0', () => log('info', 'escuchando', { port }));
  for (const sig of ['SIGTERM', 'SIGINT'])
    process.on(sig, () => server.close(() => process.exit(0)));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main();
