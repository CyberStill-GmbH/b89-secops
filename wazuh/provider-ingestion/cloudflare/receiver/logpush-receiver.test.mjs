// node --test wazuh/provider-ingestion/cloudflare/receiver/
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { createHandler, parseRoute, Spool, tokenMatches } from './logpush-receiver.mjs';

const TOKEN = 'a'.repeat(48);

function makeSpool(maxPending = 10) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lp-'));
  fs.mkdirSync(path.join(dir, 'tmp'));
  fs.mkdirSync(path.join(dir, 'incoming'));
  return new Spool(dir, maxPending);
}

async function call(handle, { method = 'POST', url, headers = {}, body = '' }) {
  const req = Readable.from(body ? [Buffer.from(body)] : []);
  Object.assign(req, { method, url, headers });
  const res = {
    status: 0,
    body: '',
    headersSent: false,
    writeHead(status) {
      this.status = status;
      this.headersSent = true;
    },
    end(text = '') {
      this.body = text;
    },
  };
  await handle(req, res);
  return res;
}

test('parseRoute acepta dataset y zona; rechaza traversal y formatos raros', () => {
  assert.deepEqual(parseRoute('/hooks/cloudflare-logpush/http_requests/0123abc?x=1'), {
    dataset: 'http_requests',
    scope: '0123abc',
  });
  for (const bad of [
    '/hooks/cloudflare-logpush/../etc/x',
    '/hooks/cloudflare-logpush/HTTP/zone',
    '/hooks/cloudflare-logpush/http_requests/zo.ne',
    '/hooks/cloudflare-logpush/http_requests',
  ]) {
    assert.equal(parseRoute(bad), null, bad);
  }
});

test('tokenMatches en tiempo constante y nunca con valores vacíos', () => {
  assert.equal(tokenMatches(TOKEN, TOKEN), true);
  assert.equal(tokenMatches('b'.repeat(48), TOKEN), false);
  assert.equal(tokenMatches(undefined, TOKEN), false);
  assert.equal(tokenMatches('', ''), false);
});

test('un lote autenticado se publica de forma atómica en incoming/', async () => {
  const spool = makeSpool();
  const { handle, stats } = createHandler({ token: TOKEN, spool });
  const res = await call(handle, {
    url: '/hooks/cloudflare-logpush/http_requests/zone1',
    headers: { 'x-b89-logpush-token': TOKEN },
    body: '{"ClientIP":"192.0.2.1"}\n',
  });
  assert.equal(res.status, 200);
  const files = fs.readdirSync(spool.incoming);
  assert.equal(files.length, 1);
  assert.match(files[0], /^\d{13}-[0-9a-f]{24}\.http_requests\.zone1\.ndjson$/);
  assert.equal(fs.readdirSync(spool.tmp).length, 0);
  assert.equal(stats.accepted, 1);
});

test('sin token, dataset no permitido, método, vacío o tamaño: no escribe nada', async () => {
  const spool = makeSpool();
  const { handle } = createHandler({ token: TOKEN, spool, maxBody: 10 });
  const url = '/hooks/cloudflare-logpush/http_requests/zone1';
  const ok = { 'x-b89-logpush-token': TOKEN };
  assert.equal((await call(handle, { url, body: '{}' })).status, 401);
  assert.equal(
    (await call(handle, { url, headers: { 'x-b89-logpush-token': 'x'.repeat(48) }, body: '{}' }))
      .status,
    401,
  );
  assert.equal(
    (
      await call(handle, {
        url: '/hooks/cloudflare-logpush/other_ds/zone1',
        headers: ok,
        body: '{}',
      })
    ).status,
    403,
  );
  assert.equal((await call(handle, { method: 'GET', url, headers: ok })).status, 405);
  assert.equal((await call(handle, { url, headers: ok })).status, 400);
  assert.equal((await call(handle, { url, headers: ok, body: 'x'.repeat(11) })).status, 413);
  assert.equal(fs.readdirSync(spool.incoming).length, 0);
});

test('contrapresión: con el spool lleno responde 503 para que Cloudflare reintente', async () => {
  const spool = makeSpool(1);
  const { handle } = createHandler({ token: TOKEN, spool });
  const args = {
    url: '/hooks/cloudflare-logpush/dns_logs/zone1',
    headers: { 'x-b89-logpush-token': TOKEN },
    body: '{}',
  };
  assert.equal((await call(handle, args)).status, 200);
  assert.equal((await call(handle, args)).status, 503);
  assert.equal(fs.readdirSync(spool.incoming).length, 1);
});

test('healthz responde sin autenticación', async () => {
  const { handle } = createHandler({ token: TOKEN, spool: makeSpool() });
  assert.equal((await call(handle, { method: 'GET', url: '/healthz' })).status, 200);
});
