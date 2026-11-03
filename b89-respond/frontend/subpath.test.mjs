import assert from 'node:assert/strict';
import { test } from 'node:test';
import { prefixSource } from './subpath.mjs';

test('prefixes upstream route and navigation patterns under /b89-respond', () => {
  const source = [
    'window.location.pathname.startsWith("/login")',
    '<Route path="/workflows" />',
    'navigate("/apps")',
    'navigate(`/settings`)',
    '<a href="/docs">docs</a>',
    '<Link to="/dashboard" />',
    'const path = "/admin";',
    'const globalUrl = window.location.origin;',
    'const url = `${window.location.origin}/api/v1/health`;',
  ].join('\n');
  assert.equal(
    prefixSource(source),
    [
      'window.location.pathname.startsWith("/b89-respond/login")',
      '<Route path="/b89-respond/workflows" />',
      'navigate("/b89-respond/apps")',
      'navigate(`/b89-respond/settings`)',
      '<a href="/b89-respond/docs">docs</a>',
      '<Link to="/b89-respond/dashboard" />',
      'const path = "/b89-respond/admin";',
      'const globalUrl = "/b89-respond";',
      'const url = `/b89-respond/api/v1/health`;',
    ].join('\n'),
  );
});

test('is idempotent for an already prefixed bundle and leaves external URLs alone', () => {
  const source = [
    'navigate("/b89-respond/workflows")',
    '<img src="https://assets.example.test/logo.svg" />',
    'const url = "https://shuffler.io/docs";',
  ].join('\n');
  assert.equal(prefixSource(prefixSource(source)), prefixSource(source));
  assert.equal(prefixSource(source), source);
});
