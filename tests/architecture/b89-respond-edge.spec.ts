import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';

const root = fileURLToPath(new URL('../../', import.meta.url));
const read = (path: string) => readFileSync(resolve(root, path), 'utf8');

it('B89 Respond edge mount is optional, preflighted and protected by the existing B89 session', () => {
  const edge = read('wazuh/edge/b89-edge.conf');
  const route = read('wazuh/edge/b89-b89-respond.location.conf');
  const deploy = read('wazuh/edge/apply-edge.sh');

  expect(edge).toContain('${B89_RESPOND_LOCATION}');
  expect(route).toContain('location ^~ /b89-respond/');
  expect(route).toContain('auth_request /_b89/introspect;');
  expect(route).toContain('error_page 401 = @b89_sign_in;');
  expect(route).toContain('error_page 403 = @b89_forbidden;');
  expect(route).toContain('proxy_pass http://${B89_RESPOND_UPSTREAM}/;');
  expect(route).toContain('X-Forwarded-Prefix /b89-respond;');
  expect(deploy).toContain('B89_RESPOND_UPSTREAM');
  expect(deploy).toContain('[[ "$b89_respond_code" == 200 ]]');
  expect(deploy).toContain('302 https://$SOC_HOSTNAME/b89/login?nextUrl=/b89-respond/');
});
