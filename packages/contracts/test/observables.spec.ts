import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  buildObservables,
  normalizeCommandLine,
  normalizeDomain,
  normalizePath,
  normalizePort,
  OBSERVABLES_EXTENSION_NAMESPACE,
  readObservables,
  redactSecrets,
  sha256FromHashes,
} from '../src/observables/index.js';

const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
const cmd = (value: string) => normalizeCommandLine(value, sha);
const path = (value: string) => normalizePath(value, sha);

describe('b89.observables · redacción de secretos', () => {
  it.each([
    ['opción --password', 'tool.exe --password S3cr3t! --user ana', 'S3cr3t!'],
    ['opción --token=', 'deploy --token=ghp_abcdefghijklmnop', 'ghp_abcdefghijklmnop'],
    ['/p: de Windows', 'net use \\\\srv\\c$ /p:Cl4veSecreta', 'Cl4veSecreta'],
    ['cadena de conexión', 'app "Server=db;User Id=sa;Password=Pa55word;"', 'Pa55word'],
    ['credencial en URL', 'curl https://ana:Pa55@api.example.com/x', 'Pa55'],
    ['bearer', 'curl -H "Authorization: Bearer abcdefghijklmnopqrstu"', 'abcdefghijklmnopqrstu'],
    ['JWT suelto', 'x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl', 'eyJhbGciOiJIUzI1NiJ9'],
    [
      'clave AWS',
      'aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP',
      'AKIAABCDEFGHIJKLMNOP',
    ],
    ['mysql -p pegado', 'mysql -u root -pMiClave123 db', 'MiClave123'],
  ])('%s', (_label, input, secret) => {
    const redacted = redactSecrets(input, sha);
    expect(redacted).not.toContain(secret);
    expect(redacted).toContain('{REDACTED}');
    expect(cmd(input)).not.toContain(secret);
  });

  it('no confunde -p de puerto en otros programas', () => {
    expect(redactSecrets('ssh -p 2222 host', sha)).toBe('ssh -p 2222 host');
  });

  it('PowerShell -enc: hash corto estable que distingue payloads sin guardarlos', () => {
    const payloadA =
      'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const payloadB =
      'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkB';
    const a = cmd(`powershell.exe -NoP -enc ${payloadA}`);
    const a2 = cmd(`powershell.exe -NoP -EncodedCommand ${payloadA}`);
    const b = cmd(`powershell.exe -NoP -enc ${payloadB}`);
    expect(a).not.toContain(payloadA);
    expect(a).toMatch(/\{B64:[g-v]{16}\}/u);
    const marker = (value: string | undefined) => /\{B64:[g-v]{16}\}/u.exec(value ?? '')?.[0];
    expect(marker(a)).toBe(marker(a2));
    expect(a).not.toBe(b);
  });
});

describe('b89.observables · valores variables', () => {
  it('timestamps, GUID, rutas temporales y perfiles de usuario no cambian el valor', () => {
    const first = cmd(
      'C:\\Users\\ana\\AppData\\Local\\Temp\\tmp8F3A1.ps1 -run {3F2504E0-4F89-11D3-9A0C-0305E82C3301} 2026-11-24T09:00:00Z',
    );
    const second = cmd(
      'c:\\users\\luis\\appdata\\local\\temp\\tmp9B2C7.ps1 -run {6BA7B810-9DAD-11D1-80B4-00C04FD430C8} 2026-11-25T10:11:12Z',
    );
    expect(first).toBe(second);
    expect(first).toContain('{TMP}');
    expect(first).toContain('{GUID}');
    expect(first).toContain('{TS}');
  });

  it('rutas temporales y home de Linux', () => {
    expect(cmd('/tmp/x123/run.sh --home /home/ana/.cfg')).toBe(
      cmd('/tmp/x987/run.sh --home /home/luis/.cfg'),
    );
  });

  it('un argumento distinto sí cambia el valor', () => {
    expect(cmd('schtasks /create /tn Backup')).not.toBe(cmd('schtasks /create /tn Updater'));
  });

  it('las rutas de Windows no distinguen mayúsculas; las de Linux sí', () => {
    expect(path('C:\\Windows\\System32\\SvcHost.exe')).toBe('c:\\windows\\system32\\svchost.exe');
    expect(path('/usr/bin/Tool')).toBe('/usr/bin/Tool');
  });

  it('puertos efímeros, dominios y hashes', () => {
    expect(normalizePort(443)).toBe(443);
    expect(normalizePort('51234')).toBeUndefined();
    expect(normalizeDomain('API.Example.COM.')).toBe('api.example.com');
    expect(normalizeDomain('10.0.0.1')).toBeUndefined();
    const hash = 'A'.repeat(64);
    expect(sha256FromHashes(`MD5=${'1'.repeat(32)},SHA256=${hash},IMPHASH=00`)).toBe(
      hash.toLowerCase(),
    );
  });
});

describe('b89.observables · extensión', () => {
  it('sin observables de comportamiento no hay extensión, aunque haya agente', () => {
    expect(buildObservables({ agentId: '017' }, sha)).toBeUndefined();
  });

  it('se construye, se lee de vuelta igual (idempotente) y descarta versiones ajenas', () => {
    const built = buildObservables(
      {
        agentId: '017',
        processImage: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c whoami',
        destinationIp: '203.0.113.9',
        destinationPort: 443,
        techniques: ['t1059.003', 'nope'],
        tactics: ['Execution'],
      },
      sha,
    );
    expect(built).toMatchObject({
      v: 1,
      agentId: '017',
      process: { image: 'c:\\windows\\system32\\cmd.exe', commandLine: 'cmd.exe /c whoami' },
      destination: { ip: '203.0.113.9', port: 443 },
      mitre: { techniques: ['T1059.003'], tactics: ['execution'] },
    });
    const read = readObservables({ [OBSERVABLES_EXTENSION_NAMESPACE]: built }, sha);
    expect(read).toEqual(built);
    expect(readObservables({ [OBSERVABLES_EXTENSION_NAMESPACE]: { v: 2 } }, sha)).toBeUndefined();
    expect(readObservables(undefined, sha)).toBeUndefined();
  });
});
