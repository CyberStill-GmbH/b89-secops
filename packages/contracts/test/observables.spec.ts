import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  buildObservables,
  isRandomTempToken,
  normalizeCommandLine,
  normalizeDomain,
  normalizePath,
  normalizePort,
  OBSERVABLES_EXTENSION_NAMESPACE,
  OBSERVABLES_NORMALIZER_VERSION,
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

describe('b89.observables · normalizador v2 de temporales (por ubicación)', () => {
  it('la versión del normalizador es 2', () => {
    expect(OBSERVABLES_NORMALIZER_VERSION).toBe('2');
  });

  describe('(a) mismo comportamiento, nombres aleatorios distintos ⇒ mismo valor', () => {
    it.each([
      [
        'GetTempFileName: hex sin dígitos, con dígitos y en mayúsculas',
        [
          'C:\\Users\\ana\\AppData\\Local\\Temp\\tmpcbbf.ps1',
          'C:\\Users\\luis\\AppData\\Local\\Temp\\tmp4F2A.ps1',
          'c:\\users\\ana\\appdata\\local\\temp\\TMPCBBF.PS1',
        ],
      ],
      [
        'GetRandomFileName alfanumérico',
        [
          'C:\\Windows\\Temp\\xkq3z1ab.ps1',
          'C:\\Windows\\Temp\\0a5bc2de.ps1',
          'C:\\Windows\\Temp\\ab0cd1ef.ps1',
        ],
      ],
      [
        'mktemp con letras, dígitos y mayúsculas (incluso solo letras)',
        ['/tmp/tmp.aBcD3fGh9K', '/tmp/tmp.ZZtopABCDE', '/tmp/tmp.q1w2e3r4t5'],
      ],
      [
        'carpetas aleatorias anidadas bajo el temporal',
        ['C:\\Windows\\Temp\\7zS3A1B\\setup.exe', 'C:\\Windows\\Temp\\7zS9F0C\\setup.exe'],
      ],
      ['/var/tmp y /dev/shm', ['/var/tmp/x9f3k2/run.sh', '/var/tmp/b8c2d0/run.sh']],
    ])('%s', (_label, paths) => {
      const normalized = paths.map((value) => path(value));
      expect(new Set(normalized).size, normalized.join(' | ')).toBe(1);
      expect(normalized[0]).toContain('{TMP}');
    });

    it('dentro de una línea de comando también', () => {
      expect(cmd('powershell.exe -File C:\\Windows\\Temp\\tmpcbbf.ps1 -Job 7')).toBe(
        cmd('POWERSHELL.EXE -File C:\\Windows\\Temp\\tmp4f2a.ps1 -Job 7'),
      );
    });
  });

  describe('(b) nombres con significado o fuera del temporal ⇒ NO se fusionan', () => {
    it.each([
      [
        'palabras tras el prefijo',
        'C:\\Windows\\Temp\\tmpbackup.ps1',
        'C:\\Windows\\Temp\\tmpcache.ps1',
      ],
      ['palabra + número corto', '/tmp/backup2.sh', '/tmp/cache3.sh'],
      ['CamelCase con significado', '/tmp/BackupLog.txt', '/tmp/RestoreLog.txt'],
      [
        'misma parte aleatoria, extensión distinta',
        'C:\\Windows\\Temp\\tmpcbbf.ps1',
        'C:\\Windows\\Temp\\tmpcbbf.exe',
      ],
      [
        'fuera de un directorio temporal (Windows)',
        'C:\\Scripts\\job4f2a.ps1',
        'C:\\Scripts\\jobcbbf.ps1',
      ],
      ['fuera de un directorio temporal (Linux)', '/opt/app/run1x9.sh', '/opt/app/run2k8.sh'],
      [
        'prefijo de generador distinto',
        'C:\\Windows\\Temp\\~DF3A1B.tmp',
        'C:\\Windows\\Temp\\tmp3A1B.tmp',
      ],
    ])('%s', (_label, left, right) => {
      expect(path(left)).not.toBe(path(right));
    });

    it('conserva la extensión y la clase de prefijo (v1 convertía .ps1 en .ps{N})', () => {
      expect(path('C:\\Windows\\Temp\\tmpcbbf.ps1')).toBe('{TMP}\\tmp{N}.ps1');
      expect(path('C:\\Windows\\Temp\\~DF3A1B.tmp')).toBe('{TMP}\\~df{N}.tmp');
      expect(path('/tmp/_MEI12345/python3.dll')).toBe('{TMP}/_mei{N}/python3.dll');
      expect(path('C:\\Scripts\\job4f2a.ps1')).toBe('c:\\scripts\\job4f2a.ps1');
    });
  });

  it.each([
    ['cbbf', true],
    ['4F2A', true],
    ['xkq3z1ab', true],
    ['aBcDeF', true],
    ['backup', false],
    ['backup2', false],
    ['BackupLog', false],
    ['ab', false],
    ['{GUID}', false],
  ])('isRandomTempToken(%s) = %s', (token, expected) => {
    expect(isRandomTempToken(token)).toBe(expected);
  });
});
