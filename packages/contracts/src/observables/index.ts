/**
 * Aprendizaje SOC · etapa B — extensión `b89.observables` v1 del SecurityEvent
 * (docs/soc-learning/01-diseno.md §4.2–§4.3).
 *
 * Es un namespace dentro de `extensions`, igual que `microsoft.office365`: aditivo dentro del
 * contrato 1.0.0, ningún consumidor actual lo lee. Lleva lo que hace falta para distinguir un
 * comportamiento de otro (proceso, archivo, destino, MITRE) ya **normalizado y redactado**: los
 * valores variables (timestamps, GUID, rutas temporales, puertos efímeros) se reemplazan por
 * marcadores y los secretos se quitan antes de que el evento salga del normalizador.
 *
 * Las funciones de este módulo son puras y deterministas: la misma entrada da siempre la misma
 * salida, en cualquier proceso. El contrato no depende de Node: quien normaliza inyecta un
 * `Sha256Hex` (en el backend, `node:crypto`). Un hash no criptográfico permitiría fabricar a
 * propósito dos payloads con el mismo marcador. Cambiar una regla de normalización exige subir
 * `OBSERVABLES_NORMALIZER_VERSION`, porque cambia la huella de las alertas.
 */

export const OBSERVABLES_EXTENSION_NAMESPACE = 'b89.observables' as const;
export const OBSERVABLES_SCHEMA_VERSION = 1 as const;
/**
 * Historial:
 * - `1`: primera versión.
 * - `2`: temporales normalizados por UBICACIÓN y por segmento (carpetas y archivo bajo el
 *   directorio temporal), conservando extensión y clase de prefijo. v1 solo reemplazaba tramos hex
 *   con algún dígito: `tmpcbbf`, `GetRandomFileName` y `mktemp` producían huellas distintas para
 *   el mismo comportamiento, y `.ps1` se convertía en `.ps{N}`.
 * La versión entra en la huella: una huella v1 y una v2 del mismo evento nunca son iguales.
 */
export const OBSERVABLES_NORMALIZER_VERSION = '2' as const;

export const OBSERVABLES_LIMITS = Object.freeze({
  pathMaximum: 512,
  commandLineMaximum: 2048,
  domainMaximum: 253,
  mitreMaximum: 16,
});

export interface ObservedProcess {
  readonly image?: string;
  readonly commandLine?: string;
  readonly sha256?: string;
}

export interface ObservedFile {
  readonly path?: string;
  readonly sha256?: string;
}

export interface ObservedDestination {
  readonly ip?: string;
  readonly port?: number;
  readonly domain?: string;
}

export interface ObservedMitre {
  readonly techniques: readonly string[];
  readonly tactics: readonly string[];
}

/** Contenido de `extensions['b89.observables']`. Todo opcional salvo las versiones. */
export interface ObservablesV1 {
  readonly v: typeof OBSERVABLES_SCHEMA_VERSION;
  readonly normalizer: string;
  readonly agentId?: string;
  readonly process?: ObservedProcess;
  readonly parent?: { readonly image?: string };
  readonly file?: ObservedFile;
  readonly destination?: ObservedDestination;
  readonly mitre?: ObservedMitre;
}

/* -------------------------------------------------------------- Redacción */

const REDACTED = '{REDACTED}';

/** SHA-256 en hexadecimal (64 caracteres). Lo inyecta quien normaliza. */
export type Sha256Hex = (value: string) => string;

/**
 * Reglas de redacción, en orden. Se aplican ANTES de cualquier otra normalización y antes de
 * persistir: un secreto en una línea de comando no debe llegar a la base ni a una huella.
 * La lista no es exhaustiva (§14 riesgos residuales); por eso la línea original nunca se guarda.
 */
type Replacement = string | ((match: string, ...groups: string[]) => string);

const secretRules = (digest: Sha256Hex): readonly (readonly [RegExp, Replacement])[] => [
  // Credenciales en una URL: esquema://usuario:clave@host
  [/([a-z][a-z0-9+.-]*:\/\/)([^\s/:@]+):([^\s/@]+)@/giu, `$1$2:${REDACTED}@`],
  // Cabecera Authorization y tokens bearer/basic.
  [/\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s"']+/giu, `$1${REDACTED}`],
  [/\b(bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/giu, `$1${REDACTED}`],
  // JWT.
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/gu, REDACTED],
  // Claves de acceso de AWS.
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu, REDACTED],
  // Opciones de línea de comando con secreto: --password x, --token=x, /p:x …
  [
    /((?:^|\s)(?:--?|\/)(?:password|passwd|pass|pwd|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret|private[-_]?key)(?:\s+|[=:]))("[^"]*"|'[^']*'|[^\s"']+)/giu,
    `$1${REDACTED}`,
  ],
  // `net use … /p:CLAVE` y `runas`-like: /p: con dos puntos es siempre una contraseña.
  [/((?:^|\s)\/p:)("[^"]*"|[^\s"']+)/giu, `$1${REDACTED}`],
  // Asignaciones clave=valor (cadenas de conexión, variables de entorno).
  [
    /\b((?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|sharedaccesskey|accountkey)\s*=\s*)("[^"]*"|'[^']*'|[^\s;"'&]+)/giu,
    `$1${REDACTED}`,
  ],
  // mysql -pCLAVE (sin espacio): solo en clientes MySQL, `-p` suele ser un puerto en otros.
  [/\b(mysql(?:dump|admin)?(?:\.exe)?\b[^\n]*?\s-p)(?!\s)([^\s"']+)/giu, `$1${REDACTED}`],
  // PowerShell -EncodedCommand (o cualquier prefijo: -e, -enc, -EncodedC…): el contenido se
  // reemplaza por un hash corto. Distingue dos payloads distintos sin guardar ninguno.
  [
    /((?:^|\s)-(e[a-z]*)\s+)([A-Za-z0-9+/]{40,}={0,2})/giu,
    (match: string, prefix: string, flag: string, payload: string) =>
      'encodedcommand'.startsWith(flag.toLowerCase())
        ? `${prefix}{B64:${shortHash(digest, payload)}}`
        : match,
  ],
];

/**
 * Hash corto en letras `g`–`v` (un nibble por letra): sin dígitos ni hex, así ninguna regla de
 * valores variables lo vuelve a tocar.
 */
function shortHash(digest: Sha256Hex, value: string): string {
  const hex = digest(value).toLowerCase();
  if (!/^[0-9a-f]{64}$/u.test(hex)) throw new TypeError('El digest debe ser SHA-256 en hex.');
  return hex
    .slice(0, 16)
    .replace(/[0-9a-f]/gu, (nibble: string) =>
      String.fromCharCode(103 + Number.parseInt(nibble, 16)),
    );
}

export function redactSecrets(value: string, digest: Sha256Hex): string {
  let result = value;
  for (const [pattern, replacement] of secretRules(digest)) {
    result =
      typeof replacement === 'string'
        ? result.replace(pattern, replacement)
        : result.replace(pattern, replacement as (substring: string, ...args: string[]) => string);
  }
  return result;
}

/* ---------------------------------------------------- Valores variables */

const GUID = /\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/giu;
const ISO_TIMESTAMP =
  /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b/giu;
const COMPACT_TIMESTAMP = /\b\d{8}[_-]?\d{6}\b/gu;
const EPOCH = /\b1[5-9]\d{8}(?:\d{3})?\b/gu;
const LONG_HEX = /\b[0-9a-f]{16,}\b/giu;

/** Marcadores ya insertados: protegidos de los reemplazos siguientes. */
const PLACEHOLDER = /\{(?:REDACTED|GUID|HEX|TS|TMP|HOME|N|B64:[g-v]{16})\}/gu;

function replaceVariables(value: string): string {
  return value
    .replace(GUID, '{GUID}')
    .replace(ISO_TIMESTAMP, '{TS}')
    .replace(COMPACT_TIMESTAMP, '{TS}')
    .replace(EPOCH, '{TS}')
    .replace(LONG_HEX, '{HEX}');
}

const WINDOWS_HOME = /\b[a-z]:\\users\\[^\\\s"']+\\/giu;
/**
 * Directorios temporales (la ubicación decide, no la forma del nombre). Capturan TODOS los
 * segmentos que cuelgan del directorio, no solo el primero (v1 solo normalizaba el primero).
 */
const WINDOWS_TEMP =
  /(?:\{HOME\}\\appdata\\local\\temp|%temp%|%tmp%|\b[a-z]:\\windows\\temp)((?:\\[^\\\s"']+)*)/giu;
const UNIX_HOME = /(^|[\s"'=])\/home\/[^/\s"']+\//gu;
const UNIX_TEMP = /(^|[\s"'=])\/(?:tmp|var\/tmp|dev\/shm)((?:\/[^/\s"']+)*)/gu;

/**
 * Prefijos de generadores conocidos de temporales (se comparan sin mayúsculas). Se conserva la
 * «clase de prefijo» (`tmp`, `~df`, `_mei`…) y se reemplaza solo la parte aleatoria que sigue.
 */
const TEMP_PREFIXES = [
  'jar_cache',
  'scoped_dir',
  'tmp.',
  'temp',
  'pyi-',
  '_mei',
  '~wrs',
  '~wrd',
  '~df',
  'is-',
  'msi',
  'nsu',
  'nsx',
  'wct',
  'tmp',
] as const;

/**
 * Prefijos cuya plantilla SIEMPRE va seguida de caracteres aleatorios (`mktemp` → `tmp.XXXXXXXXXX`,
 * PyInstaller `_MEIxxxxx`, Inno Setup `is-XXXXX`, Chrome `scoped_dir…`). Tras ellos, cualquier
 * resto alfanumérico de ≥ 4 caracteres es aleatorio, aunque solo tenga letras.
 */
const RANDOM_SUFFIX_PREFIXES = new Set(['tmp.', '_mei', 'pyi-', 'is-', 'scoped_dir', 'jar_cache']);

/** Extensiones con dígitos que tienen significado y se conservan tal cual. */
const DIGIT_EXTENSIONS = new Set([
  'ps1',
  'psm1',
  'psd1',
  'mp3',
  'mp4',
  'm4a',
  '7z',
  'bz2',
  'p7b',
  'p12',
]);

const ANY_PLACEHOLDER = /^\{[A-Za-z0-9:]+\}$/u;

/**
 * ¿Parece la parte aleatoria de un generador? Reglas, en orden:
 * - hex puro de ≥ 3 (`cbbf`, `4F2A`): `GetTempFileName` usa 4 hex;
 * - palabra + número corto (`backup2`, `cache10`): NO, es un nombre con significado;
 * - letras y dígitos mezclados (`xkq3z1ab`): `GetRandomFileName`, `mktemp`;
 * - mayúsculas y minúsculas alternadas con alguna minúscula aislada (`aBcDeF`): `mktemp`. Un
 *   nombre CamelCase (`BackupLog`) tiene tramos en minúscula de ≥ 2 y se conserva.
 * Límite conocido: un nombre aleatorio solo de letras minúsculas no hex (p. ej. `xkqzabcd`,
 * ~19 % de los de `GetRandomFileName`) no se distingue de una palabra y se conserva.
 */
export function isRandomTempToken(token: string): boolean {
  const value = token.replace(/^[._-]+|[._-]+$/gu, '');
  if (value.length < 3 || ANY_PLACEHOLDER.test(value)) return false;
  if (/^[0-9a-f]+$/iu.test(value)) return true;
  if (/^[a-z]{3,}\d{1,2}$/iu.test(value)) return false;
  if (/\d/u.test(value) && /[a-z]/iu.test(value) && /^[a-z0-9._-]+$/iu.test(value)) return true;
  return (
    value.length >= 5 &&
    /[a-z]/u.test(value) &&
    /[A-Z]/u.test(value) &&
    /^[a-z]+$/iu.test(value) &&
    /(?:^|[A-Z])[a-z](?=[A-Z]|$)/u.test(value)
  );
}

/** Nombre sin extensión: conserva la clase de prefijo y reemplaza la parte aleatoria por `{N}`. */
function normalizeTempStem(stem: string): string {
  const lower = stem.toLowerCase();
  for (const prefix of TEMP_PREFIXES) {
    if (lower.startsWith(prefix) && stem.length > prefix.length) {
      const rest = stem.slice(prefix.length);
      const guaranteed = RANDOM_SUFFIX_PREFIXES.has(prefix) && /^[a-z0-9_-]{4,}$/iu.test(rest);
      // `tmpbackup` y `tmpcache` tienen significado: no se fusionan.
      return guaranteed || isRandomTempToken(rest) ? `${prefix}{N}` : stem;
    }
  }
  if (isRandomTempToken(stem)) return '{N}';
  // Prefijo propio + parte aleatoria (`setup3f9a2` → `setup{N}`).
  const split = /^([a-z]{3,})(.+)$/iu.exec(stem);
  if (split && isRandomTempToken(split[2]!)) return `${split[1]!.toLowerCase()}{N}`;
  return stem;
}

/** Último segmento (archivo): la extensión se conserva (`.ps1` ≠ `.exe`) salvo si es aleatoria. */
function normalizeTempFile(name: string): string {
  const dot = name.lastIndexOf('.');
  const extension = dot > 0 ? name.slice(dot + 1) : '';
  if (!/^[a-z0-9]{1,8}$/iu.test(extension)) return normalizeTempStem(name);
  const stem = name.slice(0, dot);
  const keep = /^[a-z]+$/iu.test(extension) || DIGIT_EXTENSIONS.has(extension.toLowerCase());
  return `${normalizeTempStem(stem)}.${keep ? extension : '{N}'}`;
}

/** Segmentos bajo un directorio temporal: carpetas aleatorias → `{N}`; el archivo, por partes. */
function normalizeTempTail(tail: string | undefined, separator: string): string {
  if (!tail) return '';
  const segments = tail.split(separator).filter((segment) => segment.length > 0);
  return segments
    .map((segment, index) =>
      index === segments.length - 1 ? normalizeTempFile(segment) : normalizeTempStem(segment),
    )
    .map((segment) => `${separator}${segment}`)
    .join('');
}

function replacePaths(value: string): string {
  return value
    .replace(WINDOWS_HOME, '{HOME}\\')
    .replace(
      WINDOWS_TEMP,
      (_match, tail: string | undefined) => `{TMP}${normalizeTempTail(tail, '\\')}`,
    )
    .replace(UNIX_HOME, '$1{HOME}/')
    .replace(
      UNIX_TEMP,
      (_match, lead: string, tail: string | undefined) =>
        `${lead}{TMP}${normalizeTempTail(tail, '/')}`,
    );
}

const WINDOWS_EXECUTABLE = /\.(?:exe|com|bat|cmd|ps1|vbs|msc|scr|cpl|dll)$/iu;

function isWindowsPath(value: string): boolean {
  return /^(?:[a-z]:\\|\\\\|%[a-z]+%)/iu.test(value) || value.includes('\\');
}

/* ---------------------------------------------------- Normalizadores */

/** Ruta de archivo o imagen de proceso. Windows no distingue mayúsculas: se pasa a minúsculas. */
export function normalizePath(value: unknown, digest: Sha256Hex): string | undefined {
  if (typeof value !== 'string') return undefined;
  let path = value.trim().replace(/^"(.*)"$/u, '$1');
  if (path.length === 0) return undefined;
  if (isWindowsPath(path)) path = path.toLowerCase();
  path = replacePaths(replaceVariables(redactSecrets(path, digest)));
  return path.slice(0, OBSERVABLES_LIMITS.pathMaximum);
}

/**
 * Línea de comando: redacta secretos, reemplaza valores variables, colapsa espacios y pasa a
 * minúsculas solo el ejecutable si es una ruta de Windows (los argumentos pueden distinguir
 * mayúsculas). El orden de los argumentos se conserva: cambia el comportamiento.
 */
export function normalizeCommandLine(value: unknown, digest: Sha256Hex): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  let line = redactSecrets(trimmed, digest).replace(/\s+/gu, ' ');
  // Ejecutable: primer token, con o sin comillas.
  const head = /^("([^"]+)"|(\S+))/u.exec(line);
  if (head) {
    const executable = head[2] ?? head[3] ?? '';
    // Un ejecutable de Windows sin ruta (`POWERSHELL.EXE`) tampoco distingue mayúsculas.
    const normalizedExecutable =
      isWindowsPath(executable) || WINDOWS_EXECUTABLE.test(executable)
        ? executable.toLowerCase()
        : executable;
    line = `${normalizedExecutable}${line.slice(head[0].length)}`;
  }
  // Rutas de Windows dentro de los argumentos, también sin distinguir mayúsculas.
  line = line.replace(/\b[a-z]:\\[^\s"']*/giu, (path) => path.toLowerCase());
  line = replacePaths(replaceVariables(line));
  return line.slice(0, OBSERVABLES_LIMITS.commandLineMaximum);
}

export function normalizeSha256(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const hash = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/u.test(hash) ? hash : undefined;
}

/** `SHA256=…,MD5=…` (Sysmon) o un hash suelto. */
export function sha256FromHashes(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const match = /(?:^|[,;\s])sha256=([0-9a-f]{64})(?:$|[,;\s])/iu.exec(value);
  return match ? normalizeSha256(match[1]) : normalizeSha256(value);
}

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;

export function normalizeIp(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const ip = value
    .trim()
    .toLowerCase()
    .replace(/^::ffff:/u, '');
  if (IPV4.test(ip)) return ip;
  return IPV6.test(ip) && ip.includes(':') ? ip : undefined;
}

/** Puerto de destino; los efímeros (≥ 49152) no describen el servicio y se descartan. */
export function normalizePort(value: unknown): number | undefined {
  const port =
    typeof value === 'number' ? value : typeof value === 'string' ? Number(value.trim()) : NaN;
  if (!Number.isInteger(port) || port < 1 || port >= 49152) return undefined;
  return port;
}

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}$/u;

export function normalizeDomain(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const domain = value.trim().toLowerCase().replace(/\.$/u, '');
  if (domain.length === 0 || normalizeIp(domain) !== undefined) return undefined;
  return DOMAIN.test(domain) ? domain : undefined;
}

/** «Credential Access» → `credential-access`; `TA0006` se conserva en mayúsculas. */
export function normalizeTactic(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const raw = value.trim();
  if (/^TA\d{4}$/iu.test(raw)) return raw.toUpperCase();
  const slug = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-|-$/gu, '');
  return slug.length > 0 && slug.length <= 64 ? slug : undefined;
}

export function normalizeTechnique(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const id = value.trim().toUpperCase();
  return /^T\d{4}(?:\.\d{3})?$/u.test(id) ? id : undefined;
}

/* ------------------------------------------------ Lectura del evento */

function asObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function cleanStrings(values: unknown, normalize: (value: unknown) => string | undefined) {
  if (!Array.isArray(values)) return [];
  const result = new Set<string>();
  for (const value of values) {
    const normalized = normalize(value);
    if (normalized !== undefined) result.add(normalized);
    if (result.size >= OBSERVABLES_LIMITS.mitreMaximum) break;
  }
  return [...result].sort();
}

/**
 * Lee `extensions['b89.observables']` de un evento y lo vuelve a normalizar (idempotente). Un
 * valor ausente, de otra versión o mal formado se trata como ausente: la huella cae a nivel
 * grueso, que nunca autocierra. Nunca lanza.
 */
export function readObservables(
  extensions: Readonly<Record<string, unknown>> | undefined,
  digest: Sha256Hex,
): ObservablesV1 | undefined {
  const raw = asObject(extensions?.[OBSERVABLES_EXTENSION_NAMESPACE]);
  if (!raw || raw['v'] !== OBSERVABLES_SCHEMA_VERSION) return undefined;
  const process = asObject(raw['process']);
  const parent = asObject(raw['parent']);
  const file = asObject(raw['file']);
  const destination = asObject(raw['destination']);
  const mitre = asObject(raw['mitre']);
  return buildObservables(
    {
      agentId: typeof raw['agentId'] === 'string' ? raw['agentId'] : undefined,
      processImage: process?.['image'],
      commandLine: process?.['commandLine'],
      processSha256: process?.['sha256'],
      parentImage: parent?.['image'],
      filePath: file?.['path'],
      fileSha256: file?.['sha256'],
      destinationIp: destination?.['ip'],
      destinationPort: destination?.['port'],
      destinationDomain: destination?.['domain'],
      techniques: mitre?.['techniques'],
      tactics: mitre?.['tactics'],
    },
    digest,
  );
}

export interface ObservablesInput {
  readonly agentId?: unknown;
  readonly processImage?: unknown;
  readonly commandLine?: unknown;
  readonly processSha256?: unknown;
  readonly parentImage?: unknown;
  readonly filePath?: unknown;
  readonly fileSha256?: unknown;
  readonly destinationIp?: unknown;
  readonly destinationPort?: unknown;
  readonly destinationDomain?: unknown;
  readonly techniques?: unknown;
  readonly tactics?: unknown;
}

function defined<T>(value: T | undefined): value is T {
  return value !== undefined;
}

/**
 * Construye la extensión a partir de valores crudos de cualquier proveedor. Devuelve
 * `undefined` si no hay ningún observable de comportamiento ni MITRE: el `agentId` solo no
 * justifica la extensión (ya viaja como recurso `host`).
 */
export function buildObservables(
  input: ObservablesInput,
  digest: Sha256Hex,
): ObservablesV1 | undefined {
  const image = normalizePath(input.processImage, digest);
  const commandLine = normalizeCommandLine(input.commandLine, digest);
  const processSha256 = sha256FromHashes(input.processSha256);
  const parentImage = normalizePath(input.parentImage, digest);
  const filePath = normalizePath(input.filePath, digest);
  const fileSha256 = normalizeSha256(input.fileSha256);
  const ip = normalizeIp(input.destinationIp);
  const port = normalizePort(input.destinationPort);
  const domain = normalizeDomain(input.destinationDomain);
  const techniques = cleanStrings(input.techniques, normalizeTechnique);
  const tactics = cleanStrings(input.tactics, normalizeTactic);

  const process: ObservedProcess | undefined =
    defined(image) || defined(commandLine) || defined(processSha256)
      ? {
          ...(defined(image) ? { image } : {}),
          ...(defined(commandLine) ? { commandLine } : {}),
          ...(defined(processSha256) ? { sha256: processSha256 } : {}),
        }
      : undefined;
  const file: ObservedFile | undefined =
    defined(filePath) || defined(fileSha256)
      ? {
          ...(defined(filePath) ? { path: filePath } : {}),
          ...(defined(fileSha256) ? { sha256: fileSha256 } : {}),
        }
      : undefined;
  const destination: ObservedDestination | undefined =
    defined(ip) || defined(port) || defined(domain)
      ? {
          ...(defined(ip) ? { ip } : {}),
          ...(defined(port) ? { port } : {}),
          ...(defined(domain) ? { domain } : {}),
        }
      : undefined;
  const mitre = techniques.length > 0 || tactics.length > 0 ? { techniques, tactics } : undefined;
  if (!process && !defined(parentImage) && !file && !destination && !mitre) return undefined;
  const agentId =
    typeof input.agentId === 'string' && /^[A-Za-z0-9._-]{1,64}$/u.test(input.agentId.trim())
      ? input.agentId.trim()
      : undefined;
  return {
    v: OBSERVABLES_SCHEMA_VERSION,
    normalizer: OBSERVABLES_NORMALIZER_VERSION,
    ...(defined(agentId) ? { agentId } : {}),
    ...(process ? { process } : {}),
    ...(defined(parentImage) ? { parent: { image: parentImage } } : {}),
    ...(file ? { file } : {}),
    ...(destination ? { destination } : {}),
    ...(mitre ? { mitre } : {}),
  };
}

/** Marcadores que la normalización inserta; útil para pruebas y para la explicación al analista. */
export const OBSERVABLES_PLACEHOLDER_PATTERN = PLACEHOLDER;
