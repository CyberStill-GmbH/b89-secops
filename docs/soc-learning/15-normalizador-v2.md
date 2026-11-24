# Normalizador v2: archivos temporales

Fecha: 2026-11-24 · rama `feat/soc-learning-stage-a` · arreglo aprobado por el dueño.

## Causa raíz (v1)

En `packages/contracts/src/observables/index.ts`, función `tempLeaf` de v1:

```ts
leaf.slice(1).replace(/[0-9a-f]*\d[0-9a-f]*/giu, '{N}')
```

Tres defectos:

1. Solo reemplaza **tramos hex que contienen un dígito**. `tmpcbbf` (hex sin dígito) quedaba
   tal cual. Las letras fuera de `a-f` (`GetRandomFileName`: `xkq3z1ab` → `xkq{N}z{N}`; `mktemp`:
   `tmp.aBcD3fGh9K`) sobrevivían, así que cada ejecución daba otra huella.
2. Se aplicaba también a la **extensión**: `.ps1` → `.ps{N}`.
3. Solo procesaba **el primer segmento** bajo el directorio temporal; las carpetas aleatorias
   anidadas (`Temp\7zS3A1B\setup.exe`) quedaban sin tocar.

Reproducción: `scripts/soc-learning/measure-temp-normalization.ts` (tabla de abajo) y la prueba de
propiedades del laboratorio (45 de 1000 pares distintos con el generador del laboratorio).

## Diseño v2

**Decide la ubicación.** Solo se normaliza lo que cuelga de un directorio temporal:
- Windows: `{HOME}\AppData\Local\Temp`, `%TEMP%`, `%TMP%` y `X:\Windows\Temp`;
- Linux: `/tmp`, `/var/tmp` y `/dev/shm`.

Fuera de ellos no cambia nada (`C:\Scripts\job4f2a.ps1` se conserva).

**Por segmento.**
- Cada carpeta bajo el temporal: si su nombre parece aleatorio → `{N}`.
- El archivo: `<clase de prefijo>{N}.<extensión>`.
- La **extensión se conserva**, así que `.ps1` y `.exe` se siguen distinguiendo. Solo se
  reemplaza una extensión que parece aleatoria: tiene dígitos y no está en la lista de
  extensiones con dígitos que significan algo (`ps1`, `psm1`, `psd1`, `mp3`, `mp4`, `m4a`, `7z`,
  `bz2`, `p7b`, `p12`).

**Clase de prefijo.** Se conservan los prefijos de los generadores conocidos (`tmp`, `temp`,
`~df`, `~wrs`, `~wrd`, `_mei`, `is-`, `msi`, `nsu`, `nsx`, `wct`, `pyi-`, `scoped_dir`,
`jar_cache`, `tmp.`). Solo se reemplaza lo que sigue, y solo si es aleatorio.
- Tras `tmp.`, `_mei`, `is-`, `pyi-`, `scoped_dir` y `jar_cache`, la plantilla siempre es
  aleatoria: cualquier resto alfanumérico de 4 o más caracteres se reemplaza.
- Sin prefijo conocido: si el nombre entero parece aleatorio se reemplaza entero; si es una
  palabra seguida de una parte aleatoria (`setup3f9a2`) se conserva la palabra (`setup{N}`).

**Qué cuenta como aleatorio** (`isRandomTempToken`):
- hex puro de 3 o más (`cbbf`, `4F2A`);
- letras y dígitos mezclados (`xkq3z1ab`), **salvo** palabra + número corto (`backup2`), que se
  conserva;
- mayúsculas y minúsculas alternadas con alguna minúscula aislada (`aBcDeF`); un CamelCase con
  significado (`BackupLog`) se conserva.

**Límite conocido.** Un nombre aleatorio solo de letras que no son hex (`xkqzabcd`) es
indistinguible de una palabra y se conserva. Con `GetRandomFileName` le pasa al ~14 % de los
nombres, y otro ~5 % tiene forma de palabra + número. Es la elección conservadora: una huella
distinta escala, nunca cierra.

## Versionado

- `OBSERVABLES_NORMALIZER_VERSION = '2'`.
- La versión entra en el hash de la huella (`normalizer` en el JSON canónico) y se guarda en
  `soc_alert_fingerprints.normalizer_version`. Una huella v1 y una v2 del mismo evento **nunca**
  son iguales; lo prueba `fingerprint.spec.ts`.
- Las filas v1 **no se tocan**: la tabla es append-only (triggers).

**Grupos abiertos al desplegar.** El primer evento v2 de un comportamiento abre un grupo **nuevo**,
y el grupo v1 queda intacto: mismo contador, misma revisión. Ese grupo v1 sigue en estado `open`
porque nunca llegará otra alerta v1 que lo selle; en la práctica queda inactivo y su `lastSeenAt`
deja de avanzar. El reparto es aceptado y está probado en `modules/soc/test/alert-group.spec.ts`
(«despliegue del normalizador v2»).

Si molesta en la consola, se puede sellar con un job que cierre los grupos abiertos con
`lastSeenAt + ventana < ahora`. No se implementa aquí.

**Patrones aprendidos con v1:** **no existen**. La etapa D no está implementada; no hay tabla ni
código de patrones (`grep learning_patterns` no devuelve nada en migraciones ni en código), así
que no hay nada que migrar. Cuando exista, regirá el diseño §4.3: un patrón cuya huella use otra
versión del normalizador pasa a `superseded` y vuelve a validarse con dos firmas. Nunca se
convierte en silencio.

## Seguridad (adversario)

Tras el arreglo, el atacante obtiene el mismo valor normalizado de línea de comando que un script
temporal legítimo con solo elegir un nombre aleatorio. Eso es intencional: el nombre aleatorio no
describe el comportamiento. Lo que impide la colisión es el resto de la huella: hash del proceso,
destino, proceso padre, usuario y equipo. `fingerprint.spec.ts` («adversario…») lo prueba con
otro hash, otro destino y otro padre: la huella cambia en los tres casos, y solo en ese
componente.

Riesgo residual: si el proceso es `powershell.exe` (mismo hash para todos) y el atacante copia
destino, padre, usuario y equipo, la única diferencia sería el **contenido** del script, que la
huella no ve. Sería útil añadir a los observables el hash del archivo de script cuando la fuente
lo dé (Sysmon FileCreate o syscheck). Queda como recomendación para la etapa B2.

## Efecto medido

`scripts/soc-learning/measure-temp-normalization.ts`: 200 comportamientos × 20 repeticiones,
semilla fija.

| Generador | v1: huellas por comportamiento | v1: fuera de la mayoritaria | v2: huellas por comportamiento | v2: fuera de la mayoritaria |
|---|---:|---:|---:|---:|
| `GetTempFileName` (`tmpCBBF`) | 1,40 (279 grupos) | 2,0 % | **1,00** (200) | **0,0 %** |
| `GetRandomFileName` (`xkq3z1ab`) | 20,00 (4000 grupos) | 95,0 % | **5,79** (1157) | **23,9 %** (límite conocido) |
| `mktemp` (`tmp.aBcD3fGh9K`) | 20,00 (4000 grupos) | 95,0 % | **1,00** (200) | **0,0 %** |

Otras mediciones:
- **Fixtures del repo** (`fingerprint-coverage.ts`): sin cambio. Huella fina 140 de 2274 (6 %)
  y 152 huellas distintas (78 finas), igual en v1 y v2: ninguna fixture contiene rutas
  temporales.
- **Laboratorio** (`research/soc-lab`): la copia exacta se reconoce en 500 de 500 (antes 478) y
  sigue habiendo 0 variantes casi idénticas autocerradas. La prueba de propiedades pasa de 45/1000
  fallos a 0.
- **Verificación de que la regresión detecta el defecto:** con el contrato v1 restaurado
  temporalmente, la nueva prueba de `fingerprint.spec.ts` falla en 389 de 1000 pares; con v2,
  en 0.
