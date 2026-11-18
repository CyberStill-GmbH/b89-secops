# 15 · Correlación: secuencias, identidad, evidencia tardía y cobertura

Estado: implementado en local en `services/b89-correlator` y en la ingesta de candidatos de la API
(2026-11-18). Sin despliegue ni medición sobre datos reales. Ninguna regla nueva está activa: la
secuencia nueva corre en modo sombra.

## Qué es un candidato

Un candidato es una agrupación propuesta para investigar. No es un incidente. El SOC acepta los
incidentes; el correlador solo propone. Cada explicación lleva `lifecycle` con ese texto y la API
lo guarda como razón `Alcance:`. Las alertas originales siguen visibles y vinculadas. El resumen
inline (`b89AlertIds`) llega como máximo a 50; el ledger guarda la membresía completa
(`GET /v1/candidates/{id}/members?kind=alerts|observations`). Así, el límite del resumen nunca
recorta el expediente ni el informe.

## Reglas temporales

`Pattern` admite etapas ordenadas, `MinStages`, `MinSources` (fuentes distintas),
`MinDistinctRules` (reglas distintas), ventana y `Mode` (`active` | `shadow`).
`B89_CORRELATOR_PATTERNS_JSON` ajusta `Window`, `MinSources`, `MinStages`, `MinDistinctRules` y
`Mode`. Un valor fuera de rango impide el arranque. `PatternVersion` es la huella de la regla
efectiva, así que cualquier ajuste cambia la versión citada.

Secuencia nueva `identity-change-new-location-endpoint`, que empieza en sombra:

1. `identity.change`: cambio de contraseña o de método MFA (operaciones de M365/Entra en lista
   cerrada; `UpdateLoginProfile`, `DeactivateMFADevice` y otras de AWS; grupo `b89_identity_change`).
2. `auth.new_location`: el motor la deriva de un acceso exitoso desde un país (o, sin
   geolocalización, una IP exacta) que no figura en la línea base de 30 días del usuario. El primer
   lugar visto nunca cuenta como «nuevo». Un país solo se compara con países y una IP solo con IPs.
3. `endpoint.activity`: usuario y equipo gestionado en el mismo evento de una fuente endpoint.
   Los inicios de sesión fallidos no cuentan.

Debe cumplirse el orden no decreciente, la ventana de 24 h, al menos 2 fuentes y 2 reglas. Cada
etapa trae `criteria`, el campo y valor que la satisfizo. La narrativa empieza con «Correlación
temporal; no demuestra causalidad ni compromiso».

## Identidad tipada

`Observation.Provenance` registra, por entidad, `field`, `method` y `confidence`:

| Método | Confianza | Ejemplo |
|---|---|---|
| `exact` | high | UPN/e-mail, ARN, IP, nombre corto de agente, instance id |
| `alias` | high | alias configurado explícitamente |
| `domain_default` | medium | `DOMINIO\usuario` completado con el dominio por defecto |
| `host_scoped` | medium | cuenta local `local:<host>/<usuario>` |
| `first_label` | medium | FQDN truncado al primer label (dos dominios pueden colisionar) |
| `host_alias` | medium | IP privada resuelta a un equipo por coocurrencia |
| `bare_name` | low | nombre suelto sin dominio |

Una secuencia solo pivota sobre confianza `medium` o mayor. Una entidad `low` suma riesgo como
contexto, pero no conecta etapas. Cuando el pivote es `medium`, la normalización aparece como
contradicción. Las coincidencias de texto, sufijo o prefijo nunca fusionan identidades: hay
pruebas con UPN casi iguales y con sufijos de dominio.

## Tiempo y evidencia tardía

- `Observation.Time` es la hora del proveedor (`data.b89.event_time`, `CreationTime` de O365,
  `eventTime` de AWS, `systemTime` de Windows) cuando es plausible: no más de 5 min por delante de
  la ingesta ni más de 7 días por detrás. Si no lo es, se usa la hora de ingesta, y la explicación
  lo declara como dato faltante. `IngestedAt` conserva la hora en que Wazuh registró el evento.
- El watermark propio del correlador sigue en disco. El watermark del proveedor
  (`cursor_position` del latido del colector) se expone por fuente como `providerWatermark`.
- Ante evidencia tardía, el motor evalúa el patrón en la hora del evento y en cada etapa posterior
  dentro de la ventana. Si el episodio ya tiene un candidato, ese candidato se actualiza: sube
  `revision`, la evidencia nueva va a `additionalStageEvidence` y al ledger, y no se abre otro.
  Si un candidato parcial se completa, se abre un candidato completo aparte (otra prioridad y otra
  clave de idempotencia).
- Las pruebas cubren tres órdenes invertidos o mezclados (mismo ID y mismas etapas), replay y
  solapamiento (deduplicación por ID) y reinicio sobre el mismo ledger (mismos IDs, sin miembros
  duplicados).
- Límite: una alerta B89 ya emitida no se reescribe con revisiones posteriores. El expediente debe
  leer `GET /v1/candidates/{id}` y el ledger.

## Explicación para el analista

`Explanation` agrega `checks` (umbral requerido y observado, cumplido o no), `contradictions`
(veredictos benignos o FP de alertas vinculadas, sesiones distintas del proveedor, pivote
normalizado, una sola fuente), `missingData` (etapas no observadas, hora de ingesta usada,
ubicación por IP, cobertura incompleta), `provenance` y `lifecycle`. La API los guarda como razones
(`Regla:`, `Umbral …`, `Contradicción:`, `Dato faltante:`, `Alcance:`) dentro de límites:
8 umbrales y 6 líneas de 300 caracteres. Así, el informe cita la misma validación.

## Operación observable

`/readyz` (`observedSources`) y `/metrics` exponen, por fuente: lecturas, procesados, duplicados,
eventos tardíos (≥ 5 min entre evento e ingesta), retraso máximo de ingesta, latido del colector,
retraso del proveedor, watermark del proveedor y `coverage`:

- `complete`: el latido es reciente (< 1 h), `outcome=ok` y el retraso del proveedor es ≤ 15 min.
- `incomplete`: el colector falló, su latido está viejo o va atrasado, o el propio correlador está
  en backfill, con lectura fallida o poniéndose al día. Esto último afecta a todas las fuentes.
- `unknown`: no llegó ningún latido. **No significa «sin actividad».**

`coverageComplete` solo es `true` si todas las fuentes están en `complete`. Las brechas de
cobertura se escriben en `missingData` al abrir el candidato y otra vez al emitirlo. Contadores
globales: candidatos abiertos, actualizados y en sombra, eventos fuera de orden, latidos,
documentos de la ventana pendiente y páginas.

Regla de latidos: antes no había ninguna regla para `source_heartbeat`. El evento quedaba en nivel 0
bajo la raíz de cada proveedor y nunca llegaba a `wazuh-alerts`. Ahora existe
`detections/platform/collector-heartbeat` (ids 101980–101981, nivel 3, sin notificación):

- 101980 es hija de cualquier raíz `b89_provider` (Cloudflare, Bitdefender, Snyk, AWS, M365).
- 101981 es raíz para los latidos que no tienen regla de proveedor (SharePoint).

Ambas alcanzan el nivel mínimo predeterminado del correlador (`B89_CORRELATOR_MIN_LEVEL=3`).
El release del host AWS instala `etc/rules/b89_soc_collector_heartbeat.xml` mediante
`infra/aws-poweruser/scripts/setup-wazuh-content.sh`, junto con las reglas de Office 365 y de
proveedores que definen el grupo `b89_provider`. El instalador ejecuta `wazuh-analysisd -t`
antes de reiniciar el manager. Las cuatro muestras sintéticas pasaron en Wazuh 4.14.8.
La comprobación en el entorno desplegado queda pendiente hasta observar un latido real en
`wazuh-alerts` y el estado de su fuente en `/readyz`.

## Superficies de consola y API

- `GET /api/operations/health` → `soc.correlator.coverage` `{ complete, sources[] }` (estado, motivo
  de una allowlist, atraso del proveedor y edad del último evento; sin watermark ni texto libre).
  Solo una fuente `incomplete` agrega `CORRELATOR_COVERAGE_INCOMPLETE` a `degradedReasons`. Una
  fuente `unknown` se muestra, pero no degrada. El estado `catching_up` del correlador ahora se
  acepta; antes la API lo mostraba como «correlador inaccesible».
- Consola, Operaciones → «Cobertura de fuentes»: `incomplete` y `unknown` se rotulan
  «Cobertura incompleta», con el motivo por fuente. Nunca se muestran como «sin actividad».
- `GET /api/risk/entities/:type/:ref` separa `candidates` (activos) de `shadowCandidates` (reglas en
  evaluación). Cada candidato agrega `mode`, `revision`, `updatedAt` y `linkedAlertCount`. La
  explicación agrega `checks`, `contradictions`, `missingData`, `additionalStageEvidence` y
  `lifecycle`. `provenance` no se proyecta porque contiene claves internas. Cuando hay candidatos en
  sombra, la herramienta de Bunny agrega `shadowNote` para que el modelo no los presente como
  hallazgos.
- Vista de alerta, investigación y bandeja: las razones se agrupan en «Motivos de la prioridad»,
  «Secuencia observada», «Umbrales de la regla» (cumplido o no), «Contradicciones», «Datos
  faltantes», «Evidencia citada» y «Siguientes pasos». El «Alcance» se muestra como aviso
  «Candidato del correlador». Además se corrigieron las claves React duplicadas (`key={reason.code}`).

## Tuning medido

`evaluate-corpus` (esquema `b89-correlator-eval/v1`) acepta ahora `source` y `candidateDuplicate`
opcionales por ejemplo. El informe agrega `bySource`, `byBaselinePriority` y `candidateDuplicates`.
Los duplicados se cuentan aparte y no como falsos positivos. Los cortes son descriptivos: no tienen
prueba de significancia propia. Para activar una regla en sombra hace falta:

1. Exportar sus candidatos `status=shadow` (`GET /v1/candidates?status=shadow`) con ventanas
   adjudicadas por analistas.
2. Correr `evaluate-corpus` contra la línea base. La regla exige `sufficientEvidence`,
   `guardrailsPassed`, que no haya regresión de P1 ni de TP conocidos y que la precisión por fuente
   y prioridad sea aceptable.
3. Activarla con `{"ID":"…","Mode":"active"}` y registrar el `PatternVersion` resultante.

Que haya menos grupos no prueba, por sí solo, que haya menos falsos positivos.
