# 07 · Detección, ML y respuesta (B89 Respond)

> Leyenda: **[verificado]** hecho y comprobado; **[sin verificar]** existe en el repositorio pero no
> se ha probado de extremo a extremo; **[propuesto]** diseño sin código ni despliegue. La arquitectura
> serverless está en [02](02-arquitectura.md).

## Detección en tres capas

| Capa | Dónde | Qué hace | Ejemplo | Estado |
| --- | --- | --- | --- | --- |
| 1. Regla | **Wazuh** (`wazuh/office365/rules`, `wazuh/manager/rules`) | Evento → alerta con nivel y MITRE | Login sin MFA, regla de reenvío en buzón (reglas Office 365 B89) | Reglas en el repo [sin verificar en AWS] |
| 1b. Secuencia simple | **Wazuh** (`if_matched_sid`/`if_matched_group`, `same_field`, `timeframe`) | N eventos relacionados → alerta compuesta | Éxito tras fuerza bruta (M365 100505, AWS 101713, SSH 101750), rol/MFA/reenvío tras compromiso (101700–101703), CloudTrail apagado tras IAM (101710) | [verificado] en AWS con logtest; programa en [17](17-ingenieria-de-deteccion.md) |
| 2. Anomalía (ML) | **OpenSearch Anomaly Detection** (RCF, en el Indexer) | Desvío del comportamiento por entidad | Volumen de descargas de SharePoint por usuario | Detectores en el repo [sin verificar] |
| 3. Contexto e incidente | **B89 API** (`modules/detection`, TS, EC2 vigente; Lambda propuesto) | Agrupa alertas y anomalías por entidad, aplica la cadena de compromiso M365 y asigna prioridad P1–P4 con razones | Credenciales, persistencia y exfiltración del mismo usuario en 24 h → P1 | Código existente [sin verificar en Lambda] |

Regla práctica: si se puede expresar sobre un solo flujo de eventos, va en Wazuh (capas 1 y 1b). Si
necesita estado de casos, varias fuentes o explicación para el analista, va en TS (capa 3).

## ML con Anomaly Detection

Detectores versionados en `wazuh/indexer/anomaly-detection/`, aplicados por `apply-detectors.sh`
[sin verificar]:

| Detector | Entidad (`category_field`) | Feature | Intervalo |
| --- | --- | --- | --- |
| `b89-logins-per-user` | `data.dstuser` | Conteo de accesos correctos y fallidos | 5 min |
| `b89-m365-login-failures` | `data.office365.UserId` | Conteo de `UserLoginFailed` | 5 min |
| `b89-m365-file-downloads` | `data.office365.UserId` | Conteo de `FileDownloaded` y `FileSyncDownloadedFull` | 5 min |
| `b89-agent-alert-volume` | `agent.name` | Conteo de alertas con `rule.level ≥ 7` | 5 min |
| `b89-provider-aws-activity` | Flujo AWS (`data.b89.vendor=aws`) | Conteo de actividad de nivel ≥ 7 | 5 min |
| `b89-provider-bitdefender-activity` | Flujo Bitdefender (`data.b89.vendor=bitdefender`) | Conteo de eventos de nivel ≥ 8 | 5 min |
| `b89-provider-snyk-activity` | Flujo Snyk (`data.b89.vendor=snyk`) | Conteo de vulnerabilidades abiertas de nivel ≥ 7 | 5 min |
| `b89-cf-payments-errors` | `http.host` (3 hosts) | Errores de pago | 1 min |
| Otros detectores `b89-cf-*` | `client.ip` (alta cardinalidad) | Exportaciones y operaciones de pago | 5 min |
| `b89-waf-blocks-per-zone` | `data.cloudflare.zone_name` | Bloqueos y desafíos WAF | 5 min |

**Integración con B89 [desplegada en AWS; evidencia operativa inicial]:**
1. La API consulta cada 5 s el endpoint interno fijo del gateway para resultados recientes. La
   cuenta `b89_reader` solo lee `wazuh-alerts-*`, `b89-cloudflare-traffic-*` y
   `.opendistro-anomaly-results*`; el gateway no expone el Indexer públicamente ni permite elegir
   una ruta arbitraria.
2. Se aceptan resultados B89 con `anomaly_grade ≥ 0.80` y `confidence ≥ 0.90`; esto excluye la
   fase de baja confianza durante el aprendizaje inicial documentada por OpenSearch. El rango
   incluye 15 min al arrancar y 2 min de solape en cada pasada. `search_after` evita saltarse
   páginas; los resultados de la misma entidad/detector se agrupan por una ventana determinista
   de 30 min para evitar alertas repetidas mientras persiste una anomalía.
3. La normalización conserva detector, grado, confianza, entidad y features resumidas en el
   namespace `b89.opensearch-ad`. Se crea una alerta de investigación P3 con el título legible
   del catálogo. No crea un incidente ni una acción de respuesta por sí sola; la correlación B89
   puede subir su prioridad con otras señales de la entidad.
4. La alerta entra en el outbox común y se entrega a los canales B89 habilitados (Teams, correo o
   push). OpenSearch Alerting no es el canal de notificación del SOC. El antiguo script de
   monitores queda como observabilidad técnica y no es evidencia de entrega a una persona.

Detalles, diagramas, umbrales y rollback: [16 · OpenSearch ML: cobertura y entrega profesional](detection-engineering/16-opensearch-ad-alert-delivery.md).

Python queda descartado salvo que un caso medido supere a RCF (criterio de ADR-007).

**Wazuh 5 [propuesto, sujeto a GA]:** Security Analytics con reglas Sigma y correlación entre tipos
de log. B89 consumiría sus *findings* igual que los de AD.

## Ingesta: push más reconciliación

| Vía | Mecanismo | Rol | Estado |
| --- | --- | --- | --- |
| **Push** | Integracion `custom-b89` del Manager (`wazuh/manager/integrations/custom-b89.py`): firma HMAC-SHA256 y envia solo `alertId`, `managerName` y `occurredAt` a `POST /api/ingest/wazuh`; API persiste el hint en inbox PostgreSQL y el worker consulta el documento original del Indexer | Fast path durable en el API local; el emisor `integratord` sigue siendo best-effort y no reintenta | Implementacion local; faltan pruebas ejecutadas de Vitest/PostgreSQL, fixture/mapping autorizado del Indexer, sincronizacion de secreto/URL y canario. No desplegado ni medido en producción |
| **Pull** | Poller con cursor y lease con fencing sobre `wazuh-alerts-*` (`modules/soc/src/ingestion.ts`, `apps/api/src/runtime/ingestion-poller.ts`) | Reconciliacion durable e idempotente por documento | Codigo existente; corre en proceso dentro de la API |

En el camino serverless [propuesto]: el endpoint `ingest/wazuh` valida la firma y un timestamp de
no más de 5 minutos, y **encola en SQS** en vez de procesar en línea; el pull pasa a ser una
ejecución de EventBridge Scheduler cada pocos minutos ([11](11-cache-y-colas.md)). Las fuentes AWS
(CloudTrail, GuardDuty, Security Hub, WAF) entran por reglas de EventBridge hacia la misma cola y
se normalizan en `modules/telemetry`.

El endpoint no promueve el cuerpo recibido: confirma la recepción durable y el consumidor busca el
documento original en Indexer. Así conserva evidencia y reutiliza la identidad/deduplicación del pull.
Una búsqueda aún no visible se reintenta con backoff; los fallos terminales quedan registrados y el
pull con lease/cursor continúa como reconciliación. El controller valida `Content-Length` y limita
el hint canónico a 64 KiB; el parser Fastify aún tiene un máximo global de 1 MiB antes de esa
validación, por lo que queda pendiente imponer el límite de 64 KiB antes del parseo. Se valida HMAC
con ventana temporal de cinco minutos y se aplica 100 solicitudes/s por instancia. Esta
implementación no demuestra por sí sola una entrega casi instantánea: falta medir latencia real y
comprobar el mapping del Indexer y la configuración de ambos extremos. Ver [25](25-programa-confiabilidad-e-investigacion.md#punto-1--ingesta-push-durable-en-el-perfil-vigente).

## Respuesta: B89 Respond sobre Step Functions

Principio: **B89 decide y deja evidencia; otros ejecutan.** La API no guarda credenciales de
escritura de Graph ni de firewalls; esas credenciales viven en roles IAM y secretos acotados por
acción. **B89 Respond** orquesta con **Step Functions Standard** (sin Shuffle y sin servidor).
El diseño detallado está en [13](13-b89-respond.md) y [14](14-b89-respond-conexion-b89.md)
(estos dos aún describen Shuffle y se reescriben aparte).

| Pieza | Papel | Estado |
| --- | --- | --- |
| Step Functions **Standard** | Un playbook = una máquina de estados con espera de aprobación humana (`waitForTaskToken`), ejecución nombrada por el id de la solicitud (idempotencia) y auditoría de la ejecución | [propuesto] |
| Step Functions **Express** | Enriquecimiento y acciones de bajo riesgo y alto volumen (p. ej. reputación de IP), sin aprobación | [propuesto] |
| Wazuh **Active Response** | Ejecutor aprobado de acciones de endpoint (`firewall-drop`, deshabilitar cuenta) vía Wazuh API | Mecanismo nativo de Wazuh; adaptador en `modules/soar` [propuesto] |
| Lambdas de acción | Graph (`revokeSignInSessions`, deshabilitar usuario), enriquecimiento | [propuesto] |
| `modules/soar` | Notificaciones (Teams, push, correo) con outbox, lease y fencing; catálogo de acciones | Notificaciones existen [sin verificar]; catálogo de acciones **no existe** aún |

```mermaid
sequenceDiagram
  participant A as Analista
  participant API as B89 API (EC2 vigente; Lambda objetivo)
  participant SF as Step Functions (B89 Respond)
  participant L as Líder SOC
  participant W as Wazuh API (Active Response)
  participant X as Lambda de acción (Graph)
  A->>API: Solicita acción del catálogo sobre un incidente
  API->>API: audita y valida capacidad y scope
  API->>SF: StartExecution (name = id de la solicitud)
  SF->>API: tarea con token (waitForTaskToken) y aviso al aprobador
  L->>API: Aprueba (≠ solicitante, step-up)
  API->>SF: SendTaskSuccess (token)
  alt acción de endpoint
    SF->>W: PUT /active-response
  else acción M365
    SF->>X: invoca con idempotencyKey
  end
  SF->>API: resultado → timeline del incidente y auditoría
```

La aprobación es siempre humana y por una segunda persona. Un rechazo, un timeout de espera o una
falla dejan el resultado en un estado explícito (`REJECTED`, `EXPIRED`, `UNKNOWN`), sin reintento
ciego de efectos externos (ADR-028).

**Catálogo inicial [propuesto]** (`modules/soar/src/actions/`):

| Acción | Executor | Riesgo | Aprobación |
| --- | --- | --- | --- |
| `endpoint.block-ip` | Wazuh AR `firewall-drop` (con timeout) | Medio | Líder SOC |
| `endpoint.isolate-host` | Wazuh AR, script de aislamiento propio | Alto | Líder SOC con step-up |
| `m365.revoke-sessions` | Lambda → Graph `revokeSignInSessions` | Alto | Líder SOC con step-up |
| `m365.disable-user` | Lambda → Graph | Alto | Líder SOC con step-up |
| `enrich.ip-reputation` | Step Functions Express | Bajo | Ninguna (sin efectos) |

**Gates antes de la primera acción real:**
1. Fencing token en el outbox de acciones y notificaciones (P0). Hoy el outbox tiene lease con
   fencing en la ingesta; en notificaciones hay que confirmarlo.
2. Step-up (`max_age`) para aprobar. Hoy la etapa privilegiada responde `STEP_UP_REQUIRED`
   porque el login aún no lo prueba (`apps/api/src/runtime/role-administration.ts`).
3. Usuario de Wazuh API con permiso **solo** `active-response:command`, guardado en Secrets Manager.
4. Rol IAM de cada Lambda de acción limitado a su API (sin credenciales compartidas).
5. Cerrar U-008: guardas de transición, catálogo y cardinalidades.

## Esfuerzo estimado [propuesto, no medido]

| Pieza | Compatibilidad | Esfuerzo |
| --- | --- | --- |
| Anomaly Detection | Backend ya en el Indexer de Wazuh | Bajo: 3 JSON ya escritos y un lector en `modules/connectors` |
| Active Response | Nativo | Bajo: usuario de API mínimo y adaptador en `modules/soar` |
| Step Functions (B89 Respond) | Servicio gestionado | Medio: máquinas de estado, Lambdas de acción y gobernanza en B89 |
| Security Analytics y Sigma | Nativo en Wazuh 5; en 4.x hay reportes de problemas de arranque | Esperar GA; no recomendado en 4.x |
