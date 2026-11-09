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
| 3. Contexto e incidente | **B89 API** (`modules/detection`, TS, en Lambda) | Agrupa alertas y anomalías por entidad, aplica la cadena de compromiso M365 y asigna prioridad P1–P4 con razones | Credenciales, persistencia y exfiltración del mismo usuario en 24 h → P1 | Código existente [sin verificar en Lambda] |

Regla práctica: si se puede expresar sobre un solo flujo de eventos, va en Wazuh (capas 1 y 1b). Si
necesita estado de casos, varias fuentes o explicación para el analista, va en TS (capa 3).

## ML con Anomaly Detection

Detectores versionados en `wazuh/indexer/anomaly-detection/`, aplicados por `apply-detectors.sh`
[sin verificar]:

| Detector | Entidad (`category_field`) | Feature | Intervalo |
| --- | --- | --- | --- |
| `b89-m365-login-failures` | `data.office365.UserId` | Conteo de `UserLoginFailed` | 10 min |
| `b89-m365-file-downloads` | `data.office365.UserId` | Conteo de `FileDownloaded` y `FileSyncDownloadedFull` | 15 min |
| `b89-agent-alert-volume` | `agent.name` | Conteo de alertas con `rule.level ≥ 7` | 10 min |

**Integración con B89 [propuesto]:**
1. `modules/connectors` lee `.opendistro-anomaly-results*` con `anomaly_grade ≥ 0.7`, con la misma
   credencial de solo lectura ampliada a ese índice. El lector corre en una Lambda dentro de la VPC
   (ruta privada al Indexer).
2. `modules/telemetry` lo normaliza a `SecurityEvent` con `kind: anomaly`, conservando detector,
   grado, confianza y entidad.
3. `modules/detection` lo trata como una señal más. Una anomalía sola no crea un incidente: sube la
   prioridad de un grupo de alertas de la misma entidad con la razón `ANOMALY_CORROBORATED`.

Python queda descartado salvo que un caso medido supere a RCF (criterio de ADR-007).

**Wazuh 5 [propuesto, sujeto a GA]:** Security Analytics con reglas Sigma y correlación entre tipos
de log. B89 consumiría sus *findings* igual que los de AD.

## Ingesta: push más reconciliación

| Vía | Mecanismo | Rol | Estado |
| --- | --- | --- | --- |
| **Push** | Integración `custom-b89` del Manager (`wazuh/manager/integrations/custom-b89.py`): firma HMAC-SHA256 y envía por alerta de nivel ≥ 7 a `POST /api/ingest/wazuh` | Latencia baja, best-effort (integratord no reintenta) | Script y plantilla en el repo [sin verificar]. El endpoint **no existe aún** en `apps/api` |
| **Pull** | Poller con cursor y lease con fencing sobre `wazuh-alerts-*` (`modules/soc/src/ingestion.ts`, `apps/api/src/runtime/ingestion-poller.ts`) | Reconciliación: no se pierde nada. Deduplica por `_id` | Código existente; hoy corre en proceso dentro de la API [sin verificar] |

En el camino serverless [propuesto]: el endpoint `ingest/wazuh` valida la firma y un timestamp de
no más de 5 minutos, y **encola en SQS** en vez de procesar en línea; el pull pasa a ser una
ejecución de EventBridge Scheduler cada pocos minutos ([11](11-cache-y-colas.md)). Las fuentes AWS
(CloudTrail, GuardDuty, Security Hub, WAF) entran por reglas de EventBridge hacia la misma cola y
se normalizan en `modules/telemetry`.

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
  participant API as B89 API (Lambda)
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
