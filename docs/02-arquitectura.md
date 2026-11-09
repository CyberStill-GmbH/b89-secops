# 02 · Arquitectura

> Estado (2026-11-08): describe el despliegue **vigente** en AWS, modo PowerUser
> ([`infra/aws-poweruser`](../infra/aws-poweruser/README.md)). Cada afirmación se contrastó con el
> código del repositorio; lo que no se pudo comprobar se marca **por verificar**. El diseño
> serverless (Lambda, Cognito, Step Functions) es el **diseño objetivo** y no está desplegado: ver
> [Diseño objetivo](#diseño-objetivo-no-desplegado).

## En una frase

**B89 SOC corre en un solo nodo EC2 con Docker**: Wazuh 4.14.8 (manager, indexer y dashboard con
marca B89), el motor B89 (API TypeScript + PostgreSQL), B89 Respond (SOAR) y un edge nginx que
impone la sesión B89 en todo. Delante hay un ALB con WAF. No se usa ningún recurso IAM: la cuenta
solo concede el permission set `SOC-PowerUser`, que no puede crear roles ni hacer `iam:PassRole`.

## Despliegue AWS y flujos de datos

```mermaid
flowchart LR
  subgraph Fuentes
    AG[Agentes Wazuh<br/>endpoints y servidores]
    M365[Microsoft 365<br/>módulo office365]
    BD[Bitdefender GravityZone]
    SN[Snyk]
    CF[Cloudflare]
    CT[CloudTrail<br/>trail de la cuenta]
  end
  subgraph AWS["AWS 061098277310 · us-east-1"]
    EB[EventBridge<br/>us-east-1 + 16 centinelas]
    SNS[SNS cifrado KMS<br/>17 temas]
    R53[Route 53<br/>dev.security.b89.io<br/>agents.dev.security.b89.io]
    ALB[ALB + WAFv2<br/>ACM TLS 1.3/1.2]
    S3[(S3: evidencia,<br/>logs ALB, CloudTrail)]
    subgraph EC2["EC2 r7i.xlarge · Ubuntu 24.04 · EBS gp3 cifrado (KMS)"]
      EDGE[edge nginx<br/>auth_request]
      AWSR[aws-events<br/>receptor SNS]
      COL[Collectors systemd<br/>Bitdefender · Snyk · Cloudflare]
      MGR[Wazuh manager<br/>reglas B89]
      IDX[(Wazuh indexer<br/>wazuh-alerts-*)]
      DSB[Wazuh dashboard<br/>b89_ops + b89_i18n]
      GW[wazuh-gateway<br/>token estático]
      API[Motor B89 API]
      PG[(PostgreSQL 18<br/>TLS)]
      RESP[B89 Respond<br/>+ puente SSO]
      MAIL[b89-alert-mail]
    end
  end
  ANTH[API de Anthropic<br/>Claude]
  GRAPH[Microsoft Graph<br/>sendMail]
  U((Analista)) -->|HTTPS| R53 --> ALB --> EDGE
  AG -->|TCP 1514/1515| MGR
  M365 -.->|bloqueado: falta ActivityFeed.Read| MGR
  BD & SN & CF --> COL -->|JSONL| MGR
  CT --> EB --> SNS -->|HTTPS /hooks/aws-sns| ALB
  CT --> S3
  EDGE -->|/hooks/aws-sns| AWSR -->|JSONL| MGR
  MGR -->|filebeat| IDX
  DSB --> IDX
  EDGE -->|/ con x-proxy-user| DSB
  EDGE -->|/api| API
  EDGE -->|/b89-respond| RESP
  API -->|cada 60 s| GW -->|b89_reader, solo lectura| IDX
  API --> PG
  API -->|Bunny| ANTH
  MGR -.->|alertas nivel ≥ 8| MAIL -.->|bloqueado: falta Mail.Send| GRAPH
```

Flujo de una alerta: la fuente llega al **manager**, que aplica el ruleset oficial más las reglas
B89 y escribe la alerta en `wazuh-alerts-*`. El **motor B89** la lee cada 60 s por el gateway de
solo lectura, la normaliza al contrato `SecurityEvent`, la promueve a la **cola de alertas** y la
persona la agrupa en **incidentes**; cada mutación queda en la **cadena de auditoría**. La persona
trabaja en el dashboard (vistas `b89_ops`), puede preguntar a **Bunny**, abrir **B89 Respond** y,
cuando se conceda el permiso, recibir el **correo** de alertas de nivel ≥ 8.

## Recursos AWS (Terraform `infra/aws-poweruser`)

| Recurso | Detalle | Archivo |
| --- | --- | --- |
| Red | VPC `10.89.0.0/24`, dos subredes públicas (dos AZ, exigidas por el ALB), IGW; SG por defecto cerrado | `main.tf`, `public.tf` |
| Nodo | EC2 `r7i.xlarge` (x86_64: las imágenes del API están fijadas a amd64), Ubuntu 24.04, IMDSv2 obligatorio, **sin perfil de instancia**, gp3 100 GB cifrado con CMK, EIP | `main.tf`, `templates/cloud-init.sh` |
| SG del nodo | 443 solo desde el ALB; 22 desde `allowed_admin_cidrs`; TCP 1514–1515 desde `agent_cidrs` (hoy `0.0.0.0/0`, aprobado por el dueño el 2026-11-03) | `main.tf`, `environments/dev.tfvars` |
| Borde | ALB público con ACM (`ELBSecurityPolicy-TLS13-1-2-2021-06`), HTTP→HTTPS, access logs a S3 (90 días); WAFv2 con IpReputation, KnownBadInputs, CommonRuleSet y límite de 2000 peticiones/5 min por IP | `public.tf` |
| DNS | `dev.security.b89.io` alias al ALB; `agents.dev.security.b89.io` registro A a la EIP (los agentes no pasan por el ALB) | `main.tf` |
| Cifrado | CMK `alias/b89-soc-dev-data` (EBS y S3 de evidencia) y CMK del tema SNS, ambas con rotación | `main.tf`, `aws-monitoring.tf` |
| Evidencia | Bucket S3 con KMS, versionado, TLS obligatorio, sin acceso público, `force_destroy = false` | `main.tf` |
| Monitoreo de la cuenta | Trail de la cuenta (solo escritura de management events, multirregión, S3 SSE-S3 con expiración a 90 días); EventBridge → SNS → webhook en 17 regiones | `aws-trail.tf`, `aws-monitoring.tf`, `modules/aws-events-sentinel` |
| Presupuesto | AWS Budget mensual por etiqueta `project=b89` | `main.tf` |
| Estado | S3 `b89-tfstate-061098277310-us-east-1`, clave `aws-poweruser/dev/terraform.tfstate`, lock nativo | `backend.hcl` |

El trail de la organización vive en la cuenta de administración (258231095330) y no entrega a
EventBridge de esta cuenta; por eso existe el trail propio (`598294a`). Desde entonces llegan
eventos reales a Wazuh (p. ej. la regla 101616, cambio del pipeline).

## Contenedores del nodo (`infra/aws-poweruser/host`)

Proyecto Compose `b89`, red `172.30.89.0/24`. Base: `wazuh-docker` v4.14.8 (single-node) clonado en
`/opt/b89/wazuh-docker`, con los overrides B89.

| Servicio | Imagen | Función | Expuesto |
| --- | --- | --- | --- |
| `wazuh.manager` | `wazuh/wazuh-manager:4.14.8` | Agentes, reglas, módulos (office365, vulnerabilidades, SCA) | 1514/1515 públicos; API 55000 solo loopback |
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.14.8` (heap 3 GB) | Almacena alertas, estados e inventario | 9200 solo loopback |
| `wazuh.dashboard` | `b89/wazuh-dashboard:4.14.8` (overlay B89) | UI; IP fija `172.30.89.10`, la única en la que el indexer confía para proxy auth | No |
| `edge` | `nginx:1.29.3` (IP fija `172.30.89.11`) | TLS (Let's Encrypt), `auth_request` a la API, rutas `/`, `/api`, `/b89-respond`, `/hooks/aws-sns` | 80/443 (443 solo desde el ALB) |
| `api` | `b89/api:local` | Motor B89: sesión, alertas, incidentes, auditoría, avisos, Bunny | No |
| `postgres` | `postgres:18.6` | Estado del motor, TLS con CA interna | No |
| `wazuh-gateway` | `nginx:1.29.3` | Valida el token estático e inyecta la credencial `b89_reader` hacia el indexer | No |
| `aws-events` | `node:24.21.0` (solo lectura, sin capacidades, 128 MB) | Verifica firma SNS v2, deduplica y escribe JSONL para el manager | No |
| B89 Respond | `shuffle-backend`, `shuffle-orborus`, `shuffle-opensearch`, `b89-respond-frontend`, `b89-respond-sso` | SOAR embebido y puente SSO | No (`compose.respond.yaml`) |

Fuera de Docker, en el host: el agente Wazuh del propio nodo (`001 b89-soc-dev-node`, grupo
`linux-pilot`), los collectors y el notificador de correo como timers systemd
([18](18-integraciones.md)).

## Identidad y sesión

Un solo login: el de B89 (`/b89/login`, plugin `b89_ops`). El edge consulta
`/api/auth/introspect` en cada petición (caché ≤ 5 s) y fija `x-proxy-user`/`x-proxy-roles` hacia el
dashboard; el indexer solo acepta esas cabeceras desde `172.30.89.10`. El formulario del Security
plugin no es accesible. El despliegue usa la **identidad fija de demo** (sin Entra real) con cuentas
de contraseña por rol. Detalle en [04](04-identidad-y-acceso.md).

## Motor B89 (`apps/api`)

- **Ingesta:** `B89_INGESTION_SOURCE=wazuh`, modo `static-token`, intervalo 60 s, ventana inicial de
  60 min. El cursor se corrigió en `833c088` para no quedarse atascado; las alertas de proveedores
  entran como alertas de primera clase.
- **Alertas → incidentes → auditoría:** la API promueve alertas a la cola, el analista las clasifica
  y las agrupa en incidentes; cada cambio se escribe con su evento de auditoría en la misma
  transacción, en una **cadena SHA-256** append-only (un trigger bloquea UPDATE/DELETE), verificable
  desde «Auditoría e integridad».
- **Roles y capacidades:** cuatro roles runtime (`b89.soc.analyst`, `b89.soc.lead`, `b89.auditor`,
  `b89.platform.admin`) con denegación por defecto (`modules/access/src/capabilities.ts`).
- **Bunny:** Claude por la API directa de Anthropic ([15](15-bunny-asistente.md)).

## Qué no hay en este modo (y por qué)

Todo lo que necesita una identidad IAM en el host o un rol de servicio: Secrets Manager/SSM,
Lambda, Step Functions, Scheduler, Session Manager, DLM (snapshots automáticos), Flow Logs,
CloudWatch Logs del trail, el módulo AWS de Wazuh y Bedrock. Consecuencias y mitigaciones en
[21 · Postura de seguridad](21-postura-de-seguridad.md); brechas abiertas en
[19](19-brechas-y-roadmap.md).

## Diseño objetivo (no desplegado)

Si un administrador de la cuenta crea los roles y concede `iam:PassRole` acotado a `b89-*`, el
destino es el diseño serverless de [`infra/aws-serverless`](../infra/aws-serverless/README.md):
CloudFront + WAF, Cognito federado con Entra, API Gateway HTTP + Lambda, Step Functions para B89
Respond, SQS/EventBridge y Aurora Serverless v2, con Wazuh como único nodo con servidor. Ese
Terraform pasó `fmt`/`validate` pero **no tiene plan ni apply**. Documentos de ese diseño:
[cloud/aws/architecture.md](cloud/aws/architecture.md), [09](09-plan-de-lanzamiento.md),
[11](11-cache-y-colas.md), [12](12-backend-en-el-siem.md) y [13](13-b89-respond.md) §2–4.

## Principios que se conservan

1. **Monolito modular hexagonal** (`modules/*` sin frameworks; lo valida `pnpm boundaries`).
2. **Contrato canónico `SecurityEvent` 1.0.0** (`packages/contracts`).
3. **Mutación, auditoría y outbox en una transacción.**
4. **Denegación por defecto** y negaciones auditadas.
5. **Sin acciones automáticas:** Active Response de Wazuh apagada; toda acción con efectos pasa por
   B89 Respond con aprobación del Líder SOC.
6. **Secretos fuera de Git, del estado de Terraform y del user_data:** se generan en el host, en
   `/opt/b89/secrets` (0700, archivos 0600).

## Cómo se modifica el sistema

| Quiero… | Lo hago en… |
| --- | --- |
| Una detección nueva | `detections/`, según [17](17-ingenieria-de-deteccion.md) |
| Una fuente nueva por API | Un collector en `wazuh/provider-ingestion` y su rango en `detections/catalog.yaml` |
| Una vista o un texto de la consola | `wazuh/dashboard/plugins/b89_ops` (español en `b89_i18n`) |
| Una política de agente o del manager | `wazuh/manager/policy` ([16](16-politicas.md)) |
| Retención | `wazuh/indexer/ism` |
| Infraestructura | `infra/aws-poweruser` (plan revisado antes de cada apply) |
