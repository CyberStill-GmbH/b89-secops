# 10 · Decisiones vigentes

Este registro único reemplaza ADR-001…027 y U-001…U-021. Los textos originales siguen en git
(`git show 050f9fa:docs/adr/`). Para cambiar una decisión se edita la fila y se agrega la fecha;
no se crean archivos nuevos.

Estados: **Vigente**, **Gate** (decidida, pero falta evidencia antes de producción) y
**Abierta**.

## Decisiones B89 (fork serverless, 2026-11-02)

Estas decisiones definen B89 SOC frente a la base heredada. Detalle en
[02](02-arquitectura.md).

| ID | Decisión | Estado |
| --- | --- | --- |
| B1 | **Serverless por defecto en AWS.** La API, el SOAR, las colas y el estado corren en Lambda, Step Functions, SQS, EventBridge y Aurora Serverless v2. La única excepción es el núcleo Wazuh | Vigente, implementación propuesta |
| B2 | **B89 Respond = Step Functions** con aprobación humana (`waitForTaskToken`). Se retira Shuffle | Vigente, implementación propuesta |
| B3 | La API lee el Indexer por la ruta privada de VPC; se retira KrakenD | Propuesta |
| B4 | SQS + EventBridge Scheduler reemplazan BullMQ y el worker persistente | Propuesta |
| B5 | Wazuh Manager + Indexer + Dashboard en **un nodo EC2 Graviton** (ASG `min=max=1`), sin NAT, con snapshots EBS y de Indexer a S3. No se usa OpenSearch Serverless porque Wazuh no es compatible | Vigente, implementación propuesta |
| B6 | Auditoría y evidencia en S3 Object Lock (compliance) replicadas a una cuenta de archivo de logs separada | Propuesta |
| B7 | Tres cuentas AWS (`b89-soc-workload`, `b89-log-archive`, `b89-security-tooling`) | Propuesta |
| B8 | B89 opera **solo en AWS**. El perfil Azure queda archivado en [`archive/azure`](archive/azure/README.md) | Vigente |
| B9 | Marcas: **B89 SOC** (producto), **B89 Respond** (respuesta), **B89 Cases** (casos). Dominio y logo definitivos pendientes de B89 | Vigente |
| B10 | **Bunny**, el asistente de IA integrado (Claude por Bedrock o API de Anthropic), de **solo lectura** y con los permisos de la persona; datos personales seudonimizados; apagado por defecto. Detalle en [15](15-bunny-asistente.md). El proveedor `anthropic` directo exige dictamen de Legal (N1/N2) | Vigente, sin probar contra el proveedor real |

## Negocio (detalle en [01](01-producto.md#decisiones-de-negocio-que-se-conservan))

| ID | Decisión | Estado | Origen |
| --- | --- | --- | --- |
| N1 | Operación autogestionada: sin SaaS de logs ni de observabilidad (SBS 504-2021, arts. 22–25) | Gate: dictamen de Legal | compliance SBS |
| N2 | Minimización de datos personales (Ley 29733) | Vigente | ADR-018/022 |
| N3 | Wazuh detecta y B89 coordina. No hay un segundo SIEM | Vigente | ADR-015/024 |
| N4 | Primera vertical M365 → Wazuh → B89 → Teams | Vigente | ADR-024 |
| N5 | SoD: nadie aprueba lo que pidió, sin `ADMIN` universal | Vigente | ADR-017 |
| N6 | Teams solo avisa. El acuse vive en B89 | Vigente | ADR-022 |
| N7 | Sin purga automática hasta que Legal ratifique la retención | Gate | ADR-018 |
| N8 | No publicar SLO, EPS ni KPIs sin medición | Vigente | ADR-016 |
| N9 | Una sola sesión activa por persona. Un login nuevo reemplaza la sesión anterior en la consola y en el dashboard | Vigente (falta hacerla atómica) | ADR-017 |
| N11 | **Auditable para ISO 27001 y ciberseguridad SBS.** Se conserva toda la evidencia (RDS, S3, auditoría con cadena hash y snapshots) y el diseño se ajustará a sus controles | Vigente (próximo scope) | 2026-10-14 (dueño) |
| N10 | Un cambio aprobado de rol o una baja de acceso revoca las sesiones y exige nuevo login | Gate: flujo de roles todavía no desplegado; grant y revocación viven en stores distintos; verificar `remaining = 0` y corte en el Dashboard antes de producción | ADR-017, 2026-10-13 |
| N12 | PCI-DSS solo si B89 procesa datos de tarjeta: enmascarar PAN antes de indexar y retener logs 12 meses (3 en línea). Detalle en [01](01-producto.md) | Gate: confirmar con B89 | 2026-11-02 |
| N13 | **Excepción temporal solo para la demo:** una cuenta administrativa sintética (`b89.platform.admin`, `amr: ['pwd']`) entra con usuario y contraseña (hash scrypt), sesión servidor-side en cookie `HttpOnly; Secure; SameSite=Strict` y JWT RS256 validado por el mismo pipeline. Apagada por defecto, vence como máximo a 30 días del arranque y la sesión dura ≤ 8 h. Detalle y modelo de amenaza en [04](04-identidad-y-acceso.md#excepción-demo-contraseña-del-administrador) | Gate: **debe retirarse antes de producción** (código y variables `B89_DEMO_ADMIN_*`). Dueño: dueño del producto (cguevara). Fecha límite: el `B89_DEMO_ADMIN_LOGIN_UNTIL` de la demo, nunca después de 2026-12-03 | 2026-11-03 (dueño) |

## Arquitectura

| ID | Decisión | Estado | Fecha |
| --- | --- | --- | --- |
| A1 | Monolito modular hexagonal en TS (NestJS 12/Fastify 5, Prisma 7, Postgres 18). Los módulos no importan frameworks | Vigente | 2026-09 (ADR-001/003/016) |
| A2 | Contrato canónico `SecurityEvent` 1.0.0 | Vigente | ADR-011 |
| A3 | Mutación, auditoría y outbox en una transacción. Auditoría append-only con cadena hash | Vigente | ADR-012/021 |
| A4 | Secretos solo por `secretRef` y control plane write-only | Vigente | ADR-013/027 |
| A5 | **Sin fork del manager ni del Indexer de Wazuh.** El overlay B89 se versiona en `wazuh/` sobre la versión oficial fijada | Vigente | 2026-10-13 |
| A6 | **B89 SecOps ES Wazuh con identidad B89.** La UI de Wazuh 4.14.8 (OSD 2.19.6) se rebrandea de principio a fin como overlay versionado en `wazuh/dashboard/` (parches mínimos, assets B89, plugins separados `b89_ops` y `b89_i18n`). **`apps/web` se descarta** | Vigente | 2026-10-13 (dueño) |
| A7 | **El login TS de B89 es la identidad del dashboard** (nginx `auth_request` más proxy auth). OIDC nativo de OSD queda solo como fallback | Vigente | 2026-10-13 |
| A8 | ~~KrakenD se mantiene mientras lo use la ingesta~~ **Sustituida por B3.** La API lee el Indexer por la ruta privada de VPC y `platform/gateway` se retira cuando esa ruta tenga paridad | Sustituida (B3) | 2026-10-13, revisada para B89 |
| A9 | Valkey como pieza de resiliencia: caché con lazy loading e invalidación explícita y estado efímero compartido. **Para B89 las colas BullMQ pasan a SQS (B4)**; Valkey queda opcional como ElastiCache Serverless o DynamoDB TTL. Postgres sigue siendo la verdad. Diseño en [11](11-cache-y-colas.md) | Vigente, ajustada por B4 | 2026-10-14 |
| A10 | **Retirar Grafana, Loki y Prometheus.** CloudWatch para métricas de infraestructura. Logs de API y ALB a Wazuh (cumple N1) | Vigente | 2026-10-13 (sustituye ADR-025 en lo de observabilidad) |
| A11 | Retención hot/warm/cold con ISM y snapshots a S3 (no Azure) | Vigente (gate N7 para el borrado) | 2026-10-13 (sustituye ADR-008/018 en el mecanismo) |
| A12 | ML con OpenSearch Anomaly Detection. Python solo si un caso medido supera a RCF | Vigente | 2026-10-13 (sustituye ADR-007) |
| A13 | **El SOAR propio de B89 no se construye como producto aparte; B89 Respond es la capa de respuesta gobernada.** Heredado: Shuffle rebrandeado. **Vigente para B89 (B2): se implementa sobre Step Functions** y **B89 Core gobierna** catálogo/versiones, capacidades, SoD, aprobaciones, idempotencia, auditoría y estado. Ningún analista invoca la ejecución directamente. | Vigente; implementación Step Functions propuesta | 2026-10-13 (base original), B89 2026-11-02 |
| A14 | Ingesta push (`custom-b89`) más pull de reconciliación | Vigente (fase 2) | 2026-10-13 |
| A15 | Fuentes nuevas por módulos de Wazuh, no por adaptadores TS | Vigente | 2026-10-13 |
| A16 | Lanzamiento sobre **Wazuh 4.14.8** (lo que corre en AWS). La imagen anterior queda como histórico: AMI `ami-0123456789abcdef0` (`b89-secops-wazuh-historico-4.14.8-20261013`). Wazuh 5 llega como cluster nuevo cuando haya GA | Vigente | 2026-10-13 (dueño) |
| A22 | ~~El backend vive dentro del SIEM (opción B)~~ **Sustituida por B1/B5.** El backend B89 corre en Lambda, no en el host del SIEM ni en ECS | Sustituida | 2026-10-14, revisada para B89 |
| A17 | CI, candidato, publicación y despliegue separados. Imágenes inmutables `git-<sha>` | Vigente | ADR-023 |
| A18 | **Sin capas de complejidad nuevas.** Se reutiliza lo que hay: host Wazuh como edge, API y Postgres actuales y long-poll; nada de SSE, colas nuevas ni servicios extra para el lanzamiento | Vigente | 2026-10-13 (dueño) |
| A19 | **UI en español** con el plugin `b89_i18n`: glosario curado más la API Translator on-device de Chrome. **Nunca** se usa un servicio de traducción externo (N1/N2) | Vigente | 2026-10-13 |
| A20 | **No se rotan secretos** al desplegar: los scripts reutilizan las credenciales publicadas (`B89_ROTATE` sigue en false) | Vigente | 2026-10-13 (dueño) |
| A21 | Apply en AWS: el pipeline oficial es el workflow `terraform-demo`. Desde Windows solo se permite `-target` revisado, porque los CRLF y `dirname()` con `\` generan diffs falsos (reemplazo de la EC2 de Wazuh y rutas rotas en SSM) | Vigente | 2026-10-13 |

## Abiertas

| ID | Pregunta | Owner | Cierra cuando |
| --- | --- | --- | --- |
| U-008 | Guardas de transición, catálogo SOAR y cardinalidades alerta–incidente | SOC/Security | Catálogo de [07](07-deteccion-ml-y-soar.md) aprobado con tests de transición |
| U-004 | Matriz de retención firmada | Legal/Compliance | Firma más pruebas de purga |
| U-017 | KPIs de negocio del MVP | Product Owner | Fórmula, fuente y owner aprobados |
| U-018 | CIDR de la red confiable, proxies y claims de passkey | Identity/Infra | E2E dentro, fuera y por proxy |
| U-022 | Resuelta por B2: B89 Respond usa Step Functions, sin Shuffle (AGPL) ni StackStorm. Queda abierto solo el retiro del código heredado de Shuffle | Platform | Se elimina `b89-respond/` heredado |
| U-023 | ¿Migración de datos 4.x → 5.x por snapshot? (las RC se contradicen) | Platform | Prueba en sandbox |

## Decisiones de Codex integradas (PR #31, 2026-10-13)

Texto completo en `reference/decisiones/` y `reference/`. Se reconcilian con las instrucciones del dueño
posteriores al PR:

| ID | Decisión | Estado frente a la dirección vigente |
| --- | --- | --- |
| ADR-028 | Shuffle como SOAR no-code por webhook, con B89 como dueño del catálogo, las aprobaciones, la idempotencia y la auditoría | **Vigente.** El producto se llama **B89 Respond** (A13) y es el siguiente scope |
| ADR-029 | B89 SecOps como plataforma SIEM/XDR; **B89 Cases** como espacio colaborativo de investigación (inspirado en TheHive) | **Vigente**, salvo la consola: el dueño decidió que la UI es la de Wazuh rebrandeada (A6), no una consola propia. B89 Cases vive en las vistas de incidentes del plugin `b89_ops` |
| ADR-030 | Arquitectura resiliente objetivo: LB de entrada, réplicas sin estado, KrakenD interno, scheduler y pollers con leases, Redis/BullMQ para jobs pequeños, admisión durable y tiers HOT/WARM/COLD (`reference/b89-secops-resilient-architecture.md`) | **Objetivo vigente por etapas.** Valkey y el worker vuelven en esta actualización con el rol definido en [11](11-cache-y-colas.md) (A9) |
