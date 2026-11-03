# AWS serverless: topología, costos y gates

> Estado: **propuesto**. Lo que hoy existe en `infra/aws/` es el Terraform heredado de la demo
> (EC2 de Wazuh, ECS, RDS, ElastiCache y S3). Este documento define el destino y el orden de
> migración. Las cifras de costo son **estimaciones de orden de magnitud**, no mediciones: hay que
> validarlas con AWS Pricing Calculator y la factura real antes de comprometer presupuesto.

La arquitectura lógica está en [02](../../02-arquitectura.md). Aquí se justifica cada servicio por
robustez, estabilidad y costo.

## Mapa de servicios

| Capa | Servicio | Por qué este y no otro |
| --- | --- | --- |
| Borde | CloudFront + AWS WAF | Un solo origen para `/` y `/api`; reglas gestionadas, límite de tasa y geobloqueo sin servidores |
| Identidad | Cognito + federación OIDC con Entra | MFA y revocación sin operar un IdP; el dominio ya existe en `modules/access` |
| API | API Gateway **HTTP API** + Lambda arm64 | HTTP API cuesta una fracción de REST API y cubre JWT authorizer. Lambda arm64 es más barato por ms |
| Colas | SQS estándar + DLQ, EventBridge Scheduler | Sin Redis persistente; reintentos y DLQ nativos |
| Orquestación | Step Functions **Standard** (aprobaciones) y **Express** (alto volumen) | `waitForTaskToken` espera horas sin costo de cómputo |
| Datos | Aurora Serverless v2 PostgreSQL | Conserva Prisma, el trigger de auditoría y las transacciones; escala a 0 ACU en inactividad |
| Evidencia | S3 Object Lock (compliance) + KMS + réplica | Inmutabilidad exigible a una fintech |
| Núcleo de detección | EC2 Graviton + EBS, un nodo, ASG `min=max=1` | Único componente sin versión serverless ([02](../../02-arquitectura.md#el-núcleo-wazuh-por-qué-no-es-serverless-y-cómo-se-hace-robusto)) |
| Fuentes AWS | CloudTrail, GuardDuty, Security Hub, WAF logs | Entran por EventBridge a SQS y se normalizan a `SecurityEvent` |
| Secretos | Secrets Manager + KMS | Solo por referencia (`secretRef`) |
| Observabilidad | CloudWatch Logs, métricas y alarmas | Los logs de seguridad van a Wazuh; los de infraestructura a CloudWatch |

## Decisiones de robustez

- **Multi-AZ donde es gratis**: Lambda, API Gateway, SQS, Step Functions, DynamoDB/S3 son regionales.
  Aurora usa dos AZ; el nodo Wazuh es el único de una sola AZ.
- **Falla del nodo Wazuh**: el ASG lo reemplaza y el volumen de datos se reconecta o se restaura del
  último snapshot. Mientras tanto, la ingesta cloud-native sigue (EventBridge → SQS retiene hasta
  14 días) y B89 Cases sigue operando; solo se pierde la UI de Wazuh y la detección de agentes.
  RTO/RPO objetivo: **por definir y medir** en el gate de recuperación ([09](../../09-plan-de-lanzamiento.md)).
- **Idempotencia**: ejecuciones de Step Functions nombradas por el id de la solicitud; consumidores
  SQS con clave de idempotencia. Entrega al menos una vez es el supuesto.
- **Contrapresión**: concurrencia reservada en las Lambdas que escriben en Aurora, para no agotar
  conexiones (usar RDS Proxy si la medición lo exige).
- **Inmutabilidad**: Object Lock en modo compliance con retención fijada por Legal (U-004); réplica
  a `b89-log-archive` con cuenta y claves KMS distintas.

## Decisiones de costo

- **Sin NAT Gateway.** Es el gasto oculto típico. El nodo Wazuh usa endpoints de VPC (gateway de S3
  gratis; interfaces para Secrets Manager, KMS y CloudWatch Logs) y los Lambdas fuera de VPC cuando
  no necesitan el Indexer.
- **Graviton en todo** (EC2 y Lambda).
- **Retención caliente corta**: el Indexer guarda 7 días; el resto en snapshots S3 con ciclo de
  vida a Intelligent-Tiering y luego Glacier.
- **Savings Plan de cómputo a 1 año** solo para el nodo Wazuh, una vez medido su tamaño real.
- **Dos Step Functions**: Standard para flujos con aprobación (pocos, largos) y Express para
  transformaciones de alto volumen (muchos, cortos).
- **Aurora a 0 ACU** en entornos no productivos y mínimo bajo en producción.

### Orden de magnitud mensual (estimación, un entorno de producción pequeño)

| Rubro | Rango estimado | Quién domina el costo |
| --- | --- | --- |
| Nodo Wazuh (EC2 arm64 + EBS + snapshots) | Cientos de USD | Tamaño de la instancia y retención caliente |
| Aurora Serverless v2 | Decenas de USD | ACU activas y almacenamiento |
| Lambda, API Gateway, SQS, Step Functions, EventBridge | Pocas decenas de USD | Volumen de eventos |
| WAF + CloudFront | Decenas de USD | Reglas gestionadas y tráfico |
| Endpoints de VPC (interfaz) | Decenas de USD | Número de endpoints × AZ |
| S3, KMS, Secrets Manager | Decenas de USD | Retención de evidencia |
| GuardDuty y Security Hub | Variable por uso | Volumen de eventos analizados |

El rubro dominante es el nodo Wazuh, no la parte serverless. Reducir ese costo implica bajar la
retención caliente o el tamaño de la instancia, no cambiar de servicio.

## Orden de migración desde el Terraform heredado

1. Cuentas y landing zone (Organizations, SCPs, CloudTrail organizacional, `b89-log-archive`).
2. Núcleo Wazuh en el nodo único, con backups y prueba de restauración.
3. Plano B89: Cognito, API Gateway + Lambda (adaptador sobre `apps/api`), Aurora y SQS. Retirar
   ECS, RDS fijo y ElastiCache cuando haya paridad.
4. B89 Respond sobre Step Functions con los playbooks aprobados.
5. Endurecimiento: Object Lock, réplica, pruebas de recuperación y evidencia para el auditor.

Cada paso exige evidencia verificable antes del siguiente; el criterio de aceptación de cada fase
vive en [09](../../09-plan-de-lanzamiento.md).

## Qué no está resuelto

- Región AWS y residencia de datos exigida por el regulador de B89.
- Marco regulatorio aplicable a B89 (SBS 504-2021, Ley 29733, PCI-DSS) a confirmar con Legal y
  Cumplimiento de B89; el diseño solo asume que se exige auditoría inmutable y trazabilidad.
- Volumen real de eventos por segundo, que define el tamaño del nodo Wazuh.
- Si el tamaño del Indexer justifica pasar a tres nodos.
