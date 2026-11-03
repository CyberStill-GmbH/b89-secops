# 06 · Operación

> Estado: **propuesto**. Describe cómo se opera B89 SOC serverless en AWS ([02](02-arquitectura.md)).
> `infra/aws/` hoy contiene el Terraform de la demo anterior (ECS, RDS, EC2); el Terraform
> serverless aún no existe ([09](09-plan-de-lanzamiento.md)). Lo que sí es **hecho** (sin verificar
> en AWS) son los workflows de GitHub, los scripts de `wazuh/` y la configuración de integraciones.
> **Ninguna cifra de costo de este documento está verificada**: son órdenes de magnitud para
> decidir y deben validarse con el AWS Pricing Calculator y el plan de Terraform (decisión N8).

## Topología AWS (propuesta)

| Recurso | Cuenta | Notas |
| --- | --- | --- |
| CloudFront + WAF | `b89-soc-workload` | Borde único: `/` al dashboard y `/api` a API Gateway |
| Cognito, API Gateway HTTP, Lambda (arm64) | `b89-soc-workload` | Identidad y B89 API ([04](04-identidad-y-acceso.md)) |
| Step Functions Standard, SQS + DLQ, EventBridge | `b89-soc-workload` | B89 Respond, ingesta y colas ([11](11-cache-y-colas.md), [13](13-b89-respond.md)) |
| Aurora Serverless v2 (PostgreSQL) | `b89-soc-workload` | Casos, sesiones y auditoría |
| Nodo Wazuh: EC2 Graviton en ASG `min=max=1` + NLB para agentes | `b89-soc-workload` | Única parte con servidor ([02](02-arquitectura.md)) |
| VPC con subredes privadas y **sin NAT Gateway**, con endpoints de VPC (S3 de tipo gateway; Secrets Manager, KMS, CloudWatch Logs, SSM de tipo interfaz) | `b89-soc-workload` | Las Lambdas que leen el Indexer van en la VPC |
| S3 de snapshots, S3 con Object Lock (evidencia y auditoría) | `b89-soc-workload` | [05](05-datos-y-retencion.md) |
| Réplica de auditoría y evidencia (Object Lock) | `b89-log-archive` | Solo escritura desde workload |
| GuardDuty, Security Hub, Detective | `b89-security-tooling` | Administrador delegado |

Lo retirado de la topología anterior (KrakenD, ECS Fargate, RDS fijo, ElastiCache, worker,
Shuffle en VM, NAT y el frontend alojado aparte) está justificado en
[02](02-arquitectura.md#qué-salió-del-diseño-y-por-qué).

## Costos

Distinción obligatoria en este documento:

- **Verificado:** ninguna cifra. Aún no hay plan de Terraform serverless ni facturas de B89 SOC.
- **Estimado (a validar con AWS Pricing Calculator):** todo lo de la tabla, a precios de lista
  on-demand en una región de EE. UU., para una demo de bajo tráfico. Son rangos, no presupuesto.
  La región final y los descuentos (Savings Plans, acuerdos) cambian los valores.

| Componente | Qué domina el costo | Orden de magnitud USD/mes (ESTIMADO) |
| --- | --- | --- |
| Nodo Wazuh (EC2 Graviton, clase de 4 vCPU y 16 GB) | Horas de cómputo 24×7 | Centenas bajas (~100–150); es el mayor costo fijo |
| Volumen EBS del Indexer (gp3, cientos de GB) y snapshots diarios | GB aprovisionados | Decenas |
| Endpoints de VPC de interfaz (unos 4–6 en 2 AZ) | Horas por endpoint y AZ | Decenas altas (~50–100). **"Sin NAT" no es gratis**: cambia el costo de NAT por el de endpoints, a cambio de no sacar tráfico a Internet |
| Aurora Serverless v2 | ACU-horas y almacenamiento. Con pausa a 0 ACU casi solo almacenamiento; con 0,5 ACU permanente, decenas | De un dígito a ~45 |
| WAF (web ACL, reglas gestionadas, solicitudes) | Reglas y volumen | Decenas bajas |
| NLB (agentes Wazuh) | Horas y LCU | Decenas bajas |
| S3 (snapshots, evidencia, Glacier) | GB almacenados y solicitudes | De un dígito a decenas según volumen |
| CloudWatch (logs, métricas, alarmas) | GB ingeridos | De un dígito a decenas |
| GuardDuty y Security Hub | Volumen analizado | Decenas, muy variable |
| Lambda, API Gateway HTTP, Step Functions, SQS, EventBridge, Cognito, CloudFront, KMS, Secrets Manager | Por uso; a volumen de demo | En conjunto, decenas bajas |

**Orden de magnitud total de una demo:** unos **USD 300–450/mes (ESTIMADO)**, dominado por el nodo
Wazuh, los endpoints de VPC y el almacenamiento, no por el cómputo serverless. La cifra de la
demo anterior (~USD 190–229/mes) también era una estimación de lista y no es comparable: tenía
ECS, RDS y NAT fijos. Palancas (propuestas): Savings Plan o instancia reservada para el nodo,
mínimo de endpoints necesarios, Aurora en pausa fuera de horario en la demo y ciclo de vida a
Glacier. Antes de cada apply se compara el plan de Terraform con esta tabla.

## Observabilidad

La decisión N1 (no tercerizar) exige que la observabilidad sea autogestionada y quede dentro de las
cuentas de B89. **CloudWatch es un servicio de AWS, no un SaaS de terceros**; Grafana, Loki y
Prometheus se retiran ([10](10-decisiones.md), A10). Wazuh cubre la observabilidad de seguridad.

| Señal | Fuente | Dónde se ve |
| --- | --- | --- |
| Logs JSON de la API (con `correlationId`) | CloudWatch Logs de cada Lambda | Alarmas por filtros de métricas. Opcional: los ingiere el módulo AWS de Wazuh (`cloudwatchlogs`) → `wazuh-alerts-*`. La configuración (**hecha**) está en `wazuh/manager/ossec.b89-integrations.xml.tmpl` para los log groups anteriores; los nuevos se añaden |
| Métricas de Lambda, API Gateway, Step Functions, SQS (profundidad y DLQ), Aurora (ACU y conexiones) | CloudWatch Metrics nativas | Alarmas de CloudWatch → SNS → correo o Teams. Las métricas no salen de la cuenta |
| Ejecuciones de B89 Respond fallidas o detenidas | Step Functions y EventBridge | Alarma a SNS |
| Logs del borde | CloudFront y WAF a S3 | Módulo AWS de Wazuh |
| Salud del nodo Wazuh (CPU, disco, estado de la instancia, agentes, disco del Indexer) | CloudWatch Agent, Wazuh API e Indexer | Alarmas de CloudWatch y vistas nativas del dashboard |
| Salud de la ingesta B89 (cursores, retrasos, `PROVIDER_RESPONSE_INVALID`) | `GET /api/operations/health` | Vista «Salud operativa» de B89 |
| Acciones de los usuarios en B89 | Cadena de auditoría | Vista «Auditoría» de B89. **Se mantiene separada** de los logs (ADR-021) |
| Actividad de la cuenta AWS | CloudTrail (organización) | S3 en `b89-log-archive` y hacia Wazuh / EventBridge |

Ventaja: las acciones del SOC sobre su propia herramienta (logins, denegaciones, aprobaciones) se
vuelven eventos Wazuh y se alertan con reglas B89, por ejemplo una ráfaga de `AUTHZ_DENIED` del
mismo usuario. Esto apoya el monitoreo de APIs que pide la SBS (art. 21, a confirmar con B89).

Prerrequisitos a verificar: rol IAM del nodo con `logs:FilterLogEvents`/`GetLogEvents` sobre los log
groups y `s3:GetObject` sobre los buckets de logs; endpoint de VPC de CloudWatch Logs.

## Backups, RTO y RPO del nodo Wazuh

El nodo es el **punto de falla único aceptado** ([02](02-arquitectura.md)). El disco no es la
fuente de verdad: lo es el conjunto de snapshots.

| Mecanismo | Qué protege | Propuesta |
| --- | --- | --- |
| ASG `min=max=1` | Falla de la instancia o de la AZ | Reemplazo automático; el volumen de datos se reasocia o se restaura |
| Snapshots EBS (Data Lifecycle Manager) | Disco, configuración y claves del Manager | Diarios, con retención por definir; copia a otra región por decidir |
| Snapshots del Indexer a S3 (ISM) | Índices | Al salir de hot ([05](05-datos-y-retencion.md)) |
| Overlay `wazuh/` versionado | Reglas, decoders, ISM, plugin | Reaplicable por script idempotente desde git |

**RPO y RTO: hipótesis de diseño, no medidas** (N8 prohíbe publicarlas como objetivo vigente sin
prueba). Con snapshots EBS diarios el RPO del disco sería de hasta 24 h; con snapshots horarios, de
horas. Los agentes Wazuh guardan un buffer limitado de eventos si el Manager no responde, pero no
se debe contar con él. El RTO sería el reemplazo automático de la instancia (minutos) más, si el
volumen se pierde, la restauración del snapshot y la reaplicación del overlay (horas). **Gate:** un
simulacro (terminar la instancia y restaurar) que mida ambos valores antes de producción.

## Despliegue

- **Terraform en `infra/aws`**, con estado remoto y bloqueo. El pipeline corre en **GitHub Actions
  con OIDC** (sin claves de larga vida) y un rol de despliegue por cuenta. Antes de cada apply hay
  que verificar cuenta, región y backend, revisar todos los create/replace/destroy y comparar el
  costo con la tabla de arriba. Si aparece algo inesperado, se detiene.
- **Lambdas:** artefactos arm64 empaquetados por el pipeline y publicados con el SHA de git
  (`git-<sha>`), con versiones y alias para revertir. Step Functions y colas se definen en
  Terraform. Los workflows actuales (ECR y ECS) se reemplazan: **propuesto**.
- **Base de datos:** las migraciones de `platform/database/migrator` corren como paso del pipeline
  antes de promover las Lambdas.
- **Overlay Wazuh:** los workflows `initialize-wazuh.yml` y `configure-wazuh-office365.yml`
  empaquetan `wazuh/` y lo aplican por SSM con scripts idempotentes (hecho). Las fases 1–2 añaden
  `wazuh/edge`, `wazuh/indexer/*` y `wazuh/dashboard` al mismo empaquetado.
- **Sin NAT:** ningún recurso depende de un NAT Gateway. Qué Lambda va dentro o fuera de la VPC
  (las que llaman a Entra o Teams necesitan salida) se decide en la fase 1.
- **Secretos:** se cargan en Secrets Manager con workflow y nunca entran a tfvars ni al estado.

## Runbooks mínimos

| Situación | Acción |
| --- | --- |
| Pausar o reanudar la demo anterior conservando state y datos | [Control de costos reversible](operations/aws-demo-cost-control.md) (describe la topología previa con ECS y RDS) |
| La fuente «Wazuh Indexer · alertas» está en rojo | `GET /api/operations/health`. Revisar los logs de la Lambda de ingesta en CloudWatch y la DLQ. Desde el nodo, `curl --cacert` al Indexer con `b89_reader` (SSM). Workflow `repair-ingestion.yml` |
| Nadie puede entrar al dashboard | Probar `curl -i https://<dominio>/api/auth/introspect` con cookie. Revisar Cognito y la Lambda. Si la API cae, el break-glass es el usuario interno `admin` por `https://<ip-privada>:5601` vía SSM port-forward, nunca público |
| Disco del Indexer > 80 % | `GET _plugins/_ism/explain/wazuh-alerts-*` para ver índices atascados en una fase. Revisar el repo `b89-s3` |
| Nodo Wazuh caído o sin responder | Estado del ASG y de la instancia; si no se recupera, restaurar el último snapshot EBS y reaplicar el overlay |
| Restaurar historia | [05](05-datos-y-retencion.md#restauración) |
| Revocar a alguien de inmediato | Sacarlo del grupo SOC en Entra (la sincronización Graph revoca) o `POST /api/admin/sessions/:ref/revoke`. El dashboard se pierde en ≤ 5 s |
| Teardown de la demo | Ver `infra/aws/README.md`. Los buckets con Object Lock en modo compliance no se vacían antes de vencer su retención: usar plazos cortos en la demo |
