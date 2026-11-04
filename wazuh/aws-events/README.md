# AWS → Wazuh B89 (sin IAM)

Monitoreo de la propia cuenta AWS (061098277310) desde el nodo PowerUser. El rol SSO `SOC-PowerUser`
no puede crear IAM ni hacer `iam:PassRole`, así que el módulo AWS de Wazuh (que lee S3/CloudWatch con
credenciales) no se usa. En su lugar, un pipeline **push** que solo usa políticas de recurso:

```
CloudTrail (trail de organización, ya existente)
  → EventBridge, bus default (reglas regionales; solo eventos de escritura)
  → SNS (política del tema: events.amazonaws.com + aws:SourceArn; CMK propia en us-east-1)
  → HTTPS https://dev.security.b89.io/hooks/aws-sns (ALB + WAF → edge nginx: solo POST, 300 KB, 50 r/s)
  → receptor aws-events (contenedor node, sin puertos publicados)
  → /var/ossec/logs/b89-collectors/aws/aws-events.jsonl (<localfile log_format="json">)
  → reglas 101600–101699 → wazuh-alerts-* → dashboard «B89 · AWS»
```

| Pieza | Dónde |
| --- | --- |
| Terraform (CMK, tema, 10 reglas us-east-1, 16 centinelas regionales, suscripciones) | `infra/aws-poweruser/aws-monitoring.tf`, `modules/aws-events-sentinel` |
| Receptor | `receiver/sns-receiver.mjs` (+ `sns-receiver.test.mjs`, `node --test`) |
| Servicio y edge | `infra/aws-poweruser/host/compose.b89.yaml` (`aws-events`), `edge.conf.template` (bloque `B89:aws-sns`), `host/aws-events.env` (temas aceptados) |
| Reglas y logtest | `rules/b89_aws_rules.xml`, `tests/make-cases.mjs` → `aws-cases.jsonl`, `tests/run-aws-logtest.sh` |
| Instalación en el manager | `sudo bash wazuh/aws-events/install-aws-events.sh` (crea el directorio de salida, reglas, `<localfile>`, `wazuh-analysisd -t`, reinicia solo el manager) |
| Dashboard | `wazuh/dashboard/saved-objects/build_aws_dashboard.py` → `b89-aws.ndjson` |

## Receptor

- Firma SNS **SignatureVersion 2** (SHA256withRSA); `SigningCertURL` solo `https://sns.<región del tema>.amazonaws.com/*.pem`,
  certificado vigente con SAN `sns.amazonaws.com` o `sns.<región>.amazonaws.com` (los temas se crean con `signature_version = 2`).
- Solo los `TopicArn` de `B89_AWS_SNS_TOPIC_ARNS`; la cabecera `x-amz-sns-topic-arn` debe coincidir.
- Confirma la suscripción (GET `SubscribeURL`) solo con firma válida, tema esperado y URL
  `https://sns.<región>.amazonaws.com/?Action=ConfirmSubscription&TopicArn=<el mismo>&Token=…`.
- Dedupe por `MessageId` y por id del evento EventBridge (un evento root + IAM coincide con dos reglas).
- Timestamp ≤ 1 h; token bucket → 503 (SNS reintenta; la política de entrega reintenta < 1 h).
- Normaliza a campos planos `aws.*` (`event_name`, `event_source`, `user_type`, `principal`, `source_ip`,
  `console_login`, `mfa_used`, `open_to_world`, …) y deja `request_parameters` / `response_elements` como texto
  recortado: el decodificador JSON de Wazuh limita campos y la línea a 64 KB.
- Sin secretos; nunca registra el contenido de los mensajes.

## Reglas (101600–101699)

| Nivel | Regla |
| --- | --- |
| 13 | 101605 login de consola root · 101620 CloudTrail StopLogging/DeleteTrail · 101664/101673 hallazgo crítico |
| 12 | 101606 API de root · 101612 cómputo/VPC en región no habitual · 101615 manipulación del pipeline B89 · 101622–101624 GuardDuty/Security Hub/Config deshabilitados · 101632 admin concedido · 101636 Organizations/SCP · 101657 KMS ScheduleKeyDeletion · 101663/101672 hallazgo alto |
| 10 | 101608 fuerza bruta (5 fallos/5 min por IP) · 101611 actividad en región no habitual · 101621 CloudTrail modificado · 101625 Access Analyzer · 101631 IAM alto riesgo · 101634 permission sets · 101635 Organizations · 101641 SG abierto a Internet · 101644 flow logs borrados · 101645 snapshot/AMI compartido · 101651/101652 S3 público · 101656 KMS DisableKey |
| 8 | 101609 login IAM sin MFA · 101630 IAM · 101633 Identity Center · 101640 SG · 101642 NACL · 101643 rutas/gateways · 101650 S3 · 101655 KMS política · hallazgos medios |
| 3–6 | 101601/101602/101610 actividad, 101607 login fallido (5), 101613 servicio AWS en otra región (4), 101616 cambio del pipeline (6), 101646 EC2 RunInstances |

`bash wazuh/aws-events/tests/run-aws-logtest.sh b89-wazuh.manager-1` → 50/50 casos.

## Límites (sin IAM)

- Reenviar a un bus central exige rol IAM: cada región tiene su propio tema/regla (centinela).
- Sin eventos de lectura (Get/List/Describe) ni eventos de datos (S3 GetObject…): exigirían el estado
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` o un trail con selectores de datos (no se piden).
- Sin VPC Flow Logs, S3 access logs ni CloudWatch Logs: requieren rol de entrega o lectura con credenciales.
- Identity Center vive en la cuenta de administración: sus cambios no llegan a esta cuenta.
- GuardDuty y Security Hub están apagados: las reglas de hallazgos quedan listas pero sin datos.
