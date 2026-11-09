# B89 SOC en AWS, modo PowerUser (`infra/aws-poweruser`)

Despliegue para cuentas donde el operador solo tiene el permission set **SOC-PowerUser**:
no puede crear recursos IAM ni hacer `iam:PassRole`. Sin eso AWS no permite Lambda,
Step Functions, EventBridge Scheduler, perfiles de instancia EC2, DLM ni Flow Logs, de modo
que el diseño serverless de `infra/aws-serverless` no se puede aplicar. Este stack lo
reemplaza por **un nodo EC2 sin rol** que corre todo el SOC en Docker.

## Qué crea Terraform (sin IAM)

VPC propia con dos subredes públicas e IGW; ALB público (`public.tf`) con ACM (TLS 1.3/1.2),
WAFv2 (IpReputation, KnownBadInputs, Common, límite por IP) y access logs; SG del nodo con 443
solo desde el ALB, 22 desde `allowed_admin_cidrs` y TCP 1514/1515 desde `agent_cidrs`; CMK de
KMS con rotación (EBS y S3), EC2 `r7i.xlarge` Ubuntu 24.04 con IMDSv2 y disco gp3 cifrado, EIP,
registros `dev.security.b89.io` (alias al ALB) y `agents.dev.security.b89.io` (A a la EIP),
bucket S3 de evidencia (KMS, versionado, TLS-only, sin acceso público) y Budget mensual.

## Qué corre en el nodo (`host/compose.b89.yaml`, `host/compose.respond.yaml`)

- Wazuh 4.14.8 single-node: manager, indexer y dashboard con la marca B89 y los plugins
  `b89_ops`/`b89_i18n` (imagen de `infra/local/wazuh-dashboard/Dockerfile`).
- Login: **solo el de B89** (proxy auth). El edge fija `x-proxy-user`/`x-proxy-roles` tras
  `/api/auth/introspect`; el indexer solo los acepta desde la IP fija del dashboard
  (172.30.89.10, `scripts/apply-indexer-security.sh`). El formulario del Security plugin no es
  accesible.
- PostgreSQL 18 con TLS (CA interna), migrador y API B89 (perfil `production`, identidad fija de
  demo y login de administrador demo), con la ingesta de Wazuh por el gateway de token estático.
- B89 Respond (Shuffle v2.3.0 rebrandeado) en `/b89-respond/`, detrás de la sesión B89 y
  embebible solo por el mismo origen (`scripts/deploy-respond.sh`).
- Contenido del manager: reglas B89, grupos de agentes e integraciones instaladas sin activar
  (`scripts/setup-wazuh-content.sh`); el propio nodo enrolado como agente
  (`scripts/setup-host-agent.sh`). Agentes externos: [AGENTS.md](AGENTS.md).
- Edge nginx. Los secretos se generan en el host, en `/opt/b89/secrets` (0700, archivos 0600):
  no pasan por Terraform, el estado, el user_data ni Git.
- Correlador determinista privado, sin puerto publicado y limitado a la red interna API/gateway.
  Arranca con emisión desactivada; operación, canary, métricas y rollback en
  [CORRELATOR-OPERACION.md](CORRELATOR-OPERACION.md).

## Despliegue

```bash
cd infra/aws-poweruser
terraform init -backend-config=backend.hcl
terraform apply -var-file=environments/dev.tfvars
SSH_KEY=<clave privada> HOST=$(terraform output -raw public_ip) SOC_HOSTNAME=dev.security.b89.io \
  bash scripts/ship.sh
```

`ship.sh` copia el árbol de trabajo (sin `.env*`, `.git` ni `node_modules`) a `/opt/b89/src`
y ejecuta `scripts/deploy-host.sh`, que es idempotente.

Credenciales generadas (en el host, solo root):

- Login B89 (administrador demo): `admin@b89.io` / `/opt/b89/secrets/demo-admin-password.txt`.
- B89 Respond: `SHUFFLE_ADMIN_USERNAME` / `SHUFFLE_ADMIN_PASSWORD` de `/opt/b89/secrets/compose.env`.
- Break-glass del indexer (solo por SSH, no por el dashboard): `admin` / `INDEXER_ADMIN_PASSWORD`.
- Contraseña de enrolamiento de agentes: `/opt/b89/secrets/wazuh-authd.pass`.
- Secretos de servicios (Anthropic, Entra, Bitdefender, Snyk, correo, Cloudflare y Teams):
  `/opt/b89/secrets/services.env`, copiado por SSH desde el `.env` local, nunca versionado.

### Alertas de revisión en Teams

El transporte del API publica alertas P1/P2 creadas o escaladas y la apertura de incidentes
críticos. Para activarlo, guarda la URL firmada del Teams Workflow en
`/opt/b89/secrets/services.env` como `B89_TEAMS_WORKFLOW_URL` (archivo root-only, modo `0600`) y
vuelve a ejecutar `scripts/deploy-host.sh` por SSH para actualizar el entorno privado del API y
recrear el servicio. La URL no debe aparecer en Terraform, argumentos, historial de shell, logs ni
Git. Sin ese secreto el canal queda desactivado. Las tarjetas incluyen título, prioridad, estado,
puntaje, señal, regla, motivos de prioridad, alertas relacionadas, fecha y enlace directo a B89;
no incluyen el evento crudo ni datos de identidades o IP.

## Ingesta de alertas de Wazuh (sin Entra)

`deploy-host.sh` lo deja configurado (`scripts/setup-ingestion.sh` crea `b89_reader`, el token y el
certificado; el servicio `wazuh-gateway` está en `host/compose.b89.yaml`). Para que lea alertas sin Entra (la identidad
demo no emite tokens de workload) se usa el modo `static-token`: el API envía un bearer estático
a un gateway nginx interno (`platform/gateway/static-token/wazuh-gateway.conf.template`) que
inyecta la credencial read-only `b89_reader` hacia el Indexer. Detalle y modelo de amenaza en
[docs/04](../../docs/04-identidad-y-acceso.md#ingesta-de-wazuh-sin-entra-token-estático-del-gateway).

Generar el token en el host (una vez; rotarlo = repetir y reiniciar API y gateway):

```bash
openssl rand -base64 48 | tr -d '\n'
```

| Dónde                         | Variable                                           | Valor                                                                                                         |
| ----------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `/opt/b89/config/api.env`     | `B89_INGESTION_SOURCE`                             | `wazuh`                                                                                                       |
| `/opt/b89/config/api.env`     | `B89_WAZUH_GATEWAY_AUTH`                           | `static-token`                                                                                                |
| `/opt/b89/config/api.env`     | `B89_WAZUH_GATEWAY_BASE_URL`                       | `https://<servicio del gateway>:8443` (nombre cubierto por su certificado, firmado por `/opt/b89/pki/ca.pem`) |
| `/opt/b89/secrets/api.env`    | `B89_WAZUH_GATEWAY_ACCESS_TOKEN`                   | el token generado                                                                                             |
| entorno del gateway (secreto) | `B89_WAZUH_GATEWAY_ACCESS_TOKEN`                   | el mismo token                                                                                                |
| entorno del gateway (secreto) | `WAZUH_INDEXER_BASIC_AUTH_B64`                     | `base64("b89_reader:<contraseña>")`                                                                           |
| entorno del gateway           | `WAZUH_INDEXER_UPSTREAM`, `WAZUH_INDEXER_TLS_NAME` | `wazuh.indexer:9200`, nombre del certificado del Indexer                                                      |

Opcionales del API: `B89_INGESTION_SOURCE_ID` (por defecto `wazuh-indexer`),
`B89_INGESTION_INTERVAL` (`60s`) y `B89_INGESTION_INITIAL_LOOKBACK_MINUTES` (`60`). No hacen falta
`B89_INGESTION_GATEWAY_SCOPE` ni el client secret de Entra. El servicio del gateway y el usuario
`b89_reader` en el Indexer se agregan al compose del nodo; su puerto no se publica.

## Lo que este modo NO tiene (y por qué)

Todo lo que necesita una identidad IAM para el host o un rol de servicio:

- Secrets Manager / SSM Parameter Store: el host no tiene credenciales; los secretos son archivos locales.
- SQS/EventBridge (GuardDuty, Security Hub → SOC), Step Functions (B89 Respond), Scheduler,
  Lambdas de onboarding y la asociación SSM que enrola agentes: requieren roles.
- Session Manager: el acceso es SSH, restringido a `allowed_admin_cidrs`.
- Snapshots automáticos (DLM) y subida de respaldos a S3 desde el host: requieren rol. El
  bucket de evidencia existe, pero se carga desde la estación del operador.
- Entra ID real: el API usa la identidad fija de demo y la excepción de contraseña del
  administrador (vence a los 29 días; cada `deploy-host.sh` la renueva).

Para el diseño completo, un administrador de la cuenta debe crear los roles de
`infra/aws-serverless` y conceder `iam:PassRole` acotado a `b89-*`.

## Baja

```bash
ssh ... 'cd /opt/b89/wazuh-docker/single-node && sudo docker compose -p b89 down -v'   # opcional
terraform destroy -var-file=environments/dev.tfvars
```

El bucket de evidencia tiene `force_destroy = false`: vaciarlo antes del destroy.
