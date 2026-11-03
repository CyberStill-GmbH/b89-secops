# B89 SOC en AWS, modo PowerUser (`infra/aws-poweruser`)

Despliegue para cuentas donde el operador solo tiene el permission set **SOC-PowerUser**:
no puede crear recursos IAM ni hacer `iam:PassRole`. Sin eso AWS no permite Lambda,
Step Functions, EventBridge Scheduler, perfiles de instancia EC2, DLM ni Flow Logs, de modo
que el diseño serverless de `infra/aws-serverless` no se puede aplicar. Este stack lo
reemplaza por **un nodo EC2 sin rol** que corre todo el SOC en Docker.

## Qué crea Terraform (sin IAM)

VPC propia con una subred pública e IGW, SG (22 y 443 solo desde `allowed_admin_cidrs`;
80 abierto solo para ACME HTTP-01 y la redirección; 1514/1515 desde `agent_cidrs`), CMK de
KMS con rotación (EBS y S3), EC2 `r7i.large` Ubuntu 24.04 con IMDSv2 y disco gp3 cifrado,
EIP, registro A `dev.security.b89.io` en la zona `security.b89.io`, bucket S3 de evidencia
(KMS, versionado, TLS-only, sin acceso público) y Budget mensual.

## Qué corre en el nodo (`host/compose.b89.yaml`)

Wazuh 4.14.8 single-node (manager, indexer, dashboard con la marca B89 construido con
`infra/local/wazuh-dashboard/Dockerfile`), PostgreSQL 18 con TLS (CA interna), migrador y
API B89 (perfil `production`, identidad fija de demo y login de administrador demo) y edge
nginx con Let's Encrypt. Los secretos se generan en el host, en `/opt/b89/secrets` (0700,
archivos 0600): no pasan por Terraform, el estado, el user_data ni Git.

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

- Login del dashboard (Security plugin): `admin` / `INDEXER_ADMIN_PASSWORD` de `/opt/b89/secrets/compose.env`.
- Administrador demo del API B89: `admin@b89.io` / `/opt/b89/secrets/demo-admin-password.txt`.

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
