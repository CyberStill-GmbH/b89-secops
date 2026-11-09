# 22 · Registro de cambios del despliegue B89 SOC

> Esfuerzo de despliegue del 2026-11-02 al 2026-11-08 en la rama `b89/rebrand-serverless`. Agrupado
> por tema; cada línea cita el commit. Lo que otros agentes tienen en curso figura al final.

## 2026-11-02 · Marca B89 y nueva base

- Rebrand de la base de código original a **B89 SecOps** y reparación de identificadores en CI
  (`d32c76b`, `7cb8198`); identidad visual oficial B89 (`4f0b582`).
- Perfil Azure archivado: B89 opera solo en AWS (`8870d20`); documentación reescrita (`25bfcf5`).
- Login B89 con usuario y contraseña junto a Entra (`7d14a5b`), ilustración optimizada a WebP
  (`a4fbee8`), pantalla de carga animada (`10ed341`).
- Frontend de B89 Respond con la identidad B89 (`e3d0fa4`).

## 2026-11-03 · Del diseño serverless al nodo PowerUser

- API: Bunny con historial y login de contraseña de la cuenta demo administradora (`c6692c6`);
  panel de Bunny en `b89_ops` y Terraform serverless (`6ec149d`); verificación con PostgreSQL
  (`d043aa4`, `c01ed00`).
- Terraform serverless con plan/apply por OIDC, ACM y Route 53 (`be42458`, `f4cf77d`, `cb34a36`).
  No se pudo aplicar: la cuenta no permite IAM ni `iam:PassRole`.
- **Stack PowerUser sin IAM** y overlay local del dashboard con edge (`ee5e3c0`); el nodo corre el
  SOC completo (`68462e6`).
- Ingesta de Wazuh sin Entra con gateway de token estático (`d30bd3d`); zonas horarias `±HHMM` de
  Wazuh aceptadas en vez de poner en cuarentena cada alerta (`32a3bc8`).
- Login detrás del edge, IP fija del dashboard, API local en 3089 (`31d259a`); correcciones del login
  (`fd59e12`, `42b14fd`, `cfa7ca8`); aviso de cookies (`27a0b56`).
- Marca: activos visuales (`ff7acbc`), conejo como logo y favicon (`4a7210e`), splash (`3439217`,
  `7213ec1`, `5733a77`).
- B89 Respond embebido en el SIEM en local (`1012ae6`).
- Bunny: variables `B89_BUNNY_*` aceptadas, Anthropic con `claude-sonnet-5-5` por defecto
  (`5eeaa5a`, `5c2ba99`).

## 2026-11-04 · Fuentes, políticas, Respond y vistas

- Bunny: el panel sobrevive a los re-render de `<body>` de OSD (`596001a`).
- **Collectors** de solo lectura para Bitdefender GravityZone, Snyk y Cloudflare con reglas Wazuh
  (`82c39b1`); instalador en el host y Office 365 sobre el manager en Docker (`fab88f2`); JSONL
  precreado para no perder el primer lote (`dea6a4f`).
- **Correo de alertas** críticas y altas por Microsoft Graph (`a32df7b`), umbral en nivel 8
  (`9542103`). Bloqueado hasta conceder `Mail.Send`.
- **Políticas como código:** grupos de agentes (`4698a51`), `ossec.conf` del manager e instalación de
  reglas con control de colisión de IDs (`eaf7207`), retención ISM sin S3 y verificación (`46598d5`).
- **B89 Respond:** SSO desde la sesión B89, «Volver al SIEM» y capa en español (`ea09db6`); marca de
  Respond (`b45eadc`); textos, marketing del upstream oculto y cookies heredadas (`a85f1af`);
  playbooks exportables con puerta de aprobación (`b84562e`).
- Ingesta: cursor de Wazuh desatascado y alertas de proveedores como alertas de primera clase
  (`833c088`).
- **Monitoreo de la cuenta AWS sin IAM** (EventBridge → SNS → Wazuh, 17 regiones) (`7e7424b`,
  `8ff9f21`); trail de la cuenta porque el de la organización vive en la cuenta de administración
  (`598294a`): llegan eventos reales (p. ej. regla 101616).
- Puertos de agentes abiertos a Internet, aprobado por el dueño (`e9d6eb0`).
- **Cuentas demo por rol** (`75cbf37`).
- **Resumen del SOC** como portada, páginas Integraciones y Políticas, dashboards por proveedor
  (`d339cac`); vistas de la app de Wazuh para roles de solo lectura (`1b1d4eb`, `499a0ba`,
  `3ed6ed4`).
- **Detección como código:** catálogo, herramientas y 24 reglas nuevas (`5381874`), vistas de
  análisis de detección (`8217d9f`).

## 2026-11-08 · Documentación

- Documentación de la plataforma vigente: índice, arquitectura, operación, integraciones, guía de
  usuario, identidad, postura de seguridad, brechas y este registro. Material heredado (Azure, ECS,
  Sophos/Cato, Shuffle por webhook) movido a [`archive/`](archive/README.md).

## En curso (otros agentes, sin fusionar)

- Detección de conexiones de red y más capacidades nativas de Wazuh.
- Rediseño de interfaz e identidad: logos reales de servicios, reportes PDF con marca, vista de
  investigación, limpieza de la navegación.
- Calidad de respuesta de Bunny.
- Monitoreo de proveedores con timers `b89-provider-*` y salud de M365.
- Correlación basada en riesgo (Go), silencio de fuentes (Python), priorización KEV/EPSS (Python):
  ver [19](19-brechas-y-roadmap.md).
