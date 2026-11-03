<p align="center">
  <img src="docs/reference/assets/b89-logo.svg" alt="B89 SOC" width="320" />
</p>

# B89 SecOps

**Plataforma SOC de la fintech B89, serverless sobre AWS.** Una URL, un login Entra y un shell: el
dashboard de Wazuh con marca B89, al que B89 añade casos, correlación contextual, respuesta
gobernada, auditoría inmutable, gestión de acceso con revocación inmediata y avisos con acuse humano.
La investigación colaborativa es **B89 Cases** y la automatización de respuesta es **B89 Respond**
(AWS Step Functions, con aprobación humana antes de cada acción).

> Este repositorio es un derivado de QAPAQ SecOps adaptado a B89. El renombrado de marca ya está en
> el código; el despliegue serverless descrito abajo es el **destino de diseño** y aún no tiene
> Terraform completo en `infra/aws/` (ver [plan de lanzamiento](docs/09-plan-de-lanzamiento.md)).

## Arquitectura en breve

- **Serverless**: CloudFront + WAF, Cognito (federado con Entra), API Gateway HTTP + Lambda,
  Step Functions, SQS/EventBridge, Aurora Serverless v2 (PostgreSQL) y S3 con Object Lock.
- **Un solo nodo con servidor**: el núcleo **Wazuh** (Manager, Indexer, Dashboard) en una EC2
  Graviton, porque Wazuh no existe como servicio sin servidor. Wazuh recolecta, detecta y guarda;
  lo que B89 cambia de Wazuh vive versionado en [`wazuh/`](wazuh/README.md), sin fork del código.
- **B89** (TypeScript) coordina el trabajo humano: quién toma una alerta, cómo se vuelve caso,
  quién aprueba una acción, qué queda como evidencia y quién puede entrar.

Detalle y diagrama en [docs/02-arquitectura.md](docs/02-arquitectura.md).

## Marca

| Nombre          | Qué es                                                                    |
| --------------- | ------------------------------------------------------------------------- |
| **B89 SOC**     | La plataforma completa                                                    |
| **B89 Cases**   | Casos, tareas y continuidad de investigación (antes «Ayni Qapaq»)         |
| **B89 Respond** | Respuesta gobernada sobre Step Functions (antes «Ankay», que era Shuffle) |

## Estructura

| Ruta                      | Contenido                                                                                                                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wazuh/`                  | Overlay B89 de Wazuh: reglas, Office 365, edge nginx, seguridad del Indexer, ISM, detectores ML, integraciones y dashboard                                             |
| `apps/api`, `apps/worker` | Backend B89 (login Entra, casos, auditoría, avisos). Se empaqueta en Lambda y SQS según [docs/12](docs/12-backend-en-el-siem.md) y [docs/11](docs/11-cache-y-colas.md) |
| `modules/`                | Dominio hexagonal sin frameworks: `access`, `soc`, `detection`, `soar`, `connectors`, `telemetry`                                                                      |
| `platform/`               | Auditoría, configuración y secretos, base de datos (Prisma/Postgres), testing, gateway (en retiro)                                                                     |
| `packages/contracts`      | Contrato `SecurityEvent` 1.0.0 y catálogo de errores                                                                                                                   |
| `b89-respond/`            | Código heredado de B89 Respond basado en Shuffle, a reemplazar por Step Functions                                                                                      |
| `infra/aws`               | Terraform de AWS (demo actual). `infra/local`: Postgres, Redis y MinIO para desarrollo                                                                                 |
| `infra/azure`             | Perfil Azure **heredado y archivado**; B89 opera solo en AWS                                                                                                           |

## Documentación

Empieza por [`docs/README.md`](docs/README.md):

1. [Producto y decisiones de negocio](docs/01-producto.md)
2. [Arquitectura serverless](docs/02-arquitectura.md)
3. [Evaluación de componentes y decisión de fork](docs/03-evaluacion-de-componentes.md)
4. [Identidad, acceso y administración de usuarios](docs/04-identidad-y-acceso.md)
5. [Datos y retención hot/warm/cold](docs/05-datos-y-retencion.md)
6. [Operación, costos y observabilidad](docs/06-operacion.md)
7. [Detección, ML y SOAR](docs/07-deteccion-ml-y-soar.md)
8. [Frontend unificado](docs/08-frontend-unificado.md)
9. [Plan de lanzamiento](docs/09-plan-de-lanzamiento.md)
10. [Decisiones vigentes](docs/10-decisiones.md)

## Desarrollo

```powershell
pnpm install
pnpm infra:up          # Postgres, Redis, MinIO locales (infra/local/README.md)
pnpm dev:api
pnpm verify            # lint, typecheck, unit, boundaries
```

Requisitos: Node 24.21 y pnpm 12.4. Baseline completa en
[`docs/reference/toolchain-and-capacity.md`](docs/reference/toolchain-and-capacity.md).

## Licencias

Código B89: ver [LICENSE](LICENSE). Wazuh Manager y sus reglas y decoders son GPLv2. El Indexer,
el Dashboard y OpenSearch son Apache-2.0. Las reglas y decoders derivados que viven en `wazuh/`
mantienen la atribución GPLv2.
