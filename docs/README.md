# Documentación B89 SecOps

La documentación principal consolida producto, arquitectura, operación y decisiones de **B89 SOC**,
la plataforma SOC serverless de la fintech B89 sobre AWS. El material histórico heredado de la base de código
original (sprints, informes, auditorías C-0X y ADR previos) sigue en git: `git show 050f9fa:docs/<ruta>`.

| # | Documento | Pregunta que responde |
| - | --- | --- |
| 01 | [Producto](01-producto.md) | Qué es B89 SOC y qué añade sobre Wazuh |
| 02 | [Arquitectura](02-arquitectura.md) | Cómo encajan las piezas serverless y el núcleo Wazuh |
| 03 | [Evaluación de componentes](03-evaluacion-de-componentes.md) | Qué se conserva, qué se migra y qué se retira, y por qué no hay fork del manager |
| 04 | [Identidad y acceso](04-identidad-y-acceso.md) | Login Entra único (Cognito) para la consola y el dashboard |
| 05 | [Datos y retención](05-datos-y-retencion.md) | Hot/warm/cold, evidencia y auditoría inmutable |
| 06 | [Operación](06-operacion.md) | AWS, costos, observabilidad, backups y despliegue |
| 07 | [Detección, ML y SOAR](07-deteccion-ml-y-soar.md) | Correlación, anomalías y respuesta gobernada (B89 Respond) |
| 08 | [Frontend unificado](08-frontend-unificado.md) | El dashboard de Wazuh como shell y B89 dentro |
| 09 | [Plan de lanzamiento](09-plan-de-lanzamiento.md) | Fases serverless, criterios de aceptación y orden |
| 10 | [Decisiones](10-decisiones.md) | Registro único de decisiones vigentes (incluye B1–B9 del fork) |
| 11 | [Colas y caché](11-cache-y-colas.md) | SQS, EventBridge Scheduler y dónde queda Valkey |
| 12 | [Backend en Lambda](12-backend-en-el-siem.md) | Cómo la API B89 deja ECS y qué fases quedan |
| 13 | [B89 Respond](13-b89-respond.md) | Diseño de la respuesta gobernada sobre Step Functions y estado heredado de Shuffle |
| 14 | [B89 Respond y B89 Core](14-b89-respond-conexion-b89.md) | Contrato entre el catálogo, las aprobaciones y la ejecución |
| 15 | [Bunny](15-bunny-asistente.md) | El asistente de IA integrado: qué lee, con qué permisos, privacidad y configuración |
| 16 | [Políticas de seguridad](16-politicas.md) | Catálogo de políticas como código: agentes, manager, reglas, retención del Indexer y roles |

La referencia visual del frontend B89 está en [Identidad visual B89](brand/b89-visual-identity.md); incluye tipografía, paleta, logo y la biblioteca recortada de mascotas e ilustraciones.

`reference/` guarda las decisiones heredadas (ADR-028 a 030 en `reference/decisiones/`, B89 Cases, la
arquitectura resiliente y el rollout de Terraform) y los archivos que el código o la CI leen
(catálogo de errores, inventario de fuentes, guía de extensión de proveedores, baseline de toolchain
y gates de release). Si se mueven, hay que actualizar los tests que los referencian.

## Arquitectura cloud

- [AWS serverless: topología, costos y gates](cloud/aws/architecture.md)
- [Archivo: perfil Azure heredado](archive/azure/README.md). B89 opera solo en AWS; no es destino de despliegue.

## Reglas de esta documentación

- Un tema, un documento. Si algo ya está en el código o en git, se enlaza en vez de repetirse.
- Cada afirmación de estado distingue **hecho y verificado**, **hecho sin verificar contra el
  proveedor real** y **propuesto**.
- Las decisiones nuevas se agregan como fila en [10-decisiones.md](10-decisiones.md), no como un
  archivo ADR nuevo.
