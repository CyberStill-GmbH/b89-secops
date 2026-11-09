# 19 · Brechas y roadmap

> Estado al 2026-11-08. Análisis de brechas del SOC B89 frente a un SOC de referencia, con el estado
> de cada línea de trabajo. «En curso» significa que otro agente la está construyendo y **aún no hay
> código fusionado** en la rama; se actualiza cuando aterriza. Postura y límites estructurales en
> [21](21-postura-de-seguridad.md).

| # | Brecha | Impacto | Estado | Responsable / dónde |
| --- | --- | --- | --- | --- |
| 1 | **Cobertura de endpoints**: no hay agentes en equipos ni servidores de B89; solo el propio nodo (`001`) | La mayoría de reglas de endpoint, AD, FIM, SCA y vulnerabilidades no ven el parque real | Abierta. Enrolamiento listo (puertos 1514/1515 abiertos, contraseña, grupos y políticas) | TI de B89 + plataforma; [AGENTS.md](../infra/aws-poweruser/AGENTS.md), [16](16-politicas.md). Otro agente trabaja en detección de conexiones de red y en aprovechar más capacidades de Wazuh |
| 2 | **Correlación y alertas basadas en riesgo** con resolución de entidades (UEBA-lite) | Hoy la correlación es por regla (`if_matched_sid`, ventanas) y la agrupación en incidentes es manual | En curso (servicio en Go) | Otro agente; enlace pendiente |
| 3 | **Retroalimentación del veredicto del analista** para falsos positivos | El veredicto se registra en el triaje, pero no ajusta reglas ni umbrales | Parcial: veredicto en la cola de alertas y cierre auditado por regla con `detections/tools/close-false-positives.mjs`; falta el bucle automático hacia las reglas | Ingeniería de detección; [17](17-ingenieria-de-deteccion.md) |
| 4 | **Métricas del SOC**: MTTD, MTTA, MTTR y SLA por prioridad | Sin medición no hay gestión del servicio | Abierta. SLA P1–P4 definidos en [detection-engineering/03](detection-engineering/03-modelo-operativo.md); la vista de calidad de detección existe, el cálculo de tiempos no | Por asignar |
| 5 | **Inteligencia de amenazas / coincidencia de IOC** | Sin enriquecimiento ni detección por indicadores conocidos | Abierta | Por asignar (candidatas: listas CDB de Wazuh alimentadas por un feed) |
| 6 | **Silencio de fuentes y salud de la plataforma** | Una fuente que deja de enviar pasa inadvertida | En curso (Python). Hoy: «Salud de fuentes» para la ingesta del motor y «Integraciones» con último evento por proveedor | Otro agente; enlace pendiente |
| 7 | **Priorización de vulnerabilidades** con CISA KEV y EPSS | Snyk y Wazuh priorizan solo por CVSS/severidad | En curso (Python) | Otro agente; enlace pendiente |
| 8 | **Respaldos sin IAM y riesgo de nodo único** | Sin DLM ni subida automática a S3; un fallo del nodo o del disco detiene todo el SOC | Abierta. Respaldo manual documentado en [06 §6](06-operacion.md#6-respaldos-y-restauración), sin ensayo de restauración | Plataforma; requiere rol IAM o tarea programada desde una estación |
| 9 | **Cobertura de M365 bloqueada** por permisos de Entra | Sin auditoría de M365/Entra: la fuente de identidad principal queda ciega | Bloqueada: faltan `ActivityFeed.Read` (y `SecurityAlert.Read.All`/`SecurityIncident.Read.All` para `ms-graph`); `Mail.Send` bloquea el correo | Administrador de Entra de B89; [18](18-integraciones.md#microsoft-365--entra-id) |
| 10 | **Deception / canary tokens** | Sin señales de alta fidelidad ante intrusión | Abierta | Por asignar |
| 11 | **Ciclo cerrado Respond ↔ incidentes** | Las ejecuciones de B89 Respond no quedan en el incidente ni en la auditoría B89 | Abierta. Playbooks exportables con puerta de aprobación (`b84562e`); contención deshabilitada por defecto (decisión B12) | Por asignar; [13](13-b89-respond.md), [14](14-b89-respond-conexion-b89.md) |

## Orden sugerido

1. **#9 y #1** (decisiones de B89, no de código): conceder permisos de Entra y enrolar agentes
   multiplican la cobertura sin desarrollo.
2. **#8**: respaldo y restauración ensayados antes de depender del SOC.
3. **#6, #7, #2** al fusionarse el trabajo en curso.
4. **#4 y #3**: métricas y bucle de veredicto, para medir y reducir ruido.
5. **#11, #5, #10**.

## Cómo se actualiza

Cada agente que fusione trabajo de una brecha cambia su fila (estado, enlace al documento o al
código) en el mismo commit. Una brecha se cierra solo con evidencia: prueba automatizada o
verificación en el nodo con fecha.
