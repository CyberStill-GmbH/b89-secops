# Auditoría integral del SOC B89 y plan de mejora

Fecha: 2026-11-17. Alcance: lectura de arquitectura, ingesta, correlación, analista IA,
notificaciones y componentes frontend; revisión local del código y documentación. No es una
certificación de producción ni un pentest. Los despliegues y el acceso real a proveedores deben
validarse por separado.

## Resumen ejecutivo

La mayor oportunidad no consiste en agregar más modelos o más reglas: es cerrar el ciclo de
evidencia, desde la fuente hasta la decisión humana, con cobertura medible y visible. El SOC ya
tiene piezas útiles —correlador Go, checkpoints, persistencia de investigaciones, permisos y
expedientes— pero las garantías varían por integración y no todas están verificadas en vivo.
La UI debe mostrar con claridad cuándo hay cero alertas y cuándo una fuente dejó de consultar,
perdió cobertura o no alcanzó el Indexer.

## Alcance: todas las funciones del SOC

| Función | Mejora prioritaria |
| --- | --- |
| L1 / triage | Cola por prioridad y antigüedad, señales disparadoras, duplicados del caso y acciones autorizadas con motivo visible |
| L2 / investigación | Expediente con entidades tipadas, eventos paginados, hipótesis alternativas y vacíos explícitos |
| L3 / respuesta | Timeline, responsable, SLA, aprobaciones, tareas y acuse de notificaciones |
| Detection engineering | Corpus adjudicado, comparación baseline/candidato, métricas por regla y promoción/rollback con evidencia |
| Threat hunting | Búsquedas reproducibles, pivotes entidad-evento-alerta-caso y alcance consultado |
| Plataforma / integraciones | Checkpoints, timers, permisos, lag, reintentos, capacidad, retención y conciliación |
| SOC lead / manager | Backlog por prioridad/responsable, SLA, turnos y canales fallidos |
| CISO / auditoría | Tendencias trazables a incidentes y evidencia; `unknown`/`partial` nunca se grafica como cero |

Los permisos deben acompañar cada función. Cada herramienta MCP aplica tenant, capacidad,
aprobación y auditoría; la IA no requiere una cuenta privilegiada universal.

## Prioridad 0: cobertura y continuidad de las fuentes

**Hallazgo.** La salud y la actividad reciente no bastan para demostrar que un stream se consulta,
que sus páginas se agotan, que el cursor avanza ni que el Indexer recibe lo escrito. La auditoría
live del 2026-11-16 encontró temporizadores SharePoint deshabilitados; las ejecuciones anteriores
mostraban cero eventos, lo que por sí solo no prueba un error de Graph. En Cloudflare el colector
de auditoría y firewall funcionaba, pero el token devolvió 403 en los endpoints de Logpush. Por
tanto, la API adaptativa no acredita cobertura de todos los datasets.

**Mejora.** Una ficha de fuente debe informar producto/datasets configurados, permiso comprobado,
estado del scheduler, última consulta exitosa, watermark/lag, páginas agotadas, último evento,
registros leídos/escritos/indexados, brechas y retención. Diferenciar `sin eventos`, `deshabilitada`,
`permiso denegado`, `atrasada`, `parcial` y `fallida`. Un canario sintético por fuente debe recorrer
proveedor o sandbox → colector → JSONL duradero → Wazuh → Indexer → vista del SOC y conciliar
identificadores/conteos.

**Aceptación.** Simular caída superior a una hora, restauración, proveedor vacío, 401/403, página
repetida, límite de API, disco lleno y restart. El cursor no salta; la recuperación drena por lotes;
la consola enseña la brecha y se cierra solo tras conciliación del destino. Medir lag y tasa de
eventos perdidos por fuente y conservar evidencia de ejecución.

## Prioridad 1: investigación exacta y cobertura demostrable

**Hallazgos.** En `apps/api/src/assistant/analyst-evidence.ts`, las entidades de eventos se
relacionan mediante búsqueda de subcadena sobre JSON; esto puede unir identidades distintas, por
ejemplo `alice` y `malice`, o IPs con prefijos comunes. El proveedor se infiere desde el título de
alerta, un campo mutable. La lectura tiene topes: hasta 50 alertas por trabajo, 20 relacionadas,
ventanas de eventos paginadas, ocho eventos retenidos en algunos paquetes y límites de contexto.
Aunque ciertos topes generan `partial`, debe probarse que cada ruta que recorta datos invalide la
cobertura. El correlador también limita a 50 IDs de alerta en el resumen de candidato.

**Mejoras.** Comparar entidades con tipos y valores canónicos; leer fuente/proveedor desde campos
normalizados e inmutables. Usar cursores durables y referencias paginadas al expediente, con
resúmenes de evidencia por segmento. Separar tres conceptos: rango consultado por completo,
retención disponible en el proveedor y evidencia seleccionada para el modelo. El PDF debe mostrar
cada límite y enlaces a páginas adicionales, sin llamar «completo» a un paquete que perdió filas.
Para casos correlacionados, persistir membresía completa en almacenamiento durable; el límite de
IDs inline solo puede afectar al resumen, nunca a la investigación ni al reporte.

**Aceptación.** Fixtures adversariales de prefijo/sufijo, entidades homónimas y orden distinto;
pruebas por encima de cada límite conocido y lectores que paginan, omiten páginas o expiran. La
inferencia no cita eventos no incluidos; una cobertura incompleta no produce veredicto concluyente.

## Prioridad 1: calidad de detecciones y correlación

**Hallazgo.** Hay reglas versionadas y fixtures, pero la reducción de grupos repetidos no equivale
a una reducción medida de falsos positivos. Hace falta medir precisión y recall con alertas
etiquetadas por analistas y por fuente/prioridad, además de pérdidas, duplicados, ruido por regla y
tiempo hasta el caso correlacionado.

**Mejora.** Crear un ciclo de detección en modo sombra: corpus anonimizado y adjudicado, ejecución
de reglas nuevas contra baseline, reporte de alertas añadidas/retiradas y aprobación de detección
engineering antes de activar. En Go, versionar claves/ventanas de correlación y mantener un ledger
de miembros completo e idempotente. No fusionar casos solo por IP o coincidencia temporal; exigir
entidades normalizadas y una relación explicable. Reabrir o actualizar un caso cuando entre
evidencia nueva, sin repetir notificaciones por cada miembro.

**Aceptación.** Golden datasets por proveedor, regresión de severidad, pruebas de reloj fuera de
orden y cardinalidad 51+, replay idempotente, y KPI de precisión/recall con tamaño de muestra y
intervalos de confianza. Ninguna regla se declara «menos falsos positivos» sin la comparación.

## Prioridad 1: confianza y límites del analista IA

**Hallazgo.** El diseño de triaje y los controles presupuestarios existen, pero la precisión real
del modelo no está probada en un corpus adjudicado. Las acciones de cierre benigno requieren
guardas, pero la configuración autónoma y su impacto deben observarse de forma independiente. El
riesgo principal es presentar correlación o una hipótesis del modelo como evidencia.

**Mejoras.** Mantener shadow mode hasta medir desempeño por fuente, prioridad y tipo de evidencia;
medir precision, recall, calibración, abstención, falsos negativos P1, latencia y costo por
investigación. Exigir regla+entidad exactas, evidencia íntegra, fuentes sanas, sin TP conocido y
ausencia de corroboración actual para cerrar benignas. Añadir kill switch de análisis autónomo,
reapertura auditable con evidencia nueva y límites tenant-scoped para cada tool MCP. Registrar
consulta, referencias devueltas, decisión de política, versión de prompt/modelo y acciones, sin
copiar contenido sensible a los logs.

**Aceptación.** Evaluación temporal holdout, ataques de prompt injection en campos de alerta,
pruebas de permisos por tenant/rol, repetición idempotente y rollback. Ningún cierre automático P1/P2.

## Prioridad 1: notificaciones y respuesta

**Hallazgo.** Un HTTP 202 o la aceptación de Teams no demuestra que una persona recibió/atendió el
aviso. El operador necesita correlacionar alerta/caso → intento → entrega por canal → acuse humano →
escalación por timeout.

**Mejora.** Mostrar acuses y fallos reales por canal, edad del aviso, responsable, siguiente
escalación y un timeline único por caso. Usar dedupe por caso/urgencia, reintento con backoff y
fallback configurado; nunca suprimir P1 porque un canal está degradado. Mantener cambios de
contención bajo aprobación y separación de funciones.

**Aceptación.** Prueba Teams sandbox de punta a punta, webhook inválido, timeout, duplicado, caída
del worker y acuse posterior; verificar una sola escalación y audit trail completo.

## Prioridad 2: consola CISO y flujo de analista

**Mejoras para CISO.** Una portada con exposición, incidentes P1/P2 abiertos, fuentes fuera de
SLO, lag de ingesta, entrega/acuse de notificaciones, backlog, tendencia de severidad y evidencia
de controles. Cada cifra debe llevar periodo, fuente, frescura, definición y drill-down; `unknown`
no se presenta como cero. Añadir vistas ejecutivas de riesgo por servicio/activo/identidad y
seguimiento de compromisos, sin calcular puntuaciones opacas.

**Mejoras para analistas.** Cola persistible en URL, filtros guardados, triage masivo seguro,
timeline unificada, asignación/ownership y acciones rápidas. Las cartas del resumen deben exponer
las críticas directamente; el caso completo debe enlazar entidades, eventos, alertas relacionadas,
avisos, evidencias faltantes y próximos pasos. El PDF B89 debe poder descargarse directamente y
preservar fuentes, filtros, zona horaria, referencias, límites y auditoría; browser-print no es
equivalente a un PDF generado por el servidor.

**Aceptación.** Pruebas de accesibilidad con teclado/lector, navegación profunda compartible,
viewport móvil, estados loading/empty/error/partial y tiempos medidos para triage de un caso
sintético. Revisión humana de textos en español y exportaciones golden.

## Prioridad 2: operación, seguridad y gobierno

- Publicar runbook y prueba de recuperación/restauración; definir retención, legal hold, purga,
  capacidad y RTO/RPO con responsables. La cola durable no es retención ilimitada.
- Inventariar cada secreto/permisos por proveedor; usar el mínimo de lectura, alarmar renovación
  próxima y errores 401/403 sin imprimir valores.
- Verificar que IaC y runtime coincidan: hash de release, versión de reglas, timers, configuración,
  estado de DB y servicios. El panel debe detectar una unidad instalada pero deshabilitada.
- Revisar superficie MCP: exposición de red, autenticación, rate limit, scope de tools, protección
  SSRF, aislamiento tenant, redacción y presupuesto global. Un endpoint local no equivale a un
  servidor MCP externo listo para uso.
- Reconciliar alertas/casos/acciones y cambios de configuración con actor, motivo, ticket,
  aprobador y versión previa; habilitar exportación verificable para auditoría.

## Secuencia sugerida

1. **Cerrar visibilidad de fuente:** fuentes/temporizadores/checkpoints y conciliación Indexer;
   reparar las fuentes deshabilitadas y completar Logpush con permisos/datasets comprobados.
2. **Asegurar integridad de evidencia:** matching tipado, fuente canónica, cursores y límites
   explícitos en expedientes/reportes.
3. **Mejorar respuesta humana:** timeline de notificaciones, acuse y escalación P1 verificadas.
4. **Validar correlación/detección:** corpus adjudicado, baseline, métricas y ledger durable de
   miembros.
5. **Gated launch de IA:** shadow, scorecards, revisión humana y luego autonomía limitada solo
   para acciones con criterios y rollback aprobados.
6. **Pulir UX ejecutiva/analista y exportación PDF**, guiado por pruebas de tarea y accesibilidad.

## Fuentes internas revisadas

`docs/02-arquitectura.md`, `docs/06-operacion.md`, `docs/08-frontend-unificado.md`,
`docs/09-plan-de-lanzamiento.md`, `docs/10-decisiones.md`,
`docs/25-programa-confiabilidad-e-investigacion.md`,
`docs/27-aisoc-mcp-evaluacion-y-plan.md`, `apps/api/src/assistant/analyst-evidence.ts`,
`modules/assistant/src/investigations/`, `services/b89-correlator/internal/risk/engine.go`,
`wazuh/provider-ingestion/` y las vistas del plugin `b89_ops`.
