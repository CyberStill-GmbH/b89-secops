# Correlación e investigación por episodio

## Estado comprobado el 18 de noviembre de 2026

La comprobación se hizo contra el árbol de trabajo local. El servicio se probó en Docker con Go 1.23.12 mediante `go test -race ./...`. La suite terminó con éxito. La prueba de exportación se ejecutó con `pnpm exec vitest run --config vitest.config.ts apps/api/test/ai-investigations.spec.ts` y pasaron los 16 casos.

| Objetivo | Comportamiento y alcance comprobado |
| --- | --- |
| Membresía durable | El resumen conserva hasta 50 alertas. El ledger de un solo escritor, ubicado en `B89_CORRELATOR_MEMBERS_DIR`, guarda alertas y observaciones por separado. La API pagina ambos conjuntos. La prueba de exportación recorre 101 referencias de cada tipo y comprueba los permisos. El anexo indica la fecha de consulta porque puede haber incorporaciones después del análisis. |
| Reglas temporales | La configuración de inicio admite ajustes por patrón con `B89_CORRELATOR_PATTERNS_JSON`. La explicación registra la ventana efectiva, etapas, mínimo de fuentes y versión. Las pruebas cubren las secuencias y la corroboración. |
| Identidad y contexto | La resolución de entidades usa valores canónicos. Los identificadores disponibles de organización y sesión aportan contexto de M365. El lector del expediente compara claves tipadas para evitar coincidencias parciales. La cobertura de estos campos depende del registro de origen. |
| Reinicio y repetición | El runner guarda el límite temporal de la última ventana terminada y reconstruye el estado al arrancar. Las pruebas de watermark y paginación cubren caída, ventana incompleta y checkpoint corrupto. El historial que aún pueda recuperarse depende de la retención del Indexer. |
| Candidato e incidente | El motor propone un candidato con evidencia vinculada. La gestión del incidente corresponde al SOC. Una revisión del candidato puede añadir miembros al expediente existente. |
| Evaluación | El evaluador compara predicciones explícitas de ambas versiones en las mismas ventanas adjudicadas. Desglosa resultados por familia, fuente y prioridad, con cobertura de anotaciones de duplicados. El criterio opcional de promoción identifica segmentos que ganan falsos positivos aunque el total mejore. La precisión y el recall operativos quedan pendientes de medir sobre episodios adjudicados del SOC. |
| Explicación | La proyección de riesgo incluye regla, versión, entidades, etapas, referencias, contradicciones y datos faltantes. El informe permite distinguir las citas de la investigación de la membresía consultada durante la exportación. |
| Operación | Las métricas distinguen lecturas, eventos procesados, duplicados, candidatos abiertos y actualizados. El estado de cobertura usa el heartbeat disponible y la ventana procesada. Una fuente sin evidencia suficiente requiere estado desconocido o incompleto. |

Los registros previos a la creación de un candidato solo pueden vincularse si el motor conservó las referencias de sus etapas o contribuciones. Una recuperación tras reinicio requiere persistir el volumen y mantener acceso al historial. La aceptación del despliegue deberá comprobar ambos extremos con el volumen real.

El 18 de noviembre se verificó el reemplazo del proceso en Docker. Un contenedor con UID/GID 65532 escribió un episodio sintético y confirmó la emisión de su alerta. Tras retirar ese contenedor, otro abrió el mismo volumen, localizó el episodio por la alerta emitida y recuperó las 101 referencias vinculadas en tres páginas y las dos observaciones de origen. Ambos trabajaron sin red y con el sistema de archivos raíz en solo lectura. La prueba ejercita el almacenamiento del motor con Docker local. La retención del Indexer y el montaje del host AWS requieren comprobación en ese entorno.

La prueba se reproduce desde la raíz del repositorio con `services/b89-correlator/scripts/test-volume-replacement.ps1`. El script crea y retira su propio volumen. En la validación local se ejecutaron sus comandos Docker directamente porque Windows restringe la ejecución de archivos PowerShell.

Para reproducir la comparación, prepara las ventanas adjudicadas y ejecuta el [replay pareado](../../services/b89-correlator/cmd/replay-corpus/README.md) con las dos configuraciones de patrones y la misma instantánea de observaciones. El comando genera predicciones con dos instancias independientes del motor Go. Conserva ventanas sin detección y rechaza aperturas fuera del marco adjudicado. La [guía del evaluador](../../services/b89-correlator/cmd/evaluate-corpus/README.md) explica cómo interpretar los conteos, el resultado sintético y los códigos de salida.

## Cómo rastrear una alerta hasta su candidato

La API guarda el identificador estable del candidato (`rc_…`) en cada nueva alerta emitida por el correlador. El analista abre el expediente por ese identificador aunque el candidato haya salido de la lista reciente. Para una alerta histórica, la consulta interna `GET /v1/candidates-by-alert/{alertId}` busca el candidato que la emitió. Al reiniciar, el servicio reconstruye el índice a partir de los archivos que conservan ese vínculo.

El lector recorre las alertas asignadas y sus relaciones explícitas. Una prueba de regresión recupera 52 asignadas y 24 relacionadas. El contexto enviado al modelo conserva su propio presupuesto de tokens. La suite local completa de la API pasó las 479 pruebas de 39 archivos y la comprobación de tipos. En Docker, el correlador pasó `go test -race ./...` con Go 1.23.12, incluidas las pruebas de persistencia del vínculo, reinicio y replay.

Al revisar un expediente, conserve el ID de la alerta, el ID del candidato y la fecha de consulta de sus miembros. Las citas del informe identifican la evidencia utilizada en el análisis original. Una consulta posterior puede incluir incorporaciones más recientes. Si falta el registro de membresía de una alerta histórica, su vínculo queda sin confirmar.

La calidad de la agrupación sigue pendiente de evaluación con un corpus etiquetado por analistas. Para medir la variación de falsos positivos y de recall, ambas versiones deben procesar los mismos episodios adjudicados.

## Historial de diseño

Estado: implementación local, 2026-11-15. Sin despliegue ni medición de precisión en producción.

## Decisión de arquitectura

Se conserva el correlador Go existente. No se incorpora otro motor en Rust: en esta revisión no
se ha demostrado un cuello de botella que justifique duplicar resolución de entidades, estado,
reglas y operación. Un lenguaje distinto no elimina investigaciones duplicadas ni convierte
una correlación temporal en evidencia de compromiso. El trabajo prioritario es conectar la
identidad del candidato con la investigación y conservar sus miembros y revisiones.

El código ya tiene deduplicación por ID de observación, resolución de entidades, ventanas,
amortiguación de repetición por regla y candidatos explicables por patrón o umbral. La
agrupación estadística de `DedupAlerts` no es un expediente durable. Varios patrones pueden
producir candidatos superpuestos para una entidad; no deben ocultarse técnicas distintas
por compartir usuario o IP. Una futura consolidación entre candidatos necesita una identidad
de caso persistida y reglas explícitas de fusión, no solamente igualdad del pivote.

## Defectos corregidos

1. La admisión de miembros solo comprobaba límites superiores de tiempo. Una observación
   arbitrariamente antigua podía sumarse a un candidato actual. Ahora se exige pertenecer
   al intervalo desde `FirstSeen`, además del gap y duración máxima existentes. Las llegadas
   tardías dentro del intervalo siguen admitidas sin retroceder `LastSeen`.
2. Un candidato conservaba las fuentes y tácticas originales aunque recibiera nueva evidencia.
   Ahora incorpora fuentes y tácticas no suprimidas de los miembros nuevos. La IA puede
   reconocer corroboración posterior y evitar reutilizar una conclusión benigna obsoleta.
   La actualización copia las listas para no modificar instantáneas previamente entregadas.

No se cambia la severidad, no se cierra una alerta automáticamente y no se elimina evidencia
original del Indexer. El historial de falsos positivos debe servir para evitar inferencia
repetida solo cuando el contexto sigue siendo equivalente y suficientemente cubierto.

## Límites registrados el 15 de noviembre, antes del ledger

- `B89AlertIDs` conserva como máximo 50 referencias; la explicación también limita los IDs.
  Son proyecciones, no una prueba de cobertura exhaustiva. No se debe prometer un informe
  completo sin recuperar y verificar todos los miembros mediante paginación durable.
- Los candidatos se mantienen en memoria. Reinicios y actualización de miembros requieren
  reconciliación con el almacén durable de investigaciones.
- Actualizar fuentes/tácticas no reescribe una notificación ya enviada ni el título histórico.
  El consumidor debe revisar la nueva evidencia y decidir si amerita una revisión del informe.
- Menos grupos no significa menos falsos positivos. La medición exige casos adjudicados,
  recall de verdaderos positivos, cobertura y volumen comparable.

## Validación inicial

Regresión: `internal/risk/candidate_members_test.go`. Comprueba rechazo de eventos históricos,
admisión de evidencia tardía válida, actualización de nuevas fuentes/tácticas, inmutabilidad
de las listas anteriores y deduplicación de relecturas. Ejecución del paquete completo con
detector de carreras en Docker; registrar resultado real antes de considerar validada la entrega.

Para evaluar otra herramienta, primero medir CPU, memoria, demora de correlación, volumen,
calidad de agrupación y coste por investigación en este flujo. Una comparación Rust/Go solo
se acepta con el mismo corpus, presupuesto y semántica de detección; no hay benchmark de
Rust en esta entrega ni ahorro de tokens cuantificado.
