# Comparación de versiones en un periodo reservado

Ejecutar desde la raíz del módulo Go con las predicciones de dos versiones sobre las mismas ventanas adjudicadas.

```sh
go run ./cmd/evaluate-corpus -input corpus.json -output informe.json -require-fp-reduction
```

El informe reúne las matrices de confusión de ambas versiones en `overallBaseline` y `overallCandidate`. Cuenta una sola vez cada ventana compartida entre familias. Las etiquetas ambiguas quedan fuera de las métricas. Conviene inspeccionar las familias por separado para identificar regresiones que una mejora global pueda ocultar.

La opción adicional exige una reducción significativa en la prueba exacta pareada de McNemar sobre los negativos adjudicados. El ejecutable devuelve 3 ante pérdida de un positivo conocido o un P1 protegido, 4 ante muestra insuficiente y 5 cuando la reducción exigida carece de evidencia. El informe queda disponible en los tres casos. Para automatizar por código de salida, compilar el binario con `go build ./cmd/evaluate-corpus` y ejecutarlo directamente.

Para revisar una promoción por fuente, familia y prioridad, añade `-require-no-slice-fp-increase`. Si un segmento acumula más falsos positivos que en la base, el comando identifica el segmento, muestra ambos conteos y devuelve 6. Este criterio operativo es estricto incluso con un solo caso adicional. La significación estadística global sigue disponible por separado.

Cada ventana debe incluir dos predicciones booleanas explícitas. Un campo omitido o nulo invalida la entrada y el comando devuelve 2. Para comparar duplicados, anota `baselineDuplicate` en cada detección de la base. Si falta alguna anotación, el informe devuelve `baselineDuplicates: null` en los segmentos afectados y detalla cuántas detecciones se anotaron.

## Resultado sintético de referencia

`TestRunPassesOnlyWithSufficientEvidenceAndNoRegressions` construye 200 ventanas etiquetadas y 1 000 eventos elegibles. Ambas versiones detectan los 20 positivos. De las 180 ventanas negativas, la versión base alerta en 20. La primera variante candidata alerta en cero y supera el criterio. La segunda alerta en las 180 y devuelve 5. Reproducir con `go test ./cmd/evaluate-corpus -run TestRunPassesOnlyWithSufficientEvidenceAndNoRegressions -v`.

Este ensayo utiliza predicciones sintéticas para verificar el evaluador. La medición de una regla en operación requiere ejecutar las dos versiones en modo sombra sobre la misma instantánea y aportar adjudicaciones independientes de los analistas.
