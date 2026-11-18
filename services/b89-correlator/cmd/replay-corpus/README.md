# Replay pareado de configuraciones de patrones

Desde la raíz del módulo Go, usar una instantánea local de observaciones normalizadas y un marco de adjudicación independiente. El ejecutable escribe un corpus UTF-8 en stdout al terminar la validación. Estos comandos usan redirección de un shell POSIX. En Windows PowerShell 5.1 usar `cmd /c` para la redirección del binario, ya que PowerShell puede convertir la salida a UTF-16.

```sh
go build -o replay-corpus ./cmd/replay-corpus
./replay-corpus -frame marco.json -observations observaciones.json > corpus.json
go run ./cmd/evaluate-corpus -input corpus.json -output informe.json -require-fp-reduction
```

## Entradas

`observaciones.json` contiene un array JSON de `model.Observation` en orden de llegada (`IngestedAt` ascendente, orden del archivo para empates). Cada fila necesita `ID`, `Source`, `RuleID`, `Time` e `IngestedAt`. Cada entidad requiere la entrada de `Provenance` que produce el normalizador, con su clave y confianza. Conservar las relaciones de igualdad y las diferencias entre valores al seudonimizar entidades, ubicaciones, tenants y sesiones. Un ejemplo sintético de fila es

```json
{"ID":"event-01","Source":"linux","RuleID":"rule-01","Level":7,"Time":"2026-01-01T23:58:00Z","IngestedAt":"2026-01-02T00:01:00Z","TimeSource":"provider","Entities":[{"type":"ip","value":"ip-01"}],"Provenance":{"ip:ip-01":{"key":"ip:ip-01","field":"srcip","method":"exact","confidence":"high"}},"Stages":["ssh.success"]}
```

Ejemplo de `marco.json`. Sustituir el marcador del digest por el SHA-256 hexadecimal de los bytes exactos de la instantánea. Los dos arrays de patrones aceptan el formato de overrides del servicio. `[]` selecciona sus valores por defecto.

```json
{
  "CorpusID":"holdout-01",
  "SourceSnapshotSHA256":"<sha256>",
  "AnnotationProtocol":"double-review-v1",
  "EvaluationStart":"2026-01-02T00:00:00Z",
  "EvaluationEnd":"2026-01-03T00:00:00Z",
  "BaselinePatterns":[],
  "CandidatePatterns":[{"ID":"ssh-bruteforce-then-access","Window":"1h"}],
  "Families":[{
    "PatternID":"ssh-bruteforce-then-access",
    "EligibleSourceEvents":1,
    "Windows":[{
      "ID":"w-01","EntityKey":"ip:ip-01","Source":"linux",
      "Start":"2026-01-02T00:00:00Z","End":"2026-01-03T00:00:00Z",
      "Label":"negative","BaselinePriority":"P3","DuplicateGroup":"episode-01"
    }]
  }]
}
```

Construir el marco con ventanas positivas, negativas y ambiguas, incluidas las ventanas sin alerta. Registrar `EligibleSourceEvents` según el criterio de elegibilidad del protocolo en el periodo reservado. El operador aporta ese denominador, la fuente adjudicada y la cobertura de la instantánea. El programa comprueba la integridad de los bytes. La exhaustividad de la adjudicación y de la recogida requiere verificación externa.

## Atribución y alcance

- Cada variante arranca con un motor independiente en memoria, política de riesgo por defecto y los patrones de su configuración. El identificador de versión deriva de los fingerprints de todos los patrones efectivos. Registrar también la revisión Git del binario para reproducir el código ejecutado. Este comando compara configuraciones dentro de una misma compilación.
- Los dos motores procesan la misma secuencia completa. Los eventos llegados antes del inicio preparan el historial y los episodios. Incluir el historial anterior relevante, especialmente los 30 días de ubicaciones para la regla que detecta una ubicación nueva. La poda usa el reloj de llegada, al inicio y en la primera llegada transcurrida al menos una hora desde la poda anterior.
- La coincidencia usa `Time`. Se atribuye la apertura al instante en que llegó la observación que permitió conocerla (`IngestedAt`), incluso si el último paso de la secuencia ocurrió antes. Todos los límites son intervalos semiabiertos `[Start, End)`. Se rechazan llegadas desde el final del periodo en adelante. Las ventanas deben quedar enteras dentro del periodo.
- Se cuenta una apertura de candidato activo o sombra por patrón, entidad y ventana. El proceso corre sin red, feedback, supresiones, enriquecimiento, emisión, escrituras de servicio ni enlaces a alertas B89. Las actualizaciones de un episodio existente y los candidatos por umbral quedan fuera de esta métrica de aperturas. La prioridad base corresponde a la apertura. Para una ventana sin apertura base, se toma la prioridad adjudicada.
- Se rechazan aperturas de una familia seleccionada que carecen de ventana, ventanas solapadas del mismo patrón y entidad, o dos aperturas de la misma variante en una ventana. Adjudicar cada apertura en una ventana apropiada antes de repetir la evaluación. La salida retiene todas las ventanas sin aperturas.
- `DuplicateGroup` identifica ventanas que analistas atribuyen al mismo episodio del mismo patrón y entidad. Asignar una clave propia a cada episodio independiente. Dentro del periodo se marca duplicada la segunda apertura y las sucesivas del grupo para cada variante por separado. Conservar la fuente y prioridad para los cortes del evaluador.
- Cada archivo de entrada y el corpus serializado están limitados a 32 MiB. El comando valida el corpus con el evaluador antes de escribirlo. El replay sintético de las pruebas comprueba la mecánica. La eficacia operacional requiere datos y etiquetas representativos.

Ejecutar `go test -race ./cmd/replay-corpus` para verificar la atribución temporal de una observación tardía, los grupos duplicados independientes, las no detecciones y el rechazo de marcos inconsistentes.
