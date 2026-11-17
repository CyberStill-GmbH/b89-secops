# Cloudflare: recuperación de intervalo fijo

Fecha: 2026-11-16. CLI local implementada; no demuestra entrega al portal.

`wazuh/provider-ingestion/cloudflare/backfill.py` recupera auditoría y eventos de firewall adaptativos hacia un JSONL y checkpoint aislados del colector regular. Debe ejecutarse un solo escritor por salida.

```sh
python3 wazuh/provider-ingestion/cloudflare/backfill.py \
  --config /etc/b89-collectors/cloudflare.json \
  --since 2026-11-16T05:00:00Z --until FECHA_FINAL_UTC \
  --output /var/lib/b89-recovery/cloudflare-20261116.jsonl \
  --state /var/lib/b89-recovery/cloudflare-20261116.state.json
```

El inicio corresponde a las 00:00 del 16 de noviembre en Lima. Fijar el final una vez y conservarlo al reanudar. El checkpoint queda vinculado al intervalo y salida; rechaza reutilización para otra ventana. Nunca usar los archivos de estado/salida del colector activo. La herramienta rechaza coincidencias con las rutas de producción presentes en la configuración.

Cada lote se confirma con el mecanismo durable compartido: checkpoint previo, append, fsync y confirmación. Al reanudar no vuelve a escribir un stream terminado. Un fallo de una zona no bloquea las demás. Si no avanza el cursor, conserva el punto anterior y registra un fallo. Salida 0: streams solicitados terminaron; salida 2: uno o más streams fallaron; salida 1: error global.

La cobertura siempre declara `exhaustive=false`: la API adaptativa no equivale a todos los datasets ni prueba ausencia de muestreo. Auditoría se filtra al intervalo semiabierto solicitado después de la lectura y conserva el límite de páginas del colector; excederlo falla visiblemente. La recuperación no modifica automáticamente Wazuh, no elimina originales ni deduplica contra eventos ya procesados por el colector regular. Antes de incorporarla al portal se requiere reconciliar identificadores, configurar ingesta y verificar conteos de entrada e Indexer. La hora del evento original está en el payload; la recepción tardía debe distinguirse de ella.

Pruebas: `python -m unittest discover -s wazuh/provider-ingestion/tests -p test_cloudflare_backfill.py`: 5/5 pasan (reanudación sin doble append, aislamiento de zona denegada, falta de progreso, rechazo de rutas activas, límites temporales de auditoría). Datos sintéticos locales; sin ejecución contra Cloudflare.
