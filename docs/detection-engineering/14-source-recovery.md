# Recuperación automática tras interrupciones de fuentes

Fecha: 2026-11-16. Estado: política y runtime locales probados; despliegue y aceptación de extremo a extremo pendientes.

## Objetivo y límites

Una fuente silenciosa no equivale a una fuente sana ni a ausencia de ataques. Al recuperar conectividad, el colector debe continuar desde el último intervalo confirmado en almacenamiento durable, y no desde la hora actual. La recuperación está limitada por la retención y los permisos del proveedor. Ningún consumidor puede reconstruir eventos que el proveedor nunca conservó o ya eliminó. La API adaptativa de Cloudflare tampoco representa todos sus datasets.

## Implementación

El runtime `common/b89_collector.py` permite activar recuperación inmediata por lotes mediante:

```json
{
  "catchup_cursor_field": "firewall_cursors",
  "catchup_max_batches": 4,
  "catchup_delay_seconds": 120
}
```

El instalador configura esta política para Cloudflare. Cada ejecución fija una meta temporal, consulta desde los checkpoints existentes y confirma cada lote con el protocolo durable ya implementado: checkpoint de escritura, append, fsync y confirmación del cursor. El lote siguiente recibe el estado confirmado. Un fallo posterior conserva el progreso anterior; no obliga a empezar desde ahora ni a descartar el atraso.

La política admite entre 1 y 10 lotes por ejecución. Al agotar el presupuesto, deja `recovery.status=catching_up`, `lag_seconds`, `target` y número de streams en el estado. El timer inicia otra ejecución después del intervalo configurado. Los timers generados pasan a `OnUnitInactiveSec`, para programar desde la terminación y evitar que un proceso largo altere la cadencia prevista. La ejecución sigue siendo un servicio oneshot único; no debe lanzarse un segundo escritor manual sobre los mismos archivos.

Un retroceso del cursor o desaparición de un stream impide confirmar el lote. Un cursor sin progreso deja estado `stalled` y código de salida de fallo. El retraso y el estado se escriben también al journal sin contenido de eventos. `last_success` significa escritura local exitosa, no cobertura completa ni recepción en el Indexer. Solo watermarks que representan intervalos explorados pueden activar esta política: el timestamp del último evento de auditoría, por ejemplo, puede permanecer antiguo en una cuenta sin cambios y no sirve para decidir atraso.

## Flujo operativo

1. Detectar silencio con dos señales independientes: última ejecución del colector y último evento recibido. Diferenciar permisos denegados, proveedor inaccesible, fuente legítimamente inactiva y destino bloqueado.
2. Mantener el checkpoint ante fallo. El timer existente reintenta; al volver el proveedor, drenar lotes hasta el presupuesto de ejecución y continuar en el siguiente ciclo.
3. Registrar brechas de retención como incidentes de cobertura. No avanzar silenciosamente el cursor para ocultarlas. Resolver mediante un archivo histórico o Logpush cuando exista; cualquier abandono de un rango exige una decisión explícita y auditada.
4. Reconciliar conteos por stream/intervalo entre proveedor, JSONL durable, Wazuh y el Indexer. Guardar identificadores/hash para reconocer reenvíos; no eliminar registros por coincidencia aproximada de IP o texto.
5. Cerrar la incidencia de cobertura únicamente después de demostrar recuperación y recepción. No basta con que el servicio vuelva a estar activo.

## Pendientes explícitos

- La metadata de recuperación está en el archivo de estado y journal; aún no se publica en el panel de salud ni genera una notificación específica.
- Los demás proveedores conservan su comportamiento actual hasta definir watermarks y semántica de replay propios. No hay garantía universal de recuperación para APIs de snapshots o ventanas ya vencidas.
- Cloudflare conserva el checkpoint al saturar la API o agotar la paginación, pero puede requerir Logpush o intervención para avanzar. El runner no ignora esas restricciones.
- La atomicidad local no sustituye el acuse del Indexer. Rotación, espacio de disco y lectura tras reinicio requieren prueba operativa; no se certifica entrega completa con pruebas unitarias.

## Validación

`python -m unittest discover -s wazuh/provider-ingestion/tests -p test_source_recovery.py`: 7 pruebas pasan. Cubren drenaje progresivo, presupuesto acotado, rollback del cursor, ausencia de progreso, fallo después de un lote confirmado, desaparición de stream y colectores no elegibles. La suite existente `test_b89_collectors.py` se ejecuta como regresión del runtime compartido.
