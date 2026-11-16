# Cloudflare Logpush: recepción durable de lotes locales

Fecha: 2026-11-16. Estado: adaptador local implementado y probado; **sin entrega Cloudflare real configurada ni verificada**.

## Contrato implementado

`wazuh/provider-ingestion/cloudflare/logpush.py` recibe un archivo NDJSON o gzip ya entregado a un spool local confiable. No publica un endpoint HTTP ni crea jobs Logpush. El proceso que descarga objetos debe escribir un archivo temporal y renombrarlo atómicamente cuando esté completo; después invoca el adaptador.

```sh
python3 wazuh/provider-ingestion/cloudflare/logpush.py \
  --input /var/spool/b89/cloudflare/object.json.gz \
  --output /var/log/b89/cloudflare-logpush.jsonl \
  --state /var/lib/b89/cloudflare-logpush.json \
  --dataset firewall_events --scope-id ACCOUNT_OR_ZONE_ID
```

Cada registro conserva su objeto original en `cloudflare.raw`, dataset, ámbito y SHA-256 del contenido descomprimido del lote. `firewall_events` añade campos compatibles con las reglas WAF existentes. Se conservan acciones permitidas, bloqueadas y desconocidas, y datasets nuevos. No hay filtro por severidad, prioridad ni veredicto.

La escritura usa el checkpoint previo, append y fsync del runtime común. Una interrupción después de escribir el lote y antes de confirmar el estado se recupera sin duplicar el append. Un archivo de bloqueo del sistema operativo evita dos escritores simultáneos sobre la misma salida. Debe utilizarse **un único estado por salida**, y no compartir la salida con otro colector. La huella combina ámbito, dataset y contenido: repetir el mismo lote no duplica registros; el mismo contenido en otro ámbito permanece separado. No deduplica eventos entre lotes diferentes: retenerlos es preferible a eliminar eventos legítimos sin un identificador estable del proveedor.

## Límites explícitos

- Entrada comprimida y expandida: 16 MiB; registro normalizado: 60 000 bytes; además aplica el máximo de lote del runtime común. Al excederlo, falla el lote sin confirmar estado. El archivo original se conserva para dividirlo o remediarlo; no se trunca silenciosamente.
- JSON malformado, claves duplicadas, NaN, valores no objeto y UTF-8 inválido rechazan el lote completo antes de escribir. No se imprime contenido de registros ni secretos.
- El ledger de SHA no se purga automáticamente y crece con los lotes. Se necesita plan de retención y almacenamiento durable antes de operación de alto volumen. No borrar estado mientras puedan repetirse objetos antiguos.
- El adaptador no borra ni rota el spool o la salida. Retención, rotación coordinada con Wazuh y capacidad de disco son requisitos de operación.
- La conservación local no prueba que Wazuh decodifique e indexe todos los campos: hay que validar tamaños, objetos anidados y datasets reales con logtest y reconciliación de conteos.

## Integración que falta para cobertura real

1. Inventariar cuentas, zonas, productos, datasets y campos habilitados por el plan de Cloudflare.
2. Configurar jobs Logpush por dataset/ámbito hacia un destino durable autorizado, sin filtros excluyentes ni sampling adicional. Registrar cualquier muestreo inherente al dataset.
3. Implementar el transporte de objetos al spool y ejecutar este adaptador con reintentos; confirmar objetos solamente después de salida exitosa. No exponer una entrada HTTP sin autenticación y límites.
4. Configurar `localfile` JSON de Wazuh y una regla base para datasets desconocidos; conservar registro bruto además de alertas y aplicar retención acordada.
5. Reconciliar cantidades por lote/dataset entre proveedor, spool, salida local e Indexer. Probar replay, reinicio, permisos denegados, disco lleno y retraso del destino antes de afirmar cobertura completa.

## Evidencia local

Comando: `python -m unittest discover -s wazuh/provider-ingestion/tests -p test_cloudflare_logpush.py`.
Seis pruebas pasan en CPython 3.14 de Windows: gzip y preservación de datos, replay exacto, ámbito/dataset desconocido, rechazo atómico de entradas inválidas, límites de expansión/registro, recuperación de caída tras append y vínculo del estado con la salida. Son pruebas sintéticas locales; no certifican recepción desde Cloudflare ni entrega al Indexer.
