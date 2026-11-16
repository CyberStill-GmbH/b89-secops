# Cloudflare: precisión y cobertura de las detecciones

Fecha: 2026-11-16. Estado: cambios locales; sin despliegue ni aceptación de proveedor.

## Defectos corregidos

| Caso | Comportamiento corregido |
| --- | --- |
| Operación administrativa fallida | Las reglas que describen cambios DNS, controles, identidad y eliminación de zona exigen `audit.result=true`. Una tentativa fallida conserva la regla 101502. |
| Lectura administrativa | `get`, `list`, `read`, `view` y `search` no se presentan como modificaciones de DNS, controles o credenciales. Permanecen en auditoría. |
| Purga de zona | `purge` deja de activar la regla de eliminación de zona 101507. Una purga no demuestra eliminación. `delete` y `deleted` exitosos conservan severidad 12. |
| Tipo DNS | La coincidencia `dns.record` usa PCRE2 explícito con punto escapado, conservando el tipo exacto. `dnsXrecord` es un control negativo. |
| Eventos firewall restantes | La regla base 101512 pasa de nivel 2 a 3 para que eventos como `skip` puedan indexarse con el umbral habitual de alertas 3. No implica peligro ni escalación. |
| Otros conjuntos Logpush | La regla 101514 conserva visibilidad de `event_type=logpush` a nivel 3, sin clasificar como ataque un registro genérico. Un fixture `gateway_dns` verifica el contrato. |

La colección de logs y la detección son contratos distintos. El cambio de nivel solo mejora la
visibilidad de los eventos firewall que llegan al manager; no hace exhaustiva una API muestreada,
no agrega conjuntos de Cloudflare y no garantiza recepción de registros no emitidos por el proveedor.
La retención de todos los logs debe comprobarse en el canal de archivo de eventos, además del índice
de alertas. Las reglas de reducción de ruido existentes siguen vigentes.

## Evidencia y validación

La suite `collector-cases.jsonl` incorpora diez casos negativos y uno de recepción Logpush:
cinco operaciones fallidas, tres lecturas, una purga y un tipo DNS parecido. Los casos positivos existentes conservan sus
expectativas: cambio de control, eliminación de control, credencial y eliminación de zona.

`python detections/tools/b89_detections.py lint`: 42 casos de uso, 298 reglas, cero errores;
14 avisos previos de nomenclatura en reglas AWS y del servicio de proveedores.

La aceptación exige ejecutar `wazuh-analysisd -t` y `wazuh-logtest` con las reglas instaladas
en un manager desechable. El lint no demuestra orden de coincidencia ni correlación temporal.
También se debe verificar el umbral real `log_alert_level` y la llegada de un evento Cloudflare
autorizado después del despliegue. No se atribuye una reducción porcentual de falsos positivos
a estas pruebas sintéticas.

### Resultado local de Wazuh

Manager desechable `wazuh/wazuh-manager:4.14.8`, Docker Desktop, sin red:
árbol de trabajo sobre `ba212c97f6092c702875653938e69fc15aa2d290` con estos cambios sin commit.

- `wazuh-analysisd -t`: código 0.
- Suite collectors: **60/60** casos correctos (seis refinamientos del catálogo).
- Cloudflare noise-tuning: **67/67**; waf-attack-surge: **56/56**.
- [Salida íntegra de collectors](evidence/2026-11-16/cloudflare-collectors-logtest.txt).

La primera ejecución detectó una incompatibilidad del patrón DNS con el motor predeterminado.
Se fijó `type=pcre2` y se repitieron los 60 casos completos con éxito. La prueba final envía
los JSONL mediante `subprocess.run(..., input=bytes)` a `docker exec -i ... wazuh-logtest`;
compara con `b89_detections.py check-logtest ... --suite collectors`. No se ejecutaron
acciones ni consultas contra Cloudflare real.
