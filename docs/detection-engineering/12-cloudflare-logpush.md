# Cloudflare Logpush: entrega HTTP, spool durable y detección

Fecha: 2026-11-18. Estado: receptor, consumidor, reglas y aprovisionamiento de jobs implementados y
probados. **Los jobs se crean solo cuando el token de Cloudflare tenga «Logs: Write» (zona).**
Hasta entonces el receptor queda listo y el instalador lo informa.

## Qué cubre

| Origen | Cómo llega | Reglas |
| --- | --- | --- |
| Eventos de firewall/WAF | Logpush `firewall_events` + API GraphQL adaptativa de respaldo (`security.py`) | 101510?101513, 101539?101544 |
| Auditoría de cuenta | API REST (`security.py`) | 101501–101507 |
| **Peticiones HTTP** (`http_requests`) | Logpush → HTTPS → receptor | 101515–101522 |
| **DNS autoritativo** (`dns_logs`) | Logpush → HTTPS → receptor | 101525–101528 |

Auditoría de cuenta sigue por API. Mientras Logpush no está activo, el firewall usa GraphQL adaptativo; al activar los jobs se apaga ese respaldo para evitar duplicados. Desde 2026-09-30 Cloudflare ofrece
Logpush en todos los planes con precio por uso (25 GB/mes incluidos por exportación externa).

## Historia y continuidad sin Logpush

Logpush no recupera el pasado: solo envía lo que ocurre desde que el job existe. Para no perder nada:

- **`traffic.py`** (timer de 2 min) lee `httpRequestsAdaptive` y `dnsAnalyticsAdaptive` de la API
  GraphQL. En todos los planes conservan **31 días** de registros individuales, **muestreados**.
  - **Arranque:** empieza 30 días atrás y recupera en lotes de hasta 40 000 registros, sin saturar
    Wazuh.
  - **Después:** sigue en vivo con 5 min de retraso.
  - **Al activarse Logpush:** el instalador escribe `state/cloudflare-logpush-active-since` y el
    collector termina en ese instante, sin duplicar.
  - **Marcado:** los eventos llevan `b89.source=graphql-history|graphql-live` y `b89.sampled=true`.
  - **Reglas:** las de ráfaga (frecuencia) cuentan solo Logpush; el muestreo y la entrega por lotes
    las falsearían. Un sondeo histórico entra a nivel 3 (101523); uno en vivo, a nivel 6 (101516).
- **`backfill.py --mark-history`** recupera firewall (31 días) y auditoría (hasta 18 meses) anteriores
  al arranque del collector de API. Los eventos llevan `b89.history=true` y caen en 101508/101509
  (nivel 3). Un cambio antiguo queda visible sin avisos ni investigaciones como si fuera de hoy.
- **Antes de 31 días:** Cloudflare solo conserva totales diarios (`httpRequests1dGroups`), no
  registros. Eso no se puede recuperar como logs.

## Circuito

```
Cloudflare jobs (b89-http-requests / b89-firewall-events / b89-dns-logs, por zona)
  → POST https://<SOC_HOSTNAME>/hooks/cloudflare-logpush/<dataset>/<zone_id>
     cabecera X-B89-Logpush-Token (header_… en destination_conf)
  → edge nginx (solo POST, 33 MB, límite de tasa)
  → contenedor cloudflare-logpush (receiver/logpush-receiver.mjs)
       token en tiempo constante · dataset permitido · tmp/ → rename → incoming/ · 503 si el spool está lleno
  → b89-collector-cloudflare-logpush.timer (cada 1 min, logpush_spool.py)
       logpush.ingest por lote, en orden · done/ (24 h) · failed/ (7 días) · latido en state/cloudflare-logpush.json
  → /var/ossec/logs/b89-collectors/cloudflare-logpush.jsonl (<localfile> json) → reglas 1015xx y alertas legibles
```

- **Secreto compartido:** `/opt/b89/secrets/collectors/cloudflare-logpush-token` (48 hex, 0600).
  Lo genera `prepare-logpush-receiver.sh` si no existe y nunca se imprime. Para rotarlo hay que
  borrarlo, volver a ejecutar el instalador de collectors (reconcilia los jobs con el destino nuevo)
  y recrear el contenedor.
- **Validación de Cloudflare:** el objeto de prueba `{"content":"tests"}` se acepta y no genera eventos.
- **Reenvíos:** se suprimen por SHA-256 de lote (ámbito + dataset + contenido). El ledger guarda los
  últimos 20 000 lotes.
- **Rotación:** la salida rota a los 512 MB y se conserva una generación anterior.
- **Errores:** un lote con contenido inválido pasa a `failed/` sin bloquear la cola. Un error
  transitorio deja el lote en `incoming/` y detiene la pasada para respetar el orden.
- **Volumen:** cada petición HTTP y cada consulta DNS entran a nivel 0, sin alerta. Solo alertan los
  patrones: sondeo de rutas sensibles, escaneo, ráfagas de 4xx/5xx, métodos anómalos, AXFR/IXFR y
  enumeración por NXDOMAIN.
- **WAF y ataques web:** el job pide acción, origen, ID/explicación de regla, categorías y referencias de firmas y, si el plan las ofrece, puntuaciones SQLi/XSS/RCE. Las reglas 101539/101540 detectan nombres de reglas que indican inyección; 101541/101542 detectan también categorías de firma como SQLi, XSS, RCE, SSRF, XXE y traversal.
  Si la acción fue `log`, la solicitud pudo llegar a la aplicación; un bloqueo o desafío no es evidencia de explotación. Estas señales cubren ataques que Cloudflare WAF reconoce, pero no garantizan detectar las diez categorías OWASP: control de acceso, configuración insegura y fallas fuera del tráfico HTTP requieren otras fuentes.
- **Límites del proveedor:** Logpush entrega lotes aproximadamente cada minuto, no en un segundo.
  Cloudflare documenta que algunas coincidencias OWASP secundarias del panel no aparecen en su JSON
  exportado; no existe garantía documentada aquí de que Logpush individualice todas las reglas hijas.
  Hay que comprobar el ID de la regla con una prueba autorizada en la zona y seguirlo hasta el Indexer.

## Operación

```sh
# Aprovisionar o conciliar jobs (idempotente; --dry-run no escribe). Salida 2 = falta «Logs: Write».
sudo python3 -I /opt/b89/collectors/provider-ingestion/cloudflare/provision_logpush.py \
  --config /opt/b89/collectors/etc/cloudflare-logpush.json
# Estado del consumidor
sudo cat /opt/b89/collectors/state/cloudflare-logpush.json
```

El instalador de collectors ejecuta ambas cosas cuando Cloudflare está habilitado. `deploy-host.sh`
prepara el spool y el secreto y arranca el contenedor en cada despliegue.

## Permiso del token

Cloudflare exige **Logs: Write** para cualquier operación de la API de Logpush, incluido listar jobs.
Logs: Read no alcanza. Los jobs de zona necesitan el permiso en ámbito de zona, para todas las zonas
vigiladas. Sin él, `GET /zones/<id>/logpush/jobs` responde 403 (código 10000).

## Evidencia

- `node --test wazuh/provider-ingestion/cloudflare/receiver/logpush-receiver.test.mjs`
  (ruta, token, atomicidad, límites, contrapresión).
- `python -m pytest wazuh/provider-ingestion/tests/test_cloudflare_logpush*.py`
  (normalización HTTP/DNS, objeto de validación, reenvío, inválidos, orden ante errores
  transitorios, ledger acotado, conciliación de jobs y falta de permiso).
- `wazuh-logtest` con `tests/collector-cases.jsonl` (casos 61–68: reglas 101515–101527).
