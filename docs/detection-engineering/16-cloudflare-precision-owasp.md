# 16 · Cloudflare: precisión en credenciales robadas y detección OWASP sobre el log HTTP

Fecha: 2026-11-22. Reglas: `wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml` (101530–101545),
`detections/cloudflare/noise-tuning` (101745) y `detections/cloudflare/web-attacks-owasp` (102000–102019).

## 1. Diagnóstico

### Falsos positivos de «credenciales robadas» (101531)

| Causa | Efecto |
| --- | --- |
| La regex de host aceptaba `apipayments.b89.io`, la **API de integración de comercios** (máquina a máquina). | Cada comercio que se autentica desde AWS/GCP era «credencial robada». |
| Una alerta **nivel 13 por petición**. | Una sesión de 40 peticiones = 40 alertas P1. |
| `OPTIONS`/`HEAD` (preflight del navegador) contaban como sesión válida. | Ruido sin uso de credencial. |
| Staging/UAT (`stg-`, `uat-`) desde la nube (QA/CI) alertaban igual que producción. | Ruido de pruebas. |
| `akamai` y `google llc` en la lista de hosting. | iCloud Private Relay (Akamai) y Google One VPN / Chrome IP Protection son relés de dispositivos personales del personal. |
| `google cloud` no coincidía con `GOOGLE-CLOUD-PLATFORM` (guion). | Falso negativo de GCP. |
| Sin forma de declarar salidas corporativas (oficina, VPN, automatización propia en AWS). | Uso interno legítimo alertando siempre. |

### OWASP y escaneos no detectados

| Causa | Efecto |
| --- | --- |
| `logpush.py` descartaba la **cadena de consulta** (`ClientRequestQuery`) y las puntuaciones WAF del log HTTP. | `?id=1' union select…` era invisible para las reglas. |
| Solo había reglas OWASP sobre **eventos del WAF** (101539–101544). | Lo que Cloudflare dejó pasar (modo registro, plan sin WAF gestionado) no se veía. |
| Escaneo (101517) y enumeración (101519) exigían `b89.source=logpush`. | Con datos GraphQL (muestreados, todos los planes) nunca disparaban. |
| No había fuerza bruta ni relleno de credenciales sobre el login. | OWASP A07 sin cobertura. |
| La suite `collector-cases` esperaba la regla 101523, eliminada el 18/11. | La suite fallaba en el caso 69. |

## 2. Principio de precisión

1. **Una petición aislada no abre caso.** Solo eleva si hay impacto observable: la aplicación responde **500**
   ante una carga inequívoca, o se usa una credencial/token desde infraestructura de atacante.
2. **Agregar por IP** con umbrales distintos según la fuente: Logpush (cada petición) frente a GraphQL
   (~1 de cada 11; 2 registros ≈ 20 peticiones).
3. **Degradar, no silenciar:** escáneres autorizados y salidas corporativas bajan de nivel, siguen indexados.
4. **Cada patrón tiene su fixture FP** (callback OAuth a `localhost`, `{{config.url}}`, `${date}`,
   «select a car from the list»).

## 3. Backoffice de pagos (101530–101545, 101745)

| Regla | Nivel | Cuándo |
| --- | --- | --- |
| 101534 | 0 | `OPTIONS`/`HEAD` (preflight). |
| 101536 | 3 | Staging/UAT desde nube/VPN (QA/CI). |
| 101531 | 12 | `login` o `refresh-token` correcto desde hosting/VPN: uso directo de la credencial o del token. |
| 101532 | 13 | Exportación desde hosting/VPN. |
| 101537 | 13 | Escritura (`POST/PUT/PATCH/DELETE`) en `/backoffice/` desde hosting/VPN: posible movimiento de dinero. |
| 101538 | 3 | Cualquier otra petición correcta desde hosting/VPN (señal). |
| 101545 | 12 | 5+ registros de 101538 de la misma IP en 30 min (sesión sostenida, token robado). |
| 101745 | 3 | IP en `b89-backoffice-trusted-egress`: degrada 101531/101532/101537/101538. |

Caso real del 17/11 (token robado **sin login**: refresh + llamadas de staff desde Datacamp y AWS): lo
detectan 101531 (refresh), 101537 (escrituras de dinero) y 101545 (sesión sostenida).

**Acción pendiente del dueño:** cargar en `detections/lists/b89-backoffice-trusted-egress` las IPs de oficina,
VPN corporativa y automatización propia (formato `prefijo:etiqueta`, p. ej. `38.250.148.:oficina-lima`). Hoy
contiene solo un valor sintético RFC 5737.

## 4. OWASP, escaneo y fuerza bruta (102000–102019)

Entrada: `cloudflare.http.request_target` = ruta + consulta, decodificada dos veces (`%2527` → `'`), en
minúsculas, máx. 2048 caracteres. La calcula `logpush.py` para Logpush y GraphQL.

| OWASP | Señal (nivel 2) | Escala a |
| --- | --- | --- |
| A03 inyección SQL | 102001: `union select`, `' or 1=1`, `sleep(n)`, `information_schema`… | 102009 (500, nivel 10) · 102010 (2xx/3xx, nivel 5) |
| A03 XSS | 102002: `<script`, `onerror=`, `javascript:`, `document.cookie`… | ídem |
| A01 recorrido de rutas / LFI | 102003: `../`, `/etc/passwd`, `php://`, `/proc/self/` | ídem |
| A03 inyección de comandos | 102004: `;cat`, `$(id)`, `&& whoami`, `/bin/sh` | ídem |
| A10 SSRF | 102005: `169.254.169.254`, `metadata.google.internal`, `gopher://`, `file:///` | ídem |
| A06/A03 Log4Shell, plantillas | 102006: `${jndi:`, `{{7*7}}`, `__class__` | ídem |
| A05 herramientas de escaneo | 102007: User-Agent sqlmap, nuclei, nikto… | campañas |
| A07 autenticación | 102015: `POST` de login con 401/403 | 102016/102017 (fuerza bruta, 10) · 102018/102019 (relleno distribuido, 12) |

Agregaciones: campaña por IP 102011 (Logpush 5/10 min) y 102012 (GraphQL 2/30 min), nivel 8; escaneo de rutas
sensibles muestreado 102013 (3/15 min), nivel 8; enumeración 4xx muestreada 102014 (6/5 min), nivel 7.
Escáneres autorizados (`b89-authorized-scanners`): 102008, nivel 2, no cuentan.

Fuera de alcance del log HTTP: A02, A04, A08 y A09 (no dejan huella en la URL).

## 5. Con los permisos actuales

- **Sin «Logs: Write»** (solo lectura de Analytics): llega GraphQL muestreado. Funcionan todas las reglas con
  umbrales GraphQL (102012, 102013, 102014, 102017, 102019, 101545). Los cuerpos de POST no se ven en ningún caso.
- **Con «Logs: Write»**: Logpush entrega cada petición y las puntuaciones `WAFAttackScore`/SQLi/XSS/RCE (si el
  plan las ofrece); se activan 102011, 102016 y 102018.

## 6. Validación

`bash detections/tools/test-in-container.sh` (Wazuh 4.14.8 desechable): `analysisd -t`, suite `collectors`
(87 casos, 14 nuevos de backoffice) y los paquetes `noise-tuning` (+1) y `web-attacks-owasp` (74 casos, 5 FP).
`python -m pytest wazuh/provider-ingestion/tests/test_cloudflare_logpush.py` cubre `request_target`.

## Lista blanca de la API de pagos (2026-11-23)

Regla del dueño: sobre `apipayments.b89.io`, un cliente o proveedor **con IPs registradas** que llama
desde otra IP es alerta crítica (sobre todo login, pagos, payins y payouts); un cliente **sin IPs**
(«No requiere», «Pendiente»…) no genera alerta, venga de donde venga.

- **Dónde se edita:** consola → Tráfico de Cloudflare → pestaña «Lista blanca» (permiso
  `allowlist.manage`, solo administración de plataforma; `allowlist.read` para el SOC). La lista inicial
  es la del Excel «Whitelist_IPs_Clientes_B89» (40 clientes y 10 proveedores); las IPs que perdieron
  los puntos quedan en la nota «por reconfirmar» y no se vigilan hasta corregirlas.
- **Identificadores:** texto que aparece en las peticiones de un cliente (p. ej. su código de comercio
  en la ruta). Permiten reconocerlo cuando llama desde una IP que no es suya (→ 101547) y eximir a los
  clientes sin IP (→ sin alerta).
- **Cómo llega al colector:** la API expone `GET /api/cloudflare/allowlist/feed` con
  `Authorization: Bearer $B89_ALLOWLIST_FEED_TOKEN` (≥ 32 caracteres, en el entorno de la API).
  En el host de Wazuh, un timer cada 2 minutos ejecuta
  `B89_API_URL=… B89_ALLOWLIST_FEED_TOKEN_FILE=/etc/b89/allowlist-feed.token python3 wazuh/provider-ingestion/cloudflare/sync_allowlist.py`,
  que escribe `/var/ossec/etc/b89/cloudflare-allowlist.json` de forma atómica y conserva la última
  versión buena si la API no responde. El colector lo relee cuando cambia.
- **Veredicto del colector** (`cloudflare.http.allowlist_verdict`): `allowed`, `client_without_ip`,
  `outside` o `unknown`, más `allowlist_client`, `allowlist_sensitive` y `allowlist_revision`. Sin
  archivo no hay veredicto ni alerta. `B89_CF_ALLOWLIST_HOSTS` cambia los hosts vigilados.
- **Reglas:** 101546 (base, 0), 101547 (cliente con IP desde otra IP, 13), 101548 (login o pago desde
  IP fuera de la lista, 12), 101549 (resto de la API desde IP fuera de la lista, 5). Caso de uso
  `detections/cloudflare/payments-api-allowlist`. Pruebas: `tests/test_cloudflare_allowlist.py`.
  Pendiente: `wazuh-logtest` en contenedor.
