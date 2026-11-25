# 20 · Monitoreo de plataforma, priorización de vulnerabilidades y canarios

> Estado al 2026-11-09, desplegado en AWS (`dev.security.b89.io`). Código: [`wazuh/platform-monitoring/`](../wazuh/platform-monitoring/).
> Leyenda: **[verificado]** probado en el host real; **[sin verificar]** existe pero no se probó de extremo a extremo.

Un SOC que no sabe cuándo está ciego genera una falsa sensación de seguridad. Esta capa contesta tres
preguntas cada pocos minutos: **¿llegan los datos?** (fuentes, collectors, agentes, ingesta B89),
**¿la plataforma está sana?** (contenedores, indexer, certificados, host) y **¿qué vulnerabilidades importan de
verdad?** (CISA KEV + FIRST EPSS + exposición). Todo lo que detecta se convierte en una alerta Wazuh B89
(reglas 102100–102179) que sigue el mismo camino que cualquier otra: indexer → B89 → Resumen/Integraciones.

## Piezas

| Pieza | Script | Cadencia (systemd) | Salida |
| --- | --- | --- | --- |
| Monitor de salud | `b89_platform_monitor.py` | `b89-platform-monitor.timer` cada 5 min | `b89-collectors/platform-health.jsonl` |
| Priorización KEV/EPSS | `b89_vulnprio.py run` | `b89-vulnprio.timer` cada 1 h (feeds cada 24 h) | `b89-collectors/vulnprio.jsonl`, listas CDB, `report.json` |
| Enriquecimiento en línea de Snyk | `snyk/issues.py` + `common/b89_vuln_priority.py` | con el collector (15 min) | campos `b89.vuln.*` en cada issue |
| Canarios | `b89_canary.py inject` / `verify` | inyección diaria 06:10 UTC; verificación cada 10 min | una línea sintética por pipeline |

Python estándar (sin dependencias), igual que los collectors. Instalación idempotente en el host:

```bash
sudo bash /opt/b89/src/wazuh/platform-monitoring/install-platform-monitoring.sh   # --no-restart para no reiniciar
systemctl list-timers 'b89-*'
journalctl -u b89-platform-monitor -o cat | tail
```

El instalador hace respaldo (`/opt/b89/backups/platform-monitoring-<ts>/` y `etc/b89-backup-platform-<ts>` en
el manager), valida con `wazuh-analysisd -t` (revierte si falla), persiste el `ossec.conf` montado de
wazuh-docker y reinicia **solo** el manager. No toca `deploy-host.sh`, `ship.sh` ni el compose.

## Identidades (solo lectura, mínimo privilegio)

El código no lee ninguna credencial de administrador. El instalador crea, con la credencial admin de
`compose.env`, tres identidades de solo lectura y las autoprueba:

| Identidad | Dónde | Permisos | Autoprueba |
| --- | --- | --- | --- |
| `b89_monitor` | Indexer (usuario interno) | rol `b89_platform_monitor`: `cluster_monitor`, ISM explain, `read` en `wazuh-alerts-*` y `wazuh-states-vulnerabilities-*`, `indices_monitor` | busca 200, escribe 403 **[verificado]** |
| `b89-monitor` | API del manager | rol RBAC `readonly` (único) | lee agentes 200 **[verificado]** |
| `b89_monitor` | Postgres | sin contraseña, solo socket local del contenedor (`pg_hba` exige SCRAM por red), `SELECT` en `source_poll_observations`, `source_stream_activity`, `source_health_transitions`, transacciones de solo lectura | **[verificado]** |

Contraseñas en `/opt/b89/secrets/platform-monitoring/` (0600). El lector `b89_reader` del gateway no sirve
aquí: el gateway solo expone `wazuh-alerts-*/_search` y `_cluster/health`, y el monitor necesita watermarks,
ISM y el estado de vulnerabilidades. Pendiente para docs/16 §5: agregar `b89_platform_monitor` a
`roles.b89.yml` para que la verificación de roles no lo marque como desconocido.

## 1. Monitor de salud

| Chequeo (`b89.health.check`) | Qué mira | Umbral por defecto | Regla · nivel |
| --- | --- | --- | --- |
| `source_silent` | Último evento por fuente en `wazuh-alerts-*` (una agregación por fuente) y latido del pipeline | ver tabla de cadencias | 102104 · 10 |
| `collector_failing` | `last_success` del estado del collector, `Result` de la unit y timer activo | 3 intervalos sin éxito | 102105 · 8 |
| `agent_disconnected` | `lastKeepAlive` y estado de cada agente (API, `readonly`) | > 15 min no activo | 102106 · 10 |
| `host_disk` / `indexer_disk` | Disco del host (`/`, `/var/lib/docker`), `_cat/allocation` y bloqueos `read_only_allow_delete` | > 85 % (crítico > 95 % host, ≥ 90 % indexer o bloqueo) | 102107 · 12 / 102108 · 13 |
| `container_unhealthy` | `docker ps`: estado, healthcheck y reinicios de los contenedores `b89-*` | esenciales críticos | 102109 · 10 / 102110 · 12 |
| `indexer_cluster` | `_cluster/health` | amarillo / rojo | 102111 · 8 / 102112 · 12 |
| `ism_error` | `_plugins/_ism/explain/wazuh-*` | cualquier acción fallida | 102114 · 7 |
| `cert_expiry` | Let's Encrypt del edge, certificados del indexer/dashboard/manager/admin, CA, gateway, Postgres y API | < 30 días (< 7 crítico) | 102115 · 8 / 102116 · 12 |
| `ingestion_lag` | Última pasada correcta de la ingesta B89 y distancia entre el último evento de Wazuh y lo leído por B89 | > 15 min | 102117 · 9 / 102118 · 11 |
| `host_memory` / `host_load` | `/proc/meminfo`, `loadavg` por vCPU | > 92 % / > 2,0 | 102119 · 8 |
| `edge_unreachable` | `https://dev.security.b89.io/` vía ALB | distinto de 200/30x/401/403 | 102120 · 12 |
| `vuln_intel_stale` | Edad de la caché KEV/EPSS | > 48 h | 102121 · 5 |
| `canary_missing` | Veredicto de los canarios | falta o > 26 h sin veredicto | 102122 · 10 |
| `sns_subscription` | Suscripciones SNS `PendingConfirmation` | opcional: requiere credenciales AWS en el host (apagado en modo PowerUser) | 102123 · 7 |
| `monitor_error` | Un chequeo no pudo correr (credencial, API caída) o el monitor dejó de correr (lo vigila el canario) | — | 102124 · 5 / 102125 · 10 |
| `source_status` | Instantánea por fuente, una por hora | — | 102101 · 3 |
| Recuperación (`status=ok`) | Cierre de un problema abierto | — | 102102 · 3 |

**Solo transiciones:** un problema se emite al abrirse, se re-notifica cada 6 h (o al empeorar de severidad) y
se cierra con un evento de recuperación. Con todo sano el monitor escribe unas 10 líneas por hora (las
instantáneas). Un chequeo que no pudo correr no cierra los problemas que ya tenía abiertos.

### Cadencia esperada por fuente

Configurable en `/opt/b89/platform-monitoring/etc/monitor.json` (`sources`). En modo **heartbeat** (fuentes de
bajo volumen) la fuente no está «silenciosa» por no tener eventos: se exige que el pipeline lata (éxito del
collector o receptor sano) y solo se esperan eventos dentro de una ventana larga. Así un Snyk sin issues nuevos
o una cuenta AWS tranquila no generan falsos positivos, pero un collector caído sí.

| Fuente | Modo | Latido | Silencio máximo | Ventana de eventos |
| --- | --- | --- | --- | --- |
| Snyk | heartbeat | collector (15 min) | 45 min | 7 días |
| Cloudflare | heartbeat | collector (5 min) | 20 min | 72 h |
| Bitdefender | heartbeat | collector (10 min, instantánea diaria) | 30 min | 26 h |
| AWS (EventBridge → SNS) | heartbeat | contenedor `b89-aws-events-1` sano | 15 min | 72 h + canario diario |
| Agentes Wazuh (todo lo que no es proveedor) | heartbeat | contenedor del Manager (15 min) | 15 min | No aplica; cada agente se vigila por `lastKeepAlive` (> 15 min desconectado) |

Los agentes no se declaran silenciosos por falta de alertas: un agente sano puede no producir detecciones.
La conectividad se mide con `agent_disconnected` por `lastKeepAlive`; el heartbeat de esta fila solo
confirma que el Manager sigue vivo. Así, ausencia de incidentes no genera una falsa alarma de ingesta.
| Office 365 | **deshabilitada** | — | — | bloqueada hasta conceder `ActivityFeed.Read` |

### Contrato de campos para la UI (Resumen / Integraciones)

Sin tocar `b89_ops`: el dueño de la UI puede leer el estado por fuente de `wazuh-alerts-*` con:

```text
rule.groups: b89_platform_health
data.b89.vendor = "b89-platform", data.b89.event_type = "health"
data.b89.health.check      source_status | source_silent | collector_failing | agent_disconnected | ...
data.b89.health.status     problem | ok
data.b89.health.severity   info | warning | critical
data.b89.health.source     snyk | cloudflare | bitdefender | aws | office365 | wazuh-agents | wazuh | b89 | host | edge | vulnprio | canary
data.b89.health.source_state   (solo source_status) ok | silent | failing | disabled
data.b89.health.key        "<check>:<source>[:<component>]"  (correlación problema ↔ recuperación)
data.b89.health.summary    texto en español para el analista
data.b89.health.last_seen  último evento o éxito (ISO 8601)   · since · value · threshold · unit · component
```

Receta: el último `source_status` por `data.b89.health.source` (agregación `terms` + `top_hits` por `timestamp`)
da el estado vigente de cada tarjeta; los `problem` sin `ok` posterior con la misma `key` son los problemas
abiertos. La instantánea es horaria, así que la UI debe tratar como desconocido un estado de más de 2 h.

## 2. Priorización de vulnerabilidades (KEV + EPSS + exposición)

### Fuentes y términos de uso

| Feed | URL | Términos | Uso |
| --- | --- | --- | --- |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Dominio público: el repositorio oficial `cisagov/kev-data` declara licencia **CC0** | Diario |
| FIRST EPSS | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (enlazado desde first.org/epss/data) | Publicado «gratis, sin registro»; FIRST **pide atribución** cuando se usa en productos. Atribución: *«EPSS — Exploit Prediction Scoring System, FIRST.org (first.org/epss)»*; cada evento registra `epss_model` y `epss_date` | Diario |

Se descarga el CSV completo en vez de llamar a la API por CVE: el inventario de CVE del cliente nunca sale del
host. Las descargas son atómicas; si fallan se conserva la caché anterior y a las 48 h salta `vuln_intel_stale`.

### Modelo de prioridad

| Prioridad | Condición (umbral EPSS configurable, por defecto 0,5 / 0,1) | Efecto |
| --- | --- | --- |
| **P1** | CVE en KEV, o EPSS ≥ 0,5 en un activo expuesto a Internet | Sube el nivel (Snyk crítica 14, alta 13, media/baja 12; hallazgo VD 13, 14 si expuesto) |
| **P2** | EPSS ≥ 0,5, o severidad crítica en un activo expuesto | Alta → 11, media → 10; hallazgo VD 10 |
| **P3** | Resto | Sin cambio |
| **P4** (ruido) | Solo con evidencia positiva: no KEV, EPSS conocido < 0,1, la fuente dice **explícitamente** que no hay fix, no expuesto, sin exploit maduro | Alta/crítica bajan a 6 (Snyk) / 5–6 (alertas VD nativas): siguen visibles, no avisan |

Falla segura: sin CVE (issues de licencia o código), sin EPSS para ese CVE, **con estado de fix desconocido**
o sin caché, el nivel original no cambia. Un SOC no degrada lo que no puede demostrar que es ruido: la detección
de vulnerabilidades de Wazuh no informa si existe fix, así que sus hallazgos nunca bajan (solo suben por KEV/EPSS). Un exploit maduro nunca baja. **Exposición:** proyectos Snyk de la lista CDB
`b89-internet-facing-projects` (la misma que usan las reglas 101730–101731) más patrones configurables, y
agentes declarados en `B89_EXPOSED_AGENTS`. El nodo SOC **no** se declara expuesto: su security group solo
admite el ALB (80/443), SSH desde la IP de administración y los puertos de agentes, y el edge corre en un
contenedor cuyo software no está en el inventario de paquetes del host.

### Por qué campos en línea + listas CDB (la vía nativa de Wazuh)

- **Snyk → campos en el evento.** El collector agrega `b89.vuln.{priority,reason,cve,kev,epss,epss_percentile,epss_band,exposed,fix}`
  al ingerir, y las reglas 102150–102159 (hijas de 101453–101458) ajustan el nivel. Es la forma nativa: la
  decisión está en el propio evento antes de que exista la alerta, sin reiniciar el manager y sin depender
  del orden de llegada. Una lista CDB no sirve aquí: `snyk.issue.problems` es un arreglo (Wazuh lo aplana a
  texto separado por comas) y `match_key` no busca dentro de él.
- **Detección de vulnerabilidades de Wazuh → listas CDB.** Las alertas nativas (0520, 23503–23506) las
  genera el manager: no hay un collector donde enriquecerlas, pero su CVE es un campo único, así que una lista
  CDB por CVE es lo nativo. `b89_vulnprio.py run` regenera `etc/lists/b89-vuln-kev` (todo KEV) y
  `b89-vuln-noise` (CVE que son P4 en **todos** los activos donde aparecen) y las reglas 102170–102175 las usan.
  Como Wazuh VD no informa fix, `b89-vuln-noise` queda con el centinela `.invalid` (vacía en la práctica) hasta que
  una fuente aporte ese dato; `b89-vuln-kev` sí rige. Límite: las listas CDB se cargan al arrancar analysisd, así que un cambio rige desde el siguiente reinicio
  del manager (el instalador reinicia una vez tras `analysisd -t`). Por eso los cambios a P1/P2 no esperan:
  salen al momento como eventos `b89-vulnprio` (102161–102163).
- **Convivencia con la calibración de detección.** `detections/snyk/severity-calibration` (101732–101734) baja
  las altas/críticas no expuestas y sin exploit (7/10) y carga antes (`b89_soc_*`), así que gana el primer match
  bajo 101453/101455/101456. Las hijas KEV/EPSS declaran **ambos padres** (`<if_sid>101455, 101733</if_sid>`,
  etc.; 102167 eleva la crítica P2 desde 101734): una CVE en KEV sube aunque la calibración la haya bajado. Si el
  archivo de calibración no está instalado, Wazuh ignora ese padre con un aviso y la regla sigue valiendo. Probado
  con las reglas de detección cargadas (62 casos de logtest).
- **Re-priorización.** Si un CVE entra en KEV después de ingerido el issue, el job horario lo detecta y emite
  un evento `b89-vulnprio` (solo P1/P2, solo cuando la prioridad cambia). Un resumen diario (102165) registra
  los conteos antes/después.

### Impacto en AWS

**Corrección (2026-11-09).** La primera medición (1.112 → 78, −93 %) trataba «fix desconocido» como «sin fix» y
degradaba a P4 los 1.012 hallazgos altos/críticos de Wazuh VD. Eso escondía riesgo potencialmente real y se
retiró: P4 exige ahora que la fuente diga explícitamente que no hay fix. Además, la línea base «antes» refleja
los niveles vigentes en producción, que ya incluyen la calibración de detección (101732–101734).

Datos del 2026-11-09 (383 issues Snyk abiertos; 3.210 hallazgos VD del agente `b89-soc-dev-node`; 1.769 CVE en
KEV; 401.956 puntajes EPSS, modelo `v2026.06.15`):

| Origen | Antes (altas+críticas, nivel ≥ 10) | Después | Qué cambia |
| --- | --- | --- | --- |
| Wazuh VD | 1.012 (105 críticas, 907 altas) | **1.012** | Nada: fix desconocido → sin degradación; ninguna CVE en KEV ni con EPSS ≥ 0,5 |
| Snyk | **pendiente de re-medir** con la línea base calibrada | **pendiente** | 93 issues son P4 con evidencia (Snyk informa `fixable=false`, EPSS < 0,1, no expuestos) |

Lectura honesta: hoy KEV/EPSS **no reduce** el volumen de VD y no eleva nada, porque ninguna CVE abierta está
en KEV ni tiene EPSS ≥ 0,5. Su valor es el día en que una entre en KEV (alerta P1 en menos de 1 h, aunque la
calibración la haya bajado) y la vista priorizada (`report.json`). La reducción de ruido de Snyk ya la hace en
buena parte la calibración de detección; P4 agrega la degradación de las críticas internas sin fix (10 → 6).

**Falsos positivos de la primera instalación.** El nodo SOC se marcó por error como expuesto y se emitieron 105
eventos `b89-vulnprio` P2 (regla 102163, nivel 10). Se cierran con el mismo mecanismo auditado que la regla 521
(`detections/tools/close-false-positives.mjs`: principal `svc:b89-detection-engineering`,
assign → triage `false_positive` → close, auditoría con cadena hash). Hoy no puede haber otra 102163 legítima
(ningún hallazgo tiene EPSS ≥ 0,5 y no hay activos expuestos), pero la pasada en seco debe mostrar `matching: 105`
antes de aplicar:

```bash
cd /opt/b89/src
docker run --rm --network b89_default --env-file /opt/b89/config/api.env --env-file /opt/b89/secrets/api.env   -v "$PWD/detections/tools/close-false-positives.mjs:/app/dist/b89-close-fp.mjs:ro"   b89/api:local dist/b89-close-fp.mjs --rule 102163   --reason "falso positivo: P2 por exposición mal declarada del nodo SOC en la primera instalación de b89-vulnprio (docs/20)"
# si matching = 105: repetir con --apply
```

```bash
sudo /usr/bin/python3 -I /opt/b89/platform-monitoring/bin/b89_vulnprio.py report --config /opt/b89/platform-monitoring/etc/vulnprio.json
```

## 3. Canarios (detección de extremo a extremo)

Cada día a las 06:10 UTC se escribe un evento sintético por pipeline, rotulado
`b89.event_type = "canary"` y `b89.canary.label = "sintético/canary · no requiere acción"`, en el mismo archivo
que Wazuh ya lee para esa fuente (el inyector espera a que el collector no esté escribiendo). Las reglas de
canario son **nivel 3**: se indexan y llegan a B89, pero no paginan ni van al correo (que es desde nivel 8).

| Pipeline | Entrada | Regla |
| --- | --- | --- |
| bitdefender / snyk / cloudflare | JSONL del collector | 102130 / 102131 / 102132 |
| aws | JSONL del receptor SNS (`b89-collectors/aws/aws-events.jsonl`) | 102133 |
| platform | `platform-health.jsonl` | 102134 |
| vulnprio | `vulnprio.jsonl` | 102166 |
| agent | `logger -t b89-canary` → journald → agente Wazuh 001 | 102135 |

La verificación busca el `id` del canario en `wazuh-alerts-*` y luego comprueba que una pasada correcta de la
ingesta B89 haya leído más allá de esa marca de tiempo. Si en 30 min no se cumplen ambas, el veredicto es
`missing` con la etapa que falló (`inject`, `wazuh` o `b89`) y el monitor abre `canary_missing` (102122, nivel
10). El canario prueba archivo → logcollector → analysisd → indexer → B89. No prueba la API del proveedor (eso
lo cubre `collector_failing`) ni SNS → receptor, cuya firma no se puede falsificar (eso lo cubre el latido del
contenedor). El verificador vigila además al monitor: si este deja de correr 30 min, emite él mismo
`monitor_error` crítico (102125) y su recuperación.

```bash
sudo /usr/bin/python3 -I /opt/b89/platform-monitoring/bin/b89_canary.py inject --config /opt/b89/platform-monitoring/etc/canary.json
sudo /usr/bin/python3 -I /opt/b89/platform-monitoring/bin/b89_canary.py status --config /opt/b89/platform-monitoring/etc/canary.json
```

## Pruebas

```bash
python -m pytest -q wazuh/platform-monitoring/tests        # 53 pruebas, sin red ni docker
bash wazuh/platform-monitoring/tests/run-logtest.sh        # 62 casos wazuh-logtest en un manager 4.14.8 desechable (con la calibración Snyk de detections/)
python wazuh/manager/policy/check_rule_ids.py <todas las reglas B89>   # 102100-102179 sin colisiones
```

## Rangos de IDs

| Rango | Uso |
| --- | --- |
| 102100–102129 | Salud de plataforma (`b89_watch_platform_rules.xml`) |
| 102130–102149 | Canarios |
| 102150–102179 | Priorización de vulnerabilidades (`b89_watch_vulnprio_rules.xml`) |

Los archivos se llaman `b89_watch_*` para cargar después de todos los `b89_*` y `b89_soc_*` de los que
cuelgan (`if_sid` entre archivos exige ese orden). Los rangos están registrados en
`detections/catalog.yaml#id_ranges` (`platform` 102100–102149 y `vulnerability` 102150–102179, owner
platform-monitoring).

> **Renumeración 2026-11-25.** Hasta esa fecha el monitor usaba 101800–101879, que pertenece a las
> detecciones de red (docs/18): 42 IDs colisionaban y Wazuh se quedaba con la primera definición cargada
> (`b89_soc_*`), así que la salud, los canarios y la priorización KEV/EPSS no llegaban a dispararse con esos
> IDs. Se renumeró +300 con los mismos offsets (101807 → 102107, 101866 → 102166…). Una alerta con ID
> 1018xx se trata siempre como detección de red, nunca como salud de plataforma.

## Hallazgos del primer día

- **Indexer en amarillo:** 6 réplicas sin asignar de `.opendistro-ism-managed-index-history-*` y
  `.opendistro-job-scheduler-lock` en el nodo único (102111, nivel 8). docs/16 §4 pide dejar en 0 las réplicas del
  índice interno de ISM. Hay que volver a aplicarlo y fijar
  `plugins.index_state_management.history.number_of_replicas: 0`.
- Office 365 sigue sin eventos desde 2026-11-04 (permiso `ActivityFeed.Read`): queda como fuente deshabilitada
  declarada, no como alarma.
