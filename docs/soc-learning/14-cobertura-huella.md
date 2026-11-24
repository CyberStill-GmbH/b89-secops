# Cobertura de huella fina vs gruesa (T6)

Fecha: 2026-11-24 · rama `feat/soc-learning-stage-a` · precondición de la etapa D.

**Resumen.** Con las fixtures del repo, solo **Cloudflare** produce huella fina de forma
sistemática (98 %). Red llega al 11 %. AWS, M365, SharePoint, Bitdefender, Snyk y las reglas de
serie de Wazuh están en **0 %**. Con la huella actual, la etapa D solo podría proponer
autocierres para Cloudflare y para una parte de red. Hay dos causas, y ninguna es un fallo de la
huella:
- el extractor no lee campos que los decoders ya traen (Windows 5156, `b89-netconn`, Docker);
- en las fuentes de nube el «comportamiento» es la operación y el objeto, que la huella v1 no
  considera.

Estos números **no son la cobertura de producción**: las fixtures no son una muestra del tráfico
real (abajo, sesgos). La cifra que decide la etapa D sale de correr el mismo script sobre el
volcado anonimizado.

## Cómo se reproduce

```powershell
pnpm exec tsx --conditions=development scripts/soc-learning/fingerprint-coverage.ts
```

```powershell
pnpm exec tsx --conditions=development scripts/soc-learning/fingerprint-coverage.ts --alerts <volcado.jsonl> --out cobertura.md
```

El script es de solo lectura y usa el normalizador (`modules/telemetry/src/wazuh-normalization.ts`)
y la huella (`modules/detection/src/fingerprint.ts`) **reales**; no reimplementa la lógica.

Sin volcado usa:
- las 67 alertas sintéticas del correlador (`services/b89-correlator/testdata/wazuh-alerts.jsonl`);
- las fixtures JSON de `detections/*/*/fixtures.jsonl`, convertidas en alerta con la primera regla
  de su `metadata.yaml`;
- las líneas de `b89-netconn`, decodificadas con una réplica del regex de su decoder.

Las demás líneas de texto exigen `wazuh-logtest` y se cuentan aparte.

## Resultado sobre fixtures (2026-11-24)

Alertas evaluadas: 2274. Con huella fina: 140 (6 %). En cuarentena: 1 (fixture rota a propósito).
No evaluables sin logtest: 49.

| Fuente | Alertas | Fina | Sin sujeto | Sin comportamiento | Campos presentes sin mapear |
|---|---:|---:|---:|---:|---|
| aws | 26 | 0 % | 0 | 26 | — |
| bitdefender | 9 | 0 % | 0 | 9 | — |
| cloudflare | 125 | 98 % | 0 | 3 | `data.cloudflare.firewall.path`, `data.cloudflare.http.path`, `data.cloudflare.http.uri` |
| m365 | 37 | 0 % | 0 | 37 | — |
| network | 169 | 11 % | 0 | 151 | `data.host`, `data.url`, `data.win.eventdata.application`, `data.win.eventdata.destAddress` |
| platform | 4 | 0 % | 0 | 4 | — |
| sharepoint | 1832 | 0 % | 0 | 1832 | `data.sharepoint.site.url`, `data.sharepoint.item.url` |
| snyk | 13 | 0 % | 0 | 13 | — |
| wazuh (serie) | 59 | 0 % | 0 | 59 | `data.url` |

Reglas gruesas con más alertas:

| Regla | Alertas | Fina | Falta | Campos presentes sin mapear |
|---|---:|---:|---|---|
| `sharepoint:101900` | 1437 | 0 % | comportamiento | — |
| `sharepoint:101915` | 331 | 0 % | comportamiento | — |
| `network:101830` | 83 | 0 % | comportamiento | `data.host`, `data.url` |
| `cloudflare:101741` | 68 | 97 % | comportamiento | `data.cloudflare.*.path`, `data.cloudflare.http.uri` |
| `m365:101700` | 33 | 0 % | comportamiento | — |
| `wazuh:5402` | 30 | 0 % | comportamiento | — |
| `network:101880` | 29 | 17 % | comportamiento | `data.win.eventdata.application`, `destAddress`, `destPort` |
| `network:101842` | 28 | 0 % | comportamiento | `data.host`, `data.url` |
| `sharepoint:101925` | 22 | 0 % | comportamiento | — |
| `wazuh:510` | 20 | 0 % | comportamiento | — |
| `network:101860` | 8 | 38 % | comportamiento | `data.host`, `data.url`, `data.b89.net.process` |
| `network:101850` | 6 | 0 % | comportamiento | `data.docker.Actor.Attributes.image` |

La tabla completa (25 reglas) la imprime el script.

## Sesgos y límites (leer antes de usar las cifras)

- **No es una muestra de producción.** Los conteos reflejan cuántas fixtures escribió cada caso de
  uso; SharePoint pesa el 80 %. Hay que leer la tabla por fuente, no el 6 % global.
- **El sujeto está inflado.** A cada fixture se le asigna un agente sintético (`017`), así que
  ninguna sale «sin sujeto». En producción, las alertas de colectores (Cloudflare, AWS, M365)
  llevan el agente del manager y las de red pueden no traer usuario: la cobertura real puede ser
  **menor**.
- **Regla aproximada.** Cada fixture se atribuye a la primera regla de su caso de uso, no a la
  que dispararía `wazuh-logtest`. La fuente es fiable (sale del rango); la regla exacta no.
- **Sin logtest.** 49 líneas de texto (auditd, SSH, AD, threat-intel) quedan fuera porque su
  decodificación la hace Wazuh.

## Recomendaciones (por impacto en la etapa D)

| # | Cambio | Dónde | Efecto esperado | Riesgo |
|---|---|---|---|---|
| 1 | Leer Windows 5156 (Filtering Platform): `application` → imagen, `destAddress`/`destPort` → destino | `modules/telemetry/src/wazuh-observables.ts` | `network:101880` pasa de 17 % a casi 100 % fina | Bajo: aditivo; sube el normalizador (las huellas existentes no se mezclan) |
| 2 | Leer `data.b89.net.process` (`b89-netconn`) como imagen de proceso | idem | Conexiones Linux con proceso | Bajo |
| 3 | Leer `data.url`/`data.host` del edge como destino (dominio y ruta sin query) | idem | `network:1018xx` edge y `wazuh:31xxx` web | Medio: la ruta varía; normalizar ids y quitar query |
| 4 | Leer `data.docker.Actor.Attributes.image` como imagen | idem | Docker runtime | Bajo |
| 5 | Huella v2 con «comportamiento de nube»: operación + tipo de objeto (M365 `Operation`/`Workload`, AWS `eventName`/`eventSource`, SharePoint operación + sitio) | `@b89/contracts` (observables v2) + `fingerprint.ts` (v2) | Habilita patrones finos en las fuentes de nube, hoy en 0 % | **Alto**: decide qué cuenta como «mismo comportamiento» en nube; necesita diseño y aprobación (cambia la huella) |
| 6 | Correr el script sobre el volcado anonimizado | — | Cifras reales por regla | — |

Los puntos 1–4 son ampliaciones del extractor que caben en la versión del mapping (1.5.0) y en el
normalizador `2` del contrato. Cada una exige subir `OBSERVABLES_NORMALIZER_VERSION`; los patrones
de la versión anterior quedan `superseded` (diseño §4.3). El punto 5 es una decisión de diseño para
el dueño y no se implementa sin aprobación.

**Precondición de la etapa D:** no promover patrones de una fuente con menos del 50 % de huella
fina en el volcado real, salvo para «agrupar», que no oculta nada.
