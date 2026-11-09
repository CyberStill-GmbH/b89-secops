# 17 · Ingeniería de detección y operación del Blue Team

> Leyenda: **[verificado]** hecho y comprobado contra el manager real; **[sin verificar]** existe en el repo
> pero no se probó de extremo a extremo; **[propuesto]** diseño sin implementación. Estado al 2026-11-04.

B89 SOC detecta con Wazuh (reglas, capa 1 y 1b de [07](07-deteccion-ml-y-soar.md)), prioriza con B89 Core
(P1–P4 con razones, `modules/detection`) y responde con B89 Respond bajo aprobación humana
([13](13-b89-respond.md), [14](14-b89-respond-conexion-b89.md)). Este documento define el **programa** que
hace que eso funcione como una disciplina: cómo nace, se prueba, se despliega, se mide y se retira una
detección, quién opera las alertas y con qué tiempos, y qué falta para cerrar las brechas.

## Mapa del programa

| Pieza | Dónde | Estado |
| --- | --- | --- |
| Ciclo de vida, flujo de ramas/PR y estándar de metadatos | [detection-engineering/01](detection-engineering/01-ciclo-de-vida.md) | Vigente |
| Contenido como código: `detections/<fuente>/<caso-de-uso>/` | [`detections/`](../detections/README.md) | 23 casos de uso, 71 reglas del SOC, 24 nuevas **[verificado]** |
| Cobertura MITRE ATT&CK generada desde el XML + brechas | [detection-engineering/02](detection-engineering/02-cobertura-mitre.md), [`detections/reports/mitre-coverage.md`](../detections/reports/mitre-coverage.md) | 49 → 60 técnicas, 12 → 13 tácticas **[verificado]** |
| Runbooks de triage e investigación | [detection-engineering/runbooks](detection-engineering/runbooks/README.md) | Vigente |
| Modelo operativo del Blue Team (turnos, SLA, escalamiento, métricas) | [detection-engineering/03](detection-engineering/03-modelo-operativo.md) | Propuesto; objetivos sin publicar hasta medir (N8) |
| Playbooks de B89 Respond (triage, contención con aprobación) | [detection-engineering/04](detection-engineering/04-playbooks-b89-respond.md), [`b89-respond/playbooks/`](../b89-respond/playbooks/) | Exportables, **no importados**; contención apagada |
| Backlog y hoja de ruta de ingeniería de seguridad | [detection-engineering/05](detection-engineering/05-backlog.md) | Priorizado |
| Ajuste y reducción de falsos positivos (allowlists CDB, contexto, corroboración, anomalías, registro) | [detection-engineering/07](detection-engineering/07-ajuste-falsos-positivos.md), [`detections/lists/`](../detections/lists/) | 16 reglas de ajuste, 6 listas versionadas; 328 FP de 521 cerrados con auditoría **[verificado]** |
| Vistas de análisis (OSD) | [detection-engineering/06](detection-engineering/06-vistas-de-analisis.md), `wazuh/dashboard/saved-objects/detection/` | 6 dashboards importados en AWS **[verificado]** |

## Qué quedó desplegado en AWS (dev.security.b89.io, 2026-11-04)

- **Reglas:** 14 archivos instalados con `detections/tools/deploy-detections.sh` (respaldo
  `etc/b89-backup-20261104T201808Z-detections`, `wazuh-analysisd -t` OK, manager reiniciado, agente 001
  `Active`). 10 archivos nuevos `b89_soc_*.xml` (24 reglas, 101700–101760) y las descripciones normalizadas de
  O365, AD, lanzamiento y endpoint (mismos IDs). Lista CDB `b89-internet-facing-projects` creada con un
  centinela `.invalid` y declarada en `<ruleset>` (también en el `ossec.conf` montado de wazuh-docker).
- **Pruebas:** 317 casos de `wazuh-logtest` en un manager desechable 4.14.8 (185 de suites existentes + 132
  nuevos), todos correctos; 7 casos de suites existentes quedan **refinados** a una regla hija más específica
  (declarado en `detections/catalog.yaml`). En el manager productivo, los 8 casos de uso nuevos con logtest pasan
  salvo Snyk expuesto, que depende de poblar la lista (comportamiento esperado). **Prueba en vivo FIM** en el
  agente 001: `authorized_keys2`, `cron.d` y unidad systemd disparan 101755, 101757 y 101756 en el mismo segundo.
- **Vistas:** 73 objetos guardados (6 dashboards `B89 · …`, 10 cazas) importados en el tenant global con
  `infra/aws-poweruser/scripts/bootstrap-detection-content.sh` (proxy auth desde el contenedor del dashboard).

## Principios

1. **Una detección es código:** XML + metadatos + fixtures + resultado esperado + runbook, revisados por PR.
   Nada se edita a mano en el manager ni en el dashboard.
2. **Sin datos no hay detección:** una regla sin fuente que la alimente se marca `pending-provider-evidence` o
   `experimental`; la cobertura MITRE cuenta reglas, el dashboard de cobertura muestra lo que **dispara**.
3. **Wazuh detecta, B89 prioriza, una persona decide:** las reglas no ejecutan nada (Active Response apagado,
   docs/16); toda acción con efectos pasa por B89 Respond con aprobación del Líder SOC (N5, A13).
4. **Los IDs no se reutilizan** y cada fuente tiene un rango (`detections/catalog.yaml`).
5. **Toda descripción empieza por `B89 <Fuente>:`** (M365, Entra, AWS, Linux, Windows, AD, Bitdefender, Snyk,
   Cloudflare, Sophos, Cato). El lint lo exige en las reglas del SOC.

## Ajuste y reducción de falsos positivos

Resumen (detalle, técnicas y registro con fixtures en [detection-engineering/07](detection-engineering/07-ajuste-falsos-positivos.md)):

- **Degradar, no silenciar:** nivel 0 solo para ruido redundante (sesiones PAM de cuentas admin, que ya
  auditan 5402/5715) o FP técnicos probados (rootcheck sobre overlay de Docker). Los principales de confianza
  (rol SSO del SOC, `b89service@b89.io`) bajan de nivel pero siguen indexados; lo destructivo sigue alertando.
- **Allowlists en `detections/lists/`** (CDB versionadas, cambio por PR). El motor de correlación y riesgo propone
  altas desde los veredictos `false_positive`; un humano aprueba.
- **Severidad con corroboración:** correo (≥ 8) y B89 Respond (≥ 12) solo con activo crítico, exposición, exploit
  maduro, horario o segunda señal.
- **Anomalías:** detectores RCF `b89-logins-per-user` y `b89-waf-blocks-per-zone` con monitores de Alerting
  (`detections/tools/apply-anomaly-monitors.sh`).
- **Histórico:** las 328 alertas B89 de la regla 521 se cerraron como `false_positive` con el script de servicio
  `detections/tools/close-false-positives.mjs` (984 eventos de auditoría con cadena hash, correlación `close-fp-521-*`).
