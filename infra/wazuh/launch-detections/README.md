# Paquete de detección B89 para lanzamiento

> **Nota (legado):** las menciones a Azure describen el perfil heredado de QAPAQ SecOps, archivado en
> [`docs/archive/azure`](../../../docs/archive/azure/README.md). B89 SOC opera solo en AWS ([02](../../../docs/02-arquitectura.md)); lo técnico
> que sigue aquí vale como referencia del perfil heredado, no como runbook vigente.

> **Nota (heredado):** Shuffle y su webhook son el estado heredado de B89 Respond. El diseño vigente es
> Step Functions ([13](../../../docs/13-b89-respond.md), [14](../../../docs/14-b89-respond-conexion-b89.md)); este material se reemplaza (fase M5).

Estado: **preconfigurado en Git; no instalado en un Manager real**. El catálogo
mantiene 30 casos priorizados. Las reglas locales de este paquete consumen un
contrato JSON plano `integration=b89-provider`; los adapters Sophos/Cato/Entra
que deben emitirlo aún necesitan implementación y pruebas con proveedor. Los
detectores M365 existentes se referencian por su ID, no se copian ni se editan.

## Contrato de entrada de proveedores

Los adapters autorizados que decidan enrutar eventos a Wazuh deben escribir una
línea JSON por evento con identificadores y campos planos. Ejemplo exclusivamente
sintético:

```json
{
  "integration": "b89-provider",
  "b89_vendor": "sophos",
  "b89_event_type": "threat_detected",
  "b89_severity": "critical",
  "b89_status": "active",
  "b89_endpoint_id": "endpoint-lab-01",
  "b89_user_id": "usuario@b89-lab.example",
  "b89_source_record_id": "event-synthetic-001"
}
```

El adapter conserva el raw de proveedor fuera de este log, agrega `source_record_id`
estable, redacción y referencia/hash del raw. No escribir tokens, cuerpo de correo,
URL sensible ni payload raw en `alerts.json`. Cursor y admisión durable pertenecen
al adapter; Wazuh no avanza checkpoints de Sophos/Cato.

Campos comunes: `integration`, `b89_vendor`, `b89_event_type`,
`b89_source_record_id`, `b89_severity`, `b89_status`, `b89_action`,
`b89_user_id`, `b89_actor`, `b89_endpoint_id`, `b89_host`,
`b89_source_ip`, `b89_destination`, `b89_hash`, `b89_remedy_result`,
`b89_change_status`, `b89_path_scope`. Omit campos ausentes; no rellenar
valores desconocidos con defaults que eleven prioridad.

## Contenido

- `rules/b89_launch_provider_rules.xml`: reglas locales 101200–101215 para
  detecciones puntuales y telemetría normalizada. No habilita Active Response.
- `agent-groups/`: perfiles de referencia para Windows/Linux; Sysmon está
  separado para no solicitar un canal inexistente en equipos sin ese producto.
- `b89-respond/playbooks.json`: seis contratos de triage read-only. Especificación, no un
  export JSON importable de Shuffle.
- `../../../docs/security/launch-detection-catalog-2026-10-20.json`: 30 detecciones
  con prioridad, motor, señales, dependencias y estado de activación.
- `tests/`: fixtures sintéticas positivas/negativas para probar reglas con
  `wazuh-logtest` 4.14.8.
- `validate_catalog.py`: verifica el catálogo de 30, unicidad y referencias a
  reglas instaladas existentes.

## Aplicación al iniciar Wazuh

El siguiente bundle de release Azure incluye el catálogo y ambas reglas locales B89.
Su instalador las copia de forma atómica en `/var/ossec/etc/rules/`, garantiza que el
directorio está registrado en el `<ruleset>` activo, valida con
`/var/ossec/bin/wazuh-analysisd -t` y reinicia el Manager con rollback si falla. Esto
requiere construir y publicar un bundle nuevo y después instalarlo; el candidato Blob
publicado el 23 de octubre todavía no contiene este cambio. No reiniciar un Manager
ajeno desde CI.

Las reglas proveedoras solo generarán alertas después de instalar en el Manager el
adaptador local que escriba el contrato anterior. El archivo del catálogo es fuente
de configuración del backlog y no se debe presentar como cobertura operativa.

## Verificación

```bash
python infra/wazuh/launch-detections/validate_catalog.py
docker run --detach --rm --name b89-wazuh-launch-test wazuh/wazuh-manager:4.14.8
bash infra/wazuh/launch-detections/tests/run-logtest.sh b89-wazuh-launch-test
docker rm -f b89-wazuh-launch-test
```

Los fixtures prueban evaluación sintética del motor; no son prueba de conectividad
con Microsoft, Sophos, Cato ni endpoints reales. El workflow de CI corre el mismo
logtest en Manager fijado. La activación de cada caso requiere cumplir su `activation`
en el catálogo y la aceptación real descrita en el perfil de demo multifuente.

## Fuentes upstream

- Wazuh mantiene [reglas base](https://github.com/wazuh/wazuh-ruleset) y documenta
  [reglas personalizadas](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html),
  [decodificación JSON](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
  y [configuración central de agentes](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html).
- Las reglas portables candidatas se seleccionan desde [SigmaHQ](https://github.com/SigmaHQ/sigma);
  conservar UUID, estado, falsos positivos y DRL 1.1 para cualquier adaptación.
- El conector Sophos se debe ajustar al contrato de
  [Sophos Central SIEM Integration](https://github.com/sophos/Sophos-Central-SIEM-Integration)
  y a la [referencia oficial SIEM API](https://developer.sophos.com/siem/).
- Cato se integra mediante su [API oficial](https://api.catonetworks.com/documentation/)
  y el [SDK oficial Go](https://github.com/catonetworks/cato-go-sdk), sujeto a que el
  tenant tenga disponible `eventsFeed` y los permisos mínimos.
- Los playbooks se convertirán a formato exportado solo desde la instancia B89 Respond/
  Shuffle fijada, usando [documentación de workflows](https://github.com/Shuffle/shuffle-docs)
  y revisando artefactos upstream en [shuffle-workflows](https://github.com/Shuffle/shuffle-workflows).
