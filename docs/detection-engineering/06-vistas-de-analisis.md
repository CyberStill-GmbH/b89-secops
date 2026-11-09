# 06 · Vistas de análisis (OpenSearch Dashboards)

Parte de [17 · Ingeniería de detección](../17-ingenieria-de-deteccion.md). Fuente:
`wazuh/dashboard/saved-objects/detection/build_detection_dashboards.py` → `b89-detection-dashboards.ndjson`
(73 objetos, IDs `b89-det-*`, paleta de la [identidad B89](../brand/b89-visual-identity.md): Coral = crítica,
Fucsia = alta, Amarillo = media, Turquesa = baja/éxito, Azul = neutro, Lavanda = sin dato).

| Dashboard | ID | Qué responde | Índices |
| --- | --- | --- | --- |
| **B89 · Cobertura MITRE ATT&CK** | `b89-det-dashboard-mitre` | Qué técnicas y tácticas disparan, cuáles cubre el repositorio y qué brechas quedan | `wazuh-alerts-*` + matriz generada |
| **B89 · Gestión de vulnerabilidades** | `b89-det-dashboard-vulnerabilities` | Qué CVE y paquetes parchar primero en los agentes, y qué issues de Snyk están expuestos con exploit | `wazuh-states-vulnerabilities-*`, `wazuh-alerts-*` |
| **B89 · Identidad y acceso** | `b89-det-dashboard-identity` | Quién falla y entra, desde dónde, y qué privilegios cambian (M365/Entra, AWS, SSH) | `wazuh-alerts-*` |
| **B89 · Integridad y cumplimiento** | `b89-det-dashboard-integrity` | Qué archivos cambian (persistencia B89), qué controles CIS fallan y qué requisitos PCI/NIST tienen alertas | `wazuh-alerts-*` |
| **B89 · Threat hunting** | `b89-det-dashboard-hunting` | Diez cazas (H01–H10) con hipótesis, abribles en Discover | `wazuh-alerts-*` |
| **B89 · Calidad de detección** | `b89-det-dashboard-quality` | Volumen por regla, reglas ruidosas, niveles, proporción B89 y MITRE | `wazuh-alerts-*` |

**Importación** (host AWS, como administrador de servicio, nunca con el login de una persona):

```bash
sudo bash infra/aws-poweruser/scripts/bootstrap-detection-content.sh
```

Sale desde el contenedor del dashboard con proxy auth (`b89-bootstrap`, `b89.platform.admin`), igual que
`bootstrap-wazuh-app.sh`; exige que existan los index patterns `wazuh-alerts-*` y `wazuh-states-vulnerabilities-*`,
importa con `overwrite=true` (idempotente) y verifica los seis dashboards. Importado en AWS el 2026-11-04
(73/73) **[verificado]**. Los paneles de M365/Entra quedan vacíos hasta BL-I01.

**Regenerar** después de cambiar reglas: `b89_detections.py coverage` y luego el builder (la matriz y las brechas
del dashboard de cobertura salen del JSON de cobertura).

**Permisos:** los roles de solo lectura (`b89.soc.analyst`, `b89.soc.lead`, `b89.auditor`) leen
`wazuh-alerts-*` y `wazuh-states-*` (`wazuh/indexer/security/roles.b89.yml`), así que todas las vistas funcionan
para analistas; guardar cambios en el tenant global queda para el Líder SOC.
