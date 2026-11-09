# SharePoint y OneDrive

## Alcance y estado

B89 recoge actividad de archivos, uso compartido y postura del tenant. Hay dos rutas para auditoría:

- El módulo nativo `office365` lee `Audit.SharePoint` y OneDrive cuando la aplicación de Entra tiene
  `ActivityFeed.Read` en Office 365 Management APIs.
- El collector B89 consulta Purview Audit Search por Microsoft Graph cuando la vía nativa no está
  disponible. Requiere `AuditLogsQuery-SharePoint.Read.All` y/o `AuditLogsQuery-OneDrive.Read.All`.

La postura usa `SharePointTenantSettings.Read.All` y `Sites.Read.All`. El enriquecimiento opcional de
cuentas requiere `User.Read.All`. Preferir permisos de aplicación de solo lectura y conceder
consentimiento de administrador. La app/tenant debe ser la de B89.

La integración aparece en **Resumen del SOC** e **Integraciones** con estado **No configurada** mientras
`b89_ops.integrations.sharepoint.state` sea `disabled`. La instalación prepara servicios y dashboard,
pero no activa timers de forma predeterminada.

## Reglas y fuentes

Las detecciones `101900–101979` están en `detections/sharepoint/` y cubren descargas/sincronización y
borrado masivos, accesos de invitados o cuentas deshabilitadas, enlaces anónimos/externos, cambios
débiles de política, administradores y postura. Las reglas usan los eventos normalizados `office365.*`
y los eventos de estado/postura `b89.*` / `sharepoint.*`.

MITRE ATT&CK se declara por regla XML. La lista `b89-m365-service-accounts` permite mantener fuera de
umbrales de volumen las cuentas de servicio y sincronización aprobadas. Añadir cuentas reales mediante
el procedimiento de cambios del SOC, nunca en el ejemplo versionado.

## Activación segura

1. Confirmar permisos efectivos con el checker de acceso; debe informar HTTP 200 para las vías que se
   habilitarán. No basta con que los permisos aparezcan configurados en Entra.
2. Con las credenciales del tenant B89 disponibles en `/opt/b89/secrets/services.env`, ejecutar
   `sudo env B89_ENABLE_SHAREPOINT=true bash wazuh/provider-ingestion/install-b89-collectors.sh`.
3. Activar únicamente después de validar el checker. El instalador
   falla cerrado si la auditoría está bloqueada o el diagnóstico recibe HTTP 403; deja ambos timers
   apagados.
4. Revisar `systemctl status b89-collector-sharepoint-audit.timer
   b89-collector-sharepoint-posture.timer` y los JSONL en `/var/ossec/logs/b89-collectors/`.
5. Al completar la validación, cambiar `b89_ops.integrations.sharepoint.state` a `auto` y recrear el
   contenedor de OpenSearch Dashboards para que la tarjeta refleje los eventos.

El modo de auditoría es `auto`: si ActivityFeed está disponible, el collector no duplica los eventos
que ya recoge el módulo nativo; si no, usa Purview Graph. Si no hay permisos efectivos, registra estado
de capacidad y no procesa auditoría. La postura funciona parcialmente según los permisos concedidos.

## Mapamundi

Los dashboards M365 y SharePoint incluyen un mapa base real de OpenSearch Maps. La capa de eventos está
desactivada y el estado vacío indica que `data.office365.geoip.location` aún debe existir en
`wazuh-alerts-*` con mapping `geo_point`. No se convierten IPs en coordenadas ni se usan datos ficticios.
Tras desplegar GeoIP confiable y confirmar el mapping y el plugin Maps en la imagen de Wazuh Dashboard
4.14.8, habilitar la capa para eventos del proveedor y regenerar/importar los saved objects.

## Triage de exfiltración

Ante una alerta P1/P2, verificar primero usuario, operación, archivo/sitio, volumen y ventana temporal;
correlacionar IP, país solo si proviene de GeoIP confiable, y actividad de Entra/endpoint. Confirmar si
la cuenta está en la allowlist de sincronización, si existe cambio aprobado y si los enlaces externos
están autorizados. Preservar el evento original y el contexto de postura. Escalar al dueño de SharePoint
y al líder SOC; aplicar revocaciones o bloqueo únicamente por el proceso de respuesta aprobado.

No cerrar una alerta solo porque el usuario es invitado o de servicio: la allowlist reduce ruido de
volumen, pero los cambios de permisos, actividad fuera de horario o una cuenta deshabilitada requieren
revisión.
