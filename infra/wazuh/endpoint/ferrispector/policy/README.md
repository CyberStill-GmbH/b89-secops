# Política corporativa de Ferrispector

## Estado y alcance

La política versionada `starter-credentials.yar` detecta exposición de credenciales y algunos identificadores personales con contexto. El estado inicial es `pilot`: las reglas se compilan, pero deben validarse con muestras sintéticas y aprobarse por Seguridad de Datos antes de activarse en endpoints. No había una política YARA corporativa para endpoints en el repositorio.

Los seis detectores de credenciales de alta confianza quedan activos por defecto. Las reglas avanzadas de AWS, cadenas de conexión, asignaciones genéricas, DNI y RUC quedan apagadas por defecto; el administrador puede activarlas desde **Políticas → Protección de datos**. DNI/RUC requieren aprobación de privacidad. No se cargan datos reales de prueba.

## Catálogo de reglas

| ID | Regla YARA-X | Severidad | Detección | Inicio |
| --- | --- | --- | --- | --- |
| B89-DLP-CRED-001 | `B89_CRED_PRIVATE_KEY_PEM` | Alta | Clave privada PEM | Activa |
| B89-DLP-CRED-002 | `B89_CRED_GITHUB_TOKEN` | Alta | Token GitHub reconocible | Activa |
| B89-DLP-CRED-003 | `B89_CRED_SLACK_TOKEN` | Alta | Token Slack reconocible | Activa |
| B89-DLP-CRED-004 | `B89_CRED_GOOGLE_API_KEY` | Alta | Clave Google API | Activa |
| B89-DLP-CRED-005 | `B89_CRED_AZURE_STORAGE_KEY` | Alta | `AccountKey` de Azure Storage | Activa |
| B89-DLP-CRED-006 | `B89_CRED_OPENAI_API_KEY` | Alta | Clave API de OpenAI | Activa |
| B89-DLP-CRED-007 | `B89_CRED_AWS_ACCESS_KEY_PAIR` | Alta | ID y secreto de AWS en el mismo archivo | Apagada |
| B89-DLP-CRED-008 | `B89_SECRET_DATABASE_CONNECTION` | Alta | URI PostgreSQL, MySQL o MongoDB con usuario y clave | Apagada |
| B89-DLP-CRED-009 | `B89_SECRET_CREDENTIAL_ASSIGNMENT` | Media | Valor largo junto a un nombre de campo de secreto | Apagada |
| B89-DLP-PII-001 | `B89_PII_PERU_DNI_CONTEXTUAL` | Media | Ocho dígitos cerca de una etiqueta DNI | Apagada |
| B89-DLP-PII-002 | `B89_PII_PERU_RUC_CONTEXTUAL` | Media | Once dígitos cerca de una etiqueta RUC | Apagada |
| B89-DLP-FP-001 | `B89_DLP_EXACT_FILE_FINGERPRINT` | Alta | SHA-256 exacto presente en el catálogo corporativo | Siempre disponible |

Una severidad alta significa que se encontró un formato parecido a una credencial; no confirma que siga activa, pertenezca a B89 o se haya filtrado. El analista valida contexto y rota/revoca por el procedimiento del proveedor. Reglas de DNI/RUC solo coinciden cuando también aparece una etiqueta cercana; aun así pueden existir falsos positivos.

## Fingerprints de documentos

`fingerprints.sha256` contiene un hash SHA-256 aprobado por línea. El endpoint calcula el SHA-256 de cada archivo observado y compara el resultado con el catálogo. Una coincidencia genera una alerta sin transmitir nombre, ruta, contenido ni cadenas coincidentes.

El administrador puede pegar o cargar el catálogo desde el panel de B89. Solo se aceptan valores hexadecimales de 64 caracteres, uno por línea; no nombres, rutas ni notas que puedan revelar datos personales. El catálogo aprobado se propaga a endpoints inscritos en hasta 30 segundos. Si no hay huellas del CISO, el catálogo permanece vacío y no hay coincidencias por fingerprint.

El hash exacto detecta copias byte a byte. Cambios dentro del documento producen otro hash; para documentos modificados se necesitan clasificadores como EDM de Microsoft Purview, no una lista de SHA-256. La acción opcional de cuarentena solo se aplica a estos matches exactos. Cuando se activa, RabbitDLP copia el archivo al almacén local protegido, verifica el hash y elimina la copia observada; conserva localmente la ruta original y el ACL para permitir una restauración administrativa. La ruta y el contenido nunca se envían a B89 ni a Wazuh. Las reglas YARA de contenido solo alertan.

## Configuración del endpoint

El instalador exige `-WatchRoot` con directorios locales explícitos aprobados por privacidad. El agente inspecciona archivos al crearse o cambiar, ejecuta un barrido al arrancar y vuelve a conciliar las rutas cada hora. Tras una pausa de 800 ms, el archivo se inspecciona localmente con YARA-X.

En el instalador, configura `-DlpControlPlaneUrl 'https://dev.security.b89.io'`. Te pedirá un token de inscripción generado en **Políticas → Protección de datos**. El token de inscripción se usa una vez y no se guarda. El servidor devuelve una credencial exclusiva del endpoint; solo esa credencial se guarda en config.json con ACL para SYSTEM y Administrators. Cada consulta usa HTTPS; el servidor aplica permisos y revisión CAS. El endpoint no marca una política como aplicada hasta confirmar la revisión al servidor.

Sin control plane, el instalador puede operar con el paquete local verificado por SHA-256 externo. Ese modo no recibe cambios del panel.

## Aprobar y publicar cambios

1. El propietario de datos describe una categoría, propósito, rutas y retención de eventos permitidos.
2. Ingeniería agrega una regla con nombre estable y `meta` que incluya `policy_id`, `policy_version`, `title`, `category` y `severity`.
3. Se revisan falsos positivos y coste de escaneo con datos sintéticos, nunca secretos reales.
4. Seguridad de Datos aprueba el alcance; el SOC aprueba la severidad.
5. Se empaqueta una versión, se valida externamente el SHA-256 y se registra la decisión.
6. Se confirma en Wazuh una alerta sintética de extremo a extremo con resultado redactado.

El panel permite activar/desactivar reglas incluidas, actualizar fingerprints, decidir si las huellas exactas van a cuarentena y administrar grupos USB autorizados. Cada grupo de SOC contiene los SIDs de usuarios o grupos locales/Active Directory. El agente Windows genera la política de Device Control de Microsoft Defender con acceso para esas identidades y denegación del almacenamiento extraíble para las demás. No se deshabilitan las cuentas de Windows.

USB está apagado por defecto. Para activarlo, el operador debe confirmar que los equipos usan Microsoft Defender for Endpoint Plan 1/2 o Defender for Business. El agente Windows también comprueba compatibilidad y conflictos con políticas de MDM/Intune/GPO antes de escribir los valores locales. Muestra `active` solo cuando `Get-MpComputerStatus` informa que Device Control está habilitado, con denegación predeterminada `Allow` acotada a `RemovableMediaDevices`; las reglas XML de RabbitDLP deniegan el acceso al almacenamiento extraíble fuera de los SIDs autorizados. Los equipos reportan `unsupported`, `conflict`, `pending` o `error` si no pueden confirmar la aplicación. Consulta [configuración oficial](https://learn.microsoft.com/en-us/defender-endpoint/device-control-configure), [condiciones por SID](https://learn.microsoft.com/en-us/defender-endpoint/device-control-policies) y [planes compatibles](https://learn.microsoft.com/en-us/defender-endpoint/device-control-faq).

Las políticas de grupos no sincronizan membresías de usuarios desde AD ni Entra. El SOC debe proporcionar SIDs válidos de Windows y revisar que los equipos estén bajo administración y licenciamiento compatibles. Reglas YARA nuevas requieren compilar y distribuir una versión nueva del paquete. Los eventos incluyen la huella del contenido de política para identificar qué configuración se aplicó.

## Recepción de alertas

El endpoint escribe JSONL en `C:\ProgramData\B89\Ferrispector\events.jsonl`. La configuración local del agente Wazuh lee esa ruta; el manager aplica la regla `101110` de `infra/wazuh/endpoint/rules/b89_endpoint_rules.xml` y genera prioridad alta. El instalador de endpoint no toca el Manager: su regla debe desplegarse con la política administrada del Manager.

El evento incluye regla, hostname, hash SHA-256 del archivo, extensión, tamaño, hora y hash de política; no incluye ruta, contenido ni texto coincidente. Un match exacto incluye el estado y el ID de cuarentena, nunca la ruta ni el contenido.

## DLP de Microsoft 365

El repositorio tiene reglas SharePoint/OneDrive `101949` (coincidencia DLP), `101950` (DLP alta) y `101951` (anulación) en `detections/sharepoint/labels-and-dlp/rule.xml`. Su metadata indica `testing`; `docs/23-sharepoint-onedrive.md` indica que falta `ActivityFeed.ReadDlp`. No hay evidencia suficiente para afirmar que los eventos DLP de M365 llegan al Indexer.

## Límites

Ferrispector detecta contenido en disco; no inspecciona tráfico de red ni bloquea carga web, correo, impresión o portapapeles. La cuarentena exacta es reversible y no aplica a coincidencias de contenido. El control de USB cubre almacenamiento extraíble con Microsoft Defender Device Control; no equivale a bloquear cualquier periférico USB.
