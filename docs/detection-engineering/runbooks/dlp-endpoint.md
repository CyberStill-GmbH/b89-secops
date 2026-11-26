# Runbook · DLP de endpoints (RabbitDLP)

Reglas 101110–101116 (`infra/wazuh/endpoint/rules/b89_endpoint_rules.xml`). Las coincidencias de reglas de
contenido generan alertas y no cambian el archivo. La política puede poner en cuarentena una coincidencia
SHA-256 exacta de la lista aprobada. En Windows también puede denegar almacenamiento USB a los SIDs que el
SOC no autorice mediante Device Control de Microsoft Defender. El bloqueo USB está apagado por defecto y
no bloquea el inicio de sesión de la cuenta. macOS y Linux solo reportan; no aplican esta política USB.
Los eventos incluyen equipo, regla, extensión, tamaño y huella SHA-256; nunca envían ruta ni contenido.

## Instalar un equipo

1. En **DLP de endpoints**, abre una ficha de Windows, macOS o Linux y descarga la arquitectura del equipo.
   Los paquetes contienen el motor YARA-X v1.24.0, las reglas iniciales y sus avisos de licencia; cada
   archivo de origen se comprueba con SHA-256 durante la compilación. La descarga requiere `dlp.configure`
   y queda auditada como `dlp.installer.requested`.
2. Extrae el ZIP en el equipo y abre **Conectar un equipo** en la consola. Selecciona el sistema, indica la
   carpeta aprobada y los datos del servidor que pida el asistente. En Windows, el SHA-256 del ZIP se
   completa al descargarlo y el instalador lo compara antes de instalar.
3. Crea una clave de un solo uso, vence en 30 minutos. Pégala cuando el instalador la solicite; no la pongas
   en el comando ni en el historial de la terminal. En Windows ejecuta PowerShell como administrador; en
   macOS o Linux usa `sudo`.
4. Espera a que la consola muestre el equipo conectado. La primera conexión recibe la política activa en
   menos de un minuto. Si no aparece, comprueba red, permisos de la carpeta y la URL de la consola.

La API entrega paquetes solo a quien tenga `dlp.configure`; la ruta de descarga responde sin caché. Si la
clave no se puede guardar, la consola muestra la referencia para Plataforma. Si falla el registro de
auditoría después de crearla, la API anula la clave para que no quede un secreto activo sin seguimiento.

## Triage de 10 minutos

1. Abre la alerta y mira «Por qué saltó»: qué tipo de dato se encontró y en qué equipo.
2. Abre **DLP de endpoints** y revisa si el equipo está «Protegido» y con la revisión vigente.
3. Revisa el estado de la acción. Si una huella exacta aparece como `quarantined`, anota su ID; el archivo quedó en la cuarentena local protegida. Si aparece `failed`, coordina una revisión local como administrador.
4. Para restaurar un archivo, usa la herramienta de RabbitDLP en Windows (`restore-quarantined-file.ps1 -List` y luego `-Id <id>`) o los comandos que muestra el desinstalador en macOS/Linux. La restauración valida el hash y no sobrescribe un archivo existente.
5. Credencial real: rótala o revócala en el servicio de origen y revisa su uso reciente; si no se aplicó cuarentena, elimina el archivo según el procedimiento de respuesta.
6. Dato personal o documento protegido: confirma si ese equipo y esa carpeta pueden guardarlo; si no, muévelo a la ubicación aprobada.
7. Clasifica la alerta con la conclusión y una nota de lo que hiciste.

## Configurar y resolver el control USB

En **DLP de endpoints → Control de USB**, el SOC crea grupos de autorización y agrega un SID de Windows por línea. El SID puede pertenecer a un usuario o a un grupo local/de Active Directory. RabbitDLP no sincroniza membresías; usa los SIDs que recibe Windows. Antes de guardar el bloqueo, el operador debe verificar una licencia compatible de Defender y confirmar que no existe otra política de Device Control. La consola no valida la licencia. En cada equipo, revisa el estado reportado: `active`, `pending`, `conflict`, `unsupported` o `error`. `active` significa que Defender confirmó la política, no que se haya probado el bloqueo físico.

Los eventos de dispositivos denegados se consultan en **Microsoft Defender → Reports → Endpoints → Device control** o Advanced Hunting (`DeviceEvents` con `ActionType == "RemovableStoragePolicyTriggered"`). B89 recibe el estado de la política, pero todavía no ingiere esos eventos detallados. Para verlos como alertas en el SIEM, falta conectar y validar la fuente de eventos de Defender.

## 101110–101112 · Hallazgos

- 101110 (nivel 5): dato sensible de una regla avanzada (DNI, RUC, contraseñas en texto).
- 101111 (nivel 8): credencial reconocible (clave privada, token de GitHub, Slack, Google, Azure, OpenAI, AWS, base de datos).
- 101112 (nivel 10): copia exacta de un documento protegido por huella.

## 101113–101116 · Salud del agente

1. 101114 (sin política más de 5 minutos): revisa si el equipo fue revocado a propósito. Si no, comprueba la red del equipo y que la consola responda.
2. 101116 (muchos archivos sin revisar): revisa permisos de las carpetas aprobadas y archivos bloqueados por otro programa.
