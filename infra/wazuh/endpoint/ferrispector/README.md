# RabbitDLP (motor Ferrispector) en Windows, macOS y Linux

RabbitDLP es el producto de endpoints de B89; Ferrispector es su motor local YARA-X. Inspecciona únicamente las carpetas `WatchRoot` aprobadas en la instalación y envía eventos JSONL a un agente Wazuh existente. La política puede poner en cuarentena copias exactas de huellas SHA-256 aprobadas. Las coincidencias de contenido YARA siguen siendo alertas para reducir falsos positivos.

## Política y datos

El paquete usa la política `policy/starter-credentials.yar`: seis detectores de credenciales activos por defecto y cinco reglas avanzadas optativas. DNI/RUC requieren aprobación de privacidad; las reglas avanzadas pueden elevar falsos positivos. `policy/fingerprints.sha256` es un catálogo inicialmente vacío con una huella SHA-256 aprobada por línea. El administrador gestiona reglas activas y fingerprints desde **DLP de endpoints** en la consola. Los cambios del servidor se consultan cada 30 segundos (esa consulta es también el latido: sin ella durante 2 minutos, el equipo aparece «Sin conexión») y el endpoint informa la revisión como aplicada solo después de confirmar el acuse.

## Conectar un equipo desde la consola

En **DLP de endpoints → Conectar un equipo**: (1) crea la clave (un solo uso, vence en 30 minutos); (2) elige el sistema, escribe la carpeta aprobada y copia el comando ya armado con la URL de la consola; cuando el instalador lo pida, pega la clave; (3) la consola detecta sola cuándo el equipo se conecta. «Cancelar y anular la clave» invalida una clave sin usar.

Cada evento reporta el ID de regla, hostname, SHA-256 del archivo, extensión, tamaño, hora y hash de política. No incluye rutas ni contenido. Los registros locales de cuarentena conservan la ruta original y los permisos solo bajo SYSTEM y Administradores; la ruta no se envía al SIEM. El token de inscripción no se escribe en eventos, logs de servicio ni argumentos de proceso. Se solicita de forma oculta y se usa una sola vez. El servidor devuelve endpointCredential, una credencial exclusiva del equipo, y solo esta credencial se guarda en config.json con permisos de administrador.

## Crear paquetes para macOS o Linux

Ejecuta el builder en un equipo macOS o Linux con `curl`, `tar`, `python3`, `zip` y `shasum` o `sha256sum`. Los activos YARA-X v1.24.0 se descargan del [release oficial](https://github.com/VirusTotal/yara-x/releases/tag/v1.24.0); el builder rechaza cualquier SHA-256 que no coincida con el pin de esa plataforma y arquitectura.

```sh
./build-unix-package.sh arm64 ./RabbitDLP-macos-arm64.zip
./build-unix-package.sh x64 ./RabbitDLP-linux-x64.zip
```

El builder selecciona la plataforma donde se ejecuta. Para una compilación macOS ARM64, por ejemplo, usa `arm64`; para Linux x64, ejecuta el builder en Linux y usa `x64`. No construye paquetes cruzados.

Para Windows, compila un instalador gráfico de RabbitDLP con Inno Setup 6.4 o posterior. El instalador integra el paquete, pide elevación de administrador, presenta un asistente para Wazuh, las carpetas aprobadas y el token de B89, muestra el progreso por etapas, y registra un desinstalador en **Aplicaciones instaladas** y el menú Inicio. Si Wazuh aún no está instalado, el asistente solicita su contraseña de registro; esa contraseña y el token DLP no se pasan como argumentos ni se incluyen en el registro del instalador. El grupo inicial es default; cualquier grupo personalizado elegido debe existir previamente en Wazuh. La URL solicitada es la URL base HTTPS de la consola B89, sin una ruta de pantalla ni /api/dlp/agent/enroll; el instalador agrega la ruta de API de inscripción.

Si la instalación falla, el asistente muestra la etapa y el error concreto. RabbitDLP guarda el diagnóstico en C:\ProgramData\B89\RabbitDLP\Logs\install-last-error.txt; si el fallo ocurrió al instalar Wazuh, también guarda el registro MSI detallado en wazuh-agent-install.log. Ambos archivos quedan limitados a SYSTEM y Administradores. El instalador verifica que Wazuh haya registrado al agente antes de intentar la inscripción DLP; para un administrador público, el equipo debe poder alcanzar TCP 1515 para el registro y TCP 1514 para el tráfico del agente.

En Windows, se permiten como raíz aprobada las carpetas de Microsoft Cloud Files seleccionadas explícitamente, como Documentos dentro de OneDrive. No se siguen enlaces simbólicos o junctions genéricos ni se inspeccionan archivos con puntos de reanálisis, por lo que RabbitDLP no fuerza la descarga de archivos solo en la nube.

```powershell
.\build-rabbitdlp-installer.ps1 -Architecture x64
```

El resultado es `dist/rabbitdlp/RabbitDLP-Setup-Windows-x64-1.1.0.exe` y un `.sha256` externo. La arquitectura `arm64` también está disponible. Verifica y distribuye el hash por un canal aprobado separado del instalador.

RabbitDLP queda bajo `C:\Program Files\B89\RabbitDLP`; los datos y la credencial protegida del agente conservan la ruta compatible `C:\ProgramData\B89\Ferrispector`. La tarea programada se ejecuta como `SYSTEM` para leer únicamente las carpetas escogidas. Al desinstalar, se detiene la tarea, se quita la sección marcada de `ossec.conf`, se revierte solo la política USB local que RabbitDLP pueda verificar como propia y se eliminan la configuración, la credencial y los eventos locales. Si hay elementos en cuarentena, se preservan y se deja una herramienta de restauración en `C:\ProgramData\B89\RabbitDLP\restore-quarantined-file.ps1`; el agente Wazuh y las carpetas vigiladas permanecen. El endpoint remoto debe revocarse desde DLP de endpoints.

Para listar o restaurar archivos desde una consola PowerShell elevada:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\B89\RabbitDLP\restore-quarantined-file.ps1' -List
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\B89\RabbitDLP\restore-quarantined-file.ps1' -Id <id-de-cuarentena>
```

La restauración verifica el SHA-256 y nunca sobrescribe la ruta original si ya existe otro archivo.

Los ejecutables se construyen sin certificado de firma de B89; Windows puede mostrar un aviso de editor desconocido hasta que se incorporen firma de código y certificado corporativo.

Antes de distribuirlo comercialmente, compila con la licencia comercial de Inno Setup que corresponda al equipo de desarrollo.

## Instalar en macOS o Linux

Requisitos: macOS o Linux x64/ARM64, Python 3, un agente Wazuh ya instalado y conectado, y privilegios de administrador. Extrae el ZIP verificado y ejecuta el instalador con la ruta o rutas concretas aprobadas:

```sh
sudo ./install-unix-endpoint.sh install \
  --watch-root /Users/investigacion/proyecto \
  --control-plane-url https://dev.security.b89.io
```

Repite `--watch-root` si hay más de una carpeta aprobada. La URL del control plane es opcional: sin ella, se usa la política local incluida y no hay cambios remotos. Con URL, el instalador pide el token de inscripción en una entrada oculta. No pegues el token como argumento de terminal.

El instalador requiere que Wazuh ya exista y no cambia el manager ni las credenciales Wazuh. Agrega una entrada marcada a `ossec.conf` para que Wazuh lea `/var/lib/b89/ferrispector/events.jsonl` como JSON. Guarda una copia antes de editar ese archivo. Si el agente Wazuh no está instalado, primero instálalo y conéctalo con el procedimiento corporativo.

El servicio corre como `root` porque necesita permisos para leer las carpetas autorizadas:

- macOS: `launchd`, plist `/Library/LaunchDaemons/io.b89.ferrispector.plist`.
- Linux: `systemd`, unidad `b89-ferrispector.service`.

La instalación guarda programa y reglas bajo `/opt/b89/ferrispector`, y configuración, credencial de endpoint, estado local y eventos bajo `/var/lib/b89/ferrispector`. El script omite enlaces simbólicos y no sigue directorios enlazados. No vigila el disco entero: solo recorre `WatchRoot`.

La lectura se realiza por sondeo, cada 30 segundos. Por eso un cambio de archivo puede tardar hasta 30 segundos en detectarse; no es una notificación instantánea del sistema operativo. En el primer arranque se concilian los archivos de las rutas seleccionadas.


## Rotación, migración y CLI interna

La inscripción invalida el token de instalación y devuelve una credencial nueva solo una vez. El servidor persiste únicamente su SHA-256 y exige esa credencial para policy y ack. Windows, macOS y Linux usan configuración v2; la configuración v1 con agent_token es incompatible.

Después de aplicar la migración, los endpoints previos quedan en versión 0 y ya no sincronizan políticas. Para volver a conectarlos, revoca el endpoint antiguo en DLP de endpoints, crea un token nuevo y reinstala RabbitDLP con las mismas rutas WatchRoot aprobadas. En macOS o Linux, ejecuta primero install-unix-endpoint.sh remove y luego install-unix-endpoint.sh install con las rutas aprobadas y el control plane. La eliminación local no revoca el endpoint remoto. En Windows, vuelve a ejecutar el instalador. No reutilices el token anterior.

La CLI interna del servicio no es un instalador: en Unix el servicio ejecuta ferrispector.py run --config <ruta>; en Windows la tarea programada ejecuta ferrispector.ps1 -Mode Watch -ConfigPath <ruta>. La operación enroll de Unix pide el token con entrada oculta y no acepta un argumento --token. No pases secretos como argumentos de proceso. Si el servidor completó el enrolamiento pero falló el guardado local, revoca el endpoint huérfano y solicita un token nuevo.
## Desinstalar RabbitDLP

```sh
sudo ./install-unix-endpoint.sh remove
```

Esto detiene y quita el servicio, elimina la sección local de RabbitDLP de `ossec.conf`, sus archivos y la credencial local. Si existe cuarentena, preserva únicamente esos archivos y una utilidad de restauración sin credenciales. Lista y restaura con privilegios de administrador usando los comandos que muestra el desinstalador. Conserva Wazuh y las carpetas vigiladas. La copia de respaldo `ossec.conf.b89-backup` queda disponible junto al archivo de configuración. Revoca también la credencial remota desde la interfaz; remove solo limpia este equipo.

Si la desinstalación conservó la cuarentena, puedes listarla y restaurar un archivo desde una terminal con permisos de administrador:

```sh
sudo python3 /var/lib/b89/ferrispector/quarantine-restore.py list \
  --config /var/lib/b89/ferrispector/quarantine-restore-config.json
sudo python3 /var/lib/b89/ferrispector/quarantine-restore.py restore \
  --config /var/lib/b89/ferrispector/quarantine-restore-config.json \
  --id ID_DE_CUARENTENA
```

En Windows, desinstala desde **Aplicaciones instaladas** o desde el menú Inicio. La desinstalación local no revoca el endpoint remoto; revócalo también desde DLP de endpoints.

## Permisos, firma y límites

El acceso administrativo se limita al instalador y al servicio local. Los procesos de análisis leen los archivos de las rutas autorizadas y guardan temporalmente metadatos de ruta localmente para no volver a escanear archivos sin cambios; esos metadatos no se incluyen en los eventos enviados. El catálogo fingerprint contiene hashes sin rutas ni nombres.

El SHA-256 del activo comprueba que el archivo descargado coincide con el valor fijado. Esto no equivale a una firma de B89 ni garantiza la procedencia del ZIP final si el hash del paquete no se valida por separado. YARA-X es software de terceros; se incluye su aviso BSD-3-Clause en `THIRD-PARTY-NOTICES.txt`. No se incluyen certificados de firma B89, notarización de macOS ni firma de paquetes. Aplica el control de Gatekeeper y la política de ejecución de tu organización.

El bloqueo USB de Windows usa las reglas locales de Device Control de Microsoft Defender y los SIDs de usuarios/grupos que gestiona el SOC. Requiere Microsoft Defender for Endpoint Plan 1/2 o Defender for Business y una política sin conflicto con Intune o GPO. RabbitDLP detecta esos conflictos y comunica el estado real al SOC. Consulta [configuración de Device Control](https://learn.microsoft.com/en-us/defender-endpoint/device-control-configure) y [requisitos de licencia](https://learn.microsoft.com/en-us/defender-endpoint/device-control-faq).

YARA-X detecta patrones visibles en archivos leídos; no bloquea exfiltración de red, correo, carga web, impresión ni portapapeles. Las huellas exactas no detectan documentos modificados. La cuarentena automática solo se ofrece para una huella SHA-256 exacta cargada por el SOC; una alerta de contenido no mueve el archivo. La acción requiere habilitarse en la política de B89 y puede restaurarse con privilegios de administrador.
