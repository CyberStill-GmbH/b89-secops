# Ferrispector en Windows, macOS y Linux

Ferrispector es un detector local de B89 basado en YARA-X. Inspecciona únicamente las carpetas `WatchRoot` aprobadas en la instalación y envía eventos JSONL a un agente Wazuh existente. Detecta; no bloquea ni pone archivos en cuarentena.

## Política y datos

El paquete usa la política `policy/starter-credentials.yar`: seis detectores de credenciales activos por defecto y cinco reglas avanzadas optativas. DNI/RUC requieren aprobación de privacidad; las reglas avanzadas pueden elevar falsos positivos. `policy/fingerprints.sha256` es un catálogo inicialmente vacío con una huella SHA-256 aprobada por línea. El administrador gestiona reglas activas y fingerprints desde **Políticas → Protección de datos**. Los cambios del servidor se consultan cada 30 segundos y el endpoint informa la revisión como aplicada solo después de confirmar el acuse.

Cada evento reporta el ID de regla, hostname, SHA-256 del archivo, extensión, tamaño, hora y hash de política. No incluye rutas ni contenido. El token de inscripción no se escribe en eventos, logs de servicio ni argumentos de proceso. Se solicita de forma oculta y se usa una sola vez. El servidor devuelve endpointCredential, una credencial exclusiva del equipo, y solo esta credencial se guarda en config.json con permisos de administrador.

## Crear paquetes para macOS o Linux

Ejecuta el builder en un equipo macOS o Linux con `curl`, `tar`, `python3`, `zip` y `shasum` o `sha256sum`. Los activos YARA-X v1.24.0 se descargan del [release oficial](https://github.com/VirusTotal/yara-x/releases/tag/v1.24.0); el builder rechaza cualquier SHA-256 que no coincida con el pin de esa plataforma y arquitectura.

```sh
./build-unix-package.sh arm64 ./Ferrispector-macos-arm64.zip
./build-unix-package.sh x64 ./Ferrispector-linux-x64.zip
```

El builder selecciona la plataforma donde se ejecuta. Para una compilación macOS ARM64, por ejemplo, usa `arm64`; para Linux x64, ejecuta el builder en Linux y usa `x64`. No construye paquetes cruzados.

Para Windows, ejecuta el builder incluido en Windows PowerShell:

```powershell
.\build-windows-package.ps1 -Architecture x64 -OutputPath .\Ferrispector-Windows-x64.zip
```

Cada builder genera un `.sha256` externo para el paquete. Verifica y distribuye ese hash por un canal aprobado separado del archivo ZIP. Los paquetes no están firmados por B89.

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

Después de aplicar la migración, los endpoints previos quedan en versión 0 y ya no sincronizan políticas. Para volver a conectarlos, revoca el endpoint antiguo en Políticas de protección de datos, crea un token nuevo y reinstala Ferrispector con las mismas rutas WatchRoot aprobadas. En macOS o Linux, ejecuta primero install-unix-endpoint.sh remove y luego install-unix-endpoint.sh install con las rutas aprobadas y el control plane. La eliminación local no revoca el endpoint remoto. En Windows, vuelve a ejecutar el instalador. No reutilices el token anterior.

La CLI interna del servicio no es un instalador: en Unix el servicio ejecuta ferrispector.py run --config <ruta>; en Windows la tarea programada ejecuta ferrispector.ps1 -Mode Watch -ConfigPath <ruta>. La operación enroll de Unix pide el token con entrada oculta y no acepta un argumento --token. No pases secretos como argumentos de proceso. Si el servidor completó el enrolamiento pero falló el guardado local, revoca el endpoint huérfano y solicita un token nuevo.
## Quitar Ferrispector

```sh
sudo ./install-unix-endpoint.sh remove
```

Esto detiene y quita el servicio, elimina la sección local de Ferrispector de `ossec.conf`, sus archivos y la credencial local. Revoca también la credencial remota desde la interfaz; remove solo limpia este equipo. Conserva Wazuh y las carpetas vigiladas. La copia de respaldo `ossec.conf.b89-backup` queda disponible junto al archivo de configuración.

Para Windows, usa `install-windows-endpoint.ps1` según las instrucciones del propio instalador.

## Permisos, firma y límites

El acceso administrativo se limita al instalador y al servicio local. Los procesos de análisis leen los archivos de las rutas autorizadas y guardan temporalmente metadatos de ruta localmente para no volver a escanear archivos sin cambios; esos metadatos no se incluyen en los eventos enviados. El catálogo fingerprint contiene hashes sin rutas ni nombres.

El SHA-256 del activo comprueba que el archivo descargado coincide con el valor fijado. Esto no equivale a una firma de B89 ni garantiza la procedencia del ZIP final si el hash del paquete no se valida por separado. YARA-X es software de terceros; se incluye su aviso BSD-3-Clause en `THIRD-PARTY-NOTICES.txt`. No se incluyen certificados de firma B89, notarización de macOS ni firma de paquetes. Aplica el control de Gatekeeper y la política de ejecución de tu organización.

YARA-X detecta patrones visibles en archivos leídos; no es una prevención de exfiltración. Las huellas exactas no detectan documentos modificados. La política incluida no cubre todos los datos personales, documentos comprimidos, tráfico, correo, carga web, impresión ni portapapeles. Una alerta requiere revisión humana y no autoriza cuarentena, borrado o sanción.
