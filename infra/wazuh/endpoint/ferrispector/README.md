# Ferrispector para Windows

Ferrispector es un detector local B89 que usa YARA-X. El paquete ZIP incluye motor, reglas, catálogo de fingerprints, instalador y avisos de licencia. El instalador reutiliza un Wazuh ya conectado al manager indicado o instala Wazuh 4.14.10-1 y verifica la firma Authenticode y el publisher `Wazuh, Inc`.

## Reglas incluidas

El paquete inicial activa seis patrones reconocibles de credenciales: clave privada PEM, token GitHub, token Slack, clave Google API, clave Azure Storage y clave OpenAI. Incluye reglas avanzadas opt-in para pares de credenciales AWS, cadenas de conexión de bases de datos, valores largos junto a campos de secreto y números peruanos con etiquetas DNI/RUC.

Los números DNI/RUC y las reglas genéricas empiezan apagados desde el panel. Actívalos solo con aprobación de Seguridad de Datos y revisión de falsos positivos. No se incluyen datos de ejemplo que sean secretos reales.

El catálogo `policy/fingerprints.sha256` acepta una huella SHA-256 aprobada por línea. Está vacío hasta que el CISO proporcione fingerprints. Una coincidencia exacta detecta copias idénticas; cambios del documento producen otra huella.

## Construir un paquete

YARA-X `v1.24.0` se descarga desde su release oficial y se valida con el SHA-256 fijado en el script.

```powershell
.\build-windows-package.ps1 `
  -Architecture x64 `
  -OutputPath .\output\Ferrispector-Windows-x64.zip
```

Para actualizar fingerprints antes del build, agrega únicamente hashes aprobados a `policy/fingerprints.sha256`. Para actualizar reglas integradas, aumenta la versión, revisa patrones y construye un paquete nuevo. El ZIP no está firmado por B89: entrega también el SHA-256 `.sha256` por un canal confiable.

## Instalar en una PC

1. Descarga el ZIP y su hash desde un canal aprobado.
2. Extráelo una vez en la PC monitoreada.
3. Ejecuta PowerShell como administrador:

```powershell
.\install-windows-endpoint.ps1 `
  -FerrispectorPackage .\Ferrispector-Windows-x64.zip `
  -ExpectedPackageSha256 '<SHA-256 validado por canal independiente>' `
  -WazuhManager 'wazuh.example.internal' `
  -WatchRoot 'D:\ProyectosAprobados' `
  -DlpControlPlaneUrl 'https://dev.security.b89.io'
```

El instalador pide un token de inscripción generado en **Políticas → Protección de datos**. El token se usa para vincular un endpoint y se guarda con permisos restringidos a SYSTEM y Administrators. Si se omite `-DlpControlPlaneUrl`, el equipo usa las reglas y fingerprints del ZIP sin recibir cambios remotos.

`WatchRoot` es obligatorio y debe ser local, existir y contar con aprobación de privacidad. Ferrispector barre esas rutas al iniciar y cada hora, además de vigilar cambios. Cuando está conectado, consulta las reglas y fingerprints cada 30 segundos y confirma su revisión al servidor. La UI informa la revisión aplicada solo después del acuse del equipo.

## Qué se envía a Wazuh

La instalación crea `C:\ProgramData\B89\Ferrispector\events.jsonl` y agrega su ruta completa a `ossec.conf`. Cada evento incluye regla, hostname, hash SHA-256 del archivo, extensión, tamaño, hora y huella de política. No registra la ruta, el contenido ni el texto coincidente. La regla `101110` genera prioridad media; `101111` eleva las credenciales reconocibles y fingerprints exactos a prioridad alta. Ambas se despliegan desde la política administrada de Wazuh.

## Límites

YARA-X inspecciona bytes locales y patrones que estén visibles en el archivo. Fingerprints exactos cubren copias idénticas; no identifican documentos editados. La política inicial no clasifica en forma semántica documentos Office comprimidos, tarjetas de pago ni datos personales generales. Para esa cobertura, usar clasificadores de Microsoft Purview o clasificación exacta/entrenada aprobada.

Ferrispector detecta; no bloquea copias, correo, carga web, impresión ni portapapeles. Un hallazgo requiere revisión y no autoriza cuarentena, borrado o sanción.

## DLP de Microsoft 365

El repo también incluye reglas SharePoint/OneDrive `101949` (coincidencia DLP), `101950` (severidad alta) y `101951` (anulación). La metadata sigue en `testing` y `ActivityFeed.ReadDlp` no está concedido, por lo que no hay evidencia suficiente de entrega de eventos DLP al Indexer.

## Licencia

El paquete incluye `THIRD-PARTY-NOTICES.txt` con el aviso BSD-3-Clause de YARA-X. Ferrispector es un wrapper B89, no un producto de VirusTotal o Google.
