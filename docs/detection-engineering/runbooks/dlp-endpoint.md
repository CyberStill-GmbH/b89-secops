# Runbook · DLP de endpoints (Ferrispector)

Reglas 101110–101116 (`infra/wazuh/endpoint/rules/b89_endpoint_rules.xml`). Ferrispector detecta; no
bloquea, no mueve y no borra archivos. Los eventos traen el equipo, la regla, la extensión, el tamaño y la
huella SHA-256 del archivo; nunca la ruta ni el contenido.

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
3. Contacta a la persona que usa el equipo y pídele que ubique el archivo por su huella SHA-256 (la consola la muestra en el detalle técnico).
4. Credencial real: rótala o revócala en el servicio de origen y revisa su uso reciente; luego borra el archivo.
5. Dato personal o documento protegido: confirma si ese equipo y esa carpeta pueden guardarlo; si no, muévelo a la ubicación aprobada.
6. Clasifica la alerta con la conclusión y una nota de lo que hiciste.

## 101110–101112 · Hallazgos

- 101110 (nivel 5): dato sensible de una regla avanzada (DNI, RUC, contraseñas en texto).
- 101111 (nivel 8): credencial reconocible (clave privada, token de GitHub, Slack, Google, Azure, OpenAI, AWS, base de datos).
- 101112 (nivel 10): copia exacta de un documento protegido por huella.

## 101113–101116 · Salud del agente

1. 101114 (sin política más de 5 minutos): revisa si el equipo fue revocado a propósito. Si no, comprueba la red del equipo y que la consola responda.
2. 101116 (muchos archivos sin revisar): revisa permisos de las carpetas aprobadas y archivos bloqueados por otro programa.
