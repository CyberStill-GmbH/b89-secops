RabbitDLP para Windows
======================

RabbitDLP está activo en este equipo. La tarea RabbitDLP inicia el detector local de forma automática con Windows y analiza solamente las carpetas aprobadas en el asistente.

El grupo inicial del agente Wazuh es default. Si eliges un grupo personalizado, créalo primero en el administrador Wazuh.

Administra equipos y reglas en DLP de endpoints de B89. RabbitDLP genera alertas para coincidencias de contenido. Puede poner en cuarentena copias exactas de huellas aprobadas y bloquear el almacenamiento USB de cuentas no autorizadas si el SOC activa Device Control y los equipos cumplen los requisitos de Microsoft Defender.

Si la instalación falla, consulta C:\ProgramData\B89\RabbitDLP\Logs\install-last-error.txt. El registro MSI de Wazuh, si se generó, está en la misma carpeta. Los archivos de diagnóstico solo son accesibles para SYSTEM y Administradores.

Las carpetas locales de Cloud Files, como Documentos dentro de OneDrive, se admiten si las seleccionas explícitamente. RabbitDLP no sigue enlaces simbólicos o junctions genéricos y omite archivos que Windows marca como puntos de reanálisis para evitar descargar archivos solo en la nube.

Para quitarlo, usa Aplicaciones instaladas de Windows o el acceso «Desinstalar RabbitDLP» del menú Inicio. La desinstalación quita RabbitDLP, su credencial y los eventos locales, además de su entrada marcada de Wazuh. Si hay archivos en cuarentena, los conserva junto con la herramienta para listarlos y restaurarlos como administrador. Conserva el agente Wazuh y las carpetas aprobadas. También revoca el equipo en DLP de endpoints para invalidar su credencial remota.

La detección usa YARA-X. Consulta THIRD-PARTY-NOTICES.txt incluido con los componentes instalados.
