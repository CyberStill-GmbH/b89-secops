// GENERADO por apps/api/scripts/generate-bunny-knowledge.py. No editar a mano.
// Fuentes: docs/detection-engineering (runbooks, playbooks), detections/ y XML de reglas B89.
/* eslint-disable */
import type { SocKnowledge } from './soc-knowledge.js';

export const SOC_KNOWLEDGE: SocKnowledge = {
 "attackVersion": "Enterprise v16",
 "runbookIndex": "# Runbooks de triage e investigación B89\n\nParte de [17 · Ingeniería de detección](../../17-ingenieria-de-deteccion.md). Cada runbook sigue el mismo\nesquema: **alcance** (reglas), **triage en 10 minutos**, **investigación**, **contención** (siempre por B89\nRespond con aprobación del Líder SOC), **recuperación**, **cierre y evidencia** y **consultas** (KQL para\nDiscover sobre `wazuh-alerts-*`).\n\n| Runbook | Casos de uso | Prioridad típica |\n| --- | --- | --- |\n| [Ataques de credenciales](credenciales.md) | M365 fuerza bruta/spray y cadena, BEC, Kerberos, consola AWS, SSH | P1–P2 |\n| [Escalada de privilegios](escalada-de-privilegios.md) | Roles de Entra y tier 0, IAM/Identity Center, grupos de AD, sudo/grupos y persistencia Linux | P1–P2 |\n| [Malware y EDR](malware-edr.md) | Bitdefender (malware, cuarentena, protección deshabilitada), Sophos, Outlook → proceso | P1–P2 |\n| [Vulnerabilidad expuesta](vulnerabilidad-expuesta.md) | Snyk crítica/alta con exploit maduro y expuesta, Wazuh VD | P1–P3 |\n| [Oleada en el WAF](oleada-waf.md) | Cloudflare 101513 y 101740, cambios de control | P2 |\n| [CloudTrail y auditoría](cloudtrail-y-auditoria.md) | CloudTrail/GuardDuty/Config apagados, auditoría de M365 desactivada | P1 |\n| [Exfiltración desde SharePoint](exfiltracion-sharepoint.md) | SharePoint/OneDrive: descarga masiva, borrado, uso compartido externo, política, etiquetas, postura | P1–P3 |\n| [Reglas estándar de Wazuh](reglas-estandar-wazuh.md) | Office 365 (MailItemsAccessed, envíos, descargas, admin), FIM, rootcheck, paquetes, SSH, SCA | P3–P4 |\n\nReglas comunes a todos:\n\n- **Evidencia primero:** antes de contener, exportar la alerta B89 (id, prioridad, razones) y los documentos\n  Wazuh (`_id`, índice). La auditoría B89 con cadena hash registra cada transición.\n- **Sin datos personales en canales abiertos:** en Teams/correo solo referencias; el detalle vive en B89 (N2).\n- **Nada se suprime sin registro:** un falso positivo se documenta en el incidente y se convierte en afinamiento\n  (lista CDB, ventana de mantenimiento en B89 o PR de la regla).\n- **Cierre:** clasificación VP/FP/benigno, causa raíz, acciones y lección para el backlog de detección.",
 "playbooks": "# 04 · Playbooks de B89 Respond\n\nParte de [17 · Ingeniería de detección](../17-ingenieria-de-deteccion.md). Archivos:\n[`b89-respond/playbooks/`](../../b89-respond/playbooks/) (exportables de Shuffle 2.3.0, el motor heredado que\ncorre hoy en AWS con la marca B89 Respond). Contrato verificado por `node --test b89-respond/playbooks/playbooks.test.mjs`.\n\n> **Requieren aprobación de B89.** Ninguno está importado en la instancia. Los de contención llevan la compuerta\n> `b89_contencion_habilitada = false`: encenderla es una decisión que se registra en\n> [10](../10-decisiones.md) (A13, N5) junto con los permisos de proveedor que exige. El destino de diseño sigue\n> siendo Step Functions ([13](../13-b89-respond.md)); estos flujos documentan la lógica para portarla.\n\n| Archivo | Catálogo | Riesgo | Aprobación | Efectos |\n| --- | --- | --- | --- | --- |\n| `b89-triage-enriquecimiento.json` | `b89.triage-enrichment` | Bajo | No (solo lectura) | Nota en el incidente B89 y aviso por correo |\n| `b89-contencion-identidad-aprobada.json` | `b89.identity-containment` | Alto | Líder SOC + step-up, SoD | Revocar sesiones y deshabilitar la cuenta de Entra |\n| `b89-contencion-endpoint-aprobada.json` | `b89.endpoint-containment` | Medio | Líder SOC, SoD | `firewall-drop` 600 s en el agente (Wazuh Active Response) |\n\n## Triage y enriquecimiento\n\nDisparo: webhook del adaptador `infra/wazuh/shuffle` (alertas nivel ≥ 12, payload v1 **sin** usuario, IP ni\n`full_log`). Pasos: `validar_y_deduplicar` (contrato v1, `executionKey = alert.id`, clasifica la fuente y elige\nel runbook) → `buscar_alerta_b89` (prioridad P1–P4 y razones, API B89 de solo lectura) y\n`contexto_agente_wazuh` (estado, SO y grupo) → `resumen_triage` (texto en español) → `nota_en_incidente_b89`\n(solo si la alerta ya está en un incidente) y `aviso_correo_b89`.\n\n**Correo:** usa el mismo contrato que el servicio de correo B89 (`wazuh/alert-mail`): Graph `sendMail` desde el\nbuzón del SOC, asunto `B89 SOC · <SEVERIDAD> · <título>`, contenido mínimo y enlace a la consola. Hoy la app no\ntiene `Mail.Send`; hasta concederlo (acotado al buzón con Application Access Policy), el paso falla cerrado y la\nnota en B89 se conserva. Que B89 Respond tenga esa credencial es una excepción a «Respond no guarda credenciales\nde proveedor» y debe aprobarse; la alternativa es encolar la intención de aviso en el outbox de B89 (contrato\npendiente en [14](../14-b89-respond-conexion-b89.md)).\n\n## Contención con aprobación\n\nDisparo: solicitud de B89 Core (`incidentRef`, `executionKey`, `requestedBy`, `targetRef`, `actionId`; nunca\ncontraseñas ni tokens). Flujo: `validar_solicitud` → `contexto_para_aprobar` → **User Input**\n`aprobacion_lider_soc` → `verificar_compuerta` (aprobador ≠ solicitante **y** `b89_contencion_habilitada = true`)\n→ acción → `resultado_en_incidente_b89` (ejecutada, rechazada o bloqueada; sin reintento ciego, ADR-028).\n\n| Playbook | Prerrequisitos antes de habilitar |\n| --- | --- |\n| Identidad (Entra) | Permisos Graph `User.RevokeSessions.All` y `User.EnableDisableAccount.All` en una app dedicada; step-up para aprobar (docs/07, gate 2); prueba sobre una cuenta sintética |\n| Endpoint (Wazuh AR) | Usuario de la API de Wazuh con solo `active-response:command` (docs/07, gate 3); `firewall-drop` solo existe en agentes Linux; allowlist de IPs administrativas (`B89_AR_WHITELIST`) |\n\nLas autenticaciones se referencian por nombre (`b89-api-lectura`, `b89-graph-contencion`,\n`wazuh-api-active-response`, …) y se crean en el almacén cifrado de B89 Respond; el JSON no contiene secretos\n(lo comprueba el test).",
 "runbooks": [
  {
   "id": "cloudtrail-y-auditoria",
   "title": "Manipulación de CloudTrail y de la auditoría",
   "path": "docs/detection-engineering/runbooks/cloudtrail-y-auditoria.md",
   "sections": [
    "Triage en 10 minutos",
    "Contención",
    "Investigación",
    "M365: auditoría desactivada (100527, 100528)",
    "Consultas"
   ],
   "ruleIds": [
    "100527",
    "100528",
    "101620",
    "101621",
    "101710",
    "101711",
    "101712"
   ],
   "useCases": [
    "B89-DET-AWS-001",
    "B89-DET-M365-003"
   ],
   "markdown": "# Runbook · Manipulación de CloudTrail y de la auditoría\n\nAlcance: `aws/cloudtrail-tampering` (101710–101712, base 101620/101621 del paquete AWS), servicios de detección\nAWS (101622–101625, 101644), pipeline de monitoreo B89 (101615) y `m365/audit-tampering` (100527, 100528).\n**Siempre P1**: borrar el rastro es la acción de un intruso o rompe la evidencia regulatoria (SBS 504-2021, N11).\n\n## Triage en 10 minutos\n\n1. **¿Quién?** `data.aws.principal` / `data.aws.principal_arn`, tipo (`Root`, `IAMUser`, `AssumedRole`) e IP.\n   Principal de CI/Terraform con cambio aprobado → documentar y cerrar como benigno.\n2. **¿Qué más hizo en la última hora?** 101710 (IAM antes), 101711 (root), 101712 (varios servicios) ya lo dicen;\n   ampliar a 24 h con `data.aws.principal:\"<p>\"`.\n3. **¿Sigue apagado?** Verificar en la consola: `GetTrailStatus` (IsLogging), GuardDuty, Config, Security Hub.\n\n## Contención\n\n1. **Restaurar el registro primero** (`StartLogging`, recrear el detector/recorder) — por un administrador con el ticket.\n2. Inhabilitar el principal: quitar sesiones/permisos del rol, desactivar access keys, y para root: cambiar\n   contraseña y revisar MFA.\n3. Si es la organización: SCP que impida `cloudtrail:StopLogging`/`DeleteTrail` salvo al rol de plataforma (BL-A).\n\n## Investigación\n\n- Hueco de evidencia: desde `StopLogging` hasta `StartLogging` no hay CloudTrail de ese trail; usar los eventos de\n  EventBridge ya entregados a B89, VPC Flow Logs y logs de servicios.\n- Revisar creaciones de usuarios/llaves/roles y snapshots compartidos (101645) en la ventana.\n\n## M365: auditoría desactivada (100527, 100528)\n\nReactivar `UnifiedAuditLogIngestionEnabled` / auditoría del buzón, identificar al administrador, revisar sus\ninicios de sesión y roles (runbook de [credenciales](credenciales.md)).\n\n## Consultas\n\n```text\nrule.id:(101620 or 101621 or 101710 or 101711 or 101712)\nrule.groups:b89_aws_defense_disabled\nrule.id:(100527 or 100528)\n```\n\n**Cierre:** registro restaurado y verificado, principal contenido, ventana sin evidencia documentada en el\nincidente (auditoría B89), y lección (SCP, alerta de salud del pipeline 101615)."
  },
  {
   "id": "credenciales",
   "title": "Ataques de credenciales",
   "path": "docs/detection-engineering/runbooks/credenciales.md",
   "sections": [
    "Triage en 10 minutos",
    "M365 / Entra: cadena de compromiso (101700–101703)",
    "BEC: reglas de bandeja y reenvío (100510–100514, 101702)",
    "Exfiltración (100515, 100529)",
    "Kerberos (101304–101307)",
    "Consola AWS tras fuerza bruta (101713)",
    "SSH tras fuerza bruta (101750)",
    "Consultas"
   ],
   "ruleIds": [
    "100502",
    "100503",
    "100504",
    "100505",
    "100506",
    "100510",
    "100511",
    "100512",
    "100513",
    "100514",
    "100515",
    "100529",
    "100530",
    "101304",
    "101305",
    "101306",
    "101307",
    "101700",
    "101701",
    "101702",
    "101703",
    "101713",
    "101750"
   ],
   "useCases": [
    "B89-DET-AD-002",
    "B89-DET-AWS-002",
    "B89-DET-LNX-001",
    "B89-DET-M365-002",
    "B89-DET-M365-005",
    "B89-DET-M365-001",
    "B89-DET-M365-004"
   ],
   "markdown": "# Runbook · Ataques de credenciales\n\nAlcance: `m365/credential-attacks` (100502–100506, 100530), `m365/compromise-chain` (101700–101703),\n`m365/bec-mailbox-persistence` (100510–100514), `m365/data-exfiltration`, `ad/kerberos-attacks` (101304–101307),\n`aws/console-bruteforce-success` (101713, base 101607/101608), `linux/ssh-bruteforce-success` (101750, base\n5710/5712/5763). Playbooks: `b89-triage-enriquecimiento` (automático) y `b89-contencion-identidad-aprobada` /\n`b89-contencion-endpoint-aprobada` (con aprobación).\n\n## Triage en 10 minutos\n\n1. ¿Hubo **éxito**? 100505, 101703, 101713, 101750 = sí → **P1**. Solo fallos (100503, 100504, 101608, 5712) → P2/P3.\n2. ¿La cuenta es privilegiada o break-glass? (razones `PRIVILEGED_IDENTITY` / `BREAK_GLASS_IDENTITY` en B89) → P1.\n3. ¿La IP de origen es de B89 (oficina, VPN, CI)? Si sí y la persona confirma por un canal fuera de banda, es\n   benigno: documentar y cerrar.\n4. ¿Hay acciones posteriores de la misma cuenta (cadena)? Abrir la caza **H01** del dashboard «B89 · Threat hunting».\n\n<a id=\"cadena-m365\"></a>\n## M365 / Entra: cadena de compromiso (101700–101703)\n\n- **Investigar:** en Discover, `data.office365.UserId:\"<cuenta>\"` 48 h: inicios (IP, país, cliente), cambios de\n  MFA (100526), reglas de bandeja (100510–100512), roles (100520/101704), consentimientos (100522).\n- **Contener (aprobación):** `m365.revoke-sessions` y, si hay persistencia, `m365.disable-user` desde B89. Mientras\n  el playbook no esté habilitado, lo ejecuta un administrador de Entra con el ticket del incidente.\n- **Recuperar:** restablecer contraseña, eliminar métodos MFA no reconocidos, borrar reglas de bandeja/reenvío,\n  revocar consentimientos y roles agregados, revisar correos enviados (fraude de pago).\n\n<a id=\"bec\"></a>\n## BEC: reglas de bandeja y reenvío (100510–100514, 101702)\n\n- Confirmar destino del reenvío (dominio externo = P1 si hay pagos involucrados).\n- Revisar mensajes movidos/borrados por la regla: suelen esconder respuestas de proveedores o bancos.\n- Avisar a Tesorería/Riesgos no financieros si el buzón gestiona pagos.\n\n<a id=\"exfiltracion\"></a>\n## Exfiltración (100515, 100529)\n\n- Enlace anónimo: ¿el archivo contiene datos personales o de clientes? Si sí, revocar el enlace y escalar a Legal.\n- eDiscovery: confirmar caso legal aprobado por Compliance; si no existe, P1.\n\n<a id=\"kerberos\"></a>\n## Kerberos (101304–101307)\n\n- Agrupar por cuenta de servicio y origen; RC4 aislado es higiene (P3), muchas cuentas desde un host = Kerberoasting (P1).\n- DCSync candidato: el principal debe ser un DC o una cuenta de sincronización documentada.\n\n<a id=\"aws\"></a>\n## Consola AWS tras fuerza bruta (101713)\n\n- Ver `data.aws.principal`, MFA y región; listar lo que hizo ese principal después (`data.aws.principal:\"<p>\"`).\n- Contener: deshabilitar el login profile / access keys del usuario IAM (consola AWS por un administrador con el\n  ticket; no hay acción automatizada para AWS) y rotar credenciales.\n\n<a id=\"ssh\"></a>\n## SSH tras fuerza bruta (101750)\n\n- `data.srcip` y `data.dstuser`: ¿cuenta con llave o contraseña? En los nodos B89 la autenticación por contraseña\n  debería estar deshabilitada: si entró con contraseña, es hallazgo de hardening además del incidente.\n- Revisar lo que hizo la sesión: sudo (5402), cambios FIM (101755–101760), usuarios nuevos (5902).\n- Contener (aprobación): `endpoint.block-ip` (firewall-drop 600 s) y, si hubo acceso real, aislar el host.\n\n## Consultas\n\n```text\nrule.groups:b89_attack_chain\nrule.id:(100502 or 100503 or 100504 or 100505) and data.office365.UserId:\"<cuenta>\"\nrule.groups:sshd and data.srcip:\"<ip>\"\nrule.groups:aws and data.aws.source_ip:\"<ip>\"\n```\n\n**Cierre:** clasificación, métodos MFA y sesiones revocadas, IPs bloqueadas (con vencimiento), lección para el\nbacklog (p. ej. Conditional Access, deshabilitar contraseña en SSH)."
  },
  {
   "id": "dlp-endpoint",
   "title": "DLP de endpoints (Ferrispector)",
   "path": "docs/detection-engineering/runbooks/dlp-endpoint.md",
   "sections": [
    "Instalar un equipo",
    "Triage de 10 minutos",
    "101110–101112 · Hallazgos",
    "101113–101116 · Salud del agente"
   ],
   "ruleIds": [
    "101110",
    "101111",
    "101112",
    "101113",
    "101114",
    "101115",
    "101116"
   ],
   "useCases": [],
   "markdown": "# Runbook · DLP de endpoints (Ferrispector)\n\nReglas 101110–101116 (`infra/wazuh/endpoint/rules/b89_endpoint_rules.xml`). Ferrispector detecta; no\nbloquea, no mueve y no borra archivos. Los eventos traen el equipo, la regla, la extensión, el tamaño y la\nhuella SHA-256 del archivo; nunca la ruta ni el contenido.\n\n## Instalar un equipo\n\n1. En **DLP de endpoints**, abre una ficha de Windows, macOS o Linux y descarga la arquitectura del equipo.\n   Los paquetes contienen el motor YARA-X v1.24.0, las reglas iniciales y sus avisos de licencia; cada\n   archivo de origen se comprueba con SHA-256 durante la compilación. La descarga requiere `dlp.configure`\n   y queda auditada como `dlp.installer.requested`.\n2. Extrae el ZIP en el equipo y abre **Conectar un equipo** en la consola. Selecciona el sistema, indica la\n   carpeta aprobada y los datos del servidor que pida el asistente. En Windows, el SHA-256 del ZIP se\n   completa al descargarlo y el instalador lo compara antes de instalar.\n3. Crea una clave de un solo uso, vence en 30 minutos. Pégala cuando el instalador la solicite; no la pongas\n   en el comando ni en el historial de la terminal. En Windows ejecuta PowerShell como administrador; en\n   macOS o Linux usa `sudo`.\n4. Espera a que la consola muestre el equipo conectado. La primera conexión recibe la política activa en\n   menos de un minuto. Si no aparece, comprueba red, permisos de la carpeta y la URL de la consola.\n\nLa API entrega paquetes solo a quien tenga `dlp.configure`; la ruta de descarga responde sin caché. Si la\nclave no se puede guardar, la consola muestra la referencia para Plataforma. Si falla el registro de\nauditoría después de crearla, la API anula la clave para que no quede un secreto activo sin seguimiento.\n\n## Triage de 10 minutos\n\n1. Abre la alerta y mira «Por qué saltó»: qué tipo de dato se encontró y en qué equipo.\n2. Abre **DLP de endpoints** y revisa si el equipo está «Protegido» y con la revisión vigente.\n3. Contacta a la persona que usa el equipo y pídele que ubique el archivo por su huella SHA-256 (la consola la muestra en el detalle técnico).\n4. Credencial real: rótala o revócala en el servicio de origen y revisa su uso reciente; luego borra el archivo.\n5. Dato personal o documento protegido: confirma si ese equipo y esa carpeta pueden guardarlo; si no, muévelo a la ubicación aprobada.\n6. Clasifica la alerta con la conclusión y una nota de lo que hiciste.\n\n## 101110–101112 · Hallazgos\n\n- 101110 (nivel 5): dato sensible de una regla avanzada (DNI, RUC, contraseñas en texto).\n- 101111 (nivel 8): credencial reconocible (clave privada, token de GitHub, Slack, Google, Azure, OpenAI, AWS, base de datos).\n- 101112 (nivel 10): copia exacta de un documento protegido por huella.\n\n## 101113–101116 · Salud del agente\n\n1. 101114 (sin política más de 5 minutos): revisa si el equipo fue revocado a propósito. Si no, comprueba la red del equipo y que la consola responda.\n2. 101116 (muchos archivos sin revisar): revisa permisos de las carpetas aprobadas y archivos bloqueados por otro programa."
  },
  {
   "id": "escalada-de-privilegios",
   "title": "Escalada de privilegios (Entra, AWS, AD y Linux)",
   "path": "docs/detection-engineering/runbooks/escalada-de-privilegios.md",
   "sections": [
    "Triage en 10 minutos",
    "Entra",
    "AWS",
    "Active Directory",
    "Linux (grupos privilegiados y persistencia por FIM)",
    "Consultas"
   ],
   "ruleIds": [
    "100520",
    "100521",
    "100522",
    "100523",
    "100524",
    "100525",
    "100526",
    "101300",
    "101301",
    "101302",
    "101303",
    "101704",
    "101710",
    "101711",
    "101712",
    "101752",
    "101755",
    "101756",
    "101757",
    "101758",
    "101759",
    "101760"
   ],
   "useCases": [
    "B89-DET-AD-001",
    "B89-DET-AWS-001",
    "B89-DET-ENTRA-002",
    "B89-DET-ENTRA-003",
    "B89-DET-ENTRA-001",
    "B89-DET-LNX-003",
    "B89-DET-LNX-002"
   ],
   "markdown": "# Runbook · Escalada de privilegios (Entra, AWS, AD y Linux)\n\nAlcance: `entra/privileged-role-assignment` (100520, 100521, 101704), `entra/app-consent-and-credentials`\n(100522, 100523), `entra/auth-methods-and-federation` (100524–100526), reglas IAM/Identity Center/Organizations\ndel paquete AWS (101630–101636), `aws/cloudtrail-tampering` (101710), `ad/privileged-groups-and-policy`\n(101300–101303), `linux/privileged-group-membership` (101752) y `linux/persistence-fim` (101755–101760).\n\n## Triage en 10 minutos\n\n1. **¿Hay un cambio aprobado?** Buscar el ticket de cambio o la ventana de mantenimiento cargada en B89. Sin\n   cambio aprobado → mínimo P2; tier 0 (Global/Privileged Role Admin, `AdministratorAccess`, Domain Admins, root) → P1.\n2. **¿Quién lo hizo y quién lo recibió?** Actor (`UserId`, `aws.principal`, `srcuser`) y objetivo (`ObjectId`,\n   rol, `dstuser`). Un actor que se otorga a sí mismo = P1.\n3. **¿Vino después de un acceso anómalo?** Si hay 101700/101710 ya es cadena (P1).\n\n<a id=\"entra\"></a>\n## Entra\n\n- Ver la asignación en Entra (Roles y administradores → auditoría) y en PIM si es elegible o activa.\n- Consentimientos y credenciales de apps (100522/100523): ¿la app es interna? ¿quién la publicó? Revisar\n  permisos `Mail.Read`, `Files.Read.All`, `offline_access`.\n- Federación (100524): **P1 siempre**; validar con el equipo de identidad en el mismo turno.\n- **Contener:** retirar el rol/consentimiento/credencial (administrador de Entra con el ticket); si el actor está\n  comprometido, playbook de identidad (aprobación).\n\n## AWS\n\n- `data.aws.event_name` y `data.aws.request_parameters`: política adjunta, usuario/rol creado, permission set.\n- Revisar si el mismo principal tocó CloudTrail, GuardDuty o Config (101710/101712) → ver [CloudTrail y auditoría](cloudtrail-y-auditoria.md).\n- **Contener:** quitar la política/rol, desactivar access keys nuevas, SCP de bloqueo si es la organización.\n\n<a id=\"active-directory\"></a>\n## Active Directory\n\n- 4728/4732/4756 sobre grupos integrados: confirmar con el owner del grupo; AdminSDHolder/GPO (101303) con ticket.\n- Borrado de Security (101302): preservar el log del DC y escalar a P1.\n\n<a id=\"linux\"></a>\n## Linux (grupos privilegiados y persistencia por FIM)\n\n- 101752: ¿quién (`srcuser`) agregó a quién (`dstuser`) a `sudo`/`docker`/`lxd`? `docker` y `lxd` equivalen a root.\n- 101755 llaves SSH, 101758 sudoers, 101759 PAM: **P1 fuera de cambio**; comparar con el `diff` de FIM\n  (sin diff en `shadow` ni llaves por privacidad: pedir el archivo al owner del host).\n- 101756/101757 unidad systemd o cron: revisar `ExecStart`/comando; correlacionar con `dpkg` (2902/2904) para\n  descartar instalación de paquetes.\n- **Contener:** retirar la llave/entrada, revertir sudoers/PAM desde configuración versionada, bloquear la IP de\n  origen de la sesión (playbook de endpoint, aprobación) y rotar credenciales del host.\n\n## Consultas\n\n```text\nrule.groups:(b89_privilege_escalation or b89_aws_iam or azure_ad)\nrule.id:(100520 or 100521 or 101704 or 101700)\nrule.id:(101755 or 101756 or 101757 or 101758 or 101759 or 101760)\nrule.id:(2960 or 2961 or 101752)\n```"
  },
  {
   "id": "exfiltracion-sharepoint",
   "title": "Exfiltración desde SharePoint y OneDrive",
   "path": "docs/detection-engineering/runbooks/exfiltracion-sharepoint.md",
   "sections": [
    "Triage en 10 minutos",
    "Investigación",
    "Contención (con aprobación del Líder SOC)",
    "Recuperación y cierre",
    "Consultas"
   ],
   "ruleIds": [
    "101900",
    "101901",
    "101902",
    "101903",
    "101904",
    "101905",
    "101906",
    "101907",
    "101908",
    "101909",
    "101910",
    "101911",
    "101912",
    "101913",
    "101914",
    "101915",
    "101916",
    "101917",
    "101918",
    "101919",
    "101920",
    "101925",
    "101926",
    "101927",
    "101928",
    "101929",
    "101930",
    "101935",
    "101936",
    "101937",
    "101938",
    "101939",
    "101940",
    "101941",
    "101945",
    "101946",
    "101947",
    "101948",
    "101949",
    "101950",
    "101951",
    "101960",
    "101961",
    "101962",
    "101963",
    "101964",
    "101965",
    "101966",
    "101967",
    "101968",
    "101969",
    "101970",
    "101971",
    "101972"
   ],
   "useCases": [
    "B89-DET-SP-001",
    "B89-DET-SP-003",
    "B89-DET-SP-005",
    "B89-DET-SP-002",
    "B89-DET-SP-006",
    "B89-DET-SP-004"
   ],
   "markdown": "# Runbook · Exfiltración desde SharePoint y OneDrive\n\nAlcance: `sharepoint/exfiltration` (101900–101911), `sharepoint/mass-deletion` (101915–101920),\n`sharepoint/external-sharing` (101925–101930), `sharepoint/sharing-policy-and-admins` (101935–101941),\n`sharepoint/labels-and-dlp` (101945–101951), `sharepoint/posture` (101960–101972) y la regla heredada 100515\n(enlace anónimo). Fuente y permisos: [23 · SharePoint y OneDrive](../../23-sharepoint-onedrive.md).\nPlaybook: contención manual en el centro de administración de SharePoint/Entra por un operador con el ticket,\naprobada por el Líder SOC (B89 no escribe en Microsoft 365).\n\n## Triage en 10 minutos\n\n1. **¿Quién y con qué identidad?** `data.office365.UserId`. Invitado (`#ext#`, 101905/101906), cuenta\n   deshabilitada (101907) o cuenta de servicio (lista `b89-m365-service-accounts`: si aparece ahí con nivel ≥ 8, la\n   lista no la cubre → revisar). Mirar en Entra los inicios de sesión de esa cuenta en las 24 h previas: un login\n   tras fuerza bruta (100505) o desde la IP de un spray (101703) convierte cualquier alerta de esta página en **P1**.\n2. **¿Desde dónde?** `data.office365.ClientIP`: en Spamhaus/Feodo (101908) o Tor (101909) → **P1** sin más\n   análisis. Red nueva para el usuario (101904, solo vía Purview) → confirmar con el usuario por un canal distinto\n   del correo.\n3. **¿Cuánto y cuándo?** 101902 (150 en 10 min) es P2; fuera de horario (101903, 40 en 30 min) es P1.\n   Distinguir **sincronización** (`FileSyncDownloadedFull`, cliente OneDrive, un dispositivo) de **descarga web**\n   (`FileDownloaded`, navegador, `UserAgent`): la primera suele ser un equipo nuevo; la segunda, extracción.\n4. **¿Sale de B89?** Enlace anónimo (100515/101926), correo personal (101927/101930), invitado (101928). Si el\n   mismo archivo perdió su etiqueta justo antes (101948) → **P1**, exfiltración preparada.\n5. **¿Destrucción?** 101917/101918/101920: borrado masivo o vaciado de la papelera de segunda etapa → P1 si hay\n   ransomware o salida del empleado; restaurar es urgente (la papelera de la colección conserva 93 días).\n6. **¿Cambió la superficie?** 101936/101937/101963 (Cualquier persona habilitado), 101938–101941 (administradores):\n   ¿hay ticket de TI? Sin ticket → tratar como compromiso de un administrador (runbook de\n   [escalada de privilegios](escalada-de-privilegios.md)).\n\n| Prioridad | Cuándo |\n| --- | --- |\n| P1 | IP maliciosa/Tor, fuera de horario, red nueva + volumen, etiqueta quitada y compartido, destrucción o papelera vaciada, tenant debilitado, administrador invitado |\n| P2 | Volumen en horario, invitado en volumen, cuenta deshabilitada, correo personal, enlaces anónimos en volumen, administrador agregado, DLP alta |\n| P3 | Enlace anónimo aislado, compartición con un socio, DLP media, sitio nuevo, permiso externo encontrado |\n| P4 | Marcas (nivel ≤ 3) y fotos de postura: solo búsqueda y contexto |\n\n## Investigación\n\n- **Alcance de lo descargado:** todos los `ObjectId`/`SourceFileName` del usuario en la ventana (consulta abajo);\n  sitios afectados (`SiteUrl`) y su clasificación; ¿hay archivos con etiqueta o DLP (101949–101951)?\n- **Dispositivo:** `UserAgent`, `Platform`, `DeviceDisplayName`, `IsManagedDevice` (si el registro los trae). Un\n  dispositivo no administrado + volumen sube la prioridad.\n- **Línea de tiempo:** inicio de sesión → acceso → descarga/compartición → borrado. Buscar reglas de bandeja o\n  reenvíos (100510–100512) del mismo usuario: el BEC suele exfiltrar por correo y SharePoint a la vez.\n- **Enlaces creados:** en el sitio, «Administrar acceso» del archivo; en postura, `sharepoint.finding.*`\n  (101966–101968) muestra enlaces anónimos y externos existentes aunque falte la auditoría.\n- **Empleado que se va:** cruzar con RR. HH.; la actividad de una cuenta ya deshabilitada (101907) puede ser\n  registrada antes del bloqueo (comparar `CreationTime` con la hora del bloqueo en Entra).\n\n## Contención (con aprobación del Líder SOC)\n\n- Revocar sesiones y restablecer credenciales en Entra; bloquear el inicio de sesión si hay compromiso.\n- Quitar los enlaces anónimos y los permisos externos del contenido afectado; si hace falta, bajar el uso\n  compartido del sitio a «Solo personas de la organización» mientras dura la investigación.\n- Quitar el administrador de colección agregado sin ticket y revisar los demás.\n- Destrucción: restaurar desde la papelera de la colección de sitios o con «Restaurar este OneDrive/biblioteca».\n- Revertir la configuración del tenant debilitada (`sharingCapability`) y registrar quién la cambió.\n\n## Recuperación y cierre\n\nVerificar que no quedan enlaces del atacante (siguiente pasada de postura, 101966–101968), que la etiqueta volvió\na los archivos afectados y que la cuenta de servicio legítima que causó un falso positivo quedó en la allowlist\npor PR (`detections/lists/b89-m365-service-accounts` o `b89-m365-sharing-approved`). Clasificar VP/FP/benigno,\ncausa raíz y lección para el backlog (umbral, lista o regla).\n\n## Consultas\n\n```text\nrule.groups:b89_sharepoint and rule.level >= 8\nrule.groups:b89_sharepoint and data.office365.UserId:\"<usuario>\"\nrule.id:(101900 or 101902 or 101903 or 101904) and data.office365.UserId:\"<usuario>\"\nrule.groups:b89_external_sharing or rule.id:(100515 or 101926)\nrule.id:(101945 or 101946 or 101948)\nrule.groups:b89_posture and data.sharepoint.finding.kind:anonymous_link\nrule.groups:b89_source_health and data.b89.capability.status:blocked\n```"
  },
  {
   "id": "malware-edr",
   "title": "Malware y EDR",
   "path": "docs/detection-engineering/runbooks/malware-edr.md",
   "sections": [
    "Triage en 10 minutos",
    "Protección deshabilitada + malware (101720–101723)",
    "Investigación",
    "Recuperación y cierre",
    "Consultas"
   ],
   "ruleIds": [
    "101100",
    "101401",
    "101402",
    "101403",
    "101404",
    "101405",
    "101406",
    "101407",
    "101408",
    "101409",
    "101410",
    "101411",
    "101720",
    "101721",
    "101722",
    "101723"
   ],
   "useCases": [
    "B89-DET-BD-001",
    "B89-DET-BD-002",
    "B89-DET-WIN-001"
   ],
   "markdown": "# Runbook · Malware y EDR\n\nAlcance: `bitdefender/malware-and-protection` (101401–101411), `bitdefender/protection-disabled-malware`\n(101720–101723), paquete de lanzamiento Sophos/Windows (101201, 101202, 101208–101211, 101219) y\n`windows/outlook-child-process` (101100). Playbook: `b89-contencion-endpoint-aprobada` (Linux) y aislamiento en la\nconsola del EDR (GravityZone) por un operador con el ticket.\n\n## Triage en 10 minutos\n\n1. **¿Activo o remediado?** `infected:true` (101402) = malware activo sin remediar → P1. Cuarentena (101410) = el\n   EDR actuó → P2, salvo repetición (101411, 3 en 1 h) → P1.\n2. **¿Con la protección apagada?** 101720–101723 → **P1**: el atacante o un técnico apagó la defensa con malware\n   presente. Llamar al usuario/owner del endpoint.\n3. **¿Endpoint crítico?** Razón `CRITICAL_ASSET` en B89 (servidores de pagos, estaciones de Tesorería) → P1.\n\n<a id=\"proteccion-deshabilitada\"></a>\n## Protección deshabilitada + malware (101720–101723)\n\n- En GravityZone: política aplicada, módulos deshabilitados, quién cambió la política (auditoría de GravityZone).\n- ¿Hubo cambio aprobado (instalación de software)? Si no, tratar como evasión (T1562.001).\n- **Contener:** aislar el endpoint en GravityZone (aprobación del Líder SOC; el collector B89 es solo lectura) y\n  volver a aplicar la política.\n\n## Investigación\n\n- Amenaza, ruta y hash (cuarentena); primer endpoint con esa amenaza (`bitdefender.quarantine.threat_name`).\n- Mismo usuario en M365/Entra: inicios y reenvíos en las 24 h previas (phishing como vector).\n- Si el endpoint tiene agente Wazuh: FIM y procesos (Sysmon cuando exista, BL-E01).\n\n## Recuperación y cierre\n\nEscaneo completo, reimagen si hubo persistencia, rotación de credenciales usadas en el equipo, verificación de que\nla política volvió (`policy_applied:true`) y lección (p. ej. bloquear la desinstalación del agente).\n\n## Consultas\n\n```text\nrule.groups:b89_malware\nrule.id:(101720 or 101721 or 101722 or 101723)\nrule.groups:bitdefender and data.bitdefender.endpoint.name:\"<host>\"\n```"
  },
  {
   "id": "oleada-waf",
   "title": "Oleada de ataques en el WAF (Cloudflare)",
   "path": "docs/detection-engineering/runbooks/oleada-waf.md",
   "sections": [
    "Triage en 10 minutos",
    "Contención (cambio aprobado)",
    "Investigación y cierre",
    "Consultas"
   ],
   "ruleIds": [
    "101501",
    "101502",
    "101503",
    "101504",
    "101505",
    "101506",
    "101507",
    "101508",
    "101509",
    "101510",
    "101511",
    "101512",
    "101513",
    "101514",
    "101740"
   ],
   "useCases": [
    "B89-DET-CF-001",
    "B89-DET-CF-002"
   ],
   "markdown": "# Runbook · Oleada de ataques en el WAF (Cloudflare)\n\nAlcance: `cloudflare/audit-and-waf` (101501–101513) y `cloudflare/waf-attack-surge` (101740).\n\n## Triage en 10 minutos\n\n1. **¿Una IP o muchas?** 101513 = una IP insistente (20 en 5 min); 101740 = oleada distribuida (50 IPs distintas en\n   10 min sobre un host) → P2.\n2. **¿Qué buscan?** Rutas (`data.cloudflare.firewall.path`) y regla del WAF (`rule_description`): SQLi, RCE,\n   `/login` (credenciales), rutas de un CVE reciente.\n3. **¿Pasa algo?** Eventos `log` (101511) con la misma firma = la regla está solo en modo registro: el ataque llega\n   a la aplicación → P1 si coincide con una vulnerabilidad expuesta (caza **H07**).\n4. **¿Alguien tocó los controles?** 101504/101505 (WAF/ruleset deshabilitado) en la misma ventana → P1.\n\n## Contención (cambio aprobado)\n\n- Rate limiting o regla de bloqueo por ASN/país/ruta; Under Attack mode si afecta disponibilidad.\n- Pasar a `block` la regla administrada que está en `log`.\n- Nunca bloquear rangos de proveedores de B89 sin confirmar (pagos, monitoreo).\n\n## Investigación y cierre\n\nTop IPs, ASN y países (H08), user agents, horarios; correlacionar con errores 5xx de la aplicación y con logins\nexitosos en la misma ventana. Cerrar con la medida aplicada y su vencimiento.\n\n## Consultas\n\n```text\nrule.id:(101513 or 101740)\nrule.groups:b89_waf and data.cloudflare.firewall.host:\"<host>\"\nrule.id:101511\n```"
  },
  {
   "id": "reglas-estandar-wazuh",
   "title": "Reglas estándar de Wazuh con volumen en B89",
   "path": "docs/detection-engineering/runbooks/reglas-estandar-wazuh.md",
   "sections": [
    "Triage en 10 minutos",
    "Buzones de Exchange Online",
    "SharePoint y OneDrive",
    "Administración de Entra ID, Exchange y cumplimiento",
    "Integridad de archivos, paquetes y rootcheck",
    "SSH, SCA y agente",
    "Cierre y evidencia",
    "Consultas"
   ],
   "ruleIds": [
    "19003",
    "19007",
    "220",
    "2902",
    "2904",
    "510",
    "521",
    "550",
    "553",
    "554",
    "5710",
    "5762",
    "91533",
    "91548",
    "91578",
    "91702",
    "91703",
    "91707",
    "91708",
    "91712",
    "91713"
   ],
   "useCases": [
    "B89-STOCK-M365-001",
    "B89-STOCK-M365-002",
    "B89-STOCK-M365-003",
    "B89-STOCK-HOST-001",
    "B89-STOCK-HOST-002",
    "B89-STOCK-HOST-003",
    "B89-STOCK-HOST-004",
    "B89-STOCK-HOST-005",
    "B89-STOCK-WAZUH-001"
   ],
   "markdown": "# Runbook · Reglas estándar de Wazuh con volumen en B89\n\nAlcance: reglas estándar de Wazuh 4.14.8 con volumen en B89: Office 365 (91578, 91707, 91708, 91702, 91703, 91712, 91713, 91548, 91533), integridad de archivos (550, 553, 554), rootcheck (510, 521), paquetes (2902, 2904), SSH (5710, 5762), SCA (19003, 19007) y agente (220).\n\nMetadatos y guía por regla: [`detections/wazuh-stock/stock-rules.yaml`](../../../detections/wazuh-stock/stock-rules.yaml).\n\nCasi todo este volumen es **actividad normal registrada**, no ataque. El trabajo es separar lo\nhabitual de lo que no encaja, con la entidad (usuario, IP, host) como eje.\n\n## Triage en 10 minutos\n\n1. **¿Quién y dónde?** Usuario, IP y host de la alerta. ¿Es el dueño del recurso? ¿Es su IP o su país habitual?\n2. **¿Hay contexto que la explique?** Despliegue, actualización de paquetes, alta de personal o ventana de cambios en la misma hora.\n3. **¿Se acompaña de otra señal?** Alertas B89 de la misma entidad (fuerza bruta, regla de bandeja, descarga masiva, cambio de rol) en ±24 h.\n4. **Volumen:** comparar con el historial de 30 días de la misma regla y entidad. Lo habitual y sin otra señal se cierra como benigno con la razón.\n\n## Buzones de Exchange Online\n\nCasos de uso `wazuh-stock/m365-mailbox-access` (91578 MailItemsAccessed, 91707 envío, 91708 envío con otros permisos).\n\n- MailItemsAccessed es auditoría de lectura del buzón: la sincronización de Outlook del propio dueño la genera sin parar. **Benigno** si el actor es el dueño (o un delegado conocido), desde su IP habitual y con un cliente conocido.\n- **Escalar** si accede alguien que no es el dueño ni delegado, una aplicación desconocida, desde IP o país inusual, con lectura masiva (Bind de muchos elementos) o `IsThrottled=true`; o si 91708 aparece sin delegación documentada o tras una regla de bandeja o reenvío (100510).\n- Siguiente paso de investigación: [credenciales](credenciales.md) (cadena M365 y BEC).\n\n## SharePoint y OneDrive\n\nCasos de uso `wazuh-stock/m365-sharepoint-files` (91702 descarga, 91703 nivel de permiso).\n\n- Descargas individuales son trabajo normal; el volumen lo vigilan las reglas B89 de [exfiltración](exfiltracion-sharepoint.md).\n- **Escalar** si descarga un invitado o anónimo, desde IP inusual, o si se añade un nivel de permiso de control total por alguien que no administra el sitio.\n\n## Administración de Entra ID, Exchange y cumplimiento\n\nCasos de uso `wazuh-stock/m365-directory-admin` (91712, 91713, 91548, 91533).\n\n- **Escalar** si el grupo es privilegiado o da acceso a datos sensibles, si el actor no es administrador o actúa fuera de horario, o si el cmdlet cambia protección, retención o auditoría (Set-/Remove-/New-).\n- Ver [escalada de privilegios](escalada-de-privilegios.md).\n\n## Integridad de archivos, paquetes y rootcheck\n\nCasos de uso `wazuh-stock/host-integrity-fim` (550, 553, 554), `wazuh-stock/host-packages` (2902, 2904) y `wazuh-stock/host-rootcheck` (510, 521).\n\n- Un cambio FIM en binarios o en /etc a la misma hora que 2902/2904 es una **actualización**: benigno.\n- 521 sobre /var/lib/docker o /var/lib/containerd es el **falso positivo conocido** de las capas overlay (la política linux-servers lo ignora; si aparece, el agente no tiene la política al día).\n- **Escalar** cambios en SSH, sudoers, cuentas, cron, systemd o authorized_keys sin despliegue; binarios cambiados sin paquete; borrado de logs; herramientas ofensivas instaladas; 521 fuera de Docker o repetido.\n\n## SSH, SCA y agente\n\nCasos de uso `wazuh-stock/host-ssh` (5710, 5762), `wazuh-stock/host-hardening-sca` (19003, 19007) y `wazuh-stock/wazuh-agent-config` (220).\n\n- 5710 desde Internet es ruido de escáneres; **escalar** si después hay un login válido desde esa IP o si apuntan a usuarios reales.\n- SCA es postura, no incidente: P4 al backlog de hardening, salvo regresión súbita de controles críticos.\n- 220: la política de grupo publicada tiene algo que el agente no acepta; revisar `verify-agent-conf` y la visibilidad perdida del host.\n\n## Cierre y evidencia\n\n- Benigno: anotar la razón concreta (dueño del buzón desde IP habitual, actualización de paquetes a la misma hora…).\n- Si una misma causa benigna se repite, proponer afinamiento (lista CDB, exclusión de ruta o ajuste de nivel) en vez de cerrar a mano cada vez.\n- Verdadero positivo: abrir incidente y seguir el runbook específico enlazado arriba.\n\n## Consultas\n\n- MailItemsAccessed de un usuario: `rule.id:91578 and data.office365.UserId:\"usuario@b89.io\"`\n- Accesos a buzón por alguien distinto del dueño: `rule.id:91578 and not data.office365.MailboxOwnerUPN:data.office365.UserId` (revisar en Discover, el campo cambia según la operación)\n- FIM con actualización en la misma hora: `rule.id:(550 or 553 or 554 or 2902 or 2904) and agent.name:\"host\"`"
  },
  {
   "id": "vulnerabilidad-expuesta",
   "title": "Vulnerabilidad expuesta",
   "path": "docs/detection-engineering/runbooks/vulnerabilidad-expuesta.md",
   "sections": [
    "Triage en 10 minutos",
    "Contención",
    "Remediación y SLA objetivo de parcheo [propuesto, N8]",
    "Consultas"
   ],
   "ruleIds": [
    "101451",
    "101452",
    "101453",
    "101454",
    "101455",
    "101456",
    "101457",
    "101458",
    "101730",
    "101731"
   ],
   "useCases": [
    "B89-DET-SNYK-002",
    "B89-DET-SNYK-001"
   ],
   "markdown": "# Runbook · Vulnerabilidad expuesta\n\nAlcance: `snyk/vulnerabilities` (101451–101458), `snyk/exposed-critical-exploit` (101730–101731) y Wazuh\nVulnerability Detection (`wazuh-states-vulnerabilities-*`, dashboard «B89 · Gestión de vulnerabilidades»).\n\n## Triage en 10 minutos\n\n1. **¿Expuesta a Internet?** 101730/101731 (proyecto en `b89-internet-facing-projects`) → P1 crítica, P2 alta.\n   Si no está en la lista, confirmar con el equipo dueño si el servicio se publica por Cloudflare (y corregir la lista).\n2. **¿Explotable?** `exploit_maturity: Mature` o CVE en CISA KEV → sube un nivel de prioridad.\n3. **¿Alcanzable?** Snyk reachability / ruta de código; dependencia de desarrollo no desplegada → P3.\n4. **¿Hay ataque en curso?** Caza **H07**: WAF (101513/101740) sobre el host del proyecto en las últimas 24 h.\n\n## Contención\n\n- Regla temporal en el WAF de Cloudflare (virtual patching) sobre la ruta afectada, con cambio aprobado.\n- Si hay indicios de explotación: tratar como incidente de acceso inicial (T1190) y revisar logs de la app.\n\n## Remediación y SLA objetivo de parcheo [propuesto, N8]\n\n| Caso | Objetivo |\n| --- | --- |\n| Crítica expuesta con exploit maduro | 72 h (o mitigación WAF en 24 h) |\n| Crítica no expuesta / alta expuesta | 15 días |\n| Alta no expuesta | 30 días |\n| Media/baja | Ciclo normal de dependencias |\n\nInfraestructura (Wazuh VD): priorizar por `vulnerability.score.base`, número de agentes y paquetes del kernel o\nservicios expuestos (sshd, nginx, docker). Panel «paquetes a parchar primero».\n\n## Consultas\n\n```text\nrule.groups:b89_exposure\nrule.groups:snyk and data.snyk.issue.exploit_maturity:Mature\nvulnerability.severity:(Critical or High)          (índice wazuh-states-vulnerabilities-*)\n```"
  }
 ],
 "useCases": [
  {
   "id": "B89-STOCK-M365-001",
   "title": "Acceso a buzones de Exchange Online (MailItemsAccessed, envíos y envío con otros permisos)",
   "source": "wazuh-stock",
   "useCase": "m365-mailbox-access",
   "status": "stable",
   "ruleIds": [
    "91578",
    "91707",
    "91708"
   ],
   "mitre": [
    "T1114.002",
    "T1114.003"
   ],
   "priorityHint": "P4",
   "falsePositives": [
    "El propio dueño sincronizando su buzón (Outlook escritorio, móvil o web): MailItemsAccessed de tipo Sync o Bind continuo, mismo usuario que el buzón y su IP habitual. Es el 99 % del volumen.",
    "Buzones compartidos o delegados (asistentes, buzón de soporte): otro usuario con permiso FullAccess leyendo de forma habitual.",
    "Aplicaciones de respaldo, archivado o eDiscovery con permiso de aplicación: AppId conocido y acceso masivo programado.",
    "Envíos (91707) en el trabajo normal; envío con otros permisos (91708) de delegados configurados."
   ],
   "dataSources": [
    "Office 365 Management Activity API: Audit.Exchange (MailItemsAccessed, Send, SendAs, SendOnBehalf)"
   ],
   "escalateWhen": [
    "Quien accede NO es el dueño del buzón ni un delegado conocido, o es una aplicación (ClientAppId) desconocida.",
    "IP o país inusual para el usuario, o la misma IP aparece en alertas de autenticación fallida o de spray.",
    "Bind sobre muchos elementos en minutos (lectura masiva), o IsThrottled=true (más de 1000 eventos en 24 h: Microsoft deja de registrar el detalle).",
    "Envío con otros permisos (91708) sin delegación documentada, o justo después de una regla de bandeja o reenvío (100510)."
   ]
  },
  {
   "id": "B89-STOCK-M365-002",
   "title": "Archivos y permisos de SharePoint/OneDrive (descarga y nivel de permiso)",
   "source": "wazuh-stock",
   "useCase": "m365-sharepoint-files",
   "status": "stable",
   "ruleIds": [
    "91702",
    "91703"
   ],
   "mitre": [
    "T1530",
    "T1098"
   ],
   "priorityHint": "P4",
   "falsePositives": [
    "Descargas del trabajo diario y del cliente de sincronización de OneDrive.",
    "Niveles de permiso creados por el propietario del sitio o por TI al montar un sitio nuevo."
   ],
   "dataSources": [
    "Office 365 Management Activity API: Audit.SharePoint"
   ],
   "escalateWhen": [
    "Volumen anómalo de descargas de una persona (lo cubren las reglas B89 101902/101913 de exfiltración).",
    "Descarga por un usuario invitado o anónimo, o desde IP/país inusual.",
    "Nivel de permiso con control total añadido por alguien que no administra el sitio."
   ]
  },
  {
   "id": "B89-STOCK-M365-003",
   "title": "Cambios administrativos en Entra ID, Exchange y el centro de cumplimiento",
   "source": "wazuh-stock",
   "useCase": "m365-directory-admin",
   "status": "stable",
   "ruleIds": [
    "91712",
    "91713",
    "91548",
    "91533"
   ],
   "mitre": [
    "T1098",
    "T1098.007"
   ],
   "priorityHint": "P3",
   "falsePositives": [
    "Altas de grupos y miembros hechas por TI o por el flujo de alta de personal.",
    "Cmdlets de lectura (Get-*) del centro de cumplimiento y del registro de administración de Exchange."
   ],
   "dataSources": [
    "Office 365 Management Activity API: Audit.AzureActiveDirectory, Audit.Exchange (admin), SecurityComplianceCenterEOPCmdlet"
   ],
   "escalateWhen": [
    "El grupo es privilegiado (administradores, Accesos_SOC, grupos con roles de Entra asignables) o da acceso a datos sensibles.",
    "Quien hace el cambio no figura como administrador, o actúa fuera de horario o desde IP inusual.",
    "Cmdlets que cambian protección o retención (Set-/Remove-/New- de políticas de antispam, antimalware, retención o auditoría)."
   ]
  },
  {
   "id": "B89-STOCK-HOST-001",
   "title": "Integridad de archivos en servidores (FIM de Wazuh)",
   "source": "wazuh-stock",
   "useCase": "host-integrity-fim",
   "status": "stable",
   "ruleIds": [
    "550",
    "553",
    "554"
   ],
   "mitre": [
    "T1565.001",
    "T1070.004",
    "T1485"
   ],
   "priorityHint": "P4",
   "falsePositives": [
    "Actualizaciones de paquetes: cambios en /usr/bin, /usr/sbin, /etc o /boot en la misma ventana que 2902/2904 (dpkg) o unattended-upgrades.",
    "Despliegues de B89 (releases en /opt/b89) y rotación de configuración por el propio orquestador.",
    "Archivos temporales o de estado que el ruido conocido aún no ignora."
   ],
   "dataSources": [
    "Wazuh syscheck (FIM programado cada 12 h y en tiempo real en rutas de persistencia)"
   ],
   "escalateWhen": [
    "Cambio en /etc/ssh, sudoers, /etc/passwd|shadow, cron, systemd o authorized_keys sin despliegue ni actualización en la ventana.",
    "Binario del sistema modificado sin paquete instalado o actualizado a la misma hora.",
    "Borrado (553) de logs, de reglas de auditoría o de archivos de seguridad."
   ]
  },
  {
   "id": "B89-STOCK-HOST-002",
   "title": "Instalación y configuración de paquetes Debian/Ubuntu",
   "source": "wazuh-stock",
   "useCase": "host-packages",
   "status": "stable",
   "ruleIds": [
    "2902",
    "2904"
   ],
   "mitre": [],
   "priorityHint": "P4",
   "falsePositives": [
    "unattended-upgrades y parches programados: muchos paquetes juntos, nombres del sistema base.",
    "«half configured» (2904) transitorio durante una actualización normal."
   ],
   "dataSources": [
    "syslog /var/log/dpkg.log (agente Wazuh)"
   ],
   "escalateWhen": [
    "Paquete de herramientas ofensivas o de red (nmap, netcat, socat, masscan, hydra, proxychains) o de acceso remoto.",
    "Instalación manual fuera de una ventana de cambios, por una sesión SSH interactiva no esperada.",
    "2904 repetido para el mismo paquete: actualización rota que deja el host sin parches."
   ]
  },
  {
   "id": "B89-STOCK-HOST-003",
   "title": "Rootcheck (anomalías del host y posible rootkit de kernel)",
   "source": "wazuh-stock",
   "useCase": "host-rootcheck",
   "status": "stable",
   "ruleIds": [
    "510",
    "521"
   ],
   "mitre": [
    "T1014"
   ],
   "priorityHint": "P3",
   "falsePositives": [
    "Capas overlay de Docker/containerd (/var/lib/docker, /var/lib/containerd): cambian mientras check_sys las recorre y disparan 521. La política linux-servers ya las ignora; si aparecen, el agente no tiene la política al día.",
    "Procesos o puertos efímeros de contenedores que existen en un chequeo y no en el siguiente."
   ],
   "dataSources": [
    "Wazuh rootcheck (cada 12 h)"
   ],
   "escalateWhen": [
    "521 en una ruta fuera de Docker/containerd, o repetido en el mismo archivo en pasadas distintas.",
    "Proceso oculto o puerto oculto confirmado con ps/ss en el host.",
    "Coincide con cambios FIM en binarios del sistema o módulos del kernel."
   ]
  },
  {
   "id": "B89-STOCK-HOST-004",
   "title": "SSH expuesto (usuarios inexistentes y conexiones reiniciadas)",
   "source": "wazuh-stock",
   "useCase": "host-ssh",
   "status": "stable",
   "ruleIds": [
    "5710",
    "5762"
   ],
   "mitre": [
    "T1110.001",
    "T1021.004"
   ],
   "priorityHint": "P4",
   "falsePositives": [
    "Escáneres de Internet contra un SSH expuesto: usuarios genéricos (admin, test, oracle) desde IPs de nube o de listas de reputación.",
    "Conexiones reiniciadas (5762) por clientes que cortan el handshake o por balanceadores."
   ],
   "dataSources": [
    "journald/sshd (agente Wazuh)"
   ],
   "escalateWhen": [
    "La misma IP o rango consigue un login válido después (reglas B89 de fuerza bruta con éxito).",
    "Intentos contra usuarios reales del host o desde IPs internas.",
    "SSH no debería estar expuesto a Internet (allowed_admin_cidrs): revisar el security group."
   ]
  },
  {
   "id": "B89-STOCK-HOST-005",
   "title": "Configuración segura (SCA, benchmarks CIS)",
   "source": "wazuh-stock",
   "useCase": "host-hardening-sca",
   "status": "stable",
   "ruleIds": [
    "19003",
    "19007"
   ],
   "mitre": [],
   "priorityHint": "P4",
   "falsePositives": [
    "Controles CIS que B89 acepta por diseño (por ejemplo particiones separadas en instancias de nube): no son incidentes."
   ],
   "dataSources": [
    "Wazuh SCA (cada 12 h)"
   ],
   "escalateWhen": [
    "Un control que antes pasaba ahora falla (regresión de hardening) en SSH, auditd, permisos de archivos sensibles o cuentas.",
    "Puntaje que cae de golpe tras un cambio: posible manipulación o despliegue defectuoso."
   ]
  },
  {
   "id": "B89-STOCK-WAZUH-001",
   "title": "Agente Wazuh no aplica la configuración remota",
   "source": "wazuh-stock",
   "useCase": "wazuh-agent-config",
   "status": "stable",
   "ruleIds": [
    "220"
   ],
   "mitre": [],
   "priorityHint": "P3",
   "falsePositives": [
    "Política de grupo recién publicada con un bloque que el agente no admite (por ejemplo comandos remotos sin logcollector.remote_commands=1): el agente sigue con la configuración anterior."
   ],
   "dataSources": [
    "Wazuh agentd (configuración centralizada agent.conf)"
   ],
   "escalateWhen": [
    "El agente queda sin FIM, rootcheck o logs tras el fallo: se pierde visibilidad del host.",
    "Nadie publicó un cambio de política: alguien modificó agent.conf en el manager fuera del repositorio."
   ]
  },
  {
   "id": "B89-DET-AD-002",
   "title": "Kerberoasting, AS-REP roasting, DCSync y spray Kerberos",
   "source": "ad",
   "useCase": "kerberos-attacks",
   "status": "experimental",
   "ruleIds": [
    "101304",
    "101305",
    "101306",
    "101307"
   ],
   "mitre": [
    "T1558.003",
    "T1558.004",
    "T1003.006",
    "T1110.003"
   ],
   "priorityHint": "P3 aislado; P1 si se correlaciona",
   "falsePositives": [
    "Aplicaciones heredadas que exigen RC4.",
    "Replicación legítima entre DC (DCSync candidato)."
   ],
   "dataSources": [
    "Windows Security de DC (4769, 4768, 4662, 4771)"
   ]
  },
  {
   "id": "B89-DET-AD-001",
   "title": "Grupos privilegiados, política de auditoría, GPO y borrado de Security",
   "source": "ad",
   "useCase": "privileged-groups-and-policy",
   "status": "experimental",
   "ruleIds": [
    "101300",
    "101301",
    "101302",
    "101303"
   ],
   "mitre": [
    "T1098.007",
    "T1562.002",
    "T1070.001",
    "T1484.001"
   ],
   "priorityHint": "P1 borrado de Security y grupos tier 0",
   "falsePositives": [
    "Cambios de GPO del equipo de plataforma con ticket."
   ],
   "dataSources": [
    "Windows Security de controladores de dominio (4728/4732/4756, 4719, 1102, 5136)"
   ]
  },
  {
   "id": "B89-DET-AWS-001",
   "title": "Manipulación de CloudTrail con contexto (IAM previo, root, cegamiento múltiple)",
   "source": "aws",
   "useCase": "cloudtrail-tampering",
   "status": "testing",
   "ruleIds": [
    "101710",
    "101711",
    "101712"
   ],
   "mitre": [
    "T1562.008",
    "T1098.003",
    "T1078.004",
    "T1562.001"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Reconfiguración planificada del trail por Terraform (principal de CI con cambio aprobado).",
    "Desmontaje de un entorno de pruebas (cuenta sandbox)."
   ],
   "dataSources": [
    "CloudTrail management events vía EventBridge → SNS → receptor B89 (wazuh/aws-events)"
   ]
  },
  {
   "id": "B89-DET-AWS-002",
   "title": "Acceso a la consola AWS tras fuerza bruta",
   "source": "aws",
   "useCase": "console-bruteforce-success",
   "status": "testing",
   "ruleIds": [
    "101713"
   ],
   "mitre": [
    "T1110.001",
    "T1078.004"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Persona que se equivocó cinco veces y luego acertó (confirmar fuera de banda)."
   ],
   "dataSources": [
    "AWS Console Sign In vía EventBridge"
   ]
  },
  {
   "id": "B89-TUNE-AWS-001",
   "title": "Cambios del propio SOC en el pipeline de monitoreo AWS",
   "source": "aws",
   "useCase": "trusted-principals",
   "status": "testing",
   "ruleIds": [
    "101714",
    "101715",
    "101716"
   ],
   "mitre": [
    "T1562.008"
   ],
   "priorityHint": "P4 / P2",
   "falsePositives": [
    "Credenciales del SOC robadas: por eso lo destructivo no baja de 9 y 101710–101712 siguen evaluando la cadena."
   ],
   "dataSources": [
    "CloudTrail vía EventBridge → SNS → receptor B89 (trail de la cuenta, 598294a)"
   ]
  },
  {
   "id": "B89-DET-BD-001",
   "title": "Malware, cuarentena y protección degradada en GravityZone",
   "source": "bitdefender",
   "useCase": "malware-and-protection",
   "status": "production",
   "ruleIds": [
    "101401",
    "101402",
    "101403",
    "101404",
    "101405",
    "101406",
    "101407",
    "101408",
    "101409",
    "101410",
    "101411"
   ],
   "mitre": [
    "T1204",
    "T1562.001"
   ],
   "priorityHint": "P1 infectado; P2 detección y protección deshabilitada",
   "falsePositives": [
    "Archivos EICAR de pruebas.",
    "Desinstalación planificada del agente (aparece como antimalware deshabilitado)."
   ],
   "dataSources": [
    "Bitdefender GravityZone API (collector b89-collector-bitdefender, cada 10 min)"
   ]
  },
  {
   "id": "B89-DET-BD-002",
   "title": "Malware con la protección deshabilitada (EDR + evasión)",
   "source": "bitdefender",
   "useCase": "protection-disabled-malware",
   "status": "testing",
   "ruleIds": [
    "101720",
    "101721",
    "101722",
    "101723"
   ],
   "mitre": [
    "T1204",
    "T1562.001"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Técnico que apaga el antimalware para instalar software aprobado y coincide con una detección PUA."
   ],
   "dataSources": [
    "Bitdefender GravityZone API (estado del endpoint con cambio)"
   ]
  },
  {
   "id": "B89-DET-CF-001",
   "title": "Auditoría de cuenta y WAF de Cloudflare",
   "source": "cloudflare",
   "useCase": "audit-and-waf",
   "status": "production",
   "ruleIds": [
    "101501",
    "101502",
    "101503",
    "101504",
    "101505",
    "101506",
    "101507",
    "101510",
    "101511",
    "101512",
    "101513",
    "101514"
   ],
   "mitre": [
    "T1584.002",
    "T1562",
    "T1562.007",
    "T1098",
    "T1485",
    "T1190",
    "T1595"
   ],
   "priorityHint": "P2 controles; P1 zona borrada",
   "falsePositives": [
    "Cambios de DNS planificados por despliegues.",
    "Escáneres autorizados (pentest)."
   ],
   "dataSources": [
    "Cloudflare audit logs y firewall events por zona (collector b89-collector-cloudflare, cada 5 min)"
   ]
  },
  {
   "id": "B89-TUNE-CF-001",
   "title": "Escáneres autorizados, automatización DNS y corroboración por zona crítica",
   "source": "cloudflare",
   "useCase": "noise-tuning",
   "status": "testing",
   "ruleIds": [
    "101741",
    "101742",
    "101743",
    "101744",
    "101745"
   ],
   "mitre": [
    "T1190",
    "T1595"
   ],
   "priorityHint": "P1/P2 solo en zona crítica",
   "falsePositives": [
    "Zona crítica no listada: el ataque quedaría en 7 (cola, sin correo). Revisar la lista con cada alta de zona."
   ],
   "dataSources": [
    "Cloudflare firewall events y audit logs"
   ]
  },
  {
   "id": "B89-DET-CF-004",
   "title": "API de pagos · peticiones desde IPs fuera de la lista blanca de clientes y proveedores",
   "source": "cloudflare",
   "useCase": "payments-api-allowlist",
   "status": "experimental",
   "ruleIds": [
    "101546",
    "101547",
    "101548",
    "101549"
   ],
   "mitre": [
    "T1078"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Un cliente cambió de IP o agregó un servidor y no lo avisó (agrega la IP en Cloudflare → Lista blanca).",
    "IPs de monitoreo o pruebas de B89 que no están cargadas como «Infraestructura B89».",
    "Un cliente «No requiere» que sí llama a la API sin identificador configurado."
   ],
   "dataSources": [
    "Cloudflare Logpush (http_requests) enriquecido por el colector con la lista blanca de la consola"
   ]
  },
  {
   "id": "B89-DET-CF-002",
   "title": "Oleada distribuida contra un host del WAF",
   "source": "cloudflare",
   "useCase": "waf-attack-surge",
   "status": "testing",
   "ruleIds": [
    "101740"
   ],
   "mitre": [
    "T1595.002",
    "T1190"
   ],
   "priorityHint": "P2",
   "falsePositives": [
    "Picos de tráfico legítimo que activan desafíos (campañas de marketing, bots verificados mal clasificados)."
   ],
   "dataSources": [
    "Cloudflare firewall events"
   ]
  },
  {
   "id": "B89-DET-CF-003",
   "title": "Ataques web (OWASP Top 10), escaneos y fuerza bruta en el log HTTP de Cloudflare",
   "source": "cloudflare",
   "useCase": "web-attacks-owasp",
   "status": "testing",
   "ruleIds": [
    "102000",
    "102001",
    "102002",
    "102003",
    "102004",
    "102005",
    "102006",
    "102007",
    "102008",
    "102009",
    "102010",
    "102011",
    "102012",
    "102013",
    "102014",
    "102015",
    "102016",
    "102017",
    "102018",
    "102019"
   ],
   "mitre": [
    "T1190",
    "T1595.002",
    "T1595.003",
    "T1110.001",
    "T1110.004"
   ],
   "priorityHint": "P2 solo con evidencia de impacto (500) o ataque a credenciales; el resto, cola sin correo",
   "falsePositives": [
    "Búsquedas o documentación con «../» o «select … from»: el patrón SQL exige un catálogo de sistema (information_schema, pg_catalog…) y el recorrido de rutas a 2xx queda en 5 (fuera de la cola).",
    "Callbacks OAuth a localhost en staging y plantillas {{config}} sin renderizar: excluidos del patrón (fixtures FP).",
    "Pentest autorizado: IPs en b89-authorized-scanners bajan a 102008 (nivel 2) y no cuentan para campañas.",
    "Comercios con credenciales caducadas reintentando: 102018 exige 30 IPs distintas en 10 min."
   ],
   "dataSources": [
    "Cloudflare http_requests por Logpush (cada petición; requiere Logs Write en el token)",
    "Cloudflare httpRequestsAdaptive por GraphQL (todos los planes; muestreado ~1 de cada 11)"
   ]
  },
  {
   "id": "B89-DET-DLP-001",
   "title": "DLP de endpoints · credenciales, datos personales y documentos protegidos en archivos",
   "source": "dlp",
   "useCase": "dlp-endpoint-findings",
   "status": "experimental",
   "ruleIds": [
    "101110",
    "101111",
    "101112"
   ],
   "mitre": [
    "T1552.001"
   ],
   "priorityHint": "P3",
   "falsePositives": [
    "Archivos de ejemplo o de pruebas con claves falsas (README, fixtures, documentación).",
    "Copias de trabajo legítimas de un documento protegido en una carpeta autorizada.",
    "Números de DNI o RUC en documentos que el área tiene permitido guardar."
   ],
   "dataSources": [
    "Ferrispector (YARA-X) vía agente Wazuh, JSONL sin rutas ni contenido"
   ]
  },
  {
   "id": "B89-DET-DLP-002",
   "title": "DLP de endpoints · salud del agente Ferrispector",
   "source": "dlp",
   "useCase": "dlp-agent-health",
   "status": "experimental",
   "ruleIds": [
    "101113",
    "101114",
    "101115",
    "101116"
   ],
   "mitre": [],
   "priorityHint": "P4",
   "falsePositives": [
    "Corte breve de red o reinicio del servidor (se recupera solo en minutos).",
    "Archivos bloqueados por otro programa mientras se escriben."
   ],
   "dataSources": [
    "Ferrispector (eventos policy_sync_error y scan_error) vía agente Wazuh"
   ]
  },
  {
   "id": "B89-DET-NET-005",
   "title": "Ataques web contra la consola del SOC (edge nginx)",
   "source": "edge",
   "useCase": "http-attacks",
   "status": "testing",
   "ruleIds": [
    "101830",
    "101831",
    "101832",
    "101833",
    "101834",
    "101835",
    "101836",
    "101837",
    "101838",
    "101839",
    "101840",
    "101841"
   ],
   "mitre": [
    "T1190",
    "T1595.002",
    "T1595.003",
    "T1595",
    "T1499"
   ],
   "priorityHint": "P3; P2 si hay campaña o correlación",
   "falsePositives": [
    "URLs del dashboard con rison/KQL que contienen comillas y operadores (se probó el caso de Discover).",
    "Herramientas de monitoreo sintético propias: usar un User-Agent sin nombres de escáner."
   ],
   "dataSources": [
    "bitácora JSON del edge nginx (b89-collectors/edge/access.json), IP real vía X-Forwarded-For del ALB"
   ]
  },
  {
   "id": "B89-DET-NET-006",
   "title": "Inicios de sesión en la consola del SOC por IP",
   "source": "edge",
   "useCase": "soc-authentication",
   "status": "testing",
   "ruleIds": [
    "101842",
    "101843",
    "101844",
    "101845",
    "101846"
   ],
   "mitre": [
    "T1110",
    "T1110.001",
    "T1078",
    "T1110.003"
   ],
   "priorityHint": "P1 para 13; P2 para 9-10",
   "falsePositives": [
    "Usuario que olvidó la contraseña y reintenta (bajo el umbral de 6 en 5 min)."
   ],
   "dataSources": [
    "bitácora JSON del edge: POST /api/auth/password con resultado derivado de Location (authError=)"
   ]
  },
  {
   "id": "B89-DET-ENTRA-002",
   "title": "Consentimiento OAuth y credenciales nuevas en aplicaciones",
   "source": "entra",
   "useCase": "app-consent-and-credentials",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100522",
    "100523"
   ],
   "mitre": [
    "T1528",
    "T1098.001"
   ],
   "priorityHint": "P2",
   "falsePositives": [
    "Rotación planificada de secretos de apps internas (ventana de mantenimiento)."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-ENTRA-003",
   "title": "Cambios de MFA, Conditional Access y federación",
   "source": "entra",
   "useCase": "auth-methods-and-federation",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100524",
    "100525",
    "100526"
   ],
   "mitre": [
    "T1484.002",
    "T1556.009",
    "T1556.006"
   ],
   "priorityHint": "P1 federación; P2 resto",
   "falsePositives": [
    "Registro de MFA de altas nuevas (alto volumen en onboarding).",
    "Cambios de CA del equipo de identidad con cambio aprobado."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-ENTRA-001",
   "title": "Nuevo administrador en Entra (rol privilegiado y tier 0)",
   "source": "entra",
   "useCase": "privileged-role-assignment",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "101704"
   ],
   "mitre": [
    "T1098.003"
   ],
   "priorityHint": "P1 para tier 0",
   "falsePositives": [
    "Activaciones PIM planificadas de los administradores de plataforma (deben venir con ticket).",
    "Altas de onboarding del equipo de identidad: correlacionar con el cambio aprobado."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-LAUNCH-001",
   "title": "Paquete de lanzamiento: Sophos, Cato, Entra, AD, Windows y Linux normalizados",
   "source": "launch",
   "useCase": "normalized-provider-pack",
   "status": "experimental",
   "ruleIds": [
    "101201",
    "101202",
    "101203",
    "101204",
    "101205",
    "101206",
    "101207",
    "101208",
    "101209",
    "101210",
    "101211",
    "101212",
    "101213",
    "101214",
    "101215"
   ],
   "mitre": [
    "T1204",
    "T1059",
    "T1562",
    "T1071",
    "T1078.004",
    "T1098.003",
    "T1098.007",
    "T1070.001",
    "T1562.001",
    "T1059.001",
    "T1027",
    "T1053.005",
    "T1543.003",
    "T1547",
    "T1110.001",
    "T1548.003"
   ],
   "priorityHint": "P1 los marcados P0 en el catálogo de lanzamiento",
   "falsePositives": [
    "Ver el catálogo de lanzamiento por detección."
   ],
   "dataSources": [
    "Eventos JSON normalizados por B89 (b89_vendor = sophos, cato, entra, active_directory, windows, linux)"
   ]
  },
  {
   "id": "B89-DET-NET-004",
   "title": "Ejecución interactiva en contenedores críticos del SOC",
   "source": "linux",
   "useCase": "docker-runtime",
   "status": "testing",
   "ruleIds": [
    "101850",
    "101851",
    "101852"
   ],
   "mitre": [
    "T1609",
    "T1610"
   ],
   "priorityHint": "P3 (P2 fuera de una ventana de cambio)",
   "falsePositives": [
    "Scripts de despliegue y políticas B89 (deploy-detections.sh, apply-*.sh) hacen docker exec en el manager: esperado durante un despliegue."
   ],
   "dataSources": [
    "wodle docker-listener del grupo linux-docker-hosts (agente 001)"
   ]
  },
  {
   "id": "B89-DET-NET-002",
   "title": "Llamadas de red auditadas (connect/bind/accept) de sesiones interactivas",
   "source": "linux",
   "useCase": "network-auditd",
   "status": "testing",
   "ruleIds": [
    "101810",
    "101812",
    "101813",
    "101814",
    "101815",
    "101816",
    "101818",
    "101811",
    "101817"
   ],
   "mitre": [
    "T1059.004",
    "T1571",
    "T1046",
    "T1040",
    "T1071",
    "T1505.003"
   ],
   "priorityHint": "P2 para 10-12",
   "falsePositives": [
    "Administrador que usa nc/nmap/tcpdump para diagnosticar: confirmar con el ticket de cambio; no se suprime.",
    "IPv6 o claves no enriquecidas (auditd sin log_format ENRICHED): la regla cae a 101810 sin IP."
   ],
   "dataSources": [
    "auditd del host con b89-audit-network.rules (distribuido por el grupo linux-servers), log_format audit"
   ]
  },
  {
   "id": "B89-DET-NET-001",
   "title": "Puertos en escucha y conexiones TCP nuevas del host",
   "source": "linux",
   "useCase": "network-connections",
   "status": "testing",
   "ruleIds": [
    "101800",
    "101801",
    "101802",
    "101803",
    "101804",
    "101805",
    "101806",
    "101807",
    "101808",
    "101809"
   ],
   "mitre": [
    "T1571",
    "T1059.004",
    "T1071",
    "T1133"
   ],
   "priorityHint": "P2 para 10-12; P4 para 3-5 (caza)",
   "falsePositives": [
    "Despliegue o actualización que publica un puerto nuevo: agregarlo por PR a infra/wazuh/network/lists/b89-expected-listeners.",
    "Un servicio SaaS nuevo (destino poco común): agregar el prefijo a infra/wazuh/network/lists/b89-egress-static.",
    "Conexiones cortas (< 2 min) no se ven en la foto de ss: las cubre auditd (network-auditd) para sesiones interactivas."
   ],
   "dataSources": [
    "command monitoring del grupo linux-servers: b89-netconn.sh (ss) cada 2 min (eventos) y 5 min (foto)",
    "agente 001 (b89-soc-dev-node)"
   ]
  },
  {
   "id": "B89-TUNE-LNX-001",
   "title": "Ruido de sesiones administrativas, SSH por contexto y rootcheck en overlay",
   "source": "linux",
   "useCase": "noise-tuning",
   "status": "testing",
   "ruleIds": [
    "101761",
    "101762",
    "101763",
    "101765",
    "101766",
    "101767"
   ],
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "priorityHint": "P3 en horario; P2 fuera de horario (P1 si además hay fuerza bruta: 101750)",
   "falsePositives": [
    "Operador que entra desde una IP nueva (red móvil, viaje): agregar el prefijo por PR a b89-admin-ips.",
    "La hora del manager es UTC: el horario B89 se expresa como 01:00–13:00 UTC (20:00–08:00 Lima)."
   ],
   "dataSources": [
    "journald del agente 001 (pam_unix, sshd)",
    "rootcheck del agente"
   ]
  },
  {
   "id": "B89-DET-LNX-003",
   "title": "Persistencia y debilitamiento de autenticación por FIM en tiempo real",
   "source": "linux",
   "useCase": "persistence-fim",
   "status": "testing",
   "ruleIds": [
    "101755",
    "101756",
    "101757",
    "101758",
    "101759",
    "101760"
   ],
   "mitre": [
    "T1098.004",
    "T1543.002",
    "T1053.006",
    "T1053.003",
    "T1548.003",
    "T1556.003",
    "T1556",
    "T1021.004"
   ],
   "priorityHint": "P2 (P1 fuera de cambio aprobado)",
   "falsePositives": [
    "Despliegues y actualizaciones de paquetes (apt crea unidades y cron); correlacionar con dpkg (2902/2904).",
    "Rotación de llaves por el equipo de plataforma."
   ],
   "dataSources": [
    "FIM realtime del grupo linux-servers (/root/.ssh, /etc/ssh, /etc/sudoers.d, /etc/pam.d, /etc/cron.*, /etc/systemd/system)"
   ]
  },
  {
   "id": "B89-DET-LNX-002",
   "title": "Usuario agregado a grupo privilegiado en Linux",
   "source": "linux",
   "useCase": "privileged-group-membership",
   "status": "testing",
   "ruleIds": [
    "101752"
   ],
   "mitre": [
    "T1098.007",
    "T1548"
   ],
   "priorityHint": "P2",
   "falsePositives": [
    "Altas de administradores vía gestión de configuración (registrar el cambio)."
   ],
   "dataSources": [
    "journald (gpasswd) del agente"
   ]
  },
  {
   "id": "B89-DET-LNX-001",
   "title": "Acceso SSH exitoso tras fuerza bruta (30 min)",
   "source": "linux",
   "useCase": "ssh-bruteforce-success",
   "status": "testing",
   "ruleIds": [
    "101750"
   ],
   "mitre": [
    "T1110.001",
    "T1078.003",
    "T1021.004"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Administrador que falla la llave y entra con la correcta desde su IP (los fallos de 5710/5712 son de usuarios inexistentes; si la IP es de B89, confirmar)."
   ],
   "dataSources": [
    "journald/sshd del agente (grupo linux-servers); datos reales en b89-soc-dev-node"
   ]
  },
  {
   "id": "B89-DET-NET-003",
   "title": "Seguimiento de sesiones SSH por cuenta",
   "source": "linux",
   "useCase": "ssh-session-tracking",
   "status": "testing",
   "ruleIds": [
    "101820",
    "101821"
   ],
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "priorityHint": "P2",
   "falsePositives": [
    "Operador que cambia de red (VPN, móvil) varias veces en una hora."
   ],
   "dataSources": [
    "journald/sshd del agente (grupo linux-servers)"
   ]
  },
  {
   "id": "B89-DET-M365-003",
   "title": "Desactivación de la auditoría de M365",
   "source": "m365",
   "useCase": "audit-tampering",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100527",
    "100528"
   ],
   "mitre": [
    "T1562.008"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Cuentas de servicio de backup con AuditBypass aprobado (registrar en docs/10)."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-M365-002",
   "title": "Persistencia en buzón (BEC): reglas, reenvío y delegación",
   "source": "m365",
   "useCase": "bec-mailbox-persistence",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100510",
    "100511",
    "100512",
    "100513",
    "100514"
   ],
   "mitre": [
    "T1564.008",
    "T1114.003",
    "T1098.002"
   ],
   "priorityHint": "P2 (P1 si correlaciona con un acceso anómalo)",
   "falsePositives": [
    "Reglas legítimas de organización de correo (mover a carpeta) creadas desde Outlook (100511).",
    "Reenvío aprobado a buzones compartidos internos: documentar excepción por destinatario."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-M365-005",
   "title": "Cadena de compromiso de cuenta M365 (acceso → privilegio/MFA/reenvío)",
   "source": "m365",
   "useCase": "compromise-chain",
   "status": "testing",
   "ruleIds": [
    "101700",
    "101701",
    "101702",
    "101703"
   ],
   "mitre": [
    "T1098.003",
    "T1078.004",
    "T1556.006",
    "T1098.005",
    "T1114.003",
    "T1564.008",
    "T1110.003"
   ],
   "priorityHint": "P1",
   "falsePositives": [
    "Usuario que olvidó su contraseña, la recuperó y configuró MFA nuevo en la misma sesión (101701): confirmar con la persona por un canal fuera de banda.",
    "Spray desde una salida NAT compartida y login legítimo de otra persona detrás de la misma IP (101703)."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-M365-001",
   "title": "Ataques de credenciales contra Microsoft 365",
   "source": "m365",
   "useCase": "credential-attacks",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100502",
    "100503",
    "100504",
    "100505",
    "100506",
    "100530"
   ],
   "mitre": [
    "T1110.001",
    "T1110.003",
    "T1110",
    "T1078.004"
   ],
   "priorityHint": "P1 para 100505/100530; P2 para 100503/100504",
   "falsePositives": [
    "Usuarios con la contraseña caducada reintentando desde varios dispositivos (100503).",
    "Salidas NAT compartidas (oficina, VPN) que suman fallos de muchas personas (100504).",
    "Pruebas de break-glass planificadas: registrar el ensayo en el cambio antes de hacerlo."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-M365-004",
   "title": "Exfiltración por enlaces anónimos y eDiscovery",
   "source": "m365",
   "useCase": "data-exfiltration",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "100515",
    "100529"
   ],
   "mitre": [
    "T1567",
    "T1114"
   ],
   "priorityHint": "P3 / P2",
   "falsePositives": [
    "Áreas que comparten material público con enlaces anónimos (marketing).",
    "Casos legales en curso con exportación aprobada por Compliance."
   ],
   "dataSources": [
    "Office 365 Management Activity API (módulo office365 de Wazuh): Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General"
   ]
  },
  {
   "id": "B89-DET-NET-008",
   "title": "Misma IP atacante en Cloudflare WAF, edge del SOC y SSH",
   "source": "network",
   "useCase": "cross-source-correlation",
   "status": "testing",
   "ruleIds": [
    "101870",
    "101871",
    "101872",
    "101873",
    "101874",
    "101875",
    "101876"
   ],
   "mitre": [
    "T1190",
    "T1595",
    "T1078",
    "T1110",
    "T1078.003"
   ],
   "priorityHint": "P1 para 13-14",
   "falsePositives": [
    "IP compartida (CGNAT, proxy corporativo) entre un atacante y un usuario."
   ],
   "dataSources": [
    "Cloudflare firewall events (vía lista diaria b89-cf-waf-attackers)",
    "edge nginx",
    "sshd"
   ]
  },
  {
   "id": "B89-DET-NET-007",
   "title": "Conexiones e inicios de sesión con IPs de reputación pública",
   "source": "network",
   "useCase": "threat-intel",
   "status": "testing",
   "ruleIds": [
    "101860",
    "101861",
    "101865",
    "101868",
    "101862",
    "101863",
    "101864",
    "101867",
    "101866"
   ],
   "mitre": [
    "T1078",
    "T1090.003",
    "T1078.003",
    "T1021.004",
    "T1595",
    "T1071",
    "T1133"
   ],
   "priorityHint": "P1 para 12-13 con éxito; P3 el resto",
   "falsePositives": [
    "Usuario legítimo detrás de Tor o de una red reasignada recientemente: confirmar con la persona."
   ],
   "dataSources": [
    "listas CDB b89-ti-blocklist y b89-ti-tor (timer diario del host)",
    "SSH, edge, command monitoring y auditd"
   ]
  },
  {
   "id": "B89-DET-PLAT-001",
   "title": "Latido de los collectors de proveedores (cobertura de fuentes)",
   "source": "platform",
   "useCase": "source-health",
   "status": "testing",
   "ruleIds": [
    "101980",
    "101981"
   ],
   "mitre": [],
   "priorityHint": "ninguna (evidencia de cobertura, no alerta)",
   "falsePositives": [
    "No aplica; el volumen es una alerta por corrida de cada collector."
   ],
   "dataSources": [
    "Latido de wazuh/provider-ingestion/common/b89_collector.py (source_heartbeat, allowlist sin URLs ni secretos)"
   ]
  },
  {
   "id": "B89-DET-SP-001",
   "title": "Exfiltración desde SharePoint/OneDrive (volumen, horario, red nueva, invitados, cuentas deshabilitadas, IP maliciosa)",
   "source": "sharepoint",
   "useCase": "exfiltration",
   "status": "testing",
   "ruleIds": [
    "101900",
    "101901",
    "101902",
    "101903",
    "101904",
    "101905",
    "101906",
    "101907",
    "101908",
    "101909",
    "101910",
    "101911",
    "101912",
    "101913",
    "101914"
   ],
   "mitre": [
    "T1530",
    "T1213.002",
    "T1078.004",
    "T1090.003"
   ],
   "priorityHint": "P1 (12) / P2 (10–11) / P4 marcas",
   "falsePositives": [
    "Sincronización del cliente OneDrive (FileSyncDownloadedFull): en datos reales fue el 97 % de las descargas y un equipo resincronizó 6449 archivos en 25 h (41 alertas P2 con el umbral común). Ahora tiene marca y umbral propios (101912/101913, 500/10 min, P3).",
    "Migraciones o respaldos con cuenta de servicio: registrarla en b89-m365-service-accounts (baja a 2 y no cuenta).",
    "Viajes: red nueva legítima; confirmar con el usuario y con los inicios de sesión de Entra."
   ],
   "dataSources": [
    "Office 365 Management Activity API, Audit.SharePoint (módulo office365 de Wazuh; ActivityFeed.Read)",
    "Microsoft Graph Purview Audit Search /security/auditLog/queries (collector b89-sharepoint-audit; AuditLogsQuery-SharePoint.Read.All / AuditLogsQuery-OneDrive.Read.All)"
   ]
  },
  {
   "id": "B89-DET-SP-003",
   "title": "Uso compartido externo: enlaces anónimos en volumen y correos personales",
   "source": "sharepoint",
   "useCase": "external-sharing",
   "status": "testing",
   "ruleIds": [
    "101925",
    "101926",
    "101927",
    "101928",
    "101929",
    "101930"
   ],
   "mitre": [
    "T1567",
    "T1537"
   ],
   "priorityHint": "P1 (12) / P2 (9–11) / P3 (4)",
   "falsePositives": [
    "Marketing y comunicaciones publican con enlaces anónimos (b89-m365-sharing-approved).",
    "Proveedores con correo gratuito (documentar y aprobar por PR)."
   ],
   "dataSources": [
    "Office 365 Management Activity API, Audit.SharePoint (módulo office365 de Wazuh; ActivityFeed.Read)",
    "Microsoft Graph Purview Audit Search /security/auditLog/queries (collector b89-sharepoint-audit; AuditLogsQuery-SharePoint.Read.All / AuditLogsQuery-OneDrive.Read.All)"
   ]
  },
  {
   "id": "B89-DET-SP-005",
   "title": "Etiquetas de confidencialidad quitadas o rebajadas y coincidencias DLP",
   "source": "sharepoint",
   "useCase": "labels-and-dlp",
   "status": "testing",
   "ruleIds": [
    "101945",
    "101946",
    "101947",
    "101948",
    "101949",
    "101950",
    "101951"
   ],
   "mitre": [
    "T1562",
    "T1567",
    "T1213.002"
   ],
   "priorityHint": "P1 (12–13) / P2 (8–11) / P3 (7)",
   "falsePositives": [
    "Reclasificación aprobada con justificación (JustificationText).",
    "Políticas DLP en modo prueba (revisar la severidad en Purview)."
   ],
   "dataSources": [
    "Office 365 Management Activity API, Audit.SharePoint (módulo office365 de Wazuh; ActivityFeed.Read)",
    "Microsoft Graph Purview Audit Search /security/auditLog/queries (collector b89-sharepoint-audit; AuditLogsQuery-SharePoint.Read.All / AuditLogsQuery-OneDrive.Read.All)"
   ]
  },
  {
   "id": "B89-DET-SP-002",
   "title": "Borrado masivo y vaciado de la papelera en SharePoint/OneDrive",
   "source": "sharepoint",
   "useCase": "mass-deletion",
   "status": "testing",
   "ruleIds": [
    "101915",
    "101916",
    "101917",
    "101918",
    "101919",
    "101920"
   ],
   "mitre": [
    "T1485",
    "T1490"
   ],
   "priorityHint": "P1 (12–13) / P2 (10)",
   "falsePositives": [
    "Reorganización de bibliotecas por el dueño del sitio (con aviso previo).",
    "Retención o limpieza automatizada con cuenta de servicio (registrar en la allowlist)."
   ],
   "dataSources": [
    "Office 365 Management Activity API, Audit.SharePoint (módulo office365 de Wazuh; ActivityFeed.Read)",
    "Microsoft Graph Purview Audit Search /security/auditLog/queries (collector b89-sharepoint-audit; AuditLogsQuery-SharePoint.Read.All / AuditLogsQuery-OneDrive.Read.All)"
   ]
  },
  {
   "id": "B89-DET-SP-006",
   "title": "Postura de SharePoint y salud de la fuente",
   "source": "sharepoint",
   "useCase": "posture",
   "status": "pending-provider-evidence",
   "ruleIds": [
    "101960",
    "101961",
    "101962",
    "101963",
    "101964",
    "101965",
    "101966",
    "101967",
    "101968",
    "101969",
    "101970",
    "101971",
    "101972"
   ],
   "mitre": [
    "T1484",
    "T1567",
    "T1537"
   ],
   "priorityHint": "P1 (12) / P2 (8–10) / P3",
   "falsePositives": [
    "Sitios de proyectos con socios: permisos externos esperados (revisión trimestral de accesos)."
   ],
   "dataSources": [
    "Microsoft Graph /admin/sharepoint/settings (SharePointTenantSettings.Read.All)",
    "Microsoft Graph /sites/getAllSites, /drives, /permissions (Sites.Read.All)",
    "Collector b89-sharepoint-posture y b89-sharepoint-audit (eventos de capacidad)"
   ]
  },
  {
   "id": "B89-DET-SP-004",
   "title": "Política de uso compartido debilitada y administradores de colección de sitios",
   "source": "sharepoint",
   "useCase": "sharing-policy-and-admins",
   "status": "testing",
   "ruleIds": [
    "101935",
    "101936",
    "101937",
    "101938",
    "101939",
    "101940",
    "101941"
   ],
   "mitre": [
    "T1484",
    "T1098",
    "T1078.004",
    "T1530"
   ],
   "priorityHint": "P1 (12) / P2 (8–11)",
   "falsePositives": [
    "Cambio aprobado por TI (ticket).",
    "Acceso al OneDrive de un empleado que se va (proceso de RR. HH.: documentarlo en el caso)."
   ],
   "dataSources": [
    "Office 365 Management Activity API, Audit.SharePoint (módulo office365 de Wazuh; ActivityFeed.Read)",
    "Microsoft Graph Purview Audit Search /security/auditLog/queries (collector b89-sharepoint-audit; AuditLogsQuery-SharePoint.Read.All / AuditLogsQuery-OneDrive.Read.All)"
   ]
  },
  {
   "id": "B89-DET-SNYK-002",
   "title": "Crítica con exploit maduro en proyecto expuesto por Cloudflare",
   "source": "snyk",
   "useCase": "exposed-critical-exploit",
   "status": "testing",
   "ruleIds": [
    "101730",
    "101731"
   ],
   "mitre": [
    "T1190"
   ],
   "priorityHint": "P1 crítica; P2 alta",
   "falsePositives": [
    "Lista desactualizada: un proyecto que dejó de estar publicado sigue en la lista.",
    "Paquete vulnerable presente pero ruta de código no alcanzable (Snyk reachability)."
   ],
   "dataSources": [
    "Snyk issues",
    "Inventario B89: lista CDB b89-internet-facing-projects (proyecto Snyk → zona/host Cloudflare)"
   ]
  },
  {
   "id": "B89-TUNE-SNYK-001",
   "title": "Calibración de severidad de Snyk por exposición y explotabilidad",
   "source": "snyk",
   "useCase": "severity-calibration",
   "status": "testing",
   "ruleIds": [
    "101732",
    "101733",
    "101734"
   ],
   "mitre": [
    "T1190"
   ],
   "priorityHint": "P3/P4",
   "falsePositives": [
    "Proyecto expuesto que falta en la lista: quedaría degradado. La lista es parte del cambio de cada servicio publicado."
   ],
   "dataSources": [
    "Snyk issues",
    "Lista b89-internet-facing-projects"
   ]
  },
  {
   "id": "B89-DET-SNYK-001",
   "title": "Vulnerabilidades de código y dependencias (Snyk)",
   "source": "snyk",
   "useCase": "vulnerabilities",
   "status": "production",
   "ruleIds": [
    "101451",
    "101452",
    "101453",
    "101454",
    "101455",
    "101456",
    "101457",
    "101458"
   ],
   "mitre": [
    "T1190"
   ],
   "priorityHint": "P2 crítica; P3 alta",
   "falsePositives": [
    "Dependencias de desarrollo no desplegadas.",
    "Issues ya mitigados por WAF sin marcar en Snyk."
   ],
   "dataSources": [
    "Snyk REST API de issues (collector b89-collector-snyk, cada 15 min)"
   ]
  },
  {
   "id": "B89-DET-NET-009",
   "title": "Conexiones de red de endpoints Windows (Sysmon 3/22, WFP, firewall)",
   "source": "windows",
   "useCase": "network-connections",
   "status": "testing",
   "ruleIds": [
    "101880",
    "101881",
    "101882",
    "101883",
    "101884",
    "101885",
    "101886",
    "101887",
    "101888"
   ],
   "mitre": [
    "T1046",
    "T1071",
    "T1595",
    "T1105",
    "T1572"
   ],
   "priorityHint": "P2 para 10-12",
   "falsePositives": [
    "Instaladores legítimos que usan msiexec/bitsadmin contra CDNs públicas."
   ],
   "dataSources": [
    "grupo opt-in windows-telemetry-extended (gate de privacidad): Sysmon 3/22, Security 5156/5157 y pfirewall.log",
    "sin agentes Windows hoy: fixtures en el manager desechable"
   ]
  },
  {
   "id": "B89-DET-WIN-001",
   "title": "Outlook lanza un proceso sospechoso (Sysmon 1)",
   "source": "windows",
   "useCase": "outlook-child-process",
   "status": "experimental",
   "ruleIds": [
    "101100"
   ],
   "mitre": [
    "T1204.002"
   ],
   "priorityHint": "P2",
   "falsePositives": [
    "Complementos de Outlook que lanzan procesos auxiliares (inventariar y excluir por hash/firma)."
   ],
   "dataSources": [
    "Sysmon Event ID 1 (grupo windows-telemetry-extended, opt-in con gate de privacidad)"
   ]
  }
 ],
 "rules": {
  "100502": {
   "id": "100502",
   "level": 3,
   "description": "B89 M365: inicio de sesión fallido de $(office365.UserId) desde $(office365.ClientIP).",
   "mitre": [],
   "groups": [
    "authentication_failed",
    "b89_credential_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100503": {
   "id": "100503",
   "level": 10,
   "description": "B89 M365: fuerza bruta contra $(office365.UserId) (10 fallos en 5 min).",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "authentication_failures",
    "b89_credential_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100504": {
   "id": "100504",
   "level": 12,
   "description": "B89 M365: password spray desde $(office365.ClientIP) contra múltiples cuentas.",
   "mitre": [
    "T1110.003"
   ],
   "groups": [
    "authentication_failures",
    "b89_credential_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100505": {
   "id": "100505",
   "level": 13,
   "description": "B89 M365: inicio de sesión exitoso de $(office365.UserId) tras fuerza bruta.",
   "mitre": [
    "T1110",
    "T1078.004"
   ],
   "groups": [
    "authentication_success",
    "b89_initial_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100506": {
   "id": "100506",
   "level": 3,
   "description": "B89 M365: inicio de sesión exitoso de $(office365.UserId) desde $(office365.ClientIP).",
   "mitre": [],
   "groups": [
    "authentication_success",
    "b89_initial_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100510": {
   "id": "100510",
   "level": 12,
   "description": "B89 M365: $(office365.UserId) creó o modificó una regla de bandeja que reenvía u oculta correo.",
   "mitre": [
    "T1564.008",
    "T1114.003"
   ],
   "groups": [
    "exchange",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100511": {
   "id": "100511",
   "level": 8,
   "description": "B89 M365: $(office365.UserId) actualizó reglas de bandeja desde un cliente.",
   "mitre": [
    "T1564.008"
   ],
   "groups": [
    "exchange",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100512": {
   "id": "100512",
   "level": 12,
   "description": "B89 M365: reenvío de buzón configurado por $(office365.UserId) sobre $(office365.ObjectId).",
   "mitre": [
    "T1114.003"
   ],
   "groups": [
    "exchange",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100513": {
   "id": "100513",
   "level": 10,
   "description": "B89 M365: $(office365.UserId) otorgó SendAs sobre $(office365.ObjectId).",
   "mitre": [
    "T1098.002"
   ],
   "groups": [
    "exchange",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100514": {
   "id": "100514",
   "level": 11,
   "description": "B89 M365: $(office365.UserId) creó o modificó una regla de transporte.",
   "mitre": [
    "T1114.003"
   ],
   "groups": [
    "exchange",
    "b89_exfiltration"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100515": {
   "id": "100515",
   "level": 7,
   "description": "B89 M365: $(office365.UserId) creó un enlace anónimo a $(office365.ObjectId).",
   "mitre": [
    "T1567"
   ],
   "groups": [
    "sharepoint",
    "b89_exfiltration"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-004"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100520": {
   "id": "100520",
   "level": 13,
   "description": "B89 Entra: $(office365.UserId) agregó un miembro a un rol privilegiado de Entra.",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "azure_ad",
    "b89_privilege_escalation",
    "b89_pending_provider_evidence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100521": {
   "id": "100521",
   "level": 9,
   "description": "B89 Entra: $(office365.UserId) agregó un miembro a un rol de Entra.",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "azure_ad",
    "b89_privilege_escalation",
    "b89_pending_provider_evidence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100522": {
   "id": "100522",
   "level": 10,
   "description": "B89 Entra: $(office365.UserId) concedió permisos a una aplicación ($(office365.Operation)).",
   "mitre": [
    "T1528"
   ],
   "groups": [
    "azure_ad",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-ENTRA-002"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100523": {
   "id": "100523",
   "level": 10,
   "description": "B89 Entra: credenciales agregadas a una aplicación por $(office365.UserId).",
   "mitre": [
    "T1098.001"
   ],
   "groups": [
    "azure_ad",
    "b89_persistence",
    "b89_pending_provider_evidence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-ENTRA-002"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100524": {
   "id": "100524",
   "level": 14,
   "description": "B89 Entra: cambio de dominio o federación por $(office365.UserId).",
   "mitre": [
    "T1484.002"
   ],
   "groups": [
    "azure_ad",
    "b89_defense_evasion"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-ENTRA-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100525": {
   "id": "100525",
   "level": 10,
   "description": "B89 Entra: $(office365.UserId) modificó una política de Entra ($(office365.Operation)).",
   "mitre": [
    "T1556.009"
   ],
   "groups": [
    "azure_ad",
    "b89_defense_evasion",
    "b89_pending_provider_evidence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-ENTRA-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100526": {
   "id": "100526",
   "level": 8,
   "description": "B89 Entra: cambio de métodos de autenticación de $(office365.UserId).",
   "mitre": [
    "T1556.006"
   ],
   "groups": [
    "azure_ad",
    "b89_persistence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-ENTRA-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "100527": {
   "id": "100527",
   "level": 14,
   "description": "B89 M365: $(office365.UserId) desactivó la auditoría unificada.",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "exchange",
    "b89_defense_evasion"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-003"
   ],
   "runbooks": [
    "cloudtrail-y-auditoria"
   ]
  },
  "100528": {
   "id": "100528",
   "level": 12,
   "description": "B89 M365: auditoría de buzón desactivada o eximida por $(office365.UserId).",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "exchange",
    "b89_defense_evasion"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-003"
   ],
   "runbooks": [
    "cloudtrail-y-auditoria"
   ]
  },
  "100529": {
   "id": "100529",
   "level": 12,
   "description": "B89 M365: exportación de eDiscovery por $(office365.UserId).",
   "mitre": [
    "T1114"
   ],
   "groups": [
    "compliance",
    "b89_exfiltration",
    "b89_pending_provider_evidence"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-004"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "100530": {
   "id": "100530",
   "level": 14,
   "description": "B89 M365: actividad de inicio de sesión de la cuenta de emergencia $(office365.UserId).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "authentication",
    "b89_initial_access"
   ],
   "file": "wazuh/office365/rules/b89_office365_rules.xml",
   "useCases": [
    "B89-DET-M365-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101100": {
   "id": "101100",
   "level": 8,
   "description": "B89 Windows: Outlook inició un proceso que requiere revisión: $(win.eventdata.image). SigmaHQ 208748f7-881d-47ac-a29c-07ea84bf691d; autores Michael Haag, Florian Roth, Markus Neis, Elastic y FPT.EagleEye Team; DRL-1.1.",
   "mitre": [
    "T1204.002"
   ],
   "groups": [
    "b89_initial_access",
    "b89_phishing_triage"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-WIN-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101110": {
   "id": "101110",
   "level": 5,
   "description": "B89 DLP: Ferrispector encontró datos sensibles en un archivo del equipo $(endpoint) (regla $(yara_rule_id)).",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_endpoint"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-001"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101111": {
   "id": "101111",
   "level": 8,
   "description": "B89 DLP: Ferrispector encontró una credencial guardada en un archivo del equipo $(endpoint) (regla $(yara_rule_id)).",
   "mitre": [
    "T1552.001"
   ],
   "groups": [
    "b89_dlp",
    "b89_endpoint"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-001"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101112": {
   "id": "101112",
   "level": 10,
   "description": "B89 DLP: apareció una copia exacta de un documento protegido en el equipo $(endpoint).",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_endpoint"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-001"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101113": {
   "id": "101113",
   "level": 3,
   "description": "B89 DLP: Ferrispector no pudo consultar la política en el servidor.",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_dlp_health"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-002"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101114": {
   "id": "101114",
   "level": 7,
   "description": "B89 DLP: Ferrispector lleva más de 5 minutos sin recibir la política (credencial revocada o servidor inaccesible).",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_dlp_health"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-002"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101115": {
   "id": "101115",
   "level": 3,
   "description": "B89 DLP: Ferrispector no pudo revisar un archivo ($(error_code)).",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_dlp_health"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-002"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101116": {
   "id": "101116",
   "level": 6,
   "description": "B89 DLP: Ferrispector falla al revisar muchos archivos del mismo equipo; la protección puede estar incompleta.",
   "mitre": [],
   "groups": [
    "b89_dlp",
    "b89_dlp_health"
   ],
   "file": "infra/wazuh/endpoint/rules/b89_endpoint_rules.xml",
   "useCases": [
    "B89-DET-DLP-002"
   ],
   "runbooks": [
    "dlp-endpoint"
   ]
  },
  "101200": {
   "id": "101200",
   "level": 0,
   "description": "B89: evento de proveedor normalizado recibido.",
   "mitre": [],
   "groups": [
    "b89_provider_base"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml"
  },
  "101201": {
   "id": "101201",
   "level": 15,
   "description": "B89 Sophos: detectó una amenaza alta/crítica activa en endpoint $(b89_endpoint_id).",
   "mitre": [
    "T1204",
    "T1059"
   ],
   "groups": [
    "b89_malware",
    "b89_sophos"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101202": {
   "id": "101202",
   "level": 14,
   "description": "B89 Sophos: no pudo remediar la amenaza en $(b89_endpoint_id); requiere respuesta del SOC.",
   "mitre": [
    "T1562"
   ],
   "groups": [
    "b89_malware",
    "b89_sophos",
    "b89_remediation_failed"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101203": {
   "id": "101203",
   "level": 13,
   "description": "B89 Cato: permitió tráfico con veredicto de amenaza alta/crítica desde $(b89_source_ip) hacia $(b89_destination).",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_network",
    "b89_cato",
    "b89_threat_allowed"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101204": {
   "id": "101204",
   "level": 5,
   "description": "B89 Cato: bloqueó un evento de amenaza; correlacionar antes de elevar prioridad.",
   "mitre": [],
   "groups": [
    "b89_network",
    "b89_cato",
    "b89_blocked"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101205": {
   "id": "101205",
   "level": 13,
   "description": "B89 Entra: informó un inicio de sesión de riesgo alto para $(b89_user_id) desde $(b89_source_ip).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "b89_identity",
    "b89_entra",
    "b89_risky_signin"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101206": {
   "id": "101206",
   "level": 13,
   "description": "B89 Entra: asignación de rol privilegiado Entra sin cambio aprobado; actor $(b89_actor), destino $(b89_user_id).",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "b89_identity",
    "b89_entra",
    "b89_privilege_escalation"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101207": {
   "id": "101207",
   "level": 13,
   "description": "B89 AD: miembro agregado a grupo privilegiado de AD sin cambio aprobado; host $(b89_host), destino $(b89_user_id).",
   "mitre": [
    "T1098.007"
   ],
   "groups": [
    "b89_identity",
    "b89_active_directory",
    "b89_privilege_escalation"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101208": {
   "id": "101208",
   "level": 14,
   "description": "B89 Windows: se limpió el registro Security de Windows en $(b89_host).",
   "mitre": [
    "T1070.001"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_windows"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101209": {
   "id": "101209",
   "level": 13,
   "description": "B89 Windows: protección antimalware en tiempo real deshabilitada en $(b89_host).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_windows"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101210": {
   "id": "101210",
   "level": 10,
   "description": "B89 Windows: PowerShell codificado iniciado por proceso no habitual en $(b89_host).",
   "mitre": [
    "T1059.001",
    "T1027"
   ],
   "groups": [
    "b89_execution",
    "b89_windows"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101211": {
   "id": "101211",
   "level": 10,
   "description": "B89 Windows: nueva tarea o servicio sin cambio aprobado en $(b89_host).",
   "mitre": [
    "T1053.005",
    "T1543.003"
   ],
   "groups": [
    "b89_persistence",
    "b89_windows"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101212": {
   "id": "101212",
   "level": 9,
   "description": "B89 FIM: cambio de archivo bajo ruta de persistencia monitoreada en $(b89_host).",
   "mitre": [
    "T1547"
   ],
   "groups": [
    "b89_persistence",
    "b89_fim"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101213": {
   "id": "101213",
   "level": 12,
   "description": "B89 Linux: ráfaga de fallos SSH desde $(b89_source_ip) en cinco minutos.",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "b89_linux",
    "b89_brute_force"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101214": {
   "id": "101214",
   "level": 9,
   "description": "B89 Linux: uso privilegiado de sudo fuera de cambio aprobado en $(b89_host).",
   "mitre": [
    "T1548.003"
   ],
   "groups": [
    "b89_linux",
    "b89_privilege_escalation"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101215": {
   "id": "101215",
   "level": 3,
   "description": "B89 Linux: fallo de autenticación SSH desde $(b89_source_ip) en $(b89_host).",
   "mitre": [],
   "groups": [
    "b89_linux",
    "b89_authentication_failed"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_launch_provider_rules.xml",
   "useCases": [
    "B89-DET-LAUNCH-001"
   ]
  },
  "101216": {
   "id": "101216",
   "level": 14,
   "description": "B89: cambio destructivo en control de seguridad de Cloudflare; verificar actor, recurso y cambio aprobado.",
   "mitre": [
    "T1562.007"
   ],
   "groups": [
    "b89_cloudflare",
    "b89_defense_evasion"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101217": {
   "id": "101217",
   "level": 8,
   "description": "B89: cambio administrativo en Cloudflare por $(b89_actor) sobre $(b89_product): $(b89_action).",
   "mitre": [],
   "groups": [
    "b89_cloudflare",
    "b89_change_monitoring"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101218": {
   "id": "101218",
   "level": 11,
   "description": "B89: hallazgo alto/crítico activo en Snyk; valorar exposición, entorno productivo y explotabilidad antes de priorizar.",
   "mitre": [
    "T1195"
   ],
   "groups": [
    "b89_snyk",
    "b89_vulnerability"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101219": {
   "id": "101219",
   "level": 13,
   "description": "B89: incidente alto/crítico abierto de Bitdefender en endpoint $(b89_endpoint_id).",
   "mitre": [
    "T1204",
    "T1059"
   ],
   "groups": [
    "b89_bitdefender",
    "b89_malware"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101220": {
   "id": "101220",
   "level": 7,
   "description": "B89: el collector de $(b89_vendor) no tiene autorización API (HTTP $(b89_http_status)); la fuente está degradada.",
   "mitre": [],
   "groups": [
    "b89_source_health",
    "b89_authentication_failed"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101221": {
   "id": "101221",
   "level": 5,
   "description": "B89: error de consulta de $(b89_vendor); revisar la salud de la integración.",
   "mitre": [],
   "groups": [
    "b89_source_health"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101222": {
   "id": "101222",
   "level": 2,
   "description": "B89: se restableció la conexión de lectura a $(b89_vendor).",
   "mitre": [],
   "groups": [
    "b89_source_health",
    "b89_provider_recovered"
   ],
   "file": "infra/wazuh/launch-detections/rules/b89_provider_service_rules.xml"
  },
  "101300": {
   "id": "101300",
   "level": 12,
   "description": "B89 AD: miembro añadido a un grupo integrado privilegiado de AD; revisar actor, miembro y cambio aprobado.",
   "mitre": [
    "T1098.007"
   ],
   "groups": [
    "b89_ad_privilege_change",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-001"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101301": {
   "id": "101301",
   "level": 12,
   "description": "B89 AD: se modificó la política de auditoría; validar el cambio y que la cobertura de registros permanezca activa.",
   "mitre": [
    "T1562.002"
   ],
   "groups": [
    "b89_ad_defense_evasion",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-001"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101302": {
   "id": "101302",
   "level": 13,
   "description": "B89 AD: se limpió el registro Security de Windows; preservar evidencia y verificar el actor.",
   "mitre": [
    "T1070.001"
   ],
   "groups": [
    "b89_ad_log_tampering",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-001"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101303": {
   "id": "101303",
   "level": 10,
   "description": "B89 AD: cambio en AdminSDHolder o un objeto de Group Policy; validar autor y ticket de cambio.",
   "mitre": [
    "T1484.001"
   ],
   "groups": [
    "b89_ad_directory_change",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-001"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101304": {
   "id": "101304",
   "level": 5,
   "description": "B89 AD: ticket Kerberos de servicio emitido con RC4; verificar cuenta de servicio, origen y necesidad de compatibilidad.",
   "mitre": [
    "T1558.003"
   ],
   "groups": [
    "b89_ad_kerberos_hunt",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101305": {
   "id": "101305",
   "level": 7,
   "description": "B89 AD: TGT emitido sin preautenticación Kerberos; confirmar cuenta y excepción autorizada.",
   "mitre": [
    "T1558.004"
   ],
   "groups": [
    "b89_ad_kerberos_hunt",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101306": {
   "id": "101306",
   "level": 6,
   "description": "B89 AD: candidato a DCSync por acceso de replicación de directorio; comprobar principal, host y permisos legítimos de replicación.",
   "mitre": [
    "T1003.006"
   ],
   "groups": [
    "b89_ad_replication_hunt",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101307": {
   "id": "101307",
   "level": 6,
   "description": "B89 AD: fallo de preautenticación Kerberos; agrupar por cuenta, origen y ventana antes de clasificar password spraying.",
   "mitre": [
    "T1110.003"
   ],
   "groups": [
    "b89_ad_auth_hunt",
    "b89_ad_review"
   ],
   "file": "infra/wazuh/active-directory/rules/b89_active_directory_rules.xml",
   "useCases": [
    "B89-DET-AD-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101400": {
   "id": "101400",
   "level": 0,
   "description": "B89 Bitdefender: evento del collector GravityZone.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml"
  },
  "101401": {
   "id": "101401",
   "level": 2,
   "description": "B89 Bitdefender: estado del endpoint $(bitdefender.endpoint.name) sin hallazgos de protección.",
   "mitre": [],
   "groups": [
    "b89_endpoint_status"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101402": {
   "id": "101402",
   "level": 12,
   "description": "B89 Bitdefender: endpoint $(bitdefender.endpoint.name) infectado (malware activo sin remediar).",
   "mitre": [
    "T1204"
   ],
   "groups": [
    "b89_malware"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101403": {
   "id": "101403",
   "level": 10,
   "description": "B89 Bitdefender: detección de malware en $(bitdefender.endpoint.name).",
   "mitre": [
    "T1204"
   ],
   "groups": [
    "b89_malware"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101404": {
   "id": "101404",
   "level": 10,
   "description": "B89 Bitdefender: endpoint $(bitdefender.endpoint.name) aislado de la red.",
   "mitre": [],
   "groups": [
    "b89_containment"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101405": {
   "id": "101405",
   "level": 10,
   "description": "B89 Bitdefender: antimalware deshabilitado en $(bitdefender.endpoint.name).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_defense_evasion"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101406": {
   "id": "101406",
   "level": 7,
   "description": "B89 Bitdefender: Advanced Threat Control deshabilitado en $(bitdefender.endpoint.name).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_defense_evasion"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101407": {
   "id": "101407",
   "level": 5,
   "description": "B89 Bitdefender: firmas desactualizadas en $(bitdefender.endpoint.name).",
   "mitre": [],
   "groups": [
    "b89_hygiene"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101408": {
   "id": "101408",
   "level": 4,
   "description": "B89 Bitdefender: agente desactualizado en $(bitdefender.endpoint.name).",
   "mitre": [],
   "groups": [
    "b89_hygiene"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101409": {
   "id": "101409",
   "level": 5,
   "description": "B89 Bitdefender: la política $(bitdefender.endpoint.policy_name) no está aplicada en $(bitdefender.endpoint.name).",
   "mitre": [],
   "groups": [
    "b89_hygiene"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101410": {
   "id": "101410",
   "level": 10,
   "description": "B89 Bitdefender: amenaza $(bitdefender.quarantine.threat_name) puesta en cuarentena en $(bitdefender.quarantine.endpoint_name).",
   "mitre": [
    "T1204"
   ],
   "groups": [
    "b89_malware"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101411": {
   "id": "101411",
   "level": 13,
   "description": "B89 Bitdefender: 3+ amenazas en cuarentena en $(bitdefender.quarantine.endpoint_name) en 1 h; posible infección persistente.",
   "mitre": [
    "T1204"
   ],
   "groups": [
    "b89_malware"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_bitdefender_rules.xml",
   "useCases": [
    "B89-DET-BD-001"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101450": {
   "id": "101450",
   "level": 0,
   "description": "B89 Snyk: evento del collector de issues.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml"
  },
  "101451": {
   "id": "101451",
   "level": 2,
   "description": "B89 Snyk: issue resuelto $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101452": {
   "id": "101452",
   "level": 2,
   "description": "B89 Snyk: issue ignorado $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101453": {
   "id": "101453",
   "level": 3,
   "description": "B89 Snyk: vulnerabilidad baja $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101454": {
   "id": "101454",
   "level": 5,
   "description": "B89 Snyk: vulnerabilidad media $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101455": {
   "id": "101455",
   "level": 10,
   "description": "B89 Snyk: vulnerabilidad ALTA $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101456": {
   "id": "101456",
   "level": 12,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101457": {
   "id": "101457",
   "level": 13,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA con exploit maduro $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101458": {
   "id": "101458",
   "level": 11,
   "description": "B89 Snyk: vulnerabilidad ALTA con exploit maduro $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_snyk_rules.xml",
   "useCases": [
    "B89-DET-SNYK-001"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101500": {
   "id": "101500",
   "level": 0,
   "description": "B89 Cloudflare: evento del collector.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101501": {
   "id": "101501",
   "level": 3,
   "description": "B89 Cloudflare: $(cloudflare.audit.action) sobre $(cloudflare.audit.resource_type) por $(cloudflare.audit.actor_email).",
   "mitre": [],
   "groups": [
    "b89_audit"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101502": {
   "id": "101502",
   "level": 5,
   "description": "B89 Cloudflare: acción fallida $(cloudflare.audit.action) sobre $(cloudflare.audit.resource_type) por $(cloudflare.audit.actor_email).",
   "mitre": [],
   "groups": [
    "b89_audit"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101503": {
   "id": "101503",
   "level": 5,
   "description": "B89 Cloudflare: cambio DNS ($(cloudflare.audit.action)) en $(cloudflare.audit.zone_name) por $(cloudflare.audit.actor_email).",
   "mitre": [
    "T1584.002"
   ],
   "groups": [
    "b89_audit",
    "b89_dns_change"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101504": {
   "id": "101504",
   "level": 8,
   "description": "B89 Cloudflare: cambio de control de seguridad ($(cloudflare.audit.action) $(cloudflare.audit.resource_type)) por $(cloudflare.audit.actor_email).",
   "mitre": [
    "T1562"
   ],
   "groups": [
    "b89_audit",
    "b89_defense_evasion"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101505": {
   "id": "101505",
   "level": 10,
   "description": "B89 Cloudflare: control de seguridad eliminado/deshabilitado ($(cloudflare.audit.resource_type)) por $(cloudflare.audit.actor_email).",
   "mitre": [
    "T1562.007"
   ],
   "groups": [
    "b89_audit",
    "b89_defense_evasion"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101506": {
   "id": "101506",
   "level": 10,
   "description": "B89 Cloudflare: cambio de identidad/credenciales ($(cloudflare.audit.action) $(cloudflare.audit.resource_type)) por $(cloudflare.audit.actor_email).",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "b89_audit",
    "b89_persistence"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101507": {
   "id": "101507",
   "level": 12,
   "description": "B89 Cloudflare: zona $(cloudflare.audit.zone_name) eliminada por $(cloudflare.audit.actor_email).",
   "mitre": [
    "T1485"
   ],
   "groups": [
    "b89_audit",
    "b89_impact"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101510": {
   "id": "101510",
   "level": 3,
   "description": "Cloudflare $(cloudflare.firewall.action): solicitud a $(cloudflare.firewall.host)$(cloudflare.firewall.path) desde $(cloudflare.firewall.client_ip). Causa registrada: $(cloudflare.firewall.rule_description) ($(cloudflare.firewall.source), regla $(cloudflare.firewall.rule_id)).",
   "mitre": [],
   "groups": [
    "b89_waf"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101511": {
   "id": "101511",
   "level": 5,
   "description": "Cloudflare detectó una solicitud sospechosa pero solo la registró; pudo llegar a la aplicación: $(cloudflare.firewall.host)$(cloudflare.firewall.path), origen $(cloudflare.firewall.client_ip). Motivo: $(cloudflare.firewall.rule_description) (regla $(cloudflare.firewall.rule_id)).",
   "mitre": [],
   "groups": [
    "b89_waf"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101512": {
   "id": "101512",
   "level": 3,
   "description": "B89 Cloudflare: evento de seguridad $(cloudflare.firewall.action) en $(cloudflare.firewall.host).",
   "mitre": [],
   "groups": [
    "b89_waf"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101513": {
   "id": "101513",
   "level": 10,
   "description": "B89 Cloudflare: 20+ bloqueos/desafíos para $(cloudflare.firewall.client_ip) en 5 min; ataque sostenido contra el perímetro.",
   "mitre": [
    "T1190",
    "T1595"
   ],
   "groups": [
    "b89_waf",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101514": {
   "id": "101514",
   "level": 3,
   "description": "B89 Cloudflare: registro Logpush recibido; revisar el conjunto de datos antes de clasificar.",
   "mitre": [],
   "groups": [
    "b89_logpush"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-001"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101515": {
   "id": "101515",
   "level": 0,
   "description": "B89 Cloudflare: petición HTTP $(cloudflare.http.method) $(cloudflare.http.host)$(cloudflare.http.path) → $(cloudflare.http.status).",
   "mitre": [],
   "groups": [
    "b89_http"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101516": {
   "id": "101516",
   "level": 2,
   "description": "B89 Cloudflare: sondeo de ruta sensible $(cloudflare.http.path) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host) ($(cloudflare.http.status)).",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_http",
    "b89_web_probe"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101517": {
   "id": "101517",
   "level": 10,
   "description": "B89 Cloudflare: escaneo de rutas sensibles desde $(cloudflare.http.client_ip): 15+ sondeos en 2 min.",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_http",
    "b89_web_probe",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101518": {
   "id": "101518",
   "level": 0,
   "description": "B89 Cloudflare: respuesta 4xx a $(cloudflare.http.client_ip).",
   "mitre": [],
   "groups": [
    "b89_http"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101519": {
   "id": "101519",
   "level": 8,
   "description": "B89 Cloudflare: 60+ respuestas 4xx para $(cloudflare.http.client_ip) en 2 min; enumeración o fuerza bruta.",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_http",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101520": {
   "id": "101520",
   "level": 0,
   "description": "B89 Cloudflare: error 5xx en $(cloudflare.http.host).",
   "mitre": [],
   "groups": [
    "b89_http"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101521": {
   "id": "101521",
   "level": 9,
   "description": "B89 Cloudflare: 50+ errores 5xx en $(cloudflare.http.host) en 5 min; origen caído o bajo carga.",
   "mitre": [
    "T1499"
   ],
   "groups": [
    "b89_http",
    "b89_availability"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101522": {
   "id": "101522",
   "level": 7,
   "description": "B89 Cloudflare: método HTTP anómalo $(cloudflare.http.method) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host).",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_http",
    "b89_web_probe"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101525": {
   "id": "101525",
   "level": 0,
   "description": "B89 Cloudflare: consulta DNS $(cloudflare.dns.query) tipo $(cloudflare.dns.query_type).",
   "mitre": [],
   "groups": [
    "b89_dns"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101526": {
   "id": "101526",
   "level": 8,
   "description": "B89 Cloudflare: intento de transferencia de zona ($(cloudflare.dns.query_type)) de $(cloudflare.dns.query) desde $(cloudflare.dns.client_ip).",
   "mitre": [
    "T1590.002"
   ],
   "groups": [
    "b89_dns",
    "b89_recon"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101527": {
   "id": "101527",
   "level": 0,
   "description": "B89 Cloudflare: NXDOMAIN para $(cloudflare.dns.query).",
   "mitre": [],
   "groups": [
    "b89_dns"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101528": {
   "id": "101528",
   "level": 8,
   "description": "B89 Cloudflare: 100+ NXDOMAIN desde $(cloudflare.dns.client_ip) en 2 min; enumeración de subdominios.",
   "mitre": [
    "T1590.002"
   ],
   "groups": [
    "b89_dns",
    "b89_recon"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101530": {
   "id": "101530",
   "level": 0,
   "description": "B89 Cloudflare: backoffice de pagos $(cloudflare.http.method) $(cloudflare.http.path) desde $(cloudflare.http.client_ip) ($(cloudflare.http.status)).",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_backoffice"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101531": {
   "id": "101531",
   "level": 12,
   "description": "B89 Cloudflare: credencial del backoffice de pagos usada desde hosting/VPN ($(cloudflare.http.asn_name), $(cloudflare.http.country)) IP $(cloudflare.http.client_ip): $(cloudflare.http.path) correcto el $(cloudflare.http.datetime) UTC. Posible credencial o token robado.",
   "mitre": [
    "T1078",
    "T1550.001"
   ],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_credential_misuse"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101532": {
   "id": "101532",
   "level": 13,
   "description": "B89 Cloudflare: exportación de datos del backoffice ($(cloudflare.http.path)) desde hosting/VPN en $(cloudflare.http.country), IP $(cloudflare.http.client_ip) ($(cloudflare.http.asn_name)) el $(cloudflare.http.datetime) UTC. Posible exfiltración.",
   "mitre": [
    "T1567",
    "T1213"
   ],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_exfiltration"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101533": {
   "id": "101533",
   "level": 2,
   "description": "B89 Cloudflare: login correcto al backoffice de pagos desde $(cloudflare.http.country) IP $(cloudflare.http.client_ip) ($(cloudflare.http.asn_name)) el $(cloudflare.http.datetime) UTC.",
   "mitre": [
    "T1078"
   ],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_credential_misuse"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101534": {
   "id": "101534",
   "level": 0,
   "description": "B89 Cloudflare: verificación previa del navegador ($(cloudflare.http.method)) al backoffice; no usa credenciales.",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_backoffice"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101536": {
   "id": "101536",
   "level": 3,
   "description": "B89 Cloudflare: backoffice de pruebas ($(cloudflare.http.host)) usado desde nube/VPN ($(cloudflare.http.asn_name)) IP $(cloudflare.http.client_ip). Habitual en QA/CI; sin alerta.",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_backoffice"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101537": {
   "id": "101537",
   "level": 13,
   "description": "B89 Cloudflare: cambio en el backoffice de pagos ($(cloudflare.http.method) $(cloudflare.http.path)) desde hosting/VPN ($(cloudflare.http.asn_name), $(cloudflare.http.country)) IP $(cloudflare.http.client_ip) el $(cloudflare.http.datetime) UTC. Posible movimiento de dinero con credencial robada.",
   "mitre": [
    "T1078",
    "T1565.001"
   ],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_credential_misuse"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101538": {
   "id": "101538",
   "level": 3,
   "description": "B89 Cloudflare: petición de backoffice desde hosting/VPN ($(cloudflare.http.asn_name)) IP $(cloudflare.http.client_ip): $(cloudflare.http.method) $(cloudflare.http.path). Señal; alerta si se sostiene (101545).",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_backoffice"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101539": {
   "id": "101539",
   "level": 8,
   "description": "Cloudflare bloqueó una solicitud con patrón de posible inyección web en $(cloudflare.firewall.host)$(cloudflare.firewall.path), desde $(cloudflare.firewall.client_ip). Firma: $(cloudflare.firewall.rule_description) (regla $(cloudflare.firewall.rule_id)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_injection",
    "b89_owasp_signal",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101540": {
   "id": "101540",
   "level": 12,
   "description": "Cloudflare detectó un patrón de posible inyección web y lo dejó en modo registro; la solicitud pudo llegar a la aplicación. Revisar ahora: $(cloudflare.firewall.host)$(cloudflare.firewall.path), origen $(cloudflare.firewall.client_ip). Firma: $(cloudflare.firewall.rule_description) (regla $(cloudflare.firewall.rule_id)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_injection",
    "b89_owasp_signal",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101541": {
   "id": "101541",
   "level": 8,
   "description": "Cloudflare detuvo una solicitud con firma de ataque web ($(cloudflare.firewall.waf_signature_categories)). No llegó a la aplicación según la acción registrada. Sitio: $(cloudflare.firewall.host)$(cloudflare.firewall.path); origen: $(cloudflare.firewall.client_ip).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_attack",
    "b89_owasp_signal",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101542": {
   "id": "101542",
   "level": 12,
   "description": "Cloudflare registró una firma de ataque web ($(cloudflare.firewall.waf_signature_categories)) sin bloquearla; la solicitud pudo llegar a la aplicación. Revisar ahora: $(cloudflare.firewall.host)$(cloudflare.firewall.path), origen $(cloudflare.firewall.client_ip).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_attack",
    "b89_owasp_signal",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101543": {
   "id": "101543",
   "level": 10,
   "description": "Cloudflare observó una firma de ataque web ($(cloudflare.firewall.waf_signature_categories)); la acción fue $(cloudflare.firewall.action). Confirma si la solicitud alcanzó la aplicación. Sitio: $(cloudflare.firewall.host)$(cloudflare.firewall.path); origen: $(cloudflare.firewall.client_ip).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_attack",
    "b89_owasp_signal",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101544": {
   "id": "101544",
   "level": 8,
   "description": "Cloudflare clasificó esta solicitud como ataque probable (puntuación WAF $(cloudflare.firewall.waf_attack_score), escala 1–99); revisa $(cloudflare.firewall.host)$(cloudflare.firewall.path), acción $(cloudflare.firewall.action), origen $(cloudflare.firewall.client_ip).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_waf",
    "b89_web_attack",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101545": {
   "id": "101545",
   "level": 12,
   "description": "B89 Cloudflare: sesión sostenida en el backoffice de pagos desde hosting/VPN ($(cloudflare.http.asn_name), $(cloudflare.http.country)) IP $(cloudflare.http.client_ip): 5+ registros en 30 min. Posible token de sesión robado.",
   "mitre": [
    "T1550.001",
    "T1078"
   ],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_credential_misuse"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml"
  },
  "101546": {
   "id": "101546",
   "level": 0,
   "description": "B89 Cloudflare: API de pagos, lista blanca: $(cloudflare.http.allowlist_verdict).",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_allowlist"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-004"
   ]
  },
  "101547": {
   "id": "101547",
   "level": 13,
   "description": "B89 Cloudflare: el cliente $(cloudflare.http.allowlist_client) llamó a la API de pagos desde una IP que no es suya ($(cloudflare.http.client_ip)): $(cloudflare.http.method) $(cloudflare.http.path).",
   "mitre": [
    "T1078"
   ],
   "groups": [
    "b89_http",
    "b89_allowlist",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-004"
   ]
  },
  "101548": {
   "id": "101548",
   "level": 12,
   "description": "B89 Cloudflare: login o pago en la API de pagos desde una IP fuera de la lista blanca ($(cloudflare.http.client_ip)): $(cloudflare.http.method) $(cloudflare.http.path).",
   "mitre": [
    "T1078"
   ],
   "groups": [
    "b89_http",
    "b89_allowlist",
    "b89_attack"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-004"
   ]
  },
  "101549": {
   "id": "101549",
   "level": 5,
   "description": "B89 Cloudflare: petición a la API de pagos desde una IP fuera de la lista blanca ($(cloudflare.http.client_ip)): $(cloudflare.http.method) $(cloudflare.http.path).",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_allowlist"
   ],
   "file": "wazuh/provider-ingestion/rules/b89_cloudflare_rules.xml",
   "useCases": [
    "B89-DET-CF-004"
   ]
  },
  "101600": {
   "id": "101600",
   "level": 0,
   "description": "B89 AWS: evento de EventBridge.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101601": {
   "id": "101601",
   "level": 3,
   "description": "B89 AWS: $(aws.event_name) en consola de $(aws.principal) desde $(aws.source_ip).",
   "mitre": [],
   "groups": [
    "b89_aws_signin",
    "authentication"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101602": {
   "id": "101602",
   "level": 3,
   "description": "B89 AWS: $(aws.event_name) ($(aws.event_source)) por $(aws.principal) en $(aws.region).",
   "mitre": [],
   "groups": [
    "b89_aws_api",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101603": {
   "id": "101603",
   "level": 3,
   "description": "B89 AWS: evento $(aws.detail_type) de $(aws.source).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101605": {
   "id": "101605",
   "level": 13,
   "description": "B89 AWS: inicio de sesión de la cuenta ROOT ($(aws.event_name)) desde $(aws.source_ip).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "b89_aws_root",
    "authentication_success"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101606": {
   "id": "101606",
   "level": 12,
   "description": "B89 AWS: la cuenta ROOT ejecutó $(aws.event_name) ($(aws.event_source)) desde $(aws.source_ip).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "b89_aws_root"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101607": {
   "id": "101607",
   "level": 5,
   "description": "B89 AWS: inicio de sesión fallido en consola de $(aws.principal) desde $(aws.source_ip).",
   "mitre": [
    "T1110"
   ],
   "groups": [
    "authentication_failed"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101608": {
   "id": "101608",
   "level": 10,
   "description": "B89 AWS: posible fuerza bruta en consola: 5+ inicios fallidos desde $(aws.source_ip) en 5 min.",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "authentication_failures",
    "b89_aws_bruteforce"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101609": {
   "id": "101609",
   "level": 8,
   "description": "B89 AWS: usuario IAM $(aws.principal) entró a la consola SIN MFA desde $(aws.source_ip).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "authentication_success",
    "b89_aws_no_mfa"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101610": {
   "id": "101610",
   "level": 3,
   "description": "B89 AWS: inicio de sesión en consola de $(aws.principal) desde $(aws.source_ip).",
   "mitre": [],
   "groups": [
    "authentication_success"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101611": {
   "id": "101611",
   "level": 10,
   "description": "B89 AWS: actividad en región no habitual $(aws.region): $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1535"
   ],
   "groups": [
    "b89_aws_unusual_region"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101612": {
   "id": "101612",
   "level": 12,
   "description": "B89 AWS: creación de cómputo/red en región no habitual $(aws.region): $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1535",
    "T1496"
   ],
   "groups": [
    "b89_aws_unusual_region"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101613": {
   "id": "101613",
   "level": 4,
   "description": "B89 AWS: servicio AWS ($(aws.principal)) activo en región no habitual $(aws.region): $(aws.event_name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101615": {
   "id": "101615",
   "level": 12,
   "description": "B89 AWS: manipulación del pipeline de monitoreo B89: $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "b89_aws_tamper",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101616": {
   "id": "101616",
   "level": 6,
   "description": "B89 AWS: cambio en el pipeline de monitoreo B89: $(aws.event_name) por $(aws.principal).",
   "mitre": [],
   "groups": [
    "b89_aws_pipeline",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101620": {
   "id": "101620",
   "level": 13,
   "description": "B89 AWS: CloudTrail detenido/eliminado ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "b89_aws_defense_disabled",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml",
   "runbooks": [
    "cloudtrail-y-auditoria"
   ]
  },
  "101621": {
   "id": "101621",
   "level": 10,
   "description": "B89 AWS: configuración de CloudTrail modificada ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "b89_aws_defense_change",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml",
   "runbooks": [
    "cloudtrail-y-auditoria"
   ]
  },
  "101622": {
   "id": "101622",
   "level": 12,
   "description": "B89 AWS: GuardDuty deshabilitado o con supresión ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_aws_defense_disabled",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101623": {
   "id": "101623",
   "level": 12,
   "description": "B89 AWS: Security Hub deshabilitado/reducido ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_aws_defense_disabled",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101624": {
   "id": "101624",
   "level": 12,
   "description": "B89 AWS: AWS Config detenido/eliminado ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_aws_defense_disabled",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101625": {
   "id": "101625",
   "level": 10,
   "description": "B89 AWS: IAM Access Analyzer eliminado o con archivado ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_aws_defense_change",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101630": {
   "id": "101630",
   "level": 8,
   "description": "B89 AWS: cambio IAM $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "b89_aws_iam",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101631": {
   "id": "101631",
   "level": 10,
   "description": "B89 AWS: cambio IAM de alto riesgo $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1098",
    "T1136.003"
   ],
   "groups": [
    "b89_aws_iam",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101632": {
   "id": "101632",
   "level": 12,
   "description": "B89 AWS: privilegios administrativos concedidos ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "b89_aws_iam",
    "b89_privilege_escalation"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101633": {
   "id": "101633",
   "level": 8,
   "description": "B89 AWS: cambio en IAM Identity Center $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "b89_aws_iam",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101634": {
   "id": "101634",
   "level": 10,
   "description": "B89 AWS: Identity Center: permission set o asignación modificada ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "b89_aws_iam",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101635": {
   "id": "101635",
   "level": 10,
   "description": "B89 AWS: cambio en AWS Organizations $(aws.event_name) por $(aws.principal).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_aws_org",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101636": {
   "id": "101636",
   "level": 12,
   "description": "B89 AWS: Organizations: salida de cuenta o SCP retirada ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1484",
    "T1562"
   ],
   "groups": [
    "b89_aws_org",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101640": {
   "id": "101640",
   "level": 8,
   "description": "B89 AWS: security group modificado ($(aws.event_name)) por $(aws.principal) en $(aws.region).",
   "mitre": [
    "T1562.007"
   ],
   "groups": [
    "b89_aws_network",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101641": {
   "id": "101641",
   "level": 10,
   "description": "B89 AWS: security group abierto a Internet (0.0.0.0/0 o ::/0) por $(aws.principal).",
   "mitre": [
    "T1562.007"
   ],
   "groups": [
    "b89_aws_network",
    "b89_exposure"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101642": {
   "id": "101642",
   "level": 8,
   "description": "B89 AWS: NACL modificada ($(aws.event_name)) por $(aws.principal) en $(aws.region).",
   "mitre": [
    "T1562.007"
   ],
   "groups": [
    "b89_aws_network",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101643": {
   "id": "101643",
   "level": 8,
   "description": "B89 AWS: rutas/gateways modificados ($(aws.event_name)) por $(aws.principal) en $(aws.region).",
   "mitre": [
    "T1599"
   ],
   "groups": [
    "b89_aws_network",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101644": {
   "id": "101644",
   "level": 10,
   "description": "B89 AWS: VPC Flow Logs eliminados por $(aws.principal) en $(aws.region).",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "b89_aws_network",
    "b89_defense_evasion"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101645": {
   "id": "101645",
   "level": 10,
   "description": "B89 AWS: snapshot/AMI compartido ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1537"
   ],
   "groups": [
    "b89_aws_exfiltration"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101646": {
   "id": "101646",
   "level": 3,
   "description": "B89 AWS: EC2 $(aws.event_name) por $(aws.principal) en $(aws.region).",
   "mitre": [],
   "groups": [
    "b89_aws_ec2"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101650": {
   "id": "101650",
   "level": 8,
   "description": "B89 AWS: control de acceso S3 modificado ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "b89_aws_s3",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101651": {
   "id": "101651",
   "level": 10,
   "description": "B89 AWS: bloqueo de acceso público S3 eliminado ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "b89_aws_s3",
    "b89_exposure"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101652": {
   "id": "101652",
   "level": 10,
   "description": "B89 AWS: posible exposición pública de S3 ($(aws.event_name)) por $(aws.principal).",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "b89_aws_s3",
    "b89_exposure"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101655": {
   "id": "101655",
   "level": 8,
   "description": "B89 AWS: política/rotación KMS modificada ($(aws.event_name)) por $(aws.principal).",
   "mitre": [],
   "groups": [
    "b89_aws_kms",
    "b89_audit"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101656": {
   "id": "101656",
   "level": 10,
   "description": "B89 AWS: clave KMS deshabilitada por $(aws.principal).",
   "mitre": [
    "T1485"
   ],
   "groups": [
    "b89_aws_kms",
    "b89_impact"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101657": {
   "id": "101657",
   "level": 12,
   "description": "B89 AWS: borrado de clave KMS programado por $(aws.principal).",
   "mitre": [
    "T1485"
   ],
   "groups": [
    "b89_aws_kms",
    "b89_impact"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101660": {
   "id": "101660",
   "level": 3,
   "description": "B89 AWS GuardDuty: $(aws.finding.type) ($(aws.finding.severity_label)).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "guardduty"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101661": {
   "id": "101661",
   "level": 5,
   "description": "B89 AWS GuardDuty (baja): $(aws.finding.type).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "guardduty"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101662": {
   "id": "101662",
   "level": 8,
   "description": "B89 AWS GuardDuty (media): $(aws.finding.type).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "guardduty"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101663": {
   "id": "101663",
   "level": 12,
   "description": "B89 AWS GuardDuty (alta): $(aws.finding.type).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "guardduty"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101664": {
   "id": "101664",
   "level": 13,
   "description": "B89 AWS GuardDuty (crítica): $(aws.finding.type).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "guardduty"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101670": {
   "id": "101670",
   "level": 3,
   "description": "B89 AWS Security Hub: $(aws.finding.title) ($(aws.finding.severity_label)).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "securityhub"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101671": {
   "id": "101671",
   "level": 8,
   "description": "B89 AWS Security Hub (media): $(aws.finding.title).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "securityhub"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101672": {
   "id": "101672",
   "level": 12,
   "description": "B89 AWS Security Hub (alta): $(aws.finding.title).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "securityhub"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101673": {
   "id": "101673",
   "level": 13,
   "description": "B89 AWS Security Hub (crítica): $(aws.finding.title).",
   "mitre": [],
   "groups": [
    "b89_aws_finding",
    "securityhub"
   ],
   "file": "wazuh/aws-events/rules/b89_aws_rules.xml"
  },
  "101700": {
   "id": "101700",
   "level": 15,
   "description": "B89 M365: $(office365.UserId) concedió un rol privilegiado de Entra después de entrar tras fuerza bruta (cadena de compromiso).",
   "mitre": [
    "T1098.003",
    "T1078.004"
   ],
   "groups": [
    "azure_ad",
    "b89_privilege_escalation",
    "b89_attack_chain"
   ],
   "file": "detections/m365/compromise-chain/rule.xml",
   "useCases": [
    "B89-DET-M365-005"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101701": {
   "id": "101701",
   "level": 14,
   "description": "B89 M365: $(office365.UserId) cambió sus métodos de autenticación después de entrar tras fuerza bruta (persistencia en MFA).",
   "mitre": [
    "T1556.006",
    "T1098.005"
   ],
   "groups": [
    "azure_ad",
    "b89_persistence",
    "b89_attack_chain"
   ],
   "file": "detections/m365/compromise-chain/rule.xml",
   "useCases": [
    "B89-DET-M365-005"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101702": {
   "id": "101702",
   "level": 14,
   "description": "B89 M365: $(office365.UserId) creó reenvío u ocultación de correo después de entrar tras fuerza bruta (patrón BEC).",
   "mitre": [
    "T1114.003",
    "T1564.008"
   ],
   "groups": [
    "exchange",
    "b89_persistence",
    "b89_attack_chain"
   ],
   "file": "detections/m365/compromise-chain/rule.xml",
   "useCases": [
    "B89-DET-M365-005"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101703": {
   "id": "101703",
   "level": 13,
   "description": "B89 M365: inicio de sesión exitoso de $(office365.UserId) desde $(office365.ClientIP), origen de un password spray en la última hora.",
   "mitre": [
    "T1110.003",
    "T1078.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_attack_chain"
   ],
   "file": "detections/m365/compromise-chain/rule.xml",
   "useCases": [
    "B89-DET-M365-005"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101704": {
   "id": "101704",
   "level": 14,
   "description": "B89 Entra: $(office365.UserId) asignó un rol tier 0 (Global, Privileged Role o Privileged Authentication Administrator) a $(office365.ObjectId).",
   "mitre": [
    "T1098.003"
   ],
   "groups": [
    "azure_ad",
    "b89_privilege_escalation",
    "b89_tier0",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/entra/privileged-role-assignment/rule.xml",
   "useCases": [
    "B89-DET-ENTRA-001"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101710": {
   "id": "101710",
   "level": 15,
   "description": "B89 AWS: $(aws.principal) detuvo o borró CloudTrail ($(aws.event_name)) después de cambiar IAM en la última hora (escalada y borrado de rastro).",
   "mitre": [
    "T1562.008",
    "T1098.003"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/aws/cloudtrail-tampering/rule.xml",
   "useCases": [
    "B89-DET-AWS-001"
   ],
   "runbooks": [
    "cloudtrail-y-auditoria",
    "escalada-de-privilegios"
   ]
  },
  "101711": {
   "id": "101711",
   "level": 15,
   "description": "B89 AWS: la cuenta ROOT detuvo o borró CloudTrail ($(aws.event_name)) desde $(aws.source_ip).",
   "mitre": [
    "T1562.008",
    "T1078.004"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/aws/cloudtrail-tampering/rule.xml",
   "useCases": [
    "B89-DET-AWS-001"
   ],
   "runbooks": [
    "cloudtrail-y-auditoria",
    "escalada-de-privilegios"
   ]
  },
  "101712": {
   "id": "101712",
   "level": 15,
   "description": "B89 AWS: $(aws.principal) deshabilitó varios controles de detección en una hora (último: $(aws.event_name) en $(aws.event_source)).",
   "mitre": [
    "T1562.001",
    "T1562.008"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/aws/cloudtrail-tampering/rule.xml",
   "useCases": [
    "B89-DET-AWS-001"
   ],
   "runbooks": [
    "cloudtrail-y-auditoria",
    "escalada-de-privilegios"
   ]
  },
  "101713": {
   "id": "101713",
   "level": 13,
   "description": "B89 AWS: inicio de sesión exitoso en consola de $(aws.principal) desde $(aws.source_ip) tras fuerza bruta desde la misma IP (30 min).",
   "mitre": [
    "T1110.001",
    "T1078.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_attack_chain"
   ],
   "file": "detections/aws/console-bruteforce-success/rule.xml",
   "useCases": [
    "B89-DET-AWS-002"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101714": {
   "id": "101714",
   "level": 3,
   "description": "B89 AWS: cambio en el pipeline de monitoreo B89 por principal de confianza $(aws.principal) ($(aws.event_name)).",
   "mitre": [],
   "groups": [
    "b89_aws_api",
    "b89_audit",
    "b89_trusted_principal"
   ],
   "file": "detections/aws/trusted-principals/rule.xml",
   "useCases": [
    "B89-TUNE-AWS-001"
   ]
  },
  "101715": {
   "id": "101715",
   "level": 9,
   "description": "B89 AWS: principal de confianza $(aws.principal) modificó de forma destructiva el pipeline de monitoreo ($(aws.event_name)); confirmar el cambio.",
   "mitre": [
    "T1562.008"
   ],
   "groups": [
    "b89_audit",
    "b89_trusted_principal"
   ],
   "file": "detections/aws/trusted-principals/rule.xml",
   "useCases": [
    "B89-TUNE-AWS-001"
   ]
  },
  "101716": {
   "id": "101716",
   "level": 5,
   "description": "B89 AWS: security group modificado ($(aws.event_name)) por principal de confianza $(aws.principal) en $(aws.region).",
   "mitre": [],
   "groups": [
    "b89_aws_network",
    "b89_audit",
    "b89_trusted_principal"
   ],
   "file": "detections/aws/trusted-principals/rule.xml",
   "useCases": [
    "B89-TUNE-AWS-001"
   ]
  },
  "101720": {
   "id": "101720",
   "level": 14,
   "description": "B89 Bitdefender: malware en $(bitdefender.endpoint.name), que tuvo la protección deshabilitada en las últimas 24 h.",
   "mitre": [
    "T1204",
    "T1562.001"
   ],
   "groups": [
    "b89_malware",
    "b89_attack_chain"
   ],
   "file": "detections/bitdefender/protection-disabled-malware/rule.xml",
   "useCases": [
    "B89-DET-BD-002"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101721": {
   "id": "101721",
   "level": 14,
   "description": "B89 Bitdefender: protección deshabilitada en $(bitdefender.endpoint.name) después de una detección de malware en 24 h (posible evasión).",
   "mitre": [
    "T1562.001"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/bitdefender/protection-disabled-malware/rule.xml",
   "useCases": [
    "B89-DET-BD-002"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101722": {
   "id": "101722",
   "level": 15,
   "description": "B89 Bitdefender: malware en $(bitdefender.endpoint.name) con el antimalware deshabilitado en el mismo estado.",
   "mitre": [
    "T1204",
    "T1562.001"
   ],
   "groups": [
    "b89_malware",
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/bitdefender/protection-disabled-malware/rule.xml",
   "useCases": [
    "B89-DET-BD-002"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101723": {
   "id": "101723",
   "level": 14,
   "description": "B89 Bitdefender: malware en $(bitdefender.endpoint.name) con Advanced Threat Control deshabilitado en el mismo estado.",
   "mitre": [
    "T1204",
    "T1562.001"
   ],
   "groups": [
    "b89_malware",
    "b89_defense_evasion",
    "b89_attack_chain"
   ],
   "file": "detections/bitdefender/protection-disabled-malware/rule.xml",
   "useCases": [
    "B89-DET-BD-002"
   ],
   "runbooks": [
    "malware-edr"
   ]
  },
  "101730": {
   "id": "101730",
   "level": 14,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA con exploit maduro en $(snyk.project.name), expuesto a Internet por Cloudflare: $(snyk.issue.title).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_exposure"
   ],
   "file": "detections/snyk/exposed-critical-exploit/rule.xml",
   "useCases": [
    "B89-DET-SNYK-002"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101731": {
   "id": "101731",
   "level": 12,
   "description": "B89 Snyk: vulnerabilidad ALTA con exploit maduro en $(snyk.project.name), expuesto a Internet por Cloudflare: $(snyk.issue.title).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_exposure"
   ],
   "file": "detections/snyk/exposed-critical-exploit/rule.xml",
   "useCases": [
    "B89-DET-SNYK-002"
   ],
   "runbooks": [
    "vulnerabilidad-expuesta"
   ]
  },
  "101732": {
   "id": "101732",
   "level": 2,
   "description": "B89 Snyk: vulnerabilidad baja sin exploit maduro $(snyk.issue.title) en $(snyk.project.name) (backlog de AppSec).",
   "mitre": [],
   "groups": [],
   "file": "detections/snyk/severity-calibration/rule.xml",
   "useCases": [
    "B89-TUNE-SNYK-001"
   ]
  },
  "101733": {
   "id": "101733",
   "level": 7,
   "description": "B89 Snyk: vulnerabilidad ALTA sin exposición ni exploit maduro $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "detections/snyk/severity-calibration/rule.xml",
   "useCases": [
    "B89-TUNE-SNYK-001"
   ]
  },
  "101734": {
   "id": "101734",
   "level": 10,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA sin exposición ni exploit maduro $(snyk.issue.title) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "detections/snyk/severity-calibration/rule.xml",
   "useCases": [
    "B89-TUNE-SNYK-001"
   ]
  },
  "101740": {
   "id": "101740",
   "level": 12,
   "description": "B89 Cloudflare: oleada distribuida contra $(cloudflare.firewall.host): 50+ bloqueos o desafíos desde IPs distintas en 10 min.",
   "mitre": [
    "T1595.002",
    "T1190"
   ],
   "groups": [
    "b89_attack"
   ],
   "file": "detections/cloudflare/waf-attack-surge/rule.xml",
   "useCases": [
    "B89-DET-CF-002"
   ],
   "runbooks": [
    "oleada-waf"
   ]
  },
  "101741": {
   "id": "101741",
   "level": 11,
   "description": "B89 Cloudflare: ataque sostenido de $(cloudflare.firewall.client_ip) contra la zona crítica $(cloudflare.zone_name).",
   "mitre": [
    "T1190",
    "T1595"
   ],
   "groups": [
    "b89_waf",
    "b89_attack"
   ],
   "file": "detections/cloudflare/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-CF-001"
   ]
  },
  "101742": {
   "id": "101742",
   "level": 7,
   "description": "B89 Cloudflare: 20+ bloqueos de $(cloudflare.firewall.client_ip) en la zona no crítica $(cloudflare.zone_name); el WAF contuvo el ataque.",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_waf"
   ],
   "file": "detections/cloudflare/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-CF-001"
   ]
  },
  "101743": {
   "id": "101743",
   "level": 2,
   "description": "B89 Cloudflare: bloqueo a escáner autorizado $(cloudflare.firewall.client_ip) en $(cloudflare.firewall.host).",
   "mitre": [],
   "groups": [
    "b89_waf"
   ],
   "file": "detections/cloudflare/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-CF-001"
   ]
  },
  "101744": {
   "id": "101744",
   "level": 3,
   "description": "B89 Cloudflare: cambio DNS ($(cloudflare.audit.action)) en $(cloudflare.audit.zone_name) por la automatización aprobada $(cloudflare.audit.actor_email).",
   "mitre": [],
   "groups": [
    "b89_audit",
    "b89_dns_change",
    "b89_trusted_principal"
   ],
   "file": "detections/cloudflare/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-CF-001"
   ]
  },
  "101745": {
   "id": "101745",
   "level": 3,
   "description": "B89 Cloudflare: backoffice de pagos usado desde la salida corporativa conocida $(cloudflare.http.client_ip) ($(cloudflare.http.asn_name)): $(cloudflare.http.method) $(cloudflare.http.path).",
   "mitre": [],
   "groups": [
    "b89_http",
    "b89_backoffice",
    "b89_trusted_principal"
   ],
   "file": "detections/cloudflare/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-CF-001"
   ]
  },
  "101750": {
   "id": "101750",
   "level": 13,
   "description": "B89 Linux: acceso SSH exitoso de $(dstuser) desde $(srcip) tras fuerza bruta desde la misma IP en 30 min.",
   "mitre": [
    "T1110.001",
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_attack_chain"
   ],
   "file": "detections/linux/ssh-bruteforce-success/rule.xml",
   "useCases": [
    "B89-DET-LNX-001"
   ],
   "runbooks": [
    "credenciales"
   ]
  },
  "101752": {
   "id": "101752",
   "level": 10,
   "description": "B89 Linux: $(srcuser) agregó a $(dstuser) al grupo privilegiado $(group).",
   "mitre": [
    "T1098.007",
    "T1548"
   ],
   "groups": [
    "b89_privilege_escalation"
   ],
   "file": "detections/linux/privileged-group-membership/rule.xml",
   "useCases": [
    "B89-DET-LNX-002"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101755": {
   "id": "101755",
   "level": 12,
   "description": "B89 Linux: llaves SSH autorizadas creadas o modificadas en $(file).",
   "mitre": [
    "T1098.004"
   ],
   "groups": [
    "b89_persistence"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101756": {
   "id": "101756",
   "level": 10,
   "description": "B89 Linux: unidad systemd creada o modificada en $(file).",
   "mitre": [
    "T1543.002",
    "T1053.006"
   ],
   "groups": [
    "b89_persistence"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101757": {
   "id": "101757",
   "level": 10,
   "description": "B89 Linux: tarea cron creada o modificada en $(file).",
   "mitre": [
    "T1053.003"
   ],
   "groups": [
    "b89_persistence"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101758": {
   "id": "101758",
   "level": 12,
   "description": "B89 Linux: configuración de sudo creada o modificada en $(file).",
   "mitre": [
    "T1548.003"
   ],
   "groups": [
    "b89_privilege_escalation"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101759": {
   "id": "101759",
   "level": 12,
   "description": "B89 Linux: pila PAM creada o modificada en $(file).",
   "mitre": [
    "T1556.003"
   ],
   "groups": [
    "b89_persistence",
    "b89_credential_access"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101760": {
   "id": "101760",
   "level": 10,
   "description": "B89 Linux: configuración del servidor SSH modificada en $(file).",
   "mitre": [
    "T1556",
    "T1021.004"
   ],
   "groups": [
    "b89_defense_evasion"
   ],
   "file": "detections/linux/persistence-fim/rule.xml",
   "useCases": [
    "B89-DET-LNX-003"
   ],
   "runbooks": [
    "escalada-de-privilegios"
   ]
  },
  "101761": {
   "id": "101761",
   "level": 8,
   "description": "B89 Linux: acceso SSH exitoso de $(dstuser) desde $(srcip), IP no registrada como administrativa.",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_initial_access"
   ],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101762": {
   "id": "101762",
   "level": 11,
   "description": "B89 Linux: acceso SSH de $(dstuser) desde IP no registrada $(srcip) fuera del horario del SOC.",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_off_hours"
   ],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101763": {
   "id": "101763",
   "level": 11,
   "description": "B89 Linux: acceso SSH de $(dstuser) desde IP no registrada $(srcip) en fin de semana.",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_off_hours"
   ],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101765": {
   "id": "101765",
   "level": 0,
   "description": "B89 Linux: anomalía de rootcheck en capa overlay de contenedores (falso positivo conocido de 521).",
   "mitre": [],
   "groups": [
    "rootcheck"
   ],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101766": {
   "id": "101766",
   "level": 0,
   "description": "B89 Linux: sesión PAM de cuenta administrativa ($(srcuser) a $(dstuser)); ya auditada por sudo/SSH.",
   "mitre": [],
   "groups": [],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101767": {
   "id": "101767",
   "level": 0,
   "description": "B89 Linux: cierre de sesión PAM de cuenta administrativa $(dstuser).",
   "mitre": [],
   "groups": [],
   "file": "detections/linux/noise-tuning/rule.xml",
   "useCases": [
    "B89-TUNE-LNX-001"
   ]
  },
  "101800": {
   "id": "101800",
   "level": 7,
   "description": "B89 Linux: cambiaron los puertos en escucha del host (se abrió o se cerró uno).",
   "mitre": [
    "T1571"
   ],
   "groups": [
    "b89_listening_ports"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101801": {
   "id": "101801",
   "level": 0,
   "description": "B89 Linux: evento de red del host ($(b89.net.type) $(b89.net.direction)).",
   "mitre": [],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101802": {
   "id": "101802",
   "level": 0,
   "description": "B89 Linux: nueva escucha solo en loopback ($(dstip):$(dstport), $(b89.net.process)).",
   "mitre": [],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101803": {
   "id": "101803",
   "level": 12,
   "description": "B89 Linux: shell, netcat o intérprete $(b89.net.process) escucha en $(dstip):$(dstport)/$(protocol) (posible bind shell o túnel).",
   "mitre": [
    "T1059.004",
    "T1571"
   ],
   "groups": [
    "b89_netconn",
    "b89_attack"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101804": {
   "id": "101804",
   "level": 0,
   "description": "B89 Linux: escucha esperada $(dstip):$(dstport)/$(protocol) ($(b89.net.process)).",
   "mitre": [],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101805": {
   "id": "101805",
   "level": 8,
   "description": "B89 Linux: nuevo puerto en escucha no esperado $(dstip):$(dstport)/$(protocol) de $(b89.net.process) (uid $(b89.net.uid)).",
   "mitre": [
    "T1571"
   ],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101806": {
   "id": "101806",
   "level": 0,
   "description": "B89 Linux: conexión TCP interna $(b89.net.direction) $(srcip) → $(dstip):$(dstport) ($(b89.net.process)).",
   "mitre": [],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101807": {
   "id": "101807",
   "level": 10,
   "description": "B89 Linux: $(b89.net.process) abrió conexión saliente a $(dstip):$(dstport) (uid $(b89.net.uid)); patrón de reverse shell.",
   "mitre": [
    "T1059.004",
    "T1071"
   ],
   "groups": [
    "b89_netconn",
    "b89_attack"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101808": {
   "id": "101808",
   "level": 5,
   "description": "B89 Linux: conexión saliente a destino poco común $(dstip):$(dstport) desde $(b89.net.process) (uid $(b89.net.uid)).",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_netconn",
    "b89_rare_destination"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101809": {
   "id": "101809",
   "level": 3,
   "description": "B89 Linux: conexión entrante desde $(srcip) al puerto $(dstport) ($(b89.net.process)).",
   "mitre": [
    "T1133"
   ],
   "groups": [
    "b89_netconn"
   ],
   "file": "detections/linux/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-001"
   ]
  },
  "101810": {
   "id": "101810",
   "level": 0,
   "description": "B89 Linux: llamada de red auditada ($(audit.key)) de $(audit.exe).",
   "mitre": [],
   "groups": [
    "b89_audit_net"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101811": {
   "id": "101811",
   "level": 1,
   "description": "B89 Linux: llamada de red de sesión interactiva a destino interno $(dstip):$(dstport) ($(audit.exe)).",
   "mitre": [],
   "groups": [
    "b89_audit_net"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101812": {
   "id": "101812",
   "level": 12,
   "description": "B89 Linux: $(audit.exe) de una sesión interactiva (auid $(audit.auid)) abrió o aceptó una escucha de red (posible bind shell).",
   "mitre": [
    "T1059.004",
    "T1571"
   ],
   "groups": [
    "b89_audit_net",
    "b89_attack"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101813": {
   "id": "101813",
   "level": 10,
   "description": "B89 Linux: ejecución de herramienta de red o captura $(audit.exe) por auid $(audit.auid) (uid $(audit.uid)).",
   "mitre": [
    "T1046",
    "T1040"
   ],
   "groups": [
    "b89_audit_net"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101814": {
   "id": "101814",
   "level": 12,
   "description": "B89 Linux: $(audit.exe) (auid $(audit.auid)) se conectó a $(dstip):$(dstport); patrón de reverse shell.",
   "mitre": [
    "T1059.004",
    "T1071"
   ],
   "groups": [
    "b89_audit_net",
    "b89_attack"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101815": {
   "id": "101815",
   "level": 10,
   "description": "B89 Linux: escáner de red $(audit.exe) (auid $(audit.auid)) conectando a $(dstip):$(dstport).",
   "mitre": [
    "T1046"
   ],
   "groups": [
    "b89_audit_net",
    "b89_attack"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101816": {
   "id": "101816",
   "level": 10,
   "description": "B89 Linux: la cuenta de servicio web (uid $(audit.uid), $(audit.exe)) abrió conexión a $(dstip):$(dstport) (posible webshell o C2).",
   "mitre": [
    "T1505.003",
    "T1071"
   ],
   "groups": [
    "b89_audit_net",
    "b89_attack"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101817": {
   "id": "101817",
   "level": 3,
   "description": "B89 Linux: $(audit.exe) de una sesión interactiva (auid $(audit.auid)) se conectó a $(dstip):$(dstport).",
   "mitre": [],
   "groups": [
    "b89_audit_net"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101818": {
   "id": "101818",
   "level": 5,
   "description": "B89 Linux: proceso de sesión interactiva $(audit.exe) (auid $(audit.auid)) abrió o aceptó una escucha de red en $(dstip):$(dstport).",
   "mitre": [
    "T1571"
   ],
   "groups": [
    "b89_audit_net"
   ],
   "file": "detections/linux/network-auditd/rule.xml",
   "useCases": [
    "B89-DET-NET-002"
   ]
  },
  "101820": {
   "id": "101820",
   "level": 10,
   "description": "B89 Linux: la cuenta $(dstuser) inició sesión SSH desde 3 o más IPs no administrativas distintas en 1 h (última: $(srcip)).",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_ssh_session"
   ],
   "file": "detections/linux/ssh-session-tracking/rule.xml",
   "useCases": [
    "B89-DET-NET-003"
   ]
  },
  "101821": {
   "id": "101821",
   "level": 12,
   "description": "B89 Linux: inicio de sesión SSH directo como root desde $(srcip) (la política B89 exige cuenta nominal + sudo).",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_ssh_session"
   ],
   "file": "detections/linux/ssh-session-tracking/rule.xml",
   "useCases": [
    "B89-DET-NET-003"
   ]
  },
  "101830": {
   "id": "101830",
   "level": 0,
   "description": "B89 Edge: $(method) $(url) → $(http_status) desde $(srcip).",
   "mitre": [],
   "groups": [],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101831": {
   "id": "101831",
   "level": 8,
   "description": "B89 Edge: intento de inyección SQL contra la consola del SOC desde $(srcip): $(url).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_edge_attack",
    "attack",
    "sql_injection"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101832": {
   "id": "101832",
   "level": 8,
   "description": "B89 Edge: intento de XSS contra la consola del SOC desde $(srcip): $(url).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_edge_attack",
    "attack"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101833": {
   "id": "101833",
   "level": 8,
   "description": "B89 Edge: path traversal / lectura de archivos locales contra la consola del SOC desde $(srcip): $(url).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_edge_attack",
    "attack"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101834": {
   "id": "101834",
   "level": 10,
   "description": "B89 Edge: intento de ejecución remota de comandos (RCE/inyección/Log4Shell) desde $(srcip): $(url).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_edge_attack",
    "attack"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101835": {
   "id": "101835",
   "level": 6,
   "description": "B89 Edge: escáner de vulnerabilidades ($(user_agent)) contra la consola del SOC desde $(srcip).",
   "mitre": [
    "T1595.002"
   ],
   "groups": [
    "b89_edge_attack",
    "recon"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101836": {
   "id": "101836",
   "level": 5,
   "description": "B89 Edge: sondeo de rutas sensibles o de tecnologías ajenas a la consola del SOC desde $(srcip): $(url) → $(http_status).",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_edge_attack",
    "recon"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101837": {
   "id": "101837",
   "level": 10,
   "description": "B89 Edge: campaña de ataque/escaneo contra la consola del SOC: 10+ peticiones maliciosas desde $(srcip) en 5 min.",
   "mitre": [
    "T1595",
    "T1190"
   ],
   "groups": [
    "b89_edge_campaign",
    "attack"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101838": {
   "id": "101838",
   "level": 1,
   "description": "B89 Edge: respuesta $(http_status) a $(srcip) para $(url).",
   "mitre": [],
   "groups": [
    "b89_edge_4xx"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101839": {
   "id": "101839",
   "level": 1,
   "description": "B89 Edge: error $(http_status) del backend para $(url).",
   "mitre": [],
   "groups": [
    "b89_edge_5xx"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101840": {
   "id": "101840",
   "level": 7,
   "description": "B89 Edge: pico de respuestas 4xx para $(srcip): 40+ en 2 min (enumeración o cliente roto).",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_edge_spike"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101841": {
   "id": "101841",
   "level": 9,
   "description": "B89 Edge: pico de errores 5xx en la consola del SOC: 30+ en 2 min (caída de un backend o denegación de servicio).",
   "mitre": [
    "T1499"
   ],
   "groups": [
    "b89_edge_spike",
    "service_availability"
   ],
   "file": "detections/edge/http-attacks/rule.xml",
   "useCases": [
    "B89-DET-NET-005"
   ]
  },
  "101842": {
   "id": "101842",
   "level": 5,
   "description": "B89 Edge: inicio de sesión fallido en la consola del SOC desde $(srcip).",
   "mitre": [
    "T1110"
   ],
   "groups": [
    "b89_edge_auth_failure"
   ],
   "file": "detections/edge/soc-authentication/rule.xml",
   "useCases": [
    "B89-DET-NET-006"
   ]
  },
  "101843": {
   "id": "101843",
   "level": 3,
   "description": "B89 Edge: inicio de sesión exitoso en la consola del SOC desde $(srcip).",
   "mitre": [],
   "groups": [
    "authentication_success",
    "b89_edge_auth_success"
   ],
   "file": "detections/edge/soc-authentication/rule.xml",
   "useCases": [
    "B89-DET-NET-006"
   ]
  },
  "101844": {
   "id": "101844",
   "level": 10,
   "description": "B89 Edge: fuerza bruta contra el login de la consola del SOC: 6+ fallos desde $(srcip) en 5 min.",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "b89_edge_auth_failure",
    "b89_attack"
   ],
   "file": "detections/edge/soc-authentication/rule.xml",
   "useCases": [
    "B89-DET-NET-006"
   ]
  },
  "101845": {
   "id": "101845",
   "level": 13,
   "description": "B89 Edge: inicio de sesión exitoso en la consola del SOC desde $(srcip) tras fuerza bruta desde la misma IP.",
   "mitre": [
    "T1110.001",
    "T1078"
   ],
   "groups": [
    "b89_attack_chain",
    "b89_attack"
   ],
   "file": "detections/edge/soc-authentication/rule.xml",
   "useCases": [
    "B89-DET-NET-006"
   ]
  },
  "101846": {
   "id": "101846",
   "level": 9,
   "description": "B89 Edge: 20+ inicios de sesión fallidos en la consola del SOC desde IPs distintas en 10 min (password spraying distribuido).",
   "mitre": [
    "T1110.003"
   ],
   "groups": [
    "b89_edge_auth_failure",
    "b89_attack"
   ],
   "file": "detections/edge/soc-authentication/rule.xml",
   "useCases": [
    "B89-DET-NET-006"
   ]
  },
  "101850": {
   "id": "101850",
   "level": 10,
   "description": "B89 Linux: shell interactiva abierta dentro del contenedor crítico del SOC $(docker.Actor.Attributes.name).",
   "mitre": [
    "T1609"
   ],
   "groups": [
    "b89_container"
   ],
   "file": "detections/linux/docker-runtime/rule.xml",
   "useCases": [
    "B89-DET-NET-004"
   ]
  },
  "101851": {
   "id": "101851",
   "level": 6,
   "description": "B89 Linux: comando ejecutado dentro del contenedor crítico del SOC $(docker.Actor.Attributes.name): $(docker.Action).",
   "mitre": [
    "T1609"
   ],
   "groups": [
    "b89_container"
   ],
   "file": "detections/linux/docker-runtime/rule.xml",
   "useCases": [
    "B89-DET-NET-004"
   ]
  },
  "101852": {
   "id": "101852",
   "level": 8,
   "description": "B89 Linux: se creó un contenedor de propósito general o de herramientas ($(docker.Actor.Attributes.image)) en el nodo del SOC: $(docker.Actor.Attributes.name).",
   "mitre": [
    "T1610"
   ],
   "groups": [
    "b89_container"
   ],
   "file": "detections/linux/docker-runtime/rule.xml",
   "useCases": [
    "B89-DET-NET-004"
   ]
  },
  "101860": {
   "id": "101860",
   "level": 12,
   "description": "B89 Red: inicio de sesión exitoso desde $(srcip), IP en listas de reputación (Spamhaus DROP / abuse.ch).",
   "mitre": [
    "T1078"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101861": {
   "id": "101861",
   "level": 12,
   "description": "B89 Red: inicio de sesión exitoso desde $(srcip), nodo de salida de Tor.",
   "mitre": [
    "T1090.003",
    "T1078"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101862": {
   "id": "101862",
   "level": 8,
   "description": "B89 Red: petición a la consola del SOC desde $(srcip), IP en listas de reputación: $(method) $(url) → $(http_status).",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101863": {
   "id": "101863",
   "level": 6,
   "description": "B89 Red: petición a la consola del SOC desde un nodo de salida de Tor ($(srcip)): $(method) $(url).",
   "mitre": [
    "T1090.003"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101864": {
   "id": "101864",
   "level": 12,
   "description": "B89 Red: el host abrió una conexión a $(dstip):$(dstport) ($(b89.net.process)), IP en listas de reputación (posible C2).",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101865": {
   "id": "101865",
   "level": 13,
   "description": "B89 Red: acceso SSH exitoso de $(dstuser) desde $(srcip), IP en listas de reputación.",
   "mitre": [
    "T1078.003",
    "T1021.004"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101866": {
   "id": "101866",
   "level": 12,
   "description": "B89 Red: $(audit.exe) (auid $(audit.auid)) se conectó a $(dstip):$(dstport), IP en listas de reputación.",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101867": {
   "id": "101867",
   "level": 10,
   "description": "B89 Red: conexión TCP establecida desde $(srcip) (listas de reputación) al puerto $(dstport) del host.",
   "mitre": [
    "T1133"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101868": {
   "id": "101868",
   "level": 13,
   "description": "B89 Red: acceso SSH exitoso de $(dstuser) desde $(srcip), nodo de salida de Tor.",
   "mitre": [
    "T1090.003",
    "T1021.004"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/network/threat-intel/rule.xml",
   "useCases": [
    "B89-DET-NET-007"
   ]
  },
  "101870": {
   "id": "101870",
   "level": 12,
   "description": "B89 Red: $(srcip), ya bloqueada por el WAF de Cloudflare, ataca ahora la consola del SOC: $(url).",
   "mitre": [
    "T1190",
    "T1595"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101871": {
   "id": "101871",
   "level": 13,
   "description": "B89 Red: inicio de sesión exitoso desde $(srcip), IP que el WAF de Cloudflare bloqueó en los últimos 7 días.",
   "mitre": [
    "T1078",
    "T1190"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101872": {
   "id": "101872",
   "level": 8,
   "description": "B89 Red: $(srcip), bloqueada por el WAF de Cloudflare, intenta autenticarse en el SOC (SSH).",
   "mitre": [
    "T1110"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101873": {
   "id": "101873",
   "level": 10,
   "description": "B89 Red: $(srcip) atacó la consola web del SOC y ahora intenta SSH al mismo nodo (1 h).",
   "mitre": [
    "T1110",
    "T1190"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101874": {
   "id": "101874",
   "level": 14,
   "description": "B89 Red: acceso SSH exitoso de $(dstuser) desde $(srcip), que atacó la consola web del SOC en la última hora.",
   "mitre": [
    "T1078.003",
    "T1190"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101875": {
   "id": "101875",
   "level": 12,
   "description": "B89 Red: inicio de sesión en la consola del SOC desde $(srcip), que intentó SSH con usuarios inexistentes en la última hora.",
   "mitre": [
    "T1110",
    "T1078"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101876": {
   "id": "101876",
   "level": 12,
   "description": "B89 Red: inicio de sesión en la consola del SOC desde $(srcip), que falló contraseñas SSH de una cuenta real en la última hora.",
   "mitre": [
    "T1110",
    "T1078"
   ],
   "groups": [
    "b89_attack_chain"
   ],
   "file": "detections/network/cross-source-correlation/rule.xml",
   "useCases": [
    "B89-DET-NET-008"
   ]
  },
  "101880": {
   "id": "101880",
   "level": 0,
   "description": "B89 Windows: WFP permitió $(win.eventdata.application) → $(win.eventdata.destAddress):$(win.eventdata.destPort).",
   "mitre": [],
   "groups": [
    "b89_wfp"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101881": {
   "id": "101881",
   "level": 1,
   "description": "B89 Windows: WFP bloqueó $(win.eventdata.sourceAddress) → $(win.eventdata.destAddress):$(win.eventdata.destPort).",
   "mitre": [],
   "groups": [
    "b89_wfp"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101882": {
   "id": "101882",
   "level": 10,
   "description": "B89 Windows: 20+ conexiones bloqueadas desde $(win.eventdata.sourceAddress) a puertos distintos en 2 min (escaneo de puertos).",
   "mitre": [
    "T1046"
   ],
   "groups": [
    "b89_wfp"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101883": {
   "id": "101883",
   "level": 12,
   "description": "B89 Windows: $(win.eventdata.application) se conectó a $(win.eventdata.destAddress):$(win.eventdata.destPort), IP en listas de reputación.",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101884": {
   "id": "101884",
   "level": 6,
   "description": "B89 Windows: WFP bloqueó a $(win.eventdata.sourceAddress) (listas de reputación) hacia el puerto $(win.eventdata.destPort).",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101885": {
   "id": "101885",
   "level": 12,
   "description": "B89 Windows: $(win.eventdata.image) se conectó a $(win.eventdata.destinationIp):$(win.eventdata.destinationPort), IP en listas de reputación.",
   "mitre": [
    "T1071"
   ],
   "groups": [
    "b89_ti_hit"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101886": {
   "id": "101886",
   "level": 8,
   "description": "B89 Windows: binario del sistema abusable $(win.eventdata.image) se conectó a $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) (descarga o C2 con LOLBin).",
   "mitre": [
    "T1105"
   ],
   "groups": [
    "b89_attack"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101887": {
   "id": "101887",
   "level": 6,
   "description": "B89 Windows: $(win.eventdata.image) resolvió $(win.eventdata.queryName) (DNS dinámico o túnel inverso).",
   "mitre": [
    "T1071",
    "T1572"
   ],
   "groups": [
    "b89_dns"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101888": {
   "id": "101888",
   "level": 10,
   "description": "B89 Windows: el firewall descartó tráfico de $(srcip) (listas de reputación) hacia $(dstip):$(dstport).",
   "mitre": [
    "T1595"
   ],
   "groups": [
    "b89_ti_hit",
    "firewall_drop"
   ],
   "file": "detections/windows/network-connections/rule.xml",
   "useCases": [
    "B89-DET-NET-009"
   ]
  },
  "101900": {
   "id": "101900",
   "level": 3,
   "description": "B89 SharePoint: $(office365.UserId) descargó $(office365.SourceFileName).",
   "mitre": [],
   "groups": [
    "b89_download"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101901": {
   "id": "101901",
   "level": 2,
   "description": "B89 SharePoint: descarga de la cuenta de servicio/sincronización aprobada $(office365.UserId).",
   "mitre": [],
   "groups": [
    "b89_tuning"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101902": {
   "id": "101902",
   "level": 10,
   "description": "B89 SharePoint: descarga masiva de $(office365.UserId) (150 archivos en 10 min por web o API).",
   "mitre": [
    "T1530",
    "T1213.002"
   ],
   "groups": [
    "b89_collection",
    "b89_exfiltration"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101903": {
   "id": "101903",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) descargó 40 archivos en 30 min fuera del horario B89 (hora local $(b89.local_hour)).",
   "mitre": [
    "T1530",
    "T1213.002"
   ],
   "groups": [
    "b89_collection",
    "b89_exfiltration",
    "b89_off_hours"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101904": {
   "id": "101904",
   "level": 12,
   "description": "B89 SharePoint: descarga masiva de $(office365.UserId) desde una red nueva para el usuario ($(office365.ClientIP)).",
   "mitre": [
    "T1530",
    "T1078.004"
   ],
   "groups": [
    "b89_collection",
    "b89_exfiltration"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101905": {
   "id": "101905",
   "level": 3,
   "description": "B89 SharePoint: el invitado $(office365.UserId) accedió a $(office365.SourceFileName).",
   "mitre": [],
   "groups": [
    "b89_guest_access"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101906": {
   "id": "101906",
   "level": 10,
   "description": "B89 SharePoint: el invitado $(office365.UserId) accedió o descargó 30 archivos en 10 min.",
   "mitre": [
    "T1530",
    "T1078.004"
   ],
   "groups": [
    "b89_collection",
    "b89_guest_access"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101907": {
   "id": "101907",
   "level": 10,
   "description": "B89 SharePoint: actividad de archivos de la cuenta deshabilitada $(office365.UserId) ($(office365.Operation) en $(office365.ObjectId)).",
   "mitre": [
    "T1078.004"
   ],
   "groups": [
    "b89_initial_access"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101908": {
   "id": "101908",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) hizo $(office365.Operation) desde $(office365.ClientIP), IP en listas de amenazas (Spamhaus DROP/Feodo).",
   "mitre": [
    "T1078.004",
    "T1213.002"
   ],
   "groups": [
    "b89_initial_access",
    "b89_threat_intel"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101909": {
   "id": "101909",
   "level": 11,
   "description": "B89 SharePoint: $(office365.UserId) hizo $(office365.Operation) desde $(office365.ClientIP), nodo de salida de Tor.",
   "mitre": [
    "T1090.003",
    "T1078.004"
   ],
   "groups": [
    "b89_initial_access",
    "b89_threat_intel"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101910": {
   "id": "101910",
   "level": 3,
   "description": "B89 SharePoint: enlace anónimo usado desde $(office365.ClientIP) sobre $(office365.ObjectId).",
   "mitre": [],
   "groups": [
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101911": {
   "id": "101911",
   "level": 10,
   "description": "B89 SharePoint: 50 usos de enlaces anónimos desde $(office365.ClientIP) en 10 min (descarga masiva sin identidad).",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "b89_collection",
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101912": {
   "id": "101912",
   "level": 3,
   "description": "B89 SharePoint: el cliente de sincronización de $(office365.UserId) descargó $(office365.SourceFileName).",
   "mitre": [],
   "groups": [
    "b89_sync"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101913": {
   "id": "101913",
   "level": 7,
   "description": "B89 SharePoint: sincronización masiva de $(office365.UserId) (500 archivos en 10 min, cliente OneDrive).",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "b89_collection",
    "b89_sync"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101914": {
   "id": "101914",
   "level": 11,
   "description": "B89 SharePoint: sincronización masiva de $(office365.UserId) desde una red nueva para el usuario ($(office365.ClientIP)).",
   "mitre": [
    "T1530",
    "T1078.004"
   ],
   "groups": [
    "b89_collection",
    "b89_sync"
   ],
   "file": "detections/sharepoint/exfiltration/rule.xml",
   "useCases": [
    "B89-DET-SP-001"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101915": {
   "id": "101915",
   "level": 3,
   "description": "B89 SharePoint: $(office365.UserId) borró $(office365.ObjectId).",
   "mitre": [],
   "groups": [
    "b89_deletion"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101916": {
   "id": "101916",
   "level": 2,
   "description": "B89 SharePoint: borrado de la cuenta de servicio aprobada $(office365.UserId).",
   "mitre": [],
   "groups": [
    "b89_tuning"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101917": {
   "id": "101917",
   "level": 10,
   "description": "B89 SharePoint: borrado masivo, $(office365.UserId) borró 100 archivos o carpetas en 10 min.",
   "mitre": [
    "T1485"
   ],
   "groups": [
    "b89_impact"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101918": {
   "id": "101918",
   "level": 13,
   "description": "B89 SharePoint: destrucción masiva, $(office365.UserId) borró 300 archivos o carpetas en 15 min.",
   "mitre": [
    "T1485"
   ],
   "groups": [
    "b89_impact"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101919": {
   "id": "101919",
   "level": 3,
   "description": "B89 SharePoint: $(office365.UserId) eliminó de la papelera de segunda etapa $(office365.ObjectId).",
   "mitre": [],
   "groups": [
    "b89_deletion"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101920": {
   "id": "101920",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) vació 25 elementos de la papelera de segunda etapa en 15 min (impide la recuperación).",
   "mitre": [
    "T1490",
    "T1485"
   ],
   "groups": [
    "b89_impact"
   ],
   "file": "detections/sharepoint/mass-deletion/rule.xml",
   "useCases": [
    "B89-DET-SP-002"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101925": {
   "id": "101925",
   "level": 3,
   "description": "B89 SharePoint: enlace anónimo de la cuenta aprobada para publicar $(office365.UserId).",
   "mitre": [],
   "groups": [
    "b89_tuning",
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101926": {
   "id": "101926",
   "level": 11,
   "description": "B89 SharePoint: $(office365.UserId) creó 10 enlaces anónimos en 1 h.",
   "mitre": [
    "T1567"
   ],
   "groups": [
    "b89_exfiltration",
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101927": {
   "id": "101927",
   "level": 9,
   "description": "B89 SharePoint: $(office365.UserId) compartió $(office365.ObjectId) con el correo personal $(office365.TargetUserOrGroupName).",
   "mitre": [
    "T1537"
   ],
   "groups": [
    "b89_exfiltration",
    "b89_external_sharing",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101928": {
   "id": "101928",
   "level": 4,
   "description": "B89 SharePoint: $(office365.UserId) compartió $(office365.ObjectId) con el externo $(office365.TargetUserOrGroupName).",
   "mitre": [
    "T1537"
   ],
   "groups": [
    "b89_external_sharing",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101929": {
   "id": "101929",
   "level": 2,
   "description": "B89 SharePoint: compartición externa de la cuenta aprobada $(office365.UserId).",
   "mitre": [],
   "groups": [
    "b89_tuning",
    "b89_external_sharing"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101930": {
   "id": "101930",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) compartió 5 elementos con correos personales en 1 h.",
   "mitre": [
    "T1537"
   ],
   "groups": [
    "b89_exfiltration",
    "b89_external_sharing"
   ],
   "file": "detections/sharepoint/external-sharing/rule.xml",
   "useCases": [
    "B89-DET-SP-003"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101935": {
   "id": "101935",
   "level": 8,
   "description": "B89 SharePoint: $(office365.UserId) cambió la política de uso compartido o de acceso ($(office365.Operation)) en $(office365.ObjectId).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sharing_policy",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101936": {
   "id": "101936",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) habilitó el uso compartido con cualquier persona en $(office365.ObjectId).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sharing_policy",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101937": {
   "id": "101937",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) habilitó el uso compartido con cualquier persona en $(office365.ObjectId).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sharing_policy",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101938": {
   "id": "101938",
   "level": 10,
   "description": "B89 SharePoint: $(office365.UserId) agregó un administrador de colección de sitios en $(office365.ObjectId).",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "b89_privilege_escalation",
    "b89_site_admin",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101939": {
   "id": "101939",
   "level": 3,
   "description": "B89 SharePoint: alta de administrador de sitio por la cuenta del sistema $(office365.UserId) (aprovisionamiento).",
   "mitre": [],
   "groups": [
    "b89_tuning",
    "b89_site_admin"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101940": {
   "id": "101940",
   "level": 11,
   "description": "B89 SharePoint: $(office365.UserId) se agregó o agregó un administrador al OneDrive de otra persona ($(office365.ObjectId)).",
   "mitre": [
    "T1098",
    "T1530"
   ],
   "groups": [
    "b89_privilege_escalation",
    "b89_site_admin",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101941": {
   "id": "101941",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) hizo administrador de $(office365.ObjectId) al invitado $(office365.TargetUserOrGroupName).",
   "mitre": [
    "T1098",
    "T1078.004"
   ],
   "groups": [
    "b89_privilege_escalation",
    "b89_site_admin",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/sharing-policy-and-admins/rule.xml",
   "useCases": [
    "B89-DET-SP-004"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101945": {
   "id": "101945",
   "level": 8,
   "description": "B89 SharePoint: $(office365.UserId) quitó la etiqueta de confidencialidad de $(office365.ObjectId).",
   "mitre": [
    "T1562"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sensitivity_label",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101946": {
   "id": "101946",
   "level": 8,
   "description": "B89 SharePoint: $(office365.UserId) rebajó o quitó la etiqueta de confidencialidad de $(office365.ObjectId) ($(office365.Operation)).",
   "mitre": [
    "T1562"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sensitivity_label",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101947": {
   "id": "101947",
   "level": 12,
   "description": "B89 SharePoint: $(office365.UserId) quitó la etiqueta de confidencialidad de 10 archivos en 1 h.",
   "mitre": [
    "T1562"
   ],
   "groups": [
    "b89_defense_evasion",
    "b89_sensitivity_label"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101948": {
   "id": "101948",
   "level": 13,
   "description": "B89 SharePoint: $(office365.UserId) compartió fuera de B89 $(office365.ObjectId) después de quitarle la etiqueta de confidencialidad.",
   "mitre": [
    "T1562",
    "T1567"
   ],
   "groups": [
    "b89_exfiltration",
    "b89_sensitivity_label",
    "b89_attack_chain"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101949": {
   "id": "101949",
   "level": 7,
   "description": "B89 SharePoint: DLP detectó información sensible en $(office365.ObjectId) ($(office365.UserId)).",
   "mitre": [
    "T1213.002"
   ],
   "groups": [
    "b89_dlp"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101950": {
   "id": "101950",
   "level": 11,
   "description": "B89 SharePoint: DLP de severidad alta en $(office365.ObjectId) ($(office365.UserId)).",
   "mitre": [
    "T1213.002"
   ],
   "groups": [
    "b89_dlp"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101951": {
   "id": "101951",
   "level": 9,
   "description": "B89 SharePoint: $(office365.UserId) anuló la política DLP sobre $(office365.ObjectId).",
   "mitre": [
    "T1562",
    "T1213.002"
   ],
   "groups": [
    "b89_dlp",
    "b89_pending_provider_evidence"
   ],
   "file": "detections/sharepoint/labels-and-dlp/rule.xml",
   "useCases": [
    "B89-DET-SP-005"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101960": {
   "id": "101960",
   "level": 0,
   "description": "B89 SharePoint: evento del collector de postura y salud.",
   "mitre": [],
   "groups": [],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101961": {
   "id": "101961",
   "level": 3,
   "description": "B89 SharePoint: foto de la configuración de uso compartido del tenant ($(sharepoint.tenant.sharing_capability)).",
   "mitre": [],
   "groups": [
    "b89_posture"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101962": {
   "id": "101962",
   "level": 8,
   "description": "B89 SharePoint: cambió $(sharepoint.change.setting) del tenant: $(sharepoint.change.old) → $(sharepoint.change.new).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_posture",
    "b89_sharing_policy"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101963": {
   "id": "101963",
   "level": 12,
   "description": "B89 SharePoint: se debilitó $(sharepoint.change.setting) del tenant: $(sharepoint.change.old) → $(sharepoint.change.new).",
   "mitre": [
    "T1484"
   ],
   "groups": [
    "b89_posture",
    "b89_sharing_policy",
    "b89_defense_evasion"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101964": {
   "id": "101964",
   "level": 5,
   "description": "B89 SharePoint: sitio nuevo $(sharepoint.site.url) (creado $(sharepoint.site.created)).",
   "mitre": [],
   "groups": [
    "b89_posture"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101965": {
   "id": "101965",
   "level": 10,
   "description": "B89 SharePoint: el sitio reciente $(sharepoint.site.url) ya tiene enlaces anónimos o permisos externos.",
   "mitre": [
    "T1567",
    "T1537"
   ],
   "groups": [
    "b89_posture",
    "b89_external_sharing"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101966": {
   "id": "101966",
   "level": 7,
   "description": "B89 SharePoint: enlace anónimo ($(sharepoint.link.type)) sobre $(sharepoint.item.url).",
   "mitre": [
    "T1567"
   ],
   "groups": [
    "b89_posture",
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101967": {
   "id": "101967",
   "level": 10,
   "description": "B89 SharePoint: enlace anónimo con edición sobre $(sharepoint.item.url) (cualquiera puede modificar o reemplazar el contenido).",
   "mitre": [
    "T1567"
   ],
   "groups": [
    "b89_posture",
    "b89_anonymous_link"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101968": {
   "id": "101968",
   "level": 5,
   "description": "B89 SharePoint: $(sharepoint.grantee.email) (externo) tiene acceso a $(sharepoint.item.url).",
   "mitre": [
    "T1537"
   ],
   "groups": [
    "b89_posture",
    "b89_external_sharing"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101969": {
   "id": "101969",
   "level": 3,
   "description": "B89 SharePoint: función $(b89.capability.feature) $(b89.capability.status) (falta: $(b89.capability.missing)).",
   "mitre": [],
   "groups": [
    "b89_source_health"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101970": {
   "id": "101970",
   "level": 7,
   "description": "B89 SharePoint: la función $(b89.capability.feature) dejó de estar disponible (permiso revocado o credencial vencida; falta $(b89.capability.missing)).",
   "mitre": [],
   "groups": [
    "b89_source_health"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101971": {
   "id": "101971",
   "level": 2,
   "description": "B89 SharePoint: inventario de sitios ($(sharepoint.inventory.sites) sitios, $(sharepoint.inventory.known_findings) hallazgos de uso compartido).",
   "mitre": [],
   "groups": [
    "b89_posture"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101972": {
   "id": "101972",
   "level": 6,
   "description": "B89 SharePoint: el tenant permite enlaces \"Cualquier persona\" (sharingCapability=externalUserAndGuestSharing).",
   "mitre": [
    "T1567"
   ],
   "groups": [
    "b89_posture"
   ],
   "file": "detections/sharepoint/posture/rule.xml",
   "useCases": [
    "B89-DET-SP-006"
   ],
   "runbooks": [
    "exfiltracion-sharepoint"
   ]
  },
  "101980": {
   "id": "101980",
   "level": 3,
   "description": "B89 Integración: latido del collector $(b89.heartbeat.source_id) ($(b89.heartbeat.outcome), atraso $(b89.heartbeat.provider_lag_seconds) s).",
   "mitre": [],
   "groups": [],
   "file": "detections/platform/collector-heartbeat/rule.xml",
   "useCases": [
    "B89-DET-PLAT-001"
   ]
  },
  "101981": {
   "id": "101981",
   "level": 3,
   "description": "B89 Integración: latido del collector $(b89.heartbeat.source_id) ($(b89.heartbeat.outcome), atraso $(b89.heartbeat.provider_lag_seconds) s).",
   "mitre": [],
   "groups": [],
   "file": "detections/platform/collector-heartbeat/rule.xml",
   "useCases": [
    "B89-DET-PLAT-001"
   ]
  },
  "102000": {
   "id": "102000",
   "level": 0,
   "description": "B89 Cloudflare: respuesta 4xx a $(cloudflare.http.client_ip) (datos muestreados).",
   "mitre": [],
   "groups": [],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102001": {
   "id": "102001",
   "level": 2,
   "description": "B89 Cloudflare: intento de inyección SQL (OWASP A03) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a03_injection"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102002": {
   "id": "102002",
   "level": 2,
   "description": "B89 Cloudflare: intento de cross-site scripting (OWASP A03) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a03_injection"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102003": {
   "id": "102003",
   "level": 2,
   "description": "B89 Cloudflare: intento de recorrido de rutas o inclusión de archivos (OWASP A01) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a01_access_control"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102004": {
   "id": "102004",
   "level": 2,
   "description": "B89 Cloudflare: intento de inyección de comandos (OWASP A03) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a03_injection"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102005": {
   "id": "102005",
   "level": 2,
   "description": "B89 Cloudflare: intento de falsificación de peticiones del servidor, SSRF (OWASP A10) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a10_ssrf"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102006": {
   "id": "102006",
   "level": 2,
   "description": "B89 Cloudflare: intento de Log4Shell o inyección de plantillas (OWASP A03/A06) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path) ($(cloudflare.http.status)).",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "owasp_a06_vulnerable_components"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102007": {
   "id": "102007",
   "level": 2,
   "description": "B89 Cloudflare: herramienta de ataque o escaneo ($(cloudflare.http.user_agent)) desde $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path).",
   "mitre": [
    "T1595.002"
   ],
   "groups": [
    "b89_cf_http_attack",
    "b89_web_probe",
    "owasp_a05_misconfiguration"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102008": {
   "id": "102008",
   "level": 2,
   "description": "B89 Cloudflare: prueba de ataque web desde el escáner autorizado $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path).",
   "mitre": [],
   "groups": [
    "b89_trusted_principal"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102009": {
   "id": "102009",
   "level": 10,
   "description": "B89 Cloudflare: la aplicación falló (error $(cloudflare.http.status)) ante un ataque web desde $(cloudflare.http.client_ip): $(cloudflare.http.method) $(cloudflare.http.host)$(cloudflare.http.path). Posible vulnerabilidad explotable; revisar el origen.",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "b89_attack",
    "b89_owasp_signal"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102010": {
   "id": "102010",
   "level": 5,
   "description": "B89 Cloudflare: un ataque web desde $(cloudflare.http.client_ip) llegó a la aplicación y recibió $(cloudflare.http.status): $(cloudflare.http.method) $(cloudflare.http.host)$(cloudflare.http.path). Cloudflare no lo bloqueó; confirmar si la respuesta expuso datos.",
   "mitre": [
    "T1190"
   ],
   "groups": [
    "b89_cf_http_attack",
    "b89_owasp_signal"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102011": {
   "id": "102011",
   "level": 8,
   "description": "B89 Cloudflare: campaña de ataques web (OWASP) desde $(cloudflare.http.client_ip) contra $(cloudflare.http.host): 5+ intentos en 10 min.",
   "mitre": [
    "T1190",
    "T1595.002"
   ],
   "groups": [
    "b89_attack",
    "b89_owasp_signal"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102012": {
   "id": "102012",
   "level": 8,
   "description": "B89 Cloudflare: campaña de ataques web (OWASP) desde $(cloudflare.http.client_ip) contra $(cloudflare.http.host): 2+ intentos muestreados en 30 min (≈ 20+ reales).",
   "mitre": [
    "T1190",
    "T1595.002"
   ],
   "groups": [
    "b89_attack",
    "b89_owasp_signal"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102013": {
   "id": "102013",
   "level": 8,
   "description": "B89 Cloudflare: escaneo de rutas sensibles (/.env, /.git, wp-login…) desde $(cloudflare.http.client_ip): 3+ sondeos muestreados en 15 min (≈ 30+ reales).",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_web_probe",
    "b89_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102014": {
   "id": "102014",
   "level": 7,
   "description": "B89 Cloudflare: 6+ respuestas 4xx muestreadas para $(cloudflare.http.client_ip) en 5 min (≈ 60+ reales); enumeración de rutas o fuerza bruta.",
   "mitre": [
    "T1595.003"
   ],
   "groups": [
    "b89_web_probe",
    "b89_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102015": {
   "id": "102015",
   "level": 2,
   "description": "B89 Cloudflare: login rechazado ($(cloudflare.http.status)) para $(cloudflare.http.client_ip) en $(cloudflare.http.host)$(cloudflare.http.path).",
   "mitre": [],
   "groups": [
    "b89_cf_login_failed",
    "owasp_a07_auth"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102016": {
   "id": "102016",
   "level": 10,
   "description": "B89 Cloudflare: fuerza bruta de login (OWASP A07) desde $(cloudflare.http.client_ip) contra $(cloudflare.http.host): 10+ logins rechazados en 5 min.",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "b89_attack",
    "b89_credential_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102017": {
   "id": "102017",
   "level": 10,
   "description": "B89 Cloudflare: fuerza bruta de login (OWASP A07) desde $(cloudflare.http.client_ip) contra $(cloudflare.http.host): 3+ rechazos muestreados en 15 min (≈ 30+ reales).",
   "mitre": [
    "T1110.001"
   ],
   "groups": [
    "b89_attack",
    "b89_credential_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102018": {
   "id": "102018",
   "level": 12,
   "description": "B89 Cloudflare: relleno de credenciales distribuido (OWASP A07) contra $(cloudflare.http.host): 30+ logins rechazados desde IPs distintas en 10 min.",
   "mitre": [
    "T1110.004"
   ],
   "groups": [
    "b89_attack",
    "b89_credential_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102019": {
   "id": "102019",
   "level": 12,
   "description": "B89 Cloudflare: relleno de credenciales distribuido (OWASP A07) contra $(cloudflare.http.host): 8+ rechazos muestreados desde IPs distintas en 15 min (≈ 90+ reales).",
   "mitre": [
    "T1110.004"
   ],
   "groups": [
    "b89_attack",
    "b89_credential_attack"
   ],
   "file": "detections/cloudflare/web-attacks-owasp/rule.xml",
   "useCases": [
    "B89-DET-CF-003"
   ]
  },
  "102100": {
   "id": "102100",
   "level": 0,
   "description": "B89 Plataforma: evento del monitor de salud.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102101": {
   "id": "102101",
   "level": 3,
   "description": "B89 Integración: estado de la fuente $(b89.health.source): $(b89.health.source_state).",
   "mitre": [],
   "groups": [
    "b89_source_status"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102102": {
   "id": "102102",
   "level": 3,
   "description": "B89 Plataforma: $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_health_recovered"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102104": {
   "id": "102104",
   "level": 10,
   "description": "B89 Integración: fuente silenciosa $(b89.health.source). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_source_silent"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102105": {
   "id": "102105",
   "level": 8,
   "description": "B89 Integración: colector fallando ($(b89.health.source)). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_collector_failing"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102106": {
   "id": "102106",
   "level": 10,
   "description": "B89 Plataforma: agente desconectado $(b89.health.agent_name). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_agent_disconnected"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102107": {
   "id": "102107",
   "level": 12,
   "description": "B89 Plataforma: disco por encima del umbral ($(b89.health.component)). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_disk"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102108": {
   "id": "102108",
   "level": 13,
   "description": "B89 Plataforma: disco CRÍTICO ($(b89.health.component)). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_disk"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102109": {
   "id": "102109",
   "level": 10,
   "description": "B89 Plataforma: contenedor con problemas $(b89.health.component). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_container"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102110": {
   "id": "102110",
   "level": 12,
   "description": "B89 Plataforma: servicio esencial caído $(b89.health.component). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_container"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102111": {
   "id": "102111",
   "level": 8,
   "description": "B89 Plataforma: indexer degradado. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_indexer"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102112": {
   "id": "102112",
   "level": 12,
   "description": "B89 Plataforma: indexer en ROJO. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_indexer"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102114": {
   "id": "102114",
   "level": 7,
   "description": "B89 Plataforma: errores de ISM (retención). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_indexer"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102115": {
   "id": "102115",
   "level": 8,
   "description": "B89 Plataforma: certificado por vencer $(b89.health.component). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_certificate"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102116": {
   "id": "102116",
   "level": 12,
   "description": "B89 Plataforma: certificado vence en menos de 7 días o vencido: $(b89.health.component). $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_certificate"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102117": {
   "id": "102117",
   "level": 9,
   "description": "B89 Plataforma: ingesta B89 retrasada. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_ingestion"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102118": {
   "id": "102118",
   "level": 11,
   "description": "B89 Plataforma: ingesta B89 detenida. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_ingestion"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102119": {
   "id": "102119",
   "level": 8,
   "description": "B89 Plataforma: recursos del host. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_host"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102120": {
   "id": "102120",
   "level": 12,
   "description": "B89 Plataforma: portal del SOC inaccesible. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_edge"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102121": {
   "id": "102121",
   "level": 5,
   "description": "B89 Plataforma: feeds KEV/EPSS desactualizados. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_vulnprio"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102122": {
   "id": "102122",
   "level": 10,
   "description": "B89 Canario: el evento sintético de $(b89.health.source) no completó el recorrido. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_canary"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102123": {
   "id": "102123",
   "level": 7,
   "description": "B89 Plataforma: suscripción SNS sin confirmar. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_aws"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102124": {
   "id": "102124",
   "level": 5,
   "description": "B89 Plataforma: chequeo del monitor sin ejecutar. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_monitor"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102125": {
   "id": "102125",
   "level": 10,
   "description": "B89 Plataforma: el monitor de salud no corre. $(b89.health.summary)",
   "mitre": [],
   "groups": [
    "b89_monitor"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102129": {
   "id": "102129",
   "level": 5,
   "description": "B89 Plataforma: problema de salud $(b89.health.check). $(b89.health.summary)",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102130": {
   "id": "102130",
   "level": 3,
   "description": "B89 Canario: evento sintético de Bitdefender (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102131": {
   "id": "102131",
   "level": 3,
   "description": "B89 Canario: evento sintético de Snyk (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102132": {
   "id": "102132",
   "level": 3,
   "description": "B89 Canario: evento sintético de Cloudflare (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102133": {
   "id": "102133",
   "level": 3,
   "description": "B89 Canario: evento sintético de AWS (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102134": {
   "id": "102134",
   "level": 3,
   "description": "B89 Canario: evento sintético del monitor de plataforma (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102135": {
   "id": "102135",
   "level": 3,
   "description": "B89 Canario: evento sintético del agente Wazuh (journald) (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_platform_rules.xml"
  },
  "102150": {
   "id": "102150",
   "level": 14,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA priorizada P1 ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102151": {
   "id": "102151",
   "level": 14,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA con exploit maduro priorizada P1 ($(b89.vuln.reason)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102152": {
   "id": "102152",
   "level": 13,
   "description": "B89 Snyk: vulnerabilidad ALTA priorizada P1 ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102153": {
   "id": "102153",
   "level": 13,
   "description": "B89 Snyk: vulnerabilidad ALTA con exploit maduro priorizada P1 ($(b89.vuln.reason)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102154": {
   "id": "102154",
   "level": 12,
   "description": "B89 Snyk: vulnerabilidad media elevada a P1 ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102155": {
   "id": "102155",
   "level": 12,
   "description": "B89 Snyk: vulnerabilidad baja elevada a P1 ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102156": {
   "id": "102156",
   "level": 11,
   "description": "B89 Snyk: vulnerabilidad ALTA priorizada P2 ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102157": {
   "id": "102157",
   "level": 10,
   "description": "B89 Snyk: vulnerabilidad media elevada a P2 ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102158": {
   "id": "102158",
   "level": 6,
   "description": "B89 Snyk: vulnerabilidad crítica de baja prioridad P4 ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [],
   "groups": [
    "b89_deprioritized"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102159": {
   "id": "102159",
   "level": 6,
   "description": "B89 Snyk: vulnerabilidad alta de baja prioridad P4 ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [],
   "groups": [
    "b89_deprioritized"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102160": {
   "id": "102160",
   "level": 0,
   "description": "B89 Vulnerabilidad: evento del priorizador KEV/EPSS.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102161": {
   "id": "102161",
   "level": 14,
   "description": "B89 Vulnerabilidad: P1 en activo expuesto a Internet $(b89.vuln.asset): $(b89.vuln.cve) ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102162": {
   "id": "102162",
   "level": 13,
   "description": "B89 Vulnerabilidad: P1 en $(b89.vuln.asset): $(b89.vuln.cve) ($(b89.vuln.reason); KEV=$(b89.vuln.kev), EPSS=$(b89.vuln.epss)).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102163": {
   "id": "102163",
   "level": 10,
   "description": "B89 Vulnerabilidad: P2 en $(b89.vuln.asset): $(b89.vuln.cve) ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102164": {
   "id": "102164",
   "level": 3,
   "description": "B89 Vulnerabilidad: cambio de prioridad $(b89.vuln.previous_priority) a $(b89.vuln.priority) en $(b89.vuln.asset): $(b89.vuln.cve).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102165": {
   "id": "102165",
   "level": 3,
   "description": "B89 Vulnerabilidad: resumen diario de priorización: altas+críticas $(b89.vuln_summary.before_high_or_critical) antes, $(b89.vuln_summary.after_high_or_critical) después.",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102166": {
   "id": "102166",
   "level": 3,
   "description": "B89 Canario: evento sintético del priorizador de vulnerabilidades (sintético/canary, no requiere acción).",
   "mitre": [],
   "groups": [
    "b89_canary",
    "b89_synthetic"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102167": {
   "id": "102167",
   "level": 12,
   "description": "B89 Snyk: vulnerabilidad CRÍTICA priorizada P2 ($(b89.vuln.reason); EPSS=$(b89.vuln.epss)) $(b89.vuln.cve) en $(snyk.project.name).",
   "mitre": [],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102170": {
   "id": "102170",
   "level": 14,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) CRÍTICA en el catálogo CISA KEV afecta $(vulnerability.package.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102171": {
   "id": "102171",
   "level": 13,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) ALTA en el catálogo CISA KEV afecta $(vulnerability.package.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102172": {
   "id": "102172",
   "level": 12,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) media en el catálogo CISA KEV afecta $(vulnerability.package.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102173": {
   "id": "102173",
   "level": 12,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) baja en el catálogo CISA KEV afecta $(vulnerability.package.name).",
   "mitre": [
    "T1190"
   ],
   "groups": [],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102174": {
   "id": "102174",
   "level": 6,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) crítica de baja prioridad P4 (EPSS bajo, sin KEV, no expuesta) en $(vulnerability.package.name).",
   "mitre": [],
   "groups": [
    "b89_deprioritized"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "102175": {
   "id": "102175",
   "level": 5,
   "description": "B89 Vulnerabilidad: $(vulnerability.cve) alta de baja prioridad P4 (EPSS bajo, sin KEV, no expuesta) en $(vulnerability.package.name).",
   "mitre": [],
   "groups": [
    "b89_deprioritized"
   ],
   "file": "wazuh/platform-monitoring/rules/b89_watch_vulnprio_rules.xml"
  },
  "19003": {
   "id": "19003",
   "level": 5,
   "description": "SCA summary: $(sca.policy): Score less than 80% ($(sca.score))",
   "mitre": [],
   "groups": [
    "sca"
   ],
   "file": "wazuh-ruleset/0570-sca_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-005"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "19007": {
   "id": "19007",
   "level": 7,
   "description": "$(sca.policy): $(sca.check.title)",
   "mitre": [],
   "groups": [
    "sca"
   ],
   "file": "wazuh-ruleset/0570-sca_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-005"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "220": {
   "id": "220",
   "level": 7,
   "description": "The agent could not restart due to a $(module) failure in the remote configuration",
   "mitre": [],
   "groups": [
    "wazuh",
    "agent_restarting",
    "configuration_failure"
   ],
   "file": "wazuh-ruleset/0016-wazuh_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-WAZUH-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "2902": {
   "id": "2902",
   "level": 7,
   "description": "New dpkg (Debian Package) installed.",
   "mitre": [],
   "groups": [
    "syslog",
    "dpkg",
    "config_changed"
   ],
   "file": "wazuh-ruleset/0020-syslog_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-002"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "2904": {
   "id": "2904",
   "level": 7,
   "description": "Dpkg (Debian Package) half configured.",
   "mitre": [],
   "groups": [
    "syslog",
    "dpkg",
    "config_changed"
   ],
   "file": "wazuh-ruleset/0020-syslog_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-002"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "510": {
   "id": "510",
   "level": 7,
   "description": "Host-based anomaly detection event (rootcheck).",
   "mitre": [],
   "groups": [
    "ossec",
    "rootcheck"
   ],
   "file": "wazuh-ruleset/0015-ossec_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "521": {
   "id": "521",
   "level": 11,
   "description": "Possible kernel level rootkit",
   "mitre": [
    "T1014"
   ],
   "groups": [
    "ossec",
    "rootcheck"
   ],
   "file": "wazuh-ruleset/0015-ossec_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "550": {
   "id": "550",
   "level": 7,
   "description": "Integrity checksum changed.",
   "mitre": [
    "T1565.001"
   ],
   "groups": [
    "ossec",
    "syscheck",
    "syscheck_entry_modified"
   ],
   "file": "wazuh-ruleset/0015-ossec_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "553": {
   "id": "553",
   "level": 7,
   "description": "File deleted.",
   "mitre": [
    "T1070.004",
    "T1485"
   ],
   "groups": [
    "ossec",
    "syscheck",
    "syscheck_entry_deleted"
   ],
   "file": "wazuh-ruleset/0015-ossec_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "554": {
   "id": "554",
   "level": 5,
   "description": "File added to the system.",
   "mitre": [],
   "groups": [
    "ossec",
    "syscheck",
    "syscheck_entry_added"
   ],
   "file": "wazuh-ruleset/0015-ossec_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "5710": {
   "id": "5710",
   "level": 5,
   "description": "sshd: Attempt to login using a non-existent user",
   "mitre": [
    "T1110.001",
    "T1021.004"
   ],
   "groups": [
    "syslog",
    "sshd",
    "authentication_failed",
    "invalid_login"
   ],
   "file": "wazuh-ruleset/0095-sshd_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-004"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "5762": {
   "id": "5762",
   "level": 4,
   "description": "sshd: connection reset",
   "mitre": [],
   "groups": [
    "syslog",
    "sshd"
   ],
   "file": "wazuh-ruleset/0095-sshd_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-HOST-004"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91533": {
   "id": "91533",
   "level": 3,
   "description": "Office 365: Events from the Exchange admin audit log.",
   "mitre": [],
   "groups": [
    "office365",
    "ExchangeAdmin"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91548": {
   "id": "91548",
   "level": 5,
   "description": "Office 365: Admin actions from the Security and Compliance Center.",
   "mitre": [],
   "groups": [
    "office365",
    "SecurityComplianceCenterEOPCmdlet"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91578": {
   "id": "91578",
   "level": 5,
   "description": "Office 365: Events related to the MailItemsAccessed mailbox auditing action.",
   "mitre": [
    "T1114.002"
   ],
   "groups": [
    "office365",
    "ExchangeItemAggregated"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91702": {
   "id": "91702",
   "level": 4,
   "description": "Office 365: User downloads a file.",
   "mitre": [
    "T1530"
   ],
   "groups": [
    "office365",
    "OneDrive",
    "SharePoint"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-002"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91703": {
   "id": "91703",
   "level": 6,
   "description": "Office 365: A permission level was added to a site collection.",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "office365",
    "OneDrive",
    "SharePoint"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-002"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91707": {
   "id": "91707",
   "level": 4,
   "description": "Office 365: Sent message",
   "mitre": [
    "T1114.003"
   ],
   "groups": [
    "office365",
    "Exchange"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91708": {
   "id": "91708",
   "level": 6,
   "description": "Office 365: Sent message using different permissions",
   "mitre": [
    "T1114.003"
   ],
   "groups": [
    "office365",
    "Exchange"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-001"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91712": {
   "id": "91712",
   "level": 6,
   "description": "Office 365: Added group",
   "mitre": [
    "T1098"
   ],
   "groups": [
    "office365",
    "AzureActiveDirectory"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  },
  "91713": {
   "id": "91713",
   "level": 6,
   "description": "Office 365: Added member to group",
   "mitre": [
    "T1098.007"
   ],
   "groups": [
    "office365",
    "AzureActiveDirectory"
   ],
   "file": "wazuh-ruleset/0755-office365_rules.xml (wazuh-4.14.8)",
   "useCases": [
    "B89-STOCK-M365-003"
   ],
   "runbooks": [
    "reglas-estandar-wazuh"
   ]
  }
 },
 "techniques": {
  "T1003.006": {
   "name": "OS Credential Dumping: DCSync",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1014": {
   "name": "Rootkit",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1021.004": {
   "name": "Remote Services: SSH",
   "tactics": [
    {
     "id": "TA0008",
     "name": "Movimiento lateral"
    }
   ]
  },
  "T1027": {
   "name": "Obfuscated Files or Information",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1040": {
   "name": "Network Sniffing",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    },
    {
     "id": "TA0007",
     "name": "Descubrimiento"
    }
   ]
  },
  "T1046": {
   "name": "Network Service Discovery",
   "tactics": [
    {
     "id": "TA0007",
     "name": "Descubrimiento"
    }
   ]
  },
  "T1053.003": {
   "name": "Scheduled Task/Job: Cron",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1053.005": {
   "name": "Scheduled Task/Job: Scheduled Task",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1053.006": {
   "name": "Scheduled Task/Job: Systemd Timers",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1059": {
   "name": "Command and Scripting Interpreter",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1059.001": {
   "name": "Command and Scripting Interpreter: PowerShell",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1059.004": {
   "name": "Command and Scripting Interpreter: Unix Shell",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1070.001": {
   "name": "Indicator Removal: Clear Windows Event Logs",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1070.004": {
   "name": "Indicator Removal: File Deletion",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1071": {
   "name": "Application Layer Protocol",
   "tactics": [
    {
     "id": "TA0011",
     "name": "Comando y control"
    }
   ]
  },
  "T1078": {
   "name": "Valid Accounts",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    },
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1078.003": {
   "name": "Valid Accounts: Local Accounts",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    },
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1078.004": {
   "name": "Valid Accounts: Cloud Accounts",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    },
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1090.003": {
   "name": "Proxy: Multi-hop Proxy",
   "tactics": [
    {
     "id": "TA0011",
     "name": "Comando y control"
    }
   ]
  },
  "T1098": {
   "name": "Account Manipulation",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.001": {
   "name": "Account Manipulation: Additional Cloud Credentials",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.002": {
   "name": "Account Manipulation: Additional Email Delegate Permissions",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.003": {
   "name": "Account Manipulation: Additional Cloud Roles",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.004": {
   "name": "Account Manipulation: SSH Authorized Keys",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.005": {
   "name": "Account Manipulation: Device Registration",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1098.007": {
   "name": "Account Manipulation: Additional Local or Domain Groups",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1105": {
   "name": "Ingress Tool Transfer",
   "tactics": [
    {
     "id": "TA0011",
     "name": "Comando y control"
    }
   ]
  },
  "T1110": {
   "name": "Brute Force",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1110.001": {
   "name": "Brute Force: Password Guessing",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1110.003": {
   "name": "Brute Force: Password Spraying",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1110.004": {
   "name": "Brute Force: Credential Stuffing",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1114": {
   "name": "Email Collection",
   "tactics": [
    {
     "id": "TA0009",
     "name": "Recolección"
    }
   ]
  },
  "T1114.002": {
   "name": "Email Collection: Remote Email Collection",
   "tactics": [
    {
     "id": "TA0009",
     "name": "Recolección"
    }
   ]
  },
  "T1114.003": {
   "name": "Email Collection: Email Forwarding Rule",
   "tactics": [
    {
     "id": "TA0009",
     "name": "Recolección"
    }
   ]
  },
  "T1133": {
   "name": "External Remote Services",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1136.003": {
   "name": "Create Account: Cloud Account",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1190": {
   "name": "Exploit Public-Facing Application",
   "tactics": [
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1195": {
   "name": "Supply Chain Compromise",
   "tactics": [
    {
     "id": "TA0001",
     "name": "Acceso inicial"
    }
   ]
  },
  "T1204": {
   "name": "User Execution",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1204.002": {
   "name": "User Execution: Malicious File",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1213.002": {
   "name": "Data from Information Repositories: Sharepoint",
   "tactics": [
    {
     "id": "TA0009",
     "name": "Recolección"
    }
   ]
  },
  "T1484": {
   "name": "Domain or Tenant Policy Modification",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1484.001": {
   "name": "Domain or Tenant Policy Modification: Group Policy Modification",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1484.002": {
   "name": "Domain or Tenant Policy Modification: Trust Modification",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1485": {
   "name": "Data Destruction",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
    }
   ]
  },
  "T1490": {
   "name": "Inhibit System Recovery",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
    }
   ]
  },
  "T1496": {
   "name": "Resource Hijacking",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
    }
   ]
  },
  "T1499": {
   "name": "Endpoint Denial of Service",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
    }
   ]
  },
  "T1505.003": {
   "name": "Server Software Component: Web Shell",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1528": {
   "name": "Steal Application Access Token",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1530": {
   "name": "Data from Cloud Storage",
   "tactics": [
    {
     "id": "TA0009",
     "name": "Recolección"
    }
   ]
  },
  "T1535": {
   "name": "Unused/Unsupported Cloud Regions",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1537": {
   "name": "Transfer Data to Cloud Account",
   "tactics": [
    {
     "id": "TA0010",
     "name": "Exfiltración"
    }
   ]
  },
  "T1543.002": {
   "name": "Create or Modify System Process: Systemd Service",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1543.003": {
   "name": "Create or Modify System Process: Windows Service",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1547": {
   "name": "Boot or Logon Autostart Execution",
   "tactics": [
    {
     "id": "TA0003",
     "name": "Persistencia"
    },
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    }
   ]
  },
  "T1548": {
   "name": "Abuse Elevation Control Mechanism",
   "tactics": [
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1548.003": {
   "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
   "tactics": [
    {
     "id": "TA0004",
     "name": "Escalada de privilegios"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1550.001": {
   "name": "Use Alternate Authentication Material: Application Access Token",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0008",
     "name": "Movimiento lateral"
    }
   ]
  },
  "T1552.001": {
   "name": "Unsecured Credentials: Credentials In Files",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1556": {
   "name": "Modify Authentication Process",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1556.003": {
   "name": "Modify Authentication Process: Pluggable Authentication Modules",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1556.006": {
   "name": "Modify Authentication Process: Multi-Factor Authentication",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1556.009": {
   "name": "Modify Authentication Process: Conditional Access Policies",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    },
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0003",
     "name": "Persistencia"
    }
   ]
  },
  "T1558.003": {
   "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1558.004": {
   "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
   "tactics": [
    {
     "id": "TA0006",
     "name": "Acceso a credenciales"
    }
   ]
  },
  "T1562": {
   "name": "Impair Defenses",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1562.001": {
   "name": "Impair Defenses: Disable or Modify Tools",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1562.002": {
   "name": "Impair Defenses: Disable Windows Event Logging",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1562.007": {
   "name": "Impair Defenses: Disable or Modify Cloud Firewall",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1562.008": {
   "name": "Impair Defenses: Disable or Modify Cloud Logs",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1564.008": {
   "name": "Hide Artifacts: Email Hiding Rules",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1565.001": {
   "name": "Data Manipulation: Stored Data Manipulation",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
    }
   ]
  },
  "T1567": {
   "name": "Exfiltration Over Web Service",
   "tactics": [
    {
     "id": "TA0010",
     "name": "Exfiltración"
    }
   ]
  },
  "T1571": {
   "name": "Non-Standard Port",
   "tactics": [
    {
     "id": "TA0011",
     "name": "Comando y control"
    }
   ]
  },
  "T1572": {
   "name": "Protocol Tunneling",
   "tactics": [
    {
     "id": "TA0011",
     "name": "Comando y control"
    }
   ]
  },
  "T1584.002": {
   "name": "Compromise Infrastructure: DNS Server",
   "tactics": [
    {
     "id": "TA0042",
     "name": "Desarrollo de recursos"
    }
   ]
  },
  "T1595": {
   "name": "Active Scanning",
   "tactics": [
    {
     "id": "TA0043",
     "name": "Reconocimiento"
    }
   ]
  },
  "T1595.002": {
   "name": "Active Scanning: Vulnerability Scanning",
   "tactics": [
    {
     "id": "TA0043",
     "name": "Reconocimiento"
    }
   ]
  },
  "T1595.003": {
   "name": "Active Scanning: Wordlist Scanning",
   "tactics": [
    {
     "id": "TA0043",
     "name": "Reconocimiento"
    }
   ]
  },
  "T1599": {
   "name": "Network Boundary Bridging",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  },
  "T1609": {
   "name": "Container Administration Command",
   "tactics": [
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  },
  "T1610": {
   "name": "Deploy Container",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    },
    {
     "id": "TA0002",
     "name": "Ejecución"
    }
   ]
  }
 }
};
