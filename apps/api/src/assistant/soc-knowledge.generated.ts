// GENERADO por apps/api/scripts/generate-bunny-knowledge.py. No editar a mano.
// Fuentes: docs/detection-engineering (runbooks, playbooks), detections/ y XML de reglas B89.
/* eslint-disable */
import type { SocKnowledge } from './soc-knowledge.js';

export const SOC_KNOWLEDGE: SocKnowledge = {
 "attackVersion": "Enterprise v16",
 "runbookIndex": "# Runbooks de triage e investigación B89\n\nParte de [17 · Ingeniería de detección](../../17-ingenieria-de-deteccion.md). Cada runbook sigue el mismo\nesquema: **alcance** (reglas), **triage en 10 minutos**, **investigación**, **contención** (siempre por B89\nRespond con aprobación del Líder SOC), **recuperación**, **cierre y evidencia** y **consultas** (KQL para\nDiscover sobre `wazuh-alerts-*`).\n\n| Runbook | Casos de uso | Prioridad típica |\n| --- | --- | --- |\n| [Ataques de credenciales](credenciales.md) | M365 fuerza bruta/spray y cadena, BEC, Kerberos, consola AWS, SSH | P1–P2 |\n| [Escalada de privilegios](escalada-de-privilegios.md) | Roles de Entra y tier 0, IAM/Identity Center, grupos de AD, sudo/grupos y persistencia Linux | P1–P2 |\n| [Malware y EDR](malware-edr.md) | Bitdefender (malware, cuarentena, protección deshabilitada), Sophos, Outlook → proceso | P1–P2 |\n| [Vulnerabilidad expuesta](vulnerabilidad-expuesta.md) | Snyk crítica/alta con exploit maduro y expuesta, Wazuh VD | P1–P3 |\n| [Oleada en el WAF](oleada-waf.md) | Cloudflare 101513 y 101740, cambios de control | P2 |\n| [CloudTrail y auditoría](cloudtrail-y-auditoria.md) | CloudTrail/GuardDuty/Config apagados, auditoría de M365 desactivada | P1 |\n\nReglas comunes a todos:\n\n- **Evidencia primero:** antes de contener, exportar la alerta B89 (id, prioridad, razones) y los documentos\n  Wazuh (`_id`, índice). La auditoría B89 con cadena hash registra cada transición.\n- **Sin datos personales en canales abiertos:** en Teams/correo solo referencias; el detalle vive en B89 (N2).\n- **Nada se suprime sin registro:** un falso positivo se documenta en el incidente y se convierte en afinamiento\n  (lista CDB, ventana de mantenimiento en B89 o PR de la regla).\n- **Cierre:** clasificación VP/FP/benigno, causa raíz, acciones y lección para el backlog de detección.",
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
    "101740"
   ],
   "useCases": [
    "B89-DET-CF-001",
    "B89-DET-CF-002"
   ],
   "markdown": "# Runbook · Oleada de ataques en el WAF (Cloudflare)\n\nAlcance: `cloudflare/audit-and-waf` (101501–101513) y `cloudflare/waf-attack-surge` (101740).\n\n## Triage en 10 minutos\n\n1. **¿Una IP o muchas?** 101513 = una IP insistente (20 en 5 min); 101740 = oleada distribuida (50 IPs distintas en\n   10 min sobre un host) → P2.\n2. **¿Qué buscan?** Rutas (`data.cloudflare.firewall.path`) y regla del WAF (`rule_description`): SQLi, RCE,\n   `/login` (credenciales), rutas de un CVE reciente.\n3. **¿Pasa algo?** Eventos `log` (101511) con la misma firma = la regla está solo en modo registro: el ataque llega\n   a la aplicación → P1 si coincide con una vulnerabilidad expuesta (caza **H07**).\n4. **¿Alguien tocó los controles?** 101504/101505 (WAF/ruleset deshabilitado) en la misma ventana → P1.\n\n## Contención (cambio aprobado)\n\n- Rate limiting o regla de bloqueo por ASN/país/ruta; Under Attack mode si afecta disponibilidad.\n- Pasar a `block` la regla administrada que está en `log`.\n- Nunca bloquear rangos de proveedores de B89 sin confirmar (pagos, monitoreo).\n\n## Investigación y cierre\n\nTop IPs, ASN y países (H08), user agents, horarios; correlacionar con errores 5xx de la aplicación y con logins\nexitosos en la misma ventana. Cerrar con la medida aplicada y su vencimiento.\n\n## Consultas\n\n```text\nrule.id:(101513 or 101740)\nrule.groups:b89_waf and data.cloudflare.firewall.host:\"<host>\"\nrule.id:101511\n```"
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
    "101513"
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
   "description": "B89 Cloudflare: $(cloudflare.firewall.action) de $(cloudflare.firewall.client_ip) en $(cloudflare.firewall.host) ($(cloudflare.firewall.source)).",
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
   "description": "B89 Cloudflare: regla $(cloudflare.firewall.rule_id) coincidió solo en modo log para $(cloudflare.firewall.client_ip) en $(cloudflare.firewall.host).",
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
   "level": 2,
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
  "T1070.001": {
   "name": "Indicator Removal: Clear Windows Event Logs",
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
  "T1114": {
   "name": "Email Collection",
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
  "T1496": {
   "name": "Resource Hijacking",
   "tactics": [
    {
     "id": "TA0040",
     "name": "Impacto"
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
  "T1567": {
   "name": "Exfiltration Over Web Service",
   "tactics": [
    {
     "id": "TA0010",
     "name": "Exfiltración"
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
  "T1599": {
   "name": "Network Boundary Bridging",
   "tactics": [
    {
     "id": "TA0005",
     "name": "Evasión de defensas"
    }
   ]
  }
 }
};
