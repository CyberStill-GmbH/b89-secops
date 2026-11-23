/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { wazuhRuleIdOfTitle } from './vendors';

/**
 * Guía en lenguaje llano de una alerta: qué pasó, cómo saber si es real y qué hacer.
 *
 * Pensada para cualquier persona del equipo, no solo para quien conoce Wazuh o Cloudflare. Se elige por
 * el ID de regla citado en el título («… (wazuh 101531)»). Solo describe lo que la regla comprueba
 * (docs/detection-engineering/16): nunca afirma un compromiso que la regla no demuestra.
 */
export interface AlertGuide {
  /** Una frase: qué tipo de situación es. */
  readonly headline: string;
  /** Qué detectó B89, sin jerga. */
  readonly whatHappened: string;
  /** Cómo confirmar si es un ataque real o un falso positivo. */
  readonly isItReal: readonly string[];
  /** Pasos concretos, en orden. */
  readonly whatToDo: readonly string[];
  /** `act`: actuar ya · `review`: revisar hoy · `info`: informativo. */
  readonly urgency: 'act' | 'review' | 'info';
}

export const URGENCY_LABEL: Readonly<Record<AlertGuide['urgency'], string>> = {
  act: 'Actuar ahora',
  review: 'Revisar hoy',
  info: 'Informativo',
};

const CHECK_IP =
  'Abre «Investigar» y mira la línea de tiempo de la IP: ¿qué más hizo antes y después?';
const ASK_PERSON =
  'Pregunta a la persona dueña de la cuenta si estaba conectada a esa hora y desde dónde (VPN, viaje, nube).';

const STOLEN_CREDENTIAL: AlertGuide = {
  urgency: 'act',
  headline:
    'Alguien usó una cuenta del backoffice de pagos desde un servidor en la nube o una VPN.',
  whatHappened:
    'Una sesión válida del backoffice (login, renovación de token o acciones de personal) salió de un proveedor de hosting o VPN comercial. El personal de B89 normalmente se conecta desde su casa u oficina, no desde un servidor.',
  isItReal: [
    ASK_PERSON,
    '¿La IP o el proveedor ya aparece en días anteriores para esa misma persona? Si es nuevo, es más sospechoso.',
    'Si la IP es de la oficina, la VPN corporativa o una automatización propia, es un falso positivo: pide agregarla a la lista de salidas corporativas (b89-backoffice-trusted-egress).',
  ],
  whatToDo: [
    'Si la persona no lo reconoce: cierra sus sesiones y cambia su contraseña y su segundo factor.',
    'Revisa en «Tráfico de Cloudflare → Análisis» si hubo movimientos de dinero o exportaciones desde esa IP.',
    'Bloquea la IP en Cloudflare mientras se investiga y vincula la alerta a un incidente.',
  ],
};

const MONEY_FROM_HOSTING: AlertGuide = {
  ...STOLEN_CREDENTIAL,
  headline: 'Se hizo un cambio en el backoffice de pagos desde un servidor en la nube o una VPN.',
  whatHappened:
    'Una operación que modifica datos del backoffice (por ejemplo, una transacción de saldo) salió de un proveedor de hosting o VPN. Puede ser un movimiento de dinero con una credencial robada.',
  whatToDo: [
    'Revisa la operación con el equipo de pagos ahora y detén o revierte lo que no se reconozca.',
    'Si la persona no lo reconoce: cierra sus sesiones y cambia su contraseña y su segundo factor.',
    'Bloquea la IP en Cloudflare y abre un incidente.',
  ],
};

const EXFILTRATION: AlertGuide = {
  ...STOLEN_CREDENTIAL,
  headline: 'Se exportaron datos del backoffice desde un servidor en la nube o una VPN.',
  whatHappened:
    'Alguien descargó una exportación del backoffice desde un proveedor de hosting o VPN. Si la sesión no es legítima, los datos pueden haber salido de B89.',
  whatToDo: [
    'Identifica qué se exportó (ruta y hora) y a quién pertenece la sesión.',
    'Si no se reconoce: cierra las sesiones, cambia credenciales y avisa a cumplimiento por posible fuga de datos.',
    'Bloquea la IP en Cloudflare y abre un incidente.',
  ],
};

const WEB_ATTACK_HIT: AlertGuide = {
  urgency: 'act',
  headline: 'Un ataque web hizo fallar a la aplicación (error 500).',
  whatHappened:
    'Una petición con una carga de ataque conocida (por ejemplo, inyección SQL o de comandos) llegó a la aplicación y esta respondió con un error interno. Puede indicar una vulnerabilidad explotable.',
  isItReal: [
    'Mira la ruta y la consulta en el evento de origen: ¿la carga es claramente maliciosa?',
    'Pide al equipo de desarrollo los registros de la aplicación de ese minuto: ¿el error lo causó la carga?',
    'Si la IP es de un pentest autorizado, es una prueba: pide agregarla a b89-authorized-scanners.',
  ],
  whatToDo: [
    'Comparte la ruta con desarrollo para revisar y corregir la validación de esa entrada.',
    'Activa o pasa a «bloquear» la regla del WAF de Cloudflare que cubre ese tipo de ataque.',
    'Bloquea la IP si sigue atacando.',
  ],
};

const WEB_ATTACK_PASSED: AlertGuide = {
  urgency: 'info',
  headline: 'Un intento de ataque web llegó a la aplicación, que respondió normal.',
  whatHappened:
    'Cloudflare dejó pasar una petición con una carga de ataque y la aplicación respondió sin error. Casi siempre significa que la aplicación ignoró la carga.',
  isItReal: [
    'Si la misma IP hizo muchos intentos, verás también una alerta de «campaña».',
    'Revisa si la respuesta devolvió más datos de lo normal (tamaño de respuesta en Registros).',
  ],
  whatToDo: ['No requiere acción inmediata. Considera bloquear ese tipo de ataque en el WAF.'],
};

const WAF_BLOCKED: AlertGuide = {
  urgency: 'info',
  headline: 'Cloudflare bloqueó un intento de ataque web.',
  whatHappened:
    'El firewall de Cloudflare detectó y detuvo una petición con una firma de ataque. La petición no llegó a la aplicación.',
  isItReal: [
    'Es un intento real, pero ya contenido. Importa solo si la misma IP insiste o cambia de técnica.',
  ],
  whatToDo: ['No requiere acción. Si se repite mucho, se generará una alerta de ataque sostenido.'],
};

const WAF_LOGGED: AlertGuide = {
  urgency: 'review',
  headline: 'Cloudflare vio un ataque web pero solo lo registró: pudo llegar a la aplicación.',
  whatHappened:
    'Una regla del firewall está en modo «solo registrar». La petición con la firma de ataque no se bloqueó.',
  isItReal: [
    'Revisa si la aplicación respondió con error o con datos inusuales en ese minuto.',
    'Si la regla está en modo registro a propósito (prueba de una regla nueva), confírmalo con quien administra Cloudflare.',
  ],
  whatToDo: [
    'Pide pasar la regla de «registrar» a «bloquear» si no hay motivo para dejarla así.',
    CHECK_IP,
  ],
};

const CAMPAIGN: AlertGuide = {
  urgency: 'review',
  headline: 'Una misma IP está lanzando muchos ataques web o escaneos.',
  whatHappened:
    'B89 contó varios intentos de ataque (inyección, escaneo de rutas sensibles, errores en cadena) desde la misma IP en pocos minutos. Es un escaneo automático o un atacante probando.',
  isItReal: [
    'Si las peticiones fueron bloqueadas (403) y ninguna dio error 500, el ataque está contenido.',
    'Si la IP es de un pentest autorizado, es una prueba: pide agregarla a b89-authorized-scanners.',
  ],
  whatToDo: [
    'Bloquea la IP en Cloudflare si sigue activa.',
    'Si alguna petición recibió 2xx o 500, revisa esa ruta con desarrollo.',
  ],
};

const BRUTE_FORCE: AlertGuide = {
  urgency: 'act',
  headline: 'Están probando contraseñas contra un login.',
  whatHappened:
    'Hubo muchos inicios de sesión rechazados en poco tiempo, desde una IP o desde muchas a la vez (relleno de credenciales con contraseñas filtradas).',
  isItReal: [
    'Mira si después hubo un login correcto desde las mismas IPs: eso sí sería una cuenta comprometida.',
    'Un comercio con una contraseña vencida reintentando produce el mismo patrón desde una sola IP: confírmalo con soporte.',
  ],
  whatToDo: [
    'Activa limitación de intentos (rate limiting) o un desafío en Cloudflare para esa ruta de login.',
    'Bloquea las IPs atacantes y revisa las cuentas con login correcto en esa ventana.',
  ],
};

const SECURITY_CHANGE: AlertGuide = {
  urgency: 'review',
  headline: 'Alguien cambió una configuración de seguridad de Cloudflare.',
  whatHappened:
    'Se creó, modificó o eliminó un control de seguridad, un registro DNS, un permiso o un token en la cuenta de Cloudflare.',
  isItReal: [
    '¿La persona que aparece en el evento tenía un cambio aprobado a esa hora?',
    'Un cambio que desactiva una protección o crea un token nuevo es más sensible que uno que la agrega.',
  ],
  whatToDo: [
    'Confirma el cambio con la persona o con el ticket de cambio.',
    'Si no está aprobado: revierte el cambio, revoca tokens nuevos y revisa la cuenta de esa persona.',
  ],
};

const AVAILABILITY: AlertGuide = {
  urgency: 'review',
  headline: 'Un sitio está devolviendo muchos errores de servidor.',
  whatHappened:
    'Cloudflare registró muchas respuestas 5xx en poco tiempo: el servidor de origen está caído o sobrecargado.',
  isItReal: [
    'Avisa a operaciones: puede ser una caída normal o la consecuencia de un ataque de volumen.',
  ],
  whatToDo: [
    'Confirma con operaciones el estado del origen y si coincide con picos de tráfico de una IP.',
  ],
};

const DNS_RECON: AlertGuide = {
  urgency: 'info',
  headline: 'Alguien está tratando de descubrir los subdominios de B89.',
  whatHappened:
    'Hubo una transferencia de zona DNS o muchas consultas a nombres que no existen: es reconocimiento previo a un ataque.',
  isItReal: ['Es habitual en Internet. Importa si coincide con ataques web desde la misma IP.'],
  whatToDo: ['No requiere acción. Revisa que la transferencia de zona esté deshabilitada.'],
};

// DLP de endpoints (Ferrispector): reglas 101110-101116 (docs/detection-engineering/runbooks/dlp-endpoint.md).
const DLP_SENSITIVE: AlertGuide = {
  urgency: 'review',
  headline: 'Hay datos personales o contraseñas escritas en un archivo de un equipo.',
  whatHappened:
    'Ferrispector revisó las carpetas aprobadas del equipo y encontró un dato sensible (por ejemplo, un DNI o una contraseña en texto). No mueve ni borra el archivo, y no envía su contenido.',
  isItReal: [
    'Pregunta a quien usa el equipo si reconoce el archivo (usa la huella SHA-256 del detalle técnico para ubicarlo).',
    'Es normal si el área puede guardar ese dato y el archivo está en la carpeta autorizada.',
  ],
  whatToDo: [
    'Si el archivo no debería estar ahí, muévelo a la ubicación aprobada o bórralo.',
    'Si es una contraseña real, cámbiala en el sistema donde se usa.',
    'Clasifica la alerta y anota qué se hizo con el archivo.',
  ],
};

const DLP_CREDENTIAL: AlertGuide = {
  urgency: 'act',
  headline: 'Hay una credencial guardada en un archivo de un equipo.',
  whatHappened:
    'Ferrispector encontró una clave o token con formato reconocible (por ejemplo, de GitHub, AWS o una clave privada) en una carpeta aprobada del equipo. Cualquiera con acceso al archivo podría usarla.',
  isItReal: [
    'Confirma con quien usa el equipo si es una credencial real o un ejemplo de pruebas.',
    'Revisa en el servicio de origen si la credencial está vigente y si se usó hace poco.',
  ],
  whatToDo: [
    'Si es real, revócala o rótala ya en el servicio de origen.',
    'Borra el archivo o quita la credencial y guárdala en el gestor de secretos aprobado.',
    'Clasifica la alerta con lo que encontraste en el uso reciente de la credencial.',
  ],
};

const DLP_FINGERPRINT: AlertGuide = {
  urgency: 'act',
  headline: 'Apareció una copia exacta de un documento protegido en un equipo.',
  whatHappened:
    'El archivo tiene la misma huella SHA-256 que un documento registrado como protegido en DLP. Es una copia idéntica, no un documento parecido.',
  isItReal: [
    'Confirma si ese equipo y esa persona deberían tener el documento.',
    'Si es la copia de trabajo autorizada, es normal: considera excluir la carpeta.',
  ],
  whatToDo: [
    'Si no debería estar ahí, pide que se elimine y averigua cómo llegó (correo, USB, descarga).',
    'Si salió del equipo o se compartió, abre un incidente.',
    'Clasifica la alerta con la conclusión.',
  ],
};

const DLP_AGENT_HEALTH: AlertGuide = {
  urgency: 'review',
  headline: 'El agente DLP de un equipo no está funcionando bien.',
  whatHappened:
    'Ferrispector no puede recibir la política del servidor o no puede revisar archivos. Mientras dure, ese equipo puede no estar protegido por completo.',
  isItReal: [
    'Mira en «DLP de endpoints» si el equipo figura sin conexión o revocado.',
    'Si se revocó a propósito, es lo esperado: falta desinstalar Ferrispector en ese equipo.',
  ],
  whatToDo: [
    'Comprueba que el equipo tenga red y que la consola responda.',
    'Si sigue fallando, reinstala Ferrispector con una clave nueva desde «Conectar un equipo».',
    'Clasifica la alerta como benigna con la causa cuando se recupere.',
  ],
};

// Lista blanca de la API de pagos (reglas 101547-101549; se edita en Cloudflare → Lista blanca).
const ALLOWLIST_CLIENT_FOREIGN_IP: AlertGuide = {
  urgency: 'act',
  headline: 'Un cliente con IPs autorizadas llamó a la API de pagos desde otra IP.',
  whatHappened:
    'La petición trae el identificador de un cliente que solo debería llamar desde sus IPs registradas, pero llegó desde una IP distinta. Puede ser una credencial robada o un servidor nuevo del cliente que no avisó.',
  isItReal: [
    'Abre «Investigar» y revisa qué más hizo esa IP: logins, pagos o retiros.',
    'Pregunta al cliente si cambió de servidor o de proveedor de nube.',
  ],
  whatToDo: [
    'Si el cliente no lo reconoce, bloquea la IP en Cloudflare y rota sus credenciales de API.',
    'Si es un servidor nuevo del cliente, agrega la IP en Cloudflare → Lista blanca.',
    'Clasifica la alerta con lo que confirmó el cliente.',
  ],
};

const ALLOWLIST_UNKNOWN_SENSITIVE: AlertGuide = {
  urgency: 'act',
  headline: 'Hubo un login o un pago en la API de pagos desde una IP que no está en la lista blanca.',
  whatHappened:
    'La IP no pertenece a ningún cliente, proveedor ni a la infraestructura de B89 registrados, y la petición fue a un inicio de sesión, pago, payin o payout.',
  isItReal: [
    'Mira si el login tuvo éxito y si después hubo movimientos de dinero.',
    'Busca la IP en Cloudflare → Lista blanca: quizá es de un cliente que aún no la registró.',
  ],
  whatToDo: [
    'Si nadie la reconoce, bloquea la IP en Cloudflare y revoca la sesión o la credencial usada.',
    'Si es legítima, agrégala a la lista blanca con el cliente que corresponde.',
    'Clasifica la alerta con la conclusión.',
  ],
};

const ALLOWLIST_UNKNOWN: AlertGuide = {
  urgency: 'review',
  headline: 'Una IP fuera de la lista blanca usó la API de pagos.',
  whatHappened:
    'La petición no fue a login ni a pagos, pero la IP no está registrada para ningún cliente ni proveedor.',
  isItReal: ['Es común en escaneos de Internet. Importa si la misma IP intenta después un login o un pago.'],
  whatToDo: [
    'Revisa si la IP aparece en otras alertas.',
    'Si es de un cliente, agrégala a la lista blanca para no volver a verla.',
  ],
};

const RULE_GUIDES: Readonly<Record<string, AlertGuide>> = {
  // Lista blanca de la API de pagos
  '101547': ALLOWLIST_CLIENT_FOREIGN_IP,
  '101548': ALLOWLIST_UNKNOWN_SENSITIVE,
  '101549': ALLOWLIST_UNKNOWN,
  // DLP de endpoints
  '101110': DLP_SENSITIVE,
  '101111': DLP_CREDENTIAL,
  '101112': DLP_FINGERPRINT,
  '101113': { ...DLP_AGENT_HEALTH, urgency: 'info' },
  '101114': DLP_AGENT_HEALTH,
  '101115': { ...DLP_AGENT_HEALTH, urgency: 'info' },
  '101116': DLP_AGENT_HEALTH,
  // Backoffice de pagos
  '101531': STOLEN_CREDENTIAL,
  '101545': {
    ...STOLEN_CREDENTIAL,
    headline:
      'Una sesión del backoffice de pagos lleva un rato activa desde un servidor en la nube o una VPN.',
  },
  '101537': MONEY_FROM_HOSTING,
  '101532': EXFILTRATION,
  // Ataques web
  '102009': WEB_ATTACK_HIT,
  '102010': WEB_ATTACK_PASSED,
  '101539': WAF_BLOCKED,
  '101541': WAF_BLOCKED,
  '101540': WAF_LOGGED,
  '101542': WAF_LOGGED,
  '101543': WAF_LOGGED,
  '101544': WAF_LOGGED,
  '101511': WAF_LOGGED,
  // Campañas, escaneos y enumeración
  '102011': CAMPAIGN,
  '102012': CAMPAIGN,
  '102013': CAMPAIGN,
  '102014': CAMPAIGN,
  '101513': CAMPAIGN,
  '101517': CAMPAIGN,
  '101519': CAMPAIGN,
  '101740': CAMPAIGN,
  '101741': CAMPAIGN,
  '101742': { ...CAMPAIGN, urgency: 'info' },
  // Autenticación
  '102016': BRUTE_FORCE,
  '102017': BRUTE_FORCE,
  '102018': BRUTE_FORCE,
  '102019': BRUTE_FORCE,
  // Auditoría de cuenta
  '101503': SECURITY_CHANGE,
  '101504': SECURITY_CHANGE,
  '101505': { ...SECURITY_CHANGE, urgency: 'act' },
  '101506': SECURITY_CHANGE,
  '101507': { ...SECURITY_CHANGE, urgency: 'act' },
  // Disponibilidad y DNS
  '101521': AVAILABILITY,
  '101526': DNS_RECON,
  '101528': DNS_RECON,
};

/** Guía de una regla por su ID, o `null` si no hay una específica. */
export function guideForRule(ruleId: string | null | undefined): AlertGuide | null {
  return ruleId ? (RULE_GUIDES[ruleId] ?? null) : null;
}

/** Guía de una alerta B89 a partir de su título («… (wazuh 101531)»). */
export function guideForAlertTitle(title: string | null | undefined): AlertGuide | null {
  return title ? guideForRule(wazuhRuleIdOfTitle(title)) : null;
}

/** IDs con guía (para pruebas y documentación). */
export const GUIDED_RULE_IDS: readonly string[] = Object.keys(RULE_GUIDES);
