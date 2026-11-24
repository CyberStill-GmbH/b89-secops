# Runbooks del motor de aprendizaje SOC

Enlazados desde cada alerta de salud (`GET /api/learning/health`, chequeos `learning_*` del monitor
de plataforma). Versión para la **sombra**: el motor no cambia ninguna alerta, así que ningún
incidente de este documento pierde una detección; lo que se pierde es la evidencia de la sombra.
La versión completa (dry-run y activo) es parte de la fase 4.

**Apagado de emergencia (válido para todos):** `B89_LEARNING_KILL_SWITCH=true` o
`B89_LEARNING_ENABLED=false` y reiniciar el API. Hoy el efecto llega con el reinicio (hallazgo H10
de doc 22). Registrar el cambio en `docs/22-registro-de-cambios.md`.

## motor-caido

Alertas: `HEARTBEAT_STALE` (crítica), monitor `learning_heartbeat`.

1. `GET /api/operations/health`: ¿el API está vivo? Si no, es un incidente del API, no del motor.
2. Logs del API: errores con código del bucle de despacho (`onDispatchError`).
3. `SELECT worker_id, beat_at, claimed, failed FROM soc_learning_worker_heartbeats;`
4. Si el API vive y el latido no avanza: reiniciar el API. La cola es durable; nada se pierde.
5. Si vuelve a caer: apagar el motor (arriba) y abrir incidente con los códigos de error.

## cola-atrasada

Alertas: `BACKLOG_AGE`, `EXPIRED_LEASES`, monitor `learning_backlog`.

1. `SELECT status, count(*), min(enqueued_at), max(attempts) FROM soc_learning_jobs GROUP BY 1;`
2. ¿Ráfaga de alertas? Comparar con el volumen de ingesta. Si es transitorio, esperar a que drene.
3. Leases vencidos repetidos: el worker cae a mitad de pasada o los trabajos superan el tiempo
   (`last_error = LEARNING_TIMEOUT`). Revisar latencia de la base.
4. Si el atraso supera 30 min: apagar el motor; la ingesta no se ve afectada.

## dead-letter

Alertas: `DEAD_LETTERS`, monitor `learning_dead_letters`.

1. `SELECT last_error, count(*) FROM soc_learning_jobs WHERE status = 'dead' GROUP BY 1;`
2. Esas alertas siguen abiertas para personas: no hay acción sobre ellas.
3. Corregir la causa (código de error) y, si se quiere evidencia de sombra, reencolar:
   `UPDATE soc_learning_jobs SET status = 'pending', finished_at = NULL, available_at = now(), attempts = 0 WHERE status = 'dead' AND …;`
   (lo hace el rol de migración o un operador con cambio registrado; el runtime no borra).

## latencia

Alerta: `LATENCY_P95`. Revisar latencia de la base y el tamaño de lote/concurrencia del worker
(`LearningWorkerPolicy`). Una latencia alta en sombra no afecta a la ingesta (cola separada).

## errores

Alerta: `ERROR_RATE`. `SELECT last_error, count(*) FROM soc_learning_jobs WHERE last_error IS NOT NULL GROUP BY 1;`
Errores de base o de bloqueo (`lock_timeout`) bajo ráfaga son reintentables; si persisten, bajar la
concurrencia del worker.

## escalaciones

Alerta: `ESCALATION_SPIKE` (razón principal en el resumen).

- `GUARD_CONTEXT`: faltan listas de activos críticos o identidades privilegiadas, o venció
  `B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL`. Es lo esperado hasta poblarlas (doc 01 §6.2).
- `GUARD_SOURCE`: ver salud-de-fuente.
- `DRIFT`: el comportamiento cambió respecto de un patrón; revisar el patrón con su dueño.
- Otras: revisar en `GET /api/learning/decisions` los `checks` de las decisiones.

## pausa-de-patron

Alertas: `PATTERN_PAUSED`, monitor `learning_pattern_paused`.

1. `GET /api/learning/patterns/:id` → eventos: motivo (`RATE_LIMIT`, `TRUE_POSITIVE_ON_FINGERPRINT`,
   `READINESS_REGRESSED`, `REVERTED`, `MANUAL_REOPEN`, `REVIEW_*`).
2. TP o reversión: el patrón queda en pausa; no reanudar sin revisar las alertas con su dueño.
3. Reanudar exige un aprobador designado (`POST …/resume`) y no extiende el vencimiento.

## reversion

Alertas: `REVERSALS`, `DISAGREEMENT`. En sombra no debería haber reversiones (no hay cierres). Si
aparecen: revisar quién reabrió y por qué en `soc_learning_reversals`; el patrón ya quedó en pausa.

## salud-de-fuente

Alerta: `SOURCE_NOT_HEALTHY`. Con la fuente degradada o sin medir, el motor escala todo
(`GUARD_SOURCE`): es fail-closed. Seguir el runbook de ingesta (`/api/sources/health`).

## configuracion-cambiada

Alerta: `CONFIG_CHANGED` (crítica si sube el techo de modo), monitor `learning_config_changed`.

1. `SELECT at, max_mode, active_rules, kill_switch, sampling_key_version FROM soc_learning_config_events ORDER BY at DESC LIMIT 5;`
2. Debe existir el registro del cambio en `docs/22-registro-de-cambios.md`. Si no existe: tratarlo
   como cambio no autorizado, poner el kill switch y escalar a seguridad.

## kill-switch

Alerta informativa `KILL_SWITCH`. Confirmar que fue intencional (registro de cambio). Para volver:
quitar la variable, reiniciar y verificar `GET /api/learning/health`.

## escalacion-sin-entrega

Alertas: `ENGINE_SELF_PAUSED` (crítica), `NOTIFICATION_CHANNEL_MISSING` (crítica).

1. El motor ya está en sombra (sin efectos): ninguna alerta se cerrará ni bajará de prioridad.
2. Canal: `B89_TEAMS_WORKFLOW_URL` configurado y el despacho vivo (`GET /api/operations/health`,
   sección de outbox). Si falta el canal, el motor no pasará de sombra hasta configurarlo.
3. Avisos pendientes: `SELECT available_at, payload->>'reasonCodes', payload->>'urgency' FROM soc_outbox_messages WHERE message_type = 'soc.alert.review_requested' AND status <> 'published' AND payload->>'reasonCodes' LIKE 'LEARNING%' ORDER BY 1;`
4. Con el canal reparado y los avisos publicados, un aprobador designado reanuda:
   `POST /api/learning/engine/resume` con un comentario. Si quedan avisos vencidos, se volverá a pausar.

## clave-comprometida

Alerta relacionada: `SAMPLING_KEY_ROTATION_DUE`, `SAMPLING_KEY_UNDATED`. Si la clave de muestreo se
filtró, un atacante puede predecir qué alertas NO se revisan (muestreo de calidad).

1. Kill switch o `B89_LEARNING_MAX_MODE=shadow` y reinicio (sin cierres mientras tanto).
2. Generar una clave nueva fuera del repo (`openssl rand -base64 48`) en el gestor de secretos, con
   `B89_LEARNING_SAMPLING_KEY_ID` nuevo y `B89_LEARNING_SAMPLING_KEY_ISSUED_AT` de hoy. Reiniciar.
3. Alcance: `SELECT count(*), min(at), max(at) FROM soc_learning_decisions WHERE sampling_key_version = '<kid viejo>' AND applied_action = 'AUTO_CLOSE';`
   Revisar por personas una muestra ampliada de esos cierres (o todos, si son pocos).
4. Registrar el incidente y el cambio en `docs/22-registro-de-cambios.md`. La bitácora
   `soc_learning_config_events` muestra el cambio de `sampling_key_version`.
5. Rotación normal: cada ≤ 90 días con los pasos 2 y 4 (sin el 1 ni el 3).
