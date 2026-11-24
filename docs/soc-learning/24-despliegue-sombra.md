# Fase 2 · Preparar y lanzar el modo sombra

Fecha: 2026-11-24. Rama `feat/soc-learning-verify` (sin push). **Nada se encendió** y nada de lo de
abajo se ejecutó en staging ni en producción: son cambios, pruebas, comandos y configuración listos.

## 1. Qué cambió

| Pendiente (brief) | Estado | Evidencia | Verificado en |
|---|---|---|---|
| Motor fuera del camino crítico de la ingesta | hecho: la ingesta solo escribe un trabajo en su transacción; un worker lo consume con lease y `SKIP LOCKED`, concurrencia acotada, tiempo máximo, reintentos con espera exponencial, dead-letter e idempotencia | `e3a128f`, `e8e899d`; `learning-worker.spec.ts` (9), `learning-runtime.spec.ts` (2) | memoria · API en memoria |
| Una caída entre ingesta y evaluación ya no pierde la evaluación (H8) | hecho (cola durable) | ídem | memoria · Postgres pendiente |
| Prueba de carga a 10× | escrita, **no ejecutada** | `modules/soc/scripts/learning-load-test.ts`, paso `load` de `verify-engine.sh` | pendiente |
| Meta-monitoreo: latido, backlog, p95, errores, guardas por tipo, escaladas, cierres hipotéticos, desacuerdos, reversiones, pausas, salud de fuente, cambios de configuración | hecho | `2eea7d4`, `e8e899d` (`GET /api/learning/health`), `0e031fc` (monitor de plataforma, sin API) | memoria · pytest |
| Alertas por severidad con runbook y SLOs | hecho | `learning-health.ts`, `25-runbooks-motor.md`, §4 | memoria |
| Informe automático diario y semanal con Clopper–Pearson | hecho | `950b317` (`GET /api/learning/shadow-report`), `f175ba6` (CLI para cron) | memoria |
| Canarios contra motor y Postgres reales | escritos (37/38; D6 solo en memoria) | `learning-canaries.integration.spec.ts` | pendiente (CI/staging) |
| Diseño de canarios en producción | propuesta (§5), sin implementar | este documento | — |
| Plan de despliegue de la sombra | este documento (§6) | — | — |

Otras verificaciones de esta fase: PGlite 20/20 (incluida la cola), contrato del gateway 14/14,
248/248 pruebas unitarias de aprendizaje (`modules/soc`, el API y la configuración), `apps/api` tipado limpio en el worktree. Una prueba de
`wazuh/platform-monitoring/tests/test_vulnprio.py` falla **también sin mis cambios** (no relacionada).

## 2. Hallazgo que condiciona el reloj de 21 días

En sombra el motor solo **propone** un cierre cuando hay un patrón `active` y el contexto está
completo. Hoy, sin aprobadores, sin listas de activos e identidades privilegiadas pobladas y sin
calendario de cambios confirmado, todo termina en `GUARD_CONTEXT` o sin patrón: **la sombra
registraría escaladas, pero ningún cierre hipotético**, y los 21 días no darían evidencia de
precisión. El reloj útil empieza cuando, por regla:

1. las compuertas de la etapa D pasan y hay patrones `active` (aprobados A/A+B);
2. `B89_DETECTION_*` tiene activos críticos e identidades privilegiadas, y
   `B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL` está vigente;
3. la fuente de ingesta está `healthy`.

## 3. Aislamiento y rendimiento

- **Criterio de la prueba de carga:** p95 de la ingesta con el motor en sombra ≤ 1,2 × p95 sin motor
  + 20 ms, y 0 trabajos en dead-letter, a 10 × el volumen esperado. El script sale con error si no.
- **Volumen esperado:** desconocido aquí; el script lo recibe (`EXPECTED_PER_DAY`). Hay que medirlo
  en producción con `SELECT count(*)/7 FROM soc_alerts WHERE created_at > now() - interval '7 days'`.
- **Límites del worker** (`DEFAULT_LEARNING_WORKER_POLICY`): lote 50, concurrencia 4, lease 60 s,
  tiempo 10 s, 5 intentos, espera base 5 s. Pasada cada 5 s y al ingerir.

## 4. Meta-monitoreo, alertas y SLOs

| Alerta | Severidad | Disparo | Runbook |
|---|---|---|---|
| `HEARTBEAT_STALE` | crítica | sin latido > 5 min (o nunca) | motor-caido |
| `BACKLOG_AGE` | aviso / crítica | pendiente más viejo > 5 / 30 min | cola-atrasada |
| `EXPIRED_LEASES` | aviso | leases vencidos | cola-atrasada |
| `DEAD_LETTERS` | aviso / crítica | ≥ 1 / ≥ 10 en 24 h | dead-letter |
| `LATENCY_P95` | aviso | p95 encolado → decisión > 60 s | latencia |
| `ERROR_RATE` | aviso | > 5 % de intentos fallidos (≥ 20) | errores |
| `ESCALATION_SPIKE` | aviso | > 50 % de decisiones escalan (≥ 20) | escalaciones |
| `PATTERN_PAUSED`, `REVERSALS`, `DISAGREEMENT` | aviso | ≥ 1 en 24 h | pausa-de-patron, reversion |
| `SOURCE_NOT_HEALTHY` | aviso | fuente no `healthy` o sin medir | salud-de-fuente |
| `CONFIG_CHANGED` | aviso / crítica | cambio de configuración en 24 h / subida del techo | configuracion-cambiada |
| `KILL_SWITCH` | info | kill switch activo | kill-switch |

Entrega: el API (`/api/learning/health`, consola) y el **monitor de plataforma** leyendo la base
(latido, cola, dead-letter, pausas, configuración), que avisa aunque el API esté caído, por la regla
genérica 101829 (nivel 5). Reglas propias con más nivel necesitan IDs: los asigna el dueño del monitor
(el rango 1018xx tiene deuda de colisiones).

**SLOs propuestos (sombra):** p95 encolado → decisión ≤ 60 s (1 h); ≥ 99 % de trabajos decididos en
≤ 5 min (24 h); 0 dead-letter (24 h); latido ≤ 5 min el 99,9 % (30 d); la ingesta no se degrada.

## 5. Canarios

- **CI y staging (escrito):** `learning-canaries.integration.spec.ts` contra motor y Postgres reales.
  En staging: `DATABASE_URL=<admin de staging> pnpm exec vitest run --config vitest.integration.config.ts modules/soc/test/learning-canaries.integration.spec.ts`.
  Crea su base desechable y un tenant `canary-*`; no toca datos.
- **Producción (propuesta, sin activar):** reutilizar el canal de canarios del monitor
  (`b89_canary.py`, grupo `b89_synthetic`, nivel 3). Diseño: (1) tenant o fuente sintética dedicada;
  (2) el candidato lleva una marca `synthetic` que el motor registra pero con la que **nunca** cierra;
  (3) `learningEvidence`, el informe de sombra y `alertStats` excluyen esa marca; (4) el registro
  sellado de cada canario (qué se espera) vive fuera de la base del motor y lo verifica un job aparte;
  (5) el verificador cierra el canario tras el veredicto. Requiere un campo nuevo: queda para fase 3.

## 6. Plan de despliegue de la sombra (no ejecutado)

**Requisitos previos (todos):**

1. `verify-engine.sh` completo en verde (Postgres real, cada commit, suites ×3, carga).
2. Merge con el trabajo de la otra sesión según `COORDINACION-CLAUDE-CODEX.md` y suites ×3 integradas.
3. CI verde en la rama (requiere push: decisión del dueño).
4. Canarios al 100 % en staging.
5. Monitor de plataforma reinstalado (grants a `b89_monitor`) y su chequeo `learning` visible.
6. Registro de cambio en `docs/22-registro-de-cambios.md` con: quién aprueba, ventana, observadores,
   métricas de salida y vuelta atrás (abajo).

**Clave de muestreo propia de la sombra** (fuera del repo; el comando se muestra, no se ejecutó):

```bash
openssl rand -base64 48   # guardar en el gestor de secretos como B89_LEARNING_SAMPLING_KEY (sombra)
```

La bitácora de configuración registra solo su identificador (`kid-…`), nunca la clave.

**Configuración del entorno (sombra):**

```dotenv
B89_LEARNING_ENABLED=true
B89_LEARNING_MAX_MODE=shadow
B89_LEARNING_ACTIVE_RULES=            # vacío: nada por encima de la sombra
B89_LEARNING_SAMPLING_KEY=<del gestor de secretos>
B89_LEARNING_CHANGE_CALENDAR_ACK_UNTIL=<fecha ≤ 30 días>
B89_SOC_LEARNING_APPROVERS=<dos o más personas>
B89_SOC_CLOSURE_REASON_REQUIRED=true  # compuerta 3 de la etapa D
```

**Despliegue:** migraciones (`prisma migrate deploy` como `b89_migrator`), `post-migrate.sql`, imagen
del API, variables de arriba, reinicio. Comprobación: `GET /api/learning/health` → `OK` o solo
`SOURCE_NOT_HEALTHY`/`GUARD_CONTEXT` esperados; fila nueva en `soc_learning_config_events`.

**Quién observa:** dueño del producto y líder SOC (informe diario); plataforma (alertas de salud).

**Métricas de salida de la sombra** (por regla; detalle en doc 23): ≥ 21 días con patrones activos y
contexto completo; cota inferior Clopper–Pearson ≥ 0,97 con ≥ 30 adjudicadas; 0 TP suprimidos;
SLOs cumplidos; 0 dead-letter.

**Vuelta atrás:** `B89_LEARNING_ENABLED=false` y reinicio (la ingesta sigue igual; la cola deja de
llenarse). Las tablas quedan (son evidencia). Rollback de esquema solo sin datos
(`rollback-learning-engine.sql`).

## 7. ¿Se puede desplegar?

| Modo | Veredicto hoy | Qué falta |
|---|---|---|
| Código desplegado **con el motor apagado** | **Todavía no.** Seguro por diseño (migraciones aditivas, `B89_LEARNING_ENABLED=false`), pero **nada se verificó en PostgreSQL real** | §6.1–6.3: `verify-engine.sh` en verde, merge con la otra sesión, CI verde |
| **Sombra** | **No todavía.** | Lo anterior + canarios en staging, monitor reinstalado, clave de sombra, registro de cambio. Y para que el reloj de 21 días valga: §2 (patrones activos y contexto completo) |
| dry_run / activo | **No.** | Bloqueantes de la fase 3 (escalación que llega a una persona, `effective_priority`, notificaciones, piso de impacto inconfigurable, habilitación en dos capas, clave versionada) |

## 8. Riesgos, supuestos y qué necesito

- **Riesgo:** la sombra sin patrones activos ni contexto da cero evidencia de precisión (§2).
- **Riesgo:** sin la prueba de carga ejecutada, el aislamiento de la ingesta es diseño, no medida.
- **Supuesto:** un solo tenant por API (como el runtime actual).
- **Necesito:** (1) correr `verify-engine.sh` (ahora incluye `load` y canarios) y devolver
  `verify-engine-out/`; (2) el volumen diario esperado de alertas; (3) poblar listas de contexto y
  designar aprobadores; (4) decidir push/CI y el orden de merge con la otra sesión.
