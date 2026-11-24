# Contrato de canarios contra el motor real (etapa E)

Fecha: 2026-11-24. Estado: **ejecutándose en CI contra el motor en memoria**
(`modules/soc/test/learning-engine.contract.spec.ts`, etapa E). Pendiente: integración con
PostgreSQL real y canarios en sombra (registro sellado, ≥ 21 días).

Diferencias del motor actual con esta especificación (no son casos fallidos; están declaradas):

- B2/C7: `DEMOTE` se decide y se registra, pero todavía no cambia la prioridad efectiva (falta
  `effective_priority`). Nunca autocierra.
- C6: aceptar una propuesta de dry-run ejecuta el cierre como `svc:b89-soc-learning`.
- C10: el motor corre después del commit de la ingesta, en su propia transacción; relee alerta y
  patrón (con bloqueo) antes del efecto. Se prueba con un patrón revocado y con una alerta tocada.
- D3/D6: la pausa queda registrada y auditada; el aviso inmediato por SOAR está pendiente.

**Los resultados de canarios del laboratorio** (`research/soc-lab`, F2 E4) **son un modelo de
diseño, no evidencia.** Prueban la huella real contra una decisión *modelada*. Este documento
define las pruebas de contrato que la etapa E debe pasar contra el **motor real**, en CI (motor
en memoria) y en sombra (canarios inyectados con registro sellado).

## Reglas comunes

- **Fixture base:** un patrón `active` de huella `fine`, aprobado por dos personas, vigente
  (`expires_at` en el futuro), P4, severidad `low`, regla de bajo impacto, contexto vigente
  (listas de activos e identidades pobladas, calendario de cambios confirmado) y modo `active`
  en esa regla.
- **Cada caso** cambia una sola cosa respecto de la fixture base, salvo que se indique otra cosa.
- **Se verifica:**
  1. decisión (`AUTO_CLOSE`, `ESCALATE(<motivo>)`, `DEMOTE`, `GROUP` o `NONE`);
  2. efectos (estado de la alerta, `closure_origin`, contadores del patrón, cola de revisión);
  3. fila en `learning_decisions` con `checks` que explica el resultado;
  4. auditoría.
- **Invariante global:** ningún caso marcado «no autocierra» puede terminar con la alerta en
  `closed`. Si eso ocurre, la prueba falla y bloquea el despliegue.
- **Canarios en sombra:**
  - el registro sellado de canarios no lo ve el motor;
  - el canario usa tenant o fuente sintética;
  - queda excluido de métricas y avisos;
  - lo cierra el verificador tras el veredicto.

## Casos (38)

### A. Casi-coincidencia de la huella (no autocierra; escala con DRIFT)

| # | Cambio respecto de la base | Decisión esperada | Efectos |
|---|---|---|---|
| A1 | Otro hash del proceso | `ESCALATE(DRIFT)` con `drift = {sha256}` | Alerta abierta; patrón sin cambios |
| A2 | Otro destino (dominio) | `ESCALATE(DRIFT)` · `{destination}` | ídem |
| A3 | Otro puerto de destino | `ESCALATE(DRIFT)` · `{destinationPort}` | ídem |
| A4 | Otro usuario | `ESCALATE(DRIFT)` · `{user}` | ídem: una cuenta no hereda el patrón |
| A5 | Otro equipo (agentId) | `ESCALATE(DRIFT)` · `{host}` | ídem |
| A6 | Otro proceso padre | `ESCALATE(DRIFT)` · `{parentImage}` | ídem |
| A7 | Otra línea de comando con significado distinto | `ESCALATE(DRIFT)` · `{commandLine}` | ídem |
| A8 | Otro nombre aleatorio de temporal (`tmpCBBF` → `tmp4F2A`), todo lo demás igual | `AUTO_CLOSE` | Contraprueba: misma huella por normalización v2 |
| A9 | Misma regla y comportamiento, otro tenant | `NONE` | El tenant entra en la huella; aislamiento |

### B. Guardas sobre la misma huella (no autocierra)

| # | Cambio | Decisión esperada |
|---|---|---|
| B1 | Prioridad P2 (o P1) | `ESCALATE(GUARD_PRIORITY)` |
| B2 | P3 | Como máximo `DEMOTE`; nunca `AUTO_CLOSE` |
| B3 | Severidad normalizada `high` en una P4 | `ESCALATE(GUARD_SEVERITY)` |
| B4 | Activo en la lista de críticos (vigente **ahora**, no al aprobar) | `ESCALATE(GUARD_CRITICAL_ASSET)` |
| B5 | Identidad privilegiada o break-glass | `ESCALATE(GUARD_PRIVILEGED)` |
| B6 | Táctica MITRE de alto impacto o regla marcada `never_suppress` | `ESCALATE(GUARD_IMPACT)` |
| B7 | IP en lista de inteligencia (`b89-ti-*`) | `ESCALATE(GUARD_THREAT_INTEL)` |
| B8 | Alerta en una cadena de compromiso o con ≥ 3 alertas relacionadas | `ESCALATE(GUARD_CORRELATION)` |
| B9 | Alerta vinculada a un incidente | `ESCALATE(GUARD_INCIDENT)` |
| B10 | Fuente no sana o evidencia incompleta | `ESCALATE(GUARD_SOURCE)` |
| B11 | Dentro de una ventana de cambio que afecta al activo | `ESCALATE(GUARD_CHANGE_WINDOW)`, prioridad intacta |
| B12 | Lista de activos críticos vacía o vencida (fail-closed) | `ESCALATE(GUARD_CONTEXT)`, prioridad intacta |

### C. Estado del patrón y de la configuración

| # | Cambio | Decisión esperada |
|---|---|---|
| C1 | Patrón con `expires_at` vencido según el **reloj del servidor**, aunque la alerta ocurrió antes | No autocierra |
| C2 | Patrón `paused` o `revoked` | No autocierra |
| C3 | Kill switch global activo | `NONE`, sin efectos |
| C4 | Kill switch de la regla activo | `NONE`, sin efectos |
| C5 | Modo `shadow` en la regla | Decisión `AUTO_CLOSE` registrada, **sin** cambio de estado |
| C6 | Modo `dry_run` | Crea `learning_reviews(dry_run_approval)`; la alerta sigue abierta |
| C7 | Huella `coarse` idéntica al patrón | Nunca `AUTO_CLOSE` (como máximo `GROUP` o `DEMOTE`) |
| C8 | Patrón aprendido con el normalizador v1 y alerta v2 | `NONE` (no coincide; el patrón está `superseded`) |
| C9 | Colisión forzada: mismo `fingerprint`, `components` distintos | `ESCALATE(FINGERPRINT_COLLISION)` |
| C10 | El patrón se revoca **entre** la decisión y la escritura del efecto | No autocierra: la transacción final vuelve a comprobarlo |

### D. Radio de daño, muestreo y trazabilidad

| # | Cambio | Esperado |
|---|---|---|
| D1 | Autocierres del patrón por encima del tope diario | El exceso va a una persona; ninguno se cierra |
| D2 | N autocierres seguidos sin revisión humana | La siguiente alerta queda en revisión obligatoria |
| D3 | Ráfaga por encima del límite de volumen o alarma de deriva | Patrón `paused`, `ESCALATE(RATE_LIMIT)` y aviso inmediato |
| D4 | Alerta seleccionada por la PRF con clave | Se autocierra **y** entra en `learning_reviews(quality_sample)`; la selección es reproducible con la clave e idéntica en dos ejecuciones |
| D5 | Cierre del motor | `closure_origin = learning_engine`; **no** suma confirmaciones al patrón |
| D6 | Revisión de muestra con `TP_REAL` | Patrón `paused`, reversión registrada y aviso |
| D7 | `POST revert` sobre un autocierre | La alerta vuelve a `acknowledged`, `learning_reversals` registra quién y por qué y cuenta como desacuerdo |

## Criterio de aceptación de la etapa E

- Los 38 casos pasan en CI contra el motor en memoria y la integración con Postgres.
- En sombra, con canarios reales durante ≥ 21 días: 0 casos «no autocierra» cerrados y el 100 %
  de A8 reconocidos.
