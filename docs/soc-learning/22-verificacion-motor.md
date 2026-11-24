# Verificación independiente del motor de aprendizaje (fase 1)

Fecha: 2026-11-24. Rama `feat/soc-learning-verify` (worktree limpio `C:\projects\b89-wt-verify`,
creado desde `f14b6f7`). Sin push. **Nada se encendió.**

**Estado: hecho, pero NO verificado en PostgreSQL real.** La estación de desarrollo no soporta Docker
ni una suite completa; el dueño corre la verificación en otra máquina con un solo comando (§8). Lo que
figura como «memoria» o «PGlite» se ejecutó aquí; lo marcado «pendiente» está escrito y tipado, pero
no ejecutado.

## 1. Correcciones a reportes anteriores

| # | Qué dije antes | Qué era cierto | Corregido en |
|---|---|---|---|
| C1 | «La suite completa pasa (1767 pruebas)» | Cierto para unitarias; las specs de integración se **omitieron** (sin `DATABASE_URL`). Nada de D/E corrió en PostgreSQL real. | — (este documento) |
| C2 | (implícito) el job de CI `soc-learning-postgres` cubría el aprendizaje | Exigía **exactamente 3** migraciones de aprendizaje; con D y E hay 5 (ahora 6): **habría fallado**. | `8407bba` |
| C3 | (implícito) el rollback con resguardo cubría el aprendizaje | Solo conocía A–C: no revisaba ni borraba las tablas de D/E. | `8407bba` |
| C4 | «Firmas, eventos, decisiones y reversiones son append-only» | Solo por trigger: el rol del runtime **tenía UPDATE** (privilegios por defecto). | `9e78c70` |
| C5 | «En `schema.prisma` no se perdió nada de la otra sesión» | El contenido no cambió, pero **revertí espacios en blanco sin commit que no eran míos** (realineado de `prisma format`). Infringe la regla de no tocar líneas sin commit ajenas. | No se puede deshacer sin la copia original; la otra sesión puede volver a formatear. |

## 2. Hallazgos de la revisión adversarial

Cada hallazgo es una prueba (`modules/soc/test/learning-engine.adversarial.spec.ts`, salvo indicación).
«Falla antes» = la prueba falla con el código anterior a la corrección (comprobado).

| Id | Ruta revisada | Resultado | Prueba | Estado | Verificado en |
|---|---|---|---|---|---|
| H1 | Reloj leído **antes** del bloqueo: una espera larga dejaba cerrar con un patrón ya vencido | **Defecto.** El reloj se lee tras bloquear el patrón | H1 (falla antes) | corregido `a240cf7` | memoria |
| H2 | Excepción a mitad del efecto (cierre escrito, decisión no) | Correcto: la transacción revierte cierre y decisión; la alerta queda abierta | H2 | ok | memoria |
| H3 | Hora del evento (la controla el emisor) | Correcto: vigencia y topes usan el reloj del servidor | H3 | ok | memoria |
| H4 | Dato ausente: sin `rule_key` | Correcto: nunca supera la sombra | H4 | ok | memoria |
| H5 | Reintentos y duplicados | Correcto: una decisión por alerta (índice único); el reintento no tiene efecto | H5; PG «doble decisión» | ok | memoria · Postgres pendiente |
| H6 | Reapertura manual de un cierre del motor por `/alerts/:id/commands` | **Defecto.** No registraba reversión ni pausaba el patrón: la señal de vuelta atrás se perdía | H6 (falla antes) | corregido `a240cf7` | memoria |
| H7 | `lock_timeout` de 2 s bajo ráfaga sobre un mismo patrón | Fail-safe (la alerta queda abierta, sin decisión) **pero silencioso**: solo `onDispatchError` | PG «tope bajo carrera» (admite fallos, nunca un cierre de más) | abierto → fase 2 (cola, métricas) | Postgres pendiente |
| H8 | Fallo entre el commit de la ingesta y la evaluación (caída del proceso) | Fail-safe, pero esa alerta **nunca** se evalúa | — | abierto → fase 2 (cola con reintento) | — |
| H9 | Aceptar una propuesta de dry-run no repite las guardas (solo patrón vigente y alerta intacta) | Riesgo aceptado: una persona aprueba cada cierre; un TP nuevo lo revoca el siguiente refresco (≤ 15 min) | — | documentado | — |
| H10 | Kill switch y techo solo por variables de entorno | Efecto recién al reiniciar: el tiempo hasta el efecto es un reinicio | — | abierto → fase 3 (habilitación en base) | — |
| H11 | Orden de llegada manipulado (F3a) | Los topes reducen poco si el atacante elige el orden: defensa secundaria | F3a E4 (sintético) | documentado | laboratorio |
| H12 | Un defecto de código que intentara autocerrar P1–P3 | Nueva barrera en base: `closure_origin = learning_engine` exige `priority = P4` | PG «la base rechaza»; PGlite | hecho `82a454a` | PGlite · Postgres pendiente |

## 3. Cuenta `svc:b89-soc-learning`

| Comprobación | Prueba | Verificado en |
|---|---|---|
| No aprueba, rechaza, revoca, reanuda ni renueva (aunque tuviera capabilities de líder) | adversarial «no aprueba…» | memoria |
| Sin capabilities (como corre de verdad) ni pasa la autorización | adversarial | memoria |
| No resuelve revisiones ni revierte decisiones | adversarial | memoria |
| No cierra P1/P2 ni clases de alto impacto | contrato B1/B6 + adversarial + CHECK en base | memoria · PGlite |
| No cambia configuración ni listas | no hay superficie: la configuración es solo de entorno y el servicio no tiene capabilities | revisión de código |
| Sus cierres no cuentan como evidencia: evidencia de patrones, conteo de FP por entidad (`alertStats`), refresco | adversarial «ninguna ruta de conteo» | memoria |
| La base rechaza al servicio como firmante o como autor de una reversión | spec de roles | Postgres pendiente |

Rutas de conteo revisadas: `learningEvidence` (solo `origin = human`), `alertStats` (`DEFAULT_FALSE_POSITIVE_ORIGINS = ['human']`),
`refreshLearningPatterns` (usa `learningEvidence`). `listClosureMemory` es de la otra sesión y no está
commiteada: queda en el contrato de coordinación (debe filtrar `origin = human`).

## 4. PostgreSQL real: migraciones, rollback, stores y concurrencia

Todo escrito y tipado; **ejecución pendiente** en la máquina del dueño.

| Pendiente | Estado | Evidencia | Verificado en |
|---|---|---|---|
| 6 migraciones de aprendizaje desde cero | escrito | `scripts/ci/soc-learning-postgres.sh` paso 1 | PGlite (18/18) · Postgres pendiente |
| Desde el estado previo (etapa C con datos → D/E) | escrito | paso 4b | Postgres pendiente |
| Rollback completo y de D/E, con negativa si hay datos | escrito | pasos 3, 3b, 4c | Postgres pendiente |
| Stores Prisma (patrones, evidencia, preparación, refresco de punta a punta) | escrito | `learning-postgres.integration.spec.ts` | Postgres pendiente |
| Dos firmantes a la vez | escrito | ídem | Postgres pendiente |
| Reanudar y renovar a la vez | escrito | ídem | Postgres pendiente |
| Tope por hora y diario bajo carrera de 50 (nunca excedidos; pausa por tope) | escrito | ídem | Postgres pendiente |
| 50 ingestas simultáneas con la misma huella | existente (etapa C) | `postgres-soc.integration.spec.ts` | Postgres pendiente |
| Doble decisión del motor sobre una alerta (20 a la vez) | escrito | ídem | Postgres pendiente |
| Reversiones concurrentes (10 revert + reapertura manual) | escrito | ídem | Postgres pendiente |
| Revisión resuelta dos veces a la vez | escrito | ídem | Postgres pendiente |

## 5. Inmutabilidad y roles

| Rol | Qué se prueba | Estado | Verificado en |
|---|---|---|---|
| `b89_soc_runtime` (API **y motor**) | sin UPDATE/DELETE/TRUNCATE en firmas, eventos, decisiones, reversiones; sin DELETE/TRUNCATE en patrones y revisiones; sin DDL ni desactivar triggers | escrito | Postgres pendiente |
| `b89_migrator` (dueño) | los triggers rechazan igual UPDATE/DELETE/TRUNCATE | escrito | PGlite (triggers) · Postgres pendiente |
| Solo lectura (rol creado por la spec) | SELECT sí; escribir no | escrito | Postgres pendiente |
| **Rol propio del motor** | **No existe.** El motor corre en el proceso del API con `b89_soc_runtime`, que puede más de lo que el motor necesita | hallazgo abierto | — |

Propuesta para el rol del motor (fase 2, junto con sacarlo del camino de la ingesta): `b89_soc_learning_engine`
con SELECT en alertas, huellas, patrones, decisiones y revisiones; INSERT en decisiones, revisiones,
cierres, auditoría y outbox; UPDATE solo en `soc_alerts` (cierre) y `soc_learning_patterns` (pausa); nada más.

## 6. Higiene

**Commits de esta fase** (sobre `f14b6f7`): `8407bba` CI y rollback D/E · `9e78c70` mínimo privilegio ·
`a240cf7` reloj y reapertura manual · `82a454a` CHECK P4 en base · `a18b488` specs de PostgreSQL ·
`541a2cc` comando de verificación · este documento.

**Cada commit aislado:** pendiente (`STEPS=commits`, `git rebase --force-rebase --exec`). Aquí se tipó cada
paquete tocado y se corrió `modules/soc` (207/207) en el estado final, no por commit.

**Líneas de archivos compartidos.** Las mías están todas commiteadas; las de la otra sesión siguen sin commit:

| Archivo | Mías (commit) | De la otra sesión (sin commit) |
|---|---|---|
| `apps/api/src/bootstrap.ts` | `learningFrom()`, import de `DEFAULT_ENGINE_SETTINGS`, `loadLearningEngine`, `loadSocLearningApprovers`, `...learningFrom(environment)` (`112d6f8`) | `caseFieldReveal`, `governedAssistant` |
| `apps/api/src/runtime/secops-runtime.ts` | `LearningRuntimeOptions`, `learning?`, `learningLoop`, `learningSourceState`, métodos de aprendizaje, `evaluateLearning` tras la ingesta, imports (`112d6f8`) | `caseFieldReveal`, `governedAssistant` (opción y getters) |
| `apps/api/src/soc/soc.module.ts` | `LearningController` (`112d6f8`) | `CaseFieldsController` |
| `platform/database/bootstrap/post-migrate.sql` | REVOKE de las seis tablas de aprendizaje (`9e78c70`, rama verify) | REVOKE de `assistant_feedback_changes` |
| `platform/database/prisma/schema.prisma` | modelos D/E | ninguna hoy (ver C5) |

**Plan de integración sin pérdidas:** simulado con `git merge-file`; los cuatro archivos combinan sin
conflictos (normalizando CRLF). Orden propuesto en `COORDINACION-CLAUDE-CODEX.md`.

**Suites ×3:** pendiente en ambos modos (limpio con `STEPS=suites`; integrado, después del merge).

## 7. Riesgos y supuestos

- **Riesgo:** hasta correr §8, ninguna afirmación sobre PostgreSQL real es más que PGlite.
- **Riesgo (H7/H8):** con el motor en el camino de la ingesta, una ráfaga o una caída dejan alertas sin
  decisión y sin señal operativa. Bloqueante para la sombra (fase 2).
- **Supuesto:** la máquina de verificación tiene Docker, Node de `.nvmrc`, pnpm y `psql`.
- **Supuesto:** el CHECK P4 es compatible con datos existentes (ninguna alerta tiene hoy `closure_origin = learning_engine`).

## 8. Cómo correrlo (otra máquina)

```bash
git switch feat/soc-learning-verify        # o el worktree C:\projects\b89-wt-verify
bash scripts/soc-learning/verify-engine.sh  # postgres + commits + suites; registros en verify-engine-out/
```

Con un PostgreSQL ya disponible: `ADMIN_DATABASE_URL=postgresql://…/postgres STEPS="postgres suites" bash …`.

## 9. Qué necesito del dueño

1. Correr §8 y devolver `verify-engine-out/` (o el resumen): con eso esta tabla pasa a «Postgres real».
2. Que la otra sesión commitee sus cambios en los cuatro archivos compartidos, o aprobar el orden de merge.
3. Decidir el rol propio del motor (§5) para la fase 2.
