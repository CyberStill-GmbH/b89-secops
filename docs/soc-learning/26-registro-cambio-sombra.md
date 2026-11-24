# Registro de cambio · encender la sombra del motor de aprendizaje (borrador para completar)

Plantilla para `docs/22-registro-de-cambios.md`. **Nada de esto se ejecutó.** Los campos entre `<…>`
los completa el dueño. Los comandos van en el orden en que se ejecutan; ninguno contiene secretos.

| Campo | Valor |
|---|---|
| Cambio | Encender el motor de aprendizaje SOC en **sombra** (sin efectos sobre alertas) |
| Rama / commit | `feat/soc-learning-verify` @ `<commit>` (tras merge con la otra sesión) |
| Aprobado por | `<dueño del producto>` y `<líder SOC>` |
| Ventana | `<fecha y hora (Lima)>` |
| Observadores | `<líder SOC>` (informe diario), `<plataforma>` (salud del motor) |
| Evidencia previa | `verify-engine-out/` en verde: Postgres real, cada commit, suites ×3, carga, canarios |
| Vuelta atrás | `B89_LEARNING_ENABLED=false` y reinicio (ver abajo) |

## 1. Antes (comprobaciones)

- [ ] `verify-engine.sh` completo en verde y adjunto.
- [ ] Merge con la otra sesión hecho y suites ×3 integradas en verde.
- [ ] Canarios en staging al 100 % (`learning-canaries.integration.spec.ts` contra el Postgres de staging).
- [ ] Dos o más aprobadores designados (`B89_SOC_LEARNING_APPROVERS`).
- [ ] Canal de notificación configurado (`B89_TEAMS_WORKFLOW_URL`).

## 2. Clave de muestreo propia de la sombra

```bash
openssl rand -base64 48   # guardar en el gestor de secretos; nunca en el repo ni en logs
```

Registrar solo su identificador (`B89_LEARNING_SAMPLING_KEY_ID`, p. ej. `shadow-<aaaa-mm>`) y su
fecha (`B89_LEARNING_SAMPLING_KEY_ISSUED_AT`).

## 3. Configuración

```dotenv
B89_LEARNING_ENABLED=true
B89_LEARNING_MAX_MODE=shadow
B89_LEARNING_ACTIVE_RULES=
B89_LEARNING_SAMPLING_KEY=<del gestor de secretos>
B89_LEARNING_SAMPLING_KEY_ID=<identificador>
B89_LEARNING_SAMPLING_KEY_ISSUED_AT=<aaaa-mm-dd>
B89_SOC_LEARNING_APPROVERS=<persona-1>,<persona-2>
B89_SOC_CLOSURE_REASON_REQUIRED=true
```

## 4. Despliegue

```bash
# Migraciones como b89_migrator y endurecimiento de permisos
pnpm --filter @b89/database exec prisma migrate deploy --schema prisma/schema.prisma
psql "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 -f platform/database/bootstrap/post-migrate.sql
# Imagen del API con la configuración de arriba; reinicio.
# Monitor de plataforma: reinstalar para el chequeo `learning` y los grants de b89_monitor
bash wazuh/platform-monitoring/install-platform-monitoring.sh
```

## 5. Contexto (para que la sombra produzca evidencia)

Desde la consola o `POST /api/learning/context` (dos aprobadores designados disponibles):
activos críticos, identidades privilegiadas, break-glass y la confirmación del calendario de
cambios (≤ 30 días). Sin ellos el motor escala todo y el reloj de 21 días no cuenta.

## 6. Comprobación posterior

- `GET /api/learning/health` → `OK` (o solo avisos esperados: `SOURCE_NOT_HEALTHY` mientras se mide).
- Fila nueva en `soc_learning_config_events` con `max_mode = shadow`.
- Chequeo `learning` del monitor sin problemas.
- Al día siguiente: `GET /api/learning/shadow-report?period=daily`.

## 7. Vuelta atrás

```dotenv
B89_LEARNING_ENABLED=false
```

Reiniciar el API. La ingesta no cambia; la cola deja de llenarse; las tablas quedan como evidencia.
