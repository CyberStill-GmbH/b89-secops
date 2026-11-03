# 08 · Frontend unificado

> Leyenda: **[verificado]**, **[sin verificar]** (existe en el repo, no probado en AWS) y
> **[propuesto]**. Arquitectura general en [02](02-arquitectura.md).

## Sistema visual B89

![Monograma oficial B89 del formato de presentación 2026](brand/assets/logo/b89-mark-gradient.png)

La guía [Identidad visual B89 - Frontend](brand/b89-visual-identity.md) fija Satoshi Medium/Bold, la paleta oficial de siete colores, variantes de logotipo, Remi y Mundi, y la galería de ilustraciones recortadas de la presentación. El frontend solo muestra los recursos gráficos oficiales de B89.

## Decisión

El **dashboard de Wazuh es el shell**. Lo que ya hace bien no se rehace: Discover, dashboards,
agentes, vulnerabilidades, FIM, MITRE, reglas y gestión de índices. B89 aporta casos, gobierno
y cambios en vivo **dentro** del mismo shell, como plugin nativo de OpenSearch Dashboards (`b89_ops`).

**Servido tras CloudFront [propuesto]:** el borde único es CloudFront + WAF. `/` va al Dashboard
(origen: el nodo Wazuh en EC2, por NLB/ALB privado con origen restringido a CloudFront) y `/api`
va a API Gateway HTTP → Lambda. El navegador sigue viendo un solo origen, así que la sesión
(cookie, CSRF) funciona *same-origin* como hoy. Ni el Dashboard ni el Indexer se exponen a
Internet.

## Estado del repositorio (revisado el 2026-10-22; migración a AWS propuesta)

La fuente versionada del frontend de demo es el overlay `wazuh/dashboard/` de este repositorio,
compilado contra **Wazuh 4.14.8 / OpenSearch Dashboards 2.19.6**. El repositorio externo
`b89-dashboard` y su base Wazuh 5.x / OSD 3.x son una línea de migración separada: no se mezclan
en el artefacto actual por incompatibilidad de plugins y protocolos.

| Pieza | Dónde | Estado (código) |
| --- | --- | --- |
| Marca B89 y navegación de Wazuh | `wazuh/dashboard/patches/`, `assets/`, `plugins/b89_ops` | Overlay fijado a OSD 2.19.6 |
| Login B89 y rutas de dashboard | `plugins/b89_ops/server` y `wazuh/edge/` | Se conserva el flujo de identidad existente |
| Vistas SOC: alertas, incidentes, notificaciones, auditoría, usuarios/sesiones y fuentes | `plugins/b89_ops/public/components/` | Compiladas dentro del dashboard |
| Solicitud y aprobación de roles | `plugins/b89_ops/public/components/access_view.tsx` + `apps/api/src/soc/admin-role-grants.controller.ts` | En rama de trabajo; pendiente PR, CI y despliegue |
| Cliente de la API (same-origin, cookie, CSRF, contrato) | `plugins/b89_ops/public/api/` y `common/api_contract.ts` | CSRF se obtiene de la sesión B89 |
| Edge nginx y Security plugin (proxy auth) | `wazuh/edge/` y `wazuh/indexer/security/` | Fuente del despliegue en este repo. En AWS, CloudFront hace de borde público; nginx queda solo como proxy auth local del nodo [propuesto] |

**`apps/web` se eliminó** (`4eab88f`): sus vistas viven en el plugin `b89_ops`.

## Contrato frontend ↔ backend (verificado contra `apps/api`)

| Llamada del plugin | Endpoint del backend | Resultado |
| --- | --- | --- |
| `GET /auth/session` (identidad, capacidades, `csrfToken`) | `auth.controller.ts:111` | ✓ Mismos campos |
| `GET /alerts?status&priority&q&pageSize=50&cursor` | `soc.controller.ts:97` | ✓ Filtros y paginación (máx. 200) |
| `GET /alerts/:id` → `{alert}`; `POST /alerts/:id/commands {name, expectedRevision, …}` | `:144`, `:155` | ✓ Comandos, veredictos y estados iguales |
| `POST /incidents {alertId, title, severity, summary, expectedAlertRevision}` | `:190` | ✓ |
| `GET /incidents`, `GET /incidents/:id`, `POST /incidents/:id/commands` | `:287`, `:232`, `:326` | ✓ |
| Tareas, notas y timeline (`pageSize=200`) | `incident-work.controller.ts:111–279` | ✓ Incluye `openRequiredCount` y `transitions` |
| `GET /audit/events`, `GET /audit/verify` | `audit.controller.ts` | ✓ |
| `GET /admin/users`, `GET /admin/sessions`, `POST /admin/sessions/:ref/revoke {reason, expectedRevision}` | `admin-*.controller.ts` | ✓ |
| `GET /sources/health` → `{checkedAt, sources}` | `sources-health.controller.ts` | ✓ |
| Login `/api/auth/start?returnTo=`, retorno con `authError`, `correlationId` y `sessionNotice=superseded` | `auth.controller.ts`, `return-to.ts` | ✓ `safeReturnTo` acepta rutas del dashboard |
| Logout: `/b89/logout` → `GET /auth/session` (CSRF) → `POST /auth/logout` | `auth.controller.ts:152` | ✓ |
| Proxy auth: `GET /api/auth/introspect` → 204 con `x-b89-user` y `x-b89-roles` | `apps/api/src/soc/auth.controller.ts`, edge y Security plugin | Verificar con el runbook de release en el entorno objetivo; el build no prueba identidad en vivo |
| Administración de roles: grant, solicitud, bandeja y aprobación | `/api/admin/users/:oid/role-grant`, `/api/admin/users/:oid/role-requests`, `/api/admin/role-requests` | En esta rama; no afirmar que está desplegado hasta aprobación del PR y migración de BD |

**Endpoints del backend que el plugin todavía no usa:**

| Endpoint | Para qué | Prioridad |
| --- | --- | --- |
| `GET /api/changes` (long-poll; SSE en fase 2) | Cambios en vivo, el diferencial frente al auto-refresh de OSD | **Alta** |
| `GET /api/notifications`, `POST /api/notifications/:id/acknowledge` | Bandeja y acuse humano (N6) | Alta |
| `/api/me/push/*` | Avisos en el dispositivo | Media |
| `GET /api/incidents/:id/alerts` | Alertas vinculadas en una sola llamada | Media |
| `GET /api/operations/health` | Salud operativa | Media |
| `GET /api/admin/users/:oid` (sesiones de una persona) | Detalle para revocar | Baja |
| `/api/admin/users/:oid/role-requests` + `/api/admin/role-requests/:id/{approve,reject}` | Solicitud con SoD, aprobación separada, auditoría y revocación al completar ([04](04-identidad-y-acceso.md)) | En rama; la aprobación privilegiada requiere step-up aún no disponible |

## Riesgos detectados

1. **Compatibilidad de versión.** Mantener el artefacto de demo fijado a Wazuh 4.14.8 / OSD 2.19.6.
   La migración al repositorio `b89-dashboard` y a Wazuh 5.x / OSD 3.x requiere una rama y un
   ciclo de compatibilidad propios, con sus plugins recompilados y pruebas de integración; no forma
   parte del build de demo actual.
2. **Colisiones de rutas `/api/*`.** OSD, el plugin de Wazuh y los plugins incluidos usan sus
   propias `/api/*`. El edge enruta a B89 solo una allowlist de prefijos. **Hay que verificar
   `/api/notifications`:** el plugin *Notifications* de OSD (que el fork incluye vía
   `wazuh-dashboard-notifications`) usa ese prefijo. Si colisiona, se restringe la regla de nginx
   a las rutas exactas de B89 (`/api/notifications` y `/api/notifications/<uuid>/acknowledge`) o
   se renombra la ruta del backend.
3. **Dos edges.** `b89/deploy/nginx/b89-dashboard.conf` (fork, apunta a KrakenD) y
   `wazuh/edge/b89-edge.conf` (este repo, directo a la API). **Fuente de verdad:** `wazuh/` en este
   repo; el fork conserva solo código. En AWS [propuesto] el borde público es CloudFront (rutas `/` y
   `/api`) y la allowlist de prefijos `/api/*` se traslada a sus *behaviors*; KrakenD se retira.
4. **Roles distintos.** El fork da `wazuh-archives-*` (raw) también al analista. Este repo lo
   reserva al líder (minimización, N2). Hay que unificar en `wazuh/indexer/security/`.
5. **Sin cambios en vivo.** El plugin carga al montar y no consume `/api/changes`, así que la cola
   no se actualiza sola.
6. **Proxy auth con la API en Lambda [propuesto].** Cada petición al Dashboard dispara
   `GET /api/auth/introspect`. Con Lambda añade latencia y arranques en frío: se mantiene el
   caché de 5 s en el edge del nodo y se evalúa concurrencia provisionada para esa ruta. La
   revocación en ≤ 5 s debe re-medirse en este camino ([04](04-identidad-y-acceso.md)).

## Vínculos entre SIEM y casos

Desde una alerta B89 se abre Discover filtrado por entidad y ventana
(`app/data-explorer/discover#?_q=(query:'data.office365.UserId:"…"')`). Desde un documento de
Wazuh, un *field formatter* del plugin abre `/app/b89-alerts?id=<id>`.

## Cambios en vivo

- **Backend hoy:** long-poll `GET /api/changes?after=<cursor>` (2,5 s, por secuencia de auditoría)
  en `apps/api/src/soc/changes.controller.ts` [sin verificar en Lambda].
- **En Lambda [propuesto]:** el long-poll de 2,5 s cabe en el límite de API Gateway HTTP (30 s) y
  se mantiene, pero cada espera ocupa una invocación. El SSE `GET /api/changes/stream` **no es
  viable** sobre API Gateway HTTP (no hace *streaming* de respuesta). Opciones a decidir en
  [10](10-decisiones.md): Lambda Function URL con *response streaming* detrás de CloudFront, o
  API Gateway WebSocket. Hasta decidir, se queda el long-poll. Sin Valkey, el long-poll consulta la
  secuencia de auditoría con un intervalo mayor al de 400 ms actual ([11](11-cache-y-colas.md)).
- El plugin lo usaría para refrescar la cola y los casos, el contador del header y avisos
  `core.notifications.toasts` con las alertas P1 en cualquier pantalla (aún no lo consume).
- OSD por sí mismo solo tiene *auto-refresh* por intervalo en Discover y en los dashboards.
