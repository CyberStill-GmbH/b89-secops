# Readiness operativa B89 SecOps Azure — 2026-10-26

Este registro separa los recursos comprobados en Azure de los perfiles que siguen
apagados. No certifica el SOC como operativo.

## Evidencia confirmada

| Área | Evidencia | Estado |
| --- | --- | --- |
| Terraform EUS2 | PR [#165](https://github.com/CyberStill-GmbH/b89-secops/pull/165), commit `46fc5bd`, workflow [40421595800](https://github.com/CyberStill-GmbH/b89-secops/actions/runs/40421595800) | Apply `foundation` exitoso; plan guardado: 3 altas, 0 destrucciones, 0 reemplazos. |
| PostgreSQL | Azure CLI: `psql-b89secopsdemoeus-3a2405f3`, East US 2, PostgreSQL 16, `Standard_D2s_v3`, estado `Ready` | Las bases `b89_secops` y `b89_jobs` existen. La segunda es una base PostgreSQL; no acredita un consumidor BullMQ. |
| Key Vault | ARM confirma `kv-b89secopsd-3a2405f3`, `Succeeded`, `PublicNetworkAccess=Disabled` | Se preservó el acceso privado. La lista de nombres no se pudo leer desde esta máquina porque no estaba dentro del private endpoint; no se consultaron valores. |
| Storage de datos | `b89secdemoeus23a2405f3`: `PublicNetworkAccess=Disabled`, `defaultAction=Deny`, acceso anónimo Blob deshabilitado | Red privada; los endpoints privados permanecen. |
| State Terraform | `b89secopseus23a2405f3`: `PublicNetworkAccess=Enabled`, `defaultAction=Allow`, `allowBlobPublicAccess=false`, TLS 1.2 | Acceso de red público autenticado, no anónimo; configuración requerida por el runner GitHub hospedado y expresamente habilitada para esta demo. Es una decisión de exposición que debe revisarse antes de producción. |
| Storage de releases | `b89demoeus2rel3a2405f3`: `PublicNetworkAccess=Enabled`, `defaultAction=Allow`, `allowBlobPublicAccess=false`, TLS 1.2; contenedor `siem-release` listado | Los blobs no permiten acceso anónimo a nivel de cuenta. El endpoint acepta tráfico autenticado desde redes públicas; no se leyó contenido ni una clave de cuenta. |
| Azure Container Registry | `b89secopsdemoeus3a2405f3`: `PublicNetworkAccess=Enabled`, `adminUserEnabled=false`, sin repositorios | Endpoint público que requiere autenticación; no hay artefactos runtime publicados. |
| Detecciones AD | PR [#159](https://github.com/CyberStill-GmbH/b89-secops/pull/159), commit `c96e35f`; Wazuh Manager 4.14.8 `logtest` y CI pasaron | Reglas locales 101300–101307, en modo observación. No se aplicaron al Manager ni a un dominio y no se instaló/configuró ningún agente o GPO. |
| DNS | No hubo cambios en Route 53, Azure DNS ni `app.jappi.net.pe` | Sin cutover. |

## No desplegado / no comprobado

- `siem_host=null`, `b89_respond_host=null` y `enable_runtime=false` en el environment
  `azure-demo-eus2`.
- `AZURE_EUS2_CONTAINER_IMAGES_JSON={}` y ACR sin repositorios al consultar el
  2026-10-26; no hay imágenes runtime para instalar.
- `AZURE_EUS2_KEY_VAULT_SECRET_IDS_JSON={}`. No se cargaron ni leyeron secretos;
  tampoco se verificó desde el private endpoint qué nombres ya existen en el vault.
- La red pública autenticada está habilitada en state Storage, release Storage y ACR;
  el acceso anónimo a blobs está deshabilitado. El Storage de datos y Key Vault
  permanecen privados. No ampliar estos permisos para producción sin otro diseño.
- Sin Manager, Indexer, Dashboard B89, B89 Core, KrakenD, Valkey, host B89 Respond,
  OpenSearch de B89 Respond, agentes, Sophos, Cato, Graph/M365 o webhook real de Teams
  desplegados en EUS2.
- No hay prueba de login, permisos de usuarios, roles administrativos ni panel de
  gestión contra un runtime Azure.
- No hay estimación total validada del perfil SIEM/B89 Respond. Los USD 200/mes son
  alertas, no un límite que detenga o destruya recursos.

## Siguiente secuencia verificable

1. Generar artefactos inmutables y fijar sus digests en ACR; confirmar que las
   versiones son Wazuh 4.14.8 / OpenSearch Dashboards 2.19.6 y que el overlay B89
   y el Core incluidos coinciden con el commit de release.
2. Proveer referencias a secretos ya existentes mediante el private endpoint de
   Key Vault. Verificar únicamente metadatos requeridos, permisos mínimos y
   conectividad desde los hosts; no publicar valores en GitHub, Terraform ni logs.
3. Preparar perfil Terraform de `siem_host` y luego `b89_respond_host`, con CIDR, egress,
   discos y health checks explícitos. Revisar el plan remoto exacto, costo de lista,
   state y cualquier alta/cambio/destrucción antes del apply.
4. Desplegar primero Wazuh/B89 y verificar TLS, login, rol, API, migraciones,
   PostgreSQL y recepción de un evento sintético. Después probar M365, Sophos, Cato
   y Teams con aceptación real de cada proveedor.
5. Desplegar B89 Respond solo con imágenes y Compose fijados, secretos privados,
   persistencia y playbooks gobernados por B89; probar autorización por rol,
   SoD, idempotencia, callback y rollback.
6. Habilitar la colección de DC en un piloto autorizado, medir ruido y cobertura
   antes de extender reglas o agentes. DNS/TLS solo después de aprobar los smoke
   tests del runtime y el plan específico de cutover.
