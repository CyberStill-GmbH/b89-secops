-- B89 SecOps — endurecimiento después de cada `prisma migrate deploy`.
--
-- Los default privileges de `roles.sql` dan SELECT/INSERT/UPDATE al runtime sobre toda tabla
-- nueva. Estas excepciones se reaplican tras cada migración porque las tablas que cubren
-- pueden crearse en ella. Lo ejecuta `b89_migrator`, dueño de las tablas. Idempotente.

DO $hardening$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'b89_soc_runtime') THEN
    -- Auditoría append-only: el trigger rechaza UPDATE/DELETE y además el permiso no existe.
    IF to_regclass('public.audit_events') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_events FROM b89_soc_runtime;
    END IF;
    -- Bitácora de incidente append-only (S5-D8): solo SELECT e INSERT.
    IF to_regclass('public.incident_notes') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.incident_notes FROM b89_soc_runtime;
    END IF;
    -- Bitácora de salud de fuentes append-only (Sprint 5 · fase 2).
    IF to_regclass('public.source_health_transitions') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.source_health_transitions FROM b89_soc_runtime;
    END IF;
    -- Aprendizaje SOC · etapas D/E. Firmas, transiciones, decisiones y reversiones son
    -- append-only (trigger + permiso). Patrones y revisiones cambian de estado (CAS), pero
    -- nunca se borran: sin DELETE ni TRUNCATE.
    IF to_regclass('public.soc_learning_pattern_approvals') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.soc_learning_pattern_approvals FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_pattern_events') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.soc_learning_pattern_events FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_decisions') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.soc_learning_decisions FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_reversals') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.soc_learning_reversals FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_config_events') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.soc_learning_config_events FROM b89_soc_runtime;
    END IF;
    -- Cola y latidos: cambian de estado, pero no se borran desde el API.
    IF to_regclass('public.soc_learning_jobs') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_jobs FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_worker_heartbeats') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_worker_heartbeats FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_engine_state') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_engine_state FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_rule_enablements') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_rule_enablements FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_context_entries') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_context_entries FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_patterns') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_patterns FROM b89_soc_runtime;
    END IF;
    IF to_regclass('public.soc_learning_reviews') IS NOT NULL THEN
      REVOKE DELETE, TRUNCATE ON public.soc_learning_reviews FROM b89_soc_runtime;
    END IF;
    -- El historial de migraciones es solo lectura para el API.
    IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
      REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public._prisma_migrations FROM b89_soc_runtime;
      GRANT SELECT ON public._prisma_migrations TO b89_soc_runtime;
    END IF;
    -- Historial de Bunny: única tabla con borrado real (la persona borra lo suyo y la retención
    -- purga lo inactivo). DELETE sí; TRUNCATE no.
    IF to_regclass('public.assistant_conversations') IS NOT NULL THEN
      GRANT DELETE ON public.assistant_conversations TO b89_soc_runtime;
      REVOKE TRUNCATE ON public.assistant_conversations FROM b89_soc_runtime;
    END IF;
    -- Archivos de Bunny (informes): efimeros; el API purga los vencidos. DELETE si; TRUNCATE no.
    IF to_regclass('public.assistant_artifacts') IS NOT NULL THEN
      GRANT DELETE ON public.assistant_artifacts TO b89_soc_runtime;
      REVOKE TRUNCATE ON public.assistant_artifacts FROM b89_soc_runtime;
    END IF;
    -- Bitácora de progreso del Analista IA append-only (docs/27): solo SELECT e INSERT.
    IF to_regclass('public.ai_investigation_events') IS NOT NULL THEN
      REVOKE UPDATE, DELETE, TRUNCATE ON public.ai_investigation_events FROM b89_soc_runtime;
    END IF;
  END IF;
END
$hardening$;
