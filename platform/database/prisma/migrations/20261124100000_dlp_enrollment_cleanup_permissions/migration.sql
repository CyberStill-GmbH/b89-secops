BEGIN;

-- The API runtime has no general DELETE grant. These SECURITY DEFINER functions provide only
-- the two DLP cleanup operations needed by the enrollment flow, bounded by tenant and state.
CREATE FUNCTION public.dlp_cleanup_expired_enrollment_tokens(p_tenant_id TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM public.dlp_endpoints
   WHERE tenant_id = p_tenant_id
     AND enrolled_at IS NULL
     AND enrollment_expires_at <= clock_timestamp();
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;

ALTER FUNCTION public.dlp_cleanup_expired_enrollment_tokens(TEXT) OWNER TO b89_migrator;
REVOKE ALL ON FUNCTION public.dlp_cleanup_expired_enrollment_tokens(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.dlp_cleanup_expired_enrollment_tokens(TEXT) TO b89_soc_runtime;

CREATE FUNCTION public.dlp_cancel_enrollment_token(p_tenant_id TEXT, p_id TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM public.dlp_endpoints
   WHERE tenant_id = p_tenant_id
     AND id = p_id
     AND enrolled_at IS NULL;
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count = 1;
END;
$$;

ALTER FUNCTION public.dlp_cancel_enrollment_token(TEXT, TEXT) OWNER TO b89_migrator;
REVOKE ALL ON FUNCTION public.dlp_cancel_enrollment_token(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.dlp_cancel_enrollment_token(TEXT, TEXT) TO b89_soc_runtime;

COMMIT;
