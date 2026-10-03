-- TrustRelay v1.0 maximum-hardening pass
-- Remove the last raw anonymous PostgREST RPC entry points.
-- Public credential verification/JWKS remain available only through purpose-built Edge Functions.

do $$
declare f record;
begin
  for f in
    select p.oid::regprocedure as signature, p.proname
    from pg_proc p
    join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.proname in (
        'trustrelay_assurance_rank_v08',
        'trustrelay_health_v05',
        'trustrelay_webhook_event_catalog_v09'
      )
  loop
    execute format('revoke execute on function %s from public, anon', f.signature);
    execute format('grant execute on function %s to service_role', f.signature);
    if f.proname in ('trustrelay_assurance_rank_v08','trustrelay_webhook_event_catalog_v09') then
      execute format('grant execute on function %s to authenticated', f.signature);
    end if;
  end loop;
end $$;
