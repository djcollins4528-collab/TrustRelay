-- TrustRelay v1.0 security hardening
-- Partner decision RPCs are implementation details behind trustrelay-partner-v07.
-- Keep service_role execution for the Edge function, but prevent direct PostgREST
-- callers from bypassing Edge API-key authentication, validation, and rate limiting.

do $$
declare f record;
begin
  for f in
    select p.oid::regprocedure as signature
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in (
        'trustrelay_prepare_decision_v05',
        'trustrelay_record_decision_partner_v05',
        'trustrelay_get_decision_partner_v05'
      )
  loop
    execute format(
      'revoke execute on function %s from public, anon, authenticated',
      f.signature
    );
    execute format(
      'grant execute on function %s to service_role',
      f.signature
    );
  end loop;
end $$;
