-- Staging convergence / idempotent correction for RPC boundary hardening.
-- Safe on environments that already have 0034: restore invoker wrappers, then apply
-- the identity-bound guarded implementation from 0034.
grant usage on schema private to authenticated;

do $$
declare r record;
begin
  for r in
    select p.oid
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.prosecdef
      and p.prolang=(select oid from pg_language where lanname='sql')
      and has_function_privilege('authenticated',p.oid,'EXECUTE')
      and position('private.' in pg_get_functiondef(p.oid))>0
  loop
    execute format('alter function %s security invoker',r.oid::regprocedure);
  end loop;

  for r in
    select p.oid
    from pg_proc p
    join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='private'
      and exists (
        select 1 from pg_proc q join pg_namespace qn on qn.oid=q.pronamespace
        where qn.nspname='public' and q.proname=p.proname
          and has_function_privilege('authenticated',q.oid,'EXECUTE')
      )
  loop
    execute format('grant execute on function %s to authenticated',r.oid::regprocedure);
  end loop;
end $$;

-- The remaining statements are intentionally supplied by the preceding 0034 migration.
-- This migration exists so staging environments that received an earlier 0034 draft
-- are returned to SECURITY INVOKER public wrappers before the guarded 0034 logic is reapplied.
notify pgrst,'reload schema';
