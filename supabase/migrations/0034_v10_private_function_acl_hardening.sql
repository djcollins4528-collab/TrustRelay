begin;

do $$
declare
  r record;
begin
  for r in
    select
      p.oid::regprocedure::text as signature,
      has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec,
      has_function_privilege('service_role', p.oid, 'EXECUTE') as service_exec
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'private'
  loop
    execute format('revoke execute on function %s from public, anon', r.signature);

    if r.auth_exec then
      execute format('grant execute on function %s to authenticated', r.signature);
    end if;

    if r.service_exec then
      execute format('grant execute on function %s to service_role', r.signature);
    end if;
  end loop;
end
$$;

alter default privileges for role postgres in schema private
  revoke execute on functions from public;

create index if not exists idx_backup_restore_tests_backup_run_id_v10
  on public.backup_restore_tests(backup_run_id);

create index if not exists idx_org_members_disabled_by_v10
  on public.organization_members(disabled_by_account_id);

create index if not exists idx_org_members_removed_by_v10
  on public.organization_members(removed_by_account_id);

create index if not exists idx_org_members_role_changed_by_v10
  on public.organization_members(role_changed_by_account_id);

commit;
