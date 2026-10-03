-- TrustRelay v1.0 maximum-hardening pass
-- Defense in depth: tables intentionally denied to clients lose underlying client ACLs too.
-- Future app objects are service-role-only by default until a migration explicitly grants access.

do $$
declare t record;
begin
  for t in
    select distinct schemaname, tablename
    from pg_policies
    where schemaname='public'
      and (policyname='trustrelay_deny_clients' or policyname like '%deny_clients')
  loop
    execute format('revoke all privileges on table %I.%I from anon, authenticated',t.schemaname,t.tablename);
    execute format('grant all privileges on table %I.%I to service_role',t.schemaname,t.tablename);
  end loop;
end $$;

alter default privileges for role postgres in schema public
  revoke all privileges on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all privileges on sequences from anon, authenticated;
alter default privileges for role postgres in schema private
  revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema private
  grant execute on functions to service_role;
