-- TrustRelay v1.0 security boundary hardening.
-- Keep browser/API callers on public identity-binding wrappers and make the private
-- implementation schema inaccessible to anon/authenticated roles.

create or replace function public.trustrelay_manage_org_member_v09(
  p_org_id text,
  p_member_account_id text,
  p_action text,
  p_role text default null,
  p_title text default null
)
returns jsonb
language sql
security definer
set search_path=private,auth,pg_catalog
as $$
  select private.trustrelay_manage_org_member_v09(
    auth.uid(),p_org_id,p_member_account_id,p_action,p_role,p_title
  );
$$;

create or replace function public.trustrelay_remove_member_v09(
  p_org_id text,
  p_account_id text,
  p_reason text default null
)
returns jsonb
language sql
security definer
set search_path=private,auth,pg_catalog
as $$
  select private.trustrelay_remove_member_v09(
    auth.uid(),p_org_id,p_account_id,p_reason
  );
$$;

create or replace function public.trustrelay_restore_member_v09(
  p_org_id text,
  p_account_id text
)
returns jsonb
language sql
security definer
set search_path=private,auth,pg_catalog
as $$
  select private.trustrelay_restore_member_v09(
    auth.uid(),p_org_id,p_account_id
  );
$$;

create or replace function public.trustrelay_transfer_org_owner_v09(
  p_org_id text,
  p_new_owner_account_id text
)
returns jsonb
language sql
security definer
set search_path=private,auth,pg_catalog
as $$
  select private.trustrelay_transfer_org_owner_v09(
    auth.uid(),p_org_id,p_new_owner_account_id
  );
$$;

-- Public wrappers that delegate to private SECURITY DEFINER implementations must
-- no longer depend on the caller having direct private-schema privileges.
do $$
declare
  r record;
begin
  for r in
    select p.oid
    from pg_proc p
    join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and not p.prosecdef
      and has_function_privilege('authenticated',p.oid,'EXECUTE')
      and position('private.' in pg_get_functiondef(p.oid))>0
  loop
    execute format('alter function %s security definer',r.oid::regprocedure);
  end loop;
end $$;

-- Client roles may use only the public RPC boundary.
revoke execute on all functions in schema private from public,anon,authenticated;
revoke usage on schema private from anon,authenticated;

-- Explicit grants for the new public wrappers.
revoke all on function public.trustrelay_manage_org_member_v09(text,text,text,text,text) from public,anon;
grant execute on function public.trustrelay_manage_org_member_v09(text,text,text,text,text) to authenticated;

revoke all on function public.trustrelay_remove_member_v09(text,text,text) from public,anon;
grant execute on function public.trustrelay_remove_member_v09(text,text,text) to authenticated;

revoke all on function public.trustrelay_restore_member_v09(text,text) from public,anon;
grant execute on function public.trustrelay_restore_member_v09(text,text) to authenticated;

revoke all on function public.trustrelay_transfer_org_owner_v09(text,text) from public,anon;
grant execute on function public.trustrelay_transfer_org_owner_v09(text,text) to authenticated;

-- Future routines are fail-closed: grants must be deliberate, not inherited.
alter default privileges for role postgres in schema private revoke execute on functions from public;
alter default privileges for role postgres in schema private revoke execute on functions from anon;
alter default privileges for role postgres in schema private revoke execute on functions from authenticated;
alter default privileges for role postgres in schema public revoke execute on functions from public;
alter default privileges for role postgres in schema public revoke execute on functions from anon;
alter default privileges for role postgres in schema public revoke execute on functions from authenticated;

notify pgrst,'reload schema';
