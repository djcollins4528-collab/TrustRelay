-- TrustRelay v1.0 billing RPC reconciliation.
-- Restore the authenticated permission lookup expected by trustrelay-billing-v10.

create or replace function public.trustrelay_my_org_permissions_v09(p_org_id text)
returns jsonb
language plpgsql
security invoker
set search_path=public,pg_catalog
as $$
declare
  v_dashboard jsonb;
begin
  v_dashboard:=public.trustrelay_org_dashboard_v07(p_org_id);
  if coalesce((v_dashboard->>'ok')::boolean,false)=false then
    return v_dashboard;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organizationId',p_org_id,
    'role',v_dashboard#>>'{membership,role}',
    'permissions',coalesce(v_dashboard#>'{membership,permissions}','{}'::jsonb)
  );
end;
$$;

revoke all on function public.trustrelay_my_org_permissions_v09(text) from public,anon;
grant execute on function public.trustrelay_my_org_permissions_v09(text) to authenticated,service_role;

notify pgrst,'reload schema';
