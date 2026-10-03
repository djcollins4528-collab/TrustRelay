-- TrustRelay v1.3 enterprise SSO disable / recovery path
-- Allows an AAL2 owner/admin to disable a broken IdP without being trapped by
-- organization SSO enforcement. External IdP disable remains in the Edge control plane.

create or replace function private.trustrelay_disable_sso_core_v13(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_guard jsonb;
  v_ctx jsonb;
  v_cfg public.organization_sso_configs%rowtype;
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;

  -- Core role check intentionally avoids the SSO gate for break-fix recovery.
  v_ctx:=private.trustrelay_require_org_role_core_v10(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SSO_NOT_CONFIGURED');
  end if;

  update public.organization_sso_configs
  set status='disabled',
      enforcement_mode='optional',
      updated_at=v_now
  where organization_id=p_org_id;

  delete from public.organization_sso_domains
  where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','organization.sso.disabled',
    'organization',p_org_id,
    jsonb_build_object(
      'protocol',v_cfg.protocol,
      'providerKind',v_cfg.provider_kind
    )
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,'status','disabled',
    'enforcementMode','optional'
  );
end;
$function$;

create or replace function public.trustrelay_disable_sso_v13(p_org_id text)
returns jsonb
language sql
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_disable_sso_core_v13(auth.uid(),p_org_id);
$function$;

revoke execute on function private.trustrelay_disable_sso_core_v13(uuid,text)
from public,anon;
grant execute on function private.trustrelay_disable_sso_core_v13(uuid,text)
to authenticated,service_role;

revoke execute on function public.trustrelay_disable_sso_v13(text)
from public,anon;
grant execute on function public.trustrelay_disable_sso_v13(text)
to authenticated;
