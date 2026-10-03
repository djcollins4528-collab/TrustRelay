-- TrustRelay v1.3 SSO control-plane hardening
-- Keep public wrappers security-invoker and move privileged logic into the private schema.
-- Anonymous SSO discovery is served by the independently authenticated Edge Function.

create policy organization_sso_configs_deny_all
on public.organization_sso_configs
for all to anon, authenticated
using (false)
with check (false);

create policy organization_sso_domains_deny_all
on public.organization_sso_domains
for all to anon, authenticated
using (false)
with check (false);

create or replace function private.trustrelay_sso_config_core_v13(
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
  v_domains text[];
  v_match jsonb;
begin
  if p_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  v_ctx:=private.trustrelay_require_org_role_core_v10(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,
      'organizationId',p_org_id,
      'actorAccountId',v_ctx->>'accountId'
    );
  end if;

  select coalesce(array_agg(domain order by domain),array[]::text[])
  into v_domains
  from public.organization_sso_domains
  where organization_id=p_org_id;

  v_match:=private.trustrelay_sso_session_match_v13(p_uid,p_org_id);

  return jsonb_build_object(
    'ok',true,'configured',true,'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'protocol',v_cfg.protocol,'providerKind',v_cfg.provider_kind,
    'providerIdentifier',v_cfg.provider_identifier,
    'ssoProviderId',v_cfg.saml_provider_id,
    'issuer',v_cfg.issuer,'metadataUrl',v_cfg.metadata_url,
    'clientId',v_cfg.client_id,'domains',to_jsonb(v_domains),
    'jitEnabled',v_cfg.jit_enabled,'defaultRole',v_cfg.default_role,
    'enforcementMode',v_cfg.enforcement_mode,
    'breakGlassEnabled',v_cfg.break_glass_enabled,
    'status',v_cfg.status,'lastTestedAt',v_cfg.last_tested_at,
    'session',v_match
  );
end;
$function$;

create or replace function public.trustrelay_sso_config_v13(p_org_id text)
returns jsonb
language sql
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_sso_config_core_v13(auth.uid(),p_org_id);
$function$;

create or replace function private.trustrelay_set_sso_policy_core_v13(
  p_uid uuid,p_org_id text,p_enforcement_mode text,p_jit_enabled boolean,
  p_default_role text,p_break_glass_enabled boolean
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
  v_match jsonb;
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
begin
  if p_enforcement_mode not in ('optional','required') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_ENFORCEMENT_INVALID');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_DEFAULT_ROLE_INVALID');
  end if;
  if p_uid is null or not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  v_ctx:=private.trustrelay_require_org_role_core_v10(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  for update;
  if not found or v_cfg.status<>'active' then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_PROVIDER_NOT_ACTIVE');
  end if;

  v_match:=private.trustrelay_sso_session_match_v13(p_uid,p_org_id);
  if p_enforcement_mode='required'
     and not coalesce((v_match->>'providerMatched')::boolean,false) then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_TEST_REQUIRED');
  end if;
  if p_break_glass_enabled=false and (v_ctx->>'role')<>'owner' then
    return jsonb_build_object(
      'ok',false,'status',403,'code','OWNER_REQUIRED_FOR_BREAK_GLASS_CHANGE'
    );
  end if;
  if p_break_glass_enabled=false
     and not coalesce((v_match->>'providerMatched')::boolean,false) then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_TEST_REQUIRED');
  end if;

  update public.organization_sso_configs
  set enforcement_mode=p_enforcement_mode,
      jit_enabled=coalesce(p_jit_enabled,true),
      default_role=p_default_role,
      break_glass_enabled=coalesce(p_break_glass_enabled,true),
      last_tested_at=case
        when coalesce((v_match->>'providerMatched')::boolean,false) then v_now
        else last_tested_at
      end,
      last_tested_by_account_id=case
        when coalesce((v_match->>'providerMatched')::boolean,false)
          then v_ctx->>'accountId'
        else last_tested_by_account_id
      end,
      updated_at=v_now
  where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','organization.sso.policy_changed',
    'organization',p_org_id,
    jsonb_build_object(
      'enforcementMode',p_enforcement_mode,'jitEnabled',p_jit_enabled,
      'defaultRole',p_default_role,'breakGlassEnabled',p_break_glass_enabled
    )
  );

  return private.trustrelay_sso_config_core_v13(p_uid,p_org_id);
end;
$function$;

create or replace function public.trustrelay_set_sso_policy_v13(
  p_org_id text,p_enforcement_mode text,p_jit_enabled boolean,
  p_default_role text,p_break_glass_enabled boolean default true
)
returns jsonb
language sql
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_set_sso_policy_core_v13(
    auth.uid(),p_org_id,p_enforcement_mode,p_jit_enabled,p_default_role,p_break_glass_enabled
  );
$function$;

create or replace function private.trustrelay_sso_bootstrap_core_v13(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_ctx jsonb;
  v_account_id text;
  v_cfg public.organization_sso_configs%rowtype;
  v_match jsonb;
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
  v_existing public.organization_members%rowtype;
begin
  if p_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  v_ctx:=private.trustrelay_account_context_core_v10(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx#>>'{account,id}';

  for v_cfg in
    select *
    from public.organization_sso_configs
    where status='active' and jit_enabled=true
  loop
    v_match:=private.trustrelay_sso_session_match_v13(p_uid,v_cfg.organization_id);
    if coalesce((v_match->>'providerMatched')::boolean,false) then
      select * into v_existing
      from public.organization_members
      where organization_id=v_cfg.organization_id
        and account_id=v_account_id
      limit 1;

      if found then
        return jsonb_build_object(
          'ok',true,'joined',false,'organizationId',v_cfg.organization_id,
          'role',v_existing.role,'membershipStatus',v_existing.status
        );
      end if;

      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,updated_at
      ) values(
        v_cfg.organization_id,v_account_id,v_cfg.default_role,v_now,'active',v_now
      );

      perform private.trustrelay_append_org_audit_v09(
        v_cfg.organization_id,v_account_id,
        'organization.member.sso_jit_joined','organization_member',v_account_id,
        jsonb_build_object(
          'role',v_cfg.default_role,'protocol',v_cfg.protocol,
          'providerKind',v_cfg.provider_kind
        )
      );

      return jsonb_build_object(
        'ok',true,'joined',true,'organizationId',v_cfg.organization_id,
        'role',v_cfg.default_role
      );
    end if;
  end loop;

  return jsonb_build_object('ok',true,'joined',false);
end;
$function$;

create or replace function public.trustrelay_sso_bootstrap_v13()
returns jsonb
language sql
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_sso_bootstrap_core_v13(auth.uid());
$function$;

-- Anonymous domain discovery moves to the Edge Function. Keep the old RPC
-- unavailable externally to avoid an anonymous SECURITY DEFINER surface.
revoke execute on function public.trustrelay_sso_discover_v13(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_sso_discover_v13(text)
to service_role;

revoke execute on function private.trustrelay_sso_config_core_v13(uuid,text)
from public,anon;
grant execute on function private.trustrelay_sso_config_core_v13(uuid,text)
to authenticated,service_role;

revoke execute on function private.trustrelay_set_sso_policy_core_v13(
  uuid,text,text,boolean,text,boolean
) from public,anon;
grant execute on function private.trustrelay_set_sso_policy_core_v13(
  uuid,text,text,boolean,text,boolean
) to authenticated,service_role;

revoke execute on function private.trustrelay_sso_bootstrap_core_v13(uuid)
from public,anon;
grant execute on function private.trustrelay_sso_bootstrap_core_v13(uuid)
to authenticated,service_role;

revoke execute on function public.trustrelay_sso_config_v13(text)
from public,anon;
grant execute on function public.trustrelay_sso_config_v13(text)
to authenticated;

revoke execute on function public.trustrelay_set_sso_policy_v13(
  text,text,boolean,text,boolean
) from public,anon;
grant execute on function public.trustrelay_set_sso_policy_v13(
  text,text,boolean,text,boolean
) to authenticated;

revoke execute on function public.trustrelay_sso_bootstrap_v13()
from public,anon;
grant execute on function public.trustrelay_sso_bootstrap_v13()
to authenticated;
