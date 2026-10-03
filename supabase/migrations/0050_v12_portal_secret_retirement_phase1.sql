-- TrustRelay v1.2 portal-secret retirement, phase 1.
-- Introduce a service-role-only internal decision context and stop minting new
-- long-lived verifier portal credentials. Existing portal credentials remain
-- temporarily compatible until Edge rollout completes.

create or replace function public.trustrelay_internal_partner_context_v12(
  p_org_id text,
  p_request_id text,
  p_rate_limit integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path='public','pg_catalog'
as $$
declare
  v_key public.api_keys%rowtype;
  v_org public.organizations%rowtype;
  v_prior public.authorization_decisions%rowtype;
  v_rate record;
  v_limit integer:=greatest(1,least(coalesce(p_rate_limit,120),1000));
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_org_id is null or length(btrim(p_org_id))<4 or length(p_org_id)>160 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_REQUIRED');
  end if;

  select * into v_org
  from public.organizations
  where id=p_org_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE');
  end if;

  select * into v_key
  from public.api_keys
  where organization_id=v_org.id
    and key_type='portal'
    and revoked_at is null
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',503,'code','PORTAL_INTERNAL_IDENTITY_UNAVAILABLE');
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05('portal-internal:'||v_key.id,v_limit,60);

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object('ok',false,'status',429,'code','RATE_LIMITED','resetAt',v_rate.reset_at);
  end if;

  update public.api_keys
  set last_used_at=v_now,updated_at=v_now
  where id=v_key.id;

  if p_request_id is not null then
    select * into v_prior
    from public.authorization_decisions
    where organization_id=v_org.id and request_id=p_request_id
    limit 1;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',jsonb_build_object(
      'id',v_org.id,'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'status',v_org.status
    ),
    'apiKey',jsonb_build_object(
      'id',v_key.id,'name',v_key.name,'prefix','tr_internal',
      'keyType','portal','scopes',jsonb_build_array('decisions:read','decisions:write')
    ),
    'rate',jsonb_build_object('remaining',v_rate.remaining,'resetAt',v_rate.reset_at),
    'prior',case when v_prior.id is null then null else to_jsonb(v_prior) end
  );
end;
$$;

revoke all on function public.trustrelay_internal_partner_context_v12(text,text,integer)
from public,anon,authenticated;
grant execute on function public.trustrelay_internal_partner_context_v12(text,text,integer)
to service_role;

create or replace function private.trustrelay_create_organization_core_v10(
  p_uid uuid,p_name text,p_industry text,p_website text
)
returns jsonb
language plpgsql
security definer
set search_path='public','private','extensions','pg_catalog'
as $$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_org_id text:='org_'||replace(gen_random_uuid()::text,'-','');
  v_slug text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_hash text;
  v_key_id text:='key_'||replace(gen_random_uuid()::text,'-','');
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;
  if not found then return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND'); end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>120 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_NAME_INVALID');
  end if;

  v_slug:=regexp_replace(lower(btrim(p_name)),'[^a-z0-9]+','-','g');
  v_slug:=regexp_replace(v_slug,'(^-+|-+$)','','g');
  if length(v_slug)<2 then v_slug:='organization'; end if;
  v_slug:=left(v_slug,48)||'-'||substr(replace(gen_random_uuid()::text,'-',''),1,8);

  insert into public.organizations(
    id,name,slug,mode,status,created_at,created_by_account_id,industry,website,updated_at
  ) values (
    v_org_id,btrim(p_name),v_slug,'sandbox','active',v_now,v_account.id,
    nullif(btrim(coalesce(p_industry,'')),''),
    nullif(btrim(coalesce(p_website,'')),''),
    v_now
  ) returning * into v_org;

  insert into public.organization_billing(
    organization_id,provider,plan_code,status,billing_email,seat_quantity,
    metadata_json,created_at,updated_at
  ) values(
    v_org_id,'stripe','sandbox','not_configured',v_account.email,1,
    '{}',v_now,v_now
  );

  insert into public.organization_onboarding(
    organization_id,status,primary_contact_email,security_contact_email,billing_contact_email,
    completed_steps_json,production_status,created_at,updated_at
  ) values(
    v_org_id,'incomplete',v_account.email,null,v_account.email,
    '[]','sandbox',v_now,v_now
  );

  insert into public.organization_members(
    organization_id,account_id,role,created_at,status,title,updated_at
  ) values(v_org_id,v_account.id,'owner',v_now,'active','Owner',v_now);

  -- Portal rows are audit identities only. No recoverable credential is created.
  v_hash:=encode(digest(gen_random_bytes(32),'sha256'),'hex');

  insert into public.api_keys(
    id,organization_id,name,prefix,key_hash,scopes_json,created_at,
    key_type,created_by_account_id,last_four,secret_vault_id,updated_at
  ) values (
    v_key_id,v_org_id,'Verifier Portal Internal','tr_internal',v_hash,
    '["decisions:read","decisions:write"]',v_now,
    'portal',v_account.id,null,null,v_now
  );

  perform private.trustrelay_append_org_audit_v09(
    v_org_id,v_account.id,'organization.created','organization',v_org_id,
    jsonb_build_object(
      'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'industry',v_org.industry,
      'billingPlan','sandbox','productionStatus','sandbox'
    )
  );
  perform private.trustrelay_append_org_audit_v09(
    v_org_id,v_account.id,'api_key.created','api_key',v_key_id,
    jsonb_build_object(
      'name','Verifier Portal Internal','keyType','portal',
      'credentialStored',false,
      'scopes',jsonb_build_array('decisions:read','decisions:write')
    )
  );

  return jsonb_build_object(
    'ok',true,
    'organization',to_jsonb(v_org),
    'membership',jsonb_build_object('role','owner','status','active'),
    'billing',jsonb_build_object('planCode','sandbox','status','not_configured'),
    'onboarding',jsonb_build_object('status','incomplete','productionStatus','sandbox')
  );
end;
$$;

revoke all on function private.trustrelay_create_organization_core_v10(uuid,text,text,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_create_organization_core_v10(uuid,text,text,text)
to service_role;

notify pgrst,'reload schema';
