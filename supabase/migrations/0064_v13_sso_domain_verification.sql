-- TrustRelay v1.3 verified enterprise SSO domains
-- DNS ownership verification is mandatory before SSO discovery, JIT, or required enforcement.

alter table public.organization_sso_domains
  add column if not exists verification_status text not null default 'pending',
  add column if not exists verification_token_hash text,
  add column if not exists verification_requested_at text,
  add column if not exists verified_at text,
  add column if not exists verified_by_account_id text references public.accounts(id);

do $block$
begin
  if not exists(
    select 1 from pg_constraint
    where conname='organization_sso_domains_verification_status_check'
      and conrelid='public.organization_sso_domains'::regclass
  ) then
    alter table public.organization_sso_domains
      add constraint organization_sso_domains_verification_status_check
      check(verification_status in ('pending','verified'));
  end if;
  if not exists(
    select 1 from pg_constraint
    where conname='organization_sso_domains_token_hash_check'
      and conrelid='public.organization_sso_domains'::regclass
  ) then
    alter table public.organization_sso_domains
      add constraint organization_sso_domains_token_hash_check
      check(verification_token_hash is null or verification_token_hash ~ '^[0-9a-f]{64}$');
  end if;
end
$block$;

create or replace function private.trustrelay_sso_session_match_v13(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_cfg public.organization_sso_configs%rowtype;
  v_account_id text;
  v_ctx jsonb:=private.trustrelay_session_sso_context_v13();
  v_email text:=lower(coalesce(auth.jwt()->>'email',''));
  v_domain text;
  v_domain_verified boolean:=false;
  v_provider_match boolean:=false;
  v_break_glass boolean:=false;
begin
  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,'providerMatched',false,
      'domainVerified',false,'breakGlass',false
    );
  end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  v_domain:=split_part(v_email,'@',2);

  select exists(
    select 1
    from public.organization_sso_domains d
    where d.organization_id=p_org_id
      and d.domain=v_domain
      and d.verification_status='verified'
  ) into v_domain_verified;

  v_provider_match:=
    coalesce((v_ctx->>'isSso')::boolean,false)
    and v_domain_verified
    and v_ctx->>'protocol'=v_cfg.protocol
    and v_ctx->>'providerIdentifier'=
      case
        when v_cfg.protocol='oidc' then v_cfg.provider_identifier
        else v_cfg.saml_provider_id
      end;

  v_break_glass:=
    coalesce(v_cfg.break_glass_enabled,false)
    and not coalesce((v_ctx->>'isSso')::boolean,false)
    and v_account_id is not null
    and v_account_id=v_cfg.break_glass_account_id
    and exists(
      select 1
      from public.account_auth_bindings b
      where b.auth_user_id=p_uid
        and b.account_id=v_account_id
        and b.provider_protocol='email'
    )
    and exists(
      select 1
      from public.organization_members m
      where m.organization_id=p_org_id
        and m.account_id=v_account_id
        and m.status='active'
        and m.role='owner'
    );

  return jsonb_build_object(
    'ok',true,'configured',true,'status',v_cfg.status,
    'protocol',v_cfg.protocol,'providerKind',v_cfg.provider_kind,
    'providerMatched',v_provider_match,'domainVerified',v_domain_verified,
    'breakGlass',v_break_glass,'enforcementMode',v_cfg.enforcement_mode
  );
end;
$function$;

create or replace function private.trustrelay_sso_discover_v13(p_email text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_email text:=lower(btrim(coalesce(p_email,'')));
  v_domain text;
  v_cfg public.organization_sso_configs%rowtype;
begin
  if v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     or length(v_email)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','EMAIL_INVALID');
  end if;
  v_domain:=split_part(v_email,'@',2);

  select c.* into v_cfg
  from public.organization_sso_domains d
  join public.organization_sso_configs c
    on c.organization_id=d.organization_id
  where d.domain=v_domain
    and d.verification_status='verified'
    and c.status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',true,'configured',false);
  end if;

  return jsonb_build_object(
    'ok',true,'configured',true,
    'organizationId',v_cfg.organization_id,
    'protocol',v_cfg.protocol,
    'providerKind',v_cfg.provider_kind,
    'providerIdentifier',v_cfg.provider_identifier,
    'ssoProviderId',v_cfg.saml_provider_id,
    'enforcementMode',v_cfg.enforcement_mode
  );
end;
$function$;

create or replace function public.trustrelay_store_sso_provider_v13(
  p_org_id text,
  p_actor_account_id text,
  p_protocol text,
  p_provider_kind text,
  p_provider_identifier text,
  p_saml_provider_id text,
  p_issuer text,
  p_metadata_url text,
  p_client_id text,
  p_domains text[]
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $function$
declare
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
  v_domain text;
  v_owner text;
  v_clean text[]:=array[]::text[];
  v_all_verified boolean:=false;
begin
  if p_protocol not in ('oidc','saml')
     or p_provider_kind not in ('entra','okta','generic') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_PROVIDER_INVALID');
  end if;
  if p_protocol='oidc' and coalesce(p_provider_identifier,'')='' then
    return jsonb_build_object('ok',false,'status',400,'code','OIDC_PROVIDER_IDENTIFIER_REQUIRED');
  end if;
  if p_protocol='saml' and coalesce(p_saml_provider_id,'')='' then
    return jsonb_build_object('ok',false,'status',400,'code','SAML_PROVIDER_ID_REQUIRED');
  end if;

  foreach v_domain in array coalesce(p_domains,array[]::text[]) loop
    v_domain:=lower(btrim(v_domain));
    if not private.trustrelay_sso_domain_valid_v13(v_domain) then
      return jsonb_build_object('ok',false,'status',400,'code','SSO_DOMAIN_INVALID','domain',v_domain);
    end if;
    if not (v_domain=any(v_clean)) then
      v_clean:=array_append(v_clean,v_domain);
    end if;
  end loop;

  if cardinality(v_clean)=0 or cardinality(v_clean)>20 then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_DOMAIN_COUNT_INVALID');
  end if;

  perform pg_advisory_xact_lock(hashtextextended('sso:'||p_org_id,0));

  if exists(
    select 1 from public.organization_sso_domains
    where domain=any(v_clean) and organization_id<>p_org_id
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_DOMAIN_ALREADY_CLAIMED');
  end if;

  select m.account_id into v_owner
  from public.organization_members m
  where m.organization_id=p_org_id
    and m.role='owner'
    and m.status='active'
    and private.trustrelay_account_has_email_binding_v13(m.account_id)
  order by m.created_at
  limit 1;

  -- Preserve verified ownership for unchanged domains. New domains start pending.
  foreach v_domain in array v_clean loop
    insert into public.organization_sso_domains(
      domain,organization_id,created_at,verification_status
    ) values(v_domain,p_org_id,v_now,'pending')
    on conflict(domain) do update
      set organization_id=excluded.organization_id;
  end loop;

  delete from public.organization_sso_domains
  where organization_id=p_org_id
    and not (domain=any(v_clean));

  select coalesce(bool_and(verification_status='verified'),false)
  into v_all_verified
  from public.organization_sso_domains
  where organization_id=p_org_id;

  insert into public.organization_sso_configs(
    organization_id,protocol,provider_kind,provider_identifier,saml_provider_id,
    issuer,metadata_url,client_id,jit_enabled,default_role,enforcement_mode,
    break_glass_enabled,break_glass_account_id,status,last_tested_at,
    last_tested_by_account_id,created_at,updated_at
  ) values(
    p_org_id,p_protocol,p_provider_kind,nullif(p_provider_identifier,''),
    nullif(p_saml_provider_id,''),nullif(p_issuer,''),nullif(p_metadata_url,''),
    nullif(p_client_id,''),false,'verifier','optional',true,v_owner,
    case when v_all_verified then 'active' else 'configured' end,
    null,null,v_now,v_now
  )
  on conflict(organization_id) do update set
    protocol=excluded.protocol,
    provider_kind=excluded.provider_kind,
    provider_identifier=excluded.provider_identifier,
    saml_provider_id=excluded.saml_provider_id,
    issuer=excluded.issuer,
    metadata_url=excluded.metadata_url,
    client_id=excluded.client_id,
    jit_enabled=false,
    default_role='verifier',
    enforcement_mode='optional',
    break_glass_enabled=true,
    break_glass_account_id=v_owner,
    status=case when v_all_verified then 'active' else 'configured' end,
    last_tested_at=null,
    last_tested_by_account_id=null,
    updated_at=v_now;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.sso.configured',
    'organization',p_org_id,
    jsonb_build_object(
      'protocol',p_protocol,'providerKind',p_provider_kind,
      'domains',to_jsonb(v_clean),'domainsVerified',v_all_verified,
      'enforcementReset','optional','jitReset',false,
      'breakGlassAvailable',v_owner is not null
    )
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,
    'status',case when v_all_verified then 'active' else 'configured' end,
    'enforcementMode','optional','jitEnabled',false,
    'breakGlassAvailable',v_owner is not null,
    'domainsVerified',v_all_verified
  );
end;
$function$;

create or replace function public.trustrelay_set_sso_domain_challenge_v13(
  p_org_id text,p_actor_account_id text,p_domain text,p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_domain text:=lower(btrim(coalesce(p_domain,'')));
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_status text;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_DOMAIN_TOKEN_HASH_INVALID');
  end if;

  select verification_status into v_status
  from public.organization_sso_domains
  where organization_id=p_org_id and domain=v_domain
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SSO_DOMAIN_NOT_FOUND');
  end if;
  if v_status='verified' then
    return jsonb_build_object('ok',true,'domain',v_domain,'verificationStatus','verified');
  end if;

  update public.organization_sso_domains
  set verification_status='pending',
      verification_token_hash=p_token_hash,
      verification_requested_at=v_now,
      verified_at=null,
      verified_by_account_id=null
  where organization_id=p_org_id and domain=v_domain;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.sso.domain_verification_requested',
    'sso_domain',v_domain,jsonb_build_object('method','dns_txt')
  );

  return jsonb_build_object('ok',true,'domain',v_domain,'verificationStatus','pending');
end;
$function$;

create or replace function public.trustrelay_sso_domain_state_v13(p_org_id text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
begin
  return jsonb_build_object(
    'ok',true,
    'domains',coalesce((
      select jsonb_agg(jsonb_build_object(
        'domain',d.domain,
        'verificationStatus',d.verification_status,
        'tokenHash',d.verification_token_hash,
        'verificationRequestedAt',d.verification_requested_at,
        'verifiedAt',d.verified_at
      ) order by d.domain)
      from public.organization_sso_domains d
      where d.organization_id=p_org_id
    ),'[]'::jsonb)
  );
end;
$function$;

create or replace function public.trustrelay_mark_sso_domain_verified_v13(
  p_org_id text,p_actor_account_id text,p_domain text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_domain text:=lower(btrim(coalesce(p_domain,'')));
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_all_verified boolean;
begin
  update public.organization_sso_domains
  set verification_status='verified',
      verification_token_hash=null,
      verified_at=v_now,
      verified_by_account_id=p_actor_account_id
  where organization_id=p_org_id and domain=v_domain;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SSO_DOMAIN_NOT_FOUND');
  end if;

  select coalesce(bool_and(verification_status='verified'),false)
  into v_all_verified
  from public.organization_sso_domains
  where organization_id=p_org_id;

  if v_all_verified then
    update public.organization_sso_configs
    set status='active',updated_at=v_now
    where organization_id=p_org_id and status<>'disabled';
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.sso.domain_verified',
    'sso_domain',v_domain,jsonb_build_object('method','dns_txt')
  );

  return jsonb_build_object(
    'ok',true,'domain',v_domain,'verificationStatus','verified',
    'allDomainsVerified',v_all_verified
  );
end;
$function$;

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
  v_domain_verification jsonb;
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
      'organizationId',p_org_id,'actorAccountId',v_ctx->>'accountId'
    );
  end if;

  select coalesce(array_agg(domain order by domain),array[]::text[])
  into v_domains
  from public.organization_sso_domains
  where organization_id=p_org_id;

  select coalesce(jsonb_agg(jsonb_build_object(
    'domain',domain,
    'verificationStatus',verification_status,
    'verificationRequestedAt',verification_requested_at,
    'verifiedAt',verified_at
  ) order by domain),'[]'::jsonb)
  into v_domain_verification
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
    'domainVerification',v_domain_verification,
    'jitEnabled',v_cfg.jit_enabled,'defaultRole',v_cfg.default_role,
    'enforcementMode',v_cfg.enforcement_mode,
    'breakGlassEnabled',v_cfg.break_glass_enabled,
    'status',v_cfg.status,'lastTestedAt',v_cfg.last_tested_at,
    'session',v_match
  );
end;
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
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
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

  if not found or v_cfg.status in ('disabled','error') then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_PROVIDER_NOT_ACTIVE');
  end if;
  if p_enforcement_mode='required' and v_cfg.status<>'active' then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_DOMAIN_VERIFICATION_REQUIRED'
    );
  end if;

  v_match:=private.trustrelay_sso_session_match_v13(p_uid,p_org_id);

  if p_enforcement_mode='required'
     and not coalesce((v_match->>'providerMatched')::boolean,false) then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_TEST_REQUIRED');
  end if;
  if p_enforcement_mode='required' and coalesce(p_break_glass_enabled,false)=false then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_BREAK_GLASS_REQUIRED');
  end if;
  if p_enforcement_mode='required'
     and (
       v_cfg.break_glass_account_id is null
       or not private.trustrelay_account_has_email_binding_v13(v_cfg.break_glass_account_id)
       or not exists(
         select 1 from public.organization_members m
         where m.organization_id=p_org_id
           and m.account_id=v_cfg.break_glass_account_id
           and m.status='active' and m.role='owner'
       )
     ) then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_BREAK_GLASS_OWNER_REQUIRED'
    );
  end if;
  if coalesce(p_break_glass_enabled,false)=false and (v_ctx->>'role')<>'owner' then
    return jsonb_build_object(
      'ok',false,'status',403,'code','OWNER_REQUIRED_FOR_BREAK_GLASS_CHANGE'
    );
  end if;

  update public.organization_sso_configs
  set enforcement_mode=p_enforcement_mode,
      jit_enabled=coalesce(p_jit_enabled,false),
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

revoke execute on function public.trustrelay_set_sso_domain_challenge_v13(text,text,text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_set_sso_domain_challenge_v13(text,text,text,text)
to service_role;

revoke execute on function public.trustrelay_sso_domain_state_v13(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_sso_domain_state_v13(text)
to service_role;

revoke execute on function public.trustrelay_mark_sso_domain_verified_v13(text,text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_mark_sso_domain_verified_v13(text,text,text)
to service_role;
