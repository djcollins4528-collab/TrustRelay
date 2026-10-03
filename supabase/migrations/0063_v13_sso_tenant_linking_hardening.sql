-- TrustRelay v1.3 SSO tenant-linking and lockout hardening
-- Prevent cross-tenant email aliasing, constrain break-glass to a real email identity,
-- and force every IdP reconfiguration back to optional / no-JIT until retested.

create or replace function private.trustrelay_account_has_email_binding_v13(p_account_id text)
returns boolean
language sql
stable
security definer
set search_path to 'public','pg_catalog'
as $function$
  select exists(
    select 1
    from public.account_auth_bindings b
    where b.account_id=p_account_id
      and b.provider_protocol='email'
  );
$function$;

create or replace function private.trustrelay_ensure_account_v06(
  p_uid uuid,p_display_name text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_email text;
  v_domain text;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_person_id text;
  v_account_id text;
  v_bound_account_id text;
  v_authorized_org_id text;
  v_sso jsonb;
  v_protocol text:='email';
  v_identifier text:='email';
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
begin
  if auth.uid() is not null and p_uid is distinct from auth.uid() then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  select lower(email) into v_email
  from auth.users
  where id=p_uid;
  if v_email is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_USER_NOT_FOUND');
  end if;
  v_domain:=split_part(v_email,'@',2);

  v_bound_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_bound_account_id is not null then
    update public.account_auth_bindings
    set last_seen_at=now()
    where auth_user_id=p_uid;
    select * into v_account from public.accounts where id=v_bound_account_id;
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object(
      'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person)
    );
  end if;

  v_sso:=private.trustrelay_session_sso_context_v13();
  if coalesce((v_sso->>'isSso')::boolean,false) then
    v_protocol:=v_sso->>'protocol';
    v_identifier:=v_sso->>'providerIdentifier';
  end if;

  select * into v_account
  from public.accounts
  where lower(email)=v_email and status='active'
  limit 1;

  if found then
    if coalesce((v_sso->>'isSso')::boolean,false)=false then
      return jsonb_build_object(
        'ok',false,'status',409,'code','ACCOUNT_EMAIL_ALREADY_BOUND'
      );
    end if;

    -- Never link an enterprise identity to an existing TrustRelay account merely
    -- because the IdP asserted the same email. The existing account must already
    -- be an active member of the exact organization owning this exact IdP/domain.
    select c.organization_id into v_authorized_org_id
    from public.organization_sso_configs c
    join public.organization_sso_domains d
      on d.organization_id=c.organization_id
    join public.organization_members m
      on m.organization_id=c.organization_id
     and m.account_id=v_account.id
     and m.status='active'
    where c.status='active'
      and d.domain=v_domain
      and (
        (v_protocol='oidc' and c.protocol='oidc'
          and c.provider_identifier=v_identifier)
        or
        (v_protocol='saml' and c.protocol='saml'
          and c.saml_provider_id=v_identifier)
      )
    limit 1;

    if v_authorized_org_id is null then
      return jsonb_build_object(
        'ok',false,'status',409,
        'code','ACCOUNT_SSO_LINK_REQUIRES_ORG_MEMBERSHIP'
      );
    end if;

    insert into public.account_auth_bindings(
      auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
    ) values(
      p_uid,v_account.id,v_protocol,v_identifier,now()
    )
    on conflict(auth_user_id) do update set
      account_id=excluded.account_id,
      provider_protocol=excluded.provider_protocol,
      provider_identifier=excluded.provider_identifier,
      last_seen_at=now();

    select * into v_person
    from public.persons
    where id=v_account.person_id;

    return jsonb_build_object(
      'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person),
      'identityAlias',true,'organizationId',v_authorized_org_id
    );
  end if;

  v_person_id:='person_'||replace(p_uid::text,'-','');
  v_account_id:='acct_'||replace(p_uid::text,'-','');

  insert into public.persons(
    id,display_name,email,identity_status,created_at
  ) values(
    v_person_id,
    coalesce(nullif(btrim(p_display_name),''),split_part(v_email,'@',1)),
    v_email,'unverified',v_now
  ) returning * into v_person;

  insert into public.accounts(
    id,person_id,email,status,created_at,auth_user_id
  ) values(
    v_account_id,v_person_id,v_email,'active',v_now,p_uid
  ) returning * into v_account;

  insert into public.account_auth_bindings(
    auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
  ) values(
    p_uid,v_account.id,v_protocol,v_identifier,now()
  )
  on conflict(auth_user_id) do nothing;

  return jsonb_build_object(
    'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person)
  );
end;
$function$;

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
  v_provider_match boolean:=false;
  v_break_glass boolean:=false;
begin
  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,'providerMatched',false,'breakGlass',false
    );
  end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);

  v_provider_match:=
    coalesce((v_ctx->>'isSso')::boolean,false)
    and v_ctx->>'protocol'=v_cfg.protocol
    and v_ctx->>'providerIdentifier'=
      case
        when v_cfg.protocol='oidc' then v_cfg.provider_identifier
        else v_cfg.saml_provider_id
      end;

  -- Break-glass is deliberately an email/passwordless identity, not merely an
  -- account that also happens to own an SSO alias.
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
    'providerMatched',v_provider_match,'breakGlass',v_break_glass,
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
begin
  if p_protocol not in ('oidc','saml')
     or p_provider_kind not in ('entra','okta','generic') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_PROVIDER_INVALID');
  end if;

  if p_protocol='oidc' and coalesce(p_provider_identifier,'')='' then
    return jsonb_build_object(
      'ok',false,'status',400,'code','OIDC_PROVIDER_IDENTIFIER_REQUIRED'
    );
  end if;
  if p_protocol='saml' and coalesce(p_saml_provider_id,'')='' then
    return jsonb_build_object(
      'ok',false,'status',400,'code','SAML_PROVIDER_ID_REQUIRED'
    );
  end if;

  foreach v_domain in array coalesce(p_domains,array[]::text[]) loop
    v_domain:=lower(btrim(v_domain));
    if not private.trustrelay_sso_domain_valid_v13(v_domain) then
      return jsonb_build_object(
        'ok',false,'status',400,'code','SSO_DOMAIN_INVALID','domain',v_domain
      );
    end if;
    if not (v_domain=any(v_clean)) then
      v_clean:=array_append(v_clean,v_domain);
    end if;
  end loop;

  if cardinality(v_clean)=0 or cardinality(v_clean)>20 then
    return jsonb_build_object(
      'ok',false,'status',400,'code','SSO_DOMAIN_COUNT_INVALID'
    );
  end if;

  perform pg_advisory_xact_lock(hashtextextended('sso:'||p_org_id,0));

  if exists(
    select 1
    from public.organization_sso_domains
    where domain=any(v_clean)
      and organization_id<>p_org_id
  ) then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_DOMAIN_ALREADY_CLAIMED'
    );
  end if;

  -- A break-glass owner is only eligible when the account still has a distinct
  -- email/passwordless identity binding.
  select m.account_id into v_owner
  from public.organization_members m
  where m.organization_id=p_org_id
    and m.role='owner'
    and m.status='active'
    and private.trustrelay_account_has_email_binding_v13(m.account_id)
  order by m.created_at
  limit 1;

  insert into public.organization_sso_configs(
    organization_id,protocol,provider_kind,provider_identifier,saml_provider_id,
    issuer,metadata_url,client_id,jit_enabled,default_role,enforcement_mode,
    break_glass_enabled,break_glass_account_id,status,last_tested_at,
    last_tested_by_account_id,created_at,updated_at
  ) values(
    p_org_id,p_protocol,p_provider_kind,nullif(p_provider_identifier,''),
    nullif(p_saml_provider_id,''),nullif(p_issuer,''),nullif(p_metadata_url,''),
    nullif(p_client_id,''),false,'verifier','optional',true,v_owner,'active',
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
    status='active',
    last_tested_at=null,
    last_tested_by_account_id=null,
    updated_at=v_now;

  delete from public.organization_sso_domains
  where organization_id=p_org_id;

  foreach v_domain in array v_clean loop
    insert into public.organization_sso_domains(domain,organization_id,created_at)
    values(v_domain,p_org_id,v_now);
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.sso.configured',
    'organization',p_org_id,
    jsonb_build_object(
      'protocol',p_protocol,
      'providerKind',p_provider_kind,
      'domains',to_jsonb(v_clean),
      'enforcementReset','optional',
      'jitReset',false,
      'breakGlassAvailable',v_owner is not null
    )
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,'status','active',
    'enforcementMode','optional','jitEnabled',false,
    'breakGlassAvailable',v_owner is not null
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

  if p_enforcement_mode='required' and coalesce(p_break_glass_enabled,false)=false then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_BREAK_GLASS_REQUIRED'
    );
  end if;

  if p_enforcement_mode='required'
     and (
       v_cfg.break_glass_account_id is null
       or not private.trustrelay_account_has_email_binding_v13(v_cfg.break_glass_account_id)
       or not exists(
         select 1
         from public.organization_members m
         where m.organization_id=p_org_id
           and m.account_id=v_cfg.break_glass_account_id
           and m.status='active'
           and m.role='owner'
       )
     ) then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_BREAK_GLASS_OWNER_REQUIRED'
    );
  end if;

  -- Optional mode may disable break-glass only by an owner; required mode above
  -- deliberately never permits it.
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

revoke execute on function private.trustrelay_account_has_email_binding_v13(text)
from public,anon,authenticated;
grant execute on function private.trustrelay_account_has_email_binding_v13(text)
to service_role;

revoke execute on function private.trustrelay_ensure_account_v06(uuid,text)
from public,anon;
grant execute on function private.trustrelay_ensure_account_v06(uuid,text)
to authenticated,service_role;

revoke execute on function private.trustrelay_sso_session_match_v13(uuid,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_sso_session_match_v13(uuid,text)
to authenticated,service_role;

revoke execute on function public.trustrelay_store_sso_provider_v13(
  text,text,text,text,text,text,text,text,text,text[]
) from public,anon,authenticated;
grant execute on function public.trustrelay_store_sso_provider_v13(
  text,text,text,text,text,text,text,text,text,text[]
) to service_role;

revoke execute on function private.trustrelay_set_sso_policy_core_v13(
  uuid,text,text,boolean,text,boolean
) from public,anon;
grant execute on function private.trustrelay_set_sso_policy_core_v13(
  uuid,text,text,boolean,text,boolean
) to authenticated,service_role;
