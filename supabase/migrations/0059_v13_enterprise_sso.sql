-- TrustRelay v1.3 Enterprise SSO
-- Organization-scoped OIDC/SAML configuration, domain discovery, JIT membership,
-- centrally enforced SSO-required policy, and a protected break-glass owner path.

create table if not exists public.organization_sso_configs(
  organization_id text primary key references public.organizations(id) on delete cascade,
  protocol text not null check(protocol in ('oidc','saml')),
  provider_kind text not null check(provider_kind in ('entra','okta','generic')),
  provider_identifier text,
  saml_provider_id text,
  issuer text,
  metadata_url text,
  client_id text,
  jit_enabled boolean not null default true,
  default_role text not null default 'verifier'
    check(default_role in ('compliance','verifier','developer','auditor')),
  enforcement_mode text not null default 'optional'
    check(enforcement_mode in ('optional','required')),
  break_glass_enabled boolean not null default true,
  break_glass_account_id text references public.accounts(id),
  status text not null default 'configured'
    check(status in ('configured','active','disabled','error')),
  last_tested_at text,
  last_tested_by_account_id text references public.accounts(id),
  created_at text not null,
  updated_at text not null
);

create unique index if not exists organization_sso_configs_provider_identifier_uq
on public.organization_sso_configs(provider_identifier)
where provider_identifier is not null;

create unique index if not exists organization_sso_configs_saml_provider_id_uq
on public.organization_sso_configs(saml_provider_id)
where saml_provider_id is not null;

create table if not exists public.organization_sso_domains(
  domain text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  created_at text not null
);

create index if not exists organization_sso_domains_org_idx
on public.organization_sso_domains(organization_id);

alter table public.organization_sso_configs enable row level security;
alter table public.organization_sso_configs force row level security;
alter table public.organization_sso_domains enable row level security;
alter table public.organization_sso_domains force row level security;

revoke all on public.organization_sso_configs from public, anon, authenticated;
revoke all on public.organization_sso_domains from public, anon, authenticated;

create or replace function private.trustrelay_sso_domain_valid_v13(p_domain text)
returns boolean
language sql
immutable
set search_path to 'pg_catalog'
as $function$
  select lower(btrim(coalesce(p_domain,''))) ~
         '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
     and lower(btrim(coalesce(p_domain,''))) not in (
       'gmail.com','yahoo.com','outlook.com','hotmail.com',
       'icloud.com','aol.com','proton.me','protonmail.com'
     );
$function$;

create or replace function private.trustrelay_sso_session_match_v13(p_uid uuid,p_org_id text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_cfg public.organization_sso_configs%rowtype;
  v_account_id text;
  v_oidc_provider text:=coalesce(auth.jwt()#>>'{app_metadata,provider}','');
  v_saml_match boolean:=false;
  v_provider_match boolean:=false;
  v_break_glass boolean:=false;
begin
  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,
      'providerMatched',false,'breakGlass',false
    );
  end if;

  select id into v_account_id
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if v_cfg.protocol='oidc' then
    v_provider_match:=
      coalesce(v_cfg.provider_identifier,'')<>''
      and v_oidc_provider=v_cfg.provider_identifier;
  elsif v_cfg.protocol='saml' then
    select exists(
      select 1
      from jsonb_array_elements(coalesce(auth.jwt()->'amr','[]'::jsonb)) as x(value)
      where x.value->>'method'='sso/saml'
        and x.value->>'provider'=v_cfg.saml_provider_id
    ) into v_saml_match;
    v_provider_match:=coalesce(v_saml_match,false);
  end if;

  v_break_glass:=
    coalesce(v_cfg.break_glass_enabled,false)
    and v_account_id is not null
    and v_account_id=v_cfg.break_glass_account_id;

  return jsonb_build_object(
    'ok',true,
    'configured',true,
    'status',v_cfg.status,
    'protocol',v_cfg.protocol,
    'providerKind',v_cfg.provider_kind,
    'providerMatched',v_provider_match,
    'breakGlass',v_break_glass,
    'enforcementMode',v_cfg.enforcement_mode
  );
end;
$function$;

create or replace function private.trustrelay_sso_gate_v13(p_uid uuid,p_org_id text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_match jsonb;
  v_cfg public.organization_sso_configs%rowtype;
begin
  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found or v_cfg.status<>'active' or v_cfg.enforcement_mode<>'required' then
    return jsonb_build_object('ok',true);
  end if;

  v_match:=private.trustrelay_sso_session_match_v13(p_uid,p_org_id);
  if coalesce((v_match->>'providerMatched')::boolean,false)
     or coalesce((v_match->>'breakGlass')::boolean,false) then
    return jsonb_build_object('ok',true,'sso',v_match);
  end if;

  return jsonb_build_object(
    'ok',false,
    'status',403,
    'code','ORGANIZATION_SSO_REQUIRED',
    'organizationId',p_org_id,
    'protocol',v_cfg.protocol,
    'providerKind',v_cfg.provider_kind
  );
end;
$function$;

-- Central enforcement point used by organization permission checks.
-- Existing MFA remains mandatory; SSO is an additional gate only for organizations
-- that have successfully tested and explicitly enabled required enforcement.
create or replace function private.trustrelay_require_org_role_v07(
  p_uid uuid,p_org_id text,p_roles text[]
)
returns jsonb
language plpgsql
security definer
set search_path to 'private','auth','pg_catalog'
as $function$
declare
  v_guard jsonb;
  v_sso jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  if auth.uid() is not null then
    v_guard:=private.trustrelay_require_aal2_v12(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then
      return v_guard;
    end if;

    v_sso:=private.trustrelay_sso_gate_v13(p_uid,p_org_id);
    if coalesce((v_sso->>'ok')::boolean,false)=false then
      return v_sso;
    end if;
  end if;

  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$function$;

-- Public discovery reveals only routing material required to start an SSO flow.
-- It never returns client secrets, metadata XML, account data, or membership state.
create or replace function public.trustrelay_sso_discover_v13(p_email text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_domain text;
  v_cfg public.organization_sso_configs%rowtype;
begin
  if length(coalesce(p_email,''))>320 or position('@' in coalesce(p_email,''))<2 then
    return jsonb_build_object('ok',false,'status',400,'code','EMAIL_INVALID');
  end if;

  v_domain:=lower(split_part(btrim(p_email),'@',2));

  select c.* into v_cfg
  from public.organization_sso_domains d
  join public.organization_sso_configs c
    on c.organization_id=d.organization_id
  where d.domain=v_domain
    and c.status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',true,'configured',false);
  end if;

  return jsonb_build_object(
    'ok',true,
    'configured',true,
    'protocol',v_cfg.protocol,
    'providerKind',v_cfg.provider_kind,
    'providerIdentifier',v_cfg.provider_identifier,
    'ssoProviderId',v_cfg.saml_provider_id,
    'enforcementMode',v_cfg.enforcement_mode
  );
end;
$function$;

create or replace function public.trustrelay_sso_config_v13(p_org_id text)
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
  if not private.trustrelay_request_actor_matches_v10(auth.uid()) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  v_guard:=private.trustrelay_require_aal2_v12(auth.uid());
  if coalesce((v_guard->>'ok')::boolean,false)=false then
    return v_guard;
  end if;

  -- Use the core role check so an owner/admin can repair a bad SSO configuration.
  v_ctx:=private.trustrelay_require_org_role_core_v10(
    auth.uid(),p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then
    return v_ctx;
  end if;

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

  v_match:=private.trustrelay_sso_session_match_v13(auth.uid(),p_org_id);

  return jsonb_build_object(
    'ok',true,
    'configured',true,
    'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'protocol',v_cfg.protocol,
    'providerKind',v_cfg.provider_kind,
    'providerIdentifier',v_cfg.provider_identifier,
    'ssoProviderId',v_cfg.saml_provider_id,
    'issuer',v_cfg.issuer,
    'metadataUrl',v_cfg.metadata_url,
    'clientId',v_cfg.client_id,
    'domains',to_jsonb(v_domains),
    'jitEnabled',v_cfg.jit_enabled,
    'defaultRole',v_cfg.default_role,
    'enforcementMode',v_cfg.enforcement_mode,
    'breakGlassEnabled',v_cfg.break_glass_enabled,
    'status',v_cfg.status,
    'lastTestedAt',v_cfg.last_tested_at,
    'session',v_match
  );
end;
$function$;

-- Service-role only: called after Supabase Auth successfully creates/updates the IdP.
-- The IdP client secret is intentionally not accepted by or stored in Postgres.
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

  select account_id into v_owner
  from public.organization_members
  where organization_id=p_org_id
    and role='owner'
    and status='active'
  limit 1;

  insert into public.organization_sso_configs(
    organization_id,protocol,provider_kind,provider_identifier,saml_provider_id,
    issuer,metadata_url,client_id,jit_enabled,default_role,enforcement_mode,
    break_glass_enabled,break_glass_account_id,status,created_at,updated_at
  ) values(
    p_org_id,p_protocol,p_provider_kind,nullif(p_provider_identifier,''),
    nullif(p_saml_provider_id,''),nullif(p_issuer,''),nullif(p_metadata_url,''),
    nullif(p_client_id,''),true,'verifier','optional',true,v_owner,'active',v_now,v_now
  )
  on conflict(organization_id) do update set
    protocol=excluded.protocol,
    provider_kind=excluded.provider_kind,
    provider_identifier=excluded.provider_identifier,
    saml_provider_id=excluded.saml_provider_id,
    issuer=excluded.issuer,
    metadata_url=excluded.metadata_url,
    client_id=excluded.client_id,
    status='active',
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
      'domains',to_jsonb(v_clean)
    )
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,'status','active'
  );
end;
$function$;

create or replace function public.trustrelay_set_sso_policy_v13(
  p_org_id text,
  p_enforcement_mode text,
  p_jit_enabled boolean,
  p_default_role text,
  p_break_glass_enabled boolean default true
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

  if not private.trustrelay_request_actor_matches_v10(auth.uid()) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  v_guard:=private.trustrelay_require_aal2_v12(auth.uid());
  if coalesce((v_guard->>'ok')::boolean,false)=false then
    return v_guard;
  end if;

  v_ctx:=private.trustrelay_require_org_role_core_v10(
    auth.uid(),p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then
    return v_ctx;
  end if;

  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  for update;

  if not found or v_cfg.status<>'active' then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_PROVIDER_NOT_ACTIVE'
    );
  end if;

  v_match:=private.trustrelay_sso_session_match_v13(auth.uid(),p_org_id);

  -- Required enforcement can only be enabled from a session authenticated through
  -- the exact configured IdP. Break-glass does not satisfy this test.
  if p_enforcement_mode='required'
     and not coalesce((v_match->>'providerMatched')::boolean,false) then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_TEST_REQUIRED'
    );
  end if;

  if p_break_glass_enabled=false
     and (v_ctx->>'role')<>'owner' then
    return jsonb_build_object(
      'ok',false,'status',403,'code','OWNER_REQUIRED_FOR_BREAK_GLASS_CHANGE'
    );
  end if;

  if p_break_glass_enabled=false
     and not coalesce((v_match->>'providerMatched')::boolean,false) then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SSO_TEST_REQUIRED'
    );
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
      'enforcementMode',p_enforcement_mode,
      'jitEnabled',p_jit_enabled,
      'defaultRole',p_default_role,
      'breakGlassEnabled',p_break_glass_enabled
    )
  );

  return public.trustrelay_sso_config_v13(p_org_id);
end;
$function$;

create or replace function public.trustrelay_sso_bootstrap_v13()
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_uid uuid:=auth.uid();
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
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  v_ctx:=private.trustrelay_account_context_core_v10(v_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then
    return v_ctx;
  end if;

  v_account_id:=v_ctx#>>'{account,id}';

  for v_cfg in
    select *
    from public.organization_sso_configs
    where status='active'
      and jit_enabled=true
  loop
    v_match:=private.trustrelay_sso_session_match_v13(v_uid,v_cfg.organization_id);
    if coalesce((v_match->>'providerMatched')::boolean,false) then
      select * into v_existing
      from public.organization_members
      where organization_id=v_cfg.organization_id
        and account_id=v_account_id
      limit 1;

      if found then
        if v_existing.status='active' then
          return jsonb_build_object(
            'ok',true,'joined',false,
            'organizationId',v_cfg.organization_id,
            'role',v_existing.role
          );
        end if;

        -- JIT never resurrects a deliberately disabled/removed account.
        return jsonb_build_object(
          'ok',true,'joined',false,
          'organizationId',v_cfg.organization_id,
          'membershipStatus',v_existing.status
        );
      end if;

      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,updated_at
      ) values(
        v_cfg.organization_id,v_account_id,v_cfg.default_role,v_now,'active',v_now
      );

      perform private.trustrelay_append_org_audit_v09(
        v_cfg.organization_id,v_account_id,
        'organization.member.sso_jit_joined',
        'organization_member',v_account_id,
        jsonb_build_object(
          'role',v_cfg.default_role,
          'protocol',v_cfg.protocol,
          'providerKind',v_cfg.provider_kind
        )
      );

      return jsonb_build_object(
        'ok',true,'joined',true,
        'organizationId',v_cfg.organization_id,
        'role',v_cfg.default_role
      );
    end if;
  end loop;

  return jsonb_build_object('ok',true,'joined',false);
end;
$function$;

revoke execute on function private.trustrelay_sso_domain_valid_v13(text)
from public,anon,authenticated;
revoke execute on function private.trustrelay_sso_session_match_v13(uuid,text)
from public,anon,authenticated;
revoke execute on function private.trustrelay_sso_gate_v13(uuid,text)
from public,anon,authenticated;

revoke execute on function public.trustrelay_sso_discover_v13(text) from public;
grant execute on function public.trustrelay_sso_discover_v13(text) to anon,authenticated;

revoke execute on function public.trustrelay_sso_config_v13(text)
from public,anon;
grant execute on function public.trustrelay_sso_config_v13(text) to authenticated;

revoke execute on function public.trustrelay_store_sso_provider_v13(
  text,text,text,text,text,text,text,text,text,text[]
) from public,anon,authenticated;
grant execute on function public.trustrelay_store_sso_provider_v13(
  text,text,text,text,text,text,text,text,text,text[]
) to service_role;

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
