-- TrustRelay v1.4 — authoritative SCIM bearer credential model
-- Reconciles the legacy single-token configuration with the rotatable credential
-- model. SCIM runtime authentication is bearer-token only. OAuth token issuance
-- is intentionally not exposed until a standards-complete flow is implemented.
-- 0065 creates the first public v1.4 schema without the older staging-only
-- tenant/token columns. Add those compatibility columns before retiring them so
-- this migration is reproducible from a clean production database.

alter table public.organization_scim_configs
  add column if not exists tenant_key text,
  add column if not exists token_hash text,
  add column if not exists token_last_four text;

alter table public.organization_scim_configs
  alter column tenant_key drop not null,
  alter column token_hash drop not null,
  alter column token_last_four drop not null;

alter table public.organization_scim_configs
  add column if not exists provider_kind text not null default 'generic',
  add column if not exists rate_limit_per_minute integer not null default 300,
  add column if not exists group_sync_enabled boolean not null default false,
  add column if not exists allow_static_bearer boolean not null default true,
  add column if not exists last_sync_at timestamptz,
  add column if not exists last_error text,
  add column if not exists disabled_at timestamptz;

alter table public.organization_scim_configs
  drop constraint if exists organization_scim_configs_status_check;
update public.organization_scim_configs
set status='active'
where status='enabled';
alter table public.organization_scim_configs
  alter column status set default 'active';
alter table public.organization_scim_configs
  add constraint organization_scim_configs_status_check
  check(status in ('active','disabled'));

alter table public.organization_scim_configs
  drop constraint if exists organization_scim_configs_provider_kind_check;
alter table public.organization_scim_configs
  add constraint organization_scim_configs_provider_kind_check
  check(provider_kind in ('entra','okta','generic'));

alter table public.organization_scim_configs
  drop constraint if exists organization_scim_configs_rate_limit_check;
alter table public.organization_scim_configs
  add constraint organization_scim_configs_rate_limit_check
  check(rate_limit_per_minute between 30 and 3000);

alter table public.organization_scim_users
  add column if not exists title text,
  add column if not exists version bigint not null default 1;

create table if not exists public.organization_scim_credentials(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  client_id text not null unique,
  secret_hash text not null,
  label text not null default 'Primary',
  status text not null default 'active'
    check(status in ('active','revoked')),
  expires_at timestamptz not null,
  created_by_account_id text references public.accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  constraint organization_scim_credential_id_check
    check(id ~ '^scimcred_[a-f0-9]{32}$'),
  constraint organization_scim_credential_client_id_check
    check(client_id ~ '^tr_scim_[a-z0-9]{24,80}$'),
  constraint organization_scim_credential_secret_hash_check
    check(secret_hash ~ '^[0-9a-f]{64}$')
);

create index if not exists organization_scim_credentials_org_status_idx
  on public.organization_scim_credentials(organization_id,status,expires_at);

alter table public.organization_scim_credentials enable row level security;
alter table public.organization_scim_credentials force row level security;
revoke all on public.organization_scim_credentials from public,anon,authenticated;
drop policy if exists organization_scim_credentials_deny_all on public.organization_scim_credentials;
create policy organization_scim_credentials_deny_all
on public.organization_scim_credentials
for all to anon,authenticated using(false) with check(false);

-- OAuth access-token issuance is deliberately retired. The product exposes
-- one authentication model: a rotatable SCIM bearer secret.
drop function if exists public.trustrelay_scim_issue_access_token_v14(text,text,text);
drop function if exists private.trustrelay_scim_issue_access_token_core_v14(text,text,text);
drop table if exists public.organization_scim_access_tokens;

-- Retire the legacy configuration-token entry points. The nullable legacy
-- columns remain temporarily for a low-risk rolling migration, but are not
-- read or written by the runtime.
drop function if exists public.trustrelay_scim_auth_v14(text,text);
drop function if exists public.trustrelay_scim_config_v14(text);
drop function if exists public.trustrelay_scim_store_config_v14(text,text,text,text,text,text);
drop function if exists public.trustrelay_scim_rotate_token_v14(text,text,text,text);
drop function if exists public.trustrelay_scim_rotate_token_v14(text,text,text);
drop function if exists public.trustrelay_scim_set_policy_v14(text,text,text,text);
drop function if exists public.trustrelay_scim_set_policy_v14(text,text,text);
drop function if exists public.trustrelay_scim_write_user_v14(text,text,text,text,text,text,text,text,text,boolean);
drop function if exists public.trustrelay_scim_deactivate_user_v14(text,text);
drop function if exists private.trustrelay_scim_config_core_v14(uuid,text);
drop function if exists private.trustrelay_scim_issue_access_token_core_v14(text,text,text);

create or replace function private.trustrelay_scim_require_admin_v14(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare v_guard jsonb; v_ctx jsonb;
begin
  if p_uid is null or not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  v_ctx:=private.trustrelay_require_org_role_core_v10(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  return v_ctx;
end;
$function$;

create or replace function private.trustrelay_scim_admin_status_core_v14(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_ctx jsonb;
  v_cfg public.organization_scim_configs%rowtype;
  v_credentials jsonb:='[]'::jsonb;
  v_total bigint:=0;
  v_active bigint:=0;
begin
  v_ctx:=private.trustrelay_scim_require_admin_v14(p_uid,p_org_id);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,'organizationId',p_org_id,
      'actorAccountId',v_ctx->>'accountId',
      'credentials','[]'::jsonb,
      'counts',jsonb_build_object('users',0,'activeUsers',0,'groups',0)
    );
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',c.id,
    'clientId',c.client_id,
    'label',c.label,
    'status',c.status,
    'expiresAt',c.expires_at,
    'createdAt',c.created_at,
    'lastUsedAt',c.last_used_at,
    'revokedAt',c.revoked_at
  ) order by c.created_at desc),'[]'::jsonb)
  into v_credentials
  from public.organization_scim_credentials c
  where c.organization_id=p_org_id;

  select count(*),count(*) filter(where active)
  into v_total,v_active
  from public.organization_scim_users
  where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,
    'configured',true,
    'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'config',jsonb_build_object(
      'status',v_cfg.status,
      'providerKind',v_cfg.provider_kind,
      'defaultRole',v_cfg.default_role,
      'rateLimitPerMinute',v_cfg.rate_limit_per_minute,
      'allowStaticBearer',true,
      'groupSyncEnabled',false,
      'lastSyncAt',v_cfg.last_sync_at,
      'lastError',v_cfg.last_error,
      'disabledAt',v_cfg.disabled_at
    ),
    'credentials',v_credentials,
    'counts',jsonb_build_object(
      'users',v_total,
      'activeUsers',v_active,
      'groups',0
    )
  );
end;
$function$;

create or replace function public.trustrelay_scim_admin_status_v14(p_org_id text)
returns jsonb
language sql
security definer
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_scim_admin_status_core_v14(auth.uid(),p_org_id);
$function$;

create or replace function private.trustrelay_scim_store_credential_core_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_sso public.organization_sso_configs%rowtype;
  v_id text:='scimcred_'||replace(gen_random_uuid()::text,'-','');
  v_active_count integer:=0;
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  select * into v_sso
  from public.organization_sso_configs
  where organization_id=p_org_id and status='active'
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_ACTIVE_SSO');
  end if;

  if not exists(
    select 1 from public.organization_sso_domains
    where organization_id=p_org_id and verification_status='verified'
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_VERIFIED_DOMAIN');
  end if;

  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if p_client_id !~ '^tr_scim_[a-z0-9]{24,80}$'
     or p_secret_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_INVALID');
  end if;
  if p_expires_at<=clock_timestamp()+interval '30 days'
     or p_expires_at>clock_timestamp()+interval '3 years 1 day' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_EXPIRY_INVALID');
  end if;

  select count(*) into v_active_count
  from public.organization_scim_credentials
  where organization_id=p_org_id and status='active'
    and expires_at>clock_timestamp();
  if v_active_count>=2 then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACTIVE_CREDENTIAL_LIMIT');
  end if;

  insert into public.organization_scim_configs(
    organization_id,provider_kind,status,default_role,allow_static_bearer,
    group_sync_enabled,created_by_account_id,created_at,updated_at,disabled_at
  ) values(
    p_org_id,coalesce(v_sso.provider_kind,'generic'),'active',p_default_role,true,
    false,p_actor_account_id,now(),now(),null
  )
  on conflict(organization_id) do update set
    provider_kind=excluded.provider_kind,
    status='active',
    default_role=excluded.default_role,
    allow_static_bearer=true,
    group_sync_enabled=false,
    updated_at=now(),
    disabled_at=null,
    last_error=null;

  insert into public.organization_scim_credentials(
    id,organization_id,client_id,secret_hash,label,status,expires_at,
    created_by_account_id,created_at
  ) values(
    v_id,p_org_id,p_client_id,p_secret_hash,
    left(coalesce(nullif(btrim(p_label),''),'Primary'),80),
    'active',p_expires_at,p_actor_account_id,now()
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.credential_created',
    'scim_credential',v_id,
    jsonb_build_object(
      'clientId',p_client_id,
      'label',left(coalesce(nullif(btrim(p_label),''),'Primary'),80),
      'expiresAt',p_expires_at,
      'providerKind',coalesce(v_sso.provider_kind,'generic'),
      'defaultRole',p_default_role
    )
  );

  return jsonb_build_object(
    'ok',true,'credentialId',v_id,'clientId',p_client_id,
    'expiresAt',p_expires_at,'providerKind',coalesce(v_sso.provider_kind,'generic')
  );
end;
$function$;

create or replace function public.trustrelay_scim_store_credential_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_store_credential_core_v14(
    p_org_id,p_actor_account_id,p_client_id,p_secret_hash,p_label,p_default_role,p_expires_at
  );
$function$;

create or replace function private.trustrelay_scim_revoke_credential_core_v14(
  p_org_id text,p_actor_account_id text,p_credential_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare v_remaining integer:=0;
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  update public.organization_scim_credentials
  set status='revoked',revoked_at=coalesce(revoked_at,now())
  where id=p_credential_id and organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_CREDENTIAL_NOT_FOUND');
  end if;

  select count(*) into v_remaining
  from public.organization_scim_credentials
  where organization_id=p_org_id and status='active'
    and expires_at>clock_timestamp();

  if v_remaining=0 then
    update public.organization_scim_configs
    set status='disabled',disabled_at=now(),updated_at=now()
    where organization_id=p_org_id;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.credential_revoked',
    'scim_credential',p_credential_id,
    jsonb_build_object('remainingActiveCredentials',v_remaining)
  );
  return jsonb_build_object(
    'ok',true,'credentialId',p_credential_id,'status','revoked',
    'remainingActiveCredentials',v_remaining
  );
end;
$function$;

create or replace function public.trustrelay_scim_revoke_credential_v14(
  p_org_id text,p_actor_account_id text,p_credential_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_revoke_credential_core_v14(
    p_org_id,p_actor_account_id,p_credential_id
  );
$function$;

create or replace function private.trustrelay_scim_disable_core_v14(
  p_org_id text,p_actor_account_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  update public.organization_scim_configs
  set status='disabled',disabled_at=now(),updated_at=now()
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  update public.organization_scim_credentials
  set status='revoked',revoked_at=coalesce(revoked_at,now())
  where organization_id=p_org_id and status='active';

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.disabled',
    'organization',p_org_id,'{}'::jsonb
  );
  return jsonb_build_object('ok',true,'disabled',true);
end;
$function$;

create or replace function public.trustrelay_scim_disable_v14(
  p_org_id text,p_actor_account_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_disable_core_v14(p_org_id,p_actor_account_id);
$function$;

create or replace function private.trustrelay_scim_set_policy_core_v14(
  p_org_id text,p_actor_account_id text,p_default_role text,
  p_allow_static_bearer boolean,p_group_sync_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if coalesce(p_allow_static_bearer,true)=false then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_BEARER_AUTH_REQUIRED');
  end if;
  if coalesce(p_group_sync_enabled,false)=true then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_GROUP_SYNC_NOT_AVAILABLE');
  end if;

  update public.organization_scim_configs
  set default_role=p_default_role,
      allow_static_bearer=true,
      group_sync_enabled=false,
      updated_at=now()
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.policy_changed',
    'organization',p_org_id,
    jsonb_build_object('defaultRole',p_default_role,'authMode','bearer')
  );

  return jsonb_build_object(
    'ok',true,'defaultRole',p_default_role,
    'allowStaticBearer',true,'groupSyncEnabled',false
  );
end;
$function$;

create or replace function public.trustrelay_scim_set_policy_v14(
  p_org_id text,p_actor_account_id text,p_default_role text,
  p_allow_static_bearer boolean,p_group_sync_enabled boolean
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_set_policy_core_v14(
    p_org_id,p_actor_account_id,p_default_role,p_allow_static_bearer,p_group_sync_enabled
  );
$function$;

create or replace function private.trustrelay_scim_resolve_bearer_core_v14(
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  v_cred public.organization_scim_credentials%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select c.* into v_cred
  from public.organization_scim_credentials c
  join public.organization_scim_configs cfg
    on cfg.organization_id=c.organization_id
  where c.secret_hash=p_token_hash
    and c.status='active'
    and c.expires_at>clock_timestamp()
    and cfg.status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=v_cred.organization_id and status='active';

  update public.organization_scim_credentials
  set last_used_at=now()
  where id=v_cred.id;

  update public.organization_scim_configs
  set last_sync_at=now(),last_error=null,updated_at=now()
  where organization_id=v_cred.organization_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',v_cred.organization_id,
    'providerKind',v_cfg.provider_kind,
    'defaultRole',v_cfg.default_role,
    'rateLimitPerMinute',v_cfg.rate_limit_per_minute,
    'groupSyncEnabled',false,
    'authMode','static_bearer'
  );
end;
$function$;

create or replace function public.trustrelay_scim_resolve_bearer_v14(p_token_hash text)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_resolve_bearer_core_v14(p_token_hash);
$function$;

create or replace function private.trustrelay_scim_upsert_user_core_v14(
  p_org_id text,p_scim_id text,p_external_id text,p_user_name text,p_email text,
  p_display_name text,p_given_name text,p_family_name text,p_title text,p_active boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cfg public.organization_scim_configs%rowtype;
  v_scim public.organization_scim_users%rowtype;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_member public.organization_members%rowtype;
  v_id text;
  v_person_id text;
  v_account_id text;
  v_email text:=lower(btrim(coalesce(p_email,p_user_name,'')));
  v_user_name text:=lower(btrim(coalesce(p_user_name,'')));
  v_domain text;
  v_display text;
  v_event text;
  v_now_text text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_NOT_ACTIVE');
  end if;

  if length(v_user_name)<3 or length(v_user_name)>320
     or position('@' in v_email)<2 or length(v_email)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_USER_NAME_INVALID');
  end if;

  v_domain:=split_part(v_email,'@',2);
  if not exists(
    select 1 from public.organization_sso_domains d
    where d.organization_id=p_org_id and d.domain=v_domain
      and d.verification_status='verified'
  ) then
    return jsonb_build_object(
      'ok',false,'status',403,'code','SCIM_EMAIL_DOMAIN_NOT_VERIFIED','domain',v_domain
    );
  end if;

  if p_scim_id is not null and p_scim_id<>'' then
    select * into v_scim from public.organization_scim_users
    where organization_id=p_org_id and id=p_scim_id for update;
  elsif nullif(btrim(coalesce(p_external_id,'')),'') is not null then
    select * into v_scim from public.organization_scim_users
    where organization_id=p_org_id and external_id=btrim(p_external_id) for update;
  else
    select * into v_scim from public.organization_scim_users
    where organization_id=p_org_id and lower(user_name)=v_user_name for update;
  end if;

  if found then
    v_id:=v_scim.id;
    select * into v_account from public.accounts where id=v_scim.account_id for update;
    if lower(v_account.email)<>v_email then
      if exists(select 1 from public.account_auth_bindings b where b.account_id=v_account.id) then
        return jsonb_build_object(
          'ok',false,'status',409,'code','SCIM_USERNAME_CHANGE_REQUIRES_RELINK'
        );
      end if;
      if exists(select 1 from public.accounts a where lower(a.email)=v_email and a.id<>v_account.id) then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_ALREADY_EXISTS');
      end if;
      update public.accounts set email=v_email where id=v_account.id;
      update public.persons set email=v_email where id=v_account.person_id;
      v_account.email:=v_email;
    end if;
  else
    select * into v_account
    from public.accounts where lower(email)=v_email limit 1 for update;

    if not found then
      v_person_id:='person_'||replace(gen_random_uuid()::text,'-','');
      v_account_id:='acct_'||replace(gen_random_uuid()::text,'-','');
      v_display:=coalesce(
        nullif(btrim(coalesce(p_display_name,'')),''),
        nullif(btrim(concat_ws(' ',p_given_name,p_family_name)),''),
        split_part(v_email,'@',1)
      );
      insert into public.persons(id,display_name,email,identity_status,created_at)
      values(v_person_id,left(v_display,160),v_email,'unverified',v_now_text)
      returning * into v_person;

      insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
      values(v_account_id,v_person_id,v_email,'active',v_now_text,null)
      returning * into v_account;
    end if;

    v_id:='scimusr_'||replace(gen_random_uuid()::text,'-','');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=v_account.id
  limit 1 for update;

  if found and v_member.role in ('owner','admin') then
    return jsonb_build_object(
      'ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED'
    );
  end if;

  if coalesce(p_active,true) then
    if v_member.organization_id is null then
      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,title,updated_at,
        provisioning_source,provisioning_ref
      ) values(
        p_org_id,v_account.id,v_cfg.default_role,v_now_text,'active',
        nullif(left(btrim(coalesce(p_title,'')),160),''),
        v_now_text,'scim',v_id
      );
    else
      update public.organization_members
      set status='active',
          title=coalesce(nullif(left(btrim(coalesce(p_title,'')),160),''),title),
          disabled_at=null,disabled_by_account_id=null,
          removed_at=null,removed_by_account_id=null,
          updated_at=v_now_text,
          provisioning_source='scim',
          provisioning_ref=v_id
      where organization_id=p_org_id and account_id=v_account.id;
    end if;
  else
    if v_member.organization_id is null then
      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,title,updated_at,disabled_at,
        provisioning_source,provisioning_ref
      ) values(
        p_org_id,v_account.id,v_cfg.default_role,v_now_text,'disabled',
        nullif(left(btrim(coalesce(p_title,'')),160),''),
        v_now_text,v_now_text,'scim',v_id
      );
    else
      update public.organization_members
      set status='disabled',
          disabled_at=coalesce(disabled_at,v_now_text),
          disabled_by_account_id=null,
          updated_at=v_now_text,
          provisioning_source='scim',
          provisioning_ref=v_id
      where organization_id=p_org_id and account_id=v_account.id;
    end if;
  end if;

  v_display:=coalesce(
    nullif(btrim(coalesce(p_display_name,'')),''),
    nullif(btrim(concat_ws(' ',p_given_name,p_family_name)),''),
    split_part(v_email,'@',1)
  );
  update public.persons set display_name=left(v_display,160)
  where id=v_account.person_id;

  if exists(
    select 1 from public.organization_scim_users
    where organization_id=p_org_id and id=v_id
  ) then
    update public.organization_scim_users
    set external_id=nullif(btrim(coalesce(p_external_id,'')),''),
        user_name=v_user_name,
        email=v_email,
        display_name=nullif(left(btrim(coalesce(p_display_name,'')),160),''),
        given_name=nullif(left(btrim(coalesce(p_given_name,'')),120),''),
        family_name=nullif(left(btrim(coalesce(p_family_name,'')),120),''),
        title=nullif(left(btrim(coalesce(p_title,'')),160),''),
        active=coalesce(p_active,true),
        deprovisioned_at=case when coalesce(p_active,true) then null else coalesce(deprovisioned_at,now()) end,
        version=version+1,
        updated_at=now(),
        last_synced_at=now()
    where organization_id=p_org_id and id=v_id
    returning * into v_scim;
    v_event:=case when v_scim.active then 'organization.scim.user_updated'
                  else 'organization.scim.user_deprovisioned' end;
  else
    insert into public.organization_scim_users(
      id,organization_id,account_id,external_id,user_name,email,display_name,
      given_name,family_name,title,active,version,created_at,updated_at,last_synced_at,
      deprovisioned_at
    ) values(
      v_id,p_org_id,v_account.id,nullif(btrim(coalesce(p_external_id,'')),''),
      v_user_name,v_email,nullif(left(btrim(coalesce(p_display_name,'')),160),''),
      nullif(left(btrim(coalesce(p_given_name,'')),120),''),
      nullif(left(btrim(coalesce(p_family_name,'')),120),''),
      nullif(left(btrim(coalesce(p_title,'')),160),''),
      coalesce(p_active,true),1,now(),now(),now(),
      case when coalesce(p_active,true) then null else now() end
    ) returning * into v_scim;
    v_event:=case when v_scim.active then 'organization.scim.user_created'
                  else 'organization.scim.user_created_disabled' end;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,v_event,'scim_user',v_scim.id,
    jsonb_build_object(
      'userName',v_scim.user_name,'active',v_scim.active,
      'externalId',v_scim.external_id,'accountId',v_scim.account_id
    )
  );

  return jsonb_build_object(
    'ok',true,'user',jsonb_build_object(
      'id',v_scim.id,'organizationId',v_scim.organization_id,
      'accountId',v_scim.account_id,'externalId',v_scim.external_id,
      'userName',v_scim.user_name,'email',v_scim.email,
      'displayName',v_scim.display_name,'givenName',v_scim.given_name,
      'familyName',v_scim.family_name,'title',v_scim.title,
      'active',v_scim.active,'version',v_scim.version,
      'createdAt',v_scim.created_at,'updatedAt',v_scim.updated_at
    )
  );
end;
$function$;

create or replace function public.trustrelay_scim_upsert_user_v14(
  p_org_id text,p_scim_id text,p_external_id text,p_user_name text,p_email text,
  p_display_name text,p_given_name text,p_family_name text,p_title text,p_active boolean
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_upsert_user_core_v14(
    p_org_id,p_scim_id,p_external_id,p_user_name,p_email,p_display_name,
    p_given_name,p_family_name,p_title,p_active
  );
$function$;

create or replace function private.trustrelay_scim_delete_user_core_v14(
  p_org_id text,p_scim_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_scim public.organization_scim_users%rowtype;
  v_member public.organization_members%rowtype;
  v_now_text text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_scim
  from public.organization_scim_users
  where organization_id=p_org_id and id=p_scim_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=v_scim.account_id
  for update;

  if found and v_member.role in ('owner','admin') then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
  end if;

  update public.organization_scim_users
  set active=false,
      deprovisioned_at=coalesce(deprovisioned_at,now()),
      version=version+1,
      updated_at=now(),
      last_synced_at=now()
  where organization_id=p_org_id and id=p_scim_id;

  update public.organization_members
  set status='disabled',
      disabled_at=coalesce(disabled_at,v_now_text),
      disabled_by_account_id=null,
      updated_at=v_now_text,
      provisioning_source='scim',
      provisioning_ref=p_scim_id
  where organization_id=p_org_id and account_id=v_scim.account_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'organization.scim.user_deprovisioned',
    'scim_user',p_scim_id,
    jsonb_build_object('userName',v_scim.user_name,'accountId',v_scim.account_id)
  );
  return jsonb_build_object('ok',true,'id',p_scim_id,'active',false);
end;
$function$;

create or replace function public.trustrelay_scim_delete_user_v14(
  p_org_id text,p_scim_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_delete_user_core_v14(p_org_id,p_scim_id);
$function$;

-- Least privilege: only the interactive status RPC is exposed to authenticated
-- users. All lifecycle and credential RPCs are service-role only.
revoke all on function private.trustrelay_scim_require_admin_v14(uuid,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_admin_status_core_v14(uuid,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_store_credential_core_v14(text,text,text,text,text,text,timestamptz) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_revoke_credential_core_v14(text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_disable_core_v14(text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_set_policy_core_v14(text,text,text,boolean,boolean) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_resolve_bearer_core_v14(text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_upsert_user_core_v14(text,text,text,text,text,text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_delete_user_core_v14(text,text) from public,anon,authenticated;

revoke all on function public.trustrelay_scim_admin_status_v14(text) from public,anon;
grant execute on function public.trustrelay_scim_admin_status_v14(text) to authenticated;

revoke all on function public.trustrelay_scim_store_credential_v14(text,text,text,text,text,text,timestamptz) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_revoke_credential_v14(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_disable_v14(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_set_policy_v14(text,text,text,boolean,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_resolve_bearer_v14(text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_upsert_user_v14(text,text,text,text,text,text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_delete_user_v14(text,text) from public,anon,authenticated;

grant execute on function public.trustrelay_scim_store_credential_v14(text,text,text,text,text,text,timestamptz) to service_role;
grant execute on function public.trustrelay_scim_revoke_credential_v14(text,text,text) to service_role;
grant execute on function public.trustrelay_scim_disable_v14(text,text) to service_role;
grant execute on function public.trustrelay_scim_set_policy_v14(text,text,text,boolean,boolean) to service_role;
grant execute on function public.trustrelay_scim_resolve_bearer_v14(text) to service_role;
grant execute on function public.trustrelay_scim_upsert_user_v14(text,text,text,text,text,text,text,text,text,boolean) to service_role;
grant execute on function public.trustrelay_scim_delete_user_v14(text,text) to service_role;
