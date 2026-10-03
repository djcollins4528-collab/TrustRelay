-- TrustRelay v1.4 — SCIM 2.0 automated provisioning/deprovisioning
-- Entra/Okta compatible SCIM Users + Groups, OAuth client credentials,
-- rotatable bearer compatibility, verified-domain pre-provisioning, soft deprovisioning,
-- privileged-member protection, and hash-linked audit events.

create table if not exists public.organization_scim_configs(
  organization_id text primary key references public.organizations(id) on delete cascade,
  provider_kind text not null check(provider_kind in ('entra','okta','generic')),
  status text not null default 'active' check(status in ('active','disabled')),
  default_role text not null default 'verifier'
    check(default_role in ('compliance','verifier','developer','auditor')),
  allow_static_bearer boolean not null default true,
  group_sync_enabled boolean not null default true,
  created_by_account_id text references public.accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_sync_at timestamptz,
  last_error text
);

create table if not exists public.organization_scim_credentials(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  client_id text not null unique,
  secret_hash text not null,
  label text not null default 'Primary',
  status text not null default 'active' check(status in ('active','revoked')),
  expires_at timestamptz not null,
  created_by_account_id text references public.accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index if not exists organization_scim_credentials_org_idx
  on public.organization_scim_credentials(organization_id,status);

create table if not exists public.organization_scim_access_tokens(
  token_hash text primary key,
  credential_id text not null references public.organization_scim_credentials(id) on delete cascade,
  organization_id text not null references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_used_at timestamptz
);
create index if not exists organization_scim_access_tokens_org_idx
  on public.organization_scim_access_tokens(organization_id,expires_at);

create table if not exists public.organization_scim_users(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  account_id text not null references public.accounts(id) on delete cascade,
  external_id text,
  user_name text not null,
  email text not null,
  display_name text,
  given_name text,
  family_name text,
  title text,
  active boolean not null default true,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists organization_scim_users_org_username_uq
  on public.organization_scim_users(organization_id,lower(user_name));
create unique index if not exists organization_scim_users_org_account_uq
  on public.organization_scim_users(organization_id,account_id);
create unique index if not exists organization_scim_users_org_external_uq
  on public.organization_scim_users(organization_id,external_id)
  where external_id is not null;

create table if not exists public.organization_scim_groups(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  external_id text,
  display_name text not null,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists organization_scim_groups_org_name_uq
  on public.organization_scim_groups(organization_id,lower(display_name));
create unique index if not exists organization_scim_groups_org_external_uq
  on public.organization_scim_groups(organization_id,external_id)
  where external_id is not null;

create table if not exists public.organization_scim_group_members(
  group_id text not null references public.organization_scim_groups(id) on delete cascade,
  user_id text not null references public.organization_scim_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(group_id,user_id)
);

alter table public.organization_scim_configs enable row level security;
alter table public.organization_scim_configs force row level security;
alter table public.organization_scim_credentials enable row level security;
alter table public.organization_scim_credentials force row level security;
alter table public.organization_scim_access_tokens enable row level security;
alter table public.organization_scim_access_tokens force row level security;
alter table public.organization_scim_users enable row level security;
alter table public.organization_scim_users force row level security;
alter table public.organization_scim_groups enable row level security;
alter table public.organization_scim_groups force row level security;
alter table public.organization_scim_group_members enable row level security;
alter table public.organization_scim_group_members force row level security;

revoke all on public.organization_scim_configs from public,anon,authenticated;
revoke all on public.organization_scim_credentials from public,anon,authenticated;
revoke all on public.organization_scim_access_tokens from public,anon,authenticated;
revoke all on public.organization_scim_users from public,anon,authenticated;
revoke all on public.organization_scim_groups from public,anon,authenticated;
revoke all on public.organization_scim_group_members from public,anon,authenticated;

drop policy if exists organization_scim_configs_deny_direct on public.organization_scim_configs;
create policy organization_scim_configs_deny_direct on public.organization_scim_configs
for all to authenticated using(false) with check(false);
drop policy if exists organization_scim_credentials_deny_direct on public.organization_scim_credentials;
create policy organization_scim_credentials_deny_direct on public.organization_scim_credentials
for all to authenticated using(false) with check(false);
drop policy if exists organization_scim_access_tokens_deny_direct on public.organization_scim_access_tokens;
create policy organization_scim_access_tokens_deny_direct on public.organization_scim_access_tokens
for all to authenticated using(false) with check(false);
drop policy if exists organization_scim_users_deny_direct on public.organization_scim_users;
create policy organization_scim_users_deny_direct on public.organization_scim_users
for all to authenticated using(false) with check(false);
drop policy if exists organization_scim_groups_deny_direct on public.organization_scim_groups;
create policy organization_scim_groups_deny_direct on public.organization_scim_groups
for all to authenticated using(false) with check(false);
drop policy if exists organization_scim_group_members_deny_direct on public.organization_scim_group_members;
create policy organization_scim_group_members_deny_direct on public.organization_scim_group_members
for all to authenticated using(false) with check(false);

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
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'configured',found,
    'config',case when found then jsonb_build_object(
      'providerKind',v_cfg.provider_kind,
      'status',v_cfg.status,
      'defaultRole',v_cfg.default_role,
      'allowStaticBearer',v_cfg.allow_static_bearer,
      'groupSyncEnabled',v_cfg.group_sync_enabled,
      'createdAt',v_cfg.created_at,
      'updatedAt',v_cfg.updated_at,
      'lastSyncAt',v_cfg.last_sync_at,
      'lastError',v_cfg.last_error
    ) else null end,
    'credentials',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',c.id,'clientId',c.client_id,'label',c.label,'status',c.status,
        'expiresAt',c.expires_at,'createdAt',c.created_at,
        'lastUsedAt',c.last_used_at,'revokedAt',c.revoked_at
      ) order by c.created_at desc)
      from public.organization_scim_credentials c
      where c.organization_id=p_org_id
    ),'[]'::jsonb),
    'counts',jsonb_build_object(
      'users',(select count(*) from public.organization_scim_users u where u.organization_id=p_org_id),
      'activeUsers',(select count(*) from public.organization_scim_users u where u.organization_id=p_org_id and u.active),
      'groups',(select count(*) from public.organization_scim_groups g where g.organization_id=p_org_id)
    )
  );
end;
$function$;

create or replace function public.trustrelay_scim_admin_status_v14(p_org_id text)
returns jsonb
language sql
security invoker
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
  v_active_count integer;
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
  where organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_ACTIVE_SSO');
  end if;

  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if p_client_id !~ '^tr_scim_[a-z0-9]{24,80}$' or p_secret_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_INVALID');
  end if;
  if p_expires_at<=clock_timestamp()+interval '30 days'
     or p_expires_at>clock_timestamp()+interval '3 years 1 day' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_EXPIRY_INVALID');
  end if;

  select count(*) into v_active_count
  from public.organization_scim_credentials
  where organization_id=p_org_id and status='active' and expires_at>clock_timestamp();
  if v_active_count>=2 then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACTIVE_CREDENTIAL_LIMIT');
  end if;

  insert into public.organization_scim_configs(
    organization_id,provider_kind,status,default_role,allow_static_bearer,
    group_sync_enabled,created_by_account_id,created_at,updated_at
  ) values(
    p_org_id,v_sso.provider_kind,'active',p_default_role,true,true,
    p_actor_account_id,now(),now()
  )
  on conflict(organization_id) do update set
    provider_kind=excluded.provider_kind,status='active',
    default_role=excluded.default_role,updated_at=now(),last_error=null;

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
      'expiresAt',p_expires_at,'providerKind',v_sso.provider_kind,
      'defaultRole',p_default_role
    )
  );

  return jsonb_build_object(
    'ok',true,'credentialId',v_id,'clientId',p_client_id,
    'expiresAt',p_expires_at,'providerKind',v_sso.provider_kind
  );
end;
$function$;

create or replace function public.trustrelay_scim_store_credential_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language sql
security invoker
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

  delete from public.organization_scim_access_tokens where credential_id=p_credential_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.credential_revoked',
    'scim_credential',p_credential_id,'{}'::jsonb
  );
  return jsonb_build_object('ok',true,'credentialId',p_credential_id,'status','revoked');
end;
$function$;

create or replace function public.trustrelay_scim_revoke_credential_v14(
  p_org_id text,p_actor_account_id text,p_credential_id text
)
returns jsonb
language sql
security invoker
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
  set status='disabled',updated_at=now()
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  update public.organization_scim_credentials
  set status='revoked',revoked_at=coalesce(revoked_at,now())
  where organization_id=p_org_id and status='active';

  delete from public.organization_scim_access_tokens where organization_id=p_org_id;

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
security invoker
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

  update public.organization_scim_configs
  set default_role=p_default_role,
      allow_static_bearer=coalesce(p_allow_static_bearer,true),
      group_sync_enabled=coalesce(p_group_sync_enabled,true),
      updated_at=now()
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.policy_changed',
    'organization',p_org_id,
    jsonb_build_object(
      'defaultRole',p_default_role,
      'allowStaticBearer',coalesce(p_allow_static_bearer,true),
      'groupSyncEnabled',coalesce(p_group_sync_enabled,true)
    )
  );

  return jsonb_build_object(
    'ok',true,'defaultRole',p_default_role,
    'allowStaticBearer',coalesce(p_allow_static_bearer,true),
    'groupSyncEnabled',coalesce(p_group_sync_enabled,true)
  );
end;
$function$;

create or replace function public.trustrelay_scim_set_policy_v14(
  p_org_id text,p_actor_account_id text,p_default_role text,
  p_allow_static_bearer boolean,p_group_sync_enabled boolean
)
returns jsonb
language sql
security invoker
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_set_policy_core_v14(
    p_org_id,p_actor_account_id,p_default_role,p_allow_static_bearer,p_group_sync_enabled
  );
$function$;

create or replace function private.trustrelay_scim_issue_access_token_core_v14(
  p_client_id text,p_secret_hash text,p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  v_cred public.organization_scim_credentials%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
  v_exp timestamptz:=clock_timestamp()+interval '1 hour';
begin
  select * into v_cred
  from public.organization_scim_credentials
  where client_id=p_client_id and secret_hash=p_secret_hash
    and status='active' and expires_at>clock_timestamp()
  limit 1;

  if not found then return jsonb_build_object('ok',false,'status',401,'code','INVALID_CLIENT'); end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=v_cred.organization_id and status='active';
  if not found then return jsonb_build_object('ok',false,'status',401,'code','SCIM_DISABLED'); end if;

  delete from public.organization_scim_access_tokens
  where organization_id=v_cred.organization_id and expires_at<=clock_timestamp();

  insert into public.organization_scim_access_tokens(
    token_hash,credential_id,organization_id,created_at,expires_at
  ) values(p_token_hash,v_cred.id,v_cred.organization_id,now(),v_exp);

  update public.organization_scim_credentials set last_used_at=now() where id=v_cred.id;

  return jsonb_build_object(
    'ok',true,'organizationId',v_cred.organization_id,
    'expiresAt',v_exp,'expiresIn',3600
  );
end;
$function$;

create or replace function public.trustrelay_scim_issue_access_token_v14(
  p_client_id text,p_secret_hash text,p_token_hash text
)
returns jsonb
language sql
security invoker
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_issue_access_token_core_v14(
    p_client_id,p_secret_hash,p_token_hash
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
  v_org text;
  v_cred_id text;
  v_mode text;
  v_cfg public.organization_scim_configs%rowtype;
begin
  select t.organization_id,t.credential_id into v_org,v_cred_id
  from public.organization_scim_access_tokens t
  join public.organization_scim_credentials c on c.id=t.credential_id
  where t.token_hash=p_token_hash and t.expires_at>clock_timestamp()
    and c.status='active' and c.expires_at>clock_timestamp()
  limit 1;

  if v_org is not null then
    v_mode:='oauth_access_token';
    update public.organization_scim_access_tokens set last_used_at=now() where token_hash=p_token_hash;
  else
    select c.organization_id,c.id into v_org,v_cred_id
    from public.organization_scim_credentials c
    join public.organization_scim_configs cfg on cfg.organization_id=c.organization_id
    where c.secret_hash=p_token_hash and c.status='active'
      and c.expires_at>clock_timestamp() and cfg.status='active'
      and cfg.allow_static_bearer=true
    limit 1;
    if v_org is not null then v_mode:='static_bearer'; end if;
  end if;

  if v_org is null then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select * into v_cfg from public.organization_scim_configs
  where organization_id=v_org and status='active';
  if not found then return jsonb_build_object('ok',false,'status',401,'code','SCIM_DISABLED'); end if;

  update public.organization_scim_credentials set last_used_at=now() where id=v_cred_id;
  update public.organization_scim_configs set last_sync_at=now(),last_error=null where organization_id=v_org;

  return jsonb_build_object(
    'ok',true,'organizationId',v_org,'providerKind',v_cfg.provider_kind,
    'defaultRole',v_cfg.default_role,'groupSyncEnabled',v_cfg.group_sync_enabled,
    'authMode',v_mode
  );
end;
$function$;

create or replace function public.trustrelay_scim_resolve_bearer_v14(p_token_hash text)
returns jsonb
language sql
security invoker
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
  if not found then return jsonb_build_object('ok',false,'status',409,'code','SCIM_NOT_ACTIVE'); end if;

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
        organization_id,account_id,role,created_at,status,title,updated_at
      ) values(
        p_org_id,v_account.id,v_cfg.default_role,v_now_text,'active',
        nullif(left(btrim(coalesce(p_title,'')),160),''),v_now_text
      );
    else
      update public.organization_members
      set status='active',
          title=coalesce(nullif(left(btrim(coalesce(p_title,'')),160),''),title),
          disabled_at=null,disabled_by_account_id=null,
          removed_at=null,removed_by_account_id=null,
          updated_at=v_now_text
      where organization_id=p_org_id and account_id=v_account.id;
    end if;
  else
    if v_member.organization_id is null then
      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,title,updated_at,disabled_at
      ) values(
        p_org_id,v_account.id,v_cfg.default_role,v_now_text,'disabled',
        nullif(left(btrim(coalesce(p_title,'')),160),''),v_now_text,v_now_text
      );
    else
      update public.organization_members
      set status='disabled',disabled_at=coalesce(disabled_at,v_now_text),
          disabled_by_account_id=null,updated_at=v_now_text
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
        user_name=v_user_name,email=v_email,
        display_name=nullif(left(btrim(coalesce(p_display_name,'')),160),''),
        given_name=nullif(left(btrim(coalesce(p_given_name,'')),120),''),
        family_name=nullif(left(btrim(coalesce(p_family_name,'')),120),''),
        title=nullif(left(btrim(coalesce(p_title,'')),160),''),
        active=coalesce(p_active,true),version=version+1,updated_at=now()
    where organization_id=p_org_id and id=v_id
    returning * into v_scim;
    v_event:=case when v_scim.active then 'organization.scim.user_updated'
                  else 'organization.scim.user_deprovisioned' end;
  else
    insert into public.organization_scim_users(
      id,organization_id,account_id,external_id,user_name,email,display_name,
      given_name,family_name,title,active,version,created_at,updated_at
    ) values(
      v_id,p_org_id,v_account.id,nullif(btrim(coalesce(p_external_id,'')),''),
      v_user_name,v_email,nullif(left(btrim(coalesce(p_display_name,'')),160),''),
      nullif(left(btrim(coalesce(p_given_name,'')),120),''),
      nullif(left(btrim(coalesce(p_family_name,'')),120),''),
      nullif(left(btrim(coalesce(p_title,'')),160),''),
      coalesce(p_active,true),1,now(),now()
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
security invoker
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
  select * into v_scim from public.organization_scim_users
  where organization_id=p_org_id and id=p_scim_id for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND'); end if;

  select * into v_member from public.organization_members
  where organization_id=p_org_id and account_id=v_scim.account_id for update;

  if found and v_member.role in ('owner','admin') then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
  end if;

  update public.organization_scim_users
  set active=false,version=version+1,updated_at=now()
  where id=p_scim_id;

  update public.organization_members
  set status='disabled',disabled_at=coalesce(disabled_at,v_now_text),
      disabled_by_account_id=null,updated_at=v_now_text
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
security invoker
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_delete_user_core_v14(p_org_id,p_scim_id);
$function$;

create or replace function private.trustrelay_scim_append_audit_core_v14(
  p_org_id text,p_event_type text,p_target_type text,p_target_id text,p_metadata jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'private','pg_catalog'
as $function$
declare v_id text;
begin
  v_id:=private.trustrelay_append_org_audit_v09(
    p_org_id,null,p_event_type,p_target_type,p_target_id,coalesce(p_metadata,'{}'::jsonb)
  );
  return jsonb_build_object('ok',true,'auditEventId',v_id);
end;
$function$;

create or replace function public.trustrelay_scim_append_audit_v14(
  p_org_id text,p_event_type text,p_target_type text,p_target_id text,p_metadata jsonb
)
returns jsonb
language sql
security invoker
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_append_audit_core_v14(
    p_org_id,p_event_type,p_target_type,p_target_id,p_metadata
  );
$function$;

revoke all on function private.trustrelay_scim_admin_status_core_v14(uuid,text) from public,anon,authenticated;
grant execute on function private.trustrelay_scim_admin_status_core_v14(uuid,text) to authenticated,service_role;
revoke all on function public.trustrelay_scim_admin_status_v14(text) from public,anon;
grant execute on function public.trustrelay_scim_admin_status_v14(text) to authenticated;

revoke all on function private.trustrelay_scim_store_credential_core_v14(text,text,text,text,text,text,timestamptz) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_revoke_credential_core_v14(text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_disable_core_v14(text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_set_policy_core_v14(text,text,text,boolean,boolean) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_issue_access_token_core_v14(text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_resolve_bearer_core_v14(text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_upsert_user_core_v14(text,text,text,text,text,text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_delete_user_core_v14(text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_append_audit_core_v14(text,text,text,text,jsonb) from public,anon,authenticated;

grant execute on function private.trustrelay_scim_store_credential_core_v14(text,text,text,text,text,text,timestamptz) to service_role;
grant execute on function private.trustrelay_scim_revoke_credential_core_v14(text,text,text) to service_role;
grant execute on function private.trustrelay_scim_disable_core_v14(text,text) to service_role;
grant execute on function private.trustrelay_scim_set_policy_core_v14(text,text,text,boolean,boolean) to service_role;
grant execute on function private.trustrelay_scim_issue_access_token_core_v14(text,text,text) to service_role;
grant execute on function private.trustrelay_scim_resolve_bearer_core_v14(text) to service_role;
grant execute on function private.trustrelay_scim_upsert_user_core_v14(text,text,text,text,text,text,text,text,text,boolean) to service_role;
grant execute on function private.trustrelay_scim_delete_user_core_v14(text,text) to service_role;
grant execute on function private.trustrelay_scim_append_audit_core_v14(text,text,text,text,jsonb) to service_role;

revoke all on function public.trustrelay_scim_store_credential_v14(text,text,text,text,text,text,timestamptz) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_revoke_credential_v14(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_disable_v14(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_set_policy_v14(text,text,text,boolean,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_issue_access_token_v14(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_resolve_bearer_v14(text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_upsert_user_v14(text,text,text,text,text,text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_delete_user_v14(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_append_audit_v14(text,text,text,text,jsonb) from public,anon,authenticated;

grant execute on function public.trustrelay_scim_store_credential_v14(text,text,text,text,text,text,timestamptz) to service_role;
grant execute on function public.trustrelay_scim_revoke_credential_v14(text,text,text) to service_role;
grant execute on function public.trustrelay_scim_disable_v14(text,text) to service_role;
grant execute on function public.trustrelay_scim_set_policy_v14(text,text,text,boolean,boolean) to service_role;
grant execute on function public.trustrelay_scim_issue_access_token_v14(text,text,text) to service_role;
grant execute on function public.trustrelay_scim_resolve_bearer_v14(text) to service_role;
grant execute on function public.trustrelay_scim_upsert_user_v14(text,text,text,text,text,text,text,text,text,boolean) to service_role;
grant execute on function public.trustrelay_scim_delete_user_v14(text,text) to service_role;
grant execute on function public.trustrelay_scim_append_audit_v14(text,text,text,text,jsonb) to service_role;
