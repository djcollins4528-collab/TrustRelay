-- TrustRelay v1.4 — SCIM 2.0 user lifecycle provisioning
-- Organization-scoped Entra/Okta provisioning, hashed rotatable bearer credentials,
-- soft deprovisioning, owner protection, and SCIM-aware SSO bootstrap.

alter table public.organization_members
  add column if not exists provisioning_source text not null default 'manual',
  add column if not exists provisioning_ref text;

do $block$
begin
  if not exists(
    select 1 from pg_constraint
    where conname='organization_members_provisioning_source_check'
      and conrelid='public.organization_members'::regclass
  ) then
    alter table public.organization_members
      add constraint organization_members_provisioning_source_check
      check(provisioning_source in ('manual','sso_jit','scim'));
  end if;
end
$block$;

create table if not exists public.organization_scim_configs(
  organization_id text primary key references public.organizations(id) on delete cascade,
  tenant_key text not null unique,
  token_hash text not null,
  token_last_four text not null,
  status text not null default 'enabled'
    check(status in ('enabled','disabled')),
  default_role text not null default 'verifier'
    check(default_role in ('compliance','verifier','developer','auditor')),
  created_by_account_id text references public.accounts(id),
  last_rotated_at timestamptz not null default now(),
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organization_scim_token_hash_check
    check(token_hash ~ '^[0-9a-f]{64}$'),
  constraint organization_scim_token_last_four_check
    check(token_last_four ~ '^[A-Za-z0-9_-]{4}$'),
  constraint organization_scim_tenant_key_check
    check(tenant_key ~ '^scim_[A-Za-z0-9_-]{20,80}$')
);

create table if not exists public.organization_scim_users(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  external_id text,
  user_name text not null,
  email text not null,
  given_name text,
  family_name text,
  display_name text,
  active boolean not null default true,
  account_id text references public.accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deprovisioned_at timestamptz,
  last_synced_at timestamptz not null default now(),
  constraint organization_scim_user_id_check
    check(id ~ '^scimusr_[A-Za-z0-9_-]{20,80}$')
);

create unique index if not exists organization_scim_users_username_uq
  on public.organization_scim_users(organization_id,lower(user_name));
create unique index if not exists organization_scim_users_external_id_uq
  on public.organization_scim_users(organization_id,external_id)
  where external_id is not null and external_id<>'';
create index if not exists organization_scim_users_email_idx
  on public.organization_scim_users(organization_id,lower(email));
create index if not exists organization_scim_users_account_idx
  on public.organization_scim_users(organization_id,account_id)
  where account_id is not null;

alter table public.organization_scim_configs enable row level security;
alter table public.organization_scim_configs force row level security;
alter table public.organization_scim_users enable row level security;
alter table public.organization_scim_users force row level security;

revoke all on public.organization_scim_configs from public,anon,authenticated;
revoke all on public.organization_scim_users from public,anon,authenticated;

drop policy if exists organization_scim_configs_deny_all on public.organization_scim_configs;
create policy organization_scim_configs_deny_all
on public.organization_scim_configs
for all to anon,authenticated using(false) with check(false);

drop policy if exists organization_scim_users_deny_all on public.organization_scim_users;
create policy organization_scim_users_deny_all
on public.organization_scim_users
for all to anon,authenticated using(false) with check(false);

create or replace function private.trustrelay_scim_email_allowed_v14(
  p_org_id text,p_email text
)
returns boolean
language sql
stable
security definer
set search_path to 'public','pg_catalog'
as $function$
  select
    lower(btrim(coalesce(p_email,''))) ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    and exists(
      select 1
      from public.organization_sso_domains d
      where d.organization_id=p_org_id
        and d.domain=split_part(lower(btrim(p_email)),'@',2)
        and d.verification_status='verified'
    );
$function$;

create or replace function private.trustrelay_scim_apply_membership_v14(
  p_org_id text,p_scim_id text,p_account_id text,p_active boolean,p_default_role text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_member public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_joined boolean:=false;
  v_changed boolean:=false;
begin
  if p_account_id is null then
    return jsonb_build_object('ok',true,'linked',false,'membershipChanged',false);
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id
  for update;

  if coalesce(p_active,true)=false then
    if found and v_member.role='owner' then
      return jsonb_build_object(
        'ok',false,'status',409,'code','SCIM_OWNER_DEPROVISION_REQUIRES_TRANSFER'
      );
    end if;
    if found and v_member.status='active' then
      update public.organization_members
      set status='disabled',
          disabled_at=v_now,
          disabled_by_account_id=null,
          updated_at=v_now,
          provisioning_source='scim',
          provisioning_ref=p_scim_id
      where organization_id=p_org_id and account_id=p_account_id;
      v_changed:=true;
    end if;
    return jsonb_build_object(
      'ok',true,'linked',true,'membershipChanged',v_changed,'active',false
    );
  end if;

  if not found then
    insert into public.organization_members(
      organization_id,account_id,role,created_at,status,updated_at,
      provisioning_source,provisioning_ref
    ) values(
      p_org_id,p_account_id,p_default_role,v_now,'active',v_now,'scim',p_scim_id
    );
    v_joined:=true;
    v_changed:=true;
  elsif v_member.role<>'owner' then
    update public.organization_members
    set status='active',
        disabled_at=null,
        disabled_by_account_id=null,
        removed_at=null,
        removed_by_account_id=null,
        updated_at=v_now,
        provisioning_source='scim',
        provisioning_ref=p_scim_id
    where organization_id=p_org_id and account_id=p_account_id;
    v_changed:=v_member.status<>'active'
      or v_member.provisioning_source<>'scim'
      or coalesce(v_member.provisioning_ref,'')<>coalesce(p_scim_id,'');
  end if;

  return jsonb_build_object(
    'ok',true,'linked',true,'membershipChanged',v_changed,
    'joined',v_joined,'active',true
  );
end;
$function$;

create or replace function private.trustrelay_scim_config_core_v14(
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
  v_cfg public.organization_scim_configs%rowtype;
  v_total bigint:=0;
  v_active bigint:=0;
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

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object('ok',true,'configured',false,'organizationId',p_org_id);
  end if;

  select count(*),count(*) filter(where active)
  into v_total,v_active
  from public.organization_scim_users
  where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,'configured',true,'organizationId',p_org_id,
    'tenantKey',v_cfg.tenant_key,'status',v_cfg.status,
    'tokenLastFour',v_cfg.token_last_four,'defaultRole',v_cfg.default_role,
    'lastRotatedAt',v_cfg.last_rotated_at,'lastUsedAt',v_cfg.last_used_at,
    'totalUsers',v_total,'activeUsers',v_active
  );
end;
$function$;

create or replace function public.trustrelay_scim_config_v14(p_org_id text)
returns jsonb
language sql
security invoker
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_scim_config_core_v14(auth.uid(),p_org_id);
$function$;

create or replace function public.trustrelay_scim_store_config_v14(
  p_org_id text,p_actor_account_id text,p_tenant_key text,p_token_hash text,
  p_token_last_four text,p_default_role text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare v_now timestamptz:=clock_timestamp();
begin
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if p_tenant_key !~ '^scim_[A-Za-z0-9_-]{20,80}$'
     or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_token_last_four !~ '^[A-Za-z0-9_-]{4}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_FORMAT_INVALID');
  end if;

  if not exists(
    select 1 from public.organization_members m
    where m.organization_id=p_org_id and m.account_id=p_actor_account_id
      and m.status='active' and m.role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED');
  end if;

  if not exists(
    select 1 from public.organization_sso_configs s
    where s.organization_id=p_org_id and s.status='active'
      and s.provider_kind in ('entra','okta')
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_ACTIVE_ENTERPRISE_SSO');
  end if;

  if not exists(
    select 1 from public.organization_sso_domains d
    where d.organization_id=p_org_id and d.verification_status='verified'
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_VERIFIED_DOMAIN');
  end if;

  insert into public.organization_scim_configs(
    organization_id,tenant_key,token_hash,token_last_four,status,default_role,
    created_by_account_id,last_rotated_at,created_at,updated_at
  ) values(
    p_org_id,p_tenant_key,p_token_hash,p_token_last_four,'enabled',p_default_role,
    p_actor_account_id,v_now,v_now,v_now
  )
  on conflict(organization_id) do update set
    tenant_key=excluded.tenant_key,token_hash=excluded.token_hash,
    token_last_four=excluded.token_last_four,status='enabled',
    default_role=excluded.default_role,last_rotated_at=v_now,updated_at=v_now;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.configured',
    'organization',p_org_id,
    jsonb_build_object('defaultRole',p_default_role,'credentialRotated',true,'protocol','scim2')
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,'status','enabled',
    'tenantKey',p_tenant_key,'tokenLastFour',p_token_last_four,'defaultRole',p_default_role
  );
end;
$function$;

create or replace function public.trustrelay_scim_rotate_token_v14(
  p_org_id text,p_actor_account_id text,p_token_hash text,p_token_last_four text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare v_now timestamptz:=clock_timestamp();
begin
  if p_token_hash !~ '^[0-9a-f]{64}$'
     or p_token_last_four !~ '^[A-Za-z0-9_-]{4}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_FORMAT_INVALID');
  end if;
  if not exists(
    select 1 from public.organization_members m
    where m.organization_id=p_org_id and m.account_id=p_actor_account_id
      and m.status='active' and m.role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED');
  end if;

  update public.organization_scim_configs
  set token_hash=p_token_hash,token_last_four=p_token_last_four,
      status='enabled',last_rotated_at=v_now,updated_at=v_now
  where organization_id=p_org_id;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.token_rotated',
    'organization',p_org_id,'{}'::jsonb
  );

  return jsonb_build_object('ok',true,'tokenLastFour',p_token_last_four,'rotatedAt',v_now);
end;
$function$;

create or replace function public.trustrelay_scim_set_policy_v14(
  p_org_id text,p_actor_account_id text,p_status text,p_default_role text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare v_now timestamptz:=clock_timestamp();
begin
  if p_status not in ('enabled','disabled') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_STATUS_INVALID');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if not exists(
    select 1 from public.organization_members m
    where m.organization_id=p_org_id and m.account_id=p_actor_account_id
      and m.status='active' and m.role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED');
  end if;

  update public.organization_scim_configs
  set status=p_status,default_role=p_default_role,updated_at=v_now
  where organization_id=p_org_id;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.policy_changed',
    'organization',p_org_id,
    jsonb_build_object('status',p_status,'defaultRole',p_default_role)
  );

  return jsonb_build_object('ok',true,'status',p_status,'defaultRole',p_default_role);
end;
$function$;

create or replace function public.trustrelay_scim_auth_v14(
  p_tenant_key text,p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  v_cfg public.organization_scim_configs%rowtype;
  v_provider text;
begin
  select * into v_cfg
  from public.organization_scim_configs
  where tenant_key=p_tenant_key and token_hash=p_token_hash and status='enabled'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','SCIM_UNAUTHORIZED');
  end if;

  update public.organization_scim_configs
  set last_used_at=clock_timestamp(),updated_at=clock_timestamp()
  where organization_id=v_cfg.organization_id;

  select provider_kind into v_provider
  from public.organization_sso_configs
  where organization_id=v_cfg.organization_id;

  return jsonb_build_object(
    'ok',true,'organizationId',v_cfg.organization_id,
    'defaultRole',v_cfg.default_role,'providerKind',v_provider,
    'tenantKey',v_cfg.tenant_key
  );
end;
$function$;

create or replace function public.trustrelay_scim_write_user_v14(
  p_org_id text,p_mode text,p_scim_id text,p_external_id text,
  p_user_name text,p_email text,p_given_name text,p_family_name text,
  p_display_name text,p_active boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cfg public.organization_scim_configs%rowtype;
  v_existing public.organization_scim_users%rowtype;
  v_id text;
  v_user_name text:=lower(btrim(coalesce(p_user_name,'')));
  v_email text:=lower(btrim(coalesce(nullif(p_email,''),p_user_name,'')));
  v_account_id text;
  v_membership jsonb;
  v_now timestamptz:=clock_timestamp();
  v_event text;
begin
  if p_mode not in ('create','replace') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_WRITE_MODE_INVALID');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='enabled'
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','SCIM_DISABLED');
  end if;

  if length(v_user_name)<3 or length(v_user_name)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_USERNAME_INVALID');
  end if;
  if not private.trustrelay_scim_email_allowed_v14(p_org_id,v_email) then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EMAIL_DOMAIN_NOT_VERIFIED');
  end if;
  if p_external_id is not null and length(p_external_id)>512 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EXTERNAL_ID_INVALID');
  end if;

  if p_mode='create' then
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(user_name)=v_user_name
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_USERNAME_CONFLICT');
    end if;
    if nullif(btrim(coalesce(p_external_id,'')),'') is not null
       and exists(
         select 1 from public.organization_scim_users
         where organization_id=p_org_id and external_id=p_external_id
       ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXTERNAL_ID_CONFLICT');
    end if;
    v_id:='scimusr_'||replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-','');
  else
    select * into v_existing
    from public.organization_scim_users
    where organization_id=p_org_id and id=p_scim_id
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND');
    end if;
    v_id:=v_existing.id;
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(user_name)=v_user_name and id<>v_id
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_USERNAME_CONFLICT');
    end if;
    if nullif(btrim(coalesce(p_external_id,'')),'') is not null
       and exists(
         select 1 from public.organization_scim_users
         where organization_id=p_org_id and external_id=p_external_id and id<>v_id
       ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXTERNAL_ID_CONFLICT');
    end if;
  end if;

  select id into v_account_id
  from public.accounts
  where lower(email)=v_email and status='active'
  order by created_at
  limit 1;

  v_membership:=private.trustrelay_scim_apply_membership_v14(
    p_org_id,v_id,v_account_id,coalesce(p_active,true),v_cfg.default_role
  );
  if coalesce((v_membership->>'ok')::boolean,false)=false then return v_membership; end if;

  if p_mode='create' then
    insert into public.organization_scim_users(
      id,organization_id,external_id,user_name,email,given_name,family_name,
      display_name,active,account_id,created_at,updated_at,deprovisioned_at,last_synced_at
    ) values(
      v_id,p_org_id,nullif(btrim(coalesce(p_external_id,'')),''),
      v_user_name,v_email,nullif(btrim(coalesce(p_given_name,'')),''),
      nullif(btrim(coalesce(p_family_name,'')),''),
      nullif(btrim(coalesce(p_display_name,'')),''),
      coalesce(p_active,true),v_account_id,v_now,v_now,
      case when coalesce(p_active,true) then null else v_now end,v_now
    );
    v_event:='organization.member.scim_provisioned';
  else
    update public.organization_scim_users
    set external_id=nullif(btrim(coalesce(p_external_id,'')),''),
        user_name=v_user_name,email=v_email,
        given_name=nullif(btrim(coalesce(p_given_name,'')),''),
        family_name=nullif(btrim(coalesce(p_family_name,'')),''),
        display_name=nullif(btrim(coalesce(p_display_name,'')),''),
        active=coalesce(p_active,true),account_id=v_account_id,updated_at=v_now,
        deprovisioned_at=case when coalesce(p_active,true) then null else coalesce(deprovisioned_at,v_now) end,
        last_synced_at=v_now
    where organization_id=p_org_id and id=v_id;
    v_event:=case when coalesce(p_active,true)
      then 'organization.member.scim_updated'
      else 'organization.member.scim_deprovisioned'
    end;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,v_event,'scim_user',v_id,
    jsonb_build_object(
      'userName',v_user_name,'email',v_email,
      'externalId',nullif(btrim(coalesce(p_external_id,'')),''),
      'active',coalesce(p_active,true),'accountId',v_account_id,
      'membershipChanged',coalesce((v_membership->>'membershipChanged')::boolean,false)
    )
  );

  return jsonb_build_object(
    'ok',true,'user',(
      select jsonb_build_object(
        'id',u.id,'organizationId',u.organization_id,'externalId',u.external_id,
        'userName',u.user_name,'email',u.email,'givenName',u.given_name,
        'familyName',u.family_name,'displayName',u.display_name,'active',u.active,
        'accountId',u.account_id,'createdAt',u.created_at,'updatedAt',u.updated_at
      )
      from public.organization_scim_users u
      where u.organization_id=p_org_id and u.id=v_id
    )
  );
exception when unique_violation then
  return jsonb_build_object('ok',false,'status',409,'code','SCIM_UNIQUENESS_CONFLICT');
end;
$function$;

create or replace function public.trustrelay_scim_get_user_v14(
  p_org_id text,p_scim_id text
)
returns jsonb
language sql
security definer
set search_path to 'public','pg_catalog'
as $function$
  select coalesce((
    select jsonb_build_object(
      'ok',true,'user',jsonb_build_object(
        'id',u.id,'externalId',u.external_id,'userName',u.user_name,
        'email',u.email,'givenName',u.given_name,'familyName',u.family_name,
        'displayName',u.display_name,'active',u.active,'accountId',u.account_id,
        'createdAt',u.created_at,'updatedAt',u.updated_at
      )
    )
    from public.organization_scim_users u
    where u.organization_id=p_org_id and u.id=p_scim_id
  ),jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND'));
$function$;

create or replace function public.trustrelay_scim_list_users_v14(
  p_org_id text,p_filter_attribute text default null,p_filter_value text default null,
  p_start_index integer default 1,p_count integer default 100
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  v_start integer:=greatest(coalesce(p_start_index,1),1);
  v_count integer:=greatest(1,least(coalesce(p_count,100),100));
  v_total bigint;
  v_users jsonb;
begin
  if p_filter_attribute is not null
     and p_filter_attribute not in ('id','userName','externalId','emails.value') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_FILTER_UNSUPPORTED');
  end if;

  select count(*) into v_total
  from public.organization_scim_users u
  where u.organization_id=p_org_id
    and (
      p_filter_attribute is null
      or (p_filter_attribute='id' and u.id=p_filter_value)
      or (p_filter_attribute='userName' and lower(u.user_name)=lower(p_filter_value))
      or (p_filter_attribute='externalId' and u.external_id=p_filter_value)
      or (p_filter_attribute='emails.value' and lower(u.email)=lower(p_filter_value))
    );

  select coalesce(jsonb_agg(x.payload order by x.user_name),'[]'::jsonb)
  into v_users
  from (
    select u.user_name,jsonb_build_object(
      'id',u.id,'externalId',u.external_id,'userName',u.user_name,
      'email',u.email,'givenName',u.given_name,'familyName',u.family_name,
      'displayName',u.display_name,'active',u.active,'accountId',u.account_id,
      'createdAt',u.created_at,'updatedAt',u.updated_at
    ) payload
    from public.organization_scim_users u
    where u.organization_id=p_org_id
      and (
        p_filter_attribute is null
        or (p_filter_attribute='id' and u.id=p_filter_value)
        or (p_filter_attribute='userName' and lower(u.user_name)=lower(p_filter_value))
        or (p_filter_attribute='externalId' and u.external_id=p_filter_value)
        or (p_filter_attribute='emails.value' and lower(u.email)=lower(p_filter_value))
      )
    order by u.user_name
    offset (v_start-1)
    limit v_count
  ) x;

  return jsonb_build_object(
    'ok',true,'totalResults',v_total,'startIndex',v_start,
    'itemsPerPage',jsonb_array_length(v_users),'users',v_users
  );
end;
$function$;

create or replace function public.trustrelay_scim_deactivate_user_v14(
  p_org_id text,p_scim_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_user public.organization_scim_users%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
  v_membership jsonb;
  v_now timestamptz:=clock_timestamp();
begin
  select * into v_user
  from public.organization_scim_users
  where organization_id=p_org_id and id=p_scim_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='enabled';
  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','SCIM_DISABLED');
  end if;

  v_membership:=private.trustrelay_scim_apply_membership_v14(
    p_org_id,p_scim_id,v_user.account_id,false,v_cfg.default_role
  );
  if coalesce((v_membership->>'ok')::boolean,false)=false then return v_membership; end if;

  update public.organization_scim_users
  set active=false,deprovisioned_at=coalesce(deprovisioned_at,v_now),
      updated_at=v_now,last_synced_at=v_now
  where organization_id=p_org_id and id=p_scim_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'organization.member.scim_deprovisioned',
    'scim_user',p_scim_id,
    jsonb_build_object(
      'userName',v_user.user_name,'email',v_user.email,'accountId',v_user.account_id
    )
  );

  return jsonb_build_object('ok',true,'id',p_scim_id,'active',false);
end;
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
  v_account_email text;
  v_cfg public.organization_sso_configs%rowtype;
  v_match jsonb;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_existing public.organization_members%rowtype;
  v_scim_cfg public.organization_scim_configs%rowtype;
  v_scim_user public.organization_scim_users%rowtype;
  v_membership jsonb;
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
  v_account_email:=lower(v_ctx#>>'{account,email}');

  for v_cfg in
    select s.*
    from public.organization_sso_configs s
    where s.status='active'
      and (
        s.jit_enabled=true
        or exists(
          select 1 from public.organization_scim_configs c
          where c.organization_id=s.organization_id and c.status='enabled'
        )
      )
  loop
    v_match:=private.trustrelay_sso_session_match_v13(p_uid,v_cfg.organization_id);
    if not coalesce((v_match->>'providerMatched')::boolean,false) then continue; end if;

    select * into v_scim_cfg
    from public.organization_scim_configs
    where organization_id=v_cfg.organization_id and status='enabled'
    limit 1;

    if found then
      select * into v_scim_user
      from public.organization_scim_users
      where organization_id=v_cfg.organization_id and active=true
        and (lower(email)=v_account_email or lower(user_name)=v_account_email)
      order by updated_at desc
      limit 1;

      if not found then
        return jsonb_build_object(
          'ok',true,'joined',false,'scimManaged',true,
          'organizationId',v_cfg.organization_id,'code','SCIM_PROVISIONING_REQUIRED'
        );
      end if;

      update public.organization_scim_users
      set account_id=v_account_id,last_synced_at=clock_timestamp(),updated_at=clock_timestamp()
      where id=v_scim_user.id;

      v_membership:=private.trustrelay_scim_apply_membership_v14(
        v_cfg.organization_id,v_scim_user.id,v_account_id,true,v_scim_cfg.default_role
      );
      if coalesce((v_membership->>'ok')::boolean,false)=false then return v_membership; end if;

      if coalesce((v_membership->>'membershipChanged')::boolean,false) then
        perform private.trustrelay_append_org_audit_v09(
          v_cfg.organization_id,v_account_id,
          'organization.member.scim_linked','organization_member',v_account_id,
          jsonb_build_object(
            'scimUserId',v_scim_user.id,'providerKind',v_cfg.provider_kind,
            'defaultRole',v_scim_cfg.default_role
          )
        );
      end if;

      select * into v_existing
      from public.organization_members
      where organization_id=v_cfg.organization_id and account_id=v_account_id
      limit 1;

      return jsonb_build_object(
        'ok',true,'joined',coalesce((v_membership->>'joined')::boolean,false),
        'scimManaged',true,'organizationId',v_cfg.organization_id,
        'role',v_existing.role,'membershipStatus',v_existing.status
      );
    end if;

    if v_cfg.jit_enabled then
      select * into v_existing
      from public.organization_members
      where organization_id=v_cfg.organization_id and account_id=v_account_id
      limit 1;

      if found then
        return jsonb_build_object(
          'ok',true,'joined',false,'organizationId',v_cfg.organization_id,
          'role',v_existing.role,'membershipStatus',v_existing.status
        );
      end if;

      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,updated_at,
        provisioning_source,provisioning_ref
      ) values(
        v_cfg.organization_id,v_account_id,v_cfg.default_role,v_now,'active',v_now,
        'sso_jit',null
      );

      perform private.trustrelay_append_org_audit_v09(
        v_cfg.organization_id,v_account_id,
        'organization.member.sso_jit_joined','organization_member',v_account_id,
        jsonb_build_object(
          'role',v_cfg.default_role,'protocol',v_cfg.protocol,'providerKind',v_cfg.provider_kind
        )
      );

      return jsonb_build_object(
        'ok',true,'joined',true,'organizationId',v_cfg.organization_id,'role',v_cfg.default_role
      );
    end if;
  end loop;

  return jsonb_build_object('ok',true,'joined',false);
end;
$function$;

revoke all on function private.trustrelay_scim_email_allowed_v14(text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text) from public,anon,authenticated;
revoke all on function private.trustrelay_scim_config_core_v14(uuid,text) from public,anon;
grant execute on function private.trustrelay_scim_email_allowed_v14(text,text) to service_role;
grant execute on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text) to service_role;
grant execute on function private.trustrelay_scim_config_core_v14(uuid,text) to authenticated,service_role;

revoke all on function public.trustrelay_scim_config_v14(text) from public,anon;
grant execute on function public.trustrelay_scim_config_v14(text) to authenticated;

revoke all on function public.trustrelay_scim_store_config_v14(text,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_rotate_token_v14(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_set_policy_v14(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_auth_v14(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_write_user_v14(text,text,text,text,text,text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_get_user_v14(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_list_users_v14(text,text,text,integer,integer) from public,anon,authenticated;
revoke all on function public.trustrelay_scim_deactivate_user_v14(text,text) from public,anon,authenticated;

grant execute on function public.trustrelay_scim_store_config_v14(text,text,text,text,text,text) to service_role;
grant execute on function public.trustrelay_scim_rotate_token_v14(text,text,text,text) to service_role;
grant execute on function public.trustrelay_scim_set_policy_v14(text,text,text,text) to service_role;
grant execute on function public.trustrelay_scim_auth_v14(text,text) to service_role;
grant execute on function public.trustrelay_scim_write_user_v14(text,text,text,text,text,text,text,text,text,boolean) to service_role;
grant execute on function public.trustrelay_scim_get_user_v14(text,text) to service_role;
grant execute on function public.trustrelay_scim_list_users_v14(text,text,text,integer,integer) to service_role;
grant execute on function public.trustrelay_scim_deactivate_user_v14(text,text) to service_role;
