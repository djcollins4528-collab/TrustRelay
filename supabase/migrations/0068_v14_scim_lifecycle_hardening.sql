-- Applied staging migration 20261003232837: v14_scim_lifecycle_hardening


-- TrustRelay v1.4 SCIM lifecycle hardening.
-- Users-only provisioning, manual-membership takeover protection, per-credential
-- rate limiting, SCIM-aware SSO JIT enforcement, and invoker-safe admin status.

alter table public.organization_scim_users
  add column if not exists deprovisioned_at timestamptz,
  add column if not exists last_synced_at timestamptz not null default now();

create unique index if not exists organization_scim_users_org_email_uq
  on public.organization_scim_users(organization_id,lower(email));
create index if not exists organization_scim_users_account_fk_idx
  on public.organization_scim_users(account_id);
create index if not exists organization_scim_credentials_created_by_idx
  on public.organization_scim_credentials(created_by_account_id)
  where created_by_account_id is not null;

drop table if exists private.trustrelay_scim_rate_buckets_v14;
create table private.trustrelay_scim_rate_buckets_v14(
  credential_id text not null,
  bucket_start timestamptz not null,
  request_count integer not null default 0,
  primary key(credential_id,bucket_start)
);
revoke all on private.trustrelay_scim_rate_buckets_v14 from public,anon,authenticated;

-- Recreate the verified-domain guard here because 0067 retires the legacy
-- helper surface before the hardened lifecycle functions are installed.
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
    lower(btrim(coalesce(p_email,''))) ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+  p_org_id text,p_scim_id text,p_account_id text,p_active boolean,p_default_role text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_member public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_changed boolean:=false;
  v_joined boolean:=false;
begin
  if p_account_id is null then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_REQUIRED');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',500,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id
  for update;

  if found and v_member.role in ('owner','admin') then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
  end if;

  if found and (
    coalesce(v_member.provisioning_source,'manual')<>'scim'
    or coalesce(v_member.provisioning_ref,'')<>p_scim_id
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
  end if;

  if coalesce(p_active,true)=false then
    if found and v_member.status<>'disabled' then
      update public.organization_members
      set status='disabled',disabled_at=coalesce(disabled_at,v_now),
          disabled_by_account_id=null,updated_at=v_now
      where organization_id=p_org_id and account_id=p_account_id;
      v_changed:=true;
    end if;
    return jsonb_build_object(
      'ok',true,'membershipChanged',v_changed,'joined',false,'active',false
    );
  end if;

  if not found then
    insert into public.organization_members(
      organization_id,account_id,role,created_at,status,updated_at,
      provisioning_source,provisioning_ref
    ) values(
      p_org_id,p_account_id,p_default_role,v_now,'active',v_now,'scim',p_scim_id
    );
    v_changed:=true;
    v_joined:=true;
  elsif v_member.status<>'active' then
    update public.organization_members
    set status='active',disabled_at=null,disabled_by_account_id=null,
        removed_at=null,removed_by_account_id=null,updated_at=v_now
    where organization_id=p_org_id and account_id=p_account_id;
    v_changed:=true;
  end if;

  return jsonb_build_object(
    'ok',true,'membershipChanged',v_changed,'joined',v_joined,'active',true
  );
end;
$function$;

create or replace function private.trustrelay_scim_resolve_bearer_core_v14(
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cred public.organization_scim_credentials%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
  v_bucket timestamptz:=date_trunc('minute',clock_timestamp());
  v_count integer;
  v_retry integer;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select c.* into v_cred
  from public.organization_scim_credentials c
  join public.organization_scim_configs cfg on cfg.organization_id=c.organization_id
  where c.secret_hash=p_token_hash
    and c.status='active'
    and c.expires_at>clock_timestamp()
    and cfg.status='active'
    and cfg.allow_static_bearer=true
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=v_cred.organization_id and status='active';

  insert into private.trustrelay_scim_rate_buckets_v14(
    credential_id,bucket_start,request_count
  ) values(v_cred.id,v_bucket,1)
  on conflict(credential_id,bucket_start)
  do update set request_count=private.trustrelay_scim_rate_buckets_v14.request_count+1
  returning request_count into v_count;

  if v_count>v_cfg.rate_limit_per_minute then
    v_retry:=greatest(
      1,
      ceil(extract(epoch from (v_bucket+interval '1 minute'-clock_timestamp())))::integer
    );
    update public.organization_scim_configs
    set last_error='SCIM_RATE_LIMITED',updated_at=now()
    where organization_id=v_cred.organization_id;
    return jsonb_build_object(
      'ok',false,'status',429,'code','SCIM_RATE_LIMITED','retryAfter',v_retry
    );
  end if;

  delete from private.trustrelay_scim_rate_buckets_v14
  where credential_id=v_cred.id and bucket_start<v_bucket-interval '10 minutes';

  update public.organization_scim_credentials
  set last_used_at=now()
  where id=v_cred.id;

  update public.organization_scim_configs
  set last_sync_at=now(),last_error=null,updated_at=now()
  where organization_id=v_cred.organization_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',v_cred.organization_id,
    'credentialId',v_cred.id,
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
set search_path to 'public','private','extensions','pg_catalog'
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
  v_email text:=lower(btrim(coalesce(nullif(p_email,''),p_user_name,'')));
  v_user_name text:=lower(btrim(coalesce(p_user_name,'')));
  v_display text;
  v_membership jsonb;
  v_event text;
  v_now timestamptz:=clock_timestamp();
  v_now_text text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_NOT_ACTIVE');
  end if;

  if length(v_user_name)<3 or length(v_user_name)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_USERNAME_INVALID');
  end if;
  if v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     or length(v_email)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EMAIL_INVALID');
  end if;
  if not private.trustrelay_scim_email_allowed_v14(p_org_id,v_email) then
    return jsonb_build_object('ok',false,'status',403,'code','SCIM_EMAIL_DOMAIN_NOT_VERIFIED');
  end if;
  if nullif(btrim(coalesce(p_external_id,'')),'') is not null
     and length(p_external_id)>512 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EXTERNAL_ID_INVALID');
  end if;

  if p_scim_id is not null and p_scim_id<>'' then
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and id=p_scim_id
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND');
    end if;
  elsif nullif(btrim(coalesce(p_external_id,'')),'') is not null then
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and external_id=btrim(p_external_id)
    for update;
  else
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and lower(user_name)=v_user_name
    for update;
  end if;

  if found then
    v_id:=v_scim.id;
    select * into v_account
    from public.accounts where id=v_scim.account_id and status='active'
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_MISSING');
    end if;

    select * into v_member
    from public.organization_members
    where organization_id=p_org_id and account_id=v_account.id
    for update;

    if found and v_member.role in ('owner','admin') then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
    end if;
    if found and (
      coalesce(v_member.provisioning_source,'manual')<>'scim'
      or coalesce(v_member.provisioning_ref,'')<>v_id
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
    end if;

    if lower(v_account.email)<>v_email then
      if exists(
        select 1 from public.account_auth_bindings b where b.account_id=v_account.id
      ) then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_CHANGE_REQUIRES_RELINK');
      end if;
      if exists(
        select 1 from public.accounts a
        where lower(a.email)=v_email and a.id<>v_account.id
      ) then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_ALREADY_EXISTS');
      end if;
      update public.accounts set email=v_email where id=v_account.id;
      update public.persons set email=v_email where id=v_account.person_id;
      v_account.email:=v_email;
    end if;
  else
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(user_name)=v_user_name
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_USERNAME_CONFLICT');
    end if;
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(email)=v_email
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_CONFLICT');
    end if;

    select * into v_account
    from public.accounts
    where lower(email)=v_email and status='active'
    order by created_at
    limit 1
    for update;

    if found then
      select * into v_member
      from public.organization_members
      where organization_id=p_org_id and account_id=v_account.id
      for update;

      if found and v_member.role in ('owner','admin') then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
      end if;
      if found then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_REQUIRES_ADOPTION');
      end if;
    else
      v_display:=coalesce(
        nullif(btrim(coalesce(p_display_name,'')),''),
        nullif(btrim(concat_ws(' ',p_given_name,p_family_name)),''),
        split_part(v_email,'@',1)
      );
      v_person_id:='person_'||replace(gen_random_uuid()::text,'-','');
      v_account_id:='acct_'||replace(gen_random_uuid()::text,'-','');

      insert into public.persons(id,display_name,email,identity_status,created_at)
      values(v_person_id,left(v_display,160),v_email,'unverified',v_now_text)
      returning * into v_person;

      insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
      values(v_account_id,v_person_id,v_email,'active',v_now_text,null)
      returning * into v_account;
    end if;

    v_id:='scimusr_'||replace(gen_random_uuid()::text,'-','');
  end if;

  v_membership:=private.trustrelay_scim_apply_membership_v14(
    p_org_id,v_id,v_account.id,coalesce(p_active,true),v_cfg.default_role
  );
  if coalesce((v_membership->>'ok')::boolean,false)=false then return v_membership; end if;

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
        deprovisioned_at=case
          when coalesce(p_active,true) then null
          else coalesce(deprovisioned_at,v_now)
        end,
        version=version+1,
        updated_at=v_now,
        last_synced_at=v_now
    where organization_id=p_org_id and id=v_id
    returning * into v_scim;
    v_event:=case when v_scim.active
      then 'organization.scim.user_updated'
      else 'organization.scim.user_deprovisioned' end;
  else
    insert into public.organization_scim_users(
      id,organization_id,account_id,external_id,user_name,email,display_name,
      given_name,family_name,title,active,version,created_at,updated_at,
      deprovisioned_at,last_synced_at
    ) values(
      v_id,p_org_id,v_account.id,nullif(btrim(coalesce(p_external_id,'')),''),
      v_user_name,v_email,nullif(left(btrim(coalesce(p_display_name,'')),160),''),
      nullif(left(btrim(coalesce(p_given_name,'')),120),''),
      nullif(left(btrim(coalesce(p_family_name,'')),120),''),
      nullif(left(btrim(coalesce(p_title,'')),160),''),
      coalesce(p_active,true),1,v_now,v_now,
      case when coalesce(p_active,true) then null else v_now end,v_now
    ) returning * into v_scim;
    v_event:=case when v_scim.active
      then 'organization.scim.user_created'
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
exception
  when unique_violation then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_UNIQUENESS_CONFLICT');
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
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
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
  if found and (
    coalesce(v_member.provisioning_source,'manual')<>'scim'
    or coalesce(v_member.provisioning_ref,'')<>p_scim_id
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
  end if;

  update public.organization_scim_users
  set active=false,deprovisioned_at=coalesce(deprovisioned_at,now()),
      version=version+1,updated_at=now(),last_synced_at=now()
  where organization_id=p_org_id and id=p_scim_id
  returning * into v_scim;

  if found then
    update public.organization_members
    set status='disabled',disabled_at=coalesce(disabled_at,v_now),
        disabled_by_account_id=null,updated_at=v_now
    where organization_id=p_org_id and account_id=v_scim.account_id;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'organization.scim.user_deprovisioned','scim_user',p_scim_id,
    jsonb_build_object(
      'userName',v_scim.user_name,'email',v_scim.email,'accountId',v_scim.account_id
    )
  );

  return jsonb_build_object(
    'ok',true,'id',p_scim_id,'active',false,'version',v_scim.version
  );
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
      'actorAccountId',v_ctx->>'accountId','credentials','[]'::jsonb,
      'counts',jsonb_build_object('users',0,'activeUsers',0,'groups',0)
    );
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',c.id,'clientId',c.client_id,'label',c.label,'status',c.status,
    'expiresAt',c.expires_at,'createdAt',c.created_at,
    'lastUsedAt',c.last_used_at,'revokedAt',c.revoked_at
  ) order by c.created_at desc),'[]'::jsonb)
  into v_credentials
  from public.organization_scim_credentials c
  where c.organization_id=p_org_id;

  select count(*),count(*) filter(where active)
  into v_total,v_active
  from public.organization_scim_users
  where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,'configured',true,'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'config',jsonb_build_object(
      'status',v_cfg.status,'providerKind',v_cfg.provider_kind,
      'defaultRole',v_cfg.default_role,'rateLimitPerMinute',v_cfg.rate_limit_per_minute,
      'allowStaticBearer',true,'groupSyncEnabled',false,
      'lastSyncAt',v_cfg.last_sync_at,'lastError',v_cfg.last_error,
      'disabledAt',v_cfg.disabled_at
    ),
    'credentials',v_credentials,
    'counts',jsonb_build_object('users',v_total,'activeUsers',v_active,'groups',0)
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
          where c.organization_id=s.organization_id and c.status='active'
        )
      )
  loop
    v_match:=private.trustrelay_sso_session_match_v13(p_uid,v_cfg.organization_id);
    if not coalesce((v_match->>'providerMatched')::boolean,false) then
      continue;
    end if;

    select * into v_scim_cfg
    from public.organization_scim_configs
    where organization_id=v_cfg.organization_id and status='active'
    limit 1;

    if found then
      select * into v_scim_user
      from public.organization_scim_users
      where organization_id=v_cfg.organization_id
        and active=true
        and (lower(email)=v_account_email or lower(user_name)=v_account_email)
      order by updated_at desc
      limit 1;

      if not found then
        return jsonb_build_object(
          'ok',true,'joined',false,'scimManaged',true,
          'organizationId',v_cfg.organization_id,'code','SCIM_PROVISIONING_REQUIRED'
        );
      end if;

      if v_scim_user.account_id is distinct from v_account_id then
        return jsonb_build_object(
          'ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_MISMATCH',
          'organizationId',v_cfg.organization_id
        );
      end if;

      v_membership:=private.trustrelay_scim_apply_membership_v14(
        v_cfg.organization_id,v_scim_user.id,v_account_id,true,v_scim_cfg.default_role
      );
      if coalesce((v_membership->>'ok')::boolean,false)=false then
        return v_membership;
      end if;

      update public.organization_scim_users
      set last_synced_at=now(),updated_at=now()
      where id=v_scim_user.id;

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
        v_cfg.organization_id,v_account_id,'organization.member.sso_jit_joined',
        'organization_member',v_account_id,
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

revoke all on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text)
to service_role;

revoke all on function private.trustrelay_scim_resolve_bearer_core_v14(text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_resolve_bearer_core_v14(text)
to service_role;
revoke all on function public.trustrelay_scim_resolve_bearer_v14(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_scim_resolve_bearer_v14(text)
to service_role;

revoke all on function private.trustrelay_scim_upsert_user_core_v14(
  text,text,text,text,text,text,text,text,text,boolean
) from public,anon,authenticated;
grant execute on function private.trustrelay_scim_upsert_user_core_v14(
  text,text,text,text,text,text,text,text,text,boolean
) to service_role;
revoke all on function public.trustrelay_scim_upsert_user_v14(
  text,text,text,text,text,text,text,text,text,boolean
) from public,anon,authenticated;
grant execute on function public.trustrelay_scim_upsert_user_v14(
  text,text,text,text,text,text,text,text,text,boolean
) to service_role;

revoke all on function private.trustrelay_scim_delete_user_core_v14(text,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_delete_user_core_v14(text,text)
to service_role;
revoke all on function public.trustrelay_scim_delete_user_v14(text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_scim_delete_user_v14(text,text)
to service_role;

revoke all on function public.trustrelay_scim_admin_status_v14(text)
from public,anon;
grant execute on function private.trustrelay_scim_admin_status_core_v14(uuid,text)
to authenticated,service_role;
grant execute on function public.trustrelay_scim_admin_status_v14(text)
to authenticated;
;

    and exists(
      select 1
      from public.organization_sso_domains d
      where d.organization_id=p_org_id
        and d.domain=split_part(lower(btrim(p_email)),'@',2)
        and d.verification_status='verified'
    );
$function$;

revoke all on function private.trustrelay_scim_email_allowed_v14(text,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_email_allowed_v14(text,text)
to service_role;

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
  v_changed boolean:=false;
  v_joined boolean:=false;
begin
  if p_account_id is null then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_REQUIRED');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',500,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id
  for update;

  if found and v_member.role in ('owner','admin') then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
  end if;

  if found and (
    coalesce(v_member.provisioning_source,'manual')<>'scim'
    or coalesce(v_member.provisioning_ref,'')<>p_scim_id
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
  end if;

  if coalesce(p_active,true)=false then
    if found and v_member.status<>'disabled' then
      update public.organization_members
      set status='disabled',disabled_at=coalesce(disabled_at,v_now),
          disabled_by_account_id=null,updated_at=v_now
      where organization_id=p_org_id and account_id=p_account_id;
      v_changed:=true;
    end if;
    return jsonb_build_object(
      'ok',true,'membershipChanged',v_changed,'joined',false,'active',false
    );
  end if;

  if not found then
    insert into public.organization_members(
      organization_id,account_id,role,created_at,status,updated_at,
      provisioning_source,provisioning_ref
    ) values(
      p_org_id,p_account_id,p_default_role,v_now,'active',v_now,'scim',p_scim_id
    );
    v_changed:=true;
    v_joined:=true;
  elsif v_member.status<>'active' then
    update public.organization_members
    set status='active',disabled_at=null,disabled_by_account_id=null,
        removed_at=null,removed_by_account_id=null,updated_at=v_now
    where organization_id=p_org_id and account_id=p_account_id;
    v_changed:=true;
  end if;

  return jsonb_build_object(
    'ok',true,'membershipChanged',v_changed,'joined',v_joined,'active',true
  );
end;
$function$;

create or replace function private.trustrelay_scim_resolve_bearer_core_v14(
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cred public.organization_scim_credentials%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
  v_bucket timestamptz:=date_trunc('minute',clock_timestamp());
  v_count integer;
  v_retry integer;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select c.* into v_cred
  from public.organization_scim_credentials c
  join public.organization_scim_configs cfg on cfg.organization_id=c.organization_id
  where c.secret_hash=p_token_hash
    and c.status='active'
    and c.expires_at>clock_timestamp()
    and cfg.status='active'
    and cfg.allow_static_bearer=true
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=v_cred.organization_id and status='active';

  insert into private.trustrelay_scim_rate_buckets_v14(
    credential_id,bucket_start,request_count
  ) values(v_cred.id,v_bucket,1)
  on conflict(credential_id,bucket_start)
  do update set request_count=private.trustrelay_scim_rate_buckets_v14.request_count+1
  returning request_count into v_count;

  if v_count>v_cfg.rate_limit_per_minute then
    v_retry:=greatest(
      1,
      ceil(extract(epoch from (v_bucket+interval '1 minute'-clock_timestamp())))::integer
    );
    update public.organization_scim_configs
    set last_error='SCIM_RATE_LIMITED',updated_at=now()
    where organization_id=v_cred.organization_id;
    return jsonb_build_object(
      'ok',false,'status',429,'code','SCIM_RATE_LIMITED','retryAfter',v_retry
    );
  end if;

  delete from private.trustrelay_scim_rate_buckets_v14
  where credential_id=v_cred.id and bucket_start<v_bucket-interval '10 minutes';

  update public.organization_scim_credentials
  set last_used_at=now()
  where id=v_cred.id;

  update public.organization_scim_configs
  set last_sync_at=now(),last_error=null,updated_at=now()
  where organization_id=v_cred.organization_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',v_cred.organization_id,
    'credentialId',v_cred.id,
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
set search_path to 'public','private','extensions','pg_catalog'
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
  v_email text:=lower(btrim(coalesce(nullif(p_email,''),p_user_name,'')));
  v_user_name text:=lower(btrim(coalesce(p_user_name,'')));
  v_display text;
  v_membership jsonb;
  v_event text;
  v_now timestamptz:=clock_timestamp();
  v_now_text text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_NOT_ACTIVE');
  end if;

  if length(v_user_name)<3 or length(v_user_name)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_USERNAME_INVALID');
  end if;
  if v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     or length(v_email)>320 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EMAIL_INVALID');
  end if;
  if not private.trustrelay_scim_email_allowed_v14(p_org_id,v_email) then
    return jsonb_build_object('ok',false,'status',403,'code','SCIM_EMAIL_DOMAIN_NOT_VERIFIED');
  end if;
  if nullif(btrim(coalesce(p_external_id,'')),'') is not null
     and length(p_external_id)>512 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EXTERNAL_ID_INVALID');
  end if;

  if p_scim_id is not null and p_scim_id<>'' then
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and id=p_scim_id
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND');
    end if;
  elsif nullif(btrim(coalesce(p_external_id,'')),'') is not null then
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and external_id=btrim(p_external_id)
    for update;
  else
    select * into v_scim
    from public.organization_scim_users
    where organization_id=p_org_id and lower(user_name)=v_user_name
    for update;
  end if;

  if found then
    v_id:=v_scim.id;
    select * into v_account
    from public.accounts where id=v_scim.account_id and status='active'
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_MISSING');
    end if;

    select * into v_member
    from public.organization_members
    where organization_id=p_org_id and account_id=v_account.id
    for update;

    if found and v_member.role in ('owner','admin') then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
    end if;
    if found and (
      coalesce(v_member.provisioning_source,'manual')<>'scim'
      or coalesce(v_member.provisioning_ref,'')<>v_id
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
    end if;

    if lower(v_account.email)<>v_email then
      if exists(
        select 1 from public.account_auth_bindings b where b.account_id=v_account.id
      ) then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_CHANGE_REQUIRES_RELINK');
      end if;
      if exists(
        select 1 from public.accounts a
        where lower(a.email)=v_email and a.id<>v_account.id
      ) then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_ALREADY_EXISTS');
      end if;
      update public.accounts set email=v_email where id=v_account.id;
      update public.persons set email=v_email where id=v_account.person_id;
      v_account.email:=v_email;
    end if;
  else
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(user_name)=v_user_name
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_USERNAME_CONFLICT');
    end if;
    if exists(
      select 1 from public.organization_scim_users
      where organization_id=p_org_id and lower(email)=v_email
    ) then
      return jsonb_build_object('ok',false,'status',409,'code','SCIM_EMAIL_CONFLICT');
    end if;

    select * into v_account
    from public.accounts
    where lower(email)=v_email and status='active'
    order by created_at
    limit 1
    for update;

    if found then
      select * into v_member
      from public.organization_members
      where organization_id=p_org_id and account_id=v_account.id
      for update;

      if found and v_member.role in ('owner','admin') then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_PRIVILEGED_MEMBER_PROTECTED');
      end if;
      if found then
        return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_REQUIRES_ADOPTION');
      end if;
    else
      v_display:=coalesce(
        nullif(btrim(coalesce(p_display_name,'')),''),
        nullif(btrim(concat_ws(' ',p_given_name,p_family_name)),''),
        split_part(v_email,'@',1)
      );
      v_person_id:='person_'||replace(gen_random_uuid()::text,'-','');
      v_account_id:='acct_'||replace(gen_random_uuid()::text,'-','');

      insert into public.persons(id,display_name,email,identity_status,created_at)
      values(v_person_id,left(v_display,160),v_email,'unverified',v_now_text)
      returning * into v_person;

      insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
      values(v_account_id,v_person_id,v_email,'active',v_now_text,null)
      returning * into v_account;
    end if;

    v_id:='scimusr_'||replace(gen_random_uuid()::text,'-','');
  end if;

  v_membership:=private.trustrelay_scim_apply_membership_v14(
    p_org_id,v_id,v_account.id,coalesce(p_active,true),v_cfg.default_role
  );
  if coalesce((v_membership->>'ok')::boolean,false)=false then return v_membership; end if;

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
        deprovisioned_at=case
          when coalesce(p_active,true) then null
          else coalesce(deprovisioned_at,v_now)
        end,
        version=version+1,
        updated_at=v_now,
        last_synced_at=v_now
    where organization_id=p_org_id and id=v_id
    returning * into v_scim;
    v_event:=case when v_scim.active
      then 'organization.scim.user_updated'
      else 'organization.scim.user_deprovisioned' end;
  else
    insert into public.organization_scim_users(
      id,organization_id,account_id,external_id,user_name,email,display_name,
      given_name,family_name,title,active,version,created_at,updated_at,
      deprovisioned_at,last_synced_at
    ) values(
      v_id,p_org_id,v_account.id,nullif(btrim(coalesce(p_external_id,'')),''),
      v_user_name,v_email,nullif(left(btrim(coalesce(p_display_name,'')),160),''),
      nullif(left(btrim(coalesce(p_given_name,'')),120),''),
      nullif(left(btrim(coalesce(p_family_name,'')),120),''),
      nullif(left(btrim(coalesce(p_title,'')),160),''),
      coalesce(p_active,true),1,v_now,v_now,
      case when coalesce(p_active,true) then null else v_now end,v_now
    ) returning * into v_scim;
    v_event:=case when v_scim.active
      then 'organization.scim.user_created'
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
exception
  when unique_violation then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_UNIQUENESS_CONFLICT');
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
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
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
  if found and (
    coalesce(v_member.provisioning_source,'manual')<>'scim'
    or coalesce(v_member.provisioning_ref,'')<>p_scim_id
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_EXISTING_MEMBER_NOT_MANAGED');
  end if;

  update public.organization_scim_users
  set active=false,deprovisioned_at=coalesce(deprovisioned_at,now()),
      version=version+1,updated_at=now(),last_synced_at=now()
  where organization_id=p_org_id and id=p_scim_id
  returning * into v_scim;

  if found then
    update public.organization_members
    set status='disabled',disabled_at=coalesce(disabled_at,v_now),
        disabled_by_account_id=null,updated_at=v_now
    where organization_id=p_org_id and account_id=v_scim.account_id;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'organization.scim.user_deprovisioned','scim_user',p_scim_id,
    jsonb_build_object(
      'userName',v_scim.user_name,'email',v_scim.email,'accountId',v_scim.account_id
    )
  );

  return jsonb_build_object(
    'ok',true,'id',p_scim_id,'active',false,'version',v_scim.version
  );
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
      'actorAccountId',v_ctx->>'accountId','credentials','[]'::jsonb,
      'counts',jsonb_build_object('users',0,'activeUsers',0,'groups',0)
    );
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',c.id,'clientId',c.client_id,'label',c.label,'status',c.status,
    'expiresAt',c.expires_at,'createdAt',c.created_at,
    'lastUsedAt',c.last_used_at,'revokedAt',c.revoked_at
  ) order by c.created_at desc),'[]'::jsonb)
  into v_credentials
  from public.organization_scim_credentials c
  where c.organization_id=p_org_id;

  select count(*),count(*) filter(where active)
  into v_total,v_active
  from public.organization_scim_users
  where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,'configured',true,'organizationId',p_org_id,
    'actorAccountId',v_ctx->>'accountId',
    'config',jsonb_build_object(
      'status',v_cfg.status,'providerKind',v_cfg.provider_kind,
      'defaultRole',v_cfg.default_role,'rateLimitPerMinute',v_cfg.rate_limit_per_minute,
      'allowStaticBearer',true,'groupSyncEnabled',false,
      'lastSyncAt',v_cfg.last_sync_at,'lastError',v_cfg.last_error,
      'disabledAt',v_cfg.disabled_at
    ),
    'credentials',v_credentials,
    'counts',jsonb_build_object('users',v_total,'activeUsers',v_active,'groups',0)
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
          where c.organization_id=s.organization_id and c.status='active'
        )
      )
  loop
    v_match:=private.trustrelay_sso_session_match_v13(p_uid,v_cfg.organization_id);
    if not coalesce((v_match->>'providerMatched')::boolean,false) then
      continue;
    end if;

    select * into v_scim_cfg
    from public.organization_scim_configs
    where organization_id=v_cfg.organization_id and status='active'
    limit 1;

    if found then
      select * into v_scim_user
      from public.organization_scim_users
      where organization_id=v_cfg.organization_id
        and active=true
        and (lower(email)=v_account_email or lower(user_name)=v_account_email)
      order by updated_at desc
      limit 1;

      if not found then
        return jsonb_build_object(
          'ok',true,'joined',false,'scimManaged',true,
          'organizationId',v_cfg.organization_id,'code','SCIM_PROVISIONING_REQUIRED'
        );
      end if;

      if v_scim_user.account_id is distinct from v_account_id then
        return jsonb_build_object(
          'ok',false,'status',409,'code','SCIM_ACCOUNT_LINK_MISMATCH',
          'organizationId',v_cfg.organization_id
        );
      end if;

      v_membership:=private.trustrelay_scim_apply_membership_v14(
        v_cfg.organization_id,v_scim_user.id,v_account_id,true,v_scim_cfg.default_role
      );
      if coalesce((v_membership->>'ok')::boolean,false)=false then
        return v_membership;
      end if;

      update public.organization_scim_users
      set last_synced_at=now(),updated_at=now()
      where id=v_scim_user.id;

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
        v_cfg.organization_id,v_account_id,'organization.member.sso_jit_joined',
        'organization_member',v_account_id,
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

revoke all on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text)
to service_role;

revoke all on function private.trustrelay_scim_resolve_bearer_core_v14(text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_resolve_bearer_core_v14(text)
to service_role;
revoke all on function public.trustrelay_scim_resolve_bearer_v14(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_scim_resolve_bearer_v14(text)
to service_role;

revoke all on function private.trustrelay_scim_upsert_user_core_v14(
  text,text,text,text,text,text,text,text,text,boolean
) from public,anon,authenticated;
grant execute on function private.trustrelay_scim_upsert_user_core_v14(
  text,text,text,text,text,text,text,text,text,boolean
) to service_role;
revoke all on function public.trustrelay_scim_upsert_user_v14(
  text,text,text,text,text,text,text,text,text,boolean
) from public,anon,authenticated;
grant execute on function public.trustrelay_scim_upsert_user_v14(
  text,text,text,text,text,text,text,text,text,boolean
) to service_role;

revoke all on function private.trustrelay_scim_delete_user_core_v14(text,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_delete_user_core_v14(text,text)
to service_role;
revoke all on function public.trustrelay_scim_delete_user_v14(text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_scim_delete_user_v14(text,text)
to service_role;

revoke all on function public.trustrelay_scim_admin_status_v14(text)
from public,anon;
grant execute on function private.trustrelay_scim_admin_status_core_v14(uuid,text)
to authenticated,service_role;
grant execute on function public.trustrelay_scim_admin_status_v14(text)
to authenticated;
;
