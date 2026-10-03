-- TrustRelay v1.4 — canonical SCIM credential control reconciliation.
-- Finalizes tenant-bound bearer credentials, masked-secret metadata, and the
-- single database-side per-credential rate limiter used by the public SCIM edge.

alter table public.organization_scim_credentials
  add column if not exists secret_last_four text;

do $block$
begin
  if not exists(
    select 1 from pg_constraint
    where conname='organization_scim_credential_secret_last_four_check'
      and conrelid='public.organization_scim_credentials'::regclass
  ) then
    alter table public.organization_scim_credentials
      add constraint organization_scim_credential_secret_last_four_check
      check(secret_last_four is null or secret_last_four ~ '^[A-Za-z0-9_-]{4}$');
  end if;
end
$block$;

update public.organization_scim_configs
set tenant_key='scim_'||replace(gen_random_uuid()::text,'-','')
where tenant_key is null;

alter table public.organization_scim_configs
  alter column tenant_key set not null;

alter table public.organization_scim_configs
  drop column if exists token_hash,
  drop column if exists token_last_four,
  drop column if exists last_rotated_at,
  drop column if exists last_used_at,
  drop column if exists token_expires_at;

drop function if exists public.trustrelay_scim_store_credential_v14(
  text,text,text,text,text,text,timestamptz
);
drop function if exists private.trustrelay_scim_store_credential_core_v14(
  text,text,text,text,text,text,timestamptz
);

create or replace function private.trustrelay_scim_store_credential_core_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_secret_last_four text,p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $function$
declare
  v_sso public.organization_sso_configs%rowtype;
  v_id text:='scimcred_'||replace(gen_random_uuid()::text,'-','');
  v_active_count integer:=0;
  v_tenant text;
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
    and provider_kind in ('entra','okta')
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
     or p_secret_hash !~ '^[0-9a-f]{64}$'
     or p_secret_last_four !~ '^[A-Za-z0-9_-]{4}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_INVALID');
  end if;
  if p_expires_at<=clock_timestamp()+interval '7 days'
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

  select tenant_key into v_tenant
  from public.organization_scim_configs
  where organization_id=p_org_id;
  if v_tenant is null then
    v_tenant:='scim_'||replace(gen_random_uuid()::text,'-','');
  end if;

  insert into public.organization_scim_configs(
    organization_id,tenant_key,provider_kind,status,default_role,
    allow_static_bearer,group_sync_enabled,created_by_account_id,
    created_at,updated_at,disabled_at
  ) values(
    p_org_id,v_tenant,v_sso.provider_kind,'active',p_default_role,
    true,false,p_actor_account_id,now(),now(),null
  )
  on conflict(organization_id) do update set
    tenant_key=coalesce(public.organization_scim_configs.tenant_key,excluded.tenant_key),
    provider_kind=excluded.provider_kind,
    status='active',
    default_role=excluded.default_role,
    allow_static_bearer=true,
    group_sync_enabled=false,
    updated_at=now(),
    disabled_at=null,
    last_error=null
  returning tenant_key into v_tenant;

  insert into public.organization_scim_credentials(
    id,organization_id,client_id,secret_hash,secret_last_four,label,status,
    expires_at,created_by_account_id,created_at
  ) values(
    v_id,p_org_id,p_client_id,p_secret_hash,p_secret_last_four,
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
      'providerKind',v_sso.provider_kind,
      'defaultRole',p_default_role
    )
  );

  return jsonb_build_object(
    'ok',true,'credentialId',v_id,'clientId',p_client_id,
    'secretLastFour',p_secret_last_four,'tenantKey',v_tenant,
    'expiresAt',p_expires_at,'providerKind',v_sso.provider_kind
  );
end;
$function$;

create or replace function public.trustrelay_scim_store_credential_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_secret_last_four text,p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_store_credential_core_v14(
    p_org_id,p_actor_account_id,p_client_id,p_secret_hash,p_secret_last_four,
    p_label,p_default_role,p_expires_at
  );
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
    set last_error='SCIM_RATE_LIMITED',updated_at=clock_timestamp()
    where organization_id=v_cfg.organization_id;
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
    'tenantKey',v_cfg.tenant_key,
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
      'counts',jsonb_build_object('users',0,'activeUsers',0,'inactiveUsers',0)
    );
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',c.id,'clientId',c.client_id,'label',c.label,'status',c.status,
    'secretLastFour',c.secret_last_four,'expiresAt',c.expires_at,
    'createdAt',c.created_at,'lastUsedAt',c.last_used_at,'revokedAt',c.revoked_at
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
    'tenantKey',v_cfg.tenant_key,
    'config',jsonb_build_object(
      'tenantKey',v_cfg.tenant_key,
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
      'inactiveUsers',v_total-v_active
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

revoke all on function private.trustrelay_scim_store_credential_core_v14(
  text,text,text,text,text,text,text,timestamptz
) from public,anon,authenticated;
grant execute on function private.trustrelay_scim_store_credential_core_v14(
  text,text,text,text,text,text,text,timestamptz
) to service_role;

revoke all on function public.trustrelay_scim_store_credential_v14(
  text,text,text,text,text,text,text,timestamptz
) from public,anon,authenticated;
grant execute on function public.trustrelay_scim_store_credential_v14(
  text,text,text,text,text,text,text,timestamptz
) to service_role;

revoke all on function private.trustrelay_scim_resolve_bearer_core_v14(text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_resolve_bearer_core_v14(text)
to service_role;

revoke all on function public.trustrelay_scim_resolve_bearer_v14(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_scim_resolve_bearer_v14(text)
to service_role;

revoke all on function public.trustrelay_scim_admin_status_v14(text)
from public,anon;
grant execute on function private.trustrelay_scim_admin_status_core_v14(uuid,text)
to authenticated,service_role;
grant execute on function public.trustrelay_scim_admin_status_v14(text)
to authenticated;
