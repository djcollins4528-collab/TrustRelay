-- TrustRelay v1.1 security hardening
-- Active-session validation, fresh-session step-up for sensitive actions,
-- database throttling, finite partner-key lifetimes, key/webhook audit events,
-- and enforcement of API-key expiry in the partner decision engine.

create or replace function private.trustrelay_request_actor_matches_v10(p_uid uuid)
returns boolean
language sql
stable
security definer
set search_path to 'auth','pg_catalog'
as $$
  select case
    when coalesce(auth.role(),'') in ('anon','authenticated') then
      auth.uid() is not distinct from p_uid
      and coalesce(auth.jwt()->>'session_id','') <> ''
      and exists (
        select 1
        from auth.sessions s
        where s.id::text = auth.jwt()->>'session_id'
          and s.user_id = p_uid
          and (s.not_after is null or s.not_after > clock_timestamp())
      )
    else true
  end;
$$;

revoke all on function private.trustrelay_request_actor_matches_v10(uuid) from public, anon, authenticated;
grant execute on function private.trustrelay_request_actor_matches_v10(uuid) to service_role;

create or replace function private.trustrelay_high_risk_guard_v11(
  p_uid uuid,
  p_action text,
  p_max_session_age_minutes integer default 30,
  p_limit integer default 20,
  p_window_seconds integer default 60
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $$
declare
  v_role text := coalesce(auth.role(),'');
  v_session_id text := coalesce(auth.jwt()->>'session_id','');
  v_created_at timestamptz;
  v_not_after timestamptz;
  v_aal text;
  v_rate record;
  v_action text := lower(btrim(coalesce(p_action,'')));
  v_age integer := greatest(5, least(coalesce(p_max_session_age_minutes,30), 120));
  v_limit integer := greatest(1, least(coalesce(p_limit,20), 100));
  v_window integer := greatest(10, least(coalesce(p_window_seconds,60), 3600));
begin
  if v_role not in ('anon','authenticated') then
    return jsonb_build_object('ok',true,'internal',true);
  end if;

  if p_uid is null or auth.uid() is distinct from p_uid then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  if v_session_id='' then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_ID_REQUIRED');
  end if;

  if v_action !~ '^[a-z0-9_.:-]{2,80}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SECURITY_ACTION_INVALID');
  end if;

  select s.created_at, s.not_after, s.aal::text
    into v_created_at, v_not_after, v_aal
  from auth.sessions s
  where s.id::text=v_session_id and s.user_id=p_uid
  limit 1;

  if not found or (v_not_after is not null and v_not_after <= clock_timestamp()) then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_NOT_ACTIVE');
  end if;

  if v_created_at < clock_timestamp() - make_interval(mins => v_age) then
    return jsonb_build_object(
      'ok',false,'status',401,'code','REAUTHENTICATION_REQUIRED',
      'maxSessionAgeMinutes',v_age
    );
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05(
    'highrisk:'||p_uid::text||':'||v_action,
    v_limit,
    v_window
  );

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','SENSITIVE_ACTION_RATE_LIMITED',
      'resetAt',v_rate.reset_at
    );
  end if;

  return jsonb_build_object(
    'ok',true,'sessionId',v_session_id,'aal',coalesce(v_aal,'aal1'),
    'remaining',v_rate.remaining,'resetAt',v_rate.reset_at
  );
end;
$$;

revoke all on function private.trustrelay_high_risk_guard_v11(uuid,text,integer,integer,integer) from public, anon, authenticated;
grant execute on function private.trustrelay_high_risk_guard_v11(uuid,text,integer,integer,integer) to service_role;

create or replace function public.trustrelay_sensitive_action_guard_v11(p_action text)
returns jsonb
language sql
security definer
set search_path to 'private','auth','pg_catalog'
as $$
  select private.trustrelay_high_risk_guard_v11(auth.uid(),p_action,15,10,60);
$$;

revoke all on function public.trustrelay_sensitive_action_guard_v11(text) from public, anon;
grant execute on function public.trustrelay_sensitive_action_guard_v11(text) to authenticated, service_role;

create or replace function private.trustrelay_require_permission_v09(p_uid uuid, p_org_id text, p_permission text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_permissions jsonb;
  v_guard jsonb;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','compliance','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_permissions:=public.trustrelay_org_permissions_v09(v_ctx->>'role');
  if coalesce((v_permissions->>p_permission)::boolean,false)=false then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED',
      'permission',p_permission,'role',v_ctx->>'role'
    );
  end if;

  if p_permission = any(array[
    'organization.manage','members.manage','roles.manage',
    'api_keys.manage','webhooks.manage','audit.export','evidence.review'
  ]::text[]) then
    v_guard:=private.trustrelay_high_risk_guard_v11(
      p_uid,'permission:'||p_permission,30,20,60
    );
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  end if;

  return v_ctx || jsonb_build_object('permissions',v_permissions);
end;
$$;

create or replace function private.trustrelay_create_api_key_v07(
  p_uid uuid, p_org_id text, p_name text, p_scopes jsonb, p_expires_at text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_org public.organizations%rowtype;
  v_account_id text;
  v_key_id text := 'key_' || replace(gen_random_uuid()::text,'-','');
  v_raw text;
  v_hash text;
  v_prefix text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_scope text;
  v_allowed text[] := array['decisions:read','decisions:write'];
  v_expiry timestamptz;
  v_expiry_text text;
begin
  v_ctx := private.trustrelay_require_permission_v09(p_uid,p_org_id,'api_keys.manage');
  if coalesce((v_ctx->>'ok')::boolean,false) is false then return v_ctx; end if;

  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 100 then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_NAME_INVALID');
  end if;

  if p_scopes is null or jsonb_typeof(p_scopes) <> 'array' or jsonb_array_length(p_scopes)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPES_REQUIRED');
  end if;

  for v_scope in select jsonb_array_elements_text(p_scopes)
  loop
    if not (v_scope = any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPE_INVALID','scope',v_scope);
    end if;
  end loop;

  select * into v_org from public.organizations where id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_NOT_FOUND');
  end if;
  v_account_id := v_ctx->>'accountId';

  begin
    v_expiry := case
      when p_expires_at is null or btrim(p_expires_at)='' then clock_timestamp()+interval '90 days'
      else p_expires_at::timestamptz
    end;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_INVALID');
  end;

  if v_expiry <= clock_timestamp() then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_INVALID');
  end if;
  if v_expiry > clock_timestamp()+interval '90 days 5 minutes' then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_TOO_LONG','maxDays',90);
  end if;

  v_expiry_text := to_char(v_expiry at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_prefix := case when v_org.mode='live' then 'tr_live' else 'tr_test' end;
  v_raw := v_prefix || '_' || encode(gen_random_bytes(32),'hex');
  v_hash := encode(digest(v_raw,'sha256'),'hex');

  insert into public.api_keys(
    id,organization_id,name,prefix,key_hash,scopes_json,created_at,
    key_type,created_by_account_id,expires_at,last_four,updated_at
  ) values (
    v_key_id,p_org_id,btrim(p_name),v_prefix,v_hash,p_scopes::text,v_now,
    'partner',v_account_id,v_expiry_text,right(v_raw,4),v_now
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_account_id,'api_key.created','api_key',v_key_id,
    jsonb_build_object(
      'name',btrim(p_name),'prefix',v_prefix,'lastFour',right(v_raw,4),
      'scopes',p_scopes,'expiresAt',v_expiry_text
    )
  );

  return jsonb_build_object(
    'ok',true,'apiKey',v_raw,
    'key',jsonb_build_object(
      'id',v_key_id,'name',btrim(p_name),'prefix',v_prefix,'lastFour',right(v_raw,4),
      'scopes',p_scopes,'createdAt',v_now,'expiresAt',v_expiry_text
    )
  );
end;
$$;

create or replace function private.trustrelay_revoke_api_key_v07(p_uid uuid, p_org_id text, p_key_id text)
returns jsonb language plpgsql security definer
set search_path to 'public','private','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_key public.api_keys%rowtype;
begin
  v_ctx := private.trustrelay_require_permission_v09(p_uid,p_org_id,'api_keys.manage');
  if coalesce((v_ctx->>'ok')::boolean,false) is false then return v_ctx; end if;
  select * into v_key from public.api_keys
  where id=p_key_id and organization_id=p_org_id and key_type='partner' for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','API_KEY_NOT_FOUND'); end if;
  if v_key.revoked_at is null then
    update public.api_keys set revoked_at=v_now,updated_at=v_now where id=p_key_id;
    perform private.trustrelay_append_org_audit_v09(
      p_org_id,v_ctx->>'accountId','api_key.revoked','api_key',p_key_id,
      jsonb_build_object('name',v_key.name,'prefix',v_key.prefix,'lastFour',v_key.last_four)
    );
  end if;
  return jsonb_build_object('ok',true,'keyId',p_key_id,'revokedAt',coalesce(v_key.revoked_at,v_now));
end;
$$;

create or replace function private.trustrelay_revoke_webhook_v07(p_uid uuid, p_org_id text, p_webhook_id text)
returns jsonb language plpgsql security definer
set search_path to 'public','private','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_name text;
begin
  v_ctx := private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false) is false then return v_ctx; end if;
  select name into v_name from public.webhook_subscriptions
  where id=p_webhook_id and organization_id=p_org_id;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','WEBHOOK_NOT_FOUND'); end if;
  update public.webhook_subscriptions set status='revoked',updated_at=v_now
  where id=p_webhook_id and organization_id=p_org_id;
  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.revoked','webhook_subscription',p_webhook_id,
    jsonb_build_object('name',v_name)
  );
  return jsonb_build_object('ok',true,'webhookId',p_webhook_id,'status','revoked');
end;
$$;

create or replace function private.trustrelay_transfer_org_owner_v09(
  p_uid uuid, p_org_id text, p_new_owner_account_id text
)
returns jsonb language plpgsql security definer
set search_path to 'public','private','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_guard jsonb;
  v_current_id text;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text:='organization.ownership_transferred';
begin
  v_ctx:=private.trustrelay_require_org_role_v07(p_uid,p_org_id,array['owner']);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_guard:=private.trustrelay_high_risk_guard_v11(p_uid,'organization.transfer_owner',10,3,600);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  v_current_id:=v_ctx->>'accountId';
  if p_new_owner_account_id=v_current_id then
    return jsonb_build_object('ok',false,'status',409,'code','ALREADY_ORGANIZATION_OWNER');
  end if;
  select * into v_target from public.organization_members
  where organization_id=p_org_id and account_id=p_new_owner_account_id and status='active' for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','NEW_OWNER_MUST_BE_ACTIVE_MEMBER'); end if;
  update public.organization_members
  set role='admin',role_changed_at=v_now,role_changed_by_account_id=v_current_id,updated_at=v_now
  where organization_id=p_org_id and account_id=v_current_id and role='owner';
  update public.organization_members
  set role='owner',role_changed_at=v_now,role_changed_by_account_id=v_current_id,updated_at=v_now
  where organization_id=p_org_id and account_id=p_new_owner_account_id returning * into v_target;
  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_current_id,v_event,'organization',p_org_id,
    jsonb_build_object('fromAccountId',v_current_id,'toAccountId',p_new_owner_account_id)
  );
  perform private.trustrelay_notify_account_v09(
    p_new_owner_account_id,p_org_id,'organization',v_event,'critical',
    'You are now the organization owner',
    'Ownership of this TrustRelay organization was transferred to your account.',
    'organization',p_org_id,jsonb_build_object('previousOwnerAccountId',v_current_id,'role','owner')
  );
  perform private.trustrelay_notify_account_v09(
    v_current_id,p_org_id,'organization',v_event,'info',
    'Organization ownership transferred',
    'Ownership was transferred successfully. Your role is now admin.',
    'organization',p_org_id,jsonb_build_object('newOwnerAccountId',p_new_owner_account_id,'role','admin')
  );
  perform public.trustrelay_emit_org_event_v09(
    p_org_id,v_event,jsonb_build_object('previousOwnerAccountId',v_current_id,'newOwnerAccountId',p_new_owner_account_id)
  );
  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,
    'previousOwnerAccountId',v_current_id,'newOwnerAccountId',p_new_owner_account_id
  );
end;
$$;

do $$
declare f record; ddl text;
begin
  for f in
    select p.oid from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.proname in (
        'trustrelay_prepare_decision_v05',
        'trustrelay_record_decision_partner_v05',
        'trustrelay_get_decision_partner_v05'
      )
  loop
    ddl := pg_get_functiondef(f.oid);
    ddl := replace(
      ddl,
      'where key_hash = v_hash and revoked_at is null',
      'where key_hash = v_hash and revoked_at is null and (expires_at is null or expires_at::timestamptz > clock_timestamp())'
    );
    execute ddl;
  end loop;
end $$;
