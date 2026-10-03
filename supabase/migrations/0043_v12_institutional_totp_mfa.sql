-- TrustRelay v1.2 institutional security hardening
-- Require verified TOTP MFA (aal2) for all institutional verifier access.
-- High-risk mutations additionally require a recently verified TOTP factor.

create or replace function private.trustrelay_require_aal2_v12(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'auth','private','pg_catalog'
as $$
declare
  v_guard jsonb;
  v_jwt_role text := coalesce(auth.jwt()->>'role','');
begin
  if auth.uid() is null then
    if v_jwt_role in ('anon','authenticated') then
      return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
    end if;
    return jsonb_build_object('ok',true,'internal',true);
  end if;

  if p_uid is null or auth.uid() is distinct from p_uid then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  v_guard:=private.trustrelay_session_guard_v10(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;

  if not exists (
    select 1 from auth.mfa_factors f
    where f.user_id=p_uid
      and f.status::text='verified'
      and f.factor_type::text='totp'
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_ENROLLMENT_REQUIRED','requiredFactor','totp');
  end if;

  if coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_CHALLENGE_REQUIRED','requiredAal','aal2');
  end if;

  return jsonb_build_object('ok',true,'aal','aal2','sessionId',auth.jwt()->>'session_id');
end;
$$;

revoke all on function private.trustrelay_require_aal2_v12(uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_require_aal2_v12(uuid) to service_role;

create or replace function private.trustrelay_require_org_role_v07(
  p_uid uuid,p_org_id text,p_roles text[]
) returns jsonb
language plpgsql
security definer
set search_path='private','auth','pg_catalog'
as $$
declare
  v_guard jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if auth.uid() is not null then
    v_guard:=private.trustrelay_require_aal2_v12(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  end if;
  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$$;

revoke all on function private.trustrelay_require_org_role_v07(uuid,text,text[]) from public,anon,authenticated;
grant execute on function private.trustrelay_require_org_role_v07(uuid,text,text[]) to service_role;

create or replace function private.trustrelay_create_organization_v07(
  p_uid uuid,p_name text,p_industry text,p_website text
) returns jsonb
language plpgsql
security definer
set search_path='private','auth','pg_catalog'
as $$
declare
  v_guard jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  return private.trustrelay_create_organization_core_v10(p_uid,p_name,p_industry,p_website);
end;
$$;

create or replace function private.trustrelay_my_organizations_v07(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path='private','auth','pg_catalog'
as $$
declare
  v_guard jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  return private.trustrelay_my_organizations_core_v10(p_uid);
end;
$$;

create or replace function private.trustrelay_accept_org_invite_v07(p_uid uuid,p_token text)
returns jsonb
language plpgsql
security definer
set search_path='private','auth','pg_catalog'
as $$
declare
  v_guard jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  return private.trustrelay_accept_org_invite_core_v10(p_uid,p_token);
end;
$$;

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
  v_guard jsonb;
  v_mfa_at timestamptz;
  v_rate record;
  v_action text := lower(btrim(coalesce(p_action,'')));
  v_age integer := greatest(5, least(coalesce(p_max_session_age_minutes,30), 120));
  v_limit integer := greatest(1, least(coalesce(p_limit,20), 100));
  v_window integer := greatest(10, least(coalesce(p_window_seconds,60), 3600));
begin
  if auth.uid() is null then
    if coalesce(auth.jwt()->>'role','') in ('anon','authenticated') then
      return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
    end if;
    return jsonb_build_object('ok',true,'internal',true);
  end if;

  if v_action !~ '^[a-z0-9_.:-]{2,80}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SECURITY_ACTION_INVALID');
  end if;

  v_guard:=private.trustrelay_require_aal2_v12(p_uid);
  if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;

  select max(to_timestamp((item->>'timestamp')::double precision))
    into v_mfa_at
  from jsonb_array_elements(coalesce(auth.jwt()->'amr','[]'::jsonb)) item
  where item->>'method'='totp'
    and coalesce(item->>'timestamp','') ~ '^[0-9]+([.][0-9]+)?$';

  if v_mfa_at is null or v_mfa_at < clock_timestamp() - make_interval(mins => v_age) then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_REAUTHENTICATION_REQUIRED','maxMfaAgeMinutes',v_age);
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05('highrisk:'||p_uid::text||':'||v_action,v_limit,v_window);

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object('ok',false,'status',429,'code','SENSITIVE_ACTION_RATE_LIMITED','resetAt',v_rate.reset_at);
  end if;

  return jsonb_build_object(
    'ok',true,
    'sessionId',auth.jwt()->>'session_id',
    'aal','aal2',
    'mfaVerifiedAt',to_char(v_mfa_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'remaining',v_rate.remaining,
    'resetAt',v_rate.reset_at
  );
end;
$$;

revoke all on function private.trustrelay_high_risk_guard_v11(uuid,text,integer,integer,integer) from public,anon,authenticated;
grant execute on function private.trustrelay_high_risk_guard_v11(uuid,text,integer,integer,integer) to service_role;

notify pgrst,'reload schema';
