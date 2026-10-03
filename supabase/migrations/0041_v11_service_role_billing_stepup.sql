-- TrustRelay v1.1 security hardening
-- Remove the authenticated SECURITY DEFINER billing preflight and replace it
-- with a service-role-only bridge that verifies the exact validated user/session pair.

drop function if exists public.trustrelay_sensitive_action_guard_v11(text);

create or replace function private.trustrelay_high_risk_session_guard_v11(
  p_uid uuid,
  p_session_id text,
  p_action text,
  p_max_session_age_minutes integer default 15,
  p_limit integer default 10,
  p_window_seconds integer default 60
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $$
declare
  v_created_at timestamptz;
  v_not_after timestamptz;
  v_aal text;
  v_rate record;
  v_action text := lower(btrim(coalesce(p_action,'')));
  v_sid text := btrim(coalesce(p_session_id,''));
  v_age integer := greatest(5, least(coalesce(p_max_session_age_minutes,15), 120));
  v_limit integer := greatest(1, least(coalesce(p_limit,10), 100));
  v_window integer := greatest(10, least(coalesce(p_window_seconds,60), 3600));
begin
  if p_uid is null or v_sid='' then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_ID_REQUIRED');
  end if;

  if v_action !~ '^[a-z0-9_.:-]{2,80}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SECURITY_ACTION_INVALID');
  end if;

  select s.created_at,s.not_after,s.aal::text
    into v_created_at,v_not_after,v_aal
  from auth.sessions s
  where s.id::text=v_sid and s.user_id=p_uid
  limit 1;

  if not found or (v_not_after is not null and v_not_after<=clock_timestamp()) then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_NOT_ACTIVE');
  end if;

  if v_created_at < clock_timestamp()-make_interval(mins=>v_age) then
    return jsonb_build_object(
      'ok',false,'status',401,'code','REAUTHENTICATION_REQUIRED',
      'maxSessionAgeMinutes',v_age
    );
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05(
    'highrisk:'||p_uid::text||':'||v_action,
    v_limit,v_window
  );

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','SENSITIVE_ACTION_RATE_LIMITED',
      'resetAt',v_rate.reset_at
    );
  end if;

  return jsonb_build_object(
    'ok',true,'aal',coalesce(v_aal,'aal1'),
    'remaining',v_rate.remaining,'resetAt',v_rate.reset_at
  );
end;
$$;

revoke all on function private.trustrelay_high_risk_session_guard_v11(uuid,text,text,integer,integer,integer)
from public,anon,authenticated;
grant execute on function private.trustrelay_high_risk_session_guard_v11(uuid,text,text,integer,integer,integer)
to service_role;

create or replace function public.trustrelay_sensitive_action_guard_admin_v11(
  p_uid uuid,p_session_id text,p_action text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $$
  select private.trustrelay_high_risk_session_guard_v11(
    p_uid,p_session_id,p_action,15,10,60
  );
$$;

revoke all on function public.trustrelay_sensitive_action_guard_admin_v11(uuid,text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_sensitive_action_guard_admin_v11(uuid,text,text)
to service_role;
