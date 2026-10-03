-- TrustRelay v1.2 secretless verifier session bridge.
-- Service-role-only RPC verifies the authenticated user's actual Supabase session,
-- AAL2/TOTP state, absolute session age, organization membership and decision permission.
create or replace function public.trustrelay_portal_session_context_v12(
  p_auth_user_id uuid,
  p_session_id text,
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','auth','pg_catalog'
as $$
declare
  v_session auth.sessions%rowtype;
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_member public.organization_members%rowtype;
  v_permissions jsonb;
begin
  if p_auth_user_id is null
     or p_session_id is null or length(btrim(p_session_id))<8 or length(p_session_id)>200
     or p_org_id is null or length(btrim(p_org_id))<4 or length(p_org_id)>160 then
    return jsonb_build_object('ok',false,'status',400,'code','PORTAL_SESSION_CONTEXT_INVALID');
  end if;

  select * into v_session
  from auth.sessions
  where id::text=btrim(p_session_id)
    and user_id=p_auth_user_id
  limit 1;

  if not found
     or (v_session.not_after is not null and v_session.not_after<=clock_timestamp()) then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_NOT_ACTIVE');
  end if;

  if v_session.created_at < clock_timestamp()-interval '8 hours' then
    return jsonb_build_object('ok',false,'status',401,'code','INSTITUTIONAL_SESSION_EXPIRED','maxSessionHours',8);
  end if;

  if coalesce(v_session.aal::text,'aal1')<>'aal2' then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_CHALLENGE_REQUIRED','requiredAal','aal2');
  end if;

  if not exists(
    select 1 from auth.mfa_factors f
    where f.user_id=p_auth_user_id
      and f.status::text='verified'
      and f.factor_type::text='totp'
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_ENROLLMENT_REQUIRED','requiredFactor','totp');
  end if;

  select * into v_account
  from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_org
  from public.organizations
  where id=p_org_id and status='active'
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_NOT_FOUND');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id
    and account_id=v_account.id
    and status='active'
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ACCESS_DENIED');
  end if;

  v_permissions:=public.trustrelay_org_permissions_v09(v_member.role);
  if coalesce((v_permissions->>'decisions.evaluate')::boolean,false)=false then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED',
      'permission','decisions.evaluate','role',v_member.role
    );
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',jsonb_build_object('id',v_org.id,'name',v_org.name,'mode',v_org.mode,'status',v_org.status),
    'accountId',v_account.id,
    'role',v_member.role,
    'sessionId',v_session.id::text,
    'aal','aal2',
    'sessionCreatedAt',to_char(v_session.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
end;
$$;

revoke all on function public.trustrelay_portal_session_context_v12(uuid,text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_portal_session_context_v12(uuid,text,text)
to service_role;

notify pgrst,'reload schema';
