-- TrustRelay v1.2 institutional absolute session lifetime.
-- Verifier/admin access requires a fresh sign-in at least every 12 hours.

create or replace function private.trustrelay_require_aal2_v12(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'auth','private','pg_catalog'
as $$
declare
  v_guard jsonb;
  v_jwt_role text:=coalesce(auth.jwt()->>'role','');
  v_session_id text:=coalesce(auth.jwt()->>'session_id','');
  v_session_created timestamptz;
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

  select s.created_at into v_session_created
  from auth.sessions s
  where s.id::text=v_session_id and s.user_id=p_uid
  limit 1;

  if v_session_created is null
     or v_session_created < clock_timestamp()-interval '12 hours' then
    return jsonb_build_object(
      'ok',false,'status',401,'code','INSTITUTIONAL_SESSION_EXPIRED',
      'maxSessionHours',12
    );
  end if;

  if not exists (
    select 1 from auth.mfa_factors f
    where f.user_id=p_uid
      and f.status::text='verified'
      and f.factor_type::text='totp'
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_ENROLLMENT_REQUIRED','requiredFactor','totp');
  end if;

  if coalesce(auth.jwt()->>'aal','aal1')<>'aal2' then
    return jsonb_build_object('ok',false,'status',403,'code','MFA_CHALLENGE_REQUIRED','requiredAal','aal2');
  end if;

  return jsonb_build_object(
    'ok',true,'aal','aal2','sessionId',v_session_id,
    'maxSessionHours',12
  );
end;
$$;

revoke all on function private.trustrelay_require_aal2_v12(uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_require_aal2_v12(uuid) to service_role;
notify pgrst,'reload schema';