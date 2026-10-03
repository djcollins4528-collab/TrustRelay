-- Require a live, non-revoked Supabase session for authenticated organization-role/permission operations.
-- Service-role Edge workflows remain valid because auth.uid() is null for those trusted calls.

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
    v_guard:=private.trustrelay_session_guard_v10(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then
      return v_guard;
    end if;
  end if;

  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$$;

revoke all on function private.trustrelay_require_org_role_v07(uuid,text,text[]) from public,anon,authenticated;
grant execute on function private.trustrelay_require_org_role_v07(uuid,text,text[]) to service_role;
