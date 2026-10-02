-- TrustRelay v1.0 privacy RPC hardening.
-- Keeps privileged data access in the non-exposed private schema while public RPCs remain SECURITY INVOKER.

create or replace function private.trustrelay_submit_privacy_request_v10(
  p_request_type text,
  p_org_id text default null,
  p_details text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,auth,extensions,pg_catalog
as $$
declare
  v_uid uuid:=auth.uid();
  v_ctx jsonb;
  v_org_ctx jsonb;
  v_account_id text;
  v_email text;
  v_identity text;
  v_id text:='privacy_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_details text:=nullif(left(btrim(coalesce(p_details,'')),4000),'');
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  if p_request_type not in ('access','correction','deletion','restriction','portability','other') then
    return jsonb_build_object('ok',false,'status',400,'code','PRIVACY_REQUEST_TYPE_INVALID');
  end if;

  v_ctx:=private.trustrelay_account_context_v08(v_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then
    return v_ctx;
  end if;

  v_account_id:=v_ctx->'account'->>'id';
  v_email:=v_ctx->'account'->>'email';
  v_identity:=coalesce(
    nullif(v_ctx->'person'->>'identity_assurance_level',''),
    nullif(v_ctx->'person'->>'identity_status',''),
    'none'
  );

  if p_org_id is not null then
    v_org_ctx:=private.trustrelay_require_org_role_v07(v_uid,p_org_id,null);
    if coalesce((v_org_ctx->>'ok')::boolean,false)=false then
      return v_org_ctx;
    end if;
    if v_org_ctx->>'accountId' is distinct from v_account_id then
      return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ACCESS_DENIED');
    end if;
  end if;

  insert into public.privacy_requests(
    id,requester_account_id,organization_id,request_type,status,
    requester_email,intake_source,description,details_json,
    identity_verification_status,created_at,updated_at
  ) values(
    v_id,v_account_id,p_org_id,p_request_type,'submitted',
    v_email,'consumer_app',v_details,'{}',
    v_identity,v_now,v_now
  );

  if p_org_id is not null then
    perform private.trustrelay_append_org_audit_v09(
      p_org_id,v_account_id,'privacy.request.submitted','privacy_request',v_id,
      jsonb_build_object('requestType',p_request_type,'identityVerificationStatus',v_identity)
    );
  end if;

  return jsonb_build_object(
    'ok',true,
    'request',jsonb_build_object(
      'id',v_id,
      'organizationId',p_org_id,
      'requestType',p_request_type,
      'status','submitted',
      'identityVerificationStatus',v_identity,
      'submittedAt',v_now,
      'responseSummary',null
    )
  );
end;
$$;

create or replace function private.trustrelay_my_privacy_requests_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_uid uuid:=auth.uid();
  v_ctx jsonb;
  v_account_id text;
  v_requests jsonb;
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  v_ctx:=private.trustrelay_account_context_v08(v_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then
    return v_ctx;
  end if;

  v_account_id:=v_ctx->'account'->>'id';

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',r.id,
    'organizationId',r.organization_id,
    'requestType',r.request_type,
    'status',r.status,
    'identityVerificationStatus',coalesce(r.identity_verification_status,'none'),
    'submittedAt',r.created_at,
    'updatedAt',r.updated_at,
    'acknowledgedAt',r.acknowledged_at,
    'responseDueAt',r.response_due_at,
    'jurisdictionCode',r.jurisdiction_code,
    'completedAt',r.completed_at,
    'deniedAt',r.denied_at,
    'cancelledAt',r.cancelled_at,
    'responseSummary',coalesce(r.response_summary,r.denial_reason)
  ) order by r.created_at desc),'[]'::jsonb)
  into v_requests
  from public.privacy_requests r
  where r.requester_account_id=v_account_id;

  return jsonb_build_object('ok',true,'requests',v_requests);
end;
$$;

revoke all on function private.trustrelay_submit_privacy_request_v10(text,text,text) from public,anon;
revoke all on function private.trustrelay_my_privacy_requests_v10() from public,anon;
grant execute on function private.trustrelay_submit_privacy_request_v10(text,text,text) to authenticated;
grant execute on function private.trustrelay_my_privacy_requests_v10() to authenticated;

create or replace function public.trustrelay_submit_privacy_request_v10(
  p_request_type text,
  p_org_id text default null,
  p_details text default null
)
returns jsonb
language sql
security invoker
set search_path=private,pg_catalog
as $$
  select private.trustrelay_submit_privacy_request_v10(p_request_type,p_org_id,p_details);
$$;

create or replace function public.trustrelay_my_privacy_requests_v10()
returns jsonb
language sql
security invoker
set search_path=private,pg_catalog
as $$
  select private.trustrelay_my_privacy_requests_v10();
$$;

revoke all on function public.trustrelay_submit_privacy_request_v10(text,text,text) from public,anon;
revoke all on function public.trustrelay_my_privacy_requests_v10() from public,anon;
grant execute on function public.trustrelay_submit_privacy_request_v10(text,text,text) to authenticated;
grant execute on function public.trustrelay_my_privacy_requests_v10() to authenticated;
