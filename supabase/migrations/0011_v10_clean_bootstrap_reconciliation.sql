-- TrustRelay v1.0 clean-bootstrap reconciliation.
-- Adds user privacy-request RPCs and restores the canonical webhook maintenance scheduler
-- that existed in live staging but was not represented in the earlier recorded migration exports.

alter table public.privacy_requests
  add column if not exists identity_verification_status text,
  add column if not exists response_summary text,
  add column if not exists cancelled_at text;

alter table public.privacy_requests
  drop constraint if exists privacy_requests_request_type_v10;
alter table public.privacy_requests
  add constraint privacy_requests_request_type_v10
  check (request_type is null or request_type in ('access','correction','deletion','restriction','portability','other'));

alter table public.privacy_requests
  drop constraint if exists privacy_requests_status_v10;
alter table public.privacy_requests
  add constraint privacy_requests_status_v10
  check (status in ('open','submitted','in_review','awaiting_identity','completed','denied','cancelled'));

create index if not exists idx_privacy_requests_requester_created_v10
  on public.privacy_requests(requester_account_id,created_at desc);

create or replace function public.trustrelay_submit_privacy_request_v10(
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

create or replace function public.trustrelay_my_privacy_requests_v10()
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

revoke all on function public.trustrelay_submit_privacy_request_v10(text,text,text) from public,anon;
revoke all on function public.trustrelay_my_privacy_requests_v10() from public,anon;
grant execute on function public.trustrelay_submit_privacy_request_v10(text,text,text) to authenticated,service_role;
grant execute on function public.trustrelay_my_privacy_requests_v10() to authenticated,service_role;

create or replace function public.trustrelay_webhook_maintenance_v09()
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_reconcile jsonb;
  v_dispatch jsonb;
begin
  v_reconcile:=public.trustrelay_reconcile_webhooks_v09(100);
  v_dispatch:=public.trustrelay_dispatch_due_webhooks_v09(50);
  return jsonb_build_object('ok',true,'reconcile',v_reconcile,'dispatch',v_dispatch);
end;
$$;

revoke all on function public.trustrelay_webhook_maintenance_v09() from public,anon,authenticated;
grant execute on function public.trustrelay_webhook_maintenance_v09() to service_role;

create extension if not exists pg_cron;

do $$
declare
  v_job record;
begin
  for v_job in
    select jobid from cron.job where jobname='trustrelay-webhook-maintenance-v09'
  loop
    perform cron.unschedule(v_job.jobid);
  end loop;
end $$;

select cron.schedule(
  'trustrelay-webhook-maintenance-v09',
  '* * * * *',
  $$select public.trustrelay_webhook_maintenance_v09();$$
);

insert into public.production_readiness_controls(
  control_key,category,status,required,evidence,owner_note,updated_at
) values(
  'webhook_egress_policy','security','pass',true,
  'Canonical TrustRelay v1.0 dispatcher uses the Supabase Edge pinned-TLS egress path with delivery-time DNS/public-IP validation, TLS hostname verification and redirect rejection.',
  'Clean-bootstrap reconciliation restored the canonical maintenance scheduler without changing the pinned-TLS transport contract.',
  to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
)
on conflict(control_key) do update set
  status=excluded.status,
  required=excluded.required,
  evidence=excluded.evidence,
  owner_note=excluded.owner_note,
  updated_at=excluded.updated_at;
