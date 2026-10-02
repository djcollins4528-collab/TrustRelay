-- TrustRelay v1.0 operational hardening recorded from live staging migration history.
-- Canonical repo catch-up for migrations applied on 2026-10-01/02 after 0004_v10_production_candidate_baseline.sql.
-- Preserves the exact applied statement order, followed by the cancelled-status readiness fix.

-- Clean-bootstrap prelude for operational tables that existed before the recorded v1.0 hardening migrations.

create table if not exists public.privacy_requests(
  id text primary key,
  requester_account_id text references public.accounts(id) on delete set null,
  organization_id text references public.organizations(id) on delete set null,
  request_type text,
  status text not null default 'open',
  requester_email text,
  intake_source text,
  description text,
  details_json text not null default '{}',
  acknowledged_at text,
  completed_at text,
  denied_at text,
  denial_reason text,
  created_at text not null,
  updated_at text not null
);

alter table public.privacy_requests enable row level security;
drop policy if exists trustrelay_deny_clients on public.privacy_requests;
create policy trustrelay_deny_clients on public.privacy_requests
  as restrictive for all to anon,authenticated using(false) with check(false);
revoke all on public.privacy_requests from anon,authenticated;
grant select,insert,update on public.privacy_requests to service_role;
create index if not exists idx_privacy_requests_status_created_v10
  on public.privacy_requests(status,created_at desc);

create table if not exists public.retention_policies(
  record_class text primary key,
  retention_days integer,
  action text,
  status text not null default 'draft',
  legal_basis_note text,
  approved_by_account_id text references public.accounts(id) on delete set null,
  approved_at text,
  created_at text not null,
  updated_at text not null,
  constraint retention_days_positive_v10 check (retention_days is null or retention_days > 0)
);

alter table public.retention_policies enable row level security;
drop policy if exists trustrelay_deny_clients on public.retention_policies;
create policy trustrelay_deny_clients on public.retention_policies
  as restrictive for all to anon,authenticated using(false) with check(false);
revoke all on public.retention_policies from anon,authenticated;
grant select,insert,update on public.retention_policies to service_role;

create table if not exists public.retention_runs(
  id text primary key,
  run_type text not null,
  status text not null,
  policy_snapshot_json text not null default '[]',
  candidate_counts_json text not null default '{}',
  action_counts_json text not null default '{}',
  evidence_hash text,
  started_at text not null,
  completed_at text,
  initiated_by text,
  error_code text,
  error_message text
);

alter table public.retention_runs enable row level security;
drop policy if exists trustrelay_deny_clients on public.retention_runs;
create policy trustrelay_deny_clients on public.retention_runs
  as restrictive for all to anon,authenticated using(false) with check(false);
revoke all on public.retention_runs from anon,authenticated;
grant select,insert,update on public.retention_runs to service_role;
create index if not exists idx_retention_runs_type_status_completed_v10
  on public.retention_runs(run_type,status,completed_at desc);

-- No retention policy periods/actions are seeded here. Those require approved legal/business policy.

-- LIVE MIGRATION 20261001230035: trustrelay_v10_governance_retention_hardening
alter table private.identity_reviewers
  add column if not exists approval_status text not null default 'legacy',
  add column if not exists requested_by_account_id text references public.accounts(id) on delete set null,
  add column if not exists requested_at text,
  add column if not exists approved_by_account_id text references public.accounts(id) on delete set null,
  add column if not exists approved_at text,
  add column if not exists expires_at text,
  add column if not exists training_attested_at text,
  add column if not exists governance_notes text,
  add column if not exists last_access_reviewed_at text;

alter table private.identity_reviewers
  drop constraint if exists identity_reviewers_approval_status_v10;
alter table private.identity_reviewers
  add constraint identity_reviewers_approval_status_v10
  check (approval_status in ('legacy','pending','approved','rejected','revoked'));

create index if not exists idx_identity_reviewers_requested_by_v10
  on private.identity_reviewers(requested_by_account_id);
create index if not exists idx_identity_reviewers_approved_by_v10
  on private.identity_reviewers(approved_by_account_id);
create index if not exists idx_identity_reviewers_expiry_v10
  on private.identity_reviewers(expires_at);

create table if not exists public.production_readiness_events(
  id text primary key,
  control_key text not null references public.production_readiness_controls(control_key) on delete restrict,
  previous_status text,
  new_status text not null,
  evidence_sha256 text,
  evidence_excerpt text,
  owner_note text,
  changed_at text not null,
  constraint production_readiness_event_status_v10
    check (new_status in ('pass','fail','unknown','not_applicable')),
  constraint production_readiness_event_prev_status_v10
    check (previous_status is null or previous_status in ('pass','fail','unknown','not_applicable')),
  constraint production_readiness_event_hash_v10
    check (evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$')
);

alter table public.production_readiness_events enable row level security;

drop policy if exists trustrelay_deny_clients on public.production_readiness_events;
create policy trustrelay_deny_clients on public.production_readiness_events
  as restrictive for all to anon,authenticated using(false) with check(false);

revoke all on public.production_readiness_events from anon,authenticated;
grant select,insert on public.production_readiness_events to service_role;

create index if not exists idx_readiness_events_control_v10
  on public.production_readiness_events(control_key,changed_at desc);

create table if not exists public.reviewer_governance_events(
  id text primary key,
  reviewer_account_id text not null references public.accounts(id) on delete cascade,
  event_type text not null,
  actor_account_id text references public.accounts(id) on delete set null,
  metadata_json text not null default '{}',
  created_at text not null
);

alter table public.reviewer_governance_events enable row level security;

drop policy if exists trustrelay_deny_clients on public.reviewer_governance_events;
create policy trustrelay_deny_clients on public.reviewer_governance_events
  as restrictive for all to anon,authenticated using(false) with check(false);

revoke all on public.reviewer_governance_events from anon,authenticated;
grant select,insert on public.reviewer_governance_events to service_role;

create index if not exists idx_reviewer_governance_account_v10
  on public.reviewer_governance_events(reviewer_account_id,created_at desc);
create index if not exists idx_reviewer_governance_actor_v10
  on public.reviewer_governance_events(actor_account_id,created_at desc);

-- LIVE MIGRATION 20261001230110: trustrelay_v10_reviewer_dual_control_and_readiness_ledger
create or replace function private.trustrelay_reviewer_context_v08(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_reviewer private.identity_reviewers%rowtype;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_reviewer
  from private.identity_reviewers
  where account_id=v_account.id
    and status='active'
    and approval_status='approved'
    and training_attested_at is not null
    and (expires_at is null or expires_at::timestamptz>clock_timestamp())
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','IDENTITY_REVIEWER_REQUIRED');
  end if;

  return jsonb_build_object(
    'ok',true,
    'account',to_jsonb(v_account),
    'reviewer',to_jsonb(v_reviewer)
  );
end;
$$;

create or replace function public.trustrelay_set_identity_reviewer_v08(
  p_account_id text,
  p_role text,
  p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if not exists(select 1 from public.accounts where id=p_account_id) then
    return jsonb_build_object('ok',false,'status',404,'code','ACCOUNT_NOT_FOUND');
  end if;

  if p_role not in ('reviewer','senior_reviewer') then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEWER_ROLE_INVALID');
  end if;

  if p_enabled then
    return jsonb_build_object(
      'ok',false,'status',409,'code','REVIEWER_GOVERNANCE_REQUIRED',
      'detail','Use the v1.0 request and independent approval workflow.'
    );
  end if;

  update private.identity_reviewers
  set
    status='disabled',
    approval_status=case when approval_status='approved' then 'revoked' else approval_status end
  where account_id=p_account_id;

  insert into public.reviewer_governance_events(
    id,reviewer_account_id,event_type,actor_account_id,metadata_json,created_at
  ) values (
    'rgev_'||replace(gen_random_uuid()::text,'-',''),
    p_account_id,'reviewer.disabled',null,
    jsonb_build_object('source','legacy_v08_disable')::text,
    to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );

  return jsonb_build_object('ok',true,'accountId',p_account_id,'status','disabled');
end;
$$;

create or replace function public.trustrelay_request_identity_reviewer_v10(
  p_account_id text,
  p_role text,
  p_requested_by_account_id text,
  p_governance_notes text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if not exists(select 1 from public.accounts where id=p_account_id and status='active') then
    return jsonb_build_object('ok',false,'status',404,'code','ACCOUNT_NOT_FOUND');
  end if;

  if not exists(select 1 from public.accounts where id=p_requested_by_account_id and status='active') then
    return jsonb_build_object('ok',false,'status',404,'code','REQUESTOR_ACCOUNT_NOT_FOUND');
  end if;

  if p_account_id=p_requested_by_account_id then
    return jsonb_build_object('ok',false,'status',409,'code','SELF_REVIEWER_REQUEST_FORBIDDEN');
  end if;

  if p_role not in ('reviewer','senior_reviewer') then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEWER_ROLE_INVALID');
  end if;

  insert into private.identity_reviewers(
    account_id,reviewer_role,status,created_at,approval_status,
    requested_by_account_id,requested_at,governance_notes
  ) values (
    p_account_id,p_role,'disabled',v_now,'pending',
    p_requested_by_account_id,v_now,
    nullif(left(btrim(coalesce(p_governance_notes,'')),2000),'')
  )
  on conflict(account_id) do update set
    reviewer_role=excluded.reviewer_role,
    status='disabled',
    approval_status='pending',
    requested_by_account_id=excluded.requested_by_account_id,
    requested_at=v_now,
    approved_by_account_id=null,
    approved_at=null,
    expires_at=null,
    training_attested_at=null,
    governance_notes=excluded.governance_notes;

  insert into public.reviewer_governance_events(
    id,reviewer_account_id,event_type,actor_account_id,metadata_json,created_at
  ) values (
    'rgev_'||replace(gen_random_uuid()::text,'-',''),
    p_account_id,'reviewer.requested',p_requested_by_account_id,
    jsonb_build_object('role',p_role,'notes',nullif(left(btrim(coalesce(p_governance_notes,'')),2000),''))::text,
    v_now
  );

  return jsonb_build_object(
    'ok',true,'accountId',p_account_id,'reviewerRole',p_role,
    'approvalStatus','pending','requestedAt',v_now
  );
end;
$$;

create or replace function public.trustrelay_approve_identity_reviewer_v10(
  p_account_id text,
  p_approved_by_account_id text,
  p_training_attested boolean,
  p_expires_at text,
  p_governance_notes text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_reviewer private.identity_reviewers%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_reviewer
  from private.identity_reviewers
  where account_id=p_account_id
  for update;

  if not found or v_reviewer.approval_status<>'pending' then
    return jsonb_build_object('ok',false,'status',404,'code','REVIEWER_REQUEST_NOT_PENDING');
  end if;

  if not exists(select 1 from public.accounts where id=p_approved_by_account_id and status='active') then
    return jsonb_build_object('ok',false,'status',404,'code','APPROVER_ACCOUNT_NOT_FOUND');
  end if;

  if p_approved_by_account_id in (p_account_id,v_reviewer.requested_by_account_id) then
    return jsonb_build_object('ok',false,'status',409,'code','DUAL_CONTROL_APPROVER_INVALID');
  end if;

  if coalesce(p_training_attested,false)=false then
    return jsonb_build_object('ok',false,'status',409,'code','REVIEWER_TRAINING_REQUIRED');
  end if;

  if p_expires_at is null or p_expires_at::timestamptz<=clock_timestamp()
     or p_expires_at::timestamptz>clock_timestamp()+interval '366 days' then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEWER_EXPIRY_INVALID');
  end if;

  update private.identity_reviewers
  set
    status='active',
    approval_status='approved',
    approved_by_account_id=p_approved_by_account_id,
    approved_at=v_now,
    expires_at=p_expires_at,
    training_attested_at=v_now,
    governance_notes=coalesce(
      nullif(left(btrim(coalesce(p_governance_notes,'')),2000),''),
      governance_notes
    ),
    last_access_reviewed_at=v_now
  where account_id=p_account_id
  returning * into v_reviewer;

  insert into public.reviewer_governance_events(
    id,reviewer_account_id,event_type,actor_account_id,metadata_json,created_at
  ) values (
    'rgev_'||replace(gen_random_uuid()::text,'-',''),
    p_account_id,'reviewer.approved',p_approved_by_account_id,
    jsonb_build_object(
      'role',v_reviewer.reviewer_role,
      'expiresAt',p_expires_at,
      'trainingAttested',true
    )::text,
    v_now
  );

  return jsonb_build_object(
    'ok',true,'accountId',p_account_id,'status','active',
    'approvalStatus','approved','expiresAt',p_expires_at,'approvedAt',v_now
  );
end;
$$;

create or replace function public.trustrelay_revoke_identity_reviewer_v10(
  p_account_id text,
  p_actor_account_id text,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if not exists(select 1 from private.identity_reviewers where account_id=p_account_id) then
    return jsonb_build_object('ok',false,'status',404,'code','REVIEWER_NOT_FOUND');
  end if;

  update private.identity_reviewers
  set status='disabled',approval_status='revoked'
  where account_id=p_account_id;

  insert into public.reviewer_governance_events(
    id,reviewer_account_id,event_type,actor_account_id,metadata_json,created_at
  ) values (
    'rgev_'||replace(gen_random_uuid()::text,'-',''),
    p_account_id,'reviewer.revoked',p_actor_account_id,
    jsonb_build_object('reason',nullif(left(btrim(coalesce(p_reason,'')),1000),''))::text,
    v_now
  );

  return jsonb_build_object('ok',true,'accountId',p_account_id,'status','disabled','approvalStatus','revoked');
end;
$$;

create or replace function public.trustrelay_set_production_control_v10(
  p_control_key text,
  p_status text,
  p_evidence text,
  p_owner_note text
)
returns jsonb
language plpgsql
security definer
set search_path=public,extensions,pg_catalog
as $$
declare
  v_row public.production_readiness_controls%rowtype;
  v_previous text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_evidence text:=nullif(left(coalesce(p_evidence,''),4000),'');
  v_hash text;
begin
  if p_status not in ('pass','fail','unknown','not_applicable') then
    return jsonb_build_object('ok',false,'status',400,'code','READINESS_STATUS_INVALID');
  end if;

  select status into v_previous
  from public.production_readiness_controls
  where control_key=p_control_key
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','READINESS_CONTROL_NOT_FOUND');
  end if;

  if v_evidence is not null then
    v_hash:=encode(digest(v_evidence,'sha256'),'hex');
  end if;

  update public.production_readiness_controls
  set
    status=p_status,
    evidence=v_evidence,
    owner_note=nullif(left(coalesce(p_owner_note,''),4000),''),
    updated_at=v_now
  where control_key=p_control_key
  returning * into v_row;

  insert into public.production_readiness_events(
    id,control_key,previous_status,new_status,evidence_sha256,evidence_excerpt,owner_note,changed_at
  ) values (
    'readyev_'||replace(gen_random_uuid()::text,'-',''),
    p_control_key,v_previous,p_status,v_hash,
    case when v_evidence is null then null else left(v_evidence,500) end,
    nullif(left(coalesce(p_owner_note,''),2000),''),
    v_now
  );

  return jsonb_build_object(
    'ok',true,'control',to_jsonb(v_row),
    'platform',private.trustrelay_platform_readiness_v10()
  );
end;
$$;

revoke all on function public.trustrelay_set_identity_reviewer_v08(text,text,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_request_identity_reviewer_v10(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_approve_identity_reviewer_v10(text,text,boolean,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_revoke_identity_reviewer_v10(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_set_production_control_v10(text,text,text,text) from public,anon,authenticated;

grant execute on function public.trustrelay_set_identity_reviewer_v08(text,text,boolean) to service_role;
grant execute on function public.trustrelay_request_identity_reviewer_v10(text,text,text,text) to service_role;
grant execute on function public.trustrelay_approve_identity_reviewer_v10(text,text,boolean,text,text) to service_role;
grant execute on function public.trustrelay_revoke_identity_reviewer_v10(text,text,text) to service_role;
grant execute on function public.trustrelay_set_production_control_v10(text,text,text,text) to service_role;

-- LIVE MIGRATION 20261001230155: trustrelay_v10_operational_contacts_privacy_sla_retention_schedule
alter table public.privacy_requests
  add column if not exists jurisdiction_code text,
  add column if not exists response_due_at text,
  add column if not exists deadline_source_note text,
  add column if not exists last_escalated_at text;

create index if not exists idx_privacy_requests_due_v10
  on public.privacy_requests(status,response_due_at);

create table if not exists public.privacy_request_events(
  id text primary key,
  request_id text not null references public.privacy_requests(id) on delete cascade,
  event_type text not null,
  actor_account_id text references public.accounts(id) on delete set null,
  metadata_json text not null default '{}',
  created_at text not null
);

alter table public.privacy_request_events enable row level security;
drop policy if exists trustrelay_deny_clients on public.privacy_request_events;
create policy trustrelay_deny_clients on public.privacy_request_events
  as restrictive for all to anon,authenticated using(false) with check(false);
revoke all on public.privacy_request_events from anon,authenticated;
grant select,insert on public.privacy_request_events to service_role;
create index if not exists idx_privacy_request_events_request_v10
  on public.privacy_request_events(request_id,created_at desc);
create index if not exists idx_privacy_request_events_actor_v10
  on public.privacy_request_events(actor_account_id,created_at desc);

create table if not exists public.production_operational_contacts(
  contact_type text primary key,
  contact_email text not null,
  monitored boolean not null default false,
  verified_at text,
  verification_note text,
  updated_at text not null,
  constraint production_contact_type_v10
    check (contact_type in ('security','privacy','incident','legal','reviewer_governance'))
);

alter table public.production_operational_contacts enable row level security;
drop policy if exists trustrelay_deny_clients on public.production_operational_contacts;
create policy trustrelay_deny_clients on public.production_operational_contacts
  as restrictive for all to anon,authenticated using(false) with check(false);
revoke all on public.production_operational_contacts from anon,authenticated;
grant select,insert,update on public.production_operational_contacts to service_role;

alter table public.retention_policies
  add column if not exists execution_enabled boolean not null default false,
  add column if not exists deletion_requires_manual_approval boolean not null default true,
  add column if not exists last_dry_run_at text,
  add column if not exists last_dry_run_evidence_hash text;

alter table public.retention_policies
  drop constraint if exists retention_execution_guard_v10;
alter table public.retention_policies
  add constraint retention_execution_guard_v10
  check (not execution_enabled or (status='approved' and retention_days is not null and approved_at is not null));

create index if not exists idx_retention_policy_status_v10
  on public.retention_policies(status,execution_enabled);

create extension if not exists pg_cron;

do $$
declare v_job bigint;
begin
  select jobid into v_job from cron.job where jobname='trustrelay-retention-dry-run-v10';
  if v_job is not null then
    perform cron.unschedule(v_job);
  end if;
end $$;

select cron.schedule(
  'trustrelay-retention-dry-run-v10',
  '20 3 * * *',
  $$select public.trustrelay_retention_dry_run_v10();$$
);

-- LIVE MIGRATION 20261001230230: trustrelay_v10_objective_readiness_and_privacy_operations
create or replace function public.trustrelay_retention_dry_run_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,extensions,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_id text:='retention_'||replace(gen_random_uuid()::text,'-','');
  v_policies jsonb;
  v_counts jsonb;
  v_hash text;
begin
  select coalesce(jsonb_agg(jsonb_build_object(
    'recordClass',record_class,
    'retentionDays',retention_days,
    'action',action,
    'status',status,
    'executionEnabled',execution_enabled,
    'deletionRequiresManualApproval',deletion_requires_manual_approval,
    'approvedAt',approved_at
  ) order by record_class),'[]'::jsonb)
  into v_policies
  from public.retention_policies;

  v_counts:=jsonb_build_object(
    'totalPolicies',(select count(*) from public.retention_policies),
    'approvedPolicies',(select count(*) from public.retention_policies where status='approved' and retention_days is not null),
    'draftPolicies',(select count(*) from public.retention_policies where status='draft'),
    'executionEnabledPolicies',(select count(*) from public.retention_policies where execution_enabled=true),
    'candidateDeletionEnabled',false
  );

  v_hash:=encode(digest(concat_ws('|',v_id,v_policies::text,v_counts::text,v_now),'sha256'),'hex');

  insert into public.retention_runs(
    id,run_type,status,policy_snapshot_json,candidate_counts_json,action_counts_json,
    evidence_hash,started_at,completed_at,initiated_by
  ) values(
    v_id,'dry_run','completed',v_policies::text,v_counts::text,'{}',
    v_hash,v_now,v_now,'scheduled_or_service_role'
  );

  update public.retention_policies
  set last_dry_run_at=v_now,last_dry_run_evidence_hash=v_hash,updated_at=v_now;

  return jsonb_build_object(
    'ok',true,'runId',v_id,'status','completed','policySnapshot',v_policies,
    'candidateCounts',v_counts,'evidenceHash',v_hash,'startedAt',v_now,'completedAt',v_now
  );
end;
$$;

create or replace function public.trustrelay_set_operational_contact_v10(
  p_contact_type text,
  p_contact_email text,
  p_monitored boolean,
  p_verification_note text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_email text:=lower(btrim(coalesce(p_contact_email,'')));
  v_row public.production_operational_contacts%rowtype;
begin
  if p_contact_type not in ('security','privacy','incident','legal','reviewer_governance') then
    return jsonb_build_object('ok',false,'status',400,'code','OPERATIONAL_CONTACT_TYPE_INVALID');
  end if;

  if v_email !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','OPERATIONAL_CONTACT_EMAIL_INVALID');
  end if;

  insert into public.production_operational_contacts(
    contact_type,contact_email,monitored,verified_at,verification_note,updated_at
  ) values(
    p_contact_type,v_email,coalesce(p_monitored,false),
    case when coalesce(p_monitored,false) then v_now else null end,
    nullif(left(btrim(coalesce(p_verification_note,'')),2000),''),
    v_now
  )
  on conflict(contact_type) do update set
    contact_email=excluded.contact_email,
    monitored=excluded.monitored,
    verified_at=case when excluded.monitored then v_now else null end,
    verification_note=excluded.verification_note,
    updated_at=v_now
  returning * into v_row;

  return jsonb_build_object('ok',true,'contact',to_jsonb(v_row));
end;
$$;

create or replace function public.trustrelay_set_privacy_request_deadline_v10(
  p_request_id text,
  p_jurisdiction_code text,
  p_response_due_at text,
  p_deadline_source_note text,
  p_actor_account_id text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_row public.privacy_requests%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_response_due_at is null then
    return jsonb_build_object('ok',false,'status',400,'code','PRIVACY_DEADLINE_REQUIRED');
  end if;

  begin
    if p_response_due_at::timestamptz<=clock_timestamp() then
      return jsonb_build_object('ok',false,'status',400,'code','PRIVACY_DEADLINE_INVALID');
    end if;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','PRIVACY_DEADLINE_INVALID');
  end;

  update public.privacy_requests
  set
    jurisdiction_code=nullif(left(upper(btrim(coalesce(p_jurisdiction_code,''))),32),''),
    response_due_at=p_response_due_at,
    deadline_source_note=nullif(left(btrim(coalesce(p_deadline_source_note,'')),2000),''),
    updated_at=v_now
  where id=p_request_id
  returning * into v_row;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','PRIVACY_REQUEST_NOT_FOUND');
  end if;

  insert into public.privacy_request_events(
    id,request_id,event_type,actor_account_id,metadata_json,created_at
  ) values(
    'privev_'||replace(gen_random_uuid()::text,'-',''),
    p_request_id,'privacy.deadline.set',p_actor_account_id,
    jsonb_build_object(
      'jurisdictionCode',v_row.jurisdiction_code,
      'responseDueAt',v_row.response_due_at,
      'deadlineSourceNote',v_row.deadline_source_note
    )::text,
    v_now
  );

  return jsonb_build_object('ok',true,'request',to_jsonb(v_row));
end;
$$;

create or replace function public.trustrelay_refresh_objective_readiness_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_reviewer_count integer;
  v_retention_total integer;
  v_retention_approved integer;
  v_retention_job boolean;
  v_recent_retention boolean;
  v_security_contact boolean;
  v_privacy_contact boolean;
  v_privacy_deadlines_ready boolean;
begin
  select count(*) into v_reviewer_count
  from private.identity_reviewers
  where status='active'
    and approval_status='approved'
    and training_attested_at is not null
    and approved_by_account_id is not null
    and requested_by_account_id is not null
    and approved_by_account_id<>requested_by_account_id
    and approved_by_account_id<>account_id
    and (expires_at is null or expires_at::timestamptz>clock_timestamp());

  perform public.trustrelay_set_production_control_v10(
    'reviewer_governance',
    case when v_reviewer_count>=2 then 'pass' else 'fail' end,
    'Approved, trained, unexpired dual-control reviewers: '||v_reviewer_count::text||'. Production requires at least two.',
    'Reviewer governance is derived from the v1.0 dual-control reviewer registry.'
  );

  select count(*) into v_retention_total from public.retention_policies;
  select count(*) into v_retention_approved
  from public.retention_policies
  where status='approved' and retention_days is not null and approved_at is not null;

  select exists(
    select 1 from cron.job where jobname='trustrelay-retention-dry-run-v10' and active=true
  ) into v_retention_job;

  select exists(
    select 1 from public.retention_runs
    where run_type='dry_run' and status='completed'
      and completed_at::timestamptz>=clock_timestamp()-interval '48 hours'
  ) into v_recent_retention;

  perform public.trustrelay_set_production_control_v10(
    'retention_automation',
    case when v_retention_total>0 and v_retention_total=v_retention_approved and v_retention_job and v_recent_retention
      then 'pass' else 'fail' end,
    concat(
      'Policies approved ',v_retention_approved,'/',v_retention_total,
      '; daily dry-run scheduled=',v_retention_job,
      '; successful dry-run within 48h=',v_recent_retention,
      '; destructive execution remains separately gated.'
    ),
    'Retention readiness requires approved policy periods/actions plus active dry-run evidence.'
  );

  select exists(
    select 1 from public.production_operational_contacts
    where contact_type='security' and monitored=true and verified_at is not null
  ) into v_security_contact;

  perform public.trustrelay_set_production_control_v10(
    'security_contact',
    case when v_security_contact then 'pass' else 'fail' end,
    case when v_security_contact then 'Verified monitored security contact is configured.' else 'No verified monitored security contact is configured.' end,
    'Operational contact state is derived from production_operational_contacts.'
  );

  select exists(
    select 1 from public.production_operational_contacts
    where contact_type='privacy' and monitored=true and verified_at is not null
  ) into v_privacy_contact;

  select not exists(
    select 1 from public.privacy_requests
    where status not in ('completed','denied','withdrawn')
      and response_due_at is null
  ) into v_privacy_deadlines_ready;

  perform public.trustrelay_set_production_control_v10(
    'privacy_request_process',
    case when v_privacy_contact and v_privacy_deadlines_ready then 'pass' else 'fail' end,
    concat(
      'Monitored privacy contact=',v_privacy_contact,
      '; all open privacy requests have explicit reviewed deadlines=',v_privacy_deadlines_ready,
      '. No jurisdiction-specific deadline is auto-invented by TrustRelay.'
    ),
    'Privacy deadlines must be assigned from an approved jurisdictional/legal policy.'
  );

  return private.trustrelay_platform_readiness_v10();
end;
$$;

revoke all on function public.trustrelay_set_operational_contact_v10(text,text,boolean,text) from public,anon,authenticated;
revoke all on function public.trustrelay_set_privacy_request_deadline_v10(text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_refresh_objective_readiness_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_retention_dry_run_v10() from public,anon,authenticated;

grant execute on function public.trustrelay_set_operational_contact_v10(text,text,boolean,text) to service_role;
grant execute on function public.trustrelay_set_privacy_request_deadline_v10(text,text,text,text,text) to service_role;
grant execute on function public.trustrelay_refresh_objective_readiness_v10() to service_role;
grant execute on function public.trustrelay_retention_dry_run_v10() to service_role;

-- LIVE MIGRATION 20261002012812: trustrelay_v10_privacy_readiness_cancelled_status_fix
CREATE OR REPLACE FUNCTION public.trustrelay_refresh_objective_readiness_v10()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_reviewer_count integer;
  v_retention_total integer;
  v_retention_approved integer;
  v_retention_job boolean;
  v_recent_retention boolean;
  v_security_contact boolean;
  v_privacy_contact boolean;
  v_privacy_deadlines_ready boolean;
begin
  select count(*) into v_reviewer_count
  from private.identity_reviewers
  where status='active'
    and approval_status='approved'
    and training_attested_at is not null
    and approved_by_account_id is not null
    and requested_by_account_id is not null
    and approved_by_account_id<>requested_by_account_id
    and approved_by_account_id<>account_id
    and (expires_at is null or expires_at::timestamptz>clock_timestamp());

  perform public.trustrelay_set_production_control_v10(
    'reviewer_governance',
    case when v_reviewer_count>=2 then 'pass' else 'fail' end,
    'Approved, trained, unexpired dual-control reviewers: '||v_reviewer_count::text||'. Production requires at least two.',
    'Reviewer governance is derived from the v1.0 dual-control reviewer registry.'
  );

  select count(*) into v_retention_total from public.retention_policies;
  select count(*) into v_retention_approved
  from public.retention_policies
  where status='approved' and retention_days is not null and approved_at is not null;

  select exists(
    select 1 from cron.job where jobname='trustrelay-retention-dry-run-v10' and active=true
  ) into v_retention_job;

  select exists(
    select 1 from public.retention_runs
    where run_type='dry_run' and status='completed'
      and completed_at::timestamptz>=clock_timestamp()-interval '48 hours'
  ) into v_recent_retention;

  perform public.trustrelay_set_production_control_v10(
    'retention_automation',
    case when v_retention_total>0 and v_retention_total=v_retention_approved and v_retention_job and v_recent_retention
      then 'pass' else 'fail' end,
    concat(
      'Policies approved ',v_retention_approved,'/',v_retention_total,
      '; daily dry-run scheduled=',v_retention_job,
      '; successful dry-run within 48h=',v_recent_retention,
      '; destructive execution remains separately gated.'
    ),
    'Retention readiness requires approved policy periods/actions plus active dry-run evidence.'
  );

  select exists(
    select 1 from public.production_operational_contacts
    where contact_type='security' and monitored=true and verified_at is not null
  ) into v_security_contact;

  perform public.trustrelay_set_production_control_v10(
    'security_contact',
    case when v_security_contact then 'pass' else 'fail' end,
    case when v_security_contact then 'Verified monitored security contact is configured.' else 'No verified monitored security contact is configured.' end,
    'Operational contact state is derived from production_operational_contacts.'
  );

  select exists(
    select 1 from public.production_operational_contacts
    where contact_type='privacy' and monitored=true and verified_at is not null
  ) into v_privacy_contact;

  select not exists(
    select 1 from public.privacy_requests
    where status not in ('completed','denied','cancelled')
      and response_due_at is null
  ) into v_privacy_deadlines_ready;

  perform public.trustrelay_set_production_control_v10(
    'privacy_request_process',
    case when v_privacy_contact and v_privacy_deadlines_ready then 'pass' else 'fail' end,
    concat(
      'Monitored privacy contact=',v_privacy_contact,
      '; all open privacy requests have explicit reviewed deadlines=',v_privacy_deadlines_ready,
      '. No jurisdiction-specific deadline is auto-invented by TrustRelay.'
    ),
    'Privacy deadlines must be assigned from an approved jurisdictional/legal policy.'
  );

  return private.trustrelay_platform_readiness_v10();
end;
$function$;

REVOKE ALL ON FUNCTION public.trustrelay_refresh_objective_readiness_v10() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.trustrelay_refresh_objective_readiness_v10() TO service_role;

