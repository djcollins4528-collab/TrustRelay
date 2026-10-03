-- TrustRelay v1.0 solo-operator production scope.
-- Manual identity proofing/review is fail-closed until real dual-control reviewers exist.

create table if not exists public.production_feature_flags (
  feature_key text primary key,
  enabled boolean not null default false,
  rationale text,
  updated_at text not null
);
alter table public.production_feature_flags enable row level security;
revoke all on public.production_feature_flags from anon,authenticated;

insert into public.production_feature_flags(feature_key,enabled,rationale,updated_at)
values(
  'manual_identity_review',
  false,
  'Disabled for solo-operator production scope. Re-enable only after two independent approved/trained reviewers exist.',
  to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
)
on conflict(feature_key) do update set
  enabled=false,
  rationale=excluded.rationale,
  updated_at=excluded.updated_at;

create or replace function public.trustrelay_feature_enabled_v10(p_feature_key text)
returns boolean
language sql
security definer
set search_path=public,pg_catalog
as $$
  select coalesce((select enabled from public.production_feature_flags where feature_key=p_feature_key),false);
$$;
revoke all on function public.trustrelay_feature_enabled_v10(text) from public,anon,authenticated;
grant execute on function public.trustrelay_feature_enabled_v10(text) to service_role;

do $$
begin
  if to_regprocedure('private.trustrelay_start_proofing_core_v08(uuid,text,text)') is null then
    alter function private.trustrelay_start_proofing_v08(uuid,text,text) rename to trustrelay_start_proofing_core_v08;
  end if;
  if to_regprocedure('private.trustrelay_submit_proofing_core_v08(uuid,text)') is null then
    alter function private.trustrelay_submit_proofing_v08(uuid,text) rename to trustrelay_submit_proofing_core_v08;
  end if;
  if to_regprocedure('private.trustrelay_reviewer_context_core_v08(uuid)') is null then
    alter function private.trustrelay_reviewer_context_v08(uuid) rename to trustrelay_reviewer_context_core_v08;
  end if;
end $$;

create or replace function private.trustrelay_start_proofing_v08(
  p_uid uuid,p_requested_assurance text,p_consent_version text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object(
      'ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED',
      'detail','Manual identity proofing is not enabled for the current production operating model.'
    );
  end if;
  return private.trustrelay_start_proofing_core_v08(p_uid,p_requested_assurance,p_consent_version);
end;
$$;

create or replace function private.trustrelay_submit_proofing_v08(
  p_uid uuid,p_session_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object('ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED');
  end if;
  return private.trustrelay_submit_proofing_core_v08(p_uid,p_session_id);
end;
$$;

create or replace function private.trustrelay_reviewer_context_v08(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object('ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED');
  end if;
  return private.trustrelay_reviewer_context_core_v08(p_uid);
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
  v_manual_review_enabled boolean;
  v_retention_total integer;
  v_retention_approved integer;
  v_retention_job boolean;
  v_recent_retention boolean;
  v_security_contact boolean;
  v_privacy_contact boolean;
  v_privacy_deadlines_ready boolean;
begin
  select public.trustrelay_feature_enabled_v10('manual_identity_review') into v_manual_review_enabled;

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
    case when not v_manual_review_enabled or v_reviewer_count>=2 then 'pass' else 'fail' end,
    case
      when not v_manual_review_enabled then
        'Manual identity proofing/review is disabled at the database boundary for the solo-operator production scope. Reviewer-only context, proofing start, and proofing submission fail closed with MANUAL_IDENTITY_REVIEW_DISABLED. No production reviewer workflow is active.'
      else
        'Approved, trained, unexpired dual-control reviewers: '||v_reviewer_count::text||'. Production requires at least two while manual identity review is enabled.'
    end,
    'If manual identity review is re-enabled, require at least two independent approved/trained/unexpired reviewers before production use.'
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
$$;

notify pgrst,'reload schema';
