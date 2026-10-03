-- TrustRelay v1.0 retention dry-run candidate accounting.
-- This migration does not enable or perform deletion.

create or replace function public.trustrelay_retention_dry_run_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,extensions,pg_catalog
as $$
declare
  v_now_ts timestamptz:=clock_timestamp();
  v_now text:=to_char(v_now_ts at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_id text:='retention_'||replace(gen_random_uuid()::text,'-','');
  v_policies jsonb;
  v_counts jsonb:='{}'::jsonb;
  v_hash text;
  p record;
  c jsonb;
  cutoff timestamptz;
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

  for p in
    select * from public.retention_policies order by record_class
  loop
    if p.retention_days is null then
      c:=jsonb_build_object('eligible',false,'reason','RETENTION_DAYS_NOT_SET');
    else
      cutoff:=v_now_ts-make_interval(days=>p.retention_days);

      case p.record_class
        when 'authorization_decisions_and_org_audit' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'authorizationDecisions',(
              select count(*) from public.authorization_decisions
              where nullif(decided_at,'') is not null and decided_at::timestamptz<cutoff
            ),
            'organizationAuditEvents',(
              select count(*) from public.organization_audit_events
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            ),
            'auditEvents',(
              select count(*) from public.audit_events
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            )
          );

        when 'credential_and_grant_revocations' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'revokedCredentials',(
              select count(*) from public.credentials
              where nullif(revoked_at,'') is not null and revoked_at::timestamptz<cutoff
            ),
            'revokedGrants',(
              select count(*) from public.authority_grants
              where nullif(revoked_at,'') is not null and revoked_at::timestamptz<cutoff
            )
          );

        when 'webhook_delivery_metadata' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'deliveries',(
              select count(*) from public.webhook_deliveries
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            ),
            'deliveryAttempts',(
              select count(*) from public.webhook_delivery_attempts
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            )
          );

        when 'compliance_export_objects' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'storageObjects',(
              select count(*) from public.compliance_exports
              where storage_key is not null
                and nullif(coalesce(completed_at,created_at),'') is not null
                and coalesce(completed_at,created_at)::timestamptz<cutoff
            )
          );

        when 'compliance_export_metadata_hashes' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'exportMetadataRows',(
              select count(*) from public.compliance_exports
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            )
          );

        when 'in_app_notifications' then
          c:=jsonb_build_object(
            'eligible',p.status='approved' and p.execution_enabled,
            'cutoff',cutoff,
            'notifications',(
              select count(*) from public.notifications
              where nullif(created_at,'') is not null and created_at::timestamptz<cutoff
            )
          );

        else
          c:=jsonb_build_object('eligible',false,'reason','UNMAPPED_RECORD_CLASS');
      end case;

      c:=c||jsonb_build_object(
        'status',p.status,
        'executionEnabled',p.execution_enabled,
        'manualApprovalRequired',p.deletion_requires_manual_approval,
        'retentionDays',p.retention_days
      );
    end if;

    v_counts:=v_counts||jsonb_build_object(p.record_class,c);
  end loop;

  v_counts:=v_counts||jsonb_build_object(
    '_summary',jsonb_build_object(
      'totalPolicies',(select count(*) from public.retention_policies),
      'approvedPolicies',(select count(*) from public.retention_policies where status='approved' and retention_days is not null),
      'draftPolicies',(select count(*) from public.retention_policies where status='draft'),
      'executionEnabledPolicies',(select count(*) from public.retention_policies where execution_enabled=true),
      'candidateDeletionExecuted',false
    )
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

revoke all on function public.trustrelay_retention_dry_run_v10() from public,anon,authenticated;
grant execute on function public.trustrelay_retention_dry_run_v10() to service_role;

notify pgrst,'reload schema';
