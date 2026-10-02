-- TrustRelay v1.0 draft retention policy seed.
-- These rows mirror the existing legal/retention.html proposal.
-- They are intentionally NOT approved and destructive execution remains disabled.

insert into public.retention_policies(
  record_class,retention_days,action,status,legal_basis_note,
  approved_by_account_id,approved_at,created_at,updated_at,
  execution_enabled,deletion_requires_manual_approval
) values
  ('authorization_decisions_and_org_audit',2555,'delete','draft',
   'Proposed 7-year retention from legal/retention.html. Requires qualified legal/business approval before activation.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true),
  ('credential_and_grant_revocations',2555,'delete','draft',
   'Proposed 7-year retention from legal/retention.html. Requires qualified legal/business approval before activation.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true),
  ('webhook_delivery_metadata',365,'delete','draft',
   'Proposed 1-year retention from legal/retention.html. Response-body excerpts should be minimized and may require shorter treatment.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true),
  ('compliance_export_objects',7,'delete','draft',
   'Proposed 7-day object retention from legal/retention.html. Requires approval before activation.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true),
  ('compliance_export_metadata_hashes',2555,'delete','draft',
   'Proposed 7-year metadata/hash retention from legal/retention.html. Requires approval before activation.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true),
  ('in_app_notifications',365,'delete','draft',
   'Proposed 1-year-or-earlier retention from legal/retention.html. Requires approval before activation.',
   null,null,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
   to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),false,true)
on conflict(record_class) do nothing;

select public.trustrelay_retention_dry_run_v10();
select public.trustrelay_refresh_objective_readiness_v10();
