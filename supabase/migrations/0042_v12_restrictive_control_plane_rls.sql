-- TrustRelay v1.2 defense-in-depth RLS hardening
-- Control-plane deny policies must be restrictive so later permissive policies cannot bypass them.

drop policy if exists backup_recovery_keys_deny_clients on public.backup_recovery_keys;
create policy backup_recovery_keys_deny_clients on public.backup_recovery_keys
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists backup_restore_tests_deny_clients on public.backup_restore_tests;
create policy backup_restore_tests_deny_clients on public.backup_restore_tests
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists backup_runs_deny_clients on public.backup_runs;
create policy backup_runs_deny_clients on public.backup_runs
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists backup_source_signing_keys_deny_clients on public.backup_source_signing_keys;
create policy backup_source_signing_keys_deny_clients on public.backup_source_signing_keys
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists disaster_recovery_objects_deny_clients on public.disaster_recovery_objects;
create policy disaster_recovery_objects_deny_clients on public.disaster_recovery_objects
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists disaster_recovery_runs_deny_clients on public.disaster_recovery_runs;
create policy disaster_recovery_runs_deny_clients on public.disaster_recovery_runs
as restrictive for all to anon,authenticated using(false) with check(false);

drop policy if exists production_feature_flags_deny_clients on public.production_feature_flags;
create policy production_feature_flags_deny_clients on public.production_feature_flags
as restrictive for all to anon,authenticated using(false) with check(false);

revoke all privileges on table
  public.backup_recovery_keys,
  public.backup_restore_tests,
  public.backup_runs,
  public.backup_source_signing_keys,
  public.disaster_recovery_objects,
  public.disaster_recovery_runs,
  public.production_feature_flags
from anon,authenticated;

grant all privileges on table
  public.backup_recovery_keys,
  public.backup_restore_tests,
  public.backup_runs,
  public.backup_source_signing_keys,
  public.disaster_recovery_objects,
  public.disaster_recovery_runs,
  public.production_feature_flags
to service_role;

notify pgrst,'reload schema';
