-- TrustRelay v1.0 explicit deny policies for control-plane tables.
drop policy if exists "backup_recovery_keys_deny_clients" on public.backup_recovery_keys;
create policy "backup_recovery_keys_deny_clients" on public.backup_recovery_keys
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "backup_restore_tests_deny_clients" on public.backup_restore_tests;
create policy "backup_restore_tests_deny_clients" on public.backup_restore_tests
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "backup_runs_deny_clients" on public.backup_runs;
create policy "backup_runs_deny_clients" on public.backup_runs
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "backup_source_signing_keys_deny_clients" on public.backup_source_signing_keys;
create policy "backup_source_signing_keys_deny_clients" on public.backup_source_signing_keys
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "disaster_recovery_objects_deny_clients" on public.disaster_recovery_objects;
create policy "disaster_recovery_objects_deny_clients" on public.disaster_recovery_objects
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "disaster_recovery_runs_deny_clients" on public.disaster_recovery_runs;
create policy "disaster_recovery_runs_deny_clients" on public.disaster_recovery_runs
for all to anon, authenticated
using (false)
with check (false);

drop policy if exists "production_feature_flags_deny_clients" on public.production_feature_flags;
create policy "production_feature_flags_deny_clients" on public.production_feature_flags
for all to anon, authenticated
using (false)
with check (false);
