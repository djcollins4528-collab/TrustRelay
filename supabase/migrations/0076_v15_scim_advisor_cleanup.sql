-- TrustRelay v1.5 SCIM advisor cleanup and production policy reconciliation.

drop index if exists public.organization_scim_groups_org_external_uq;
drop index if exists public.organization_scim_groups_org_name_uq;

create index if not exists organization_scim_configs_created_by_idx
  on public.organization_scim_configs(created_by_account_id);

drop policy if exists organization_scim_configs_deny_all on public.organization_scim_configs;
create policy organization_scim_configs_deny_all
  on public.organization_scim_configs for all to anon,authenticated
  using(false) with check(false);

drop policy if exists organization_scim_users_deny_all on public.organization_scim_users;
create policy organization_scim_users_deny_all
  on public.organization_scim_users for all to anon,authenticated
  using(false) with check(false);

drop policy if exists organization_scim_credentials_deny_direct on public.organization_scim_credentials;
drop policy if exists organization_scim_credentials_deny_all on public.organization_scim_credentials;
create policy organization_scim_credentials_deny_all
  on public.organization_scim_credentials for all to anon,authenticated
  using(false) with check(false);
