-- TrustRelay v1.4 — SCIM policy/index cleanup.
-- Removes redundant deny policies and the duplicate username uniqueness index
-- reported by the database advisor. Security semantics are unchanged.

drop policy if exists organization_scim_configs_deny_direct
  on public.organization_scim_configs;

drop policy if exists organization_scim_users_deny_direct
  on public.organization_scim_users;

drop index if exists public.organization_scim_users_username_uq;
