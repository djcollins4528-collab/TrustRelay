-- TrustRelay v1.4 — remove duplicate tenant-key unique index.
-- Keep the constraint-backed organization_scim_configs_tenant_key_key index.

drop index if exists public.organization_scim_configs_tenant_key_uq;
