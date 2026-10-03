-- TrustRelay v1.2 one-time capability defense in depth.
-- The service-role-only capability table also gets RLS and structural constraints.

alter table private.trustrelay_internal_capabilities_v12 enable row level security;
alter table private.trustrelay_internal_capabilities_v12 force row level security;

drop policy if exists trustrelay_internal_capabilities_deny_clients_v12
  on private.trustrelay_internal_capabilities_v12;
create policy trustrelay_internal_capabilities_deny_clients_v12
  on private.trustrelay_internal_capabilities_v12
  as restrictive for all to anon,authenticated
  using (false) with check (false);

revoke all on table private.trustrelay_internal_capabilities_v12
from public,anon,authenticated;
grant select,insert,update,delete on table private.trustrelay_internal_capabilities_v12
to service_role;

alter table private.trustrelay_internal_capabilities_v12
  drop constraint if exists trustrelay_internal_capabilities_id_format_v12,
  drop constraint if exists trustrelay_internal_capabilities_token_hash_format_v12,
  drop constraint if exists trustrelay_internal_capabilities_body_hash_format_v12,
  drop constraint if exists trustrelay_internal_capabilities_purpose_v12,
  drop constraint if exists trustrelay_internal_capabilities_ttl_v12,
  drop constraint if exists trustrelay_internal_capabilities_consumed_time_v12;

alter table private.trustrelay_internal_capabilities_v12
  add constraint trustrelay_internal_capabilities_id_format_v12
    check (id ~ '^icap_[0-9a-f]{32}$') not valid,
  add constraint trustrelay_internal_capabilities_token_hash_format_v12
    check (token_hash ~ '^[0-9a-f]{64}$') not valid,
  add constraint trustrelay_internal_capabilities_body_hash_format_v12
    check (body_sha256 ~ '^[0-9a-f]{64}$') not valid,
  add constraint trustrelay_internal_capabilities_purpose_v12
    check (purpose='portal.decisions.evaluate') not valid,
  add constraint trustrelay_internal_capabilities_ttl_v12
    check (expires_at=created_at+interval '30 seconds') not valid,
  add constraint trustrelay_internal_capabilities_consumed_time_v12
    check (consumed_at is null or (consumed_at>=created_at and consumed_at<=expires_at)) not valid;

alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_id_format_v12;
alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_token_hash_format_v12;
alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_body_hash_format_v12;
alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_purpose_v12;
alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_ttl_v12;
alter table private.trustrelay_internal_capabilities_v12 validate constraint trustrelay_internal_capabilities_consumed_time_v12;

create index if not exists trustrelay_internal_capabilities_unconsumed_expiry_v12
  on private.trustrelay_internal_capabilities_v12(expires_at)
  where consumed_at is null;

alter default privileges in schema private revoke all on tables from public,anon,authenticated;
alter default privileges in schema private grant all on tables to service_role;

notify pgrst,'reload schema';
