-- TrustRelay live migration 20261002015449: trustrelay_v10_canonical_webhook_event_catalog
-- Restores the canonical current emitted webhook event catalog from the v0.9 release contract.

create or replace function public.trustrelay_webhook_event_catalog_v09()
returns jsonb
language sql
immutable
set search_path=pg_catalog
as $$
  select '[
    "decision.created",
    "grant.revoked",
    "credential.revoked",
    "evidence.requested",
    "evidence.submitted",
    "evidence.resolved",
    "organization.member.joined",
    "organization.member.role_changed",
    "organization.member.disabled",
    "compliance.export.ready",
    "webhook.test"
  ]'::jsonb;
$$;
