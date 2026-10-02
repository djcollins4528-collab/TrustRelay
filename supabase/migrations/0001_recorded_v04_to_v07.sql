-- TrustRelay migration history exported verbatim from Supabase on 2026-10-01.
-- Apply in listed order to an empty compatible Supabase project.

-- ============================================================
-- 20260930134539 trustrelay_v04_core
-- ============================================================
CREATE TABLE IF NOT EXISTS persons (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  email TEXT UNIQUE,
  identity_status TEXT NOT NULL DEFAULT 'unverified',
  identity_verified_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT NOT NULL DEFAULT '[]',
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  account_id TEXT,
  challenge TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  session_type TEXT NOT NULL DEFAULT 'standard',
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_proofing_sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_reference TEXT,
  status TEXT NOT NULL,
  assurance_level TEXT,
  redirect_url TEXT,
  result_json TEXT NOT NULL DEFAULT '{}',
  expires_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL DEFAULT 'sandbox',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organization_members (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (organization_id, account_id)
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes_json TEXT NOT NULL,
  revoked_at TEXT,
  last_used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_grants (
  id TEXT PRIMARY KEY,
  principal_person_id TEXT NOT NULL REFERENCES persons(id),
  representative_person_id TEXT NOT NULL REFERENCES persons(id),
  status TEXT NOT NULL DEFAULT 'active',
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  allowed_json TEXT NOT NULL,
  prohibited_json TEXT NOT NULL,
  rules_json TEXT NOT NULL,
  resources_json TEXT NOT NULL,
  escalation_json TEXT NOT NULL,
  created_by_account_id TEXT REFERENCES accounts(id),
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_person_id TEXT NOT NULL REFERENCES persons(id),
  document_type TEXT NOT NULL,
  display_name TEXT NOT NULL,
  storage_key TEXT NOT NULL UNIQUE,
  encryption_provider TEXT NOT NULL,
  encryption_iv TEXT,
  encryption_tag TEXT,
  wrapped_key TEXT,
  content_sha256 TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  scan_status TEXT NOT NULL DEFAULT 'pending',
  scan_result_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grant_evidence (
  grant_id TEXT NOT NULL REFERENCES authority_grants(id) ON DELETE CASCADE,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  PRIMARY KEY (grant_id, document_id)
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES authority_grants(id),
  jti TEXT NOT NULL UNIQUE,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  token TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS revocations (
  jti TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES credentials(id),
  reason TEXT NOT NULL,
  revoked_by_account_id TEXT REFERENCES accounts(id),
  revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_requests (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  proofing_session_id TEXT REFERENCES identity_proofing_sessions(id),
  initiated_at TEXT NOT NULL,
  cooldown_until TEXT,
  completed_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_events (
  provider TEXT NOT NULL,
  event_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  processed_at TEXT,
  payload_hash TEXT NOT NULL,
  PRIMARY KEY(provider,event_id)
);
CREATE TABLE IF NOT EXISTS audit_archives (
  event_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  storage_key TEXT,
  retain_until TEXT,
  mode TEXT,
  error TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  metadata_json TEXT NOT NULL,
  prev_hash TEXT,
  event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE SCHEMA IF NOT EXISTS trustrelay_internal;
CREATE OR REPLACE FUNCTION trustrelay_internal.audit_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_events are append-only'; END; $$ LANGUAGE plpgsql;
REVOKE ALL ON FUNCTION trustrelay_internal.audit_immutable() FROM PUBLIC;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION trustrelay_internal.audit_immutable();
DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION trustrelay_internal.audit_immutable();

CREATE INDEX IF NOT EXISTS idx_grants_principal ON authority_grants(principal_person_id);
CREATE INDEX IF NOT EXISTS idx_grants_representative ON authority_grants(representative_person_id);
CREATE INDEX IF NOT EXISTS idx_credentials_grant ON credentials(grant_id);
CREATE INDEX IF NOT EXISTS idx_identity_account ON identity_proofing_sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_recovery_account ON recovery_requests(account_id);

ALTER TABLE public.persons ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.persons FROM anon, authenticated;
ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.accounts FROM anon, authenticated;
ALTER TABLE public.passkeys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.passkeys FROM anon, authenticated;
ALTER TABLE public.challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.challenges FROM anon, authenticated;
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.sessions FROM anon, authenticated;
ALTER TABLE public.identity_proofing_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.identity_proofing_sessions FROM anon, authenticated;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.organizations FROM anon, authenticated;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.organization_members FROM anon, authenticated;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.api_keys FROM anon, authenticated;
ALTER TABLE public.authority_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.authority_grants FROM anon, authenticated;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.documents FROM anon, authenticated;
ALTER TABLE public.grant_evidence ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.grant_evidence FROM anon, authenticated;
ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.credentials FROM anon, authenticated;
ALTER TABLE public.revocations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.revocations FROM anon, authenticated;
ALTER TABLE public.recovery_codes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.recovery_codes FROM anon, authenticated;
ALTER TABLE public.recovery_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.recovery_requests FROM anon, authenticated;
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.rate_limits FROM anon, authenticated;
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.webhook_events FROM anon, authenticated;
ALTER TABLE public.audit_archives ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.audit_archives FROM anon, authenticated;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.audit_events FROM anon, authenticated;
REVOKE ALL ON SEQUENCE public.audit_events_id_seq FROM anon, authenticated;

-- ============================================================
-- 20260930134630 trustrelay_v04_supabase_hardening
-- ============================================================
CREATE OR REPLACE FUNCTION trustrelay_internal.audit_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events are append-only';
END;
$$;
REVOKE ALL ON FUNCTION trustrelay_internal.audit_immutable() FROM PUBLIC;

CREATE INDEX IF NOT EXISTS idx_accounts_person ON public.accounts(person_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON public.api_keys(organization_id);
CREATE INDEX IF NOT EXISTS idx_grants_created_by ON public.authority_grants(created_by_account_id);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON public.documents(owner_person_id);
CREATE INDEX IF NOT EXISTS idx_grant_evidence_document ON public.grant_evidence(document_id);
CREATE INDEX IF NOT EXISTS idx_org_members_account ON public.organization_members(account_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_account ON public.passkeys(account_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_account ON public.recovery_codes(account_id);
CREATE INDEX IF NOT EXISTS idx_recovery_requests_proofing ON public.recovery_requests(proofing_session_id);
CREATE INDEX IF NOT EXISTS idx_revocations_credential ON public.revocations(credential_id);
CREATE INDEX IF NOT EXISTS idx_revocations_account ON public.revocations(revoked_by_account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON public.sessions(account_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'persons','accounts','passkeys','challenges','sessions','identity_proofing_sessions',
    'organizations','organization_members','api_keys','authority_grants','documents','grant_evidence',
    'credentials','revocations','recovery_codes','recovery_requests','rate_limits','webhook_events',
    'audit_archives','audit_events'
  ]
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS trustrelay_deny_clients ON public.%I', t);
    EXECUTE format('CREATE POLICY trustrelay_deny_clients ON public.%I AS RESTRICTIVE FOR ALL TO anon, authenticated USING (false) WITH CHECK (false)', t);
  END LOOP;
END $$;

-- ============================================================
-- 20260930142220 trustrelay_v041_free_pilot_database_evidence
-- ============================================================
CREATE TABLE IF NOT EXISTS public.pilot_evidence_blobs (
  storage_key TEXT PRIMARY KEY,
  ciphertext_base64 TEXT NOT NULL,
  created_at TEXT NOT NULL
);
ALTER TABLE public.pilot_evidence_blobs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.pilot_evidence_blobs FROM anon, authenticated;
DROP POLICY IF EXISTS trustrelay_deny_clients ON public.pilot_evidence_blobs;
CREATE POLICY trustrelay_deny_clients
ON public.pilot_evidence_blobs
AS RESTRICTIVE
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- ============================================================
-- 20260930143854 trustrelay_v042_authorization_decision_evidence
-- ============================================================
create table public.authorization_decisions (
  id text primary key,
  request_id text not null unique,
  correlation_id text,
  grant_id text references public.authority_grants(id) on delete set null,
  credential_jti text references public.credentials(jti) on delete set null,
  principal_person_id text references public.persons(id) on delete set null,
  representative_person_id text references public.persons(id) on delete set null,
  action text not null,
  resource text not null,
  decision text not null,
  reason_code text not null,
  reason_detail text,
  policy_version text not null default 'v0.4.2',
  engine_version text not null default 'v0.4.2',
  request_json text not null default '{}',
  policy_snapshot_json text not null default '{}',
  evidence_json text not null default '{}',
  evaluation_hash text not null,
  audit_event_id text references public.audit_events(event_id) on delete set null,
  decided_at text not null,
  constraint authorization_decisions_decision_check
    check (decision in ('ALLOW','DENY','ESCALATE')),
  constraint authorization_decisions_action_nonempty
    check (length(btrim(action)) > 0),
  constraint authorization_decisions_resource_nonempty
    check (length(btrim(resource)) > 0),
  constraint authorization_decisions_reason_nonempty
    check (length(btrim(reason_code)) > 0),
  constraint authorization_decisions_hash_nonempty
    check (length(btrim(evaluation_hash)) > 0)
);

create index idx_authorization_decisions_grant
  on public.authorization_decisions(grant_id);

create index idx_authorization_decisions_credential_jti
  on public.authorization_decisions(credential_jti);

create index idx_authorization_decisions_principal
  on public.authorization_decisions(principal_person_id);

create index idx_authorization_decisions_representative
  on public.authorization_decisions(representative_person_id);

create index idx_authorization_decisions_decided_at
  on public.authorization_decisions(decided_at);

create index idx_authorization_decisions_outcome
  on public.authorization_decisions(decision, action);

alter table public.authorization_decisions enable row level security;

create policy trustrelay_deny_clients
on public.authorization_decisions
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

revoke all on table public.authorization_decisions from anon, authenticated;
grant select, insert on table public.authorization_decisions to service_role;

comment on table public.authorization_decisions is
  'Append-oriented evidence ledger for TrustRelay runtime authorization evaluations.';

comment on column public.authorization_decisions.policy_snapshot_json is
  'Exact policy/grant material evaluated for the request, serialized by the trusted backend.';

comment on column public.authorization_decisions.evaluation_hash is
  'Backend-computed digest binding request, evaluated policy, decision, and reason.';

-- ============================================================
-- 20260930143923 trustrelay_v042_decision_evidence_hardening
-- ============================================================
revoke update, delete, truncate, references, trigger
on table public.authorization_decisions
from service_role;

grant select, insert
on table public.authorization_decisions
to service_role;

create index idx_authorization_decisions_audit_event
  on public.authorization_decisions(audit_event_id);

-- ============================================================
-- 20260930144713 trustrelay_v05_decision_engine_foundation
-- ============================================================
alter table public.authorization_decisions
  add column organization_id text references public.organizations(id) on delete set null,
  add column api_key_id text references public.api_keys(id) on delete set null,
  add column request_fingerprint text,
  add column latency_ms integer;

create index idx_authorization_decisions_organization
  on public.authorization_decisions(organization_id);

create index idx_authorization_decisions_api_key
  on public.authorization_decisions(api_key_id);

create index idx_authorization_decisions_fingerprint
  on public.authorization_decisions(request_fingerprint);

create unique index uq_authorization_decisions_org_request
  on public.authorization_decisions(organization_id, request_id)
  where organization_id is not null;

alter table public.authorization_decisions
  add constraint authorization_decisions_latency_nonnegative
  check (latency_ms is null or latency_ms >= 0);

revoke update, delete, truncate, references, trigger
on table public.audit_events
from service_role;

grant select, insert
on table public.audit_events
to service_role;

create or replace function public.record_authorization_decision_v05(
  p_id text,
  p_request_id text,
  p_correlation_id text,
  p_organization_id text,
  p_api_key_id text,
  p_grant_id text,
  p_credential_jti text,
  p_principal_person_id text,
  p_representative_person_id text,
  p_action text,
  p_resource text,
  p_decision text,
  p_reason_code text,
  p_reason_detail text,
  p_policy_version text,
  p_engine_version text,
  p_request_json text,
  p_policy_snapshot_json text,
  p_evidence_json text,
  p_request_fingerprint text,
  p_latency_ms integer,
  p_decided_at text
)
returns table (
  decision_id text,
  audit_event_id text,
  evaluation_hash text,
  audit_event_hash text
)
language plpgsql
security definer
set search_path = public, extensions, pg_catalog
as $$
declare
  v_existing public.authorization_decisions%rowtype;
  v_prev_hash text;
  v_event_id text;
  v_event_hash text;
  v_eval_hash text;
begin
  if p_decision not in ('ALLOW','DENY','ESCALATE') then
    raise exception 'invalid decision';
  end if;

  if p_latency_ms is not null and p_latency_ms < 0 then
    raise exception 'invalid latency';
  end if;

  select *
    into v_existing
  from public.authorization_decisions
  where request_id = p_request_id
    and (
      (p_organization_id is null and organization_id is null)
      or organization_id = p_organization_id
    )
  order by decided_at desc
  limit 1;

  if found then
    return query
    select
      v_existing.id,
      v_existing.audit_event_id,
      v_existing.evaluation_hash,
      ae.event_hash
    from public.audit_events ae
    where ae.event_id = v_existing.audit_event_id;
    return;
  end if;

  perform pg_advisory_xact_lock(hashtext('trustrelay:audit-chain:v1'));

  select event_hash
    into v_prev_hash
  from public.audit_events
  order by id desc
  limit 1;

  v_event_id := 'evt_' || replace(gen_random_uuid()::text, '-', '');

  v_eval_hash := encode(
    digest(
      coalesce(p_request_fingerprint,'') || '|' ||
      coalesce(p_grant_id,'') || '|' ||
      coalesce(p_credential_jti,'') || '|' ||
      coalesce(p_principal_person_id,'') || '|' ||
      coalesce(p_representative_person_id,'') || '|' ||
      coalesce(p_action,'') || '|' ||
      coalesce(p_resource,'') || '|' ||
      coalesce(p_decision,'') || '|' ||
      coalesce(p_reason_code,'') || '|' ||
      coalesce(p_policy_snapshot_json,'{}') || '|' ||
      coalesce(p_evidence_json,'{}') || '|' ||
      coalesce(p_decided_at,''),
      'sha256'
    ),
    'hex'
  );

  v_event_hash := encode(
    digest(
      coalesce(v_prev_hash,'') || '|' ||
      v_event_id || '|' ||
      coalesce(p_organization_id,'') || '|' ||
      coalesce(p_api_key_id,'') || '|' ||
      p_request_id || '|' ||
      p_decision || '|' ||
      p_reason_code || '|' ||
      v_eval_hash || '|' ||
      p_decided_at,
      'sha256'
    ),
    'hex'
  );

  insert into public.audit_events (
    event_id,
    actor_type,
    actor_id,
    action,
    target_type,
    target_id,
    metadata_json,
    prev_hash,
    event_hash,
    created_at
  ) values (
    v_event_id,
    case when p_api_key_id is null then 'system' else 'api_key' end,
    coalesce(p_api_key_id, p_engine_version),
    'authorization_decision',
    'authorization_request',
    p_request_id,
    jsonb_build_object(
      'organization_id', p_organization_id,
      'decision', p_decision,
      'reason_code', p_reason_code,
      'evaluation_hash', v_eval_hash,
      'policy_version', p_policy_version,
      'engine_version', p_engine_version
    )::text,
    v_prev_hash,
    v_event_hash,
    p_decided_at
  );

  insert into public.authorization_decisions (
    id,
    request_id,
    correlation_id,
    organization_id,
    api_key_id,
    grant_id,
    credential_jti,
    principal_person_id,
    representative_person_id,
    action,
    resource,
    decision,
    reason_code,
    reason_detail,
    policy_version,
    engine_version,
    request_json,
    policy_snapshot_json,
    evidence_json,
    request_fingerprint,
    latency_ms,
    evaluation_hash,
    audit_event_id,
    decided_at
  ) values (
    p_id,
    p_request_id,
    p_correlation_id,
    p_organization_id,
    p_api_key_id,
    p_grant_id,
    p_credential_jti,
    p_principal_person_id,
    p_representative_person_id,
    p_action,
    p_resource,
    p_decision,
    p_reason_code,
    p_reason_detail,
    p_policy_version,
    p_engine_version,
    p_request_json,
    p_policy_snapshot_json,
    p_evidence_json,
    p_request_fingerprint,
    p_latency_ms,
    v_eval_hash,
    v_event_id,
    p_decided_at
  );

  return query
  select p_id, v_event_id, v_eval_hash, v_event_hash;
end;
$$;

revoke all on function public.record_authorization_decision_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
) from public, anon, authenticated;

grant execute on function public.record_authorization_decision_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
) to service_role;

comment on function public.record_authorization_decision_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
) is 'TrustRelay v0.5 atomic idempotent authorization-decision and audit-chain recorder.';

-- ============================================================
-- 20260930144834 trustrelay_v05_rate_limit_rpc
-- ============================================================
create or replace function public.consume_rate_limit_v05(
  p_bucket_key text,
  p_limit integer,
  p_window_seconds integer default 60
)
returns table (
  allowed boolean,
  remaining integer,
  reset_at bigint
)
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_now bigint := floor(extract(epoch from clock_timestamp()))::bigint;
  v_window_start bigint;
  v_count integer;
begin
  if p_limit <= 0 or p_window_seconds <= 0 then
    raise exception 'invalid rate limit configuration';
  end if;

  v_window_start := (v_now / p_window_seconds) * p_window_seconds;

  perform pg_advisory_xact_lock(hashtext('trustrelay:rate:' || p_bucket_key));

  insert into public.rate_limits(bucket_key, window_start, count, updated_at)
  values (p_bucket_key, v_window_start::integer, 1, to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  on conflict (bucket_key) do update
    set count = case
          when public.rate_limits.window_start = excluded.window_start
            then public.rate_limits.count + 1
          else 1
        end,
        window_start = excluded.window_start,
        updated_at = excluded.updated_at
  returning count into v_count;

  return query
  select
    (v_count <= p_limit),
    greatest(p_limit - v_count, 0),
    (v_window_start + p_window_seconds);
end;
$$;

revoke all on function public.consume_rate_limit_v05(text,integer,integer)
from public, anon, authenticated;

grant execute on function public.consume_rate_limit_v05(text,integer,integer)
to service_role;

comment on function public.consume_rate_limit_v05(text,integer,integer)
is 'TrustRelay v0.5 atomic fixed-window API rate limiter for trusted backend use.';

-- ============================================================
-- 20260930145402 trustrelay_v05_tenant_scoped_idempotency
-- ============================================================
alter table public.authorization_decisions
  drop constraint if exists authorization_decisions_request_id_key;

create unique index if not exists uq_authorization_decisions_legacy_request
  on public.authorization_decisions(request_id)
  where organization_id is null;

comment on index public.uq_authorization_decisions_org_request is
  'v0.5 idempotency boundary: request IDs are unique within an organization.';

comment on index public.uq_authorization_decisions_legacy_request is
  'Preserves uniqueness for pre-v0.5/system decisions that have no organization.';

-- ============================================================
-- 20260930151245 trustrelay_v05_partner_rpc_gateway
-- ============================================================
create or replace function public.trustrelay_health_v05()
returns jsonb
language sql
security definer
set search_path = public, pg_catalog
as $$
  select jsonb_build_object('status','ok','service','trustrelay-supabase','version','v0.5');
$$;

revoke all on function public.trustrelay_health_v05() from public, authenticated;
grant execute on function public.trustrelay_health_v05() to anon;

create or replace function public.trustrelay_prepare_decision_v05(
  p_api_key text,
  p_request_id text,
  p_request_fingerprint text,
  p_grant_id text default null,
  p_credential_jti text default null,
  p_principal_person_id text default null,
  p_representative_person_id text default null,
  p_rate_limit integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_catalog
as $$
declare
  v_key public.api_keys%rowtype;
  v_org public.organizations%rowtype;
  v_grant public.authority_grants%rowtype;
  v_explicit_grant public.authority_grants%rowtype;
  v_credential public.credentials%rowtype;
  v_principal public.persons%rowtype;
  v_representative public.persons%rowtype;
  v_revocation public.revocations%rowtype;
  v_prior public.authorization_decisions%rowtype;
  v_rate record;
  v_hash text;
  v_scopes jsonb;
  v_principal_id text;
  v_representative_id text;
begin
  if p_api_key is null or length(p_api_key) < 24 or length(p_api_key) > 512 then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid.');
  end if;

  v_hash := encode(digest(p_api_key,'sha256'),'hex');

  select * into v_key
  from public.api_keys
  where key_hash = v_hash and revoked_at is null
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid or revoked.');
  end if;

  select * into v_org
  from public.organizations
  where id = v_key.organization_id
  limit 1;

  if not found or v_org.status <> 'active' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE','message','The organization is not active.');
  end if;

  begin
    v_scopes := coalesce(v_key.scopes_json::jsonb, '[]'::jsonb);
  exception when others then
    v_scopes := '[]'::jsonb;
  end;

  if not (v_scopes ? '*' or v_scopes ? 'decisions:write') then
    return jsonb_build_object('ok',false,'status',403,'code','INSUFFICIENT_SCOPE','message','API key is missing scope: decisions:write');
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05('api:' || v_key.id, p_rate_limit, 60);

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','RATE_LIMITED',
      'message','Too many requests. Retry after the current rate-limit window resets.',
      'resetAt',v_rate.reset_at
    );
  end if;

  update public.api_keys
  set last_used_at = to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  where id = v_key.id;

  select * into v_prior
  from public.authorization_decisions
  where organization_id = v_org.id and request_id = p_request_id
  limit 1;

  if found then
    return jsonb_build_object(
      'ok',true,
      'organization',jsonb_build_object('id',v_org.id,'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'status',v_org.status),
      'apiKey',jsonb_build_object('id',v_key.id,'name',v_key.name,'prefix',v_key.prefix),
      'rate',jsonb_build_object('remaining',v_rate.remaining,'resetAt',v_rate.reset_at),
      'prior',to_jsonb(v_prior)
    );
  end if;

  if p_credential_jti is not null then
    select * into v_credential
    from public.credentials
    where jti = p_credential_jti
    limit 1;

    if found then
      select * into v_grant
      from public.authority_grants
      where id = v_credential.grant_id
      limit 1;
    end if;
  end if;

  if p_grant_id is not null then
    select * into v_explicit_grant
    from public.authority_grants
    where id = p_grant_id
    limit 1;

    if v_grant.id is not null and v_explicit_grant.id is not null and v_grant.id <> v_explicit_grant.id then
      return jsonb_build_object(
        'ok',false,'status',400,'code','AUTHORITY_REFERENCE_MISMATCH',
        'message','grantId and credentialJti refer to different authority grants.'
      );
    end if;

    if v_explicit_grant.id is not null then
      v_grant := v_explicit_grant;
    end if;
  end if;

  if v_credential.id is null and v_grant.id is not null then
    select * into v_credential
    from public.credentials
    where grant_id = v_grant.id
    order by issued_at desc
    limit 1;
  end if;

  v_principal_id := coalesce(v_grant.principal_person_id, p_principal_person_id);
  v_representative_id := coalesce(v_grant.representative_person_id, p_representative_person_id);

  if v_principal_id is not null then
    select * into v_principal from public.persons where id = v_principal_id limit 1;
  end if;

  if v_representative_id is not null then
    select * into v_representative from public.persons where id = v_representative_id limit 1;
  end if;

  if v_credential.jti is not null then
    select * into v_revocation from public.revocations where jti = v_credential.jti limit 1;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',jsonb_build_object('id',v_org.id,'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'status',v_org.status),
    'apiKey',jsonb_build_object('id',v_key.id,'name',v_key.name,'prefix',v_key.prefix),
    'rate',jsonb_build_object('remaining',v_rate.remaining,'resetAt',v_rate.reset_at),
    'grant',case when v_grant.id is null then null else to_jsonb(v_grant) end,
    'credential',case when v_credential.id is null then null else to_jsonb(v_credential) end,
    'principal',case when v_principal.id is null then null else to_jsonb(v_principal) end,
    'representative',case when v_representative.id is null then null else to_jsonb(v_representative) end,
    'revocation',case when v_revocation.jti is null then null else to_jsonb(v_revocation) end
  );
end;
$$;

revoke all on function public.trustrelay_prepare_decision_v05(text,text,text,text,text,text,text,integer)
from public, authenticated;
grant execute on function public.trustrelay_prepare_decision_v05(text,text,text,text,text,text,text,integer)
to anon;

create or replace function public.trustrelay_record_decision_partner_v05(
  p_api_key text,
  p_id text,
  p_request_id text,
  p_correlation_id text,
  p_grant_id text,
  p_credential_jti text,
  p_principal_person_id text,
  p_representative_person_id text,
  p_action text,
  p_resource text,
  p_decision text,
  p_reason_code text,
  p_reason_detail text,
  p_policy_version text,
  p_engine_version text,
  p_request_json text,
  p_policy_snapshot_json text,
  p_evidence_json text,
  p_request_fingerprint text,
  p_latency_ms integer,
  p_decided_at text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_catalog
as $$
declare
  v_key public.api_keys%rowtype;
  v_org public.organizations%rowtype;
  v_hash text;
  v_scopes jsonb;
  v_record record;
begin
  if p_api_key is null or length(p_api_key) < 24 or length(p_api_key) > 512 then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid.');
  end if;

  v_hash := encode(digest(p_api_key,'sha256'),'hex');

  select * into v_key
  from public.api_keys
  where key_hash = v_hash and revoked_at is null
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid or revoked.');
  end if;

  select * into v_org from public.organizations where id = v_key.organization_id limit 1;
  if not found or v_org.status <> 'active' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE','message','The organization is not active.');
  end if;

  begin
    v_scopes := coalesce(v_key.scopes_json::jsonb, '[]'::jsonb);
  exception when others then
    v_scopes := '[]'::jsonb;
  end;

  if not (v_scopes ? '*' or v_scopes ? 'decisions:write') then
    return jsonb_build_object('ok',false,'status',403,'code','INSUFFICIENT_SCOPE','message','API key is missing scope: decisions:write');
  end if;

  select * into v_record
  from public.record_authorization_decision_v05(
    p_id,p_request_id,p_correlation_id,v_org.id,v_key.id,p_grant_id,p_credential_jti,
    p_principal_person_id,p_representative_person_id,p_action,p_resource,p_decision,p_reason_code,
    p_reason_detail,p_policy_version,p_engine_version,p_request_json,p_policy_snapshot_json,
    p_evidence_json,p_request_fingerprint,p_latency_ms,p_decided_at
  );

  return jsonb_build_object(
    'ok',true,
    'decision_id',v_record.decision_id,
    'audit_event_id',v_record.audit_event_id,
    'evaluation_hash',v_record.evaluation_hash,
    'audit_event_hash',v_record.audit_event_hash
  );
end;
$$;

revoke all on function public.trustrelay_record_decision_partner_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
) from public, authenticated;
grant execute on function public.trustrelay_record_decision_partner_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
) to anon;

create or replace function public.trustrelay_get_decision_partner_v05(
  p_api_key text,
  p_request_id text,
  p_rate_limit integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_catalog
as $$
declare
  v_key public.api_keys%rowtype;
  v_org public.organizations%rowtype;
  v_decision public.authorization_decisions%rowtype;
  v_rate record;
  v_hash text;
  v_scopes jsonb;
begin
  if p_api_key is null or length(p_api_key) < 24 or length(p_api_key) > 512 then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid.');
  end if;

  v_hash := encode(digest(p_api_key,'sha256'),'hex');

  select * into v_key
  from public.api_keys
  where key_hash = v_hash and revoked_at is null
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID','message','The API key is invalid or revoked.');
  end if;

  select * into v_org from public.organizations where id = v_key.organization_id limit 1;
  if not found or v_org.status <> 'active' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE','message','The organization is not active.');
  end if;

  begin
    v_scopes := coalesce(v_key.scopes_json::jsonb, '[]'::jsonb);
  exception when others then
    v_scopes := '[]'::jsonb;
  end;

  if not (v_scopes ? '*' or v_scopes ? 'decisions:read') then
    return jsonb_build_object('ok',false,'status',403,'code','INSUFFICIENT_SCOPE','message','API key is missing scope: decisions:read');
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05('api:' || v_key.id, p_rate_limit, 60);

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','RATE_LIMITED',
      'message','Too many requests. Retry after the current rate-limit window resets.',
      'resetAt',v_rate.reset_at
    );
  end if;

  update public.api_keys
  set last_used_at = to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  where id = v_key.id;

  select * into v_decision
  from public.authorization_decisions
  where organization_id = v_org.id and request_id = p_request_id
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','DECISION_NOT_FOUND','message','No decision exists for that request ID.');
  end if;

  return jsonb_build_object(
    'ok',true,
    'rate',jsonb_build_object('remaining',v_rate.remaining,'resetAt',v_rate.reset_at),
    'decision',to_jsonb(v_decision)
  );
end;
$$;

revoke all on function public.trustrelay_get_decision_partner_v05(text,text,integer)
from public, authenticated;
grant execute on function public.trustrelay_get_decision_partner_v05(text,text,integer)
to anon;

-- ============================================================
-- 20260930161400 trustrelay_v051_security_invoker_hardening
-- ============================================================
alter function public.trustrelay_health_v05()
security invoker;

alter function public.trustrelay_prepare_decision_v05(
  text,text,text,text,text,text,text,integer
)
security invoker;

alter function public.trustrelay_record_decision_partner_v05(
  text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text
)
security invoker;

alter function public.trustrelay_get_decision_partner_v05(
  text,text,integer
)
security invoker;

-- ============================================================
-- 20260930161948 trustrelay_v06_schema_foundation
-- ============================================================
alter table public.accounts
  add column if not exists auth_user_id uuid references auth.users(id) on delete set null;

create unique index if not exists uq_accounts_auth_user_id
  on public.accounts(auth_user_id)
  where auth_user_id is not null;

alter table public.authority_grants
  alter column representative_person_id drop not null;

alter table public.authority_grants
  add column if not exists representative_email text,
  add column if not exists accepted_at text,
  add column if not exists activated_at text,
  add column if not exists grant_version integer not null default 1;

alter table public.authority_grants
  drop constraint if exists authority_grants_status_check;

alter table public.authority_grants
  add constraint authority_grants_status_check
  check (status in ('draft','pending_acceptance','pending_verification','active','declined','revoked','expired'));

alter table public.credentials
  add column if not exists credential_type text not null default 'trustrelay-authority+jwt',
  add column if not exists claims_json text not null default '{}',
  add column if not exists issuer text not null default 'https://trustrelay.app',
  add column if not exists grant_version integer not null default 1,
  add column if not exists signature_format text not null default 'JWS';

create table if not exists public.authority_grant_invitations (
  id text primary key,
  grant_id text not null references public.authority_grants(id) on delete cascade,
  invite_email text not null,
  token_hash text not null unique,
  status text not null default 'pending',
  invited_by_account_id text not null references public.accounts(id) on delete restrict,
  accepted_by_account_id text references public.accounts(id) on delete set null,
  expires_at text not null,
  accepted_at text,
  declined_at text,
  revoked_at text,
  created_at text not null,
  constraint authority_grant_invitations_status_check
    check (status in ('pending','accepted','declined','revoked','expired'))
);

create index if not exists idx_grant_invitations_grant
  on public.authority_grant_invitations(grant_id);

create index if not exists idx_grant_invitations_email
  on public.authority_grant_invitations(lower(invite_email));

create table if not exists public.signing_keys (
  kid text primary key,
  alg text not null default 'ES256',
  public_jwk text not null,
  public_thumbprint text not null unique,
  vault_secret_id uuid not null,
  status text not null default 'standby',
  created_at text not null,
  activated_at text,
  retired_at text,
  revoked_at text,
  constraint signing_keys_alg_check check (alg = 'ES256'),
  constraint signing_keys_status_check check (status in ('standby','active','retired','revoked'))
);

create unique index if not exists uq_signing_keys_one_active
  on public.signing_keys((status))
  where status='active';

create table if not exists public.credential_verification_events (
  id text primary key,
  jti text,
  kid text,
  valid boolean not null,
  reason_code text not null,
  request_fingerprint text,
  checked_at text not null,
  metadata_json text not null default '{}'
);

create index if not exists idx_credential_verifications_jti
  on public.credential_verification_events(jti);

alter table public.authority_grant_invitations enable row level security;
alter table public.signing_keys enable row level security;
alter table public.credential_verification_events enable row level security;

create policy trustrelay_deny_clients
on public.authority_grant_invitations
as restrictive for all to anon, authenticated
using (false) with check (false);

create policy trustrelay_deny_clients
on public.signing_keys
as restrictive for all to anon, authenticated
using (false) with check (false);

create policy trustrelay_deny_clients
on public.credential_verification_events
as restrictive for all to anon, authenticated
using (false) with check (false);

revoke all on table public.authority_grant_invitations from anon, authenticated;
revoke all on table public.signing_keys from anon, authenticated;
revoke all on table public.credential_verification_events from anon, authenticated;

grant select, insert, update on table public.authority_grant_invitations to service_role;
grant select, insert, update on table public.signing_keys to service_role;
grant select, insert on table public.credential_verification_events to service_role;

-- ============================================================
-- 20260930162009 trustrelay_v06_account_and_invite_workflow
-- ============================================================
create or replace function public.trustrelay_ensure_account_v06(
  p_auth_user_id uuid,
  p_display_name text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_catalog
as $$
declare
  v_email text;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_person_id text;
  v_account_id text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select lower(email) into v_email from auth.users where id=p_auth_user_id;

  if v_email is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_USER_NOT_FOUND');
  end if;

  select * into v_account from public.accounts where auth_user_id=p_auth_user_id limit 1;
  if found then
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
  end if;

  select * into v_account from public.accounts where lower(email)=v_email limit 1;
  if found then
    update public.accounts set auth_user_id=p_auth_user_id where id=v_account.id returning * into v_account;
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
  end if;

  v_person_id := 'person_' || replace(p_auth_user_id::text,'-','');
  v_account_id := 'acct_' || replace(p_auth_user_id::text,'-','');

  insert into public.persons(id,display_name,email,identity_status,created_at)
  values(v_person_id,coalesce(nullif(btrim(p_display_name),''),split_part(v_email,'@',1)),v_email,'unverified',v_now)
  returning * into v_person;

  insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
  values(v_account_id,v_person_id,v_email,'active',v_now,p_auth_user_id)
  returning * into v_account;

  return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
end;
$$;

create or replace function public.trustrelay_create_grant_invite_v06(
  p_auth_user_id uuid,
  p_grant_id text,
  p_invitation_id text,
  p_token_hash text,
  p_representative_email text,
  p_valid_from text,
  p_valid_until text,
  p_allowed_json text,
  p_prohibited_json text,
  p_rules_json text,
  p_resources_json text,
  p_escalation_json text,
  p_invitation_expires_at text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_grant public.authority_grants%rowtype;
  v_invite public.authority_grant_invitations%rowtype;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_rep_email text := lower(btrim(p_representative_email));
begin
  select * into v_account from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  if v_rep_email=lower(v_account.email) then
    return jsonb_build_object('ok',false,'status',400,'code','SELF_DELEGATION_NOT_ALLOWED');
  end if;

  insert into public.authority_grants(
    id,principal_person_id,representative_person_id,representative_email,status,
    valid_from,valid_until,allowed_json,prohibited_json,rules_json,resources_json,
    escalation_json,created_by_account_id,created_at,updated_at,grant_version
  ) values (
    p_grant_id,v_account.person_id,null,v_rep_email,'pending_acceptance',
    p_valid_from,p_valid_until,p_allowed_json,p_prohibited_json,p_rules_json,p_resources_json,
    p_escalation_json,v_account.id,v_now,v_now,1
  ) returning * into v_grant;

  insert into public.authority_grant_invitations(
    id,grant_id,invite_email,token_hash,status,invited_by_account_id,expires_at,created_at
  ) values (
    p_invitation_id,p_grant_id,v_rep_email,p_token_hash,'pending',v_account.id,p_invitation_expires_at,v_now
  ) returning * into v_invite;

  return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'invitation',to_jsonb(v_invite));
end;
$$;

revoke all on function public.trustrelay_ensure_account_v06(uuid,text) from public, anon, authenticated;
revoke all on function public.trustrelay_create_grant_invite_v06(uuid,text,text,text,text,text,text,text,text,text,text,text,text) from public, anon, authenticated;

grant execute on function public.trustrelay_ensure_account_v06(uuid,text) to service_role;
grant execute on function public.trustrelay_create_grant_invite_v06(uuid,text,text,text,text,text,text,text,text,text,text,text,text) to service_role;

-- ============================================================
-- 20260930162038 trustrelay_v06_accept_revoke_and_list
-- ============================================================
create or replace function public.trustrelay_accept_invitation_v06(
  p_auth_user_id uuid,
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_invite public.authority_grant_invitations%rowtype;
  v_grant public.authority_grants%rowtype;
  v_principal public.persons%rowtype;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_now_ts timestamptz := clock_timestamp();
  v_status text;
begin
  select * into v_account from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_person from public.persons where id=v_account.person_id;

  select * into v_invite
  from public.authority_grant_invitations
  where token_hash=p_token_hash
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','INVITATION_NOT_FOUND');
  end if;

  if v_invite.status <> 'pending' then
    return jsonb_build_object('ok',false,'status',409,'code','INVITATION_NOT_PENDING');
  end if;

  if v_invite.expires_at::timestamptz <= v_now_ts then
    update public.authority_grant_invitations set status='expired' where id=v_invite.id;
    return jsonb_build_object('ok',false,'status',410,'code','INVITATION_EXPIRED');
  end if;

  if lower(v_invite.invite_email) <> lower(v_account.email) then
    return jsonb_build_object('ok',false,'status',403,'code','INVITATION_EMAIL_MISMATCH');
  end if;

  select * into v_grant from public.authority_grants where id=v_invite.grant_id for update;
  select * into v_principal from public.persons where id=v_grant.principal_person_id;

  v_status := case
    when v_principal.identity_status='verified' and v_person.identity_status='verified'
      then 'active'
    else 'pending_verification'
  end;

  update public.authority_grant_invitations
  set status='accepted',accepted_by_account_id=v_account.id,accepted_at=v_now
  where id=v_invite.id
  returning * into v_invite;

  update public.authority_grants
  set representative_person_id=v_person.id,
      representative_email=lower(v_account.email),
      accepted_at=v_now,
      status=v_status,
      activated_at=case when v_status='active' then v_now else activated_at end,
      updated_at=v_now
  where id=v_grant.id
  returning * into v_grant;

  return jsonb_build_object(
    'ok',true,
    'grant',to_jsonb(v_grant),
    'invitation',to_jsonb(v_invite),
    'issueCredential',(v_status='active')
  );
end;
$$;

create or replace function public.trustrelay_revoke_grant_v06(
  p_auth_user_id uuid,
  p_grant_id text,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_grant public.authority_grants%rowtype;
  v_cred public.credentials%rowtype;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_account from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_grant from public.authority_grants where id=p_grant_id for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND');
  end if;

  if v_grant.principal_person_id <> v_account.person_id then
    return jsonb_build_object('ok',false,'status',403,'code','NOT_GRANT_PRINCIPAL');
  end if;

  if v_grant.status='revoked' then
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'alreadyRevoked',true);
  end if;

  update public.authority_grants
  set status='revoked',
      revoked_at=v_now,
      revocation_reason=nullif(btrim(p_reason),''),
      updated_at=v_now
  where id=p_grant_id
  returning * into v_grant;

  for v_cred in
    select * from public.credentials where grant_id=p_grant_id and status='active' for update
  loop
    update public.credentials
    set status='revoked',revoked_at=v_now
    where id=v_cred.id;

    insert into public.revocations(jti,credential_id,reason,revoked_by_account_id,revoked_at)
    values (
      v_cred.jti,v_cred.id,coalesce(nullif(btrim(p_reason),''),'Grant revoked'),
      v_account.id,v_now
    )
    on conflict (jti) do nothing;
  end loop;

  update public.authority_grant_invitations
  set status='revoked',revoked_at=v_now
  where grant_id=p_grant_id and status='pending';

  return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'alreadyRevoked',false);
end;
$$;

create or replace function public.trustrelay_list_grants_v06(
  p_auth_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
begin
  select * into v_account from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  return jsonb_build_object(
    'ok',true,
    'grants',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'grant',to_jsonb(g),
          'principal',to_jsonb(p),
          'representative',case when r.id is null then null else to_jsonb(r) end,
          'credentials',coalesce((
            select jsonb_agg(
              jsonb_build_object(
                'id',c.id,'jti',c.jti,'kid',c.kid,'alg',c.alg,'status',c.status,
                'issued_at',c.issued_at,'expires_at',c.expires_at,'revoked_at',c.revoked_at
              )
              order by c.issued_at desc
            )
            from public.credentials c where c.grant_id=g.id
          ),'[]'::jsonb)
        )
        order by g.created_at desc
      )
      from public.authority_grants g
      join public.persons p on p.id=g.principal_person_id
      left join public.persons r on r.id=g.representative_person_id
      where g.principal_person_id=v_account.person_id
         or g.representative_person_id=v_account.person_id
    ),'[]'::jsonb)
  );
end;
$$;

revoke all on function public.trustrelay_accept_invitation_v06(uuid,text) from public, anon, authenticated;
revoke all on function public.trustrelay_revoke_grant_v06(uuid,text,text) from public, anon, authenticated;
revoke all on function public.trustrelay_list_grants_v06(uuid) from public, anon, authenticated;

grant execute on function public.trustrelay_accept_invitation_v06(uuid,text) to service_role;
grant execute on function public.trustrelay_revoke_grant_v06(uuid,text,text) to service_role;
grant execute on function public.trustrelay_list_grants_v06(uuid) to service_role;

-- ============================================================
-- 20260930162105 trustrelay_v06_credential_persistence
-- ============================================================
create or replace function public.trustrelay_store_credential_v06(
  p_id text,
  p_grant_id text,
  p_jti text,
  p_kid text,
  p_token text,
  p_claims_json text,
  p_issued_at text,
  p_expires_at text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_grant public.authority_grants%rowtype;
  v_key public.signing_keys%rowtype;
  v_cred public.credentials%rowtype;
begin
  select * into v_grant
  from public.authority_grants
  where id=p_grant_id
  for update;

  if not found or v_grant.status <> 'active' then
    return jsonb_build_object('ok',false,'status',409,'code','GRANT_NOT_ACTIVE');
  end if;

  select * into v_key
  from public.signing_keys
  where kid=p_kid and status='active';

  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SIGNING_KEY_NOT_ACTIVE');
  end if;

  update public.credentials
  set status='superseded'
  where grant_id=p_grant_id and status='active';

  insert into public.credentials(
    id,grant_id,jti,kid,alg,token,status,issued_at,expires_at,
    credential_type,claims_json,issuer,grant_version,signature_format
  ) values (
    p_id,p_grant_id,p_jti,p_kid,'ES256',p_token,'active',p_issued_at,p_expires_at,
    'trustrelay-authority+jwt',p_claims_json,'https://trustrelay.app',v_grant.grant_version,'JWS'
  )
  returning * into v_cred;

  return jsonb_build_object('ok',true,'credential',to_jsonb(v_cred));
end;
$$;

create or replace function public.trustrelay_get_credential_context_v06(
  p_jti text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_cred public.credentials%rowtype;
  v_grant public.authority_grants%rowtype;
  v_key public.signing_keys%rowtype;
  v_rev public.revocations%rowtype;
begin
  select * into v_cred from public.credentials where jti=p_jti limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','CREDENTIAL_NOT_FOUND');
  end if;

  select * into v_grant from public.authority_grants where id=v_cred.grant_id;
  select * into v_key from public.signing_keys where kid=v_cred.kid;
  select * into v_rev from public.revocations where jti=v_cred.jti;

  return jsonb_build_object(
    'ok',true,
    'credential',to_jsonb(v_cred),
    'grant',to_jsonb(v_grant),
    'signingKey',jsonb_build_object(
      'kid',v_key.kid,
      'alg',v_key.alg,
      'publicJwk',v_key.public_jwk::jsonb,
      'status',v_key.status
    ),
    'revocation',case when v_rev.jti is null then null else to_jsonb(v_rev) end
  );
end;
$$;

create or replace function public.trustrelay_record_credential_verification_v06(
  p_id text,
  p_jti text,
  p_kid text,
  p_valid boolean,
  p_reason_code text,
  p_request_fingerprint text,
  p_metadata_json text
)
returns void
language sql
security definer
set search_path = public, pg_catalog
as $$
  insert into public.credential_verification_events(
    id,jti,kid,valid,reason_code,request_fingerprint,checked_at,metadata_json
  ) values (
    p_id,p_jti,p_kid,p_valid,p_reason_code,p_request_fingerprint,
    to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    coalesce(p_metadata_json,'{}')
  );
$$;

revoke all on function public.trustrelay_store_credential_v06(text,text,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.trustrelay_get_credential_context_v06(text) from public, anon, authenticated;
revoke all on function public.trustrelay_record_credential_verification_v06(text,text,text,boolean,text,text,text) from public, anon, authenticated;

grant execute on function public.trustrelay_store_credential_v06(text,text,text,text,text,text,text,text) to service_role;
grant execute on function public.trustrelay_get_credential_context_v06(text) to service_role;
grant execute on function public.trustrelay_record_credential_verification_v06(text,text,text,boolean,text,text,text) to service_role;

-- ============================================================
-- 20260930162122 trustrelay_v06_signing_key_vault
-- ============================================================
create or replace function public.trustrelay_bootstrap_signing_key_v06(
  p_kid text,
  p_public_jwk text,
  p_private_jwk text,
  p_public_thumbprint text
)
returns jsonb
language plpgsql
security definer
set search_path = public, vault, pg_catalog
as $$
declare
  v_existing public.signing_keys%rowtype;
  v_secret_id uuid;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_existing
  from public.signing_keys
  where status='active'
  limit 1;

  if found then
    return jsonb_build_object('ok',true,'created',false,'key',to_jsonb(v_existing));
  end if;

  v_secret_id := vault.create_secret(
    p_private_jwk,
    'trustrelay-signing-' || p_kid,
    'TrustRelay ES256 authority credential private JWK'
  );

  insert into public.signing_keys(
    kid,alg,public_jwk,public_thumbprint,vault_secret_id,status,created_at,activated_at
  ) values (
    p_kid,'ES256',p_public_jwk,p_public_thumbprint,v_secret_id,'active',v_now,v_now
  )
  returning * into v_existing;

  return jsonb_build_object('ok',true,'created',true,'key',to_jsonb(v_existing));
end;
$$;

create or replace function public.trustrelay_get_active_signing_key_v06()
returns jsonb
language plpgsql
security definer
set search_path = public, vault, pg_catalog
as $$
declare
  v_key public.signing_keys%rowtype;
  v_private text;
begin
  select * into v_key
  from public.signing_keys
  where status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',503,'code','SIGNING_KEY_UNAVAILABLE');
  end if;

  select decrypted_secret into v_private
  from vault.decrypted_secrets
  where id=v_key.vault_secret_id;

  if v_private is null then
    return jsonb_build_object('ok',false,'status',503,'code','SIGNING_KEY_UNAVAILABLE');
  end if;

  return jsonb_build_object(
    'ok',true,
    'kid',v_key.kid,
    'alg',v_key.alg,
    'publicJwk',v_key.public_jwk::jsonb,
    'privateJwk',v_private::jsonb,
    'publicThumbprint',v_key.public_thumbprint
  );
end;
$$;

revoke all on function public.trustrelay_bootstrap_signing_key_v06(text,text,text,text) from public, anon, authenticated;
revoke all on function public.trustrelay_get_active_signing_key_v06() from public, anon, authenticated;

grant execute on function public.trustrelay_bootstrap_signing_key_v06(text,text,text,text) to service_role;
grant execute on function public.trustrelay_get_active_signing_key_v06() to service_role;

-- ============================================================
-- 20260930162504 trustrelay_v06_invitation_fk_indexes
-- ============================================================
create index if not exists idx_grant_invitations_invited_by
  on public.authority_grant_invitations(invited_by_account_id);

create index if not exists idx_grant_invitations_accepted_by
  on public.authority_grant_invitations(accepted_by_account_id);

-- ============================================================
-- 20260930162551 trustrelay_v06_grant_activation_helpers
-- ============================================================
create or replace function public.trustrelay_get_grant_v06(
  p_auth_user_id uuid,
  p_grant_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_grant public.authority_grants%rowtype;
begin
  select * into v_account from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_grant from public.authority_grants where id=p_grant_id limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND');
  end if;

  if v_grant.principal_person_id <> v_account.person_id
     and coalesce(v_grant.representative_person_id,'') <> v_account.person_id then
    return jsonb_build_object('ok',false,'status',403,'code','NOT_GRANT_PARTICIPANT');
  end if;

  return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant));
end;
$$;

create or replace function public.trustrelay_refresh_grant_status_v06(
  p_grant_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_grant public.authority_grants%rowtype;
  v_principal public.persons%rowtype;
  v_rep public.persons%rowtype;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_grant from public.authority_grants where id=p_grant_id for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND');
  end if;

  if v_grant.status not in ('pending_verification','active') then
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',false);
  end if;

  if v_grant.representative_person_id is null then
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',false);
  end if;

  select * into v_principal from public.persons where id=v_grant.principal_person_id;
  select * into v_rep from public.persons where id=v_grant.representative_person_id;

  if v_principal.identity_status='verified' and v_rep.identity_status='verified' then
    if v_grant.status <> 'active' then
      update public.authority_grants
      set status='active',activated_at=coalesce(activated_at,v_now),updated_at=v_now
      where id=v_grant.id
      returning * into v_grant;
    end if;
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',true);
  end if;

  return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',false);
end;
$$;

revoke all on function public.trustrelay_get_grant_v06(uuid,text) from public, anon, authenticated;
revoke all on function public.trustrelay_refresh_grant_status_v06(text) from public, anon, authenticated;

grant execute on function public.trustrelay_get_grant_v06(uuid,text) to service_role;
grant execute on function public.trustrelay_refresh_grant_status_v06(text) to service_role;

-- ============================================================
-- 20260930162904 trustrelay_v06_public_key_rpc
-- ============================================================
create or replace function public.trustrelay_list_public_signing_keys_v06()
returns jsonb
language sql
security definer
set search_path = public, pg_catalog
as $$
  select jsonb_build_object(
    'ok',true,
    'keys',coalesce(
      jsonb_agg(
        jsonb_build_object(
          'kid',kid,
          'alg',alg,
          'publicJwk',public_jwk::jsonb,
          'status',status
        )
        order by created_at desc
      ) filter (where status in ('active','retired')),
      '[]'::jsonb
    )
  )
  from public.signing_keys;
$$;

revoke all on function public.trustrelay_list_public_signing_keys_v06() from public, anon, authenticated;
grant execute on function public.trustrelay_list_public_signing_keys_v06() to service_role;

-- ============================================================
-- 20260930163213 trustrelay_v06_auth_account_binding
-- ============================================================
create or replace function public.trustrelay_on_auth_user_created_v06()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_person_id text := 'person_' || replace(new.id::text,'-','');
  v_account_id text := 'acct_' || replace(new.id::text,'-','');
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_email text := lower(coalesce(new.email,''));
begin
  insert into public.persons(id,display_name,email,identity_status,created_at)
  values(
    v_person_id,
    coalesce(nullif(new.raw_user_meta_data->>'full_name',''),nullif(new.raw_user_meta_data->>'name',''),split_part(v_email,'@',1)),
    v_email,
    'unverified',
    v_now
  )
  on conflict (id) do nothing;

  insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
  values(v_account_id,v_person_id,v_email,'active',v_now,new.id)
  on conflict (id) do update set auth_user_id=excluded.auth_user_id;

  return new;
end;
$$;

revoke all on function public.trustrelay_on_auth_user_created_v06() from public, anon, authenticated;

drop trigger if exists trustrelay_auth_user_created_v06 on auth.users;
create trigger trustrelay_auth_user_created_v06
after insert on auth.users
for each row execute function public.trustrelay_on_auth_user_created_v06();

-- ============================================================
-- 20260930163352 trustrelay_v06_participant_rls
-- ============================================================
drop policy if exists trustrelay_deny_clients on public.accounts;
drop policy if exists trustrelay_deny_clients on public.persons;
drop policy if exists trustrelay_deny_clients on public.authority_grants;
drop policy if exists trustrelay_deny_clients on public.authority_grant_invitations;
drop policy if exists trustrelay_deny_clients on public.credentials;
drop policy if exists trustrelay_deny_clients on public.revocations;

grant select on public.accounts to authenticated;
grant select on public.persons to authenticated;
grant select, insert on public.authority_grants to authenticated;
grant update (
  representative_person_id,representative_email,status,accepted_at,activated_at,
  updated_at,revoked_at,revocation_reason
) on public.authority_grants to authenticated;
grant select, insert on public.authority_grant_invitations to authenticated;
grant update (
  status,accepted_by_account_id,accepted_at,declined_at,revoked_at
) on public.authority_grant_invitations to authenticated;
grant select on public.credentials to authenticated;
grant select on public.revocations to authenticated;

create policy accounts_select_self_v06
on public.accounts for select to authenticated
using (auth_user_id = (select auth.uid()));

create policy grants_select_participant_v06
on public.authority_grants for select to authenticated
using (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grants.principal_person_id=a.person_id
        or authority_grants.representative_person_id=a.person_id
        or lower(coalesce(authority_grants.representative_email,''))=lower(a.email)
      )
  )
);

create policy grants_insert_principal_v06
on public.authority_grants for insert to authenticated
with check (
  status='pending_acceptance'
  and representative_person_id is null
  and exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and authority_grants.principal_person_id=a.person_id
      and authority_grants.created_by_account_id=a.id
  )
);

create policy grants_update_participant_v06
on public.authority_grants for update to authenticated
using (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grants.principal_person_id=a.person_id
        or lower(coalesce(authority_grants.representative_email,''))=lower(a.email)
      )
  )
)
with check (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grants.principal_person_id=a.person_id
        or lower(coalesce(authority_grants.representative_email,''))=lower(a.email)
      )
  )
);

create policy invitations_select_participant_v06
on public.authority_grant_invitations for select to authenticated
using (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grant_invitations.invited_by_account_id=a.id
        or lower(authority_grant_invitations.invite_email)=lower(a.email)
      )
  )
);

create policy invitations_insert_principal_v06
on public.authority_grant_invitations for insert to authenticated
with check (
  status='pending'
  and exists (
    select 1 from public.accounts a
    join public.authority_grants g on g.id=authority_grant_invitations.grant_id
    where a.auth_user_id=(select auth.uid())
      and authority_grant_invitations.invited_by_account_id=a.id
      and g.principal_person_id=a.person_id
  )
);

create policy invitations_update_participant_v06
on public.authority_grant_invitations for update to authenticated
using (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grant_invitations.invited_by_account_id=a.id
        or lower(authority_grant_invitations.invite_email)=lower(a.email)
      )
  )
)
with check (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        authority_grant_invitations.invited_by_account_id=a.id
        or (
          lower(authority_grant_invitations.invite_email)=lower(a.email)
          and (
            authority_grant_invitations.accepted_by_account_id is null
            or authority_grant_invitations.accepted_by_account_id=a.id
          )
        )
      )
  )
);

create policy persons_select_participant_v06
on public.persons for select to authenticated
using (
  exists (
    select 1 from public.accounts a
    where a.auth_user_id=(select auth.uid())
      and (
        persons.id=a.person_id
        or exists (
          select 1 from public.authority_grants g
          where (
            g.principal_person_id=a.person_id
            or g.representative_person_id=a.person_id
          )
          and (
            persons.id=g.principal_person_id
            or persons.id=g.representative_person_id
          )
        )
      )
  )
);

create policy credentials_select_participant_v06
on public.credentials for select to authenticated
using (
  exists (
    select 1
    from public.authority_grants g
    join public.accounts a on (
      g.principal_person_id=a.person_id
      or g.representative_person_id=a.person_id
    )
    where a.auth_user_id=(select auth.uid())
      and g.id=credentials.grant_id
  )
);

create policy revocations_select_participant_v06
on public.revocations for select to authenticated
using (
  exists (
    select 1
    from public.credentials c
    join public.authority_grants g on g.id=c.grant_id
    join public.accounts a on (
      g.principal_person_id=a.person_id
      or g.representative_person_id=a.person_id
    )
    where a.auth_user_id=(select auth.uid())
      and c.id=revocations.credential_id
  )
);

-- ============================================================
-- 20260930163457 trustrelay_v06_authenticated_workflow_rpcs
-- ============================================================
create or replace function public.trustrelay_create_my_grant_v06(
  p_representative_email text,
  p_valid_from text,
  p_valid_until text,
  p_allowed_json text,
  p_prohibited_json text,
  p_rules_json text,
  p_resources_json text,
  p_escalation_json text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, auth, pg_catalog
as $$
declare
  v_uid uuid := auth.uid();
  v_grant_id text := 'grant_' || replace(gen_random_uuid()::text,'-','');
  v_invitation_id text := 'invite_' || replace(gen_random_uuid()::text,'-','');
  v_raw_token text := encode(gen_random_bytes(32),'hex');
  v_token_hash text;
  v_result jsonb;
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  v_token_hash := encode(digest(v_raw_token,'sha256'),'hex');

  v_result := public.trustrelay_create_grant_invite_v06(
    v_uid,
    v_grant_id,
    v_invitation_id,
    v_token_hash,
    p_representative_email,
    p_valid_from,
    p_valid_until,
    p_allowed_json,
    p_prohibited_json,
    p_rules_json,
    p_resources_json,
    p_escalation_json,
    to_char((clock_timestamp() + interval '7 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );

  if coalesce((v_result->>'ok')::boolean,false) is false then
    return v_result;
  end if;

  return v_result || jsonb_build_object('invitationToken',v_raw_token);
end;
$$;

create or replace function public.trustrelay_accept_my_invitation_v06(
  p_invitation_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, auth, pg_catalog
as $$
declare
  v_uid uuid := auth.uid();
  v_hash text;
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  if p_invitation_token is null or length(btrim(p_invitation_token)) < 32 then
    return jsonb_build_object('ok',false,'status',400,'code','INVITATION_TOKEN_INVALID');
  end if;

  v_hash := encode(digest(btrim(p_invitation_token),'sha256'),'hex');
  return public.trustrelay_accept_invitation_v06(v_uid,v_hash);
end;
$$;

create or replace function public.trustrelay_revoke_my_grant_v06(
  p_grant_id text,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_catalog
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  return public.trustrelay_revoke_grant_v06(v_uid,p_grant_id,p_reason);
end;
$$;

create or replace function public.trustrelay_get_my_grant_v06(
  p_grant_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_catalog
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  return public.trustrelay_get_grant_v06(v_uid,p_grant_id);
end;
$$;

create or replace function public.trustrelay_my_grants_v06()
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_catalog
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;

  return public.trustrelay_list_grants_v06(v_uid);
end;
$$;

revoke all on function public.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) from public, anon;
revoke all on function public.trustrelay_accept_my_invitation_v06(text) from public, anon;
revoke all on function public.trustrelay_revoke_my_grant_v06(text,text) from public, anon;
revoke all on function public.trustrelay_get_my_grant_v06(text) from public, anon;
revoke all on function public.trustrelay_my_grants_v06() from public, anon;

grant execute on function public.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) to authenticated;
grant execute on function public.trustrelay_accept_my_invitation_v06(text) to authenticated;
grant execute on function public.trustrelay_revoke_my_grant_v06(text,text) to authenticated;
grant execute on function public.trustrelay_get_my_grant_v06(text) to authenticated;
grant execute on function public.trustrelay_my_grants_v06() to authenticated;

-- ============================================================
-- 20260930163516 trustrelay_v06_drop_grant_write_policies
-- ============================================================
drop policy if exists grants_insert_principal_v06 on public.authority_grants;
drop policy if exists grants_update_participant_v06 on public.authority_grants;

-- ============================================================
-- 20260930163607 trustrelay_v06_private_schema
-- ============================================================
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

-- ============================================================
-- 20260930163632 trustrelay_v06_private_workflow_helpers
-- ============================================================
alter function public.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) set schema private;
alter function public.trustrelay_accept_my_invitation_v06(text) set schema private;
alter function public.trustrelay_revoke_my_grant_v06(text,text) set schema private;
alter function public.trustrelay_get_my_grant_v06(text) set schema private;
alter function public.trustrelay_my_grants_v06() set schema private;

revoke all on function private.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) from public, anon;
revoke all on function private.trustrelay_accept_my_invitation_v06(text) from public, anon;
revoke all on function private.trustrelay_revoke_my_grant_v06(text,text) from public, anon;
revoke all on function private.trustrelay_get_my_grant_v06(text) from public, anon;
revoke all on function private.trustrelay_my_grants_v06() from public, anon;

grant execute on function private.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) to authenticated;
grant execute on function private.trustrelay_accept_my_invitation_v06(text) to authenticated;
grant execute on function private.trustrelay_revoke_my_grant_v06(text,text) to authenticated;
grant execute on function private.trustrelay_get_my_grant_v06(text) to authenticated;
grant execute on function private.trustrelay_my_grants_v06() to authenticated;

create or replace function public.trustrelay_create_my_grant_v06(
  p_representative_email text,
  p_valid_from text,
  p_valid_until text,
  p_allowed_json text,
  p_prohibited_json text,
  p_rules_json text,
  p_resources_json text,
  p_escalation_json text
)
returns jsonb
language sql
security invoker
set search_path = private, pg_catalog
as $$
  select private.trustrelay_create_my_grant_v06(
    p_representative_email,p_valid_from,p_valid_until,p_allowed_json,p_prohibited_json,
    p_rules_json,p_resources_json,p_escalation_json
  );
$$;

create or replace function public.trustrelay_accept_my_invitation_v06(p_invitation_token text)
returns jsonb
language sql
security invoker
set search_path = private, pg_catalog
as $$
  select private.trustrelay_accept_my_invitation_v06(p_invitation_token);
$$;

create or replace function public.trustrelay_revoke_my_grant_v06(
  p_grant_id text,
  p_reason text default null
)
returns jsonb
language sql
security invoker
set search_path = private, pg_catalog
as $$
  select private.trustrelay_revoke_my_grant_v06(p_grant_id,p_reason);
$$;

create or replace function public.trustrelay_get_my_grant_v06(p_grant_id text)
returns jsonb
language sql
security invoker
set search_path = private, pg_catalog
as $$
  select private.trustrelay_get_my_grant_v06(p_grant_id);
$$;

create or replace function public.trustrelay_my_grants_v06()
returns jsonb
language sql
security invoker
set search_path = private, pg_catalog
as $$
  select private.trustrelay_my_grants_v06();
$$;

revoke all on function public.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) from public, anon;
revoke all on function public.trustrelay_accept_my_invitation_v06(text) from public, anon;
revoke all on function public.trustrelay_revoke_my_grant_v06(text,text) from public, anon;
revoke all on function public.trustrelay_get_my_grant_v06(text) from public, anon;
revoke all on function public.trustrelay_my_grants_v06() from public, anon;

grant execute on function public.trustrelay_create_my_grant_v06(text,text,text,text,text,text,text,text) to authenticated;
grant execute on function public.trustrelay_accept_my_invitation_v06(text) to authenticated;
grant execute on function public.trustrelay_revoke_my_grant_v06(text,text) to authenticated;
grant execute on function public.trustrelay_get_my_grant_v06(text) to authenticated;
grant execute on function public.trustrelay_my_grants_v06() to authenticated;

-- ============================================================
-- 20260930164713 trustrelay_v06_credential_integrity_constraints
-- ============================================================
create unique index if not exists uq_credentials_one_active_per_grant
  on public.credentials(grant_id)
  where status='active';

alter table public.authority_grants
  add constraint authority_grants_grant_version_positive
  check (grant_version > 0);

alter table public.credentials
  add constraint credentials_grant_version_positive
  check (grant_version > 0);

alter table public.credentials
  add constraint credentials_alg_es256
  check (alg = 'ES256');

alter table public.credentials
  add constraint credentials_signature_format_jws
  check (signature_format = 'JWS');

alter table public.credentials
  add constraint credentials_type_trustrelay
  check (credential_type = 'trustrelay-authority+jwt');

-- ============================================================
-- 20260930181814 trustrelay_v061_email_assurance_and_auto_activation
-- ============================================================
alter table public.persons
  add column if not exists identity_assurance_level text not null default 'none';

alter table public.persons
  add constraint persons_identity_assurance_level_check
  check (identity_assurance_level in ('none','email_verified','document_verified','high_assurance'));

create or replace function private.trustrelay_sync_email_verification_v061()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if new.confirmed_at is not null then
    update public.persons p
    set
      identity_status='verified',
      identity_verified_at=coalesce(p.identity_verified_at,v_now),
      identity_assurance_level=case
        when p.identity_assurance_level in ('document_verified','high_assurance')
          then p.identity_assurance_level
        else 'email_verified'
      end
    from public.accounts a
    where a.auth_user_id=new.id
      and a.person_id=p.id;
  end if;
  return new;
end;
$$;

revoke all on function private.trustrelay_sync_email_verification_v061() from public, anon, authenticated;

drop trigger if exists zz_trustrelay_auth_email_confirmed_insert_v061 on auth.users;
create trigger zz_trustrelay_auth_email_confirmed_insert_v061
after insert on auth.users
for each row execute function private.trustrelay_sync_email_verification_v061();

drop trigger if exists zz_trustrelay_auth_email_confirmed_update_v061 on auth.users;
create trigger zz_trustrelay_auth_email_confirmed_update_v061
after update of confirmed_at on auth.users
for each row execute function private.trustrelay_sync_email_verification_v061();

create or replace function private.trustrelay_activate_verified_grants_v061()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if new.identity_status='verified' and old.identity_status is distinct from new.identity_status then
    update public.authority_grants g
    set status='active',
        activated_at=coalesce(g.activated_at,v_now),
        updated_at=v_now
    where g.status='pending_verification'
      and g.representative_person_id is not null
      and exists (
        select 1 from public.persons p
        where p.id=g.principal_person_id and p.identity_status='verified'
      )
      and exists (
        select 1 from public.persons r
        where r.id=g.representative_person_id and r.identity_status='verified'
      );
  end if;
  return new;
end;
$$;

revoke all on function private.trustrelay_activate_verified_grants_v061() from public, anon, authenticated;

drop trigger if exists trustrelay_person_verified_activate_grants_v061 on public.persons;
create trigger trustrelay_person_verified_activate_grants_v061
after update of identity_status on public.persons
for each row execute function private.trustrelay_activate_verified_grants_v061();

-- ============================================================
-- 20260930183113 trustrelay_v061_invitation_preview
-- ============================================================
create or replace function public.trustrelay_preview_invitation_v061(
  p_auth_user_id uuid,
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_invite public.authority_grant_invitations%rowtype;
  v_grant public.authority_grants%rowtype;
  v_principal public.persons%rowtype;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_invite
  from public.authority_grant_invitations
  where token_hash=p_token_hash
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','INVITATION_NOT_FOUND');
  end if;

  if v_invite.status <> 'pending' then
    return jsonb_build_object('ok',false,'status',409,'code','INVITATION_NOT_PENDING');
  end if;

  if v_invite.expires_at::timestamptz <= clock_timestamp() then
    return jsonb_build_object('ok',false,'status',410,'code','INVITATION_EXPIRED');
  end if;

  if lower(v_invite.invite_email) <> lower(v_account.email) then
    return jsonb_build_object('ok',false,'status',403,'code','INVITATION_EMAIL_MISMATCH');
  end if;

  select * into v_grant from public.authority_grants where id=v_invite.grant_id;
  select * into v_principal from public.persons where id=v_grant.principal_person_id;

  return jsonb_build_object(
    'ok',true,
    'invitation',jsonb_build_object(
      'id',v_invite.id,
      'email',v_invite.invite_email,
      'expiresAt',v_invite.expires_at
    ),
    'principal',jsonb_build_object(
      'displayName',v_principal.display_name,
      'email',v_principal.email
    ),
    'grant',jsonb_build_object(
      'id',v_grant.id,
      'status',v_grant.status,
      'validFrom',v_grant.valid_from,
      'validUntil',v_grant.valid_until,
      'allowed',v_grant.allowed_json::jsonb,
      'prohibited',v_grant.prohibited_json::jsonb,
      'resources',v_grant.resources_json::jsonb,
      'rules',v_grant.rules_json::jsonb,
      'escalation',v_grant.escalation_json::jsonb,
      'grantVersion',v_grant.grant_version
    )
  );
end;
$$;

revoke all on function public.trustrelay_preview_invitation_v061(uuid,text) from public, anon, authenticated;
grant execute on function public.trustrelay_preview_invitation_v061(uuid,text) to service_role;

-- ============================================================
-- 20260930214456 trustrelay_v061_pilot_run_registry
-- ============================================================
create table if not exists public.pilot_runs (
  id text primary key,
  status text not null,
  started_at text not null,
  completed_at text,
  report_json text,
  constraint pilot_runs_status_check check (status in ('running','passed','failed'))
);

alter table public.pilot_runs enable row level security;

revoke all on table public.pilot_runs from public, anon, authenticated;
grant select, insert, update on table public.pilot_runs to service_role;

-- ============================================================
-- 20260930214609 trustrelay_v061_enable_pg_net_for_pilot
-- ============================================================
create extension if not exists pg_net with schema extensions;

-- ============================================================
-- 20261001161317 trustrelay_v07_institutional_schema
-- ============================================================
alter table public.organizations
  add column if not exists created_by_account_id text references public.accounts(id) on delete set null,
  add column if not exists industry text,
  add column if not exists website text,
  add column if not exists updated_at text;

alter table public.organization_members
  add column if not exists status text not null default 'active',
  add column if not exists title text,
  add column if not exists updated_at text;

alter table public.api_keys
  add column if not exists key_type text not null default 'partner',
  add column if not exists created_by_account_id text references public.accounts(id) on delete set null,
  add column if not exists expires_at text,
  add column if not exists last_four text,
  add column if not exists secret_vault_id uuid,
  add column if not exists updated_at text;

alter table public.authorization_decisions
  add column if not exists source text not null default 'api',
  add column if not exists initiated_by_account_id text references public.accounts(id) on delete set null;

create index if not exists idx_org_members_account
  on public.organization_members(account_id);

create index if not exists idx_api_keys_created_by
  on public.api_keys(created_by_account_id);

create index if not exists idx_decisions_initiated_by
  on public.authorization_decisions(initiated_by_account_id);

create unique index if not exists uq_api_keys_one_portal_key_per_org
  on public.api_keys(organization_id)
  where key_type='portal' and revoked_at is null;

create table if not exists public.organization_invitations (
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  invite_email text not null,
  role text not null,
  token_hash text not null unique,
  invited_by_account_id text not null references public.accounts(id) on delete restrict,
  accepted_by_account_id text references public.accounts(id) on delete set null,
  status text not null default 'pending',
  expires_at text not null,
  accepted_at text,
  revoked_at text,
  created_at text not null
);

create index if not exists idx_org_invitations_org
  on public.organization_invitations(organization_id);
create index if not exists idx_org_invitations_email
  on public.organization_invitations(lower(invite_email));
create index if not exists idx_org_invitations_invited_by
  on public.organization_invitations(invited_by_account_id);
create index if not exists idx_org_invitations_accepted_by
  on public.organization_invitations(accepted_by_account_id);

create table if not exists public.webhook_subscriptions (
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  name text not null,
  endpoint_url text not null,
  events_json text not null,
  secret_vault_id uuid not null,
  secret_prefix text not null,
  status text not null default 'active',
  created_by_account_id text not null references public.accounts(id) on delete restrict,
  created_at text not null,
  updated_at text not null,
  last_delivery_at text,
  consecutive_failures integer not null default 0
);

create index if not exists idx_webhook_subscriptions_org
  on public.webhook_subscriptions(organization_id);
create index if not exists idx_webhook_subscriptions_created_by
  on public.webhook_subscriptions(created_by_account_id);

create table if not exists public.webhook_deliveries (
  id text primary key,
  subscription_id text not null references public.webhook_subscriptions(id) on delete cascade,
  organization_id text not null references public.organizations(id) on delete cascade,
  event_type text not null,
  event_id text not null,
  payload_json text not null,
  payload_hash text not null,
  status text not null default 'pending',
  attempt_count integer not null default 0,
  response_status integer,
  response_body_excerpt text,
  last_error text,
  created_at text not null,
  attempted_at text,
  delivered_at text
);

create index if not exists idx_webhook_deliveries_org_created
  on public.webhook_deliveries(organization_id,created_at desc);
create index if not exists idx_webhook_deliveries_subscription_created
  on public.webhook_deliveries(subscription_id,created_at desc);
create unique index if not exists uq_webhook_delivery_event
  on public.webhook_deliveries(subscription_id,event_id);

alter table public.organization_invitations enable row level security;
alter table public.webhook_subscriptions enable row level security;
alter table public.webhook_deliveries enable row level security;

create policy trustrelay_deny_clients
on public.organization_invitations
as restrictive for all to anon, authenticated
using (false) with check (false);

create policy trustrelay_deny_clients
on public.webhook_subscriptions
as restrictive for all to anon, authenticated
using (false) with check (false);

create policy trustrelay_deny_clients
on public.webhook_deliveries
as restrictive for all to anon, authenticated
using (false) with check (false);

revoke all on public.organization_invitations from anon, authenticated;
revoke all on public.webhook_subscriptions from anon, authenticated;
revoke all on public.webhook_deliveries from anon, authenticated;

grant select,insert,update on public.organization_invitations to service_role;
grant select,insert,update on public.webhook_subscriptions to service_role;
grant select,insert,update on public.webhook_deliveries to service_role;

-- ============================================================
-- 20261001161331 trustrelay_v07_institutional_constraints
-- ============================================================
alter table public.organization_members
  add constraint organization_members_role_v07
  check (role in ('owner','admin','verifier','developer','auditor'));

alter table public.organization_members
  add constraint organization_members_status_v07
  check (status in ('active','disabled'));

alter table public.api_keys
  add constraint api_keys_type_v07
  check (key_type in ('partner','portal'));

alter table public.authorization_decisions
  add constraint authorization_decisions_source_v07
  check (source in ('api','portal'));

alter table public.organization_invitations
  add constraint organization_invitations_role_v07
  check (role in ('admin','verifier','developer','auditor'));

alter table public.organization_invitations
  add constraint organization_invitations_status_v07
  check (status in ('pending','accepted','revoked','expired'));

alter table public.webhook_subscriptions
  add constraint webhook_subscriptions_status_v07
  check (status in ('active','disabled','revoked'));

alter table public.webhook_deliveries
  add constraint webhook_deliveries_status_v07
  check (status in ('pending','delivered','failed'));

alter table public.webhook_subscriptions
  add constraint webhook_subscriptions_failures_nonnegative_v07
  check (consecutive_failures >= 0);

alter table public.webhook_deliveries
  add constraint webhook_deliveries_attempts_nonnegative_v07
  check (attempt_count >= 0);

-- ============================================================
-- 20261001161419 trustrelay_v07_org_core_rpcs
-- ============================================================
create or replace function private.trustrelay_org_context_v07(
  p_uid uuid,
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_member public.organization_members%rowtype;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_org
  from public.organizations
  where id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_NOT_FOUND');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id
    and account_id=v_account.id
    and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ACCESS_DENIED');
  end if;

  return jsonb_build_object(
    'ok',true,
    'account',to_jsonb(v_account),
    'organization',to_jsonb(v_org),
    'member',to_jsonb(v_member)
  );
end;
$$;

create or replace function private.trustrelay_create_organization_v07(
  p_uid uuid,
  p_name text,
  p_industry text,
  p_website text
)
returns jsonb
language plpgsql
security definer
set search_path = public, private, vault, extensions, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_org_id text := 'org_' || replace(gen_random_uuid()::text,'-','');
  v_slug text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_raw_key text;
  v_hash text;
  v_key_id text := 'key_' || replace(gen_random_uuid()::text,'-','');
  v_secret_id uuid;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 120 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_NAME_INVALID');
  end if;

  v_slug := regexp_replace(lower(btrim(p_name)),'[^a-z0-9]+','-','g');
  v_slug := regexp_replace(v_slug,'(^-+|-+$)','','g');
  if length(v_slug) < 2 then
    v_slug := 'organization';
  end if;
  v_slug := left(v_slug,48) || '-' || substr(replace(gen_random_uuid()::text,'-',''),1,8);

  insert into public.organizations(
    id,name,slug,mode,status,created_at,created_by_account_id,industry,website,updated_at
  ) values (
    v_org_id,btrim(p_name),v_slug,'sandbox','active',v_now,v_account.id,
    nullif(btrim(coalesce(p_industry,'')),''),
    nullif(btrim(coalesce(p_website,'')),''),
    v_now
  )
  returning * into v_org;

  insert into public.organization_members(
    organization_id,account_id,role,created_at,status,title,updated_at
  ) values (
    v_org_id,v_account.id,'owner',v_now,'active','Owner',v_now
  );

  v_raw_key := 'tr_portal_' || encode(gen_random_bytes(32),'hex');
  v_hash := encode(digest(v_raw_key,'sha256'),'hex');
  v_secret_id := vault.create_secret(
    v_raw_key,
    'trustrelay-portal-' || v_org_id,
    'TrustRelay v0.7 internal verifier portal key'
  );

  insert into public.api_keys(
    id,organization_id,name,prefix,key_hash,scopes_json,created_at,
    key_type,created_by_account_id,last_four,secret_vault_id,updated_at
  ) values (
    v_key_id,v_org_id,'Verifier Portal','tr_portal',v_hash,
    '["decisions:read","decisions:write"]',v_now,
    'portal',v_account.id,right(v_raw_key,4),v_secret_id,v_now
  );

  return jsonb_build_object(
    'ok',true,
    'organization',to_jsonb(v_org),
    'membership',jsonb_build_object('role','owner','status','active')
  );
end;
$$;

create or replace function private.trustrelay_my_organizations_v07(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  return jsonb_build_object(
    'ok',true,
    'organizations',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'organization',to_jsonb(o),
          'membership',jsonb_build_object(
            'role',m.role,'status',m.status,'title',m.title,'created_at',m.created_at
          )
        )
        order by o.created_at desc
      )
      from public.organization_members m
      join public.organizations o on o.id=m.organization_id
      where m.account_id=v_account.id and m.status='active'
    ),'[]'::jsonb)
  );
end;
$$;

create or replace function public.trustrelay_create_organization_v07(
  p_name text,
  p_industry text default null,
  p_website text default null
)
returns jsonb
language sql
security invoker
set search_path = private, auth, pg_catalog
as $$
  select private.trustrelay_create_organization_v07(
    auth.uid(),p_name,p_industry,p_website
  );
$$;

create or replace function public.trustrelay_my_organizations_v07()
returns jsonb
language sql
security invoker
set search_path = private, auth, pg_catalog
as $$
  select private.trustrelay_my_organizations_v07(auth.uid());
$$;

revoke all on function private.trustrelay_org_context_v07(uuid,text) from public,anon;
revoke all on function private.trustrelay_create_organization_v07(uuid,text,text,text) from public,anon;
revoke all on function private.trustrelay_my_organizations_v07(uuid) from public,anon;
grant execute on function private.trustrelay_org_context_v07(uuid,text) to authenticated,service_role;
grant execute on function private.trustrelay_create_organization_v07(uuid,text,text,text) to authenticated,service_role;
grant execute on function private.trustrelay_my_organizations_v07(uuid) to authenticated,service_role;

revoke all on function public.trustrelay_create_organization_v07(text,text,text) from public,anon;
revoke all on function public.trustrelay_my_organizations_v07() from public,anon;
grant execute on function public.trustrelay_create_organization_v07(text,text,text) to authenticated;
grant execute on function public.trustrelay_my_organizations_v07() to authenticated;

-- ============================================================
-- 20261001161455 trustrelay_v07_dashboard_and_api_keys
-- ============================================================
create or replace function private.trustrelay_require_org_role_v07(
  p_uid uuid,
  p_org_id text,
  p_roles text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_member public.organization_members%rowtype;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_org from public.organizations where id=p_org_id limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_NOT_FOUND');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id
    and account_id=v_account.id
    and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ACCESS_DENIED');
  end if;

  if p_roles is not null and array_length(p_roles,1) is not null
     and not (v_member.role = any(p_roles)) then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED',
      'role',v_member.role
    );
  end if;

  return jsonb_build_object(
    'ok',true,
    'accountId',v_account.id,
    'role',v_member.role,
    'organization',to_jsonb(v_org)
  );
end;
$$;

create or replace function private.trustrelay_org_dashboard_v07(
  p_uid uuid,
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_ctx jsonb;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',v_ctx->'organization',
    'membership',jsonb_build_object('role',v_ctx->>'role'),
    'metrics',jsonb_build_object(
      'totalDecisions',(select count(*) from public.authorization_decisions where organization_id=p_org_id),
      'allow',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ALLOW'),
      'deny',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='DENY'),
      'escalate',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ESCALATE'),
      'activeKeys',(select count(*) from public.api_keys where organization_id=p_org_id and key_type='partner' and revoked_at is null),
      'members',(select count(*) from public.organization_members where organization_id=p_org_id and status='active'),
      'activeWebhooks',(select count(*) from public.webhook_subscriptions where organization_id=p_org_id and status='active')
    ),
    'apiKeys',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id',k.id,'name',k.name,'prefix',k.prefix,'lastFour',k.last_four,
          'scopes',coalesce(k.scopes_json::jsonb,'[]'::jsonb),
          'revokedAt',k.revoked_at,'lastUsedAt',k.last_used_at,
          'createdAt',k.created_at,'expiresAt',k.expires_at,'keyType',k.key_type
        )
        order by k.created_at desc
      )
      from public.api_keys k
      where k.organization_id=p_org_id and k.key_type='partner'
    ),'[]'::jsonb),
    'members',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'accountId',a.id,'email',a.email,'role',m.role,'status',m.status,
          'title',m.title,'createdAt',m.created_at
        )
        order by m.created_at
      )
      from public.organization_members m
      join public.accounts a on a.id=m.account_id
      where m.organization_id=p_org_id
    ),'[]'::jsonb),
    'recentDecisions',coalesce((
      select jsonb_agg(x.row_json order by x.decided_at desc)
      from (
        select
          d.decided_at,
          jsonb_build_object(
            'id',d.id,'requestId',d.request_id,'correlationId',d.correlation_id,
            'decision',d.decision,'reasonCode',d.reason_code,'reasonDetail',d.reason_detail,
            'action',d.action,'resource',d.resource,'grantId',d.grant_id,
            'credentialJti',d.credential_jti,'decidedAt',d.decided_at,
            'evaluationHash',d.evaluation_hash,'auditEventId',d.audit_event_id,
            'latencyMs',d.latency_ms,'source',d.source
          ) as row_json
        from public.authorization_decisions d
        where d.organization_id=p_org_id
        order by d.decided_at desc
        limit 50
      ) x
    ),'[]'::jsonb)
  );
end;
$$;

create or replace function private.trustrelay_create_api_key_v07(
  p_uid uuid,
  p_org_id text,
  p_name text,
  p_scopes jsonb,
  p_expires_at text
)
returns jsonb
language plpgsql
security definer
set search_path = public, private, extensions, pg_catalog
as $$
declare
  v_ctx jsonb;
  v_org public.organizations%rowtype;
  v_account_id text;
  v_key_id text := 'key_' || replace(gen_random_uuid()::text,'-','');
  v_raw text;
  v_hash text;
  v_prefix text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_scope text;
  v_allowed text[] := array['decisions:read','decisions:write'];
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 100 then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_NAME_INVALID');
  end if;

  if p_scopes is null or jsonb_typeof(p_scopes) <> 'array' or jsonb_array_length(p_scopes)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPES_REQUIRED');
  end if;

  for v_scope in select jsonb_array_elements_text(p_scopes)
  loop
    if not (v_scope = any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPE_INVALID','scope',v_scope);
    end if;
  end loop;

  select * into v_org from public.organizations where id=p_org_id;
  v_account_id := v_ctx->>'accountId';

  if p_expires_at is not null and p_expires_at::timestamptz <= clock_timestamp() then
    return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_INVALID');
  end if;

  v_prefix := case when v_org.mode='live' then 'tr_live' else 'tr_test' end;
  v_raw := v_prefix || '_' || encode(gen_random_bytes(32),'hex');
  v_hash := encode(digest(v_raw,'sha256'),'hex');

  insert into public.api_keys(
    id,organization_id,name,prefix,key_hash,scopes_json,created_at,
    key_type,created_by_account_id,expires_at,last_four,updated_at
  ) values (
    v_key_id,p_org_id,btrim(p_name),v_prefix,v_hash,p_scopes::text,v_now,
    'partner',v_account_id,p_expires_at,right(v_raw,4),v_now
  );

  return jsonb_build_object(
    'ok',true,
    'apiKey',v_raw,
    'key',jsonb_build_object(
      'id',v_key_id,'name',btrim(p_name),'prefix',v_prefix,'lastFour',right(v_raw,4),
      'scopes',p_scopes,'createdAt',v_now,'expiresAt',p_expires_at
    )
  );
end;
$$;

create or replace function private.trustrelay_revoke_api_key_v07(
  p_uid uuid,
  p_org_id text,
  p_key_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, private, pg_catalog
as $$
declare
  v_ctx jsonb;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_key public.api_keys%rowtype;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  select * into v_key
  from public.api_keys
  where id=p_key_id and organization_id=p_org_id and key_type='partner'
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','API_KEY_NOT_FOUND');
  end if;

  if v_key.revoked_at is null then
    update public.api_keys
    set revoked_at=v_now,updated_at=v_now
    where id=p_key_id;
  end if;

  return jsonb_build_object('ok',true,'keyId',p_key_id,'revokedAt',coalesce(v_key.revoked_at,v_now));
end;
$$;

create or replace function public.trustrelay_org_dashboard_v07(p_org_id text)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_org_dashboard_v07(auth.uid(),p_org_id);
$$;

create or replace function public.trustrelay_create_api_key_v07(
  p_org_id text,
  p_name text,
  p_scopes jsonb,
  p_expires_at text default null
)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_create_api_key_v07(
    auth.uid(),p_org_id,p_name,p_scopes,p_expires_at
  );
$$;

create or replace function public.trustrelay_revoke_api_key_v07(
  p_org_id text,
  p_key_id text
)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_revoke_api_key_v07(auth.uid(),p_org_id,p_key_id);
$$;

revoke all on function private.trustrelay_require_org_role_v07(uuid,text,text[]) from public,anon;
revoke all on function private.trustrelay_org_dashboard_v07(uuid,text) from public,anon;
revoke all on function private.trustrelay_create_api_key_v07(uuid,text,text,jsonb,text) from public,anon;
revoke all on function private.trustrelay_revoke_api_key_v07(uuid,text,text) from public,anon;
grant execute on function private.trustrelay_require_org_role_v07(uuid,text,text[]) to authenticated,service_role;
grant execute on function private.trustrelay_org_dashboard_v07(uuid,text) to authenticated,service_role;
grant execute on function private.trustrelay_create_api_key_v07(uuid,text,text,jsonb,text) to authenticated,service_role;
grant execute on function private.trustrelay_revoke_api_key_v07(uuid,text,text) to authenticated,service_role;

revoke all on function public.trustrelay_org_dashboard_v07(text) from public,anon;
revoke all on function public.trustrelay_create_api_key_v07(text,text,jsonb,text) from public,anon;
revoke all on function public.trustrelay_revoke_api_key_v07(text,text) from public,anon;
grant execute on function public.trustrelay_org_dashboard_v07(text) to authenticated;
grant execute on function public.trustrelay_create_api_key_v07(text,text,jsonb,text) to authenticated;
grant execute on function public.trustrelay_revoke_api_key_v07(text,text) to authenticated;

-- ============================================================
-- 20261001161546 trustrelay_v07_members_and_webhooks
-- ============================================================
create or replace function private.trustrelay_invite_org_member_v07(
  p_uid uuid,
  p_org_id text,
  p_email text,
  p_role text
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_account_id text;
  v_invite_id text := 'orginvite_' || replace(gen_random_uuid()::text,'-','');
  v_token text := encode(gen_random_bytes(32),'hex');
  v_hash text := encode(digest(v_token,'sha256'),'hex');
  v_email text := lower(btrim(coalesce(p_email,'')));
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_expires text := to_char((clock_timestamp()+interval '7 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  if v_email !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','INVITATION_EMAIL_INVALID');
  end if;

  if p_role not in ('admin','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_ROLE_INVALID');
  end if;

  v_account_id := v_ctx->>'accountId';

  if exists (
    select 1
    from public.organization_members m
    join public.accounts a on a.id=m.account_id
    where m.organization_id=p_org_id
      and lower(a.email)=v_email
      and m.status='active'
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_EXISTS');
  end if;

  update public.organization_invitations
  set status='revoked',revoked_at=v_now
  where organization_id=p_org_id
    and lower(invite_email)=v_email
    and status='pending';

  insert into public.organization_invitations(
    id,organization_id,invite_email,role,token_hash,invited_by_account_id,
    status,expires_at,created_at
  ) values (
    v_invite_id,p_org_id,v_email,p_role,v_hash,v_account_id,
    'pending',v_expires,v_now
  );

  return jsonb_build_object(
    'ok',true,
    'invitation',jsonb_build_object(
      'id',v_invite_id,'organizationId',p_org_id,'email',v_email,
      'role',p_role,'expiresAt',v_expires,'token',v_token
    )
  );
end;
$$;

create or replace function private.trustrelay_accept_org_invite_v07(
  p_uid uuid,
  p_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public,extensions,pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_invite public.organization_invitations%rowtype;
  v_hash text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  if p_token is null or length(btrim(p_token)) < 32 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_INVITATION_INVALID');
  end if;

  v_hash := encode(digest(btrim(p_token),'sha256'),'hex');

  select * into v_invite
  from public.organization_invitations
  where token_hash=v_hash
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_INVITATION_NOT_FOUND');
  end if;

  if v_invite.status <> 'pending' then
    return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_INVITATION_NOT_PENDING');
  end if;

  if v_invite.expires_at::timestamptz <= clock_timestamp() then
    update public.organization_invitations set status='expired' where id=v_invite.id;
    return jsonb_build_object('ok',false,'status',410,'code','ORGANIZATION_INVITATION_EXPIRED');
  end if;

  if lower(v_invite.invite_email) <> lower(v_account.email) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INVITATION_EMAIL_MISMATCH');
  end if;

  insert into public.organization_members(
    organization_id,account_id,role,created_at,status,updated_at
  ) values (
    v_invite.organization_id,v_account.id,v_invite.role,v_now,'active',v_now
  )
  on conflict (organization_id,account_id)
  do update set role=excluded.role,status='active',updated_at=v_now;

  update public.organization_invitations
  set status='accepted',accepted_by_account_id=v_account.id,accepted_at=v_now
  where id=v_invite.id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',v_invite.organization_id,
    'membership',jsonb_build_object('role',v_invite.role,'status','active')
  );
end;
$$;

create or replace function private.trustrelay_create_webhook_v07(
  p_uid uuid,
  p_org_id text,
  p_name text,
  p_endpoint_url text,
  p_events jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,vault,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text := 'wh_' || replace(gen_random_uuid()::text,'-','');
  v_secret text := 'whsec_' || encode(gen_random_bytes(32),'hex');
  v_secret_id uuid;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text;
  v_allowed text[] := array['decision.created','grant.revoked','credential.revoked'];
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 100 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_NAME_INVALID');
  end if;

  if p_endpoint_url is null
     or length(p_endpoint_url) > 2048
     or p_endpoint_url !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_INVALID');
  end if;

  if p_events is null or jsonb_typeof(p_events)<>'array' or jsonb_array_length(p_events)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENTS_REQUIRED');
  end if;

  for v_event in select jsonb_array_elements_text(p_events)
  loop
    if not (v_event = any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',v_event);
    end if;
  end loop;

  v_secret_id := vault.create_secret(
    v_secret,
    'trustrelay-webhook-' || v_id,
    'TrustRelay v0.7 webhook signing secret'
  );

  insert into public.webhook_subscriptions(
    id,organization_id,name,endpoint_url,events_json,secret_vault_id,secret_prefix,
    status,created_by_account_id,created_at,updated_at
  ) values (
    v_id,p_org_id,btrim(p_name),btrim(p_endpoint_url),p_events::text,v_secret_id,
    left(v_secret,12),'active',v_ctx->>'accountId',v_now,v_now
  );

  return jsonb_build_object(
    'ok',true,
    'signingSecret',v_secret,
    'webhook',jsonb_build_object(
      'id',v_id,'name',btrim(p_name),'endpointUrl',btrim(p_endpoint_url),
      'events',p_events,'status','active','secretPrefix',left(v_secret,12),'createdAt',v_now
    )
  );
end;
$$;

create or replace function private.trustrelay_revoke_webhook_v07(
  p_uid uuid,
  p_org_id text,
  p_webhook_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  if not exists (
    select 1 from public.webhook_subscriptions
    where id=p_webhook_id and organization_id=p_org_id
  ) then
    return jsonb_build_object('ok',false,'status',404,'code','WEBHOOK_NOT_FOUND');
  end if;

  update public.webhook_subscriptions
  set status='revoked',updated_at=v_now
  where id=p_webhook_id and organization_id=p_org_id;

  return jsonb_build_object('ok',true,'webhookId',p_webhook_id,'status','revoked');
end;
$$;

create or replace function public.trustrelay_invite_org_member_v07(
  p_org_id text,
  p_email text,
  p_role text
)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_invite_org_member_v07(auth.uid(),p_org_id,p_email,p_role);
$$;

create or replace function public.trustrelay_accept_org_invite_v07(p_token text)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_accept_org_invite_v07(auth.uid(),p_token);
$$;

create or replace function public.trustrelay_create_webhook_v07(
  p_org_id text,
  p_name text,
  p_endpoint_url text,
  p_events jsonb
)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_create_webhook_v07(
    auth.uid(),p_org_id,p_name,p_endpoint_url,p_events
  );
$$;

create or replace function public.trustrelay_revoke_webhook_v07(
  p_org_id text,
  p_webhook_id text
)
returns jsonb
language sql
security invoker
set search_path = private,auth,pg_catalog
as $$
  select private.trustrelay_revoke_webhook_v07(auth.uid(),p_org_id,p_webhook_id);
$$;

revoke all on function private.trustrelay_invite_org_member_v07(uuid,text,text,text) from public,anon;
revoke all on function private.trustrelay_accept_org_invite_v07(uuid,text) from public,anon;
revoke all on function private.trustrelay_create_webhook_v07(uuid,text,text,text,jsonb) from public,anon;
revoke all on function private.trustrelay_revoke_webhook_v07(uuid,text,text) from public,anon;
grant execute on function private.trustrelay_invite_org_member_v07(uuid,text,text,text) to authenticated,service_role;
grant execute on function private.trustrelay_accept_org_invite_v07(uuid,text) to authenticated,service_role;
grant execute on function private.trustrelay_create_webhook_v07(uuid,text,text,text,jsonb) to authenticated,service_role;
grant execute on function private.trustrelay_revoke_webhook_v07(uuid,text,text) to authenticated,service_role;

revoke all on function public.trustrelay_invite_org_member_v07(text,text,text) from public,anon;
revoke all on function public.trustrelay_accept_org_invite_v07(text) from public,anon;
revoke all on function public.trustrelay_create_webhook_v07(text,text,text,jsonb) from public,anon;
revoke all on function public.trustrelay_revoke_webhook_v07(text,text) from public,anon;
grant execute on function public.trustrelay_invite_org_member_v07(text,text,text) to authenticated;
grant execute on function public.trustrelay_accept_org_invite_v07(text) to authenticated;
grant execute on function public.trustrelay_create_webhook_v07(text,text,text,jsonb) to authenticated;
grant execute on function public.trustrelay_revoke_webhook_v07(text,text) to authenticated;

-- ============================================================
-- 20261001161635 trustrelay_v07_server_partner_helpers
-- ============================================================
create or replace function public.trustrelay_partner_context_v07(
  p_api_key text,
  p_request_id text,
  p_required_scope text,
  p_rate_limit integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = public,extensions,pg_catalog
as $$
declare
  v_key public.api_keys%rowtype;
  v_org public.organizations%rowtype;
  v_prior public.authorization_decisions%rowtype;
  v_hash text;
  v_scopes jsonb;
  v_rate record;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_api_key is null or length(p_api_key)<24 or length(p_api_key)>512 then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID');
  end if;

  v_hash := encode(digest(p_api_key,'sha256'),'hex');

  select * into v_key
  from public.api_keys
  where key_hash=v_hash
    and revoked_at is null
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_INVALID');
  end if;

  if v_key.expires_at is not null and v_key.expires_at::timestamptz <= clock_timestamp() then
    return jsonb_build_object('ok',false,'status',401,'code','API_KEY_EXPIRED');
  end if;

  select * into v_org
  from public.organizations
  where id=v_key.organization_id
  limit 1;

  if not found or v_org.status<>'active' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE');
  end if;

  begin
    v_scopes := coalesce(v_key.scopes_json::jsonb,'[]'::jsonb);
  exception when others then
    v_scopes := '[]'::jsonb;
  end;

  if p_required_scope is not null
     and not (v_scopes ? '*' or v_scopes ? p_required_scope) then
    return jsonb_build_object(
      'ok',false,'status',403,'code','INSUFFICIENT_SCOPE','scope',p_required_scope
    );
  end if;

  select * into v_rate
  from public.consume_rate_limit_v05('api:'||v_key.id,p_rate_limit,60);

  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','RATE_LIMITED',
      'resetAt',v_rate.reset_at
    );
  end if;

  update public.api_keys
  set last_used_at=v_now,updated_at=v_now
  where id=v_key.id;

  if p_request_id is not null then
    select * into v_prior
    from public.authorization_decisions
    where organization_id=v_org.id and request_id=p_request_id
    limit 1;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',jsonb_build_object(
      'id',v_org.id,'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'status',v_org.status
    ),
    'apiKey',jsonb_build_object(
      'id',v_key.id,'name',v_key.name,'prefix',v_key.prefix,
      'keyType',v_key.key_type,'scopes',v_scopes
    ),
    'rate',jsonb_build_object('remaining',v_rate.remaining,'resetAt',v_rate.reset_at),
    'prior',case when v_prior.id is null then null else to_jsonb(v_prior) end
  );
end;
$$;

create or replace function public.trustrelay_get_portal_key_v07(
  p_auth_user_id uuid,
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,vault,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_key public.api_keys%rowtype;
  v_secret text;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_auth_user_id,p_org_id,array['owner','admin','verifier','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  select * into v_key
  from public.api_keys
  where organization_id=p_org_id
    and key_type='portal'
    and revoked_at is null
  limit 1;

  if not found or v_key.secret_vault_id is null then
    return jsonb_build_object('ok',false,'status',503,'code','PORTAL_KEY_UNAVAILABLE');
  end if;

  select decrypted_secret into v_secret
  from vault.decrypted_secrets
  where id=v_key.secret_vault_id;

  if v_secret is null then
    return jsonb_build_object('ok',false,'status',503,'code','PORTAL_KEY_UNAVAILABLE');
  end if;

  return jsonb_build_object(
    'ok',true,
    'apiKey',v_secret,
    'organizationId',p_org_id,
    'accountId',v_ctx->>'accountId',
    'role',v_ctx->>'role'
  );
end;
$$;

create or replace function public.trustrelay_mark_portal_decision_v07(
  p_auth_user_id uuid,
  p_org_id text,
  p_request_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_account_id text;
  v_id text;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_auth_user_id,p_org_id,array['owner','admin','verifier','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  v_account_id := v_ctx->>'accountId';

  update public.authorization_decisions
  set source='portal',initiated_by_account_id=v_account_id
  where organization_id=p_org_id and request_id=p_request_id
  returning id into v_id;

  if v_id is null then
    return jsonb_build_object('ok',false,'status',404,'code','DECISION_NOT_FOUND');
  end if;

  return jsonb_build_object('ok',true,'decisionId',v_id);
end;
$$;

create or replace function public.trustrelay_queue_webhooks_v07(
  p_org_id text,
  p_event_type text,
  p_event_id text,
  p_payload_json text
)
returns jsonb
language plpgsql
security definer
set search_path = public,vault,extensions,pg_catalog
as $$
declare
  v_sub public.webhook_subscriptions%rowtype;
  v_delivery_id text;
  v_secret text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload_hash text;
  v_targets jsonb := '[]'::jsonb;
begin
  if p_event_type not in ('decision.created','grant.revoked','credential.revoked') then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID');
  end if;

  if p_payload_json is null or length(p_payload_json)>262144 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end if;

  begin
    perform p_payload_json::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end;

  v_payload_hash := encode(digest(p_payload_json,'sha256'),'hex');

  for v_sub in
    select *
    from public.webhook_subscriptions
    where organization_id=p_org_id
      and status='active'
      and coalesce(events_json::jsonb,'[]'::jsonb) ? p_event_type
  loop
    select decrypted_secret into v_secret
    from vault.decrypted_secrets
    where id=v_sub.secret_vault_id;

    if v_secret is null then
      continue;
    end if;

    v_delivery_id := 'whd_' || replace(gen_random_uuid()::text,'-','');

    insert into public.webhook_deliveries(
      id,subscription_id,organization_id,event_type,event_id,payload_json,payload_hash,
      status,attempt_count,created_at
    ) values (
      v_delivery_id,v_sub.id,p_org_id,p_event_type,p_event_id,p_payload_json,v_payload_hash,
      'pending',0,v_now
    )
    on conflict (subscription_id,event_id) do nothing;

    if found then
      v_targets := v_targets || jsonb_build_array(
        jsonb_build_object(
          'deliveryId',v_delivery_id,
          'subscriptionId',v_sub.id,
          'endpointUrl',v_sub.endpoint_url,
          'signingSecret',v_secret
        )
      );
    end if;
  end loop;

  return jsonb_build_object('ok',true,'targets',v_targets,'payloadHash',v_payload_hash);
end;
$$;

create or replace function public.trustrelay_finish_webhook_delivery_v07(
  p_delivery_id text,
  p_success boolean,
  p_response_status integer,
  p_response_body_excerpt text,
  p_error text
)
returns void
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  v_delivery public.webhook_deliveries%rowtype;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_delivery
  from public.webhook_deliveries
  where id=p_delivery_id
  for update;

  if not found then
    return;
  end if;

  update public.webhook_deliveries
  set
    status=case when p_success then 'delivered' else 'failed' end,
    attempt_count=attempt_count+1,
    response_status=p_response_status,
    response_body_excerpt=left(p_response_body_excerpt,1000),
    last_error=left(p_error,1000),
    attempted_at=v_now,
    delivered_at=case when p_success then v_now else delivered_at end
  where id=p_delivery_id;

  update public.webhook_subscriptions
  set
    last_delivery_at=v_now,
    consecutive_failures=case when p_success then 0 else consecutive_failures+1 end,
    updated_at=v_now
  where id=v_delivery.subscription_id;
end;
$$;

create or replace function public.trustrelay_orgs_for_grant_v07(p_grant_id text)
returns jsonb
language sql
security definer
set search_path = public,pg_catalog
as $$
  select jsonb_build_object(
    'ok',true,
    'organizationIds',coalesce(
      jsonb_agg(distinct organization_id) filter (where organization_id is not null),
      '[]'::jsonb
    )
  )
  from public.authorization_decisions
  where grant_id=p_grant_id;
$$;

revoke all on function public.trustrelay_partner_context_v07(text,text,text,integer) from public,anon,authenticated;
revoke all on function public.trustrelay_get_portal_key_v07(uuid,text) from public,anon,authenticated;
revoke all on function public.trustrelay_mark_portal_decision_v07(uuid,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_queue_webhooks_v07(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_finish_webhook_delivery_v07(text,boolean,integer,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_orgs_for_grant_v07(text) from public,anon,authenticated;

grant execute on function public.trustrelay_partner_context_v07(text,text,text,integer) to service_role;
grant execute on function public.trustrelay_get_portal_key_v07(uuid,text) to service_role;
grant execute on function public.trustrelay_mark_portal_decision_v07(uuid,text,text) to service_role;
grant execute on function public.trustrelay_queue_webhooks_v07(text,text,text,text) to service_role;
grant execute on function public.trustrelay_finish_webhook_delivery_v07(text,boolean,integer,text,text) to service_role;
grant execute on function public.trustrelay_orgs_for_grant_v07(text) to service_role;

-- ============================================================
-- 20261001161845 trustrelay_v07_dashboard_management_views
-- ============================================================
create or replace function private.trustrelay_org_dashboard_v07(
  p_uid uuid,
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',v_ctx->'organization',
    'membership',jsonb_build_object('role',v_ctx->>'role'),
    'metrics',jsonb_build_object(
      'totalDecisions',(select count(*) from public.authorization_decisions where organization_id=p_org_id),
      'allow',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ALLOW'),
      'deny',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='DENY'),
      'escalate',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ESCALATE'),
      'activeKeys',(select count(*) from public.api_keys where organization_id=p_org_id and key_type='partner' and revoked_at is null),
      'members',(select count(*) from public.organization_members where organization_id=p_org_id and status='active'),
      'activeWebhooks',(select count(*) from public.webhook_subscriptions where organization_id=p_org_id and status='active')
    ),
    'apiKeys',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id',k.id,'name',k.name,'prefix',k.prefix,'lastFour',k.last_four,
          'scopes',coalesce(k.scopes_json::jsonb,'[]'::jsonb),
          'revokedAt',k.revoked_at,'lastUsedAt',k.last_used_at,
          'createdAt',k.created_at,'expiresAt',k.expires_at,'keyType',k.key_type
        )
        order by k.created_at desc
      )
      from public.api_keys k
      where k.organization_id=p_org_id and k.key_type='partner'
    ),'[]'::jsonb),
    'members',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'accountId',a.id,'email',a.email,'role',m.role,'status',m.status,
          'title',m.title,'createdAt',m.created_at
        )
        order by m.created_at
      )
      from public.organization_members m
      join public.accounts a on a.id=m.account_id
      where m.organization_id=p_org_id
    ),'[]'::jsonb),
    'pendingInvitations',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id',i.id,'email',i.invite_email,'role',i.role,'status',i.status,
          'expiresAt',i.expires_at,'createdAt',i.created_at
        )
        order by i.created_at desc
      )
      from public.organization_invitations i
      where i.organization_id=p_org_id and i.status='pending'
    ),'[]'::jsonb),
    'webhooks',coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id',w.id,'name',w.name,'endpointUrl',w.endpoint_url,
          'events',coalesce(w.events_json::jsonb,'[]'::jsonb),
          'status',w.status,'secretPrefix',w.secret_prefix,
          'createdAt',w.created_at,'lastDeliveryAt',w.last_delivery_at,
          'consecutiveFailures',w.consecutive_failures
        )
        order by w.created_at desc
      )
      from public.webhook_subscriptions w
      where w.organization_id=p_org_id
    ),'[]'::jsonb),
    'recentWebhookDeliveries',coalesce((
      select jsonb_agg(x.row_json order by x.created_at desc)
      from (
        select
          d.created_at,
          jsonb_build_object(
            'id',d.id,'subscriptionId',d.subscription_id,'eventType',d.event_type,
            'eventId',d.event_id,'status',d.status,'attemptCount',d.attempt_count,
            'responseStatus',d.response_status,'createdAt',d.created_at,
            'attemptedAt',d.attempted_at,'deliveredAt',d.delivered_at,
            'lastError',d.last_error
          ) row_json
        from public.webhook_deliveries d
        where d.organization_id=p_org_id
        order by d.created_at desc
        limit 30
      ) x
    ),'[]'::jsonb),
    'recentDecisions',coalesce((
      select jsonb_agg(x.row_json order by x.decided_at desc)
      from (
        select
          d.decided_at,
          jsonb_build_object(
            'id',d.id,'requestId',d.request_id,'correlationId',d.correlation_id,
            'decision',d.decision,'reasonCode',d.reason_code,'reasonDetail',d.reason_detail,
            'action',d.action,'resource',d.resource,'grantId',d.grant_id,
            'credentialJti',d.credential_jti,'decidedAt',d.decided_at,
            'evaluationHash',d.evaluation_hash,'auditEventId',d.audit_event_id,
            'latencyMs',d.latency_ms,'source',d.source
          ) row_json
        from public.authorization_decisions d
        where d.organization_id=p_org_id
        order by d.decided_at desc
        limit 100
      ) x
    ),'[]'::jsonb)
  );
end;
$$;

-- ============================================================
-- 20261001162049 trustrelay_v07_webhook_ssrf_hardening
-- ============================================================
create or replace function private.trustrelay_create_webhook_v07(
  p_uid uuid,
  p_org_id text,
  p_name text,
  p_endpoint_url text,
  p_events jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public,private,vault,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text := 'wh_' || replace(gen_random_uuid()::text,'-','');
  v_secret text := 'whsec_' || encode(gen_random_bytes(32),'hex');
  v_secret_id uuid;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text;
  v_allowed text[] := array['decision.created','grant.revoked','credential.revoked'];
  v_url text := btrim(coalesce(p_endpoint_url,''));
  v_host text;
begin
  v_ctx := private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','developer']
  );
  if coalesce((v_ctx->>'ok')::boolean,false) is false then
    return v_ctx;
  end if;

  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 100 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_NAME_INVALID');
  end if;

  if length(v_url)>2048 or v_url !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_INVALID');
  end if;

  if v_url ~ '^https://[^/]*@' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_USERINFO_FORBIDDEN');
  end if;

  v_host := lower(substring(v_url from '^https://([^/:?#]+)'));
  if v_host is null
     or v_host='localhost'
     or v_host like '%.localhost'
     or v_host like '%.local'
     or v_host ~ '^\['
     or v_host ~ '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_PRIVATE_NETWORK_FORBIDDEN');
  end if;

  if p_events is null or jsonb_typeof(p_events)<>'array' or jsonb_array_length(p_events)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENTS_REQUIRED');
  end if;

  for v_event in select jsonb_array_elements_text(p_events)
  loop
    if not (v_event = any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',v_event);
    end if;
  end loop;

  v_secret_id := vault.create_secret(
    v_secret,
    'trustrelay-webhook-' || v_id,
    'TrustRelay v0.7 webhook signing secret'
  );

  insert into public.webhook_subscriptions(
    id,organization_id,name,endpoint_url,events_json,secret_vault_id,secret_prefix,
    status,created_by_account_id,created_at,updated_at
  ) values (
    v_id,p_org_id,btrim(p_name),v_url,p_events::text,v_secret_id,
    left(v_secret,12),'active',v_ctx->>'accountId',v_now,v_now
  );

  return jsonb_build_object(
    'ok',true,
    'signingSecret',v_secret,
    'webhook',jsonb_build_object(
      'id',v_id,'name',btrim(p_name),'endpointUrl',v_url,
      'events',p_events,'status','active','secretPrefix',left(v_secret,12),'createdAt',v_now
    )
  );
end;
$$;

-- ============================================================
-- 20261001162335 trustrelay_v07_revocation_webhook_helpers
-- ============================================================
create or replace function public.trustrelay_credentials_for_grant_v07(p_grant_id text)
returns jsonb
language sql
security definer
set search_path = public,pg_catalog
as $$
  select jsonb_build_object(
    'ok',true,
    'credentials',coalesce(
      jsonb_agg(
        jsonb_build_object(
          'id',id,'jti',jti,'kid',kid,'status',status,
          'revokedAt',revoked_at,'expiresAt',expires_at
        )
        order by issued_at desc
      ),
      '[]'::jsonb
    )
  )
  from public.credentials
  where grant_id=p_grant_id;
$$;

revoke all on function public.trustrelay_credentials_for_grant_v07(text) from public,anon,authenticated;
grant execute on function public.trustrelay_credentials_for_grant_v07(text) to service_role;

-- ============================================================
-- 20261001162409 trustrelay_v07_org_creator_index
-- ============================================================
create index if not exists idx_organizations_created_by on public.organizations(created_by_account_id);

-- ============================================================
-- 20261001162603 trustrelay_v07_policy_evaluator
-- ============================================================
create or replace function public.trustrelay_evaluate_authority_v07(
  p_authority jsonb,
  p_action text,
  p_resource text,
  p_amount numeric,
  p_currency text,
  p_evidence jsonb
)
returns jsonb
language plpgsql
immutable
security invoker
set search_path = pg_catalog
as $$
declare
  v_allowed jsonb := coalesce(p_authority->'allowed','[]'::jsonb);
  v_prohibited jsonb := coalesce(p_authority->'prohibited','[]'::jsonb);
  v_resources jsonb := coalesce(p_authority->'resources','[]'::jsonb);
  v_rules jsonb := coalesce(p_authority->'rules','{}'::jsonb);
  v_escalation jsonb := coalesce(p_authority->'escalation','{}'::jsonb);
  v_pattern text;
  v_resource_match boolean := false;
  v_key text;
  v_limit numeric;
begin
  if v_prohibited ? p_action then
    return jsonb_build_object('decision','DENY','reasonCode','ACTION_PROHIBITED','reasonDetail','The action is explicitly prohibited by the grant.');
  end if;

  if not (v_allowed ? p_action) then
    return jsonb_build_object('decision','DENY','reasonCode','ACTION_NOT_ALLOWED','reasonDetail','The action is outside the grant''s allowed scope.');
  end if;

  for v_pattern in select jsonb_array_elements_text(v_resources)
  loop
    if v_pattern='*'
       or v_pattern=p_resource
       or (right(v_pattern,1)='*' and left(p_resource,length(v_pattern)-1)=left(v_pattern,length(v_pattern)-1)) then
      v_resource_match := true;
      exit;
    end if;
  end loop;

  if not v_resource_match then
    return jsonb_build_object('decision','DENY','reasonCode','RESOURCE_NOT_ALLOWED','reasonDetail','The resource is outside the grant''s resource scope.');
  end if;

  for v_key in select jsonb_object_keys(v_rules)
  loop
    if v_key not in ('maxAmount','allowedCurrencies','requireEvidence') then
      return jsonb_build_object('decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED','reasonDetail','The grant contains policy rules that require manual review.');
    end if;
  end loop;

  if jsonb_typeof(v_rules->'allowedCurrencies')='array' then
    if p_amount is not null and nullif(btrim(coalesce(p_currency,'')),'') is null then
      return jsonb_build_object('decision','DENY','reasonCode','CURRENCY_REQUIRED','reasonDetail','A currency is required for this monetary request.');
    end if;
    if p_currency is not null and not ((v_rules->'allowedCurrencies') ? upper(p_currency)) then
      return jsonb_build_object('decision','DENY','reasonCode','CURRENCY_NOT_ALLOWED','reasonDetail','The requested currency is not permitted by the grant.');
    end if;
  end if;

  if v_rules ? 'maxAmount' and p_amount is not null then
    begin
      v_limit := (v_rules->>'maxAmount')::numeric;
    exception when others then
      return jsonb_build_object('decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED','reasonDetail','The amount rule could not be evaluated automatically.');
    end;

    if p_amount < 0 then
      return jsonb_build_object('decision','DENY','reasonCode','AMOUNT_INVALID','reasonDetail','The requested amount is invalid.');
    end if;

    if p_amount > v_limit then
      if upper(coalesce(v_escalation->>'aboveLimit',''))='ESCALATE' then
        return jsonb_build_object('decision','ESCALATE','reasonCode','AMOUNT_ABOVE_LIMIT','reasonDetail','The amount exceeds the grant limit and requires escalation.');
      end if;
      return jsonb_build_object('decision','DENY','reasonCode','AMOUNT_ABOVE_LIMIT','reasonDetail','The amount exceeds the grant limit.');
    end if;
  end if;

  if coalesce((v_rules->>'requireEvidence')::boolean,false)
     and (p_evidence is null or p_evidence='{}'::jsonb) then
    return jsonb_build_object('decision','ESCALATE','reasonCode','EVIDENCE_REQUIRED','reasonDetail','Supporting evidence is required before this request can proceed.');
  end if;

  if coalesce((v_escalation->>'always')::boolean,false) then
    return jsonb_build_object('decision','ESCALATE','reasonCode','MANUAL_REVIEW_REQUIRED','reasonDetail','This grant requires manual review for every request.');
  end if;

  return jsonb_build_object('decision','ALLOW','reasonCode','POLICY_SATISFIED','reasonDetail','The requested action satisfies the active authority grant.');
end;
$$;

revoke all on function public.trustrelay_evaluate_authority_v07(jsonb,text,text,numeric,text,jsonb) from public,anon,authenticated;
grant execute on function public.trustrelay_evaluate_authority_v07(jsonb,text,text,numeric,text,jsonb) to service_role;

