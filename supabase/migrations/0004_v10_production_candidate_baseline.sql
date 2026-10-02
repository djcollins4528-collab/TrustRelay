-- TrustRelay v1.0 production-candidate baseline reconstructed from live staging on 2026-10-01.
-- Apply after 0003_recorded_v09.sql.

create table if not exists public.billing_events ();
create table if not exists public.billing_plans ();
create table if not exists public.legal_acceptances ();
create table if not exists public.legal_documents ();
create table if not exists public.organization_billing ();
create table if not exists public.organization_onboarding ();
create table if not exists public.production_readiness_controls ();

alter table public.billing_events add column if not exists "id" text not null;
alter table public.billing_events add column if not exists "provider" text not null;
alter table public.billing_events add column if not exists "provider_event_id" text not null;
alter table public.billing_events add column if not exists "event_type" text not null;
alter table public.billing_events add column if not exists "organization_id" text;
alter table public.billing_events add column if not exists "payload_sha256" text not null;
alter table public.billing_events add column if not exists "livemode" boolean;
alter table public.billing_events add column if not exists "status" text not null;
alter table public.billing_events add column if not exists "error_code" text;
alter table public.billing_events add column if not exists "created_at" text not null;
alter table public.billing_events add column if not exists "processed_at" text;
alter table public.billing_plans add column if not exists "code" text not null;
alter table public.billing_plans add column if not exists "name" text not null;
alter table public.billing_plans add column if not exists "status" text default 'active'::text not null;
alter table public.billing_plans add column if not exists "billing_mode" text not null;
alter table public.billing_plans add column if not exists "monthly_price_cents" integer;
alter table public.billing_plans add column if not exists "currency" text default 'usd'::text not null;
alter table public.billing_plans add column if not exists "limits_json" text not null;
alter table public.billing_plans add column if not exists "features_json" text default '[]'::text not null;
alter table public.billing_plans add column if not exists "display_order" integer default 0 not null;
alter table public.billing_plans add column if not exists "created_at" text not null;
alter table public.billing_plans add column if not exists "updated_at" text not null;
alter table public.legal_acceptances add column if not exists "id" text not null;
alter table public.legal_acceptances add column if not exists "account_id" text not null;
alter table public.legal_acceptances add column if not exists "organization_id" text;
alter table public.legal_acceptances add column if not exists "document_id" text not null;
alter table public.legal_acceptances add column if not exists "acceptance_context" text not null;
alter table public.legal_acceptances add column if not exists "accepted_at" text not null;
alter table public.legal_acceptances add column if not exists "metadata_json" text default '{}'::text not null;
alter table public.legal_documents add column if not exists "id" text not null;
alter table public.legal_documents add column if not exists "document_type" text not null;
alter table public.legal_documents add column if not exists "version" text not null;
alter table public.legal_documents add column if not exists "title" text not null;
alter table public.legal_documents add column if not exists "status" text default 'draft'::text not null;
alter table public.legal_documents add column if not exists "url_path" text not null;
alter table public.legal_documents add column if not exists "content_sha256" text;
alter table public.legal_documents add column if not exists "effective_at" text;
alter table public.legal_documents add column if not exists "published_at" text;
alter table public.legal_documents add column if not exists "superseded_at" text;
alter table public.legal_documents add column if not exists "created_at" text not null;
alter table public.legal_documents add column if not exists "binding" boolean default false not null;
alter table public.legal_documents add column if not exists "counsel_reviewed" boolean default false not null;
alter table public.organization_billing add column if not exists "organization_id" text not null;
alter table public.organization_billing add column if not exists "provider" text default 'stripe'::text not null;
alter table public.organization_billing add column if not exists "plan_code" text not null;
alter table public.organization_billing add column if not exists "status" text default 'not_configured'::text not null;
alter table public.organization_billing add column if not exists "billing_email" text;
alter table public.organization_billing add column if not exists "provider_customer_id" text;
alter table public.organization_billing add column if not exists "provider_subscription_id" text;
alter table public.organization_billing add column if not exists "provider_price_id" text;
alter table public.organization_billing add column if not exists "seat_quantity" integer default 1 not null;
alter table public.organization_billing add column if not exists "current_period_start" text;
alter table public.organization_billing add column if not exists "current_period_end" text;
alter table public.organization_billing add column if not exists "trial_end" text;
alter table public.organization_billing add column if not exists "cancel_at_period_end" boolean default false not null;
alter table public.organization_billing add column if not exists "canceled_at" text;
alter table public.organization_billing add column if not exists "last_payment_at" text;
alter table public.organization_billing add column if not exists "last_payment_failure_at" text;
alter table public.organization_billing add column if not exists "metadata_json" text default '{}'::text not null;
alter table public.organization_billing add column if not exists "created_at" text not null;
alter table public.organization_billing add column if not exists "updated_at" text not null;
alter table public.organization_onboarding add column if not exists "organization_id" text not null;
alter table public.organization_onboarding add column if not exists "status" text default 'incomplete'::text not null;
alter table public.organization_onboarding add column if not exists "primary_contact_email" text;
alter table public.organization_onboarding add column if not exists "security_contact_email" text;
alter table public.organization_onboarding add column if not exists "billing_contact_email" text;
alter table public.organization_onboarding add column if not exists "legal_entity_name" text;
alter table public.organization_onboarding add column if not exists "legal_entity_country" text;
alter table public.organization_onboarding add column if not exists "legal_entity_region" text;
alter table public.organization_onboarding add column if not exists "legal_entity_address" text;
alter table public.organization_onboarding add column if not exists "completed_steps_json" text default '[]'::text not null;
alter table public.organization_onboarding add column if not exists "production_status" text default 'sandbox'::text not null;
alter table public.organization_onboarding add column if not exists "activation_requested_at" text;
alter table public.organization_onboarding add column if not exists "activation_reviewed_at" text;
alter table public.organization_onboarding add column if not exists "activation_reviewed_by_account_id" text;
alter table public.organization_onboarding add column if not exists "activation_notes" text;
alter table public.organization_onboarding add column if not exists "created_at" text not null;
alter table public.organization_onboarding add column if not exists "updated_at" text not null;
alter table public.production_readiness_controls add column if not exists "control_key" text not null;
alter table public.production_readiness_controls add column if not exists "category" text not null;
alter table public.production_readiness_controls add column if not exists "status" text not null;
alter table public.production_readiness_controls add column if not exists "required" boolean default true not null;
alter table public.production_readiness_controls add column if not exists "evidence" text;
alter table public.production_readiness_controls add column if not exists "owner_note" text;
alter table public.production_readiness_controls add column if not exists "updated_at" text not null;

-- Constraints
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_events' and con.conname='billing_event_hash_v10') then
  alter table public.billing_events add constraint "billing_event_hash_v10" CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'::text);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_events' and con.conname='billing_event_status_v10') then
  alter table public.billing_events add constraint "billing_event_status_v10" CHECK (status = ANY (ARRAY['received'::text, 'processed'::text, 'ignored'::text, 'failed'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_events' and con.conname='billing_events_organization_id_fkey') then
  alter table public.billing_events add constraint "billing_events_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_events' and con.conname='billing_events_pkey') then
  alter table public.billing_events add constraint "billing_events_pkey" PRIMARY KEY (id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_events' and con.conname='billing_events_provider_provider_event_id_key') then
  alter table public.billing_events add constraint "billing_events_provider_provider_event_id_key" UNIQUE (provider, provider_event_id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_plans' and con.conname='billing_plan_mode_v10') then
  alter table public.billing_plans add constraint "billing_plan_mode_v10" CHECK (billing_mode = ANY (ARRAY['free'::text, 'subscription'::text, 'contract'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_plans' and con.conname='billing_plan_price_v10') then
  alter table public.billing_plans add constraint "billing_plan_price_v10" CHECK (monthly_price_cents IS NULL OR monthly_price_cents >= 0);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_plans' and con.conname='billing_plan_status_v10') then
  alter table public.billing_plans add constraint "billing_plan_status_v10" CHECK (status = ANY (ARRAY['active'::text, 'hidden'::text, 'retired'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='billing_plans' and con.conname='billing_plans_pkey') then
  alter table public.billing_plans add constraint "billing_plans_pkey" PRIMARY KEY (code);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptance_context_v10') then
  alter table public.legal_acceptances add constraint "legal_acceptance_context_v10" CHECK (acceptance_context = ANY (ARRAY['consumer'::text, 'organization'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptances_account_id_fkey') then
  alter table public.legal_acceptances add constraint "legal_acceptances_account_id_fkey" FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_documents' and con.conname='legal_documents_pkey') then
  alter table public.legal_documents add constraint "legal_documents_pkey" PRIMARY KEY (id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptances_account_id_organization_id_document_id_key') then
  alter table public.legal_acceptances add constraint "legal_acceptances_account_id_organization_id_document_id_key" UNIQUE (account_id, organization_id, document_id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptances_document_id_fkey') then
  alter table public.legal_acceptances add constraint "legal_acceptances_document_id_fkey" FOREIGN KEY (document_id) REFERENCES legal_documents(id) ON DELETE RESTRICT;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptances_organization_id_fkey') then
  alter table public.legal_acceptances add constraint "legal_acceptances_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_acceptances' and con.conname='legal_acceptances_pkey') then
  alter table public.legal_acceptances add constraint "legal_acceptances_pkey" PRIMARY KEY (id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_documents' and con.conname='legal_document_hash_v10') then
  alter table public.legal_documents add constraint "legal_document_hash_v10" CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'::text);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_documents' and con.conname='legal_document_status_v10') then
  alter table public.legal_documents add constraint "legal_document_status_v10" CHECK (status = ANY (ARRAY['draft'::text, 'published'::text, 'superseded'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_documents' and con.conname='legal_document_type_v10') then
  alter table public.legal_documents add constraint "legal_document_type_v10" CHECK (document_type = ANY (ARRAY['consumer_terms'::text, 'privacy_notice'::text, 'business_terms'::text, 'dpa'::text, 'acceptable_use'::text, 'security_statement'::text, 'subprocessors'::text, 'retention_notice'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='legal_documents' and con.conname='legal_documents_document_type_version_key') then
  alter table public.legal_documents add constraint "legal_documents_document_type_version_key" UNIQUE (document_type, version);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_billing' and con.conname='org_billing_seats_v10') then
  alter table public.organization_billing add constraint "org_billing_seats_v10" CHECK (seat_quantity >= 1 AND seat_quantity <= 10000);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_billing' and con.conname='org_billing_status_v10') then
  alter table public.organization_billing add constraint "org_billing_status_v10" CHECK (status = ANY (ARRAY['not_configured'::text, 'trialing'::text, 'active'::text, 'past_due'::text, 'canceled'::text, 'unpaid'::text, 'manual_contract'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_billing' and con.conname='organization_billing_organization_id_fkey') then
  alter table public.organization_billing add constraint "organization_billing_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_billing' and con.conname='organization_billing_pkey') then
  alter table public.organization_billing add constraint "organization_billing_pkey" PRIMARY KEY (organization_id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_billing' and con.conname='organization_billing_plan_code_fkey') then
  alter table public.organization_billing add constraint "organization_billing_plan_code_fkey" FOREIGN KEY (plan_code) REFERENCES billing_plans(code) ON DELETE RESTRICT;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_onboarding' and con.conname='org_onboarding_status_v10') then
  alter table public.organization_onboarding add constraint "org_onboarding_status_v10" CHECK (status = ANY (ARRAY['incomplete'::text, 'ready'::text, 'blocked'::text, 'complete'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_onboarding' and con.conname='org_production_status_v10') then
  alter table public.organization_onboarding add constraint "org_production_status_v10" CHECK (production_status = ANY (ARRAY['sandbox'::text, 'requested'::text, 'approved'::text, 'blocked'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_onboarding' and con.conname='organization_onboarding_activation_reviewed_by_account_id_fkey') then
  alter table public.organization_onboarding add constraint "organization_onboarding_activation_reviewed_by_account_id_fkey" FOREIGN KEY (activation_reviewed_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_onboarding' and con.conname='organization_onboarding_organization_id_fkey') then
  alter table public.organization_onboarding add constraint "organization_onboarding_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='organization_onboarding' and con.conname='organization_onboarding_pkey') then
  alter table public.organization_onboarding add constraint "organization_onboarding_pkey" PRIMARY KEY (organization_id);
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='production_readiness_controls' and con.conname='production_control_status_v10') then
  alter table public.production_readiness_controls add constraint "production_control_status_v10" CHECK (status = ANY (ARRAY['pass'::text, 'fail'::text, 'unknown'::text, 'not_applicable'::text]));
 end if;
end $mig$;
do $mig$ begin
 if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='production_readiness_controls' and con.conname='production_readiness_controls_pkey') then
  alter table public.production_readiness_controls add constraint "production_readiness_controls_pkey" PRIMARY KEY (control_key);
 end if;
end $mig$;

-- Non-constraint indexes
CREATE INDEX IF NOT EXISTS idx_billing_events_org_created ON public.billing_events USING btree (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_legal_acceptance_account ON public.legal_acceptances USING btree (account_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_legal_acceptance_org ON public.legal_acceptances USING btree (organization_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_legal_acceptances_document_v09 ON public.legal_acceptances USING btree (document_id);
CREATE INDEX IF NOT EXISTS idx_org_billing_customer ON public.organization_billing USING btree (provider_customer_id);
CREATE INDEX IF NOT EXISTS idx_org_billing_plan_code_v09 ON public.organization_billing USING btree (plan_code);
CREATE INDEX IF NOT EXISTS idx_org_billing_status ON public.organization_billing USING btree (status, plan_code);
CREATE INDEX IF NOT EXISTS idx_org_billing_subscription ON public.organization_billing USING btree (provider_subscription_id);
CREATE INDEX IF NOT EXISTS idx_org_onboarding_reviewed_by ON public.organization_onboarding USING btree (activation_reviewed_by_account_id);

-- RLS and policies
alter table public.billing_events enable row level security;
alter table public.billing_plans enable row level security;
alter table public.legal_acceptances enable row level security;
alter table public.legal_documents enable row level security;
alter table public.organization_billing enable row level security;
alter table public.organization_onboarding enable row level security;
alter table public.production_readiness_controls enable row level security;
drop policy if exists "trustrelay_deny_clients" on public.billing_events;
create policy "trustrelay_deny_clients" on public.billing_events as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.billing_plans;
create policy "trustrelay_deny_clients" on public.billing_plans as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.legal_acceptances;
create policy "trustrelay_deny_clients" on public.legal_acceptances as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.legal_documents;
create policy "trustrelay_deny_clients" on public.legal_documents as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.organization_billing;
create policy "trustrelay_deny_clients" on public.organization_billing as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.organization_onboarding;
create policy "trustrelay_deny_clients" on public.organization_onboarding as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.production_readiness_controls;
create policy "trustrelay_deny_clients" on public.production_readiness_controls as restrictive for all to anon, authenticated using (false) with check (false);

-- Seed billing_plans
insert into public.billing_plans("code","name","status","billing_mode","monthly_price_cents","currency","limits_json","features_json","display_order","created_at","updated_at") values('sandbox','Sandbox','active','free',0,'usd','{"members":5,"apiKeys":2,"webhooks":2,"decisionsPerMonth":1000,"exportsPerMonth":5}','["Sandbox organization","Test API keys","Signed webhooks","Compliance exports"]',0,'2026-10-01T21:00:24.053Z','2026-10-01T21:00:24.054Z') on conflict(code) do nothing;
insert into public.billing_plans("code","name","status","billing_mode","monthly_price_cents","currency","limits_json","features_json","display_order","created_at","updated_at") values('starter','Starter','active','subscription',null,'usd','{"members":10,"apiKeys":5,"webhooks":5,"decisionsPerMonth":25000,"exportsPerMonth":25}','["Live authorization","Identity assurance","Signed webhooks","Compliance exports"]',10,'2026-10-01T21:00:24.055Z','2026-10-01T21:00:24.055Z') on conflict(code) do nothing;
insert into public.billing_plans("code","name","status","billing_mode","monthly_price_cents","currency","limits_json","features_json","display_order","created_at","updated_at") values('growth','Growth','active','subscription',null,'usd','{"members":50,"apiKeys":20,"webhooks":20,"decisionsPerMonth":250000,"exportsPerMonth":100}','["Higher limits","Advanced evidence workflow","Priority operations","Compliance exports"]',20,'2026-10-01T21:00:24.055Z','2026-10-01T21:00:24.055Z') on conflict(code) do nothing;
insert into public.billing_plans("code","name","status","billing_mode","monthly_price_cents","currency","limits_json","features_json","display_order","created_at","updated_at") values('enterprise','Enterprise','active','contract',null,'usd','{"members":null,"apiKeys":null,"webhooks":null,"decisionsPerMonth":null,"exportsPerMonth":null}','["Contract billing","Custom limits","Production onboarding","Enterprise support"]',30,'2026-10-01T21:00:24.055Z','2026-10-01T21:00:24.055Z') on conflict(code) do nothing;

-- Seed legal_documents
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_consumer_terms_v1_0','consumer_terms','1.0-draft','Consumer Terms of Service','superseded','/legal/terms.html',null,null,null,'2026-10-01T21:17:09.856Z','2026-10-01T21:07:47.669Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_privacy_v1_0','privacy_notice','1.0-draft','Privacy Notice','superseded','/legal/privacy.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.676Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_acceptable_use_v1_0','acceptable_use','1.0-draft','Acceptable Use Policy','superseded','/legal/acceptable-use.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.677Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_business_terms_v1_0','business_terms','1.0-draft','Business Terms','superseded','/legal/business-terms.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.677Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_dpa_v1_0','dpa','1.0-draft','Data Processing Addendum','superseded','/legal/dpa.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.677Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_security_v1_0','security_statement','1.0-draft','Security Statement','superseded','/legal/security.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.677Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_retention_v1_0','retention_notice','1.0-draft','Retention Notice','superseded','/legal/retention.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.678Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_subprocessors_v1_0','subprocessors','1.0-draft','Subprocessor List','superseded','/legal/subprocessors.html',null,null,null,'2026-10-01T21:17:09.860Z','2026-10-01T21:07:47.678Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_consumer_terms','consumer_terms','1.0-draft-2026-10-01','Consumer Terms of Service','published','/legal/terms.html','49acd44e62e5a0a88ea3377467e5db33566e728f855237784f4ea014cf025d7a',null,'2026-10-01T21:08:53.329Z',null,'2026-10-01T21:08:53.330Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_aup','acceptable_use','1.0-draft-2026-10-01','Acceptable Use Policy','published','/legal/acceptable-use.html','a7d51aab8dce4777c6e2ef935d2afb6f2253a1415ce2400a401d6d1a56290498',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_business_terms','business_terms','1.0-draft-2026-10-01','Business Terms','published','/legal/business-terms.html','ae82eebb1e4b50b368befe42784789b733ab630df18c9071528bdd14a5dca3f1',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_dpa','dpa','1.0-draft-2026-10-01','Data Processing Addendum','published','/legal/dpa.html','670c2424cbe00a898d5a9068a0c139fadfaf6494d6540bf6bbe0974eb4a31054',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_privacy','privacy_notice','1.0-draft-2026-10-01','Privacy Notice','published','/legal/privacy.html','74515bd74e802be908c17b434a0c50530874edab88deddce05ed89908eebbbd4',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_retention','retention_notice','1.0-draft-2026-10-01','Data Retention Notice','published','/legal/retention.html','7c518246c06c2fc2eab690ae3d93264a39411aa165b463819c320abd3a095e59',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_security','security_statement','1.0-draft-2026-10-01','Security Statement','published','/legal/security.html','d8e6326f242d02476e8c34d8f54bb787a7917aa84bc69741a11841aed70eb0d1',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;
insert into public.legal_documents("id","document_type","version","title","status","url_path","content_sha256","effective_at","published_at","superseded_at","created_at","binding","counsel_reviewed") values('legal_v10_subprocessors','subprocessors','1.0-draft-2026-10-01','Subprocessors','published','/legal/subprocessors.html','41ed9fd21f3cfd3c6d7925e4869e1ac184506a8d64b422cc348218cf7f3b079c',null,'2026-10-01T21:08:53.331Z',null,'2026-10-01T21:08:53.331Z',false,false) on conflict(id) do nothing;

-- Seed production_readiness_controls
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('backup_recovery','availability','unknown',true,null,'Confirm paid-plan backups/PITR and recovery procedure.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('custom_smtp','availability','fail',true,null,'Configure branded transactional SMTP for production Auth email.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('billing_provider','commercial','fail',true,'Stripe provider has not yet been connected/configured.','Connect Stripe and configure live price IDs + webhook secret.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('reviewer_governance','identity','fail',true,null,'Provision production reviewers and approve reviewer access/dual-control procedure.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('custom_domain','infrastructure','fail',true,null,'Attach production custom domain before commercial launch.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('production_backend_isolation','infrastructure','fail',true,'Current Supabase project is named trustrelay-staging.','Provision a separate production Supabase project before commercial launch.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('legal_counsel_review','legal','fail',true,null,'Terms, Privacy Notice and DPA must be reviewed/approved by qualified counsel.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('legal_entity','legal','fail',true,null,'Legal contracting entity and address must be confirmed before commercial launch.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('legal_package_published','legal','fail',true,null,'Publish counsel-approved Consumer Terms, Privacy Notice, Business Terms, DPA and Acceptable Use versions before launch.','2026-10-01T21:15:12.453Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('incident_response_plan','operations','fail',true,null,'Approve incident response, escalation and notification procedures.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('security_contact','operations','fail',true,null,'Configure monitored security contact route and incident owner.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('privacy_request_process','privacy','fail',true,null,'Approve and staff access/deletion/correction request handling.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('retention_automation','privacy','fail',true,null,'Implement and validate automated deletion/retention jobs before production data is accepted.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('auth_abuse_protection','security','unknown',true,null,'Confirm production Auth rate limits and CAPTCHA/abuse controls.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('database_network_restrictions','security','unknown',true,null,'Confirm production database network restrictions.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('database_ssl_enforcement','security','unknown',true,null,'Confirm SSL enforcement in Supabase Dashboard.','2026-10-01T21:00:24.065Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('malware_scanning','security','fail',true,null,'Identity/evidence uploads currently receive type/size/hash validation but no dedicated malware scan.','2026-10-01T21:15:12.467Z') on conflict(control_key) do nothing;
insert into public.production_readiness_controls("control_key","category","status","required","evidence","owner_note","updated_at") values('security_advisor','security','pass',true,'Supabase Security Advisor has no TrustRelay-specific warnings.','Known Free-plan leaked-password advisory remains; user auth is passwordless.','2026-10-01T21:00:24.064Z') on conflict(control_key) do nothing;

-- Functions
CREATE OR REPLACE FUNCTION private.trustrelay_accept_legal_v10(p_uid uuid, p_document_id text, p_org_id text, p_context text, p_metadata jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_account_id text;
  v_doc public.legal_documents%rowtype;
  v_perm jsonb;
  v_id text:='legalacc_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';

  if p_context not in ('consumer','organization') then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_CONTEXT_INVALID');
  end if;

  select * into v_doc
  from public.legal_documents
  where id=p_document_id and status='published';

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','LEGAL_DOCUMENT_NOT_PUBLISHED');
  end if;

  if not v_doc.binding or v_doc.effective_at is null or not v_doc.counsel_reviewed then
    return jsonb_build_object('ok',false,'status',409,'code','LEGAL_DOCUMENT_NOT_EFFECTIVE');
  end if;

  if p_context='consumer' then
    if p_org_id is not null then
      return jsonb_build_object('ok',false,'status',400,'code','LEGAL_ORGANIZATION_UNEXPECTED');
    end if;
    if v_doc.document_type not in ('consumer_terms','privacy_notice','acceptable_use') then
      return jsonb_build_object('ok',false,'status',400,'code','LEGAL_DOCUMENT_CONTEXT_MISMATCH');
    end if;
  else
    if p_org_id is null then
      return jsonb_build_object('ok',false,'status',400,'code','LEGAL_ORGANIZATION_REQUIRED');
    end if;
    v_perm:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
    if coalesce((v_perm->>'ok')::boolean,false)=false then return v_perm; end if;
    if v_doc.document_type not in ('business_terms','dpa','acceptable_use','security_statement','subprocessors','retention_notice','privacy_notice') then
      return jsonb_build_object('ok',false,'status',400,'code','LEGAL_DOCUMENT_CONTEXT_MISMATCH');
    end if;
  end if;

  insert into public.legal_acceptances(
    id,account_id,organization_id,document_id,acceptance_context,accepted_at,metadata_json
  ) values (
    v_id,v_account_id,p_org_id,p_document_id,p_context,v_now,coalesce(p_metadata,'{}'::jsonb)::text
  )
  on conflict(account_id,organization_id,document_id) do nothing;

  if p_org_id is not null then
    perform private.trustrelay_append_org_audit_v09(
      p_org_id,v_account_id,'legal.document.accepted','legal_document',p_document_id,
      jsonb_build_object(
        'documentType',v_doc.document_type,'version',v_doc.version,
        'contentSha256',v_doc.content_sha256,'effectiveAt',v_doc.effective_at
      )
    );
  end if;

  return jsonb_build_object(
    'ok',true,'documentId',p_document_id,'documentType',v_doc.document_type,
    'version',v_doc.version,'contentSha256',v_doc.content_sha256,'acceptedAt',v_now
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_billing_status_v10(p_uid uuid, p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_bill public.organization_billing%rowtype;
  v_plan public.billing_plans%rowtype;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(p_uid,p_org_id,null);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_bill from public.organization_billing where organization_id=p_org_id;
  select * into v_plan from public.billing_plans where code=v_bill.plan_code;

  return jsonb_build_object(
    'ok',true,
    'billing',jsonb_build_object(
      'provider',v_bill.provider,'planCode',v_bill.plan_code,'status',v_bill.status,
      'billingEmail',v_bill.billing_email,'seatQuantity',v_bill.seat_quantity,
      'currentPeriodStart',v_bill.current_period_start,'currentPeriodEnd',v_bill.current_period_end,
      'trialEnd',v_bill.trial_end,'cancelAtPeriodEnd',v_bill.cancel_at_period_end,
      'hasCustomer',v_bill.provider_customer_id is not null,
      'hasSubscription',v_bill.provider_subscription_id is not null
    ),
    'currentPlan',jsonb_build_object(
      'code',v_plan.code,'name',v_plan.name,'billingMode',v_plan.billing_mode,
      'monthlyPriceCents',v_plan.monthly_price_cents,'currency',v_plan.currency,
      'limits',coalesce(v_plan.limits_json::jsonb,'{}'::jsonb),
      'features',coalesce(v_plan.features_json::jsonb,'[]'::jsonb)
    ),
    'plans',coalesce((
      select jsonb_agg(jsonb_build_object(
        'code',p.code,'name',p.name,'billingMode',p.billing_mode,
        'monthlyPriceCents',p.monthly_price_cents,'currency',p.currency,
        'limits',coalesce(p.limits_json::jsonb,'{}'::jsonb),
        'features',coalesce(p.features_json::jsonb,'[]'::jsonb)
      ) order by p.display_order)
      from public.billing_plans p where p.status='active'
    ),'[]'::jsonb)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_create_organization_v07(p_uid uuid, p_name text, p_industry text, p_website text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'vault', 'extensions', 'pg_catalog'
AS $function$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_org_id text:='org_'||replace(gen_random_uuid()::text,'-','');
  v_slug text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_raw_key text;
  v_hash text;
  v_key_id text:='key_'||replace(gen_random_uuid()::text,'-','');
  v_secret_id uuid;
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;
  if not found then return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND'); end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>120 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_NAME_INVALID');
  end if;

  v_slug:=regexp_replace(lower(btrim(p_name)),'[^a-z0-9]+','-','g');
  v_slug:=regexp_replace(v_slug,'(^-+|-+$)','','g');
  if length(v_slug)<2 then v_slug:='organization'; end if;
  v_slug:=left(v_slug,48)||'-'||substr(replace(gen_random_uuid()::text,'-',''),1,8);

  insert into public.organizations(
    id,name,slug,mode,status,created_at,created_by_account_id,industry,website,updated_at
  ) values (
    v_org_id,btrim(p_name),v_slug,'sandbox','active',v_now,v_account.id,
    nullif(btrim(coalesce(p_industry,'')),''),
    nullif(btrim(coalesce(p_website,'')),''),
    v_now
  ) returning * into v_org;

  -- Create billing/onboarding first so all subsequent capacity checks have a plan context.
  insert into public.organization_billing(
    organization_id,provider,plan_code,status,billing_email,seat_quantity,
    metadata_json,created_at,updated_at
  ) values(
    v_org_id,'stripe','sandbox','not_configured',v_account.email,1,
    '{}',v_now,v_now
  );

  insert into public.organization_onboarding(
    organization_id,status,primary_contact_email,security_contact_email,billing_contact_email,
    completed_steps_json,production_status,created_at,updated_at
  ) values(
    v_org_id,'incomplete',v_account.email,null,v_account.email,
    '[]','sandbox',v_now,v_now
  );

  insert into public.organization_members(
    organization_id,account_id,role,created_at,status,title,updated_at
  ) values(v_org_id,v_account.id,'owner',v_now,'active','Owner',v_now);

  v_raw_key:='tr_portal_'||encode(gen_random_bytes(32),'hex');
  v_hash:=encode(digest(v_raw_key,'sha256'),'hex');
  v_secret_id:=vault.create_secret(
    v_raw_key,'trustrelay-portal-'||v_org_id,'TrustRelay internal verifier portal key'
  );

  insert into public.api_keys(
    id,organization_id,name,prefix,key_hash,scopes_json,created_at,
    key_type,created_by_account_id,last_four,secret_vault_id,updated_at
  ) values (
    v_key_id,v_org_id,'Verifier Portal','tr_portal',v_hash,
    '["decisions:read","decisions:write"]',v_now,
    'portal',v_account.id,right(v_raw_key,4),v_secret_id,v_now
  );

  perform private.trustrelay_append_org_audit_v09(
    v_org_id,v_account.id,'organization.created','organization',v_org_id,
    jsonb_build_object(
      'name',v_org.name,'slug',v_org.slug,'mode',v_org.mode,'industry',v_org.industry,
      'billingPlan','sandbox','productionStatus','sandbox'
    )
  );
  perform private.trustrelay_append_org_audit_v09(
    v_org_id,v_account.id,'api_key.created','api_key',v_key_id,
    jsonb_build_object(
      'name','Verifier Portal','keyType','portal',
      'scopes',jsonb_build_array('decisions:read','decisions:write')
    )
  );

  return jsonb_build_object(
    'ok',true,
    'organization',to_jsonb(v_org),
    'membership',jsonb_build_object('role','owner','status','active'),
    'billing',jsonb_build_object('planCode','sandbox','status','not_configured'),
    'onboarding',jsonb_build_object('status','incomplete','productionStatus','sandbox')
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_enforce_plan_capacity_v10()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_org_id text;
  v_metric text;
  v_check jsonb;
  v_should_check boolean:=true;
begin
  if TG_TABLE_NAME='organization_members' then
    v_org_id:=new.organization_id;
    v_metric:='members';
    if new.status<>'active' then v_should_check:=false; end if;
    if TG_OP='UPDATE' and old.status='active' then v_should_check:=false; end if;

  elsif TG_TABLE_NAME='api_keys' then
    v_org_id:=new.organization_id;
    v_metric:='api_keys';
    if new.key_type<>'partner' or new.revoked_at is not null then v_should_check:=false; end if;
    if TG_OP='UPDATE' and old.key_type='partner' and old.revoked_at is null then v_should_check:=false; end if;

  elsif TG_TABLE_NAME='webhook_subscriptions' then
    v_org_id:=new.organization_id;
    v_metric:='webhooks';
    if new.status not in ('active','paused') then v_should_check:=false; end if;
    if TG_OP='UPDATE' and old.status in ('active','paused') then v_should_check:=false; end if;

  elsif TG_TABLE_NAME='authorization_decisions' then
    v_org_id:=new.organization_id;
    v_metric:='decisions';
    if v_org_id is null then v_should_check:=false; end if;

  elsif TG_TABLE_NAME='compliance_exports' then
    v_org_id:=new.organization_id;
    v_metric:='exports';

  else
    return new;
  end if;

  if not v_should_check or v_org_id is null then return new; end if;

  v_check:=private.trustrelay_plan_limit_v10(v_org_id,v_metric);
  if coalesce((v_check->>'ok')::boolean,false)=false then
    raise exception 'BILLING_PLAN_MISSING' using errcode='P0001';
  end if;

  if coalesce((v_check->>'allowed')::boolean,false)=false then
    raise exception 'PLAN_LIMIT_EXCEEDED:%:%:%',
      v_metric,coalesce(v_check->>'current','0'),coalesce(v_check->>'limit','0')
      using errcode='P0001';
  end if;

  return new;
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_enforce_plan_limit_v10()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_org_id text;
  v_metric text;
  v_should_count boolean:=true;
  v_limit jsonb;
begin
  if tg_table_name='organization_members' then
    v_org_id:=new.organization_id;
    v_metric:='members';
    v_should_count:=new.status='active' and (tg_op='INSERT' or old.status<>'active');
  elsif tg_table_name='api_keys' then
    v_org_id:=new.organization_id;
    v_metric:='api_keys';
    v_should_count:=new.key_type='partner' and new.revoked_at is null
      and (tg_op='INSERT' or old.revoked_at is not null or old.key_type<>'partner');
  elsif tg_table_name='webhook_subscriptions' then
    v_org_id:=new.organization_id;
    v_metric:='webhooks';
    v_should_count:=new.status in ('active','paused')
      and (tg_op='INSERT' or old.status not in ('active','paused'));
  elsif tg_table_name='compliance_exports' then
    v_org_id:=new.organization_id;
    v_metric:='exports';
    v_should_count:=tg_op='INSERT';
  elsif tg_table_name='authorization_decisions' then
    v_org_id:=new.organization_id;
    v_metric:='decisions';
    v_should_count:=tg_op='INSERT' and new.organization_id is not null;
  else
    return new;
  end if;

  if not v_should_count or v_org_id is null then return new; end if;

  perform pg_advisory_xact_lock(hashtext('trustrelay_plan_limit_'||v_org_id||'_'||v_metric));
  v_limit:=private.trustrelay_plan_limit_v10(v_org_id,v_metric);

  if coalesce((v_limit->>'ok')::boolean,false)=false then
    raise exception using errcode='P0001', message='PLAN_CONFIGURATION_INVALID:'||v_metric;
  end if;

  if coalesce((v_limit->>'allowed')::boolean,true)=false then
    raise exception using errcode='P0001', message='PLAN_LIMIT_EXCEEDED:'||v_metric;
  end if;

  return new;
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_latest_legal_documents_v10()
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
  select coalesce(jsonb_agg(jsonb_build_object(
    'id',x.id,'documentType',x.document_type,'version',x.version,'title',x.title,
    'urlPath',x.url_path,'contentSha256',x.content_sha256,
    'effectiveAt',x.effective_at,'publishedAt',x.published_at,
    'binding',x.binding,'counselReviewed',x.counsel_reviewed
  ) order by x.document_type),'[]'::jsonb)
  from (
    select distinct on (document_type) *
    from public.legal_documents
    where status='published'
    order by document_type,published_at desc nulls last,created_at desc
  ) x;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_org_onboarding_v10(p_uid uuid, p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_org public.organizations%rowtype;
  v_on public.organization_onboarding%rowtype;
  v_bill public.organization_billing%rowtype;
  v_plan public.billing_plans%rowtype;
  v_docs jsonb;
  v_required jsonb;
  v_effective_required_count integer;
  v_owner_count integer;
  v_blockers jsonb:='[]'::jsonb;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(p_uid,p_org_id,null);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_org from public.organizations where id=p_org_id;
  select * into v_on from public.organization_onboarding where organization_id=p_org_id;
  select * into v_bill from public.organization_billing where organization_id=p_org_id;
  select * into v_plan from public.billing_plans where code=v_bill.plan_code;
  v_docs:=private.trustrelay_latest_legal_documents_v10();

  select count(*) into v_effective_required_count
  from jsonb_array_elements(v_docs) d
  where d->>'documentType' in ('business_terms','dpa','acceptable_use')
    and coalesce((d->>'binding')::boolean,false)
    and d->>'effectiveAt' is not null;

  select coalesce(jsonb_agg(d),'[]'::jsonb) into v_required
  from jsonb_array_elements(v_docs) d
  where d->>'documentType' in ('business_terms','dpa','acceptable_use')
    and coalesce((d->>'binding')::boolean,false)
    and d->>'effectiveAt' is not null
    and not exists(
      select 1
      from public.legal_acceptances a
      where a.organization_id=p_org_id and a.document_id=d->>'id'
    );

  select count(*) into v_owner_count
  from public.organization_members
  where organization_id=p_org_id and status='active' and role='owner';

  if length(btrim(coalesce(v_org.website,'')))<8 then
    v_blockers:=v_blockers||jsonb_build_array('ORGANIZATION_WEBSITE_REQUIRED');
  end if;
  if length(btrim(coalesce(v_on.primary_contact_email,'')))<5 then
    v_blockers:=v_blockers||jsonb_build_array('PRIMARY_CONTACT_REQUIRED');
  end if;
  if length(btrim(coalesce(v_on.security_contact_email,'')))<5 then
    v_blockers:=v_blockers||jsonb_build_array('SECURITY_CONTACT_REQUIRED');
  end if;
  if length(btrim(coalesce(v_on.billing_contact_email,'')))<5 then
    v_blockers:=v_blockers||jsonb_build_array('BILLING_CONTACT_REQUIRED');
  end if;
  if length(btrim(coalesce(v_on.legal_entity_name,'')))<2 then
    v_blockers:=v_blockers||jsonb_build_array('LEGAL_ENTITY_REQUIRED');
  end if;
  if v_effective_required_count<3 then
    v_blockers:=v_blockers||jsonb_build_array('EFFECTIVE_LEGAL_PACKAGE_REQUIRED');
  elsif jsonb_array_length(v_required)>0 then
    v_blockers:=v_blockers||jsonb_build_array('LEGAL_ACCEPTANCE_REQUIRED');
  end if;
  if coalesce(v_bill.status,'not_configured') not in ('active','trialing','manual_contract') then
    v_blockers:=v_blockers||jsonb_build_array('BILLING_NOT_ACTIVE');
  end if;
  if v_owner_count<1 then
    v_blockers:=v_blockers||jsonb_build_array('OWNER_REQUIRED');
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',to_jsonb(v_org),
    'membership',jsonb_build_object(
      'role',v_ctx->>'role',
      'permissions',public.trustrelay_org_permissions_v09(v_ctx->>'role')
    ),
    'onboarding',to_jsonb(v_on),
    'billing',jsonb_build_object(
      'provider',v_bill.provider,'planCode',v_bill.plan_code,'status',v_bill.status,
      'billingEmail',v_bill.billing_email,'seatQuantity',v_bill.seat_quantity,
      'currentPeriodStart',v_bill.current_period_start,'currentPeriodEnd',v_bill.current_period_end,
      'trialEnd',v_bill.trial_end,'cancelAtPeriodEnd',v_bill.cancel_at_period_end
    ),
    'plan',jsonb_build_object(
      'code',v_plan.code,'name',v_plan.name,'billingMode',v_plan.billing_mode,
      'monthlyPriceCents',v_plan.monthly_price_cents,'currency',v_plan.currency,
      'limits',coalesce(v_plan.limits_json::jsonb,'{}'::jsonb),
      'features',coalesce(v_plan.features_json::jsonb,'[]'::jsonb)
    ),
    'publishedLegalDocuments',v_docs,
    'requiredLegalAcceptances',v_required,
    'effectiveLegalPackagePublished',v_effective_required_count>=3,
    'blockers',v_blockers,
    'readyForProductionRequest',jsonb_array_length(v_blockers)=0,
    'ownerCount',v_owner_count
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_org_runtime_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_org public.organizations%rowtype;
  v_on public.organization_onboarding%rowtype;
  v_bill public.organization_billing%rowtype;
  v_plan public.billing_plans%rowtype;
begin
  select * into v_org from public.organizations where id=p_org_id;
  if not found or v_org.status<>'active' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INACTIVE');
  end if;

  select * into v_on from public.organization_onboarding where organization_id=p_org_id;
  select * into v_bill from public.organization_billing where organization_id=p_org_id;
  select * into v_plan from public.billing_plans where code=v_bill.plan_code;

  if v_org.mode='live' then
    if coalesce(v_on.production_status,'sandbox')<>'approved' then
      return jsonb_build_object('ok',false,'status',403,'code','PRODUCTION_APPROVAL_REQUIRED');
    end if;
    if coalesce(v_bill.status,'not_configured') not in ('active','trialing','manual_contract') then
      return jsonb_build_object('ok',false,'status',402,'code','BILLING_INACTIVE');
    end if;
  end if;

  return jsonb_build_object(
    'ok',true,
    'organization',jsonb_build_object('id',v_org.id,'name',v_org.name,'mode',v_org.mode,'status',v_org.status),
    'billing',jsonb_build_object('planCode',v_bill.plan_code,'status',v_bill.status),
    'limits',coalesce(v_plan.limits_json::jsonb,'{}'::jsonb)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_plan_limit_v10(p_org_id text, p_metric text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare
  v_bill public.organization_billing%rowtype;
  v_plan public.billing_plans%rowtype;
  v_limit integer;
  v_current integer:=0;
  v_key text;
  v_start timestamptz:=date_trunc('month',clock_timestamp());
begin
  select * into v_bill from public.organization_billing where organization_id=p_org_id;
  select * into v_plan from public.billing_plans where code=v_bill.plan_code;
  if not found then return jsonb_build_object('ok',false,'status',409,'code','BILLING_PLAN_MISSING'); end if;

  v_key:=case p_metric
    when 'members' then 'members'
    when 'api_keys' then 'apiKeys'
    when 'webhooks' then 'webhooks'
    when 'decisions' then 'decisionsPerMonth'
    when 'exports' then 'exportsPerMonth'
    else null end;
  if v_key is null then return jsonb_build_object('ok',false,'status',400,'code','PLAN_METRIC_INVALID'); end if;

  begin v_limit:=(v_plan.limits_json::jsonb->>v_key)::integer;
  exception when others then v_limit:=null; end;

  case p_metric
    when 'members' then
      select count(*) into v_current from public.organization_members
      where organization_id=p_org_id and status='active';
    when 'api_keys' then
      select count(*) into v_current from public.api_keys
      where organization_id=p_org_id and key_type='partner' and revoked_at is null;
    when 'webhooks' then
      select count(*) into v_current from public.webhook_subscriptions
      where organization_id=p_org_id and status in ('active','paused');
    when 'decisions' then
      select count(*) into v_current from public.authorization_decisions
      where organization_id=p_org_id and decided_at::timestamptz>=v_start;
    when 'exports' then
      select count(*) into v_current from public.compliance_exports
      where organization_id=p_org_id and created_at::timestamptz>=v_start;
  end case;

  return jsonb_build_object(
    'ok',true,'metric',p_metric,'planCode',v_plan.code,
    'current',v_current,'limit',v_limit,
    'allowed',v_limit is null or v_current<v_limit
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_platform_readiness_for_user_v10(p_uid uuid, p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_platform jsonb;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_platform:=private.trustrelay_platform_readiness_v10();

  return jsonb_build_object(
    'ok',true,
    'ready',coalesce((v_platform->>'ready')::boolean,false),
    'blockers',coalesce((
      select jsonb_agg(jsonb_build_object(
        'key',c.control_key,
        'category',c.category,
        'status',c.status,
        'ownerNote',c.owner_note
      ) order by c.category,c.control_key)
      from public.production_readiness_controls c
      where c.required=true and c.status<>'pass'
    ),'[]'::jsonb),
    'passed',coalesce(v_platform->'passed','[]'::jsonb)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_platform_readiness_v10()
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
  select jsonb_build_object(
    'ready',not exists(
      select 1 from public.production_readiness_controls
      where required=true and status<>'pass'
    ),
    'blockers',coalesce((
      select jsonb_agg(jsonb_build_object(
        'key',control_key,'category',category,'status',status
      ) order by category,control_key)
      from public.production_readiness_controls
      where required=true and status<>'pass'
    ),'[]'::jsonb),
    'passed',coalesce((
      select jsonb_agg(control_key order by control_key)
      from public.production_readiness_controls
      where required=true and status='pass'
    ),'[]'::jsonb)
  );
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_protect_legal_document_v10()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
begin
  if old.status='published' then
    if new.id<>old.id
       or new.document_type<>old.document_type
       or new.version<>old.version
       or new.url_path<>old.url_path
       or coalesce(new.content_sha256,'')<>coalesce(old.content_sha256,'')
       or new.created_at<>old.created_at then
      raise exception 'PUBLISHED_LEGAL_DOCUMENT_IMMUTABLE' using errcode='P0001';
    end if;
  end if;
  if new.binding and (new.effective_at is null or not new.counsel_reviewed or new.status<>'published') then
    raise exception 'BINDING_LEGAL_DOCUMENT_REQUIRES_EFFECTIVE_COUNSEL_REVIEWED_PUBLICATION' using errcode='P0001';
  end if;
  return new;
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_request_production_activation_v10(p_uid uuid, p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_onboard jsonb;
  v_platform jsonb;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_onboard:=private.trustrelay_org_onboarding_v10(p_uid,p_org_id);
  if coalesce((v_onboard->>'readyForProductionRequest')::boolean,false)=false then
    return jsonb_build_object(
      'ok',false,'status',409,'code','ORGANIZATION_ONBOARDING_INCOMPLETE',
      'blockers',v_onboard->'blockers'
    );
  end if;

  v_platform:=private.trustrelay_platform_readiness_v10();
  if coalesce((v_platform->>'ready')::boolean,false)=false then
    return jsonb_build_object(
      'ok',false,'status',503,'code','PLATFORM_NOT_PRODUCTION_READY',
      'platformBlockers',v_platform->'blockers'
    );
  end if;

  update public.organization_onboarding
  set status='ready',production_status='requested',activation_requested_at=v_now,updated_at=v_now
  where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','production.activation.requested','organization',p_org_id,'{}'::jsonb
  );

  return jsonb_build_object('ok',true,'organizationId',p_org_id,'productionStatus','requested','requestedAt',v_now);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_select_billing_plan_v10(p_uid uuid, p_org_id text, p_plan_code text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_plan public.billing_plans%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_plan from public.billing_plans where code=p_plan_code and status='active';
  if not found or v_plan.code='sandbox' then
    return jsonb_build_object('ok',false,'status',400,'code','BILLING_PLAN_INVALID');
  end if;

  update public.organization_billing
  set plan_code=p_plan_code,
      status=case when status in ('active','trialing','manual_contract') then status else 'not_configured' end,
      updated_at=v_now
  where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','billing.plan.selected','organization_billing',p_org_id,
    jsonb_build_object('planCode',p_plan_code)
  );

  return jsonb_build_object('ok',true,'planCode',p_plan_code,'billingMode',v_plan.billing_mode);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_session_guard_v10(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'auth', 'pg_catalog'
AS $function$
declare
  v_session text:=auth.jwt()->>'session_id';
begin
  if p_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;
  if v_session is null or v_session='' then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_ID_REQUIRED');
  end if;
  if not exists(
    select 1 from auth.sessions s
    where s.id::text=v_session
      and s.user_id=p_uid
      and (s.not_after is null or s.not_after>clock_timestamp())
  ) then
    return jsonb_build_object('ok',false,'status',401,'code','SESSION_NOT_ACTIVE');
  end if;
  return jsonb_build_object('ok',true,'sessionId',v_session);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_update_org_onboarding_v10(p_uid uuid, p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_on public.organization_onboarding%rowtype;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if coalesce(p_primary_contact_email,'') !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'
     or coalesce(p_security_contact_email,'') !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'
     or coalesce(p_billing_contact_email,'') !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','ONBOARDING_EMAIL_INVALID');
  end if;

  if length(btrim(coalesce(p_legal_entity_name,'')))<2 then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_ENTITY_REQUIRED');
  end if;

  insert into public.organization_onboarding(
    organization_id,status,primary_contact_email,security_contact_email,billing_contact_email,
    legal_entity_name,legal_entity_country,legal_entity_region,legal_entity_address,
    completed_steps_json,production_status,created_at,updated_at
  ) values (
    p_org_id,'incomplete',lower(btrim(p_primary_contact_email)),lower(btrim(p_security_contact_email)),
    lower(btrim(p_billing_contact_email)),btrim(p_legal_entity_name),
    nullif(btrim(coalesce(p_legal_entity_country,'')),''),
    nullif(btrim(coalesce(p_legal_entity_region,'')),''),
    nullif(btrim(coalesce(p_legal_entity_address,'')),''),
    '["organization_profile"]','sandbox',v_now,v_now
  )
  on conflict(organization_id) do update set
    primary_contact_email=excluded.primary_contact_email,
    security_contact_email=excluded.security_contact_email,
    billing_contact_email=excluded.billing_contact_email,
    legal_entity_name=excluded.legal_entity_name,
    legal_entity_country=excluded.legal_entity_country,
    legal_entity_region=excluded.legal_entity_region,
    legal_entity_address=excluded.legal_entity_address,
    updated_at=v_now
  returning * into v_on;

  update public.organization_billing
  set billing_email=lower(btrim(p_billing_contact_email)),updated_at=v_now
  where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','onboarding.profile.updated','organization',p_org_id,
    jsonb_build_object(
      'primaryContactEmail',lower(btrim(p_primary_contact_email)),
      'securityContactEmail',lower(btrim(p_security_contact_email)),
      'billingContactEmail',lower(btrim(p_billing_contact_email)),
      'legalEntityName',btrim(p_legal_entity_name)
    )
  );

  return jsonb_build_object('ok',true,'onboarding',to_jsonb(v_on));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_update_org_profile_v10(p_uid uuid, p_org_id text, p_name text, p_industry text, p_website text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_org public.organizations%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>120 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_NAME_INVALID');
  end if;
  if length(btrim(coalesce(p_website,'')))<8 or p_website !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_WEBSITE_INVALID');
  end if;

  update public.organizations
  set name=btrim(p_name),
      industry=nullif(left(btrim(coalesce(p_industry,'')),100),''),
      website=left(btrim(p_website),500),
      updated_at=v_now
  where id=p_org_id
  returning * into v_org;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','organization.profile.updated','organization',p_org_id,
    jsonb_build_object('name',v_org.name,'industry',v_org.industry,'website',v_org.website)
  );

  return jsonb_build_object('ok',true,'organization',to_jsonb(v_org));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_user_onboarding_v10(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_account_id text;
  v_docs jsonb;
  v_required jsonb;
  v_effective_count integer;
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';
  v_docs:=private.trustrelay_latest_legal_documents_v10();

  select count(*) into v_effective_count
  from jsonb_array_elements(v_docs) d
  where d->>'documentType' in ('consumer_terms','privacy_notice')
    and coalesce((d->>'binding')::boolean,false)
    and d->>'effectiveAt' is not null;

  select coalesce(jsonb_agg(d),'[]'::jsonb) into v_required
  from jsonb_array_elements(v_docs) d
  where d->>'documentType' in ('consumer_terms','privacy_notice')
    and coalesce((d->>'binding')::boolean,false)
    and d->>'effectiveAt' is not null
    and not exists(
      select 1
      from public.legal_acceptances a
      where a.account_id=v_account_id
        and a.organization_id is null
        and a.document_id=d->>'id'
    );

  return jsonb_build_object(
    'ok',true,
    'account',v_ctx->'account',
    'person',v_ctx->'person',
    'publishedDocuments',v_docs,
    'requiredAcceptances',v_required,
    'effectiveConsumerLegalPackagePublished',v_effective_count>=2,
    'consumerLegalComplete',v_effective_count>=2 and jsonb_array_length(v_required)=0,
    'profileComplete',
      length(btrim(coalesce(v_ctx->'person'->>'display_name','')))>1
      and length(btrim(coalesce(v_ctx->'account'->>'email','')))>3
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_accept_legal_v10(p_document_id text, p_org_id text DEFAULT NULL::text, p_context text DEFAULT 'consumer'::text, p_metadata jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_accept_legal_v10(auth.uid(),p_document_id,p_org_id,p_context,p_metadata);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_apply_stripe_event_v10(p_event_id text, p_event_type text, p_payload_json text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare
  v_payload jsonb;
  v_obj jsonb;
  v_org_id text;
  v_plan text;
  v_customer text;
  v_subscription text;
  v_status text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_hash text;
  v_livemode boolean;
  v_period_start text;
  v_period_end text;
  v_trial_end text;
  v_cancel boolean:=false;
  v_existing public.billing_events%rowtype;
begin
  if length(btrim(coalesce(p_event_id,'')))<4 or length(btrim(coalesce(p_event_type,'')))<3 then
    return jsonb_build_object('ok',false,'status',400,'code','STRIPE_EVENT_INVALID');
  end if;

  begin v_payload:=p_payload_json::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','STRIPE_PAYLOAD_INVALID');
  end;

  v_hash:=encode(digest(p_payload_json,'sha256'),'hex');
  v_livemode:=coalesce((v_payload->>'livemode')::boolean,false);

  select * into v_existing
  from public.billing_events
  where provider='stripe' and provider_event_id=p_event_id;

  if found then
    if v_existing.payload_sha256<>v_hash then
      return jsonb_build_object('ok',false,'status',409,'code','STRIPE_EVENT_HASH_MISMATCH');
    end if;
    return jsonb_build_object('ok',true,'idempotent',true,'eventId',p_event_id,'status',v_existing.status);
  end if;

  insert into public.billing_events(
    id,provider,provider_event_id,event_type,payload_sha256,livemode,status,created_at
  ) values (
    'bill_evt_'||replace(gen_random_uuid()::text,'-',''),
    'stripe',p_event_id,p_event_type,v_hash,v_livemode,'received',v_now
  );

  v_obj:=v_payload->'data'->'object';
  v_org_id:=coalesce(
    nullif(v_obj->'metadata'->>'trustrelay_org_id',''),
    nullif(v_obj->'subscription_details'->'metadata'->>'trustrelay_org_id','')
  );
  v_plan:=coalesce(
    nullif(v_obj->'metadata'->>'trustrelay_plan_code',''),
    nullif(v_obj->'subscription_details'->'metadata'->>'trustrelay_plan_code','')
  );
  v_customer:=nullif(v_obj->>'customer','');
  v_subscription:=nullif(v_obj->>'subscription','');

  if p_event_type like 'customer.subscription.%' then
    v_subscription:=nullif(v_obj->>'id','');
    v_customer:=nullif(v_obj->>'customer','');
    v_org_id:=coalesce(v_org_id,(
      select organization_id from public.organization_billing
      where provider='stripe'
        and (provider_subscription_id=v_subscription or provider_customer_id=v_customer)
      limit 1
    ));
    v_plan:=coalesce(v_plan,(
      select plan_code from public.organization_billing where organization_id=v_org_id
    ));
    v_status:=case v_obj->>'status'
      when 'trialing' then 'trialing'
      when 'active' then 'active'
      when 'past_due' then 'past_due'
      when 'unpaid' then 'unpaid'
      when 'canceled' then 'canceled'
      when 'paused' then 'past_due'
      else 'not_configured'
    end;
    v_cancel:=coalesce((v_obj->>'cancel_at_period_end')::boolean,false);
    if (v_obj->>'current_period_start') ~ '^[0-9]+$' then
      v_period_start:=to_char(to_timestamp((v_obj->>'current_period_start')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;
    if (v_obj->>'current_period_end') ~ '^[0-9]+$' then
      v_period_end:=to_char(to_timestamp((v_obj->>'current_period_end')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;
    if (v_obj->>'trial_end') ~ '^[0-9]+$' then
      v_trial_end:=to_char(to_timestamp((v_obj->>'trial_end')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;

  elsif p_event_type='checkout.session.completed' then
    v_org_id:=coalesce(v_org_id,nullif(v_obj->>'client_reference_id',''));
    v_customer:=nullif(v_obj->>'customer','');
    v_subscription:=nullif(v_obj->>'subscription','');

  elsif p_event_type in ('invoice.paid','invoice.payment_failed') then
    v_customer:=nullif(v_obj->>'customer','');
    v_subscription:=coalesce(
      nullif(v_obj->>'subscription',''),
      nullif(v_obj->'parent'->'subscription_details'->>'subscription','')
    );
    v_org_id:=coalesce(v_org_id,(
      select organization_id from public.organization_billing
      where provider='stripe'
        and (provider_subscription_id=v_subscription or provider_customer_id=v_customer)
      limit 1
    ));
  end if;

  if v_org_id is null or not exists(select 1 from public.organizations where id=v_org_id) then
    update public.billing_events
    set status='ignored',error_code='ORGANIZATION_NOT_RESOLVED',processed_at=v_now
    where provider='stripe' and provider_event_id=p_event_id;
    return jsonb_build_object('ok',true,'ignored',true,'eventId',p_event_id,'reason','ORGANIZATION_NOT_RESOLVED');
  end if;

  if v_plan is not null and not exists(select 1 from public.billing_plans where code=v_plan and status='active') then
    update public.billing_events
    set status='failed',organization_id=v_org_id,error_code='PLAN_NOT_RESOLVED',processed_at=v_now
    where provider='stripe' and provider_event_id=p_event_id;
    return jsonb_build_object('ok',false,'status',409,'code','PLAN_NOT_RESOLVED');
  end if;

  update public.organization_billing
  set
    provider='stripe',
    plan_code=coalesce(v_plan,plan_code),
    provider_customer_id=coalesce(v_customer,provider_customer_id),
    provider_subscription_id=coalesce(v_subscription,provider_subscription_id),
    status=case
      when p_event_type like 'customer.subscription.%' then v_status
      when p_event_type='invoice.paid' and status<>'canceled' then 'active'
      when p_event_type='invoice.payment_failed' then 'past_due'
      else status end,
    current_period_start=coalesce(v_period_start,current_period_start),
    current_period_end=coalesce(v_period_end,current_period_end),
    trial_end=coalesce(v_trial_end,trial_end),
    cancel_at_period_end=case when p_event_type like 'customer.subscription.%' then v_cancel else cancel_at_period_end end,
    canceled_at=case when p_event_type='customer.subscription.deleted' then v_now else canceled_at end,
    last_payment_at=case when p_event_type='invoice.paid' then v_now else last_payment_at end,
    last_payment_failure_at=case when p_event_type='invoice.payment_failed' then v_now else last_payment_failure_at end,
    updated_at=v_now
  where organization_id=v_org_id;

  update public.billing_events
  set organization_id=v_org_id,status='processed',processed_at=v_now
  where provider='stripe' and provider_event_id=p_event_id;

  perform private.trustrelay_append_org_audit_v09(
    v_org_id,null,'billing.stripe_event.processed','organization_billing',v_org_id,
    jsonb_build_object('eventId',p_event_id,'eventType',p_event_type,'livemode',v_livemode)
  );

  if p_event_type='invoice.payment_failed' then
    perform private.trustrelay_notify_org_v09(
      v_org_id,array['owner','admin'],'organization',
      'billing.payment_failed','critical',
      'Billing payment failed',
      'TrustRelay could not confirm the latest subscription payment. Production access may be affected.',
      'organization_billing',v_org_id,jsonb_build_object('eventId',p_event_id)
    );
  elsif p_event_type in ('customer.subscription.created','customer.subscription.updated','checkout.session.completed') then
    perform private.trustrelay_notify_org_v09(
      v_org_id,array['owner','admin'],'organization',
      'billing.subscription_updated','success',
      'Billing subscription updated',
      'TrustRelay received an updated subscription state from Stripe.',
      'organization_billing',v_org_id,jsonb_build_object('eventId',p_event_id,'eventType',p_event_type)
    );
  end if;

  return jsonb_build_object('ok',true,'eventId',p_event_id,'organizationId',v_org_id,'processed',true);
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_approve_production_activation_v10(p_org_id text, p_notes text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_on public.organization_onboarding%rowtype;
  v_bill public.organization_billing%rowtype;
  v_platform jsonb;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_on from public.organization_onboarding where organization_id=p_org_id for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_ONBOARDING_NOT_FOUND'); end if;
  if v_on.production_status<>'requested' then
    return jsonb_build_object('ok',false,'status',409,'code','PRODUCTION_ACTIVATION_NOT_REQUESTED');
  end if;

  select * into v_bill from public.organization_billing where organization_id=p_org_id;
  if v_bill.status not in ('active','trialing','manual_contract') then
    return jsonb_build_object('ok',false,'status',402,'code','BILLING_INACTIVE');
  end if;

  v_platform:=private.trustrelay_platform_readiness_v10();
  if coalesce((v_platform->>'ready')::boolean,false)=false then
    return jsonb_build_object('ok',false,'status',503,'code','PLATFORM_NOT_PRODUCTION_READY','platformBlockers',v_platform->'blockers');
  end if;

  update public.organization_onboarding
  set status='complete',production_status='approved',activation_reviewed_at=v_now,
      activation_notes=nullif(left(btrim(coalesce(p_notes,'')),2000),''),updated_at=v_now
  where organization_id=p_org_id;

  update public.organizations
  set mode='live',production_activated_at=v_now,updated_at=v_now
  where id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'production.activation.approved','organization',p_org_id,
    jsonb_build_object('notes',nullif(left(btrim(coalesce(p_notes,'')),2000),''))
  );

  return jsonb_build_object('ok',true,'organizationId',p_org_id,'mode','live','productionStatus','approved','activatedAt',v_now);
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_billing_provider_context_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare
  v_b public.organization_billing%rowtype;
  v_p public.billing_plans%rowtype;
  v_o public.organization_onboarding%rowtype;
begin
  select * into v_b from public.organization_billing where organization_id=p_org_id;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','BILLING_NOT_FOUND'); end if;
  select * into v_p from public.billing_plans where code=v_b.plan_code;
  select * into v_o from public.organization_onboarding where organization_id=p_org_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',p_org_id,
    'billing',jsonb_build_object(
      'provider',v_b.provider,'planCode',v_b.plan_code,'status',v_b.status,
      'billingEmail',coalesce(v_b.billing_email,v_o.billing_contact_email),
      'customerId',v_b.provider_customer_id,
      'subscriptionId',v_b.provider_subscription_id,
      'priceId',v_b.provider_price_id,
      'seatQuantity',v_b.seat_quantity
    ),
    'plan',jsonb_build_object(
      'code',v_p.code,'name',v_p.name,'billingMode',v_p.billing_mode
    )
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_billing_status_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_billing_status_v10(auth.uid(),p_org_id);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_org_onboarding_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_org_onboarding_v10(auth.uid(),p_org_id);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_org_runtime_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'pg_catalog'
AS $function$
  select private.trustrelay_org_runtime_v10(p_org_id);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_plan_capacity_v10(p_org_id text, p_metric text)
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'private', 'pg_catalog'
AS $function$
  select private.trustrelay_plan_limit_v10(p_org_id,p_metric);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_plan_limit_v10(p_org_id text, p_metric text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'pg_catalog'
AS $function$
  select private.trustrelay_plan_limit_v10(p_org_id,p_metric);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_platform_readiness_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_platform_readiness_for_user_v10(auth.uid(),p_org_id);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_publish_legal_document_v10(p_document_id text, p_content_sha256 text, p_effective_at text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_doc public.legal_documents%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_required integer;
begin
  if p_content_sha256 !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_DOCUMENT_HASH_INVALID');
  end if;

  begin perform p_effective_at::timestamptz;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_EFFECTIVE_DATE_INVALID');
  end;

  select * into v_doc
  from public.legal_documents
  where id=p_document_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','LEGAL_DOCUMENT_NOT_FOUND');
  end if;

  if v_doc.status='superseded' then
    return jsonb_build_object('ok',false,'status',409,'code','LEGAL_DOCUMENT_SUPERSEDED');
  end if;

  update public.legal_documents
  set status='superseded',superseded_at=v_now
  where document_type=v_doc.document_type
    and id<>v_doc.id
    and status='published';

  update public.legal_documents
  set status='published',content_sha256=lower(p_content_sha256),
      effective_at=p_effective_at,published_at=v_now,superseded_at=null
  where id=p_document_id
  returning * into v_doc;

  select count(distinct document_type) into v_required
  from public.legal_documents
  where status='published'
    and document_type in ('consumer_terms','privacy_notice','business_terms','dpa','acceptable_use');

  if v_required=5 then
    update public.production_readiness_controls
    set status='pass',
        evidence='Published required legal package is present with versioned SHA-256 hashes.',
        updated_at=v_now
    where control_key='legal_package_published';
  end if;

  return jsonb_build_object('ok',true,'document',to_jsonb(v_doc),'requiredPackagePublished',v_required=5);
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_publish_legal_document_v10(p_document_id text, p_content_sha256 text, p_effective_at text, p_counsel_reviewed boolean, p_binding boolean)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_doc public.legal_documents%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_required integer;
begin
  if p_content_sha256 !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_DOCUMENT_HASH_INVALID');
  end if;

  begin perform p_effective_at::timestamptz;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','LEGAL_EFFECTIVE_DATE_INVALID');
  end;

  if coalesce(p_counsel_reviewed,false)=false or coalesce(p_binding,false)=false then
    return jsonb_build_object(
      'ok',false,'status',409,'code','LEGAL_COUNSEL_CONFIRMATION_REQUIRED'
    );
  end if;

  select * into v_doc
  from public.legal_documents
  where id=p_document_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','LEGAL_DOCUMENT_NOT_FOUND');
  end if;

  update public.legal_documents
  set status='superseded',superseded_at=v_now
  where document_type=v_doc.document_type
    and id<>v_doc.id
    and status='published'
    and binding=true;

  update public.legal_documents
  set status='published',
      content_sha256=lower(p_content_sha256),
      effective_at=p_effective_at,
      published_at=coalesce(published_at,v_now),
      superseded_at=null,
      counsel_reviewed=true,
      binding=true
  where id=p_document_id
  returning * into v_doc;

  select count(distinct document_type) into v_required
  from public.legal_documents
  where status='published'
    and binding=true
    and counsel_reviewed=true
    and effective_at is not null
    and document_type in ('consumer_terms','privacy_notice','business_terms','dpa','acceptable_use');

  if v_required=5 then
    update public.production_readiness_controls
    set status='pass',
        evidence='Required counsel-reviewed binding legal package is published with versioned SHA-256 hashes.',
        updated_at=v_now
    where control_key='legal_package_published';
  end if;

  return jsonb_build_object(
    'ok',true,'document',to_jsonb(v_doc),'requiredPackagePublished',v_required=5
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_request_production_activation_v10(p_org_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_request_production_activation_v10(auth.uid(),p_org_id);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_select_billing_plan_v10(p_org_id text, p_plan_code text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_select_billing_plan_v10(auth.uid(),p_org_id,p_plan_code);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_set_production_control_v10(p_control_key text, p_status text, p_evidence text, p_owner_note text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare
  v_row public.production_readiness_controls%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_status not in ('pass','fail','unknown','not_applicable') then
    return jsonb_build_object('ok',false,'status',400,'code','READINESS_STATUS_INVALID');
  end if;

  update public.production_readiness_controls
  set status=p_status,evidence=nullif(left(coalesce(p_evidence,''),4000),''),
      owner_note=nullif(left(coalesce(p_owner_note,''),4000),''),updated_at=v_now
  where control_key=p_control_key
  returning * into v_row;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','READINESS_CONTROL_NOT_FOUND');
  end if;

  return jsonb_build_object('ok',true,'control',to_jsonb(v_row),'platform',private.trustrelay_platform_readiness_v10());
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_update_org_onboarding_v10(p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text DEFAULT NULL::text, p_legal_entity_region text DEFAULT NULL::text, p_legal_entity_address text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_update_org_onboarding_v10(
    auth.uid(),p_org_id,p_primary_contact_email,p_security_contact_email,p_billing_contact_email,
    p_legal_entity_name,p_legal_entity_country,p_legal_entity_region,p_legal_entity_address
  );
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_update_org_profile_v10(p_org_id text, p_name text, p_industry text, p_website text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_update_org_profile_v10(auth.uid(),p_org_id,p_name,p_industry,p_website);
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_user_onboarding_v10()
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_user_onboarding_v10(auth.uid());
$function$;


-- Function ACLs
revoke all on function private.trustrelay_accept_legal_v10(p_uid uuid, p_document_id text, p_org_id text, p_context text, p_metadata jsonb) from public,anon,authenticated;
grant execute on function private.trustrelay_accept_legal_v10(p_uid uuid, p_document_id text, p_org_id text, p_context text, p_metadata jsonb) to service_role;
revoke all on function private.trustrelay_billing_status_v10(p_uid uuid, p_org_id text) from public,anon,authenticated;
grant execute on function private.trustrelay_billing_status_v10(p_uid uuid, p_org_id text) to service_role;
revoke all on function private.trustrelay_create_organization_v07(p_uid uuid, p_name text, p_industry text, p_website text) from public,anon,authenticated;
grant execute on function private.trustrelay_create_organization_v07(p_uid uuid, p_name text, p_industry text, p_website text) to authenticated;
grant execute on function private.trustrelay_create_organization_v07(p_uid uuid, p_name text, p_industry text, p_website text) to service_role;
revoke all on function private.trustrelay_enforce_plan_capacity_v10() from public,anon,authenticated;
grant execute on function private.trustrelay_enforce_plan_capacity_v10() to service_role;
revoke all on function private.trustrelay_enforce_plan_limit_v10() from public,anon,authenticated;
revoke all on function private.trustrelay_latest_legal_documents_v10() from public,anon,authenticated;
grant execute on function private.trustrelay_latest_legal_documents_v10() to service_role;
revoke all on function private.trustrelay_org_onboarding_v10(p_uid uuid, p_org_id text) from public,anon,authenticated;
grant execute on function private.trustrelay_org_onboarding_v10(p_uid uuid, p_org_id text) to service_role;
revoke all on function private.trustrelay_org_runtime_v10(p_org_id text) from public,anon,authenticated;
grant execute on function private.trustrelay_org_runtime_v10(p_org_id text) to service_role;
revoke all on function private.trustrelay_plan_limit_v10(p_org_id text, p_metric text) from public,anon,authenticated;
grant execute on function private.trustrelay_plan_limit_v10(p_org_id text, p_metric text) to service_role;
revoke all on function private.trustrelay_platform_readiness_for_user_v10(p_uid uuid, p_org_id text) from public,anon,authenticated;
grant execute on function private.trustrelay_platform_readiness_for_user_v10(p_uid uuid, p_org_id text) to authenticated;
grant execute on function private.trustrelay_platform_readiness_for_user_v10(p_uid uuid, p_org_id text) to service_role;
revoke all on function private.trustrelay_platform_readiness_v10() from public,anon,authenticated;
grant execute on function private.trustrelay_platform_readiness_v10() to service_role;
revoke all on function private.trustrelay_protect_legal_document_v10() from public,anon,authenticated;
grant execute on function private.trustrelay_protect_legal_document_v10() to service_role;
revoke all on function private.trustrelay_request_production_activation_v10(p_uid uuid, p_org_id text) from public,anon,authenticated;
grant execute on function private.trustrelay_request_production_activation_v10(p_uid uuid, p_org_id text) to service_role;
revoke all on function private.trustrelay_select_billing_plan_v10(p_uid uuid, p_org_id text, p_plan_code text) from public,anon,authenticated;
grant execute on function private.trustrelay_select_billing_plan_v10(p_uid uuid, p_org_id text, p_plan_code text) to service_role;
revoke all on function private.trustrelay_session_guard_v10(p_uid uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_session_guard_v10(p_uid uuid) to authenticated;
grant execute on function private.trustrelay_session_guard_v10(p_uid uuid) to service_role;
revoke all on function private.trustrelay_update_org_onboarding_v10(p_uid uuid, p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text) from public,anon,authenticated;
grant execute on function private.trustrelay_update_org_onboarding_v10(p_uid uuid, p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text) to service_role;
revoke all on function private.trustrelay_update_org_profile_v10(p_uid uuid, p_org_id text, p_name text, p_industry text, p_website text) from public,anon,authenticated;
grant execute on function private.trustrelay_update_org_profile_v10(p_uid uuid, p_org_id text, p_name text, p_industry text, p_website text) to service_role;
revoke all on function private.trustrelay_user_onboarding_v10(p_uid uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_user_onboarding_v10(p_uid uuid) to service_role;
revoke all on function public.trustrelay_accept_legal_v10(p_document_id text, p_org_id text, p_context text, p_metadata jsonb) from public,anon,authenticated;
grant execute on function public.trustrelay_accept_legal_v10(p_document_id text, p_org_id text, p_context text, p_metadata jsonb) to authenticated;
grant execute on function public.trustrelay_accept_legal_v10(p_document_id text, p_org_id text, p_context text, p_metadata jsonb) to service_role;
revoke all on function public.trustrelay_apply_stripe_event_v10(p_event_id text, p_event_type text, p_payload_json text) from public,anon,authenticated;
grant execute on function public.trustrelay_apply_stripe_event_v10(p_event_id text, p_event_type text, p_payload_json text) to service_role;
revoke all on function public.trustrelay_approve_production_activation_v10(p_org_id text, p_notes text) from public,anon,authenticated;
grant execute on function public.trustrelay_approve_production_activation_v10(p_org_id text, p_notes text) to service_role;
revoke all on function public.trustrelay_billing_provider_context_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_billing_provider_context_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_billing_status_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_billing_status_v10(p_org_id text) to authenticated;
grant execute on function public.trustrelay_billing_status_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_org_onboarding_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_org_onboarding_v10(p_org_id text) to authenticated;
grant execute on function public.trustrelay_org_onboarding_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_org_runtime_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_org_runtime_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_plan_capacity_v10(p_org_id text, p_metric text) from public,anon,authenticated;
grant execute on function public.trustrelay_plan_capacity_v10(p_org_id text, p_metric text) to service_role;
revoke all on function public.trustrelay_plan_limit_v10(p_org_id text, p_metric text) from public,anon,authenticated;
grant execute on function public.trustrelay_plan_limit_v10(p_org_id text, p_metric text) to service_role;
revoke all on function public.trustrelay_platform_readiness_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_platform_readiness_v10(p_org_id text) to authenticated;
grant execute on function public.trustrelay_platform_readiness_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_publish_legal_document_v10(p_document_id text, p_content_sha256 text, p_effective_at text) from public,anon,authenticated;
revoke all on function public.trustrelay_publish_legal_document_v10(p_document_id text, p_content_sha256 text, p_effective_at text, p_counsel_reviewed boolean, p_binding boolean) from public,anon,authenticated;
grant execute on function public.trustrelay_publish_legal_document_v10(p_document_id text, p_content_sha256 text, p_effective_at text, p_counsel_reviewed boolean, p_binding boolean) to service_role;
revoke all on function public.trustrelay_request_production_activation_v10(p_org_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_request_production_activation_v10(p_org_id text) to authenticated;
grant execute on function public.trustrelay_request_production_activation_v10(p_org_id text) to service_role;
revoke all on function public.trustrelay_select_billing_plan_v10(p_org_id text, p_plan_code text) from public,anon,authenticated;
grant execute on function public.trustrelay_select_billing_plan_v10(p_org_id text, p_plan_code text) to authenticated;
grant execute on function public.trustrelay_select_billing_plan_v10(p_org_id text, p_plan_code text) to service_role;
revoke all on function public.trustrelay_set_production_control_v10(p_control_key text, p_status text, p_evidence text, p_owner_note text) from public,anon,authenticated;
grant execute on function public.trustrelay_set_production_control_v10(p_control_key text, p_status text, p_evidence text, p_owner_note text) to service_role;
revoke all on function public.trustrelay_update_org_onboarding_v10(p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text) from public,anon,authenticated;
grant execute on function public.trustrelay_update_org_onboarding_v10(p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text) to authenticated;
grant execute on function public.trustrelay_update_org_onboarding_v10(p_org_id text, p_primary_contact_email text, p_security_contact_email text, p_billing_contact_email text, p_legal_entity_name text, p_legal_entity_country text, p_legal_entity_region text, p_legal_entity_address text) to service_role;
revoke all on function public.trustrelay_update_org_profile_v10(p_org_id text, p_name text, p_industry text, p_website text) from public,anon,authenticated;
grant execute on function public.trustrelay_update_org_profile_v10(p_org_id text, p_name text, p_industry text, p_website text) to authenticated;
grant execute on function public.trustrelay_update_org_profile_v10(p_org_id text, p_name text, p_industry text, p_website text) to service_role;
revoke all on function public.trustrelay_user_onboarding_v10() from public,anon,authenticated;
grant execute on function public.trustrelay_user_onboarding_v10() to authenticated;
grant execute on function public.trustrelay_user_onboarding_v10() to service_role;

-- v1.0 triggers
drop trigger if exists "trg_plan_limit_api_keys_v10" on public.api_keys;
CREATE TRIGGER trg_plan_limit_api_keys_v10 BEFORE INSERT OR UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_limit_v10();
drop trigger if exists "trustrelay_plan_api_keys_v10" on public.api_keys;
CREATE TRIGGER trustrelay_plan_api_keys_v10 BEFORE INSERT OR UPDATE OF revoked_at, key_type ON api_keys FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_capacity_v10();
drop trigger if exists "trg_plan_limit_decisions_v10" on public.authorization_decisions;
CREATE TRIGGER trg_plan_limit_decisions_v10 BEFORE INSERT ON authorization_decisions FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_limit_v10();
drop trigger if exists "trustrelay_plan_decisions_v10" on public.authorization_decisions;
CREATE TRIGGER trustrelay_plan_decisions_v10 BEFORE INSERT ON authorization_decisions FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_capacity_v10();
drop trigger if exists "trg_plan_limit_exports_v10" on public.compliance_exports;
CREATE TRIGGER trg_plan_limit_exports_v10 BEFORE INSERT ON compliance_exports FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_limit_v10();
drop trigger if exists "trustrelay_plan_exports_v10" on public.compliance_exports;
CREATE TRIGGER trustrelay_plan_exports_v10 BEFORE INSERT ON compliance_exports FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_capacity_v10();
drop trigger if exists "trustrelay_protect_legal_document_v10" on public.legal_documents;
CREATE TRIGGER trustrelay_protect_legal_document_v10 BEFORE UPDATE ON legal_documents FOR EACH ROW EXECUTE FUNCTION private.trustrelay_protect_legal_document_v10();
drop trigger if exists "trg_plan_limit_members_v10" on public.organization_members;
CREATE TRIGGER trg_plan_limit_members_v10 BEFORE INSERT OR UPDATE ON organization_members FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_limit_v10();
drop trigger if exists "trustrelay_plan_members_v10" on public.organization_members;
CREATE TRIGGER trustrelay_plan_members_v10 BEFORE INSERT OR UPDATE OF status ON organization_members FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_capacity_v10();
drop trigger if exists "trg_plan_limit_webhooks_v10" on public.webhook_subscriptions;
CREATE TRIGGER trg_plan_limit_webhooks_v10 BEFORE INSERT OR UPDATE ON webhook_subscriptions FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_limit_v10();
drop trigger if exists "trustrelay_plan_webhooks_v10" on public.webhook_subscriptions;
CREATE TRIGGER trustrelay_plan_webhooks_v10 BEFORE INSERT OR UPDATE OF status ON webhook_subscriptions FOR EACH ROW EXECUTE FUNCTION private.trustrelay_enforce_plan_capacity_v10();

-- Direct client access remains denied; server-side service_role owns v1.0 tables.
revoke all on public.billing_events from anon,authenticated;
grant all on public.billing_events to service_role;
revoke all on public.billing_plans from anon,authenticated;
grant all on public.billing_plans to service_role;
revoke all on public.legal_acceptances from anon,authenticated;
grant all on public.legal_acceptances to service_role;
revoke all on public.legal_documents from anon,authenticated;
grant all on public.legal_documents to service_role;
revoke all on public.organization_billing from anon,authenticated;
grant all on public.organization_billing to service_role;
revoke all on public.organization_onboarding from anon,authenticated;
grant all on public.organization_onboarding to service_role;
revoke all on public.production_readiness_controls from anon,authenticated;
grant all on public.production_readiness_controls to service_role;
