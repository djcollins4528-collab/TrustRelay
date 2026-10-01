-- TrustRelay v0.8 identity/evidence baseline reconstructed from live staging on 2026-10-01.
-- Apply after 0001_recorded_v04_to_v07.sql and before 0003_recorded_v09.sql.

create schema if not exists private;

create table if not exists public.evidence_review_events ();
create table if not exists public.identity_assurance_events ();
create table if not exists public.evidence_requests ();
create table if not exists public.evidence_request_documents ();
create table if not exists private.identity_reviewers ();

alter table private.identity_reviewers add column if not exists "account_id" text not null;
alter table private.identity_reviewers add column if not exists "reviewer_role" text default 'reviewer'::text not null;
alter table private.identity_reviewers add column if not exists "status" text default 'active'::text not null;
alter table private.identity_reviewers add column if not exists "created_at" text not null;
alter table public.documents add column if not exists "id" text not null;
alter table public.documents add column if not exists "owner_person_id" text not null;
alter table public.documents add column if not exists "document_type" text not null;
alter table public.documents add column if not exists "display_name" text not null;
alter table public.documents add column if not exists "storage_key" text not null;
alter table public.documents add column if not exists "encryption_provider" text not null;
alter table public.documents add column if not exists "encryption_iv" text;
alter table public.documents add column if not exists "encryption_tag" text;
alter table public.documents add column if not exists "wrapped_key" text;
alter table public.documents add column if not exists "content_sha256" text not null;
alter table public.documents add column if not exists "mime_type" text not null;
alter table public.documents add column if not exists "size_bytes" integer not null;
alter table public.documents add column if not exists "scan_status" text default 'pending'::text not null;
alter table public.documents add column if not exists "scan_result_json" text default '{}'::text not null;
alter table public.documents add column if not exists "created_at" text not null;
alter table public.documents add column if not exists "proofing_session_id" text;
alter table public.documents add column if not exists "uploaded_by_account_id" text;
alter table public.documents add column if not exists "purpose" text default 'supporting'::text not null;
alter table public.documents add column if not exists "classification" text default 'other'::text not null;
alter table public.documents add column if not exists "original_filename" text;
alter table public.documents add column if not exists "storage_bucket" text default 'trustrelay-evidence'::text not null;
alter table public.documents add column if not exists "uploaded_at" text;
alter table public.documents add column if not exists "finalized_at" text;
alter table public.documents add column if not exists "review_status" text default 'pending'::text not null;
alter table public.documents add column if not exists "reviewer_account_id" text;
alter table public.documents add column if not exists "reviewed_at" text;
alter table public.documents add column if not exists "review_reason" text;
alter table public.documents add column if not exists "review_notes" text;
alter table public.documents add column if not exists "metadata_json" text default '{}'::text not null;
alter table public.documents add column if not exists "retention_until" text;
alter table public.documents add column if not exists "deleted_at" text;
alter table public.evidence_request_documents add column if not exists "request_id" text not null;
alter table public.evidence_request_documents add column if not exists "document_id" text not null;
alter table public.evidence_request_documents add column if not exists "attached_by_account_id" text;
alter table public.evidence_request_documents add column if not exists "attached_at" text not null;
alter table public.evidence_requests add column if not exists "id" text not null;
alter table public.evidence_requests add column if not exists "grant_id" text not null;
alter table public.evidence_requests add column if not exists "requested_by_organization_id" text;
alter table public.evidence_requests add column if not exists "requested_by_account_id" text;
alter table public.evidence_requests add column if not exists "request_type" text default 'authorization_evidence'::text not null;
alter table public.evidence_requests add column if not exists "required_document_types_json" text default '[]'::text not null;
alter table public.evidence_requests add column if not exists "status" text default 'open'::text not null;
alter table public.evidence_requests add column if not exists "due_at" text;
alter table public.evidence_requests add column if not exists "resolved_at" text;
alter table public.evidence_requests add column if not exists "created_at" text not null;
alter table public.evidence_requests add column if not exists "updated_at" text not null;
alter table public.evidence_requests add column if not exists "reviewed_by_account_id" text;
alter table public.evidence_requests add column if not exists "reviewed_at" text;
alter table public.evidence_requests add column if not exists "resolution_reason" text;
alter table public.evidence_requests add column if not exists "resolution_notes" text;
alter table public.evidence_review_events add column if not exists "id" text not null;
alter table public.evidence_review_events add column if not exists "document_id" text not null;
alter table public.evidence_review_events add column if not exists "proofing_session_id" text;
alter table public.evidence_review_events add column if not exists "reviewer_account_id" text;
alter table public.evidence_review_events add column if not exists "reviewer_type" text not null;
alter table public.evidence_review_events add column if not exists "decision" text not null;
alter table public.evidence_review_events add column if not exists "reason_code" text;
alter table public.evidence_review_events add column if not exists "notes" text;
alter table public.evidence_review_events add column if not exists "event_hash" text not null;
alter table public.evidence_review_events add column if not exists "created_at" text not null;
alter table public.grant_evidence add column if not exists "grant_id" text not null;
alter table public.grant_evidence add column if not exists "document_id" text not null;
alter table public.identity_assurance_events add column if not exists "id" text not null;
alter table public.identity_assurance_events add column if not exists "person_id" text not null;
alter table public.identity_assurance_events add column if not exists "proofing_session_id" text;
alter table public.identity_assurance_events add column if not exists "reviewer_account_id" text;
alter table public.identity_assurance_events add column if not exists "provider" text not null;
alter table public.identity_assurance_events add column if not exists "from_level" text not null;
alter table public.identity_assurance_events add column if not exists "to_level" text not null;
alter table public.identity_assurance_events add column if not exists "decision" text not null;
alter table public.identity_assurance_events add column if not exists "reason_code" text;
alter table public.identity_assurance_events add column if not exists "event_hash" text not null;
alter table public.identity_assurance_events add column if not exists "created_at" text not null;
alter table public.identity_proofing_sessions add column if not exists "id" text not null;
alter table public.identity_proofing_sessions add column if not exists "account_id" text not null;
alter table public.identity_proofing_sessions add column if not exists "provider" text not null;
alter table public.identity_proofing_sessions add column if not exists "provider_reference" text;
alter table public.identity_proofing_sessions add column if not exists "status" text not null;
alter table public.identity_proofing_sessions add column if not exists "assurance_level" text;
alter table public.identity_proofing_sessions add column if not exists "redirect_url" text;
alter table public.identity_proofing_sessions add column if not exists "result_json" text default '{}'::text not null;
alter table public.identity_proofing_sessions add column if not exists "expires_at" text;
alter table public.identity_proofing_sessions add column if not exists "completed_at" text;
alter table public.identity_proofing_sessions add column if not exists "created_at" text not null;
alter table public.identity_proofing_sessions add column if not exists "updated_at" text not null;
alter table public.identity_proofing_sessions add column if not exists "subject_person_id" text;
alter table public.identity_proofing_sessions add column if not exists "requested_assurance" text;
alter table public.identity_proofing_sessions add column if not exists "consent_at" text;
alter table public.identity_proofing_sessions add column if not exists "consent_version" text;
alter table public.identity_proofing_sessions add column if not exists "submitted_at" text;
alter table public.identity_proofing_sessions add column if not exists "reviewer_account_id" text;
alter table public.identity_proofing_sessions add column if not exists "reviewed_at" text;
alter table public.identity_proofing_sessions add column if not exists "review_reason" text;
alter table public.identity_proofing_sessions add column if not exists "review_notes" text;
alter table public.identity_proofing_sessions add column if not exists "evidence_snapshot_json" text default '{}'::text not null;
alter table public.identity_proofing_sessions add column if not exists "provider_result_hash" text;
alter table public.identity_proofing_sessions add column if not exists "risk_flags_json" text default '[]'::text not null;
alter table public.persons add column if not exists "id" text not null;
alter table public.persons add column if not exists "display_name" text not null;
alter table public.persons add column if not exists "email" text;
alter table public.persons add column if not exists "identity_status" text default 'unverified'::text not null;
alter table public.persons add column if not exists "identity_verified_at" text;
alter table public.persons add column if not exists "created_at" text not null;
alter table public.persons add column if not exists "identity_assurance_level" text default 'none'::text not null;

-- Constraints
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='private' and c.relname='identity_reviewers' and con.conname='identity_reviewers_account_id_fkey') then
    alter table private.identity_reviewers add constraint "identity_reviewers_account_id_fkey" FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='private' and c.relname='identity_reviewers' and con.conname='identity_reviewers_pkey') then
    alter table private.identity_reviewers add constraint "identity_reviewers_pkey" PRIMARY KEY (account_id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='private' and c.relname='identity_reviewers' and con.conname='identity_reviewers_reviewer_role_check') then
    alter table private.identity_reviewers add constraint "identity_reviewers_reviewer_role_check" CHECK (reviewer_role = ANY (ARRAY['reviewer'::text, 'senior_reviewer'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='private' and c.relname='identity_reviewers' and con.conname='identity_reviewers_status_check') then
    alter table private.identity_reviewers add constraint "identity_reviewers_status_check" CHECK (status = ANY (ARRAY['active'::text, 'disabled'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_classification_v08') then
    alter table public.documents add constraint "documents_classification_v08" CHECK (classification = ANY (ARRAY['government_id_front'::text, 'government_id_back'::text, 'passport'::text, 'address_evidence'::text, 'authority_document'::text, 'invoice'::text, 'supporting_document'::text, 'other'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_owner_person_id_fkey') then
    alter table public.documents add constraint "documents_owner_person_id_fkey" FOREIGN KEY (owner_person_id) REFERENCES persons(id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_pkey') then
    alter table public.documents add constraint "documents_pkey" PRIMARY KEY (id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_proofing_session_id_fkey') then
    alter table public.documents add constraint "documents_proofing_session_id_fkey" FOREIGN KEY (proofing_session_id) REFERENCES identity_proofing_sessions(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_purpose_v08') then
    alter table public.documents add constraint "documents_purpose_v08" CHECK (purpose = ANY (ARRAY['identity'::text, 'grant_evidence'::text, 'supporting'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_review_status_v08') then
    alter table public.documents add constraint "documents_review_status_v08" CHECK (review_status = ANY (ARRAY['pending'::text, 'in_review'::text, 'approved'::text, 'rejected'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_reviewer_account_id_fkey') then
    alter table public.documents add constraint "documents_reviewer_account_id_fkey" FOREIGN KEY (reviewer_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_storage_key_key') then
    alter table public.documents add constraint "documents_storage_key_key" UNIQUE (storage_key);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='documents' and con.conname='documents_uploaded_by_account_id_fkey') then
    alter table public.documents add constraint "documents_uploaded_by_account_id_fkey" FOREIGN KEY (uploaded_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_request_documents' and con.conname='evidence_request_documents_attached_by_account_id_fkey') then
    alter table public.evidence_request_documents add constraint "evidence_request_documents_attached_by_account_id_fkey" FOREIGN KEY (attached_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_request_documents' and con.conname='evidence_request_documents_document_id_fkey') then
    alter table public.evidence_request_documents add constraint "evidence_request_documents_document_id_fkey" FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_request_documents' and con.conname='evidence_request_documents_pkey') then
    alter table public.evidence_request_documents add constraint "evidence_request_documents_pkey" PRIMARY KEY (request_id, document_id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_request_documents' and con.conname='evidence_request_documents_request_id_fkey') then
    alter table public.evidence_request_documents add constraint "evidence_request_documents_request_id_fkey" FOREIGN KEY (request_id) REFERENCES evidence_requests(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_request_status_v08') then
    alter table public.evidence_requests add constraint "evidence_request_status_v08" CHECK (status = ANY (ARRAY['open'::text, 'submitted'::text, 'satisfied'::text, 'rejected'::text, 'cancelled'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_requests_grant_id_fkey') then
    alter table public.evidence_requests add constraint "evidence_requests_grant_id_fkey" FOREIGN KEY (grant_id) REFERENCES authority_grants(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_requests_pkey') then
    alter table public.evidence_requests add constraint "evidence_requests_pkey" PRIMARY KEY (id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_requests_requested_by_account_id_fkey') then
    alter table public.evidence_requests add constraint "evidence_requests_requested_by_account_id_fkey" FOREIGN KEY (requested_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_requests_requested_by_organization_id_fkey') then
    alter table public.evidence_requests add constraint "evidence_requests_requested_by_organization_id_fkey" FOREIGN KEY (requested_by_organization_id) REFERENCES organizations(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_requests' and con.conname='evidence_requests_reviewed_by_account_id_fkey') then
    alter table public.evidence_requests add constraint "evidence_requests_reviewed_by_account_id_fkey" FOREIGN KEY (reviewed_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_review_events' and con.conname='evidence_review_decision_v08') then
    alter table public.evidence_review_events add constraint "evidence_review_decision_v08" CHECK (decision = ANY (ARRAY['approved'::text, 'rejected'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_review_events' and con.conname='evidence_review_events_document_id_fkey') then
    alter table public.evidence_review_events add constraint "evidence_review_events_document_id_fkey" FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_review_events' and con.conname='evidence_review_events_pkey') then
    alter table public.evidence_review_events add constraint "evidence_review_events_pkey" PRIMARY KEY (id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_review_events' and con.conname='evidence_review_events_proofing_session_id_fkey') then
    alter table public.evidence_review_events add constraint "evidence_review_events_proofing_session_id_fkey" FOREIGN KEY (proofing_session_id) REFERENCES identity_proofing_sessions(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='evidence_review_events' and con.conname='evidence_review_events_reviewer_account_id_fkey') then
    alter table public.evidence_review_events add constraint "evidence_review_events_reviewer_account_id_fkey" FOREIGN KEY (reviewer_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='grant_evidence' and con.conname='grant_evidence_document_id_fkey') then
    alter table public.grant_evidence add constraint "grant_evidence_document_id_fkey" FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='grant_evidence' and con.conname='grant_evidence_grant_id_fkey') then
    alter table public.grant_evidence add constraint "grant_evidence_grant_id_fkey" FOREIGN KEY (grant_id) REFERENCES authority_grants(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='grant_evidence' and con.conname='grant_evidence_pkey') then
    alter table public.grant_evidence add constraint "grant_evidence_pkey" PRIMARY KEY (grant_id, document_id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_assurance_events' and con.conname='identity_assurance_decision_v08') then
    alter table public.identity_assurance_events add constraint "identity_assurance_decision_v08" CHECK (decision = ANY (ARRAY['approved'::text, 'rejected'::text, 'downgraded'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_assurance_events' and con.conname='identity_assurance_events_person_id_fkey') then
    alter table public.identity_assurance_events add constraint "identity_assurance_events_person_id_fkey" FOREIGN KEY (person_id) REFERENCES persons(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_assurance_events' and con.conname='identity_assurance_events_pkey') then
    alter table public.identity_assurance_events add constraint "identity_assurance_events_pkey" PRIMARY KEY (id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_assurance_events' and con.conname='identity_assurance_events_proofing_session_id_fkey') then
    alter table public.identity_assurance_events add constraint "identity_assurance_events_proofing_session_id_fkey" FOREIGN KEY (proofing_session_id) REFERENCES identity_proofing_sessions(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_assurance_events' and con.conname='identity_assurance_events_reviewer_account_id_fkey') then
    alter table public.identity_assurance_events add constraint "identity_assurance_events_reviewer_account_id_fkey" FOREIGN KEY (reviewer_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_requested_assurance_v08') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_requested_assurance_v08" CHECK (requested_assurance IS NULL OR (requested_assurance = ANY (ARRAY['document_verified'::text, 'high_assurance'::text])));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_sessions_account_id_fkey') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_sessions_account_id_fkey" FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_sessions_pkey') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_sessions_pkey" PRIMARY KEY (id);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_sessions_reviewer_account_id_fkey') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_sessions_reviewer_account_id_fkey" FOREIGN KEY (reviewer_account_id) REFERENCES accounts(id) ON DELETE SET NULL;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_sessions_subject_person_id_fkey') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_sessions_subject_person_id_fkey" FOREIGN KEY (subject_person_id) REFERENCES persons(id) ON DELETE CASCADE;
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='identity_proofing_sessions' and con.conname='identity_proofing_status_v08') then
    alter table public.identity_proofing_sessions add constraint "identity_proofing_status_v08" CHECK (status = ANY (ARRAY['collecting'::text, 'submitted'::text, 'in_review'::text, 'approved'::text, 'rejected'::text, 'expired'::text, 'cancelled'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='persons' and con.conname='persons_email_key') then
    alter table public.persons add constraint "persons_email_key" UNIQUE (email);
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='persons' and con.conname='persons_identity_assurance_level_check') then
    alter table public.persons add constraint "persons_identity_assurance_level_check" CHECK (identity_assurance_level = ANY (ARRAY['none'::text, 'email_verified'::text, 'document_verified'::text, 'high_assurance'::text]));
  end if;
end $mig$;
do $mig$ begin
  if not exists(select 1 from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='persons' and con.conname='persons_pkey') then
    alter table public.persons add constraint "persons_pkey" PRIMARY KEY (id);
  end if;
end $mig$;

-- Non-constraint indexes
CREATE INDEX IF NOT EXISTS idx_documents_owner ON public.documents USING btree (owner_person_id);
CREATE INDEX IF NOT EXISTS idx_documents_proofing ON public.documents USING btree (proofing_session_id);
CREATE INDEX IF NOT EXISTS idx_documents_reviewer ON public.documents USING btree (reviewer_account_id);
CREATE INDEX IF NOT EXISTS idx_documents_uploader ON public.documents USING btree (uploaded_by_account_id);
CREATE INDEX IF NOT EXISTS idx_evidence_request_documents_doc ON public.evidence_request_documents USING btree (document_id);
CREATE INDEX IF NOT EXISTS idx_evreq_docs_attached_by ON public.evidence_request_documents USING btree (attached_by_account_id);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_grant ON public.evidence_requests USING btree (grant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_org ON public.evidence_requests USING btree (requested_by_organization_id);
CREATE INDEX IF NOT EXISTS idx_evidence_requests_reviewed_by ON public.evidence_requests USING btree (reviewed_by_account_id);
CREATE INDEX IF NOT EXISTS idx_evreq_requested_by_account ON public.evidence_requests USING btree (requested_by_account_id);
CREATE INDEX IF NOT EXISTS idx_evidence_review_document ON public.evidence_review_events USING btree (document_id);
CREATE INDEX IF NOT EXISTS idx_evreview_proofing ON public.evidence_review_events USING btree (proofing_session_id);
CREATE INDEX IF NOT EXISTS idx_evreview_reviewer ON public.evidence_review_events USING btree (reviewer_account_id);
CREATE INDEX IF NOT EXISTS idx_grant_evidence_document ON public.grant_evidence USING btree (document_id);
CREATE INDEX IF NOT EXISTS idx_assurance_event_person ON public.identity_assurance_events USING btree (person_id);
CREATE INDEX IF NOT EXISTS idx_assurance_events_proofing ON public.identity_assurance_events USING btree (proofing_session_id);
CREATE INDEX IF NOT EXISTS idx_assurance_events_reviewer ON public.identity_assurance_events USING btree (reviewer_account_id);
CREATE INDEX IF NOT EXISTS idx_identity_account ON public.identity_proofing_sessions USING btree (account_id);
CREATE INDEX IF NOT EXISTS idx_proofing_reviewer ON public.identity_proofing_sessions USING btree (reviewer_account_id);
CREATE INDEX IF NOT EXISTS idx_proofing_subject ON public.identity_proofing_sessions USING btree (subject_person_id);

-- RLS and current policies for v0.8 evidence surfaces
alter table public.identity_proofing_sessions enable row level security;
alter table public.documents enable row level security;
alter table public.evidence_review_events enable row level security;
alter table public.identity_assurance_events enable row level security;
alter table public.evidence_requests enable row level security;
alter table public.evidence_request_documents enable row level security;
alter table public.grant_evidence enable row level security;
drop policy if exists "trustrelay_deny_clients" on public.documents;
create policy "trustrelay_deny_clients" on public.documents as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.evidence_request_documents;
create policy "trustrelay_deny_clients" on public.evidence_request_documents as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.evidence_requests;
create policy "trustrelay_deny_clients" on public.evidence_requests as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.evidence_review_events;
create policy "trustrelay_deny_clients" on public.evidence_review_events as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.grant_evidence;
create policy "trustrelay_deny_clients" on public.grant_evidence as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.identity_assurance_events;
create policy "trustrelay_deny_clients" on public.identity_assurance_events as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "trustrelay_deny_clients" on public.identity_proofing_sessions;
create policy "trustrelay_deny_clients" on public.identity_proofing_sessions as restrictive for all to anon, authenticated using (false) with check (false);

-- Functions
CREATE OR REPLACE FUNCTION private.trustrelay_account_context_v08(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'auth', 'pg_catalog'
AS $function$
declare
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_guard jsonb;
  v_caller_uid uuid:=auth.uid();
begin
  if v_caller_uid is not null and v_caller_uid=p_uid then
    v_guard:=private.trustrelay_session_guard_v10(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  end if;

  select * into v_account
  from public.accounts
  where auth_user_id=p_uid and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_person from public.persons where id=v_account.person_id;

  return jsonb_build_object(
    'ok',true,
    'account',to_jsonb(v_account),
    'person',to_jsonb(v_person)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_attach_document_to_grant_v08(p_uid uuid, p_grant_id text, p_document_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_person_id text; v_grant public.authority_grants%rowtype; v_doc public.documents%rowtype;
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_person_id:=v_ctx->'person'->>'id';
  select * into v_grant from public.authority_grants where id=p_grant_id;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND'); end if;
  if v_person_id not in (v_grant.principal_person_id,v_grant.representative_person_id) then
    return jsonb_build_object('ok',false,'status',403,'code','GRANT_ACCESS_DENIED');
  end if;
  select * into v_doc from public.documents
  where id=p_document_id and owner_person_id=v_person_id and deleted_at is null and scan_status='basic_validated';
  if not found then return jsonb_build_object('ok',false,'status',404,'code','DOCUMENT_NOT_READY'); end if;
  insert into public.grant_evidence(grant_id,document_id) values(p_grant_id,p_document_id)
  on conflict do nothing;
  return jsonb_build_object('ok',true,'grantId',p_grant_id,'documentId',p_document_id,'reviewStatus',v_doc.review_status);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_attach_document_to_request_v08(p_uid uuid, p_request_id text, p_document_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_account_id text;
  v_person_id text;
  v_req public.evidence_requests%rowtype;
  v_grant public.authority_grants%rowtype;
  v_doc public.documents%rowtype;
  v_event_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload text;
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';
  v_person_id:=v_ctx->'person'->>'id';

  select * into v_req from public.evidence_requests
  where id=p_request_id and status in ('open','submitted') for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','EVIDENCE_REQUEST_NOT_OPEN'); end if;

  select * into v_grant from public.authority_grants where id=v_req.grant_id;
  if v_person_id not in (v_grant.principal_person_id,v_grant.representative_person_id) then
    return jsonb_build_object('ok',false,'status',403,'code','GRANT_ACCESS_DENIED');
  end if;

  select * into v_doc from public.documents
  where id=p_document_id and owner_person_id=v_person_id
    and deleted_at is null and scan_status='basic_validated';
  if not found then return jsonb_build_object('ok',false,'status',404,'code','DOCUMENT_NOT_READY'); end if;

  insert into public.evidence_request_documents(request_id,document_id,attached_by_account_id,attached_at)
  values(p_request_id,p_document_id,v_account_id,v_now)
  on conflict do nothing;

  insert into public.grant_evidence(grant_id,document_id)
  values(v_req.grant_id,p_document_id) on conflict do nothing;

  update public.evidence_requests set status='submitted',updated_at=v_now where id=p_request_id;

  perform private.trustrelay_notify_org_v09(
    v_req.requested_by_organization_id,array['owner','admin','compliance','verifier'],
    'evidence','evidence.submitted','success',
    'Evidence submitted',
    'A TrustRelay user submitted evidence for an institutional request.',
    'evidence_request',p_request_id,
    jsonb_build_object('grantId',v_req.grant_id,'documentId',p_document_id)
  );

  perform private.trustrelay_append_org_audit_v09(
    v_req.requested_by_organization_id,v_account_id,'evidence.submitted',
    'evidence_request',p_request_id,
    jsonb_build_object('grantId',v_req.grant_id,'documentId',p_document_id)
  );

  v_payload:=jsonb_build_object(
    'id',v_event_id,'type','evidence.submitted','createdAt',v_now,
    'organizationId',v_req.requested_by_organization_id,
    'data',jsonb_build_object('requestId',p_request_id,'grantId',v_req.grant_id,'documentId',p_document_id)
  )::text;
  perform public.trustrelay_queue_webhooks_v07(v_req.requested_by_organization_id,'evidence.submitted',v_event_id,v_payload);
  perform public.trustrelay_dispatch_due_webhooks_v09(50);

  return jsonb_build_object('ok',true,'requestId',p_request_id,'documentId',p_document_id);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_create_evidence_request_v08(p_uid uuid, p_org_id text, p_grant_id text, p_types jsonb, p_due_at text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_id text:='evreq_'||replace(gen_random_uuid()::text,'-','');
  v_event_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_grant public.authority_grants%rowtype;
  v_account text;
  v_payload text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'evidence.request');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if not exists(
    select 1 from public.authorization_decisions
    where organization_id=p_org_id and grant_id=p_grant_id
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','GRANT_NOT_PREVIOUSLY_EVALUATED');
  end if;

  if p_types is null or jsonb_typeof(p_types)<>'array' or jsonb_array_length(p_types)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','EVIDENCE_TYPES_REQUIRED');
  end if;

  select * into v_grant from public.authority_grants where id=p_grant_id;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND'); end if;

  insert into public.evidence_requests(
    id,grant_id,requested_by_organization_id,requested_by_account_id,
    required_document_types_json,status,due_at,created_at,updated_at
  ) values(v_id,p_grant_id,p_org_id,v_ctx->>'accountId',p_types::text,'open',p_due_at,v_now,v_now);

  for v_account in
    select id from public.accounts
    where person_id in (v_grant.principal_person_id,v_grant.representative_person_id)
      and status='active'
  loop
    perform private.trustrelay_notify_account_v09(
      v_account,p_org_id,'evidence','evidence.requested','warning',
      'Evidence requested',
      'An institution requested supporting evidence for one of your TrustRelay authority grants.',
      'evidence_request',v_id,
      jsonb_build_object('grantId',p_grant_id,'requiredDocumentTypes',p_types,'dueAt',p_due_at)
    );
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','evidence.requested','evidence_request',v_id,
    jsonb_build_object('grantId',p_grant_id,'requiredDocumentTypes',p_types,'dueAt',p_due_at)
  );

  v_payload:=jsonb_build_object(
    'id',v_event_id,'type','evidence.requested','createdAt',v_now,'organizationId',p_org_id,
    'data',jsonb_build_object('requestId',v_id,'grantId',p_grant_id,'requiredDocumentTypes',p_types,'dueAt',p_due_at)
  )::text;
  perform public.trustrelay_queue_webhooks_v07(p_org_id,'evidence.requested',v_event_id,v_payload);
  perform public.trustrelay_dispatch_due_webhooks_v09(50);

  return jsonb_build_object('ok',true,'request',jsonb_build_object(
    'id',v_id,'grantId',p_grant_id,'requiredDocumentTypes',p_types,'status','open','dueAt',p_due_at,'createdAt',v_now
  ));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_document_access_v08(p_uid uuid, p_document_id text, p_mode text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_account_id text;
  v_person_id text;
  v_doc public.documents%rowtype;
  v_is_reviewer boolean:=false;
  v_org_access boolean:=false;
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_account_id:=v_ctx->'account'->>'id';
  v_person_id:=v_ctx->'person'->>'id';

  select * into v_doc
  from public.documents
  where id=p_document_id and deleted_at is null;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','DOCUMENT_NOT_FOUND');
  end if;

  select exists(
    select 1
    from private.identity_reviewers
    where account_id=v_account_id and status='active'
  ) into v_is_reviewer;

  select exists(
    select 1
    from public.evidence_request_documents erd
    join public.evidence_requests er on er.id=erd.request_id
    join public.organization_members om
      on om.organization_id=er.requested_by_organization_id
     and om.account_id=v_account_id
     and om.status='active'
     and om.role in ('owner','admin','verifier','auditor')
    where erd.document_id=p_document_id
      and er.status in ('submitted','satisfied','rejected')
  ) into v_org_access;

  if v_doc.owner_person_id<>v_person_id and not v_is_reviewer and not v_org_access then
    return jsonb_build_object('ok',false,'status',403,'code','DOCUMENT_ACCESS_DENIED');
  end if;

  return jsonb_build_object(
    'ok',true,
    'document',to_jsonb(v_doc),
    'reviewer',v_is_reviewer,
    'organizationEvidenceAccess',v_org_access
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_finalize_document_v08(p_uid uuid, p_document_id text, p_content_sha256 text, p_actual_size integer, p_detected_mime text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_account_id text; v_doc public.documents%rowtype;
v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';

  select * into v_doc from public.documents
  where id=p_document_id and uploaded_by_account_id=v_account_id and deleted_at is null
  for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','DOCUMENT_NOT_FOUND'); end if;
  if v_doc.scan_status<>'upload_pending' then
    return jsonb_build_object('ok',false,'status',409,'code','DOCUMENT_ALREADY_FINALIZED');
  end if;
  if p_actual_size<1 or p_actual_size>10485760 then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_SIZE_INVALID');
  end if;
  if p_detected_mime not in ('application/pdf','image/jpeg','image/png','image/webp') then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_TYPE_NOT_ALLOWED');
  end if;
  if length(coalesce(p_content_sha256,''))<>64 then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_HASH_INVALID');
  end if;

  update public.documents set
    content_sha256=lower(p_content_sha256),size_bytes=p_actual_size,mime_type=p_detected_mime,
    scan_status='basic_validated',
    scan_result_json='{"validation":"type_size_hash_only","malwareScan":"not_integrated"}',
    uploaded_at=coalesce(uploaded_at,v_now),finalized_at=v_now
  where id=p_document_id returning * into v_doc;

  return jsonb_build_object('ok',true,'document',to_jsonb(v_doc));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_identity_center_v08(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_account_id text; v_person_id text;
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';
  v_person_id:=v_ctx->'person'->>'id';

  return jsonb_build_object(
    'ok',true,
    'account',v_ctx->'account',
    'person',v_ctx->'person',
    'sessions',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',s.id,'provider',s.provider,'status',s.status,
        'requestedAssurance',s.requested_assurance,'assuranceLevel',s.assurance_level,
        'submittedAt',s.submitted_at,'reviewedAt',s.reviewed_at,
        'reviewReason',s.review_reason,'createdAt',s.created_at,'updatedAt',s.updated_at
      ) order by s.created_at desc)
      from public.identity_proofing_sessions s where s.account_id=v_account_id
    ),'[]'::jsonb),
    'documents',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',d.id,'proofingSessionId',d.proofing_session_id,'purpose',d.purpose,
        'classification',d.classification,'displayName',d.display_name,
        'originalFilename',d.original_filename,'mimeType',d.mime_type,'sizeBytes',d.size_bytes,
        'scanStatus',d.scan_status,'reviewStatus',d.review_status,
        'contentSha256',case when d.content_sha256='pending' then null else d.content_sha256 end,
        'uploadedAt',d.uploaded_at,'finalizedAt',d.finalized_at,
        'reviewedAt',d.reviewed_at,'reviewReason',d.review_reason,'createdAt',d.created_at
      ) order by d.created_at desc)
      from public.documents d where d.owner_person_id=v_person_id and d.deleted_at is null
    ),'[]'::jsonb),
    'evidenceRequests',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',er.id,'grantId',er.grant_id,'status',er.status,
        'requestingOrganization',case when o.id is null then null else jsonb_build_object('id',o.id,'name',o.name) end,
        'requiredDocumentTypes',coalesce(er.required_document_types_json::jsonb,'[]'::jsonb),
        'dueAt',er.due_at,'createdAt',er.created_at,'updatedAt',er.updated_at,
        'reviewedAt',er.reviewed_at,'resolutionReason',er.resolution_reason,
        'attachedDocumentIds',coalesce((
          select jsonb_agg(erd.document_id order by erd.attached_at)
          from public.evidence_request_documents erd
          where erd.request_id=er.id
        ),'[]'::jsonb)
      ) order by er.created_at desc)
      from public.evidence_requests er
      join public.authority_grants g on g.id=er.grant_id
      left join public.organizations o on o.id=er.requested_by_organization_id
      where g.principal_person_id=v_person_id or g.representative_person_id=v_person_id
    ),'[]'::jsonb)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_prepare_document_v08(p_uid uuid, p_proofing_session_id text, p_purpose text, p_classification text, p_original_filename text, p_mime_type text, p_size_bytes integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_account_id text; v_person_id text; v_session public.identity_proofing_sessions%rowtype;
v_doc public.documents%rowtype; v_id text:='doc_'||replace(gen_random_uuid()::text,'-','');
v_ext text; v_key text; v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id'; v_person_id:=v_ctx->'person'->>'id';

  if p_purpose not in ('identity','grant_evidence','supporting') then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_PURPOSE_INVALID');
  end if;
  if p_classification not in ('government_id_front','government_id_back','passport','address_evidence','authority_document','invoice','supporting_document','other') then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_CLASSIFICATION_INVALID');
  end if;
  if p_mime_type not in ('application/pdf','image/jpeg','image/png','image/webp') then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_TYPE_NOT_ALLOWED');
  end if;
  if p_size_bytes is null or p_size_bytes<1 or p_size_bytes>10485760 then
    return jsonb_build_object('ok',false,'status',400,'code','DOCUMENT_SIZE_INVALID');
  end if;
  if p_purpose='identity' then
    select * into v_session from public.identity_proofing_sessions
    where id=p_proofing_session_id and account_id=v_account_id and status='collecting' limit 1;
    if not found then return jsonb_build_object('ok',false,'status',409,'code','PROOFING_SESSION_NOT_COLLECTING'); end if;
  end if;

  v_ext:=case p_mime_type when 'application/pdf' then '.pdf' when 'image/jpeg' then '.jpg' when 'image/png' then '.png' else '.webp' end;
  v_key:=v_account_id||'/'||coalesce(nullif(p_proofing_session_id,''),'general')||'/'||v_id||v_ext;

  insert into public.documents(
    id,owner_person_id,document_type,display_name,storage_key,encryption_provider,
    content_sha256,mime_type,size_bytes,scan_status,scan_result_json,created_at,
    proofing_session_id,uploaded_by_account_id,purpose,classification,original_filename,
    storage_bucket,review_status,metadata_json
  ) values (
    v_id,v_person_id,p_classification,left(coalesce(nullif(btrim(p_original_filename),''),p_classification),200),
    v_key,'supabase_storage_private','pending',p_mime_type,p_size_bytes,'upload_pending','{}',v_now,
    nullif(p_proofing_session_id,''),v_account_id,p_purpose,p_classification,
    left(coalesce(p_original_filename,''),255),'trustrelay-evidence','pending','{}'
  ) returning * into v_doc;

  return jsonb_build_object('ok',true,'document',to_jsonb(v_doc));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_resolve_evidence_request_v08(p_uid uuid, p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare
  v_ctx jsonb;
  v_req public.evidence_requests%rowtype;
  v_grant public.authority_grants%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_attached integer;
  v_account text;
  v_event_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_payload text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'evidence.review');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if p_resolution not in ('satisfied','rejected') then
    return jsonb_build_object('ok',false,'status',400,'code','EVIDENCE_RESOLUTION_INVALID');
  end if;

  select * into v_req from public.evidence_requests
  where id=p_request_id and requested_by_organization_id=p_org_id and status='submitted'
  for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','EVIDENCE_REQUEST_NOT_REVIEWABLE'); end if;

  select count(*) into v_attached from public.evidence_request_documents where request_id=p_request_id;
  if v_attached<1 then return jsonb_build_object('ok',false,'status',409,'code','EVIDENCE_DOCUMENT_REQUIRED'); end if;

  update public.evidence_requests
  set status=p_resolution,resolved_at=v_now,reviewed_by_account_id=v_ctx->>'accountId',
      reviewed_at=v_now,resolution_reason=nullif(btrim(coalesce(p_reason,'')),''),
      resolution_notes=nullif(left(btrim(coalesce(p_notes,'')),2000),''),
      updated_at=v_now
  where id=p_request_id returning * into v_req;

  select * into v_grant from public.authority_grants where id=v_req.grant_id;

  for v_account in
    select id from public.accounts
    where person_id in (v_grant.principal_person_id,v_grant.representative_person_id)
      and status='active'
  loop
    perform private.trustrelay_notify_account_v09(
      v_account,p_org_id,'evidence','evidence.resolved',
      case when p_resolution='satisfied' then 'success' else 'warning' end,
      case when p_resolution='satisfied' then 'Evidence accepted' else 'Evidence rejected' end,
      'An institution resolved a TrustRelay evidence request as '||p_resolution||'.',
      'evidence_request',p_request_id,
      jsonb_build_object('grantId',v_req.grant_id,'resolution',p_resolution,'reason',p_reason)
    );
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','evidence.resolved','evidence_request',p_request_id,
    jsonb_build_object('grantId',v_req.grant_id,'resolution',p_resolution,'reason',p_reason,'attachedDocumentCount',v_attached)
  );

  v_payload:=jsonb_build_object(
    'id',v_event_id,'type','evidence.resolved','createdAt',v_now,'organizationId',p_org_id,
    'data',jsonb_build_object(
      'requestId',p_request_id,'grantId',v_req.grant_id,'resolution',p_resolution,
      'reason',p_reason,'attachedDocumentCount',v_attached
    )
  )::text;
  perform public.trustrelay_queue_webhooks_v07(p_org_id,'evidence.resolved',v_event_id,v_payload);
  perform public.trustrelay_dispatch_due_webhooks_v09(50);

  return jsonb_build_object('ok',true,'request',to_jsonb(v_req),'attachedDocumentCount',v_attached);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_review_document_v08(p_uid uuid, p_document_id text, p_decision text, p_reason_code text, p_notes text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_reviewer_account text; v_reviewer_person text; v_doc public.documents%rowtype;
v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
v_event_id text:='evrev_'||replace(gen_random_uuid()::text,'-',''); v_hash text;
begin
  v_ctx:=private.trustrelay_reviewer_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_reviewer_account:=v_ctx->'account'->>'id';
  select person_id into v_reviewer_person from public.accounts where id=v_reviewer_account;

  if p_decision not in ('approved','rejected') then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEW_DECISION_INVALID');
  end if;
  select * into v_doc from public.documents where id=p_document_id and deleted_at is null for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','DOCUMENT_NOT_FOUND'); end if;
  if v_doc.owner_person_id=v_reviewer_person then
    return jsonb_build_object('ok',false,'status',403,'code','SELF_REVIEW_FORBIDDEN');
  end if;
  if v_doc.scan_status<>'basic_validated' then
    return jsonb_build_object('ok',false,'status',409,'code','DOCUMENT_NOT_READY');
  end if;

  update public.documents set
    review_status=p_decision,reviewer_account_id=v_reviewer_account,reviewed_at=v_now,
    review_reason=nullif(btrim(coalesce(p_reason_code,'')),''),
    review_notes=nullif(left(btrim(coalesce(p_notes,'')),2000),'')
  where id=p_document_id returning * into v_doc;

  v_hash:=encode(digest(
    concat_ws('|',v_event_id,p_document_id,v_reviewer_account,p_decision,coalesce(p_reason_code,''),v_doc.content_sha256,v_now),
    'sha256'
  ),'hex');

  insert into public.evidence_review_events(
    id,document_id,proofing_session_id,reviewer_account_id,reviewer_type,
    decision,reason_code,notes,event_hash,created_at
  ) values(
    v_event_id,p_document_id,v_doc.proofing_session_id,v_reviewer_account,'trustrelay',
    p_decision,nullif(btrim(coalesce(p_reason_code,'')),''),nullif(left(btrim(coalesce(p_notes,'')),2000),''),
    v_hash,v_now
  );

  return jsonb_build_object('ok',true,'document',to_jsonb(v_doc),'reviewEventId',v_event_id,'eventHash',v_hash);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_review_proofing_v08(p_uid uuid, p_session_id text, p_decision text, p_reason_code text, p_notes text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_reviewer_account text; v_reviewer_person text; v_session public.identity_proofing_sessions%rowtype;
v_account public.accounts%rowtype; v_person public.persons%rowtype; v_old text; v_target text;
v_gov integer; v_addr integer; v_pending integer;
v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
v_event_id text:='assure_'||replace(gen_random_uuid()::text,'-',''); v_hash text;
begin
  v_ctx:=private.trustrelay_reviewer_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_reviewer_account:=v_ctx->'account'->>'id';
  select person_id into v_reviewer_person from public.accounts where id=v_reviewer_account;

  if p_decision not in ('approved','rejected') then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEW_DECISION_INVALID');
  end if;

  select * into v_session from public.identity_proofing_sessions
  where id=p_session_id and status in ('submitted','in_review') for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','PROOFING_SESSION_NOT_REVIEWABLE'); end if;

  select * into v_account from public.accounts where id=v_session.account_id;
  select * into v_person from public.persons where id=v_account.person_id for update;
  if v_person.id=v_reviewer_person then
    return jsonb_build_object('ok',false,'status',403,'code','SELF_REVIEW_FORBIDDEN');
  end if;

  select count(*) into v_pending from public.documents
  where proofing_session_id=p_session_id and deleted_at is null and review_status='pending';
  if p_decision='approved' and v_pending>0 then
    return jsonb_build_object('ok',false,'status',409,'code','DOCUMENT_REVIEWS_INCOMPLETE');
  end if;

  select count(*) into v_gov from public.documents
  where proofing_session_id=p_session_id and deleted_at is null and review_status='approved'
    and classification in ('government_id_front','passport');
  select count(*) into v_addr from public.documents
  where proofing_session_id=p_session_id and deleted_at is null and review_status='approved'
    and classification='address_evidence';

  if p_decision='approved' then
    if v_gov<1 then return jsonb_build_object('ok',false,'status',409,'code','APPROVED_GOVERNMENT_ID_REQUIRED'); end if;
    if v_session.requested_assurance='high_assurance' and v_addr<1 then
      return jsonb_build_object('ok',false,'status',409,'code','APPROVED_ADDRESS_EVIDENCE_REQUIRED');
    end if;
  end if;

  v_old:=v_person.identity_assurance_level;
  v_target:=case when p_decision='approved' then v_session.requested_assurance else v_old end;

  update public.identity_proofing_sessions set
    status=case when p_decision='approved' then 'approved' else 'rejected' end,
    assurance_level=case when p_decision='approved' then v_target else assurance_level end,
    reviewer_account_id=v_reviewer_account,reviewed_at=v_now,completed_at=v_now,updated_at=v_now,
    review_reason=nullif(btrim(coalesce(p_reason_code,'')),''),
    review_notes=nullif(left(btrim(coalesce(p_notes,'')),2000),'')
  where id=p_session_id returning * into v_session;

  if p_decision='approved' and public.trustrelay_assurance_rank_v08(v_target)>public.trustrelay_assurance_rank_v08(v_old) then
    update public.persons set
      identity_status='verified',identity_assurance_level=v_target,identity_verified_at=v_now
    where id=v_person.id returning * into v_person;
  end if;

  v_hash:=encode(digest(
    concat_ws('|',v_event_id,v_person.id,p_session_id,v_reviewer_account,p_decision,v_old,v_target,coalesce(p_reason_code,''),v_now),
    'sha256'
  ),'hex');

  insert into public.identity_assurance_events(
    id,person_id,proofing_session_id,reviewer_account_id,provider,from_level,to_level,
    decision,reason_code,event_hash,created_at
  ) values(
    v_event_id,v_person.id,p_session_id,v_reviewer_account,'trustrelay_manual',v_old,v_target,
    p_decision,nullif(btrim(coalesce(p_reason_code,'')),''),v_hash,v_now
  );

  return jsonb_build_object('ok',true,'session',to_jsonb(v_session),'person',to_jsonb(v_person),'assuranceEventId',v_event_id,'eventHash',v_hash);
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_review_queue_v08(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb;
begin
  v_ctx:=private.trustrelay_reviewer_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  return jsonb_build_object(
    'ok',true,
    'sessions',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',s.id,'status',s.status,'requestedAssurance',s.requested_assurance,
        'submittedAt',s.submitted_at,'createdAt',s.created_at,
        'person',jsonb_build_object('id',p.id,'displayName',p.display_name,'email',p.email,'currentAssurance',p.identity_assurance_level),
        'documents',coalesce((
          select jsonb_agg(jsonb_build_object(
            'id',d.id,'classification',d.classification,'displayName',d.display_name,
            'mimeType',d.mime_type,'sizeBytes',d.size_bytes,'reviewStatus',d.review_status,
            'contentSha256',case when d.content_sha256='pending' then null else d.content_sha256 end
          ) order by d.created_at)
          from public.documents d where d.proofing_session_id=s.id and d.deleted_at is null
        ),'[]'::jsonb)
      ) order by s.submitted_at nulls last,s.created_at)
      from public.identity_proofing_sessions s
      join public.accounts a on a.id=s.account_id
      join public.persons p on p.id=a.person_id
      where s.status in ('submitted','in_review')
    ),'[]'::jsonb)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_reviewer_context_v08(p_uid uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_account public.accounts%rowtype; v_reviewer private.identity_reviewers%rowtype;
begin
  select * into v_account from public.accounts where auth_user_id=p_uid and status='active' limit 1;
  if not found then return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND'); end if;
  select * into v_reviewer from private.identity_reviewers where account_id=v_account.id and status='active';
  if not found then return jsonb_build_object('ok',false,'status',403,'code','IDENTITY_REVIEWER_REQUIRED'); end if;
  return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'reviewer',to_jsonb(v_reviewer));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_start_proofing_v08(p_uid uuid, p_requested_assurance text, p_consent_version text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_account_id text; v_person_id text; v_existing public.identity_proofing_sessions%rowtype;
v_id text:='proof_'||replace(gen_random_uuid()::text,'-','');
v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_requested_assurance not in ('document_verified','high_assurance') then
    return jsonb_build_object('ok',false,'status',400,'code','ASSURANCE_LEVEL_INVALID');
  end if;
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id'; v_person_id:=v_ctx->'person'->>'id';

  select * into v_existing from public.identity_proofing_sessions
  where account_id=v_account_id and status in ('collecting','submitted','in_review')
  order by created_at desc limit 1;
  if found then
    return jsonb_build_object('ok',true,'existing',true,'session',to_jsonb(v_existing));
  end if;

  insert into public.identity_proofing_sessions(
    id,account_id,subject_person_id,provider,status,assurance_level,requested_assurance,
    result_json,consent_at,consent_version,evidence_snapshot_json,risk_flags_json,created_at,updated_at
  ) values (
    v_id,v_account_id,v_person_id,'trustrelay_manual','collecting',null,p_requested_assurance,
    '{}',v_now,coalesce(nullif(btrim(p_consent_version),''),'v0.8'),
    '{}','[]',v_now,v_now
  ) returning * into v_existing;
  return jsonb_build_object('ok',true,'existing',false,'session',to_jsonb(v_existing));
end;
$function$;

CREATE OR REPLACE FUNCTION private.trustrelay_submit_proofing_v08(p_uid uuid, p_session_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare v_ctx jsonb; v_account_id text; v_session public.identity_proofing_sessions%rowtype;
v_gov integer; v_addr integer;
v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_account_context_v08(p_uid);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_account_id:=v_ctx->'account'->>'id';

  select * into v_session from public.identity_proofing_sessions
  where id=p_session_id and account_id=v_account_id for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','PROOFING_SESSION_NOT_FOUND'); end if;
  if v_session.status<>'collecting' then
    return jsonb_build_object('ok',false,'status',409,'code','PROOFING_SESSION_NOT_COLLECTING');
  end if;

  select count(*) into v_gov from public.documents
  where proofing_session_id=p_session_id and deleted_at is null
    and scan_status='basic_validated'
    and classification in ('government_id_front','passport');

  select count(*) into v_addr from public.documents
  where proofing_session_id=p_session_id and deleted_at is null
    and scan_status='basic_validated' and classification='address_evidence';

  if v_gov<1 then return jsonb_build_object('ok',false,'status',409,'code','GOVERNMENT_ID_REQUIRED'); end if;
  if v_session.requested_assurance='high_assurance' and v_addr<1 then
    return jsonb_build_object('ok',false,'status',409,'code','ADDRESS_EVIDENCE_REQUIRED');
  end if;

  update public.identity_proofing_sessions set
    status='submitted',submitted_at=v_now,updated_at=v_now,
    evidence_snapshot_json=jsonb_build_object(
      'governmentIdCount',v_gov,'addressEvidenceCount',v_addr,
      'documentIds',coalesce((
        select jsonb_agg(id order by created_at)
        from public.documents where proofing_session_id=p_session_id and deleted_at is null and scan_status='basic_validated'
      ),'[]'::jsonb)
    )::text
  where id=p_session_id returning * into v_session;

  return jsonb_build_object('ok',true,'session',to_jsonb(v_session));
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_apply_provider_result_v08(p_session_id text, p_provider text, p_provider_reference text, p_approved boolean, p_assurance_level text, p_provider_result_json text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions', 'pg_catalog'
AS $function$
declare
  v_session public.identity_proofing_sessions%rowtype;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_old text;
  v_target text;
  v_hash text;
  v_event_id text:='assure_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if length(btrim(coalesce(p_provider,'')))<2 then
    return jsonb_build_object('ok',false,'status',400,'code','PROVIDER_INVALID');
  end if;

  if p_approved and p_assurance_level not in ('document_verified','high_assurance') then
    return jsonb_build_object('ok',false,'status',400,'code','ASSURANCE_LEVEL_INVALID');
  end if;

  begin
    perform coalesce(p_provider_result_json,'{}')::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','PROVIDER_RESULT_INVALID');
  end;

  select * into v_session
  from public.identity_proofing_sessions
  where id=p_session_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','PROOFING_SESSION_NOT_FOUND');
  end if;

  if v_session.status not in ('collecting','submitted','in_review') then
    return jsonb_build_object('ok',false,'status',409,'code','PROOFING_SESSION_NOT_REVIEWABLE');
  end if;

  if p_approved and p_assurance_level<>v_session.requested_assurance then
    return jsonb_build_object('ok',false,'status',409,'code','ASSURANCE_CONSENT_MISMATCH');
  end if;

  select * into v_account from public.accounts where id=v_session.account_id;
  select * into v_person from public.persons where id=v_account.person_id for update;

  v_old:=v_person.identity_assurance_level;
  v_target:=case when p_approved then p_assurance_level else v_old end;
  v_hash:=encode(digest(coalesce(p_provider_result_json,'{}'),'sha256'),'hex');

  update public.identity_proofing_sessions
  set
    provider=p_provider,
    provider_reference=p_provider_reference,
    provider_result_hash=v_hash,
    result_json=coalesce(p_provider_result_json,'{}'),
    status=case when p_approved then 'approved' else 'rejected' end,
    assurance_level=case when p_approved then v_target else assurance_level end,
    review_reason=case when p_approved then 'PROVIDER_APPROVED' else 'PROVIDER_REJECTED' end,
    reviewed_at=v_now,
    completed_at=v_now,
    updated_at=v_now
  where id=p_session_id
  returning * into v_session;

  if p_approved
     and public.trustrelay_assurance_rank_v08(v_target)>public.trustrelay_assurance_rank_v08(v_old) then
    update public.persons
    set identity_status='verified',identity_assurance_level=v_target,identity_verified_at=v_now
    where id=v_person.id
    returning * into v_person;
  end if;

  insert into public.identity_assurance_events(
    id,person_id,proofing_session_id,reviewer_account_id,provider,from_level,to_level,
    decision,reason_code,event_hash,created_at
  ) values(
    v_event_id,v_person.id,p_session_id,null,p_provider,v_old,v_target,
    case when p_approved then 'approved' else 'rejected' end,
    case when p_approved then 'PROVIDER_APPROVED' else 'PROVIDER_REJECTED' end,
    encode(digest(concat_ws('|',v_event_id,v_person.id,p_session_id,p_provider,v_old,v_target,v_hash,v_now),'sha256'),'hex'),
    v_now
  );

  return jsonb_build_object(
    'ok',true,
    'session',to_jsonb(v_session),
    'person',to_jsonb(v_person),
    'providerResultHash',v_hash
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_assurance_rank_v08(p_level text)
 RETURNS integer
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO 'pg_catalog'
AS $function$
  select case p_level
    when 'none' then 0
    when 'email_verified' then 1
    when 'document_verified' then 2
    when 'high_assurance' then 3
    else -1
  end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_attach_document_to_grant_v08(p_grant_id text, p_document_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_attach_document_to_grant_v08(auth.uid(),p_grant_id,p_document_id);$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_attach_document_to_request_v08(p_request_id text, p_document_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_attach_document_to_request_v08(auth.uid(),p_request_id,p_document_id);$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_create_evidence_request_v08(p_org_id text, p_grant_id text, p_types jsonb, p_due_at text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_create_evidence_request_v08(auth.uid(),p_org_id,p_grant_id,p_types,p_due_at);$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_evaluate_authority_v07(p_authority jsonb, p_action text, p_resource text, p_amount numeric, p_currency text, p_evidence jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO 'pg_catalog'
AS $function$
declare
  v_allowed jsonb := coalesce(p_authority->'allowed','[]'::jsonb);
  v_prohibited jsonb := coalesce(p_authority->'prohibited','[]'::jsonb);
  v_resources jsonb := coalesce(p_authority->'resources','[]'::jsonb);
  v_rules jsonb := coalesce(p_authority->'rules','{}'::jsonb);
  v_escalation jsonb := coalesce(p_authority->'escalation','{}'::jsonb);
  v_pattern text; v_resource_match boolean := false; v_key text; v_limit numeric;
  v_min text; v_principal_level text; v_rep_level text; v_verified_count integer;
begin
  if v_prohibited ? p_action then
    return jsonb_build_object('decision','DENY','reasonCode','ACTION_PROHIBITED','reasonDetail','The action is explicitly prohibited by the grant.');
  end if;
  if not (v_allowed ? p_action) then
    return jsonb_build_object('decision','DENY','reasonCode','ACTION_NOT_ALLOWED','reasonDetail','The action is outside the grant''s allowed scope.');
  end if;
  for v_pattern in select jsonb_array_elements_text(v_resources) loop
    if v_pattern='*' or v_pattern=p_resource or (right(v_pattern,1)='*' and left(p_resource,length(v_pattern)-1)=left(v_pattern,length(v_pattern)-1)) then
      v_resource_match:=true; exit;
    end if;
  end loop;
  if not v_resource_match then
    return jsonb_build_object('decision','DENY','reasonCode','RESOURCE_NOT_ALLOWED','reasonDetail','The resource is outside the grant''s resource scope.');
  end if;

  for v_key in select jsonb_object_keys(v_rules) loop
    if v_key not in ('maxAmount','allowedCurrencies','requireEvidence','minimumAssurance','requireVerifiedEvidence') then
      return jsonb_build_object('decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED','reasonDetail','The grant contains policy rules that require manual review.');
    end if;
  end loop;

  if v_rules ? 'minimumAssurance' then
    v_min:=v_rules->>'minimumAssurance';
    v_principal_level:=p_authority->'currentAssurance'->'principal'->>'assuranceLevel';
    v_rep_level:=p_authority->'currentAssurance'->'representative'->>'assuranceLevel';
    if public.trustrelay_assurance_rank_v08(v_min)<0 then
      return jsonb_build_object('decision','ESCALATE','reasonCode','ASSURANCE_POLICY_INVALID','reasonDetail','The minimum assurance policy requires manual review.');
    end if;
    if public.trustrelay_assurance_rank_v08(coalesce(v_principal_level,'none'))<public.trustrelay_assurance_rank_v08(v_min)
       or public.trustrelay_assurance_rank_v08(coalesce(v_rep_level,'none'))<public.trustrelay_assurance_rank_v08(v_min) then
      return jsonb_build_object('decision','DENY','reasonCode','IDENTITY_ASSURANCE_INSUFFICIENT','reasonDetail','One or more parties do not currently meet the grant''s minimum identity assurance level.');
    end if;
  end if;

  if jsonb_typeof(v_rules->'allowedCurrencies')='array' then
    if p_amount is not null and nullif(btrim(coalesce(p_currency,'')),'') is null then
      return jsonb_build_object('decision','DENY','reasonCode','CURRENCY_REQUIRED','reasonDetail','A currency is required for this monetary request.');
    end if;
    if p_currency is not null and not ((v_rules->'allowedCurrencies') ? upper(p_currency)) then
      return jsonb_build_object('decision','DENY','reasonCode','CURRENCY_NOT_ALLOWED','reasonDetail','The requested currency is not permitted by the grant.');
    end if;
  end if;

  if v_rules ? 'maxAmount' and p_amount is not null then
    begin v_limit := (v_rules->>'maxAmount')::numeric;
    exception when others then
      return jsonb_build_object('decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED','reasonDetail','The amount rule could not be evaluated automatically.');
    end;
    if p_amount<0 then return jsonb_build_object('decision','DENY','reasonCode','AMOUNT_INVALID','reasonDetail','The requested amount is invalid.'); end if;
    if p_amount>v_limit then
      if upper(coalesce(v_escalation->>'aboveLimit',''))='ESCALATE' then
        return jsonb_build_object('decision','ESCALATE','reasonCode','AMOUNT_ABOVE_LIMIT','reasonDetail','The amount exceeds the grant limit and requires escalation.');
      end if;
      return jsonb_build_object('decision','DENY','reasonCode','AMOUNT_ABOVE_LIMIT','reasonDetail','The amount exceeds the grant limit.');
    end if;
  end if;

  begin v_verified_count:=coalesce((p_evidence->>'verifiedDocumentCount')::integer,0);
  exception when others then v_verified_count:=0; end;

  if coalesce((v_rules->>'requireVerifiedEvidence')::boolean,false) and v_verified_count<1 then
    return jsonb_build_object('decision','ESCALATE','reasonCode','VERIFIED_EVIDENCE_REQUIRED','reasonDetail','Approved TrustRelay evidence linked to this grant is required.');
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
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_get_grant_assurance_v08(p_grant_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare v_g public.authority_grants%rowtype; v_p public.persons%rowtype; v_r public.persons%rowtype;
begin
  select * into v_g from public.authority_grants where id=p_grant_id;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND'); end if;
  select * into v_p from public.persons where id=v_g.principal_person_id;
  select * into v_r from public.persons where id=v_g.representative_person_id;
  return jsonb_build_object(
    'ok',true,
    'principal',jsonb_build_object('personId',v_p.id,'identityStatus',v_p.identity_status,'assuranceLevel',v_p.identity_assurance_level,'verifiedAt',v_p.identity_verified_at),
    'representative',case when v_r.id is null then null else jsonb_build_object('personId',v_r.id,'identityStatus',v_r.identity_status,'assuranceLevel',v_r.identity_assurance_level,'verifiedAt',v_r.identity_verified_at) end
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_identity_center_v08()
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$ select private.trustrelay_identity_center_v08(auth.uid()); $function$;

CREATE OR REPLACE FUNCTION public.trustrelay_refresh_grant_status_v06(p_grant_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare
  v_grant public.authority_grants%rowtype;
  v_principal public.persons%rowtype;
  v_rep public.persons%rowtype;
  v_rules jsonb;
  v_min text;
  v_has_min boolean := false;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_grant from public.authority_grants where id=p_grant_id for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND'); end if;
  if v_grant.status not in ('pending_verification','active') then
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',false);
  end if;
  if v_grant.representative_person_id is null then
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',false);
  end if;

  select * into v_principal from public.persons where id=v_grant.principal_person_id;
  select * into v_rep from public.persons where id=v_grant.representative_person_id;
  begin v_rules:=coalesce(v_grant.rules_json::jsonb,'{}'::jsonb); exception when others then v_rules:='{}'::jsonb; end;

  v_has_min := v_rules ? 'minimumAssurance';
  if v_has_min then
    v_min:=v_rules->>'minimumAssurance';
    if public.trustrelay_assurance_rank_v08(v_min)<0 then
      return jsonb_build_object('ok',false,'status',409,'code','ASSURANCE_POLICY_INVALID');
    end if;
  end if;

  if v_principal.identity_status='verified'
     and v_rep.identity_status='verified'
     and (
       not v_has_min
       or (
         public.trustrelay_assurance_rank_v08(v_principal.identity_assurance_level)>=public.trustrelay_assurance_rank_v08(v_min)
         and public.trustrelay_assurance_rank_v08(v_rep.identity_assurance_level)>=public.trustrelay_assurance_rank_v08(v_min)
       )
     ) then
    if v_grant.status <> 'active' then
      update public.authority_grants
      set status='active',activated_at=coalesce(activated_at,v_now),updated_at=v_now
      where id=v_grant.id returning * into v_grant;
    end if;
    return jsonb_build_object('ok',true,'grant',to_jsonb(v_grant),'activated',true,'minimumAssurance',case when v_has_min then v_min else null end);
  end if;

  if v_grant.status='active' then
    update public.authority_grants set status='pending_verification',updated_at=v_now
    where id=v_grant.id returning * into v_grant;
  end if;

  return jsonb_build_object(
    'ok',true,'grant',to_jsonb(v_grant),'activated',false,
    'minimumAssurance',case when v_has_min then v_min else null end,
    'principalAssurance',v_principal.identity_assurance_level,
    'representativeAssurance',v_rep.identity_assurance_level
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_resolve_evidence_request_v08(p_org_id text, p_request_id text, p_resolution text, p_reason text DEFAULT NULL::text, p_notes text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$
  select private.trustrelay_resolve_evidence_request_v08(
    auth.uid(),p_org_id,p_request_id,p_resolution,p_reason,p_notes
  );
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_resolve_grant_evidence_v08(p_grant_id text, p_document_ids jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare v_ids text[]; v_count integer; v_docs jsonb;
begin
  if p_document_ids is null or jsonb_typeof(p_document_ids)<>'array' then
    return jsonb_build_object('ok',true,'verifiedDocumentCount',0,'documents','[]'::jsonb);
  end if;
  select coalesce(array_agg(value),array[]::text[]) into v_ids from jsonb_array_elements_text(p_document_ids);
  select count(*),coalesce(jsonb_agg(jsonb_build_object(
    'id',d.id,'classification',d.classification,'contentSha256',d.content_sha256,
    'reviewedAt',d.reviewed_at,'reviewStatus',d.review_status
  ) order by d.id),'[]'::jsonb)
  into v_count,v_docs
  from public.grant_evidence ge
  join public.documents d on d.id=ge.document_id
  where ge.grant_id=p_grant_id
    and d.id=any(v_ids)
    and d.deleted_at is null
    and d.scan_status='basic_validated'
    and d.review_status='approved';
  return jsonb_build_object('ok',true,'verifiedDocumentCount',v_count,'documents',v_docs);
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_review_document_v08(p_document_id text, p_decision text, p_reason_code text DEFAULT NULL::text, p_notes text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_review_document_v08(auth.uid(),p_document_id,p_decision,p_reason_code,p_notes);$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_review_proofing_v08(p_session_id text, p_decision text, p_reason_code text DEFAULT NULL::text, p_notes text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_review_proofing_v08(auth.uid(),p_session_id,p_decision,p_reason_code,p_notes);$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_review_queue_v08()
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_review_queue_v08(auth.uid());$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_set_identity_reviewer_v08(p_account_id text, p_role text, p_enabled boolean)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'pg_catalog'
AS $function$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if not exists(select 1 from public.accounts where id=p_account_id) then
    return jsonb_build_object('ok',false,'status',404,'code','ACCOUNT_NOT_FOUND');
  end if;

  if p_role not in ('reviewer','senior_reviewer') then
    return jsonb_build_object('ok',false,'status',400,'code','REVIEWER_ROLE_INVALID');
  end if;

  insert into private.identity_reviewers(account_id,reviewer_role,status,created_at)
  values(
    p_account_id,
    p_role,
    case when p_enabled then 'active' else 'disabled' end,
    v_now
  )
  on conflict(account_id) do update set
    reviewer_role=excluded.reviewer_role,
    status=excluded.status;

  return jsonb_build_object(
    'ok',true,
    'accountId',p_account_id,
    'reviewerRole',p_role,
    'status',case when p_enabled then 'active' else 'disabled' end
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.trustrelay_start_proofing_v08(p_requested_assurance text, p_consent_version text DEFAULT 'v0.8'::text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$ select private.trustrelay_start_proofing_v08(auth.uid(),p_requested_assurance,p_consent_version); $function$;

CREATE OR REPLACE FUNCTION public.trustrelay_submit_proofing_v08(p_session_id text)
 RETURNS jsonb
 LANGUAGE sql
 SET search_path TO 'private', 'auth', 'pg_catalog'
AS $function$select private.trustrelay_submit_proofing_v08(auth.uid(),p_session_id);$function$;


-- Function execution ACLs
revoke all on function private.trustrelay_account_context_v08(p_uid uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_account_context_v08(p_uid uuid) to authenticated;
grant execute on function private.trustrelay_account_context_v08(p_uid uuid) to service_role;
revoke all on function private.trustrelay_attach_document_to_grant_v08(p_uid uuid, p_grant_id text, p_document_id text) from public,anon,authenticated;
revoke all on function private.trustrelay_attach_document_to_request_v08(p_uid uuid, p_request_id text, p_document_id text) from public,anon,authenticated;
revoke all on function private.trustrelay_create_evidence_request_v08(p_uid uuid, p_org_id text, p_grant_id text, p_types jsonb, p_due_at text) from public,anon,authenticated;
revoke all on function private.trustrelay_document_access_v08(p_uid uuid, p_document_id text, p_mode text) from public,anon,authenticated;
grant execute on function private.trustrelay_document_access_v08(p_uid uuid, p_document_id text, p_mode text) to service_role;
revoke all on function private.trustrelay_finalize_document_v08(p_uid uuid, p_document_id text, p_content_sha256 text, p_actual_size integer, p_detected_mime text) from public,anon,authenticated;
grant execute on function private.trustrelay_finalize_document_v08(p_uid uuid, p_document_id text, p_content_sha256 text, p_actual_size integer, p_detected_mime text) to service_role;
revoke all on function private.trustrelay_identity_center_v08(p_uid uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_identity_center_v08(p_uid uuid) to authenticated;
grant execute on function private.trustrelay_identity_center_v08(p_uid uuid) to service_role;
revoke all on function private.trustrelay_prepare_document_v08(p_uid uuid, p_proofing_session_id text, p_purpose text, p_classification text, p_original_filename text, p_mime_type text, p_size_bytes integer) from public,anon,authenticated;
grant execute on function private.trustrelay_prepare_document_v08(p_uid uuid, p_proofing_session_id text, p_purpose text, p_classification text, p_original_filename text, p_mime_type text, p_size_bytes integer) to service_role;
revoke all on function private.trustrelay_resolve_evidence_request_v08(p_uid uuid, p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) from public,anon,authenticated;
grant execute on function private.trustrelay_resolve_evidence_request_v08(p_uid uuid, p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) to authenticated;
grant execute on function private.trustrelay_resolve_evidence_request_v08(p_uid uuid, p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) to service_role;
revoke all on function private.trustrelay_review_document_v08(p_uid uuid, p_document_id text, p_decision text, p_reason_code text, p_notes text) from public,anon,authenticated;
grant execute on function private.trustrelay_review_document_v08(p_uid uuid, p_document_id text, p_decision text, p_reason_code text, p_notes text) to authenticated;
grant execute on function private.trustrelay_review_document_v08(p_uid uuid, p_document_id text, p_decision text, p_reason_code text, p_notes text) to service_role;
revoke all on function private.trustrelay_review_proofing_v08(p_uid uuid, p_session_id text, p_decision text, p_reason_code text, p_notes text) from public,anon,authenticated;
grant execute on function private.trustrelay_review_proofing_v08(p_uid uuid, p_session_id text, p_decision text, p_reason_code text, p_notes text) to authenticated;
grant execute on function private.trustrelay_review_proofing_v08(p_uid uuid, p_session_id text, p_decision text, p_reason_code text, p_notes text) to service_role;
revoke all on function private.trustrelay_review_queue_v08(p_uid uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_reviewer_context_v08(p_uid uuid) from public,anon,authenticated;
grant execute on function private.trustrelay_reviewer_context_v08(p_uid uuid) to authenticated;
grant execute on function private.trustrelay_reviewer_context_v08(p_uid uuid) to service_role;
revoke all on function private.trustrelay_start_proofing_v08(p_uid uuid, p_requested_assurance text, p_consent_version text) from public,anon,authenticated;
grant execute on function private.trustrelay_start_proofing_v08(p_uid uuid, p_requested_assurance text, p_consent_version text) to authenticated;
grant execute on function private.trustrelay_start_proofing_v08(p_uid uuid, p_requested_assurance text, p_consent_version text) to service_role;
revoke all on function private.trustrelay_submit_proofing_v08(p_uid uuid, p_session_id text) from public,anon,authenticated;
revoke all on function public.trustrelay_apply_provider_result_v08(p_session_id text, p_provider text, p_provider_reference text, p_approved boolean, p_assurance_level text, p_provider_result_json text) from public,anon,authenticated;
grant execute on function public.trustrelay_apply_provider_result_v08(p_session_id text, p_provider text, p_provider_reference text, p_approved boolean, p_assurance_level text, p_provider_result_json text) to service_role;
revoke all on function public.trustrelay_assurance_rank_v08(p_level text) from public,anon,authenticated;
grant execute on function public.trustrelay_assurance_rank_v08(p_level text) to anon;
grant execute on function public.trustrelay_assurance_rank_v08(p_level text) to authenticated;
grant execute on function public.trustrelay_assurance_rank_v08(p_level text) to service_role;
revoke all on function public.trustrelay_attach_document_to_grant_v08(p_grant_id text, p_document_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_attach_document_to_grant_v08(p_grant_id text, p_document_id text) to authenticated;
grant execute on function public.trustrelay_attach_document_to_grant_v08(p_grant_id text, p_document_id text) to service_role;
revoke all on function public.trustrelay_attach_document_to_request_v08(p_request_id text, p_document_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_attach_document_to_request_v08(p_request_id text, p_document_id text) to authenticated;
grant execute on function public.trustrelay_attach_document_to_request_v08(p_request_id text, p_document_id text) to service_role;
revoke all on function public.trustrelay_create_evidence_request_v08(p_org_id text, p_grant_id text, p_types jsonb, p_due_at text) from public,anon,authenticated;
grant execute on function public.trustrelay_create_evidence_request_v08(p_org_id text, p_grant_id text, p_types jsonb, p_due_at text) to authenticated;
grant execute on function public.trustrelay_create_evidence_request_v08(p_org_id text, p_grant_id text, p_types jsonb, p_due_at text) to service_role;
revoke all on function public.trustrelay_evaluate_authority_v07(p_authority jsonb, p_action text, p_resource text, p_amount numeric, p_currency text, p_evidence jsonb) from public,anon,authenticated;
grant execute on function public.trustrelay_evaluate_authority_v07(p_authority jsonb, p_action text, p_resource text, p_amount numeric, p_currency text, p_evidence jsonb) to service_role;
revoke all on function public.trustrelay_get_grant_assurance_v08(p_grant_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_get_grant_assurance_v08(p_grant_id text) to service_role;
revoke all on function public.trustrelay_identity_center_v08() from public,anon,authenticated;
grant execute on function public.trustrelay_identity_center_v08() to authenticated;
grant execute on function public.trustrelay_identity_center_v08() to service_role;
revoke all on function public.trustrelay_refresh_grant_status_v06(p_grant_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_refresh_grant_status_v06(p_grant_id text) to service_role;
revoke all on function public.trustrelay_resolve_evidence_request_v08(p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) from public,anon,authenticated;
grant execute on function public.trustrelay_resolve_evidence_request_v08(p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) to authenticated;
grant execute on function public.trustrelay_resolve_evidence_request_v08(p_org_id text, p_request_id text, p_resolution text, p_reason text, p_notes text) to service_role;
revoke all on function public.trustrelay_resolve_grant_evidence_v08(p_grant_id text, p_document_ids jsonb) from public,anon,authenticated;
grant execute on function public.trustrelay_resolve_grant_evidence_v08(p_grant_id text, p_document_ids jsonb) to service_role;
revoke all on function public.trustrelay_review_document_v08(p_document_id text, p_decision text, p_reason_code text, p_notes text) from public,anon,authenticated;
grant execute on function public.trustrelay_review_document_v08(p_document_id text, p_decision text, p_reason_code text, p_notes text) to authenticated;
grant execute on function public.trustrelay_review_document_v08(p_document_id text, p_decision text, p_reason_code text, p_notes text) to service_role;
revoke all on function public.trustrelay_review_proofing_v08(p_session_id text, p_decision text, p_reason_code text, p_notes text) from public,anon,authenticated;
grant execute on function public.trustrelay_review_proofing_v08(p_session_id text, p_decision text, p_reason_code text, p_notes text) to authenticated;
grant execute on function public.trustrelay_review_proofing_v08(p_session_id text, p_decision text, p_reason_code text, p_notes text) to service_role;
revoke all on function public.trustrelay_review_queue_v08() from public,anon,authenticated;
grant execute on function public.trustrelay_review_queue_v08() to authenticated;
grant execute on function public.trustrelay_review_queue_v08() to service_role;
revoke all on function public.trustrelay_set_identity_reviewer_v08(p_account_id text, p_role text, p_enabled boolean) from public,anon,authenticated;
grant execute on function public.trustrelay_set_identity_reviewer_v08(p_account_id text, p_role text, p_enabled boolean) to service_role;
revoke all on function public.trustrelay_start_proofing_v08(p_requested_assurance text, p_consent_version text) from public,anon,authenticated;
grant execute on function public.trustrelay_start_proofing_v08(p_requested_assurance text, p_consent_version text) to authenticated;
grant execute on function public.trustrelay_start_proofing_v08(p_requested_assurance text, p_consent_version text) to service_role;
revoke all on function public.trustrelay_submit_proofing_v08(p_session_id text) from public,anon,authenticated;
grant execute on function public.trustrelay_submit_proofing_v08(p_session_id text) to authenticated;
grant execute on function public.trustrelay_submit_proofing_v08(p_session_id text) to service_role;

-- Table ACL hardening
revoke all on public.evidence_review_events from anon,authenticated;
grant all on public.evidence_review_events to service_role;
revoke all on public.identity_assurance_events from anon,authenticated;
grant all on public.identity_assurance_events to service_role;
revoke all on public.evidence_requests from anon,authenticated;
grant all on public.evidence_requests to service_role;
revoke all on public.evidence_request_documents from anon,authenticated;
grant all on public.evidence_request_documents to service_role;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('trustrelay-evidence','trustrelay-evidence',false,10485760,array['application/pdf','image/jpeg','image/png','image/webp']::text[])
on conflict(id) do update set public=false,file_size_limit=10485760,allowed_mime_types=excluded.allowed_mime_types;
