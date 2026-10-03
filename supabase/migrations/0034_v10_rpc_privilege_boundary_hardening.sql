-- TrustRelay v1.0 RPC identity-boundary hardening.
-- SECURITY DEFINER implementations remain private. Public RPCs stay SECURITY INVOKER.
-- Every client-supplied actor UUID is either bound to auth.uid() at a guarded primitive
-- or routed through a guarded private wrapper.

create or replace function private.trustrelay_request_actor_matches_v10(p_uid uuid)
returns boolean
language sql
stable
set search_path=auth,pg_catalog
as $$
  select case
    when coalesce(auth.role(),'') in ('anon','authenticated')
      then auth.uid() is not distinct from p_uid
    else true
  end;
$$;
revoke all on function private.trustrelay_request_actor_matches_v10(uuid) from public,anon;
grant execute on function private.trustrelay_request_actor_matches_v10(uuid) to authenticated;

-- Guard the two foundational actor-context functions used by most privileged RPCs.
do $$
begin
  if to_regprocedure('private.trustrelay_account_context_core_v10(uuid)') is null then
    alter function private.trustrelay_account_context_v08(uuid) rename to trustrelay_account_context_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_require_org_role_core_v10(uuid,text,text[])') is null then
    alter function private.trustrelay_require_org_role_v07(uuid,text,text[]) rename to trustrelay_require_org_role_core_v10;
  end if;
end $$;

revoke all on function private.trustrelay_account_context_core_v10(uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_require_org_role_core_v10(uuid,text,text[]) from public,anon,authenticated;

create or replace function private.trustrelay_account_context_v08(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path=private,auth,pg_catalog
as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_account_context_core_v10(p_uid);
end;
$$;
revoke all on function private.trustrelay_account_context_v08(uuid) from public,anon;
grant execute on function private.trustrelay_account_context_v08(uuid) to authenticated;

create or replace function private.trustrelay_require_org_role_v07(p_uid uuid,p_org_id text,p_roles text[])
returns jsonb
language plpgsql
security definer
set search_path=private,auth,pg_catalog
as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$$;
revoke all on function private.trustrelay_require_org_role_v07(uuid,text,text[]) from public,anon;
grant execute on function private.trustrelay_require_org_role_v07(uuid,text,text[]) to authenticated;

-- Standalone actor-RPCs that do not flow through the guarded primitives.
do $$
begin
  if to_regprocedure('private.trustrelay_accept_org_invite_core_v10(uuid,text)') is null then
    alter function private.trustrelay_accept_org_invite_v07(uuid,text) rename to trustrelay_accept_org_invite_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_create_organization_core_v10(uuid,text,text,text)') is null then
    alter function private.trustrelay_create_organization_v07(uuid,text,text,text) rename to trustrelay_create_organization_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_my_organizations_core_v10(uuid)') is null then
    alter function private.trustrelay_my_organizations_v07(uuid) rename to trustrelay_my_organizations_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_review_document_core_v10(uuid,text,text,text,text)') is null then
    alter function private.trustrelay_review_document_v08(uuid,text,text,text,text) rename to trustrelay_review_document_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_review_proofing_core_v10(uuid,text,text,text,text)') is null then
    alter function private.trustrelay_review_proofing_v08(uuid,text,text,text,text) rename to trustrelay_review_proofing_core_v10;
  end if;
  if to_regprocedure('private.trustrelay_review_queue_core_v10(uuid)') is null then
    alter function private.trustrelay_review_queue_v08(uuid) rename to trustrelay_review_queue_core_v10;
  end if;
end $$;

revoke all on function private.trustrelay_accept_org_invite_core_v10(uuid,text) from public,anon,authenticated;
revoke all on function private.trustrelay_create_organization_core_v10(uuid,text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_my_organizations_core_v10(uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_review_document_core_v10(uuid,text,text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_review_proofing_core_v10(uuid,text,text,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_review_queue_core_v10(uuid) from public,anon,authenticated;

create or replace function private.trustrelay_accept_org_invite_v07(p_uid uuid,p_token text)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_accept_org_invite_core_v10(p_uid,p_token);
end; $$;
revoke all on function private.trustrelay_accept_org_invite_v07(uuid,text) from public,anon;
grant execute on function private.trustrelay_accept_org_invite_v07(uuid,text) to authenticated;

create or replace function private.trustrelay_create_organization_v07(p_uid uuid,p_name text,p_industry text,p_website text)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_create_organization_core_v10(p_uid,p_name,p_industry,p_website);
end; $$;
revoke all on function private.trustrelay_create_organization_v07(uuid,text,text,text) from public,anon;
grant execute on function private.trustrelay_create_organization_v07(uuid,text,text,text) to authenticated;

create or replace function private.trustrelay_my_organizations_v07(p_uid uuid)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_my_organizations_core_v10(p_uid);
end; $$;
revoke all on function private.trustrelay_my_organizations_v07(uuid) from public,anon;
grant execute on function private.trustrelay_my_organizations_v07(uuid) to authenticated;

create or replace function private.trustrelay_review_document_v08(p_uid uuid,p_document_id text,p_decision text,p_reason_code text,p_notes text)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_review_document_core_v10(p_uid,p_document_id,p_decision,p_reason_code,p_notes);
end; $$;
revoke all on function private.trustrelay_review_document_v08(uuid,text,text,text,text) from public,anon;
grant execute on function private.trustrelay_review_document_v08(uuid,text,text,text,text) to authenticated;

create or replace function private.trustrelay_review_proofing_v08(p_uid uuid,p_session_id text,p_decision text,p_reason_code text,p_notes text)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_review_proofing_core_v10(p_uid,p_session_id,p_decision,p_reason_code,p_notes);
end; $$;
revoke all on function private.trustrelay_review_proofing_v08(uuid,text,text,text,text) from public,anon;
grant execute on function private.trustrelay_review_proofing_v08(uuid,text,text,text,text) to authenticated;

create or replace function private.trustrelay_review_queue_v08(p_uid uuid)
returns jsonb language plpgsql security definer set search_path=private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  return private.trustrelay_review_queue_core_v10(p_uid);
end; $$;
revoke all on function private.trustrelay_review_queue_v08(uuid) from public,anon;
grant execute on function private.trustrelay_review_queue_v08(uuid) to authenticated;

-- Existing feature-gated proofing/reviewer wrappers also bind the actor explicitly.
create or replace function private.trustrelay_start_proofing_v08(p_uid uuid,p_requested_assurance text,p_consent_version text)
returns jsonb language plpgsql security definer set search_path=public,private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object('ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED',
      'detail','Manual identity proofing is not enabled for the current production operating model.');
  end if;
  return private.trustrelay_start_proofing_core_v08(p_uid,p_requested_assurance,p_consent_version);
end; $$;

create or replace function private.trustrelay_submit_proofing_v08(p_uid uuid,p_session_id text)
returns jsonb language plpgsql security definer set search_path=public,private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object('ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED');
  end if;
  return private.trustrelay_submit_proofing_core_v08(p_uid,p_session_id);
end; $$;

create or replace function private.trustrelay_reviewer_context_v08(p_uid uuid)
returns jsonb language plpgsql security definer set search_path=public,private,auth,pg_catalog as $$
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if not public.trustrelay_feature_enabled_v10('manual_identity_review') then
    return jsonb_build_object('ok',false,'status',503,'code','MANUAL_IDENTITY_REVIEW_DISABLED');
  end if;
  return private.trustrelay_reviewer_context_core_v08(p_uid);
end; $$;

revoke all on function private.trustrelay_reviewer_context_core_v08(uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_session_guard_v10(uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_finalize_document_v08(uuid,text,text,integer,text) from public,anon,authenticated;
revoke all on function private.trustrelay_org_context_v07(uuid,text) from public,anon,authenticated;

-- Repair missing authenticated public bridges; identity is always sourced from auth.uid().
create or replace function public.trustrelay_manage_org_member_v09(
  p_org_id text,p_member_account_id text,p_action text,p_role text default null,p_title text default null
) returns jsonb language sql security invoker set search_path=private,auth,pg_catalog as $$
  select private.trustrelay_manage_org_member_v09(auth.uid(),p_org_id,p_member_account_id,p_action,p_role,p_title);
$$;
create or replace function public.trustrelay_remove_member_v09(
  p_org_id text,p_account_id text,p_reason text default null
) returns jsonb language sql security invoker set search_path=private,auth,pg_catalog as $$
  select private.trustrelay_remove_member_v09(auth.uid(),p_org_id,p_account_id,p_reason);
$$;
create or replace function public.trustrelay_restore_member_v09(
  p_org_id text,p_account_id text
) returns jsonb language sql security invoker set search_path=private,auth,pg_catalog as $$
  select private.trustrelay_restore_member_v09(auth.uid(),p_org_id,p_account_id);
$$;
create or replace function public.trustrelay_transfer_org_owner_v09(
  p_org_id text,p_new_owner_account_id text
) returns jsonb language sql security invoker set search_path=private,auth,pg_catalog as $$
  select private.trustrelay_transfer_org_owner_v09(auth.uid(),p_org_id,p_new_owner_account_id);
$$;
revoke all on function public.trustrelay_manage_org_member_v09(text,text,text,text,text) from public,anon;
grant execute on function public.trustrelay_manage_org_member_v09(text,text,text,text,text) to authenticated;
revoke all on function public.trustrelay_remove_member_v09(text,text,text) from public,anon;
grant execute on function public.trustrelay_remove_member_v09(text,text,text) to authenticated;
revoke all on function public.trustrelay_restore_member_v09(text,text) from public,anon;
grant execute on function public.trustrelay_restore_member_v09(text,text) to authenticated;
revoke all on function public.trustrelay_transfer_org_owner_v09(text,text) from public,anon;
grant execute on function public.trustrelay_transfer_org_owner_v09(text,text) to authenticated;

-- Remove legacy PUBLIC grants from private actor functions while preserving authenticated wrappers.
revoke execute on function private.trustrelay_manage_org_member_v09(uuid,text,text,text,text,text) from public,anon;
grant execute on function private.trustrelay_manage_org_member_v09(uuid,text,text,text,text,text) to authenticated;
revoke execute on function private.trustrelay_remove_member_v09(uuid,text,text,text) from public,anon;
grant execute on function private.trustrelay_remove_member_v09(uuid,text,text,text) to authenticated;
revoke execute on function private.trustrelay_restore_member_v09(uuid,text,text) from public,anon;
grant execute on function private.trustrelay_restore_member_v09(uuid,text,text) to authenticated;
revoke execute on function private.trustrelay_transfer_org_owner_v09(uuid,text,text) from public,anon;
grant execute on function private.trustrelay_transfer_org_owner_v09(uuid,text,text) to authenticated;
revoke execute on function private.trustrelay_request_compliance_export_v09(uuid,text,jsonb,text,text,text) from public,anon;
grant execute on function private.trustrelay_request_compliance_export_v09(uuid,text,jsonb,text,text,text) to authenticated;
revoke all on function private.trustrelay_grant_notification_trigger_v09() from public,anon,authenticated;

-- Future functions must be granted deliberately instead of becoming client-callable by default.
alter default privileges for role postgres in schema public revoke execute on functions from public;
alter default privileges for role postgres in schema public revoke execute on functions from anon;
alter default privileges for role postgres in schema public revoke execute on functions from authenticated;
alter default privileges for role postgres in schema private revoke execute on functions from public;
alter default privileges for role postgres in schema private revoke execute on functions from anon;

notify pgrst,'reload schema';
