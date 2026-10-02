-- TrustRelay v1.0 v0.9 organization membership schema reconciliation.
-- Recorded v0.9 functions reference lifecycle columns/roles that were missing from bootstrap DDL.

alter table public.organization_members
  add column if not exists role_changed_at text,
  add column if not exists role_changed_by_account_id text,
  add column if not exists disabled_at text,
  add column if not exists disabled_by_account_id text,
  add column if not exists removed_at text,
  add column if not exists removed_by_account_id text;

alter table public.organization_members
  drop constraint if exists organization_members_role_v07;
alter table public.organization_members
  add constraint organization_members_role_v09
  check (role in ('owner','admin','compliance','verifier','developer','auditor'));

alter table public.organization_members
  drop constraint if exists organization_members_status_v07;
alter table public.organization_members
  add constraint organization_members_status_v09
  check (status in ('active','disabled','removed'));

alter table public.organization_invitations
  drop constraint if exists organization_invitations_role_v07;
alter table public.organization_invitations
  add constraint organization_invitations_role_v09
  check (role in ('admin','compliance','verifier','developer','auditor'));

do $$
begin
  if not exists(select 1 from pg_constraint where conname='organization_members_role_changed_by_fkey') then
    alter table public.organization_members
      add constraint organization_members_role_changed_by_fkey
      foreign key(role_changed_by_account_id) references public.accounts(id) on delete set null;
  end if;
  if not exists(select 1 from pg_constraint where conname='organization_members_disabled_by_fkey') then
    alter table public.organization_members
      add constraint organization_members_disabled_by_fkey
      foreign key(disabled_by_account_id) references public.accounts(id) on delete set null;
  end if;
  if not exists(select 1 from pg_constraint where conname='organization_members_removed_by_fkey') then
    alter table public.organization_members
      add constraint organization_members_removed_by_fkey
      foreign key(removed_by_account_id) references public.accounts(id) on delete set null;
  end if;
end $$;

create or replace function private.trustrelay_invite_org_member_v07(
  p_uid uuid,p_org_id text,p_email text,p_role text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
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
  v_ctx := private.trustrelay_require_permission_v09(p_uid,p_org_id,'members.manage');
  if coalesce((v_ctx->>'ok')::boolean,false) is false then return v_ctx; end if;

  if v_email !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','INVITATION_EMAIL_INVALID');
  end if;

  if p_role not in ('admin','compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_ROLE_INVALID');
  end if;
  if (v_ctx->>'role')='admin' and p_role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  v_account_id := v_ctx->>'accountId';

  if exists (
    select 1 from public.organization_members m
    join public.accounts a on a.id=m.account_id
    where m.organization_id=p_org_id and lower(a.email)=v_email and m.status='active'
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_EXISTS');
  end if;

  update public.organization_invitations
  set status='revoked',revoked_at=v_now
  where organization_id=p_org_id and lower(invite_email)=v_email and status='pending';

  insert into public.organization_invitations(
    id,organization_id,invite_email,role,token_hash,invited_by_account_id,status,expires_at,created_at
  ) values (
    v_invite_id,p_org_id,v_email,p_role,v_hash,v_account_id,'pending',v_expires,v_now
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

notify pgrst,'reload schema';
