-- TrustRelay migration history exported verbatim from Supabase on 2026-10-01.
-- Apply in listed order to an empty compatible Supabase project.

-- ============================================================
-- Clean-bootstrap prelude: v0.9 objects that existed in live staging
-- before the recorded migration history was exported.
-- ============================================================
create schema if not exists private;

create table if not exists public.account_notifications (
  id text primary key,
  account_id text not null references public.accounts(id) on delete cascade,
  organization_id text references public.organizations(id) on delete cascade,
  event_type text not null,
  severity text not null default 'info',
  title text not null,
  body text not null,
  resource_type text,
  resource_id text,
  metadata_json text not null default '{}',
  status text not null default 'unread',
  read_at text,
  dismissed_at text,
  created_at text not null
);

create table if not exists public.notification_preferences (
  account_id text not null references public.accounts(id) on delete cascade,
  category text not null,
  in_app boolean not null default true,
  created_at text,
  updated_at text,
  primary key (account_id,category),
  constraint notification_preferences_category_v09
    check (category = any(array['authority','evidence','identity','organization','webhook','compliance','security']::text[]))
);

create table if not exists public.notifications (
  id text primary key,
  account_id text not null references public.accounts(id) on delete cascade,
  organization_id text references public.organizations(id) on delete cascade,
  category text not null,
  event_type text not null,
  severity text not null default 'info',
  title text not null,
  body text not null,
  data_json text not null default '{}',
  dedupe_key text,
  status text not null default 'unread',
  read_at text,
  archived_at text,
  created_at text not null,
  updated_at text,
  constraint notifications_category_v09
    check (category = any(array['authority','evidence','identity','organization','webhook','compliance','security']::text[])),
  constraint notifications_severity_v09
    check (severity = any(array['info','success','warning','critical']::text[])),
  constraint notifications_status_v09
    check (status = any(array['unread','read','archived']::text[]))
);
create unique index if not exists ux_notifications_account_dedupe_v09
  on public.notifications(account_id,dedupe_key) where dedupe_key is not null;

create table if not exists public.organization_audit_events (
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  actor_account_id text references public.accounts(id) on delete set null,
  event_type text not null,
  target_type text,
  target_id text,
  metadata_json text not null default '{}',
  prev_hash text,
  event_hash text not null,
  created_at text not null
);
create index if not exists idx_org_audit_org_created_v09
  on public.organization_audit_events(organization_id,created_at,id);
create unique index if not exists ux_org_audit_org_hash_v09
  on public.organization_audit_events(organization_id,event_hash);

create table if not exists public.webhook_delivery_attempts (
  id text primary key,
  delivery_id text not null references public.webhook_deliveries(id) on delete cascade,
  attempt_number integer not null,
  net_request_id bigint,
  request_timestamp text,
  response_status integer,
  response_body_excerpt text,
  error_text text,
  success boolean,
  duration_ms integer,
  created_at text not null,
  completed_at text,
  constraint webhook_delivery_attempts_number_v09 check (attempt_number > 0),
  unique (delivery_id,attempt_number)
);
create index if not exists idx_webhook_attempts_delivery_created_v09
  on public.webhook_delivery_attempts(delivery_id,created_at);

create table if not exists public.compliance_exports (
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  requested_by_account_id text references public.accounts(id) on delete set null,
  format text not null,
  scopes_json text not null default '[]',
  from_at text not null,
  to_at text not null,
  status text not null default 'preparing',
  storage_bucket text not null,
  storage_key text not null,
  content_sha256 text,
  row_count integer,
  size_bytes bigint,
  manifest_json text,
  previous_export_hash text,
  export_hash text,
  audit_chain_valid boolean,
  audit_chain_head text,
  generated_at text,
  completed_at text,
  expires_at text not null,
  error_code text,
  error_message text,
  created_at text not null,
  constraint compliance_exports_format_v09 check (format = any(array['json','csv']::text[])),
  constraint compliance_exports_status_v09 check (status = any(array['preparing','ready','failed','expired']::text[])),
  unique (organization_id,storage_key)
);
create index if not exists idx_compliance_exports_org_created_v09
  on public.compliance_exports(organization_id,created_at desc);

alter table public.account_notifications enable row level security;
alter table public.notification_preferences enable row level security;
alter table public.notifications enable row level security;
alter table public.organization_audit_events enable row level security;
alter table public.webhook_delivery_attempts enable row level security;
alter table public.compliance_exports enable row level security;

revoke all on table public.account_notifications from public,anon,authenticated;
revoke all on table public.notification_preferences from public,anon,authenticated;
revoke all on table public.notifications from public,anon,authenticated;
revoke all on table public.organization_audit_events from public,anon,authenticated;
revoke all on table public.webhook_delivery_attempts from public,anon,authenticated;
revoke all on table public.compliance_exports from public,anon,authenticated;

grant select,insert,update,delete on table public.account_notifications to service_role;
grant select,insert,update,delete on table public.notification_preferences to service_role;
grant select,insert,update,delete on table public.notifications to service_role;
grant select,insert on table public.organization_audit_events to service_role;
grant select,insert,update on table public.webhook_delivery_attempts to service_role;

grant select,insert,update on table public.compliance_exports to service_role;

drop policy if exists trustrelay_deny_clients on public.notification_preferences;
create policy trustrelay_deny_clients on public.notification_preferences
  as restrictive for all to anon,authenticated using(false) with check(false);
drop policy if exists trustrelay_deny_clients on public.notifications;
create policy trustrelay_deny_clients on public.notifications
  as restrictive for all to anon,authenticated using(false) with check(false);
drop policy if exists trustrelay_deny_clients on public.organization_audit_events;
create policy trustrelay_deny_clients on public.organization_audit_events
  as restrictive for all to anon,authenticated using(false) with check(false);
drop policy if exists trustrelay_deny_clients on public.webhook_delivery_attempts;
create policy trustrelay_deny_clients on public.webhook_delivery_attempts
  as restrictive for all to anon,authenticated using(false) with check(false);
drop policy if exists trustrelay_deny_clients on public.compliance_exports;
create policy trustrelay_deny_clients on public.compliance_exports
  as restrictive for all to anon,authenticated using(false) with check(false);

create index if not exists idx_compliance_exports_requested_by_v10
  on public.compliance_exports(requested_by_account_id);
create index if not exists idx_notifications_organization_v10
  on public.notifications(organization_id);
create index if not exists idx_org_audit_actor_v10
  on public.organization_audit_events(actor_account_id);


create or replace function private.trustrelay_org_audit_hash_v09(
  p_id text,p_org_id text,p_actor_account_id text,p_event_type text,
  p_target_type text,p_target_id text,p_metadata jsonb,p_prev_hash text,p_created_at text
)
returns text
language sql
immutable
set search_path=extensions,pg_catalog
as $tr$
  select encode(digest(
    jsonb_build_object(
      'id',p_id,
      'organizationId',p_org_id,
      'actorAccountId',p_actor_account_id,
      'eventType',p_event_type,
      'targetType',p_target_type,
      'targetId',p_target_id,
      'metadata',coalesce(p_metadata,'{}'::jsonb),
      'prevHash',p_prev_hash,
      'createdAt',p_created_at
    )::text,
    'sha256'
  ),'hex');
$tr$;

create or replace function private.trustrelay_append_org_audit_v09(
  p_org_id text,p_actor_account_id text,p_event_type text,
  p_target_type text,p_target_id text,p_metadata jsonb
)
returns text
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $tr$
declare
  v_id text:='orgaudit_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_prev text;
  v_hash text;
begin
  if p_org_id is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_org_id,0));

  select event_hash into v_prev
  from public.organization_audit_events
  where organization_id=p_org_id
  order by created_at desc,id desc
  limit 1;

  v_hash:=private.trustrelay_org_audit_hash_v09(
    v_id,p_org_id,p_actor_account_id,p_event_type,p_target_type,p_target_id,
    coalesce(p_metadata,'{}'::jsonb),v_prev,v_now
  );

  insert into public.organization_audit_events(
    id,organization_id,actor_account_id,event_type,target_type,target_id,
    metadata_json,prev_hash,event_hash,created_at
  ) values(
    v_id,p_org_id,p_actor_account_id,p_event_type,p_target_type,p_target_id,
    coalesce(p_metadata,'{}'::jsonb)::text,v_prev,v_hash,v_now
  );
  return v_id;
end;
$tr$;

create or replace function public.trustrelay_verify_org_audit_chain_v09(p_org_id text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $tr$
declare
  v_row public.organization_audit_events%rowtype;
  v_prev text:=null;
  v_expected text;
  v_count integer:=0;
begin
  for v_row in
    select * from public.organization_audit_events
    where organization_id=p_org_id
    order by created_at,id
  loop
    v_expected:=private.trustrelay_org_audit_hash_v09(
      v_row.id,v_row.organization_id,v_row.actor_account_id,v_row.event_type,
      v_row.target_type,v_row.target_id,coalesce(v_row.metadata_json,'{}')::jsonb,
      v_prev,v_row.created_at
    );
    if v_row.prev_hash is distinct from v_prev or v_row.event_hash is distinct from v_expected then
      return jsonb_build_object(
        'ok',false,'valid',false,'organizationId',p_org_id,
        'failedEventId',v_row.id,'eventsChecked',v_count
      );
    end if;
    v_prev:=v_row.event_hash;
    v_count:=v_count+1;
  end loop;
  return jsonb_build_object(
    'ok',true,'valid',true,'organizationId',p_org_id,
    'eventsChecked',v_count,'headHash',v_prev
  );
end;
$tr$;

create or replace function private.trustrelay_notify_org_v09(
  p_org_id text,p_roles text[],p_category text,p_event_type text,p_severity text,
  p_title text,p_body text,p_resource_type text,p_resource_id text,p_metadata jsonb
)
returns integer
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $tr$
declare
  v_account_id text;
  v_count integer:=0;
begin
  if p_org_id is null then return 0; end if;
  for v_account_id in
    select account_id
    from public.organization_members
    where organization_id=p_org_id
      and status='active'
      and (p_roles is null or role=any(p_roles))
  loop
    perform private.trustrelay_notify_account_v09(
      v_account_id,p_org_id,p_category,p_event_type,p_severity,p_title,p_body,
      p_resource_type,p_resource_id,coalesce(p_metadata,'{}'::jsonb)
    );
    v_count:=v_count+1;
  end loop;
  return v_count;
end;
$tr$;

create or replace function public.trustrelay_emit_org_event_v09(
  p_org_id text,p_event_type text,p_data jsonb
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $tr$
declare
  v_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload text;
  v_result jsonb;
begin
  v_payload:=jsonb_build_object(
    'id',v_id,'type',p_event_type,'createdAt',v_now,
    'organizationId',p_org_id,'data',coalesce(p_data,'{}'::jsonb)
  )::text;
  v_result:=public.trustrelay_queue_webhooks_v07(p_org_id,p_event_type,v_id,v_payload);
  perform public.trustrelay_dispatch_due_webhooks_v09(25);
  return coalesce(v_result,'{}'::jsonb)||jsonb_build_object('eventId',v_id);
end;
$tr$;

revoke all on function private.trustrelay_org_audit_hash_v09(text,text,text,text,text,text,jsonb,text,text) from public,anon,authenticated;
revoke all on function private.trustrelay_append_org_audit_v09(text,text,text,text,text,jsonb) from public,anon,authenticated;
revoke all on function private.trustrelay_notify_org_v09(text,text[],text,text,text,text,text,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.trustrelay_emit_org_event_v09(text,text,jsonb) from public,anon,authenticated;
revoke all on function public.trustrelay_verify_org_audit_chain_v09(text) from public,anon,authenticated;

grant execute on function private.trustrelay_append_org_audit_v09(text,text,text,text,text,jsonb) to service_role;
grant execute on function private.trustrelay_notify_org_v09(text,text[],text,text,text,text,text,text,text,jsonb) to service_role;
grant execute on function public.trustrelay_emit_org_event_v09(text,text,jsonb) to service_role;
grant execute on function public.trustrelay_verify_org_audit_chain_v09(text) to service_role;

-- Durable webhook schema reconcile for clean installs.
alter table public.webhook_deliveries
  add column if not exists max_attempts integer not null default 5,
  add column if not exists next_attempt_at text,
  add column if not exists dead_lettered_at text,
  add column if not exists net_request_id bigint,
  add column if not exists last_attempt_at text,
  add column if not exists last_attempt_duration_ms integer,
  add column if not exists manually_redelivered_count integer not null default 0;

alter table public.webhook_subscriptions
  add column if not exists api_version text not null default 'v0.9',
  add column if not exists failure_threshold integer not null default 10,
  add column if not exists pause_reason text,
  add column if not exists paused_at text,
  add column if not exists last_success_at text,
  add column if not exists last_failure_at text,
  add column if not exists secret_rotated_at text;

alter table public.webhook_deliveries
  drop constraint if exists webhook_deliveries_status_v07;
alter table public.webhook_deliveries
  drop constraint if exists webhook_deliveries_status_v09;
alter table public.webhook_deliveries
  add constraint webhook_deliveries_status_v09
  check (status = any(array['pending','dispatched','retrying','delivered','dead_letter','failed']::text[]));

alter table public.webhook_subscriptions
  drop constraint if exists webhook_subscriptions_status_v07;
alter table public.webhook_subscriptions
  drop constraint if exists webhook_subscriptions_status_v09;
alter table public.webhook_subscriptions
  add constraint webhook_subscriptions_status_v09
  check (status = any(array['active','paused','disabled','revoked']::text[]));

alter table public.webhook_deliveries
  drop constraint if exists webhook_deliveries_subscription_event_v09;
alter table public.webhook_deliveries
  add constraint webhook_deliveries_subscription_event_v09 unique(subscription_id,event_id);

alter table public.webhook_deliveries
  drop constraint if exists webhook_deliveries_max_attempts_v09;
alter table public.webhook_deliveries
  add constraint webhook_deliveries_max_attempts_v09 check (max_attempts between 1 and 20);

alter table public.webhook_subscriptions
  drop constraint if exists webhook_subscriptions_failure_threshold_v09;
alter table public.webhook_subscriptions
  add constraint webhook_subscriptions_failure_threshold_v09 check (failure_threshold between 1 and 100);

create index if not exists idx_webhook_deliveries_due_v09
  on public.webhook_deliveries(status,next_attempt_at,created_at);

-- ============================================================
-- 20261001204426 trustrelay_v09_event_notifications_finalize
-- ============================================================
create or replace function private.trustrelay_org_member_event_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_event text;
  v_payload jsonb;
begin
  if tg_op='INSERT' then
    if new.status='active' then
      v_event:='organization.member.joined';
      v_payload:=jsonb_build_object(
        'accountId',new.account_id,'role',new.role,'status',new.status,'createdAt',new.created_at
      );
    end if;
  elsif tg_op='UPDATE' then
    if old.status is distinct from new.status and new.status='disabled' then
      v_event:='organization.member.disabled';
      v_payload:=jsonb_build_object(
        'accountId',new.account_id,'role',new.role,'status',new.status,'disabledAt',new.disabled_at
      );
    elsif old.status is distinct from new.status and new.status='active' then
      v_event:='organization.member.joined';
      v_payload:=jsonb_build_object(
        'accountId',new.account_id,'role',new.role,'status',new.status,'reactivated',true
      );
    elsif old.role is distinct from new.role then
      v_event:='organization.member.role_changed';
      v_payload:=jsonb_build_object(
        'accountId',new.account_id,'fromRole',old.role,'toRole',new.role,'roleChangedAt',new.role_changed_at
      );
    end if;
  end if;

  if v_event is not null then
    perform public.trustrelay_emit_org_event_v09(new.organization_id,v_event,v_payload);
  end if;
  return new;
end;
$$;

drop trigger if exists trustrelay_org_member_event_v09 on public.organization_members;
create trigger trustrelay_org_member_event_v09
after insert or update of role,status on public.organization_members
for each row execute function private.trustrelay_org_member_event_trigger_v09();

revoke all on function private.trustrelay_org_member_event_trigger_v09() from public,anon,authenticated;
grant execute on function private.trustrelay_org_member_event_trigger_v09() to service_role;

create or replace function private.trustrelay_compliance_export_event_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if new.status='ready' and old.status is distinct from new.status then
    perform public.trustrelay_emit_org_event_v09(
      new.organization_id,'compliance.export.ready',
      jsonb_build_object(
        'exportId',new.id,'format',new.format,'scopes',coalesce(new.scopes_json::jsonb,'[]'::jsonb),
        'sha256',new.content_sha256,'rowCount',new.row_count,'sizeBytes',new.size_bytes,
        'completedAt',new.completed_at,'expiresAt',new.expires_at
      )
    );
  end if;
  return new;
end;
$$;

drop trigger if exists trustrelay_compliance_export_event_v09 on public.compliance_exports;
create trigger trustrelay_compliance_export_event_v09
after update of status on public.compliance_exports
for each row execute function private.trustrelay_compliance_export_event_trigger_v09();

revoke all on function private.trustrelay_compliance_export_event_trigger_v09() from public,anon,authenticated;
grant execute on function private.trustrelay_compliance_export_event_trigger_v09() to service_role;

create or replace function private.trustrelay_authority_invitation_notification_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_account_id text;
  v_principal_account text;
begin
  if tg_op='INSERT' and new.status='pending' then
    select id into v_account_id
    from public.accounts
    where lower(email)=lower(new.invite_email) and status='active'
    limit 1;

    if v_account_id is not null then
      perform private.trustrelay_notify_account_v09(
        v_account_id,null,'authority','grant.invitation.created','info',
        'Authority invitation received',
        'Someone invited you to act under a scoped TrustRelay authority grant.',
        'authority_grant_invitation',new.id,
        jsonb_build_object('grantId',new.grant_id,'expiresAt',new.expires_at)
      );
    end if;
  elsif tg_op='UPDATE'
    and old.status is distinct from new.status
    and new.status='accepted' then

    select a.id into v_principal_account
    from public.authority_grants g
    join public.accounts a on a.person_id=g.principal_person_id and a.status='active'
    where g.id=new.grant_id
    order by a.created_at
    limit 1;

    if v_principal_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_principal_account,null,'authority','grant.invitation.accepted','success',
        'Authority invitation accepted',
        'Your TrustRelay authority invitation was accepted by the representative.',
        'authority_grant',new.grant_id,
        jsonb_build_object('invitationId',new.id,'acceptedAt',new.accepted_at)
      );
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trustrelay_authority_invitation_notification_v09 on public.authority_grant_invitations;
create trigger trustrelay_authority_invitation_notification_v09
after insert or update of status on public.authority_grant_invitations
for each row execute function private.trustrelay_authority_invitation_notification_v09();

revoke all on function private.trustrelay_authority_invitation_notification_v09() from public,anon,authenticated;
grant execute on function private.trustrelay_authority_invitation_notification_v09() to service_role;

create or replace function private.trustrelay_proofing_notification_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if old.status is distinct from new.status and new.status in ('approved','rejected') then
    perform private.trustrelay_notify_account_v09(
      new.account_id,null,'identity','identity.proofing.'||new.status,
      case when new.status='approved' then 'success' else 'warning' end,
      case when new.status='approved' then 'Identity verification approved' else 'Identity verification needs attention' end,
      case when new.status='approved'
        then 'Your TrustRelay identity proofing review was approved.'
        else 'Your TrustRelay identity proofing review was rejected. Review the reason and submit updated evidence if needed.' end,
      'identity_proofing_session',new.id,
      jsonb_build_object(
        'requestedAssurance',new.requested_assurance,
        'assuranceLevel',new.assurance_level,
        'reason',new.review_reason,
        'reviewedAt',new.reviewed_at
      )
    );
  end if;
  return new;
end;
$$;

drop trigger if exists trustrelay_proofing_notification_v09 on public.identity_proofing_sessions;
create trigger trustrelay_proofing_notification_v09
after update of status on public.identity_proofing_sessions
for each row execute function private.trustrelay_proofing_notification_trigger_v09();

revoke all on function private.trustrelay_proofing_notification_trigger_v09() from public,anon,authenticated;
grant execute on function private.trustrelay_proofing_notification_trigger_v09() to service_role;

create or replace function private.trustrelay_create_webhook_v07(
  p_uid uuid,p_org_id text,p_name text,p_endpoint_url text,p_events jsonb
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text:='wh_'||replace(gen_random_uuid()::text,'-','');
  v_secret text:='whsec_'||encode(gen_random_bytes(32),'hex');
  v_secret_id uuid;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text;
  v_allowed text[]:=array[
    'decision.created','grant.revoked','credential.revoked',
    'evidence.requested','evidence.submitted','evidence.resolved',
    'organization.member.joined','organization.member.role_changed','organization.member.disabled',
    'compliance.export.ready','webhook.test'
  ];
  v_url text:=btrim(coalesce(p_endpoint_url,''));
  v_host text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>100 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_NAME_INVALID');
  end if;

  if length(v_url)>2048 or v_url !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_INVALID');
  end if;
  if v_url ~ '^https://[^/]*@' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_USERINFO_FORBIDDEN');
  end if;

  v_host:=lower(substring(v_url from '^https://([^/:?#]+)'));
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
    if not (v_event=any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',v_event);
    end if;
  end loop;

  v_secret_id:=vault.create_secret(v_secret,'trustrelay-webhook-'||v_id,'TrustRelay v0.9 webhook signing secret');

  insert into public.webhook_subscriptions(
    id,organization_id,name,endpoint_url,events_json,secret_vault_id,secret_prefix,
    status,created_by_account_id,created_at,updated_at,api_version,failure_threshold
  ) values (
    v_id,p_org_id,btrim(p_name),v_url,p_events::text,v_secret_id,left(v_secret,12),
    'active',v_ctx->>'accountId',v_now,v_now,'v0.9',10
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.created','webhook_subscription',v_id,
    jsonb_build_object('name',btrim(p_name),'endpointUrl',v_url,'events',p_events)
  );

  return jsonb_build_object(
    'ok',true,'signingSecret',v_secret,
    'webhook',jsonb_build_object(
      'id',v_id,'name',btrim(p_name),'endpointUrl',v_url,
      'events',p_events,'status','active','secretPrefix',left(v_secret,12),
      'apiVersion','v0.9','createdAt',v_now
    )
  );
end;
$$;

create or replace function public.trustrelay_queue_webhooks_v07(
  p_org_id text,p_event_type text,p_event_id text,p_payload_json text
)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,pg_catalog
as $$
declare
  v_sub public.webhook_subscriptions%rowtype;
  v_delivery_id text;
  v_secret text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload_hash text;
  v_targets jsonb:='[]'::jsonb;
  v_allowed text[]:=array[
    'decision.created','grant.revoked','credential.revoked',
    'evidence.requested','evidence.submitted','evidence.resolved',
    'organization.member.joined','organization.member.role_changed','organization.member.disabled',
    'compliance.export.ready','webhook.test'
  ];
begin
  if not (p_event_type=any(v_allowed)) then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID');
  end if;
  if p_payload_json is null or length(p_payload_json)>262144 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end if;
  begin perform p_payload_json::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end;

  v_payload_hash:=encode(digest(p_payload_json,'sha256'),'hex');

  for v_sub in
    select * from public.webhook_subscriptions
    where organization_id=p_org_id
      and status='active'
      and coalesce(events_json::jsonb,'[]'::jsonb) ? p_event_type
  loop
    select decrypted_secret into v_secret
    from vault.decrypted_secrets where id=v_sub.secret_vault_id;
    if v_secret is null then continue; end if;

    v_delivery_id:='whd_'||replace(gen_random_uuid()::text,'-','');

    insert into public.webhook_deliveries(
      id,subscription_id,organization_id,event_type,event_id,payload_json,payload_hash,
      status,attempt_count,max_attempts,created_at,next_attempt_at
    ) values (
      v_delivery_id,v_sub.id,p_org_id,p_event_type,p_event_id,p_payload_json,v_payload_hash,
      'pending',0,5,v_now,v_now
    )
    on conflict(subscription_id,event_id) do nothing;

    if found then
      v_targets:=v_targets||jsonb_build_array(jsonb_build_object(
        'deliveryId',v_delivery_id,'subscriptionId',v_sub.id,
        'endpointUrl',v_sub.endpoint_url,'signingSecret',v_secret
      ));
    end if;
  end loop;

  return jsonb_build_object('ok',true,'targets',v_targets,'payloadHash',v_payload_hash);
end;
$$;

-- ============================================================
-- 20261001204557 trustrelay_v09_notification_recursion_fix
-- ============================================================
create or replace function private.trustrelay_notify_account_v09(
  p_account_id text,
  p_org_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_resource_type text,
  p_resource_id text,
  p_metadata jsonb
)
returns text
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v_id text:='note_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_enabled boolean:=true;
begin
  if not exists(select 1 from public.accounts where id=p_account_id and status='active') then
    return null;
  end if;

  select in_app into v_enabled
  from public.notification_preferences
  where account_id=p_account_id and category=p_category;

  if v_enabled is false then return null; end if;

  insert into public.account_notifications(
    id,account_id,organization_id,event_type,severity,title,body,
    resource_type,resource_id,metadata_json,created_at
  ) values (
    v_id,p_account_id,p_org_id,p_event_type,
    case when p_severity in ('info','success','warning','critical') then p_severity else 'info' end,
    left(btrim(coalesce(p_title,'Notification')),180),
    left(btrim(coalesce(p_body,'')),2000),
    nullif(btrim(coalesce(p_resource_type,'')),''),
    nullif(btrim(coalesce(p_resource_id,'')),''),
    coalesce(p_metadata,'{}'::jsonb)::text,
    v_now
  );

  return v_id;
end;
$$;

create or replace function private.trustrelay_create_notification_v09(
  p_account_id text,
  p_organization_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_data jsonb,
  p_dedupe_key text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_id text;
  v_resource_type text;
  v_resource_id text;
  v_metadata jsonb;
begin
  v_resource_type:=nullif(btrim(coalesce(p_data->>'resourceType','')),'');
  v_resource_id:=nullif(btrim(coalesce(p_data->>'resourceId','')),'');
  v_metadata:=coalesce(p_data->'metadata','{}'::jsonb);

  if p_dedupe_key is not null then
    if exists(
      select 1
      from public.account_notifications n
      where n.account_id=p_account_id
        and n.event_type=p_event_type
        and coalesce(n.organization_id,'')=coalesce(p_organization_id,'')
        and coalesce(n.metadata_json,'{}')::jsonb->>'dedupeKey'=p_dedupe_key
        and n.dismissed_at is null
    ) then
      return jsonb_build_object('ok',true,'id',null,'suppressed',true);
    end if;
    v_metadata:=v_metadata||jsonb_build_object('dedupeKey',p_dedupe_key);
  end if;

  v_id:=private.trustrelay_notify_account_v09(
    p_account_id,p_organization_id,p_category,p_event_type,p_severity,
    p_title,p_body,v_resource_type,v_resource_id,v_metadata
  );

  return jsonb_build_object('ok',true,'id',v_id,'suppressed',v_id is null);
end;
$$;

revoke all on function private.trustrelay_notify_account_v09(text,text,text,text,text,text,text,text,text,jsonb) from public,anon,authenticated;
revoke all on function private.trustrelay_create_notification_v09(text,text,text,text,text,text,text,jsonb,text) from public,anon,authenticated;
grant execute on function private.trustrelay_notify_account_v09(text,text,text,text,text,text,text,text,text,jsonb) to service_role;
grant execute on function private.trustrelay_create_notification_v09(text,text,text,text,text,text,text,jsonb,text) to service_role;

-- ============================================================
-- 20261001204749 trustrelay_v09_notification_pipeline_canonical
-- ============================================================
create or replace function private.trustrelay_create_notification_v09(
  p_account_id text,
  p_organization_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_data jsonb,
  p_dedupe_key text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v_id text:='note_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_enabled boolean:=true;
  v_existing text;
begin
  if not exists(select 1 from public.accounts where id=p_account_id and status='active') then
    return jsonb_build_object('ok',true,'id',null,'suppressed',true,'reason','ACCOUNT_INACTIVE');
  end if;

  if p_category not in ('authority','evidence','identity','organization','webhook','compliance','security') then
    return jsonb_build_object('ok',false,'status',400,'code','NOTIFICATION_CATEGORY_INVALID');
  end if;

  select in_app into v_enabled
  from public.notification_preferences
  where account_id=p_account_id and category=p_category;

  if v_enabled is false then
    return jsonb_build_object('ok',true,'id',null,'suppressed',true,'reason','PREFERENCE_DISABLED');
  end if;

  if p_dedupe_key is not null then
    select id into v_existing
    from public.notifications
    where account_id=p_account_id and dedupe_key=p_dedupe_key
    limit 1;

    if v_existing is not null then
      return jsonb_build_object('ok',true,'id',v_existing,'suppressed',true,'reason','DUPLICATE');
    end if;
  end if;

  insert into public.notifications(
    id,account_id,organization_id,category,event_type,severity,title,body,
    data_json,dedupe_key,status,created_at
  ) values (
    v_id,p_account_id,p_organization_id,p_category,p_event_type,
    case when p_severity in ('info','success','warning','critical') then p_severity else 'info' end,
    left(btrim(coalesce(p_title,'Notification')),180),
    left(btrim(coalesce(p_body,'')),2000),
    coalesce(p_data,'{}'::jsonb)::text,
    nullif(btrim(coalesce(p_dedupe_key,'')),''),
    'unread',v_now
  )
  on conflict(account_id,dedupe_key) where dedupe_key is not null do nothing;

  if not found and p_dedupe_key is not null then
    select id into v_existing
    from public.notifications
    where account_id=p_account_id and dedupe_key=p_dedupe_key
    limit 1;
    return jsonb_build_object('ok',true,'id',v_existing,'suppressed',true,'reason','DUPLICATE');
  end if;

  return jsonb_build_object('ok',true,'id',v_id,'suppressed',false);
end;
$$;

create or replace function private.trustrelay_notify_account_v09(
  p_account_id text,
  p_org_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_resource_type text,
  p_resource_id text,
  p_metadata jsonb
)
returns text
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_result jsonb;
  v_dedupe text;
begin
  v_dedupe:=case
    when nullif(btrim(coalesce(p_resource_type,'')),'') is not null
     and nullif(btrim(coalesce(p_resource_id,'')),'') is not null
    then p_event_type||':'||p_resource_type||':'||p_resource_id
    else null
  end;

  v_result:=private.trustrelay_create_notification_v09(
    p_account_id,p_org_id,p_category,p_event_type,p_severity,p_title,p_body,
    jsonb_build_object(
      'resourceType',nullif(btrim(coalesce(p_resource_type,'')),''),
      'resourceId',nullif(btrim(coalesce(p_resource_id,'')),''),
      'metadata',coalesce(p_metadata,'{}'::jsonb)
    ),
    v_dedupe
  );

  return v_result->>'id';
end;
$$;

create index if not exists idx_notifications_account_created
  on public.notifications(account_id,created_at desc);

create index if not exists idx_notifications_account_status_created
  on public.notifications(account_id,status,created_at desc);

drop trigger if exists trustrelay_proofing_notification_v09
  on public.identity_proofing_sessions;

drop function if exists private.trustrelay_proofing_notification_trigger_v09();

drop table if exists public.account_notifications;

revoke all on function private.trustrelay_create_notification_v09(
  text,text,text,text,text,text,text,jsonb,text
) from public,anon,authenticated;

revoke all on function private.trustrelay_notify_account_v09(
  text,text,text,text,text,text,text,text,text,jsonb
) from public,anon,authenticated;

grant execute on function private.trustrelay_create_notification_v09(
  text,text,text,text,text,text,text,jsonb,text
) to service_role;

grant execute on function private.trustrelay_notify_account_v09(
  text,text,text,text,text,text,text,text,text,jsonb
) to service_role;

-- ============================================================
-- 20261001204828 trustrelay_v09_notification_canonicalization
-- ============================================================
create or replace function private.trustrelay_create_notification_v09(
  p_account_id text,
  p_organization_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_data jsonb,
  p_dedupe_key text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v_id text:='note_'||replace(gen_random_uuid()::text,'-','');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_enabled boolean:=true;
  v_existing text;
begin
  if p_category not in ('authority','evidence','identity','organization','webhook','compliance','security') then
    return jsonb_build_object('ok',false,'status',400,'code','NOTIFICATION_CATEGORY_INVALID');
  end if;

  if p_severity not in ('info','success','warning','critical') then
    return jsonb_build_object('ok',false,'status',400,'code','NOTIFICATION_SEVERITY_INVALID');
  end if;

  select in_app into v_enabled
  from public.notification_preferences
  where account_id=p_account_id and category=p_category;

  if v_enabled is false then
    return jsonb_build_object('ok',true,'id',null,'suppressed',true,'reason','PREFERENCE_DISABLED');
  end if;

  insert into public.notifications(
    id,account_id,organization_id,category,event_type,severity,title,body,
    data_json,dedupe_key,status,created_at
  ) values (
    v_id,p_account_id,p_organization_id,p_category,p_event_type,p_severity,
    left(btrim(coalesce(p_title,'')),180),
    left(btrim(coalesce(p_body,'')),2000),
    coalesce(p_data,'{}'::jsonb)::text,
    nullif(left(btrim(coalesce(p_dedupe_key,'')),240),''),
    'unread',v_now
  )
  on conflict(account_id,dedupe_key) where dedupe_key is not null
  do nothing
  returning id into v_existing;

  if v_existing is null and nullif(left(btrim(coalesce(p_dedupe_key,'')),240),'') is not null then
    select id into v_existing
    from public.notifications
    where account_id=p_account_id
      and dedupe_key=nullif(left(btrim(coalesce(p_dedupe_key,'')),240),'')
    limit 1;
    return jsonb_build_object('ok',true,'id',v_existing,'suppressed',true,'reason','DUPLICATE');
  end if;

  return jsonb_build_object('ok',true,'id',coalesce(v_existing,v_id),'suppressed',false);
end;
$$;

create or replace function private.trustrelay_notify_account_v09(
  p_account_id text,
  p_org_id text,
  p_category text,
  p_event_type text,
  p_severity text,
  p_title text,
  p_body text,
  p_resource_type text,
  p_resource_id text,
  p_metadata jsonb
)
returns text
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_result jsonb;
begin
  v_result:=private.trustrelay_create_notification_v09(
    p_account_id,p_org_id,p_category,p_event_type,p_severity,p_title,p_body,
    jsonb_build_object(
      'resourceType',p_resource_type,
      'resourceId',p_resource_id,
      'metadata',coalesce(p_metadata,'{}'::jsonb)
    ),
    null
  );
  return v_result->>'id';
end;
$$;

drop trigger if exists trustrelay_proofing_notification_v09 on public.identity_proofing_sessions;

create index if not exists idx_notifications_account_status_created
  on public.notifications(account_id,status,created_at desc);

create index if not exists idx_notifications_account_created
  on public.notifications(account_id,created_at desc);

-- ============================================================
-- 20261001204918 trustrelay_v09_compliance_notification_source
-- ============================================================
create or replace function public.trustrelay_compliance_export_dataset_v09(p_export_id text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_e public.compliance_exports%rowtype;
  v_scopes jsonb;
  v_from timestamptz;
  v_to timestamptz;
begin
  select * into v_e from public.compliance_exports where id=p_export_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','EXPORT_NOT_FOUND');
  end if;
  if v_e.status<>'preparing' then
    return jsonb_build_object('ok',false,'status',409,'code','EXPORT_NOT_PREPARING');
  end if;

  v_scopes:=coalesce(v_e.scopes_json::jsonb,'[]'::jsonb);
  v_from:=v_e.from_at::timestamptz;
  v_to:=v_e.to_at::timestamptz;

  return jsonb_build_object(
    'ok',true,
    'export',jsonb_build_object(
      'id',v_e.id,'organizationId',v_e.organization_id,'format',v_e.format,
      'scopes',v_scopes,'fromAt',v_e.from_at,'toAt',v_e.to_at,'createdAt',v_e.created_at
    ),

    'decisions',case when v_scopes ? 'decisions' then coalesce((
      select jsonb_agg(to_jsonb(d) order by d.decided_at)
      from public.authorization_decisions d
      where d.organization_id=v_e.organization_id
        and d.decided_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'webhookDeliveries',case when v_scopes ? 'webhooks' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',d.id,'subscriptionId',d.subscription_id,'eventType',d.event_type,
        'eventId',d.event_id,'payloadHash',d.payload_hash,'status',d.status,
        'attemptCount',d.attempt_count,'maxAttempts',d.max_attempts,
        'responseStatus',d.response_status,'lastError',d.last_error,
        'createdAt',d.created_at,'attemptedAt',d.attempted_at,
        'deliveredAt',d.delivered_at,'deadLetteredAt',d.dead_lettered_at,
        'nextAttemptAt',d.next_attempt_at
      ) order by d.created_at)
      from public.webhook_deliveries d
      where d.organization_id=v_e.organization_id
        and d.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'webhookAttempts',case when v_scopes ? 'webhooks' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',a.id,'deliveryId',a.delivery_id,'attemptNumber',a.attempt_number,
        'responseStatus',a.response_status,'error',a.error_text,'success',a.success,
        'durationMs',a.duration_ms,'createdAt',a.created_at,'completedAt',a.completed_at
      ) order by a.created_at)
      from public.webhook_delivery_attempts a
      join public.webhook_deliveries d on d.id=a.delivery_id
      where d.organization_id=v_e.organization_id
        and a.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'evidenceRequests',case when v_scopes ? 'evidence' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',er.id,'grantId',er.grant_id,'status',er.status,
        'requiredDocumentTypes',coalesce(er.required_document_types_json::jsonb,'[]'::jsonb),
        'dueAt',er.due_at,'createdAt',er.created_at,'updatedAt',er.updated_at,
        'reviewedAt',er.reviewed_at,'resolutionReason',er.resolution_reason,
        'documentIds',coalesce((
          select jsonb_agg(erd.document_id order by erd.attached_at)
          from public.evidence_request_documents erd
          where erd.request_id=er.id
        ),'[]'::jsonb)
      ) order by er.created_at)
      from public.evidence_requests er
      where er.requested_by_organization_id=v_e.organization_id
        and er.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'members',case when v_scopes ? 'members' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'accountId',m.account_id,'email',a.email,'role',m.role,'status',m.status,
        'title',m.title,'createdAt',m.created_at,'updatedAt',m.updated_at,
        'roleChangedAt',m.role_changed_at,'disabledAt',m.disabled_at,'removedAt',m.removed_at
      ) order by m.created_at)
      from public.organization_members m
      join public.accounts a on a.id=m.account_id
      where m.organization_id=v_e.organization_id
    ),'[]'::jsonb) else '[]'::jsonb end,

    'invitations',case when v_scopes ? 'members' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',i.id,'email',i.invite_email,'role',i.role,'status',i.status,
        'expiresAt',i.expires_at,'acceptedAt',i.accepted_at,
        'revokedAt',i.revoked_at,'createdAt',i.created_at
      ) order by i.created_at)
      from public.organization_invitations i
      where i.organization_id=v_e.organization_id
        and i.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'auditEvents',case when v_scopes ? 'audit' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',a.id,'actorAccountId',a.actor_account_id,'eventType',a.event_type,
        'targetType',a.target_type,'targetId',a.target_id,
        'metadata',coalesce(a.metadata_json::jsonb,'{}'::jsonb),
        'prevHash',a.prev_hash,'eventHash',a.event_hash,'createdAt',a.created_at
      ) order by a.created_at,a.id)
      from public.organization_audit_events a
      where a.organization_id=v_e.organization_id
        and a.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,

    'notifications',case when v_scopes ? 'notifications' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',n.id,'accountId',n.account_id,'organizationId',n.organization_id,
        'category',n.category,'eventType',n.event_type,'severity',n.severity,
        'title',n.title,'body',n.body,'data',coalesce(n.data_json::jsonb,'{}'::jsonb),
        'status',n.status,'readAt',n.read_at,'archivedAt',n.archived_at,'createdAt',n.created_at
      ) order by n.created_at)
      from public.notifications n
      where n.organization_id=v_e.organization_id
        and n.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end
  );
end;
$$;

revoke all on function public.trustrelay_compliance_export_dataset_v09(text)
from public,anon,authenticated;
grant execute on function public.trustrelay_compliance_export_dataset_v09(text) to service_role;

-- ============================================================
-- 20261001205015 trustrelay_v09_dashboard_unread_notifications
-- ============================================================
create or replace function private.trustrelay_org_dashboard_v07(p_uid uuid,p_org_id text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_permissions jsonb;
  v_account_id text;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','compliance','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_permissions:=public.trustrelay_org_permissions_v09(v_ctx->>'role');
  v_account_id:=v_ctx->>'accountId';

  return jsonb_build_object(
    'ok',true,
    'organization',v_ctx->'organization',
    'membership',jsonb_build_object(
      'role',v_ctx->>'role',
      'permissions',v_permissions
    ),
    'metrics',jsonb_build_object(
      'totalDecisions',(select count(*) from public.authorization_decisions where organization_id=p_org_id),
      'allow',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ALLOW'),
      'deny',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='DENY'),
      'escalate',(select count(*) from public.authorization_decisions where organization_id=p_org_id and decision='ESCALATE'),
      'activeKeys',(select count(*) from public.api_keys where organization_id=p_org_id and key_type='partner' and revoked_at is null),
      'members',(select count(*) from public.organization_members where organization_id=p_org_id and status='active'),
      'activeWebhooks',(select count(*) from public.webhook_subscriptions where organization_id=p_org_id and status='active'),
      'deadLetterWebhooks',(select count(*) from public.webhook_deliveries where organization_id=p_org_id and status='dead_letter'),
      'openEvidenceRequests',(select count(*) from public.evidence_requests where requested_by_organization_id=p_org_id and status in ('open','submitted')),
      'readyExports',(select count(*) from public.compliance_exports where organization_id=p_org_id and status='ready'),
      'unreadNotifications',(select count(*) from public.notifications where account_id=v_account_id and status='unread')
    ),
    'apiKeys',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',k.id,'name',k.name,'prefix',k.prefix,'lastFour',k.last_four,
        'scopes',coalesce(k.scopes_json::jsonb,'[]'::jsonb),
        'revokedAt',k.revoked_at,'lastUsedAt',k.last_used_at,
        'createdAt',k.created_at,'expiresAt',k.expires_at,'keyType',k.key_type
      ) order by k.created_at desc)
      from public.api_keys k
      where k.organization_id=p_org_id and k.key_type='partner'
    ),'[]'::jsonb),
    'members',coalesce((
      select jsonb_agg(jsonb_build_object(
        'accountId',a.id,'email',a.email,'role',m.role,'status',m.status,
        'title',m.title,'createdAt',m.created_at,'updatedAt',m.updated_at,
        'roleChangedAt',m.role_changed_at,'disabledAt',m.disabled_at,'removedAt',m.removed_at
      ) order by m.created_at)
      from public.organization_members m
      join public.accounts a on a.id=m.account_id
      where m.organization_id=p_org_id
    ),'[]'::jsonb),
    'pendingInvitations',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',i.id,'email',i.invite_email,'role',i.role,'status',i.status,
        'expiresAt',i.expires_at,'createdAt',i.created_at
      ) order by i.created_at desc)
      from public.organization_invitations i
      where i.organization_id=p_org_id and i.status='pending'
    ),'[]'::jsonb),
    'webhooks',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',w.id,'name',w.name,'endpointUrl',w.endpoint_url,
        'events',coalesce(w.events_json::jsonb,'[]'::jsonb),
        'status',w.status,'secretPrefix',w.secret_prefix,'apiVersion',w.api_version,
        'failureThreshold',w.failure_threshold,'pauseReason',w.pause_reason,'pausedAt',w.paused_at,
        'createdAt',w.created_at,'lastDeliveryAt',w.last_delivery_at,
        'lastSuccessAt',w.last_success_at,'lastFailureAt',w.last_failure_at,
        'consecutiveFailures',w.consecutive_failures,'secretRotatedAt',w.secret_rotated_at
      ) order by w.created_at desc)
      from public.webhook_subscriptions w
      where w.organization_id=p_org_id
    ),'[]'::jsonb),
    'recentWebhookDeliveries',coalesce((
      select jsonb_agg(x.row_json order by x.created_at desc)
      from (
        select d.created_at,jsonb_build_object(
          'id',d.id,'subscriptionId',d.subscription_id,'eventType',d.event_type,
          'eventId',d.event_id,'status',d.status,'attemptCount',d.attempt_count,
          'maxAttempts',d.max_attempts,'responseStatus',d.response_status,
          'createdAt',d.created_at,'attemptedAt',d.attempted_at,
          'deliveredAt',d.delivered_at,'deadLetteredAt',d.dead_lettered_at,
          'nextAttemptAt',d.next_attempt_at,'lastError',d.last_error,
          'manualRedeliveries',d.manually_redelivered_count
        ) row_json
        from public.webhook_deliveries d
        where d.organization_id=p_org_id
        order by d.created_at desc limit 50
      ) x
    ),'[]'::jsonb),
    'recentWebhookAttempts',coalesce((
      select jsonb_agg(x.row_json order by x.created_at desc)
      from (
        select a.created_at,jsonb_build_object(
          'id',a.id,'deliveryId',a.delivery_id,'attemptNumber',a.attempt_number,
          'responseStatus',a.response_status,'error',a.error_text,'success',a.success,
          'durationMs',a.duration_ms,'createdAt',a.created_at,'completedAt',a.completed_at
        ) row_json
        from public.webhook_delivery_attempts a
        join public.webhook_deliveries d on d.id=a.delivery_id
        where d.organization_id=p_org_id
        order by a.created_at desc limit 75
      ) x
    ),'[]'::jsonb),
    'recentDecisions',coalesce((
      select jsonb_agg(x.row_json order by x.decided_at desc)
      from (
        select d.decided_at,jsonb_build_object(
          'id',d.id,'requestId',d.request_id,'correlationId',d.correlation_id,
          'decision',d.decision,'reasonCode',d.reason_code,'reasonDetail',d.reason_detail,
          'action',d.action,'resource',d.resource,'grantId',d.grant_id,
          'credentialJti',d.credential_jti,'decidedAt',d.decided_at,
          'evaluationHash',d.evaluation_hash,'auditEventId',d.audit_event_id,
          'latencyMs',d.latency_ms,'source',d.source,
          'policyVersion',d.policy_version,'engineVersion',d.engine_version
        ) row_json
        from public.authorization_decisions d
        where d.organization_id=p_org_id
        order by d.decided_at desc limit 100
      ) x
    ),'[]'::jsonb),
    'evidenceRequests',coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',er.id,'grantId',er.grant_id,'status',er.status,
        'requiredDocumentTypes',coalesce(er.required_document_types_json::jsonb,'[]'::jsonb),
        'dueAt',er.due_at,'createdAt',er.created_at,'updatedAt',er.updated_at,
        'reviewedAt',er.reviewed_at,'resolutionReason',er.resolution_reason,
        'documents',coalesce((
          select jsonb_agg(jsonb_build_object(
            'id',d.id,'displayName',d.display_name,'classification',d.classification,
            'mimeType',d.mime_type,'sizeBytes',d.size_bytes,'reviewStatus',d.review_status,
            'contentSha256',case when d.content_sha256='pending' then null else d.content_sha256 end,
            'attachedAt',erd.attached_at
          ) order by erd.attached_at)
          from public.evidence_request_documents erd
          join public.documents d on d.id=erd.document_id
          where erd.request_id=er.id and d.deleted_at is null
        ),'[]'::jsonb)
      ) order by er.created_at desc)
      from public.evidence_requests er
      where er.requested_by_organization_id=p_org_id
    ),'[]'::jsonb),
    'complianceExports',case when coalesce((v_permissions->>'audit.export')::boolean,false) then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',e.id,'format',e.format,'scopes',coalesce(e.scopes_json::jsonb,'[]'::jsonb),
        'fromAt',e.from_at,'toAt',e.to_at,'status',e.status,
        'sha256',e.content_sha256,'rowCount',e.row_count,'sizeBytes',e.size_bytes,
        'manifest',case when e.manifest_json is null then null else e.manifest_json::jsonb end,
        'previousExportHash',e.previous_export_hash,'exportHash',e.export_hash,
        'createdAt',e.created_at,'completedAt',e.completed_at,'expiresAt',e.expires_at,
        'errorCode',e.error_code
      ) order by e.created_at desc)
      from public.compliance_exports e where e.organization_id=p_org_id
    ),'[]'::jsonb) else '[]'::jsonb end,
    'recentAuditEvents',case when coalesce((v_permissions->>'audit.read')::boolean,false) then coalesce((
      select jsonb_agg(x.payload order by x.created_at desc)
      from (
        select a.created_at,jsonb_build_object(
          'id',a.id,'actorAccountId',a.actor_account_id,'eventType',a.event_type,
          'targetType',a.target_type,'targetId',a.target_id,
          'metadata',coalesce(a.metadata_json::jsonb,'{}'::jsonb),
          'prevHash',a.prev_hash,'eventHash',a.event_hash,'createdAt',a.created_at
        ) payload
        from public.organization_audit_events a
        where a.organization_id=p_org_id
        order by a.created_at desc,a.id desc limit 100
      ) x
    ),'[]'::jsonb) else '[]'::jsonb end
  );
end;
$$;

-- ============================================================
-- 20261001205050 trustrelay_v09_event_dedup_and_export_alignment
-- ============================================================
create or replace function private.trustrelay_create_webhook_v07(
  p_uid uuid,p_org_id text,p_name text,p_endpoint_url text,p_events jsonb
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text:='wh_'||replace(gen_random_uuid()::text,'-','');
  v_secret text:='whsec_'||encode(gen_random_bytes(32),'hex');
  v_secret_id uuid;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text;
  v_allowed text[]:=array[
    'decision.created','grant.revoked','credential.revoked',
    'evidence.requested','evidence.submitted','evidence.resolved',
    'organization.member.invited','organization.member.joined',
    'organization.member.role_changed','organization.member.disabled',
    'organization.member.restored','organization.member.removed',
    'organization.ownership.transferred',
    'compliance.export.ready','webhook.test'
  ];
  v_url text:=btrim(coalesce(p_endpoint_url,''));
  v_host text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>100 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_NAME_INVALID');
  end if;

  if length(v_url)>2048 or v_url !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_INVALID');
  end if;

  if v_url ~ '^https://[^/]*@' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_USERINFO_FORBIDDEN');
  end if;

  v_host:=lower(substring(v_url from '^https://([^/:?#]+)'));
  if v_host is null
     or v_host='localhost'
     or v_host like '%.localhost'
     or v_host like '%.local'
     or v_host like '%.internal'
     or v_host ~ '^\['
     or v_host ~ '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_PRIVATE_NETWORK_FORBIDDEN');
  end if;

  if p_events is null or jsonb_typeof(p_events)<>'array' or jsonb_array_length(p_events)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENTS_REQUIRED');
  end if;

  for v_event in select jsonb_array_elements_text(p_events)
  loop
    if not (v_event=any(v_allowed)) then
      return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',v_event);
    end if;
  end loop;

  v_secret_id:=vault.create_secret(
    v_secret,'trustrelay-webhook-'||v_id,'TrustRelay v0.9 webhook signing secret'
  );

  insert into public.webhook_subscriptions(
    id,organization_id,name,endpoint_url,events_json,secret_vault_id,secret_prefix,
    status,created_by_account_id,created_at,updated_at,api_version,failure_threshold
  ) values(
    v_id,p_org_id,btrim(p_name),v_url,p_events::text,v_secret_id,left(v_secret,12),
    'active',v_ctx->>'accountId',v_now,v_now,'v0.9',10
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.created','webhook_subscription',v_id,
    jsonb_build_object('name',btrim(p_name),'endpointUrl',v_url,'events',p_events)
  );

  return jsonb_build_object(
    'ok',true,'signingSecret',v_secret,
    'webhook',jsonb_build_object(
      'id',v_id,'name',btrim(p_name),'endpointUrl',v_url,'events',p_events,
      'status','active','secretPrefix',left(v_secret,12),'apiVersion','v0.9','createdAt',v_now
    )
  );
end;
$$;

create or replace function public.trustrelay_queue_webhooks_v07(
  p_org_id text,p_event_type text,p_event_id text,p_payload_json text
)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,pg_catalog
as $$
declare
  v_sub public.webhook_subscriptions%rowtype;
  v_delivery_id text;
  v_secret text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload_hash text;
  v_targets jsonb:='[]'::jsonb;
  v_allowed text[]:=array[
    'decision.created','grant.revoked','credential.revoked',
    'evidence.requested','evidence.submitted','evidence.resolved',
    'organization.member.invited','organization.member.joined',
    'organization.member.role_changed','organization.member.disabled',
    'organization.member.restored','organization.member.removed',
    'organization.ownership.transferred',
    'compliance.export.ready','webhook.test'
  ];
begin
  if not (p_event_type=any(v_allowed)) then
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

  v_payload_hash:=encode(digest(p_payload_json,'sha256'),'hex');

  for v_sub in
    select * from public.webhook_subscriptions
    where organization_id=p_org_id
      and status='active'
      and (p_event_type='webhook.test' or coalesce(events_json::jsonb,'[]'::jsonb) ? p_event_type)
  loop
    select decrypted_secret into v_secret
    from vault.decrypted_secrets
    where id=v_sub.secret_vault_id;

    if v_secret is null then continue; end if;

    v_delivery_id:='whd_'||replace(gen_random_uuid()::text,'-','');

    insert into public.webhook_deliveries(
      id,subscription_id,organization_id,event_type,event_id,payload_json,payload_hash,
      status,attempt_count,max_attempts,created_at,next_attempt_at
    ) values(
      v_delivery_id,v_sub.id,p_org_id,p_event_type,p_event_id,p_payload_json,v_payload_hash,
      'pending',0,5,v_now,v_now
    )
    on conflict(subscription_id,event_id) do nothing;

    if found then
      v_targets:=v_targets||jsonb_build_array(jsonb_build_object(
        'deliveryId',v_delivery_id,'subscriptionId',v_sub.id,
        'endpointUrl',v_sub.endpoint_url,'signingSecret',v_secret
      ));
    end if;
  end loop;

  return jsonb_build_object('ok',true,'targets',v_targets,'payloadHash',v_payload_hash);
end;
$$;

create or replace function private.trustrelay_org_member_event_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_type text;
begin
  if tg_op='UPDATE'
     and old.status is distinct from new.status
     and new.status='active'
     and old.status<>'active' then
    v_type:='organization.member.restored';
  elsif tg_op='UPDATE'
     and old.status is distinct from new.status
     and new.status='removed' then
    v_type:='organization.member.removed';
  end if;

  if v_type is not null then
    perform public.trustrelay_emit_org_event_v09(
      new.organization_id,v_type,
      jsonb_build_object(
        'accountId',new.account_id,
        'role',new.role,
        'status',new.status,
        'previousStatus',old.status
      )
    );
  end if;

  return new;
end;
$$;

create or replace function private.trustrelay_compliance_export_event_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_event_id text;
  v_now text;
  v_payload text;
begin
  if new.status='ready' and old.status is distinct from new.status then
    v_event_id:='export-event-'||new.id;
    v_now:=coalesce(new.completed_at,to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    v_payload:=jsonb_build_object(
      'id',v_event_id,
      'type','compliance.export.ready',
      'createdAt',v_now,
      'organizationId',new.organization_id,
      'data',jsonb_build_object(
        'exportId',new.id,
        'format',new.format,
        'scopes',coalesce(new.scopes_json::jsonb,'[]'::jsonb),
        'sha256',new.content_sha256,
        'rowCount',new.row_count,
        'sizeBytes',new.size_bytes,
        'exportHash',new.export_hash,
        'completedAt',new.completed_at,
        'expiresAt',new.expires_at
      )
    )::text;

    perform public.trustrelay_queue_webhooks_v07(
      new.organization_id,'compliance.export.ready',v_event_id,v_payload
    );
    perform public.trustrelay_dispatch_due_webhooks_v09(25);
  end if;

  return new;
end;
$$;

create or replace function public.trustrelay_compliance_export_dataset_v09(p_export_id text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_e public.compliance_exports%rowtype;
  v_scopes jsonb;
  v_from timestamptz;
  v_to timestamptz;
begin
  select * into v_e
  from public.compliance_exports
  where id=p_export_id;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','EXPORT_NOT_FOUND');
  end if;
  if v_e.status<>'preparing' then
    return jsonb_build_object('ok',false,'status',409,'code','EXPORT_NOT_PREPARING');
  end if;

  v_scopes:=coalesce(v_e.scopes_json::jsonb,'[]'::jsonb);
  v_from:=v_e.from_at::timestamptz;
  v_to:=v_e.to_at::timestamptz;

  return jsonb_build_object(
    'ok',true,
    'export',jsonb_build_object(
      'id',v_e.id,'organizationId',v_e.organization_id,'format',v_e.format,
      'scopes',v_scopes,'fromAt',v_e.from_at,'toAt',v_e.to_at,'createdAt',v_e.created_at
    ),
    'decisions',case when v_scopes ? 'decisions' then coalesce((
      select jsonb_agg(to_jsonb(d) order by d.decided_at)
      from public.authorization_decisions d
      where d.organization_id=v_e.organization_id
        and d.decided_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'webhookDeliveries',case when v_scopes ? 'webhooks' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',d.id,'subscriptionId',d.subscription_id,'eventType',d.event_type,
        'eventId',d.event_id,'payloadHash',d.payload_hash,'status',d.status,
        'attemptCount',d.attempt_count,'responseStatus',d.response_status,
        'lastError',d.last_error,'createdAt',d.created_at,'attemptedAt',d.attempted_at,
        'deliveredAt',d.delivered_at,'deadLetteredAt',d.dead_lettered_at
      ) order by d.created_at)
      from public.webhook_deliveries d
      where d.organization_id=v_e.organization_id
        and d.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'webhookAttempts',case when v_scopes ? 'webhooks' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',a.id,'deliveryId',a.delivery_id,'attemptNumber',a.attempt_number,
        'responseStatus',a.response_status,'error',a.error_text,'success',a.success,
        'createdAt',a.created_at,'completedAt',a.completed_at
      ) order by a.created_at)
      from public.webhook_delivery_attempts a
      join public.webhook_deliveries d on d.id=a.delivery_id
      where d.organization_id=v_e.organization_id
        and a.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'evidenceRequests',case when v_scopes ? 'evidence' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',er.id,'grantId',er.grant_id,'status',er.status,
        'requiredDocumentTypes',coalesce(er.required_document_types_json::jsonb,'[]'::jsonb),
        'dueAt',er.due_at,'createdAt',er.created_at,'updatedAt',er.updated_at,
        'reviewedAt',er.reviewed_at,'resolutionReason',er.resolution_reason,
        'documentIds',coalesce((
          select jsonb_agg(erd.document_id order by erd.attached_at)
          from public.evidence_request_documents erd
          where erd.request_id=er.id
        ),'[]'::jsonb)
      ) order by er.created_at)
      from public.evidence_requests er
      where er.requested_by_organization_id=v_e.organization_id
        and er.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'members',case when v_scopes ? 'members' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'accountId',m.account_id,'email',a.email,'role',m.role,'status',m.status,
        'title',m.title,'createdAt',m.created_at,'updatedAt',m.updated_at,
        'roleChangedAt',m.role_changed_at,'disabledAt',m.disabled_at
      ) order by m.created_at)
      from public.organization_members m
      join public.accounts a on a.id=m.account_id
      where m.organization_id=v_e.organization_id
    ),'[]'::jsonb) else '[]'::jsonb end,
    'invitations',case when v_scopes ? 'members' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',i.id,'email',i.invite_email,'role',i.role,'status',i.status,
        'expiresAt',i.expires_at,'acceptedAt',i.accepted_at,'revokedAt',i.revoked_at,'createdAt',i.created_at
      ) order by i.created_at)
      from public.organization_invitations i
      where i.organization_id=v_e.organization_id
        and i.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'auditEvents',case when v_scopes ? 'audit' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',a.id,'actorAccountId',a.actor_account_id,'eventType',a.event_type,
        'targetType',a.target_type,'targetId',a.target_id,
        'metadata',coalesce(a.metadata_json::jsonb,'{}'::jsonb),
        'prevHash',a.prev_hash,'eventHash',a.event_hash,'createdAt',a.created_at
      ) order by a.created_at,a.id)
      from public.organization_audit_events a
      where a.organization_id=v_e.organization_id
        and a.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end,
    'notifications',case when v_scopes ? 'notifications' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',n.id,'accountId',n.account_id,'category',n.category,
        'eventType',n.event_type,'severity',n.severity,'title',n.title,'body',n.body,
        'data',coalesce(n.data_json::jsonb,'{}'::jsonb),
        'status',n.status,'readAt',n.read_at,'archivedAt',n.archived_at,'createdAt',n.created_at
      ) order by n.created_at)
      from public.notifications n
      where n.organization_id=v_e.organization_id
        and n.created_at::timestamptz between v_from and v_to
    ),'[]'::jsonb) else '[]'::jsonb end
  );
end;
$$;

-- ============================================================
-- 20261001205106 trustrelay_v09_remove_duplicate_member_trigger
-- ============================================================
drop trigger if exists trustrelay_org_member_event_v09 on public.organization_members;

-- ============================================================
-- 20261001205132 trustrelay_v09_webhook_event_normalization
-- ============================================================
create or replace function private.trustrelay_org_member_event_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
begin
  if tg_op='INSERT' and new.status='active' then
    perform public.trustrelay_emit_org_event_v09(
      new.organization_id,
      'organization.member.joined',
      jsonb_build_object(
        'accountId',new.account_id,
        'role',new.role,
        'status',new.status
      )
    );
  end if;
  return new;
end;
$$;

drop trigger if exists trustrelay_org_member_event_v09 on public.organization_members;
create trigger trustrelay_org_member_event_v09
after insert on public.organization_members
for each row execute function private.trustrelay_org_member_event_trigger_v09();

create or replace function private.trustrelay_restore_member_v09(
  p_uid uuid,p_org_id text,p_account_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'members.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_MEMBER_NOT_FOUND');
  end if;
  if v_target.status='removed' then
    return jsonb_build_object('ok',false,'status',409,'code','REMOVED_MEMBER_REQUIRES_INVITATION');
  end if;
  if v_target.role='owner' and (v_ctx->>'role')<>'owner' then
    return jsonb_build_object('ok',false,'status',403,'code','OWNER_ROLE_REQUIRES_OWNER');
  end if;
  if (v_ctx->>'role')='admin' and v_target.role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  update public.organization_members
  set status='active',disabled_at=null,disabled_by_account_id=null,updated_at=v_now
  where organization_id=p_org_id and account_id=p_account_id
  returning * into v_target;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','organization.member.enabled',
    'organization_member',p_account_id,jsonb_build_object('role',v_target.role)
  );

  perform private.trustrelay_notify_account_v09(
    p_account_id,p_org_id,'organization','organization.member.enabled','success',
    'Organization access restored',
    'Your TrustRelay organization access has been restored.',
    'organization',p_org_id,jsonb_build_object('role',v_target.role)
  );

  perform public.trustrelay_emit_org_event_v09(
    p_org_id,'organization.member.enabled',
    jsonb_build_object('accountId',p_account_id,'role',v_target.role,'status','active')
  );

  return jsonb_build_object('ok',true,'accountId',p_account_id,'status','active');
end;
$$;

create or replace function private.trustrelay_remove_member_v09(
  p_uid uuid,p_org_id text,p_account_id text,p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'members.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if p_account_id=v_ctx->>'accountId' then
    return jsonb_build_object('ok',false,'status',409,'code','SELF_REMOVAL_FORBIDDEN');
  end if;

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id and status<>'removed'
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_MEMBER_NOT_FOUND');
  end if;
  if v_target.role='owner' then
    return jsonb_build_object('ok',false,'status',409,'code','OWNER_REQUIRES_TRANSFER');
  end if;
  if (v_ctx->>'role')='admin' and v_target.role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  update public.organization_members
  set status='removed',removed_at=v_now,removed_by_account_id=v_ctx->>'accountId',updated_at=v_now
  where organization_id=p_org_id and account_id=p_account_id
  returning * into v_target;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','organization.member.removed',
    'organization_member',p_account_id,
    jsonb_build_object(
      'role',v_target.role,
      'reason',nullif(left(btrim(coalesce(p_reason,'')),500),'')
    )
  );

  perform private.trustrelay_notify_account_v09(
    p_account_id,p_org_id,'organization','organization.member.removed','warning',
    'Removed from organization',
    'Your TrustRelay organization membership has been removed.',
    'organization',p_org_id,jsonb_build_object('role',v_target.role)
  );

  perform public.trustrelay_emit_org_event_v09(
    p_org_id,'organization.member.removed',
    jsonb_build_object(
      'accountId',p_account_id,'role',v_target.role,'status','removed',
      'reason',nullif(left(btrim(coalesce(p_reason,'')),500),'')
    )
  );

  return jsonb_build_object('ok',true,'accountId',p_account_id,'status','removed');
end;
$$;

create or replace function private.trustrelay_transfer_org_owner_v09(
  p_uid uuid,p_org_id text,p_new_owner_account_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_current_id text;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_org_role_v07(p_uid,p_org_id,array['owner']);
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_current_id:=v_ctx->>'accountId';

  if p_new_owner_account_id=v_current_id then
    return jsonb_build_object('ok',false,'status',409,'code','ALREADY_ORGANIZATION_OWNER');
  end if;

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id
    and account_id=p_new_owner_account_id
    and status='active'
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','NEW_OWNER_MUST_BE_ACTIVE_MEMBER');
  end if;

  update public.organization_members
  set role='admin',role_changed_at=v_now,role_changed_by_account_id=v_current_id,updated_at=v_now
  where organization_id=p_org_id and account_id=v_current_id and role='owner';

  update public.organization_members
  set role='owner',role_changed_at=v_now,role_changed_by_account_id=v_current_id,updated_at=v_now
  where organization_id=p_org_id and account_id=p_new_owner_account_id
  returning * into v_target;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_current_id,'organization.ownership.transferred',
    'organization',p_org_id,
    jsonb_build_object('fromAccountId',v_current_id,'toAccountId',p_new_owner_account_id)
  );

  perform private.trustrelay_notify_account_v09(
    p_new_owner_account_id,p_org_id,'organization','organization.ownership.transferred','critical',
    'You are now the organization owner',
    'Ownership of this TrustRelay organization was transferred to your account.',
    'organization',p_org_id,
    jsonb_build_object('previousOwnerAccountId',v_current_id,'role','owner')
  );

  perform private.trustrelay_notify_account_v09(
    v_current_id,p_org_id,'organization','organization.ownership.transferred','info',
    'Organization ownership transferred',
    'Ownership was transferred successfully. Your role is now admin.',
    'organization',p_org_id,
    jsonb_build_object('newOwnerAccountId',p_new_owner_account_id,'role','admin')
  );

  perform public.trustrelay_emit_org_event_v09(
    p_org_id,'organization.ownership.transferred',
    jsonb_build_object(
      'previousOwnerAccountId',v_current_id,
      'newOwnerAccountId',p_new_owner_account_id
    )
  );

  return jsonb_build_object(
    'ok',true,'organizationId',p_org_id,
    'previousOwnerAccountId',v_current_id,'newOwnerAccountId',p_new_owner_account_id
  );
end;
$$;

do $$
declare
  v_oid oid;
  v_def text;
begin
  select p.oid into v_oid
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='private'
    and p.proname='trustrelay_create_webhook_v07'
    and pg_get_function_identity_arguments(p.oid)='p_uid uuid, p_org_id text, p_name text, p_endpoint_url text, p_events jsonb';
  select pg_get_functiondef(v_oid) into v_def;
  v_def:=replace(v_def,'organization.owner_transferred','organization.ownership.transferred');
  execute v_def;

  select p.oid into v_oid
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public'
    and p.proname='trustrelay_queue_webhooks_v07'
    and pg_get_function_identity_arguments(p.oid)='p_org_id text, p_event_type text, p_event_id text, p_payload_json text';
  select pg_get_functiondef(v_oid) into v_def;
  v_def:=replace(v_def,'organization.owner_transferred','organization.ownership.transferred');
  execute v_def;
end $$;

create or replace function public.trustrelay_webhook_event_catalog_v09()
returns jsonb
language sql
immutable
security invoker
set search_path=pg_catalog
as $$
  select '[
    "decision.created",
    "grant.revoked",
    "credential.revoked",
    "evidence.requested",
    "evidence.submitted",
    "evidence.resolved",
    "organization.member.invited",
    "organization.member.joined",
    "organization.member.role_changed",
    "organization.member.disabled",
    "organization.member.enabled",
    "organization.member.removed",
    "organization.ownership.transferred",
    "compliance.export.ready",
    "webhook.test"
  ]'::jsonb;
$$;

-- ============================================================
-- 20261001205634 trustrelay_v09_compliance_range_guard
-- ============================================================
create or replace function private.trustrelay_request_compliance_export_v09(
  p_uid uuid,p_org_id text,p_scopes jsonb,p_format text,p_from_at text,p_to_at text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text:='export_'||replace(gen_random_uuid()::text,'-','');
  v_now_ts timestamptz:=clock_timestamp();
  v_now text:=to_char(v_now_ts at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_expires text:=to_char((v_now_ts+interval '24 hours') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_scope text;
  v_scopes jsonb:=p_scopes;
  v_from text;
  v_to text;
  v_from_ts timestamptz;
  v_to_ts timestamptz;
  v_key text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'audit.export');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if p_format not in ('json','csv') then
    return jsonb_build_object('ok',false,'status',400,'code','EXPORT_FORMAT_INVALID');
  end if;

  if v_scopes is null or jsonb_typeof(v_scopes)<>'array' or jsonb_array_length(v_scopes)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','EXPORT_SCOPES_REQUIRED');
  end if;

  if v_scopes ? 'all' then
    v_scopes:='["decisions","audit","webhooks","members","evidence","api_keys","notifications"]'::jsonb;
  end if;

  for v_scope in select jsonb_array_elements_text(v_scopes)
  loop
    if v_scope not in ('decisions','audit','audit_events','webhooks','members','evidence','api_keys','notifications') then
      return jsonb_build_object('ok',false,'status',400,'code','EXPORT_SCOPE_INVALID','scope',v_scope);
    end if;
  end loop;

  v_from:=coalesce(
    p_from_at,
    to_char((v_now_ts-interval '30 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
  v_to:=coalesce(
    p_to_at,
    to_char(v_now_ts at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );

  v_from_ts:=v_from::timestamptz;
  v_to_ts:=v_to::timestamptz;

  if v_from_ts>v_to_ts then
    return jsonb_build_object('ok',false,'status',400,'code','EXPORT_DATE_RANGE_INVALID');
  end if;

  if v_to_ts-v_from_ts>interval '366 days' then
    return jsonb_build_object('ok',false,'status',400,'code','EXPORT_RANGE_INVALID');
  end if;

  v_key:=p_org_id||'/'||v_id||'.'||p_format;

  insert into public.compliance_exports(
    id,organization_id,requested_by_account_id,format,scopes_json,from_at,to_at,status,
    storage_bucket,storage_key,created_at,expires_at
  ) values(
    v_id,p_org_id,v_ctx->>'accountId',p_format,v_scopes::text,v_from,v_to,'preparing',
    'trustrelay-compliance-exports',v_key,v_now,v_expires
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','compliance.export.requested','compliance_export',v_id,
    jsonb_build_object('scopes',v_scopes,'format',p_format,'fromAt',v_from,'toAt',v_to)
  );

  return jsonb_build_object(
    'ok',true,
    'export',jsonb_build_object(
      'id',v_id,'organizationId',p_org_id,'format',p_format,'scopes',v_scopes,
      'fromAt',v_from,'toAt',v_to,'status','preparing',
      'storageBucket','trustrelay-compliance-exports','storageKey',v_key,
      'createdAt',v_now,'expiresAt',v_expires
    )
  );
exception when invalid_datetime_format then
  return jsonb_build_object('ok',false,'status',400,'code','EXPORT_DATE_INVALID');
end;
$$;

-- ============================================================
-- 20261001205653 trustrelay_v09_drop_legacy_notification_table
-- ============================================================
drop table if exists public.account_notifications;

-- ============================================================
-- 20261001205702 trustrelay_v09_canonical_consolidation
-- ============================================================
drop trigger if exists trustrelay_org_member_event_v09 on public.organization_members;
drop trigger if exists trustrelay_compliance_export_event_v09 on public.compliance_exports;
drop trigger if exists trustrelay_authority_invitation_notification_v09 on public.authority_grant_invitations;

create or replace function private.trustrelay_grant_notification_trigger_v09()
returns trigger
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_principal_account text;
  v_rep_account text;
begin
  v_principal_account:=private.trustrelay_grant_party_account_v09(new.principal_person_id);
  v_rep_account:=private.trustrelay_grant_party_account_v09(new.representative_person_id);

  if v_rep_account is null and nullif(btrim(coalesce(new.representative_email,'')),'') is not null then
    select id into v_rep_account
    from public.accounts
    where lower(email)=lower(new.representative_email)
      and status='active'
    order by created_at
    limit 1;
  end if;

  if tg_op='INSERT' then
    if v_principal_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_principal_account,null,'authority','grant.created','success',
        'Authority grant created',
        'A new TrustRelay authority grant was created.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'status',new.status,'role','principal')
      );
    end if;

    if v_rep_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_rep_account,null,'authority','grant.created','info',
        'New authority invitation',
        'A TrustRelay principal created an authority grant involving your identity.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'status',new.status,'role','representative')
      );
    end if;
    return new;
  end if;

  if old.accepted_at is null and new.accepted_at is not null then
    if v_principal_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_principal_account,null,'authority','grant.accepted','success',
        'Authority invitation accepted',
        'The representative accepted your TrustRelay authority grant.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'status',new.status)
      );
    end if;

    if v_rep_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_rep_account,null,'authority','grant.accepted','success',
        'Authority accepted',
        'You accepted this TrustRelay authority grant.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'status',new.status)
      );
    end if;
  end if;

  if old.revoked_at is null and new.revoked_at is not null then
    if v_principal_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_principal_account,null,'authority','grant.revoked','critical',
        'Authority grant revoked',
        'This TrustRelay authority grant has been revoked.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'reason',new.revocation_reason,'role','principal')
      );
    end if;

    if v_rep_account is not null then
      perform private.trustrelay_notify_account_v09(
        v_rep_account,null,'authority','grant.revoked','critical',
        'Authority revoked',
        'A TrustRelay authority grant you represented has been revoked.',
        'grant',new.id,
        jsonb_build_object('grantId',new.id,'reason',new.revocation_reason,'role','representative')
      );
    end if;
  end if;

  return new;
end;
$$;

create or replace function public.trustrelay_revoke_grant_v06(
  p_auth_user_id uuid,p_grant_id text,p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_grant public.authority_grants%rowtype;
  v_cred public.credentials%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_account
  from public.accounts
  where auth_user_id=p_auth_user_id and status='active'
  limit 1;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_grant
  from public.authority_grants
  where id=p_grant_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','GRANT_NOT_FOUND');
  end if;

  if v_grant.principal_person_id<>v_account.person_id then
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
    select *
    from public.credentials
    where grant_id=p_grant_id and status='active'
    for update
  loop
    update public.credentials
    set status='revoked',revoked_at=v_now
    where id=v_cred.id;

    insert into public.revocations(
      jti,credential_id,reason,revoked_by_account_id,revoked_at
    ) values(
      v_cred.jti,v_cred.id,
      coalesce(nullif(btrim(p_reason),''),'Grant revoked'),
      v_account.id,v_now
    )
    on conflict(jti) do nothing;
  end loop;

  update public.authority_grant_invitations
  set status='revoked',revoked_at=v_now
  where grant_id=p_grant_id and status='pending';

  return jsonb_build_object(
    'ok',true,'grant',to_jsonb(v_grant),'alreadyRevoked',false
  );
end;
$$;

create or replace function private.trustrelay_create_webhook_v07(
  p_uid uuid,p_org_id text,p_name text,p_endpoint_url text,p_events jsonb
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_id text:='wh_'||replace(gen_random_uuid()::text,'-','');
  v_secret text:='whsec_'||encode(gen_random_bytes(32),'hex');
  v_secret_id uuid;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text;
  v_catalog jsonb:=public.trustrelay_webhook_event_catalog_v09();
  v_url text:=btrim(coalesce(p_endpoint_url,''));
  v_host text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if length(btrim(coalesce(p_name,'')))<2 or length(btrim(p_name))>100 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_NAME_INVALID');
  end if;

  if length(v_url)>2048 or v_url !~ '^https://[^[:space:]]+$' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_INVALID');
  end if;

  if v_url ~ '^https://[^/]*@' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_USERINFO_FORBIDDEN');
  end if;

  v_host:=lower(substring(v_url from '^https://([^/:?#]+)'));
  if v_host is null
     or v_host='localhost'
     or v_host like '%.localhost'
     or v_host like '%.local'
     or v_host like '%.internal'
     or v_host ~ '^\['
     or v_host ~ '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_URL_PRIVATE_NETWORK_FORBIDDEN');
  end if;

  if p_events is null or jsonb_typeof(p_events)<>'array' or jsonb_array_length(p_events)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENTS_REQUIRED');
  end if;

  for v_event in select jsonb_array_elements_text(p_events)
  loop
    if not (v_catalog ? v_event) then
      return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',v_event);
    end if;
  end loop;

  v_secret_id:=vault.create_secret(
    v_secret,'trustrelay-webhook-'||v_id,'TrustRelay v0.9 webhook signing secret'
  );

  insert into public.webhook_subscriptions(
    id,organization_id,name,endpoint_url,events_json,secret_vault_id,secret_prefix,
    status,created_by_account_id,created_at,updated_at,api_version,failure_threshold
  ) values(
    v_id,p_org_id,btrim(p_name),v_url,p_events::text,v_secret_id,left(v_secret,12),
    'active',v_ctx->>'accountId',v_now,v_now,'v0.9',10
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.created','webhook_subscription',v_id,
    jsonb_build_object('name',btrim(p_name),'endpointUrl',v_url,'events',p_events)
  );

  return jsonb_build_object(
    'ok',true,'signingSecret',v_secret,
    'webhook',jsonb_build_object(
      'id',v_id,'name',btrim(p_name),'endpointUrl',v_url,'events',p_events,
      'status','active','secretPrefix',left(v_secret,12),
      'apiVersion','v0.9','createdAt',v_now
    )
  );
end;
$$;

create or replace function public.trustrelay_queue_webhooks_v07(
  p_org_id text,p_event_type text,p_event_id text,p_payload_json text
)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,pg_catalog
as $$
declare
  v_sub public.webhook_subscriptions%rowtype;
  v_delivery_id text;
  v_secret text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_payload_hash text;
  v_targets jsonb:='[]'::jsonb;
  v_catalog jsonb:=public.trustrelay_webhook_event_catalog_v09();
begin
  if not (v_catalog ? p_event_type) then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_EVENT_INVALID','event',p_event_type);
  end if;

  if p_payload_json is null or length(p_payload_json)>262144 then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end if;

  begin
    perform p_payload_json::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_PAYLOAD_INVALID');
  end;

  v_payload_hash:=encode(digest(p_payload_json,'sha256'),'hex');

  for v_sub in
    select *
    from public.webhook_subscriptions
    where organization_id=p_org_id
      and status='active'
      and (
        p_event_type='webhook.test'
        or coalesce(events_json::jsonb,'[]'::jsonb) ? p_event_type
      )
  loop
    select decrypted_secret into v_secret
    from vault.decrypted_secrets
    where id=v_sub.secret_vault_id;

    if v_secret is null then continue; end if;

    v_delivery_id:='whd_'||replace(gen_random_uuid()::text,'-','');

    insert into public.webhook_deliveries(
      id,subscription_id,organization_id,event_type,event_id,payload_json,payload_hash,
      status,attempt_count,max_attempts,created_at,next_attempt_at
    ) values(
      v_delivery_id,v_sub.id,p_org_id,p_event_type,p_event_id,p_payload_json,v_payload_hash,
      'pending',0,5,v_now,v_now
    )
    on conflict(subscription_id,event_id) do nothing;

    if found then
      v_targets:=v_targets||jsonb_build_array(jsonb_build_object(
        'deliveryId',v_delivery_id,
        'subscriptionId',v_sub.id,
        'endpointUrl',v_sub.endpoint_url
      ));
    end if;
  end loop;

  return jsonb_build_object(
    'ok',true,'targets',v_targets,'payloadHash',v_payload_hash
  );
end;
$$;

create or replace function private.trustrelay_manage_org_member_v09(
  p_uid uuid,p_org_id text,p_member_account_id text,p_action text,
  p_role text default null,p_title text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_actor_id text;
  v_actor_role text;
  v_target public.organization_members%rowtype;
  v_old_role text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event_type text;
  v_change text;
  v_event_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_payload text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(
    p_uid,p_org_id,
    case when p_action='role' then 'roles.manage' else 'members.manage' end
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_actor_id:=v_ctx->>'accountId';
  v_actor_role:=v_ctx->>'role';

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id and account_id=p_member_account_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_MEMBER_NOT_FOUND');
  end if;

  if v_target.role='owner' then
    return jsonb_build_object('ok',false,'status',409,'code','OWNER_REQUIRES_TRANSFER');
  end if;

  if v_actor_role='admin' and v_target.role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  if p_action='role' then
    if p_role not in ('admin','compliance','verifier','developer','auditor') then
      return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_ROLE_INVALID');
    end if;
    if v_actor_role='admin' and p_role='admin' then
      return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
    end if;

    v_old_role:=v_target.role;
    if v_old_role=p_role then
      return jsonb_build_object(
        'ok',true,'unchanged',true,
        'member',jsonb_build_object(
          'accountId',v_target.account_id,'role',v_target.role,'status',v_target.status
        )
      );
    end if;

    update public.organization_members
    set role=p_role,
        title=coalesce(nullif(left(btrim(coalesce(p_title,'')),120),''),title),
        role_changed_at=v_now,
        role_changed_by_account_id=v_actor_id,
        updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.role_changed';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'info',
      'Organization role updated',
      'Your TrustRelay organization role changed from '||v_old_role||' to '||p_role||'.',
      'organization',p_org_id,
      jsonb_build_object('fromRole',v_old_role,'toRole',p_role)
    );

  elsif p_action='disable' then
    if v_target.status<>'active' then
      return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_NOT_ACTIVE');
    end if;

    update public.organization_members
    set status='disabled',disabled_at=v_now,disabled_by_account_id=v_actor_id,updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.disabled';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'warning',
      'Organization access disabled',
      'Your TrustRelay organization access was disabled.',
      'organization',p_org_id,jsonb_build_object('role',v_target.role)
    );

  elsif p_action='enable' then
    if v_target.status<>'disabled' then
      return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_NOT_DISABLED');
    end if;

    update public.organization_members
    set status='active',
        disabled_at=null,
        disabled_by_account_id=null,
        removed_at=null,
        removed_by_account_id=null,
        updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.changed';
    v_change:='enabled';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'success',
      'Organization access restored',
      'Your TrustRelay organization access was restored.',
      'organization',p_org_id,
      jsonb_build_object('role',v_target.role,'change',v_change)
    );

  elsif p_action='remove' then
    if v_target.status='removed' then
      return jsonb_build_object(
        'ok',true,'unchanged',true,
        'member',jsonb_build_object(
          'accountId',v_target.account_id,'role',v_target.role,'status',v_target.status
        )
      );
    end if;

    update public.organization_members
    set status='removed',removed_at=v_now,removed_by_account_id=v_actor_id,updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.changed';
    v_change:='removed';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'warning',
      'Removed from organization',
      'Your TrustRelay organization membership was removed.',
      'organization',p_org_id,
      jsonb_build_object('role',v_target.role,'change',v_change)
    );

  else
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_MEMBER_ACTION_INVALID');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_actor_id,v_event_type,'organization_member',p_member_account_id,
    jsonb_build_object(
      'role',v_target.role,
      'status',v_target.status,
      'previousRole',v_old_role,
      'title',v_target.title,
      'change',v_change
    )
  );

  v_payload:=jsonb_build_object(
    'id',v_event_id,'type',v_event_type,'createdAt',v_now,'organizationId',p_org_id,
    'data',jsonb_build_object(
      'accountId',p_member_account_id,
      'role',v_target.role,
      'status',v_target.status,
      'previousRole',v_old_role,
      'change',v_change
    )
  )::text;

  perform public.trustrelay_queue_webhooks_v07(
    p_org_id,v_event_type,v_event_id,v_payload
  );
  perform public.trustrelay_dispatch_due_webhooks_v09(25);

  return jsonb_build_object(
    'ok',true,
    'member',jsonb_build_object(
      'accountId',v_target.account_id,
      'role',v_target.role,
      'status',v_target.status,
      'title',v_target.title,
      'updatedAt',v_target.updated_at
    )
  );
end;
$$;

create or replace function private.trustrelay_transfer_org_owner_v09(
  p_uid uuid,p_org_id text,p_new_owner_account_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_current_id text;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text:='organization.ownership_transferred';
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_current_id:=v_ctx->>'accountId';

  if p_new_owner_account_id=v_current_id then
    return jsonb_build_object('ok',false,'status',409,'code','ALREADY_ORGANIZATION_OWNER');
  end if;

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id
    and account_id=p_new_owner_account_id
    and status='active'
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','NEW_OWNER_MUST_BE_ACTIVE_MEMBER');
  end if;

  update public.organization_members
  set role='admin',
      role_changed_at=v_now,
      role_changed_by_account_id=v_current_id,
      updated_at=v_now
  where organization_id=p_org_id
    and account_id=v_current_id
    and role='owner';

  update public.organization_members
  set role='owner',
      role_changed_at=v_now,
      role_changed_by_account_id=v_current_id,
      updated_at=v_now
  where organization_id=p_org_id
    and account_id=p_new_owner_account_id
  returning * into v_target;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_current_id,v_event,
    'organization',p_org_id,
    jsonb_build_object(
      'fromAccountId',v_current_id,
      'toAccountId',p_new_owner_account_id
    )
  );

  perform private.trustrelay_notify_account_v09(
    p_new_owner_account_id,p_org_id,'organization',v_event,'critical',
    'You are now the organization owner',
    'Ownership of this TrustRelay organization was transferred to your account.',
    'organization',p_org_id,
    jsonb_build_object('previousOwnerAccountId',v_current_id,'role','owner')
  );

  perform private.trustrelay_notify_account_v09(
    v_current_id,p_org_id,'organization',v_event,'info',
    'Organization ownership transferred',
    'Ownership was transferred successfully. Your role is now admin.',
    'organization',p_org_id,
    jsonb_build_object('newOwnerAccountId',p_new_owner_account_id,'role','admin')
  );

  perform public.trustrelay_emit_org_event_v09(
    p_org_id,v_event,
    jsonb_build_object(
      'previousOwnerAccountId',v_current_id,
      'newOwnerAccountId',p_new_owner_account_id
    )
  );

  return jsonb_build_object(
    'ok',true,
    'organizationId',p_org_id,
    'previousOwnerAccountId',v_current_id,
    'newOwnerAccountId',p_new_owner_account_id
  );
end;
$$;

-- ============================================================
-- 20261001210012 trustrelay_v09_member_event_normalization
-- ============================================================
create or replace function private.trustrelay_restore_member_v09(
  p_uid uuid,p_org_id text,p_account_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_target public.organization_members%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event text:='organization.member.restored';
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'members.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id and account_id=p_account_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_MEMBER_NOT_FOUND');
  end if;
  if v_target.status='removed' then
    return jsonb_build_object('ok',false,'status',409,'code','REMOVED_MEMBER_REQUIRES_INVITATION');
  end if;
  if v_target.role='owner' and (v_ctx->>'role')<>'owner' then
    return jsonb_build_object('ok',false,'status',403,'code','OWNER_ROLE_REQUIRES_OWNER');
  end if;
  if (v_ctx->>'role')='admin' and v_target.role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  update public.organization_members
  set status='active',disabled_at=null,disabled_by_account_id=null,updated_at=v_now
  where organization_id=p_org_id and account_id=p_account_id
  returning * into v_target;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId',v_event,
    'organization_member',p_account_id,jsonb_build_object('role',v_target.role)
  );

  perform private.trustrelay_notify_account_v09(
    p_account_id,p_org_id,'organization',v_event,'success',
    'Organization access restored',
    'Your TrustRelay organization access has been restored.',
    'organization',p_org_id,jsonb_build_object('role',v_target.role)
  );

  perform public.trustrelay_emit_org_event_v09(
    p_org_id,v_event,
    jsonb_build_object('accountId',p_account_id,'role',v_target.role,'status','active')
  );

  return jsonb_build_object('ok',true,'accountId',p_account_id,'status','active');
end;
$$;

create or replace function private.trustrelay_manage_org_member_v09(
  p_uid uuid,p_org_id text,p_member_account_id text,p_action text,
  p_role text default null,p_title text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_actor_id text;
  v_actor_role text;
  v_target public.organization_members%rowtype;
  v_old_role text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_event_type text;
  v_event_id text:='evt_'||replace(gen_random_uuid()::text,'-','');
  v_payload text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(
    p_uid,p_org_id,
    case when p_action='role' then 'roles.manage' else 'members.manage' end
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  v_actor_id:=v_ctx->>'accountId';
  v_actor_role:=v_ctx->>'role';

  select * into v_target
  from public.organization_members
  where organization_id=p_org_id and account_id=p_member_account_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_MEMBER_NOT_FOUND');
  end if;

  if v_target.role='owner' then
    return jsonb_build_object('ok',false,'status',409,'code','OWNER_REQUIRES_TRANSFER');
  end if;

  if v_actor_role='admin' and v_target.role='admin' then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
  end if;

  if p_action='role' then
    if p_role not in ('admin','compliance','verifier','developer','auditor') then
      return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_ROLE_INVALID');
    end if;
    if v_actor_role='admin' and p_role='admin' then
      return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED');
    end if;

    v_old_role:=v_target.role;
    if v_old_role=p_role then
      return jsonb_build_object(
        'ok',true,'unchanged',true,
        'member',jsonb_build_object(
          'accountId',v_target.account_id,'role',v_target.role,'status',v_target.status
        )
      );
    end if;

    update public.organization_members
    set role=p_role,
        title=coalesce(nullif(left(btrim(coalesce(p_title,'')),120),''),title),
        role_changed_at=v_now,
        role_changed_by_account_id=v_actor_id,
        updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.role_changed';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'info',
      'Organization role updated',
      'Your TrustRelay organization role changed from '||v_old_role||' to '||p_role||'.',
      'organization',p_org_id,
      jsonb_build_object('fromRole',v_old_role,'toRole',p_role)
    );

  elsif p_action='disable' then
    if v_target.status<>'active' then
      return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_NOT_ACTIVE');
    end if;

    update public.organization_members
    set status='disabled',disabled_at=v_now,disabled_by_account_id=v_actor_id,updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.disabled';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'warning',
      'Organization access disabled',
      'Your TrustRelay organization access was disabled.',
      'organization',p_org_id,jsonb_build_object('role',v_target.role)
    );

  elsif p_action='enable' then
    if v_target.status<>'disabled' then
      return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_MEMBER_NOT_DISABLED');
    end if;

    update public.organization_members
    set status='active',
        disabled_at=null,
        disabled_by_account_id=null,
        removed_at=null,
        removed_by_account_id=null,
        updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.restored';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'success',
      'Organization access restored',
      'Your TrustRelay organization access was restored.',
      'organization',p_org_id,jsonb_build_object('role',v_target.role)
    );

  elsif p_action='remove' then
    if v_target.status='removed' then
      return jsonb_build_object(
        'ok',true,'unchanged',true,
        'member',jsonb_build_object(
          'accountId',v_target.account_id,'role',v_target.role,'status',v_target.status
        )
      );
    end if;

    update public.organization_members
    set status='removed',removed_at=v_now,removed_by_account_id=v_actor_id,updated_at=v_now
    where organization_id=p_org_id and account_id=p_member_account_id
    returning * into v_target;

    v_event_type:='organization.member.removed';

    perform private.trustrelay_notify_account_v09(
      p_member_account_id,p_org_id,'organization',v_event_type,'warning',
      'Removed from organization',
      'Your TrustRelay organization membership was removed.',
      'organization',p_org_id,jsonb_build_object('role',v_target.role)
    );

  else
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_MEMBER_ACTION_INVALID');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_actor_id,v_event_type,'organization_member',p_member_account_id,
    jsonb_build_object(
      'role',v_target.role,'status',v_target.status,
      'previousRole',v_old_role,'title',v_target.title
    )
  );

  v_payload:=jsonb_build_object(
    'id',v_event_id,'type',v_event_type,'createdAt',v_now,'organizationId',p_org_id,
    'data',jsonb_build_object(
      'accountId',p_member_account_id,'role',v_target.role,
      'status',v_target.status,'previousRole',v_old_role
    )
  )::text;

  perform public.trustrelay_queue_webhooks_v07(
    p_org_id,v_event_type,v_event_id,v_payload
  );
  perform public.trustrelay_dispatch_due_webhooks_v09(25);

  return jsonb_build_object(
    'ok',true,
    'member',jsonb_build_object(
      'accountId',v_target.account_id,'role',v_target.role,
      'status',v_target.status,'title',v_target.title,'updatedAt',v_target.updated_at
    )
  );
end;
$$;

-- ============================================================
-- 20261001210239 trustrelay_v09_webhook_catalog_final
-- ============================================================
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
    "identity.assurance.changed",
    "organization.member.invited",
    "organization.member.joined",
    "organization.member.role_changed",
    "organization.member.disabled",
    "organization.member.restored",
    "organization.member.removed",
    "organization.ownership.transferred",
    "compliance.export.ready",
    "webhook.test"
  ]'::jsonb;
$$;

-- ============================================================
-- 20261001210803 trustrelay_v09_assurance_event_dedup
-- ============================================================
drop trigger if exists trg_trustrelay_assurance_events_v09 on public.persons;
drop function if exists private.trustrelay_assurance_event_trigger_v09();

