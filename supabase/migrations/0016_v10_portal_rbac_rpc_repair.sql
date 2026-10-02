-- TrustRelay v1.0 portal RBAC/RPC reconciliation.
-- Repairs recorded v0.9/v1.0 function drift without exposing private tables.

create or replace function public.trustrelay_org_permissions_v09(p_role text)
returns jsonb
language sql
immutable
security invoker
set search_path=pg_catalog
as $$
  select case lower(coalesce(p_role,''))
    when 'owner' then jsonb_build_object(
      'organization.manage',true,'members.manage',true,'roles.manage',true,
      'api_keys.manage',true,'webhooks.manage',true,
      'decisions.read',true,'decisions.evaluate',true,
      'evidence.read',true,'evidence.request',true,'evidence.review',true,
      'audit.read',true,'audit.export',true
    )
    when 'admin' then jsonb_build_object(
      'organization.manage',true,'members.manage',true,'roles.manage',true,
      'api_keys.manage',true,'webhooks.manage',true,
      'decisions.read',true,'decisions.evaluate',true,
      'evidence.read',true,'evidence.request',true,'evidence.review',true,
      'audit.read',true,'audit.export',true
    )
    when 'compliance' then jsonb_build_object(
      'organization.manage',false,'members.manage',false,'roles.manage',false,
      'api_keys.manage',false,'webhooks.manage',false,
      'decisions.read',true,'decisions.evaluate',false,
      'evidence.read',true,'evidence.request',false,'evidence.review',true,
      'audit.read',true,'audit.export',true
    )
    when 'verifier' then jsonb_build_object(
      'organization.manage',false,'members.manage',false,'roles.manage',false,
      'api_keys.manage',false,'webhooks.manage',false,
      'decisions.read',true,'decisions.evaluate',true,
      'evidence.read',true,'evidence.request',true,'evidence.review',true,
      'audit.read',false,'audit.export',false
    )
    when 'developer' then jsonb_build_object(
      'organization.manage',false,'members.manage',false,'roles.manage',false,
      'api_keys.manage',true,'webhooks.manage',true,
      'decisions.read',true,'decisions.evaluate',false,
      'evidence.read',false,'evidence.request',false,'evidence.review',false,
      'audit.read',true,'audit.export',false
    )
    when 'auditor' then jsonb_build_object(
      'organization.manage',false,'members.manage',false,'roles.manage',false,
      'api_keys.manage',false,'webhooks.manage',false,
      'decisions.read',true,'decisions.evaluate',false,
      'evidence.read',true,'evidence.request',false,'evidence.review',false,
      'audit.read',true,'audit.export',true
    )
    else '{}'::jsonb
  end;
$$;

revoke all on function public.trustrelay_org_permissions_v09(text) from public,anon;
grant execute on function public.trustrelay_org_permissions_v09(text) to authenticated,service_role;

create or replace function private.trustrelay_require_permission_v09(
  p_uid uuid,p_org_id text,p_permission text
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_permissions jsonb;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    p_uid,p_org_id,array['owner','admin','compliance','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_permissions:=public.trustrelay_org_permissions_v09(v_ctx->>'role');
  if coalesce((v_permissions->>p_permission)::boolean,false)=false then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_PERMISSION_DENIED',
      'permission',p_permission,'role',v_ctx->>'role'
    );
  end if;
  return v_ctx || jsonb_build_object('permissions',v_permissions);
end;
$$;

revoke all on function private.trustrelay_require_permission_v09(uuid,text,text) from public,anon,authenticated;
grant execute on function private.trustrelay_require_permission_v09(uuid,text,text) to service_role;

create or replace function public.trustrelay_ensure_account_v06(
  p_auth_user_id uuid,p_display_name text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,auth,pg_catalog
as $$
declare
  v_email text;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_person_id text;
  v_account_id text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if auth.uid() is not null and p_auth_user_id is distinct from auth.uid() then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
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
  v_person_id:='person_'||replace(p_auth_user_id::text,'-','');
  v_account_id:='acct_'||replace(p_auth_user_id::text,'-','');
  insert into public.persons(id,display_name,email,identity_status,created_at)
  values(v_person_id,coalesce(nullif(btrim(p_display_name),''),split_part(v_email,'@',1)),v_email,'unverified',v_now)
  returning * into v_person;
  insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
  values(v_account_id,v_person_id,v_email,'active',v_now,p_auth_user_id)
  returning * into v_account;
  return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
end;
$$;

revoke all on function public.trustrelay_ensure_account_v06(uuid,text) from public,anon;
grant execute on function public.trustrelay_ensure_account_v06(uuid,text) to authenticated,service_role;

create or replace function public.trustrelay_notifications_v09(
  p_limit integer default 50,p_unread_only boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path=public,auth,pg_catalog
as $$
declare
  v_account_id text;
  v_limit integer:=greatest(1,least(coalesce(p_limit,50),100));
  v_preferences jsonb;
  v_notifications jsonb;
  v_unread bigint;
begin
  select id into v_account_id from public.accounts
  where auth_user_id=auth.uid() and status='active' limit 1;
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;
  select jsonb_build_object(
      'authority',true,'evidence',true,'identity',true,'organization',true,
      'webhook',true,'compliance',true,'security',true
    ) || coalesce(jsonb_object_agg(category,in_app),'{}'::jsonb)
  into v_preferences
  from public.notification_preferences where account_id=v_account_id;
  select count(*) into v_unread from public.notifications
  where account_id=v_account_id and status='unread';
  select coalesce(jsonb_agg(x.payload order by x.created_at desc),'[]'::jsonb)
  into v_notifications
  from (
    select n.created_at,jsonb_build_object(
      'id',n.id,'organizationId',n.organization_id,'category',n.category,
      'eventType',n.event_type,'severity',n.severity,'title',n.title,'body',n.body,
      'data',coalesce(n.data_json::jsonb,'{}'::jsonb),'status',n.status,
      'readAt',n.read_at,'archivedAt',n.archived_at,'createdAt',n.created_at
    ) payload
    from public.notifications n
    where n.account_id=v_account_id and n.status<>'archived'
      and (not coalesce(p_unread_only,false) or n.status='unread')
    order by n.created_at desc limit v_limit
  ) x;
  return jsonb_build_object(
    'ok',true,'unreadCount',v_unread,'preferences',v_preferences,'notifications',v_notifications
  );
end;
$$;

create or replace function public.trustrelay_mark_notification_v09(
  p_notification_id text,p_action text
)
returns jsonb
language plpgsql
security definer
set search_path=public,auth,pg_catalog
as $$
declare
  v_account_id text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_status text;
begin
  select id into v_account_id from public.accounts
  where auth_user_id=auth.uid() and status='active' limit 1;
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;
  if p_action='read' then
    update public.notifications
    set status='read',read_at=coalesce(read_at,v_now),updated_at=v_now
    where id=p_notification_id and account_id=v_account_id and status<>'archived'
    returning status into v_status;
  elsif p_action in ('dismiss','archive') then
    update public.notifications
    set status='archived',read_at=coalesce(read_at,v_now),archived_at=v_now,updated_at=v_now
    where id=p_notification_id and account_id=v_account_id
    returning status into v_status;
  else
    return jsonb_build_object('ok',false,'status',400,'code','NOTIFICATION_ACTION_INVALID');
  end if;
  if v_status is null then
    return jsonb_build_object('ok',false,'status',404,'code','NOTIFICATION_NOT_FOUND');
  end if;
  return jsonb_build_object('ok',true,'notificationId',p_notification_id,'status',v_status);
end;
$$;

create or replace function public.trustrelay_set_notification_preference_v09(
  p_category text,p_in_app boolean
)
returns jsonb
language plpgsql
security definer
set search_path=public,auth,pg_catalog
as $$
declare
  v_account_id text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_category not in ('authority','evidence','identity','organization','webhook','compliance','security') then
    return jsonb_build_object('ok',false,'status',400,'code','NOTIFICATION_CATEGORY_INVALID');
  end if;
  select id into v_account_id from public.accounts
  where auth_user_id=auth.uid() and status='active' limit 1;
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;
  insert into public.notification_preferences(account_id,category,in_app,created_at,updated_at)
  values(v_account_id,p_category,coalesce(p_in_app,true),v_now,v_now)
  on conflict(account_id,category)
  do update set in_app=excluded.in_app,updated_at=excluded.updated_at;
  return jsonb_build_object('ok',true,'category',p_category,'inApp',coalesce(p_in_app,true));
end;
$$;

revoke all on function public.trustrelay_notifications_v09(integer,boolean) from public,anon;
revoke all on function public.trustrelay_mark_notification_v09(text,text) from public,anon;
revoke all on function public.trustrelay_set_notification_preference_v09(text,boolean) from public,anon;
grant execute on function public.trustrelay_notifications_v09(integer,boolean) to authenticated,service_role;
grant execute on function public.trustrelay_mark_notification_v09(text,text) to authenticated,service_role;
grant execute on function public.trustrelay_set_notification_preference_v09(text,boolean) to authenticated,service_role;

grant execute on function private.trustrelay_org_onboarding_v10(uuid,text) to authenticated;
grant execute on function private.trustrelay_billing_status_v10(uuid,text) to authenticated;
grant execute on function private.trustrelay_select_billing_plan_v10(uuid,text,text) to authenticated;
grant execute on function private.trustrelay_update_org_onboarding_v10(uuid,text,text,text,text,text,text,text,text) to authenticated;
grant execute on function private.trustrelay_update_org_profile_v10(uuid,text,text,text,text) to authenticated;
grant execute on function private.trustrelay_request_production_activation_v10(uuid,text) to authenticated;
grant execute on function private.trustrelay_user_onboarding_v10(uuid) to authenticated;
grant execute on function private.trustrelay_accept_legal_v10(uuid,text,text,text,jsonb) to authenticated;
grant execute on function private.trustrelay_create_evidence_request_v08(uuid,text,text,jsonb,text) to authenticated;
grant execute on function private.trustrelay_attach_document_to_grant_v08(uuid,text,text) to authenticated;
grant execute on function private.trustrelay_attach_document_to_request_v08(uuid,text,text) to authenticated;
grant execute on function private.trustrelay_review_queue_v08(uuid) to authenticated;
grant execute on function private.trustrelay_submit_proofing_v08(uuid,text) to authenticated;

notify pgrst,'reload schema';
