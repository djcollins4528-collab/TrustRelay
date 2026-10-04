-- TrustRelay v1.5 — SCIM Group Push + enterprise role mapping.
-- Adds SCIM /Groups persistence, group membership sync, safe role mapping,
-- drift reconciliation, audit events, and admin controls.
-- Owner/Admin and manually managed memberships remain outside SCIM control.

create table if not exists public.organization_scim_groups(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  external_id text,
  display_name text not null,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organization_scim_groups_display_name_check
    check(length(btrim(display_name)) between 1 and 160),
  constraint organization_scim_groups_external_id_check
    check(external_id is null or length(external_id) between 1 and 512)
);

create unique index if not exists organization_scim_groups_org_display_name_uq
  on public.organization_scim_groups(organization_id,lower(display_name));
create unique index if not exists organization_scim_groups_org_external_id_uq
  on public.organization_scim_groups(organization_id,external_id)
  where external_id is not null;
create index if not exists organization_scim_groups_org_idx
  on public.organization_scim_groups(organization_id);

create table if not exists public.organization_scim_group_members(
  organization_id text not null references public.organizations(id) on delete cascade,
  group_id text not null references public.organization_scim_groups(id) on delete cascade,
  user_id text not null references public.organization_scim_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(group_id,user_id)
);
create index if not exists organization_scim_group_members_org_idx
  on public.organization_scim_group_members(organization_id);
create index if not exists organization_scim_group_members_user_idx
  on public.organization_scim_group_members(user_id);

create table if not exists public.organization_scim_group_mappings(
  id text primary key,
  organization_id text not null references public.organizations(id) on delete cascade,
  group_id text not null references public.organization_scim_groups(id) on delete cascade,
  role text not null,
  priority integer not null default 100,
  enabled boolean not null default true,
  created_by_account_id text references public.accounts(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organization_scim_group_mappings_role_check
    check(role in ('compliance','verifier','developer','auditor')),
  constraint organization_scim_group_mappings_priority_check
    check(priority between 1 and 1000),
  unique(organization_id,group_id)
);
create index if not exists organization_scim_group_mappings_org_idx
  on public.organization_scim_group_mappings(organization_id);
create index if not exists organization_scim_group_mappings_group_idx
  on public.organization_scim_group_mappings(group_id);
create index if not exists organization_scim_group_mappings_created_by_idx
  on public.organization_scim_group_mappings(created_by_account_id);

alter table public.organization_scim_groups enable row level security;
alter table public.organization_scim_group_members enable row level security;
alter table public.organization_scim_group_mappings enable row level security;

revoke all on public.organization_scim_groups from anon,authenticated;
revoke all on public.organization_scim_group_members from anon,authenticated;
revoke all on public.organization_scim_group_mappings from anon,authenticated;

drop policy if exists organization_scim_groups_deny_direct on public.organization_scim_groups;
create policy organization_scim_groups_deny_direct
  on public.organization_scim_groups for all to authenticated
  using(false) with check(false);

drop policy if exists organization_scim_group_members_deny_direct on public.organization_scim_group_members;
create policy organization_scim_group_members_deny_direct
  on public.organization_scim_group_members for all to authenticated
  using(false) with check(false);

drop policy if exists organization_scim_group_mappings_deny_direct on public.organization_scim_group_mappings;
create policy organization_scim_group_mappings_deny_direct
  on public.organization_scim_group_mappings for all to authenticated
  using(false) with check(false);

create or replace function private.trustrelay_scim_effective_role_v15(
  p_org_id text,p_user_id text
)
returns text
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cfg public.organization_scim_configs%rowtype;
  v_role text;
begin
  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id;

  if not found then return null; end if;

  if v_cfg.group_sync_enabled then
    select m.role into v_role
    from public.organization_scim_group_members gm
    join public.organization_scim_group_mappings m
      on m.organization_id=gm.organization_id
     and m.group_id=gm.group_id
     and m.enabled=true
    where gm.organization_id=p_org_id
      and gm.user_id=p_user_id
    order by m.priority asc,m.created_at asc,m.id asc
    limit 1;
  end if;

  v_role:=coalesce(v_role,v_cfg.default_role);
  if v_role not in ('compliance','verifier','developer','auditor') then
    return null;
  end if;
  return v_role;
end;
$function$;

create or replace function private.trustrelay_scim_reconcile_user_role_v15(
  p_org_id text,p_user_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_user public.organization_scim_users%rowtype;
  v_member public.organization_members%rowtype;
  v_role text;
  v_old_role text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into v_user
  from public.organization_scim_users
  where organization_id=p_org_id and id=p_user_id;
  if not found then
    return jsonb_build_object('ok',true,'changed',false,'reason','user_not_found');
  end if;

  select * into v_member
  from public.organization_members
  where organization_id=p_org_id and account_id=v_user.account_id
  for update;
  if not found then
    return jsonb_build_object('ok',true,'changed',false,'reason','membership_not_found');
  end if;

  if v_member.role in ('owner','admin') then
    return jsonb_build_object('ok',true,'changed',false,'reason','privileged_protected');
  end if;
  if coalesce(v_member.provisioning_source,'manual')<>'scim'
     or coalesce(v_member.provisioning_ref,'')<>p_user_id then
    return jsonb_build_object('ok',true,'changed',false,'reason','manual_protected');
  end if;

  v_role:=private.trustrelay_scim_effective_role_v15(p_org_id,p_user_id);
  if v_role is null then
    return jsonb_build_object('ok',false,'status',500,'code','SCIM_EFFECTIVE_ROLE_INVALID');
  end if;
  v_old_role:=v_member.role;

  if v_old_role is distinct from v_role then
    update public.organization_members
    set role=v_role,
        role_changed_at=v_now,
        role_changed_by_account_id=null,
        updated_at=v_now
    where organization_id=p_org_id and account_id=v_user.account_id;

    perform private.trustrelay_append_org_audit_v09(
      p_org_id,null,'organization.scim.role_reconciled',
      'organization_member',v_user.account_id,
      jsonb_build_object(
        'scimUserId',p_user_id,
        'oldRole',v_old_role,
        'newRole',v_role,
        'source','scim_group_mapping'
      )
    );
    return jsonb_build_object('ok',true,'changed',true,'oldRole',v_old_role,'role',v_role);
  end if;

  return jsonb_build_object('ok',true,'changed',false,'role',v_role);
end;
$function$;

create or replace function private.trustrelay_scim_reconcile_all_roles_v15(
  p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v record;
  v_result jsonb;
  v_changed integer:=0;
begin
  for v in
    select id from public.organization_scim_users
    where organization_id=p_org_id
  loop
    v_result:=private.trustrelay_scim_reconcile_user_role_v15(p_org_id,v.id);
    if coalesce((v_result->>'changed')::boolean,false) then
      v_changed:=v_changed+1;
    end if;
  end loop;
  return jsonb_build_object('ok',true,'changed',v_changed);
end;
$function$;

create or replace function private.trustrelay_scim_get_group_core_v15(
  p_org_id text,p_group_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_group public.organization_scim_groups%rowtype;
  v_members jsonb:='[]'::jsonb;
begin
  select * into v_group
  from public.organization_scim_groups
  where organization_id=p_org_id and id=p_group_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_GROUP_NOT_FOUND');
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'value',u.id,'display',u.user_name
  ) order by u.user_name,u.id),'[]'::jsonb)
  into v_members
  from public.organization_scim_group_members gm
  join public.organization_scim_users u
    on u.organization_id=gm.organization_id and u.id=gm.user_id
  where gm.organization_id=p_org_id and gm.group_id=p_group_id;

  return jsonb_build_object(
    'ok',true,
    'group',jsonb_build_object(
      'id',v_group.id,
      'organizationId',v_group.organization_id,
      'externalId',v_group.external_id,
      'displayName',v_group.display_name,
      'version',v_group.version,
      'createdAt',v_group.created_at,
      'updatedAt',v_group.updated_at,
      'members',v_members
    )
  );
end;
$function$;

create or replace function public.trustrelay_scim_get_group_v15(
  p_org_id text,p_group_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_get_group_core_v15(p_org_id,p_group_id);
$function$;

create or replace function private.trustrelay_scim_list_groups_core_v15(
  p_org_id text,p_filter_attribute text,p_filter_value text,
  p_start_index integer,p_count integer
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_start integer:=greatest(1,coalesce(p_start_index,1));
  v_count integer:=greatest(1,least(100,coalesce(p_count,100)));
  v_total bigint:=0;
  v_groups jsonb:='[]'::jsonb;
begin
  if p_filter_attribute is not null
     and p_filter_attribute not in ('id','displayName','externalId') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_FILTER_UNSUPPORTED');
  end if;

  select count(*) into v_total
  from public.organization_scim_groups g
  where g.organization_id=p_org_id
    and (
      p_filter_attribute is null
      or (p_filter_attribute='id' and g.id=p_filter_value)
      or (p_filter_attribute='displayName' and lower(g.display_name)=lower(p_filter_value))
      or (p_filter_attribute='externalId' and g.external_id=p_filter_value)
    );

  select coalesce(jsonb_agg(x.obj order by x.display_name,x.id),'[]'::jsonb)
  into v_groups
  from (
    select g.id,g.display_name,
      jsonb_build_object(
        'id',g.id,
        'organizationId',g.organization_id,
        'externalId',g.external_id,
        'displayName',g.display_name,
        'version',g.version,
        'createdAt',g.created_at,
        'updatedAt',g.updated_at,
        'members',coalesce((
          select jsonb_agg(jsonb_build_object(
            'value',u.id,'display',u.user_name
          ) order by u.user_name,u.id)
          from public.organization_scim_group_members gm
          join public.organization_scim_users u
            on u.organization_id=gm.organization_id and u.id=gm.user_id
          where gm.organization_id=p_org_id and gm.group_id=g.id
        ),'[]'::jsonb)
      ) as obj
    from public.organization_scim_groups g
    where g.organization_id=p_org_id
      and (
        p_filter_attribute is null
        or (p_filter_attribute='id' and g.id=p_filter_value)
        or (p_filter_attribute='displayName' and lower(g.display_name)=lower(p_filter_value))
        or (p_filter_attribute='externalId' and g.external_id=p_filter_value)
      )
    order by g.display_name,g.id
    offset v_start-1
    limit v_count
  ) x;

  return jsonb_build_object(
    'ok',true,
    'totalResults',v_total,
    'startIndex',v_start,
    'groups',v_groups
  );
end;
$function$;

create or replace function public.trustrelay_scim_list_groups_v15(
  p_org_id text,p_filter_attribute text,p_filter_value text,
  p_start_index integer,p_count integer
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_list_groups_core_v15(
    p_org_id,p_filter_attribute,p_filter_value,p_start_index,p_count
  );
$function$;

create or replace function private.trustrelay_scim_upsert_group_core_v15(
  p_org_id text,p_group_id text,p_external_id text,p_display_name text,p_member_ids text[]
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $function$
declare
  v_cfg public.organization_scim_configs%rowtype;
  v_group public.organization_scim_groups%rowtype;
  v_id text;
  v_created boolean:=false;
  v_members text[];
  v_old_members text[];
  v_affected text[];
  v_user_id text;
  v_unknown integer:=0;
  v_now timestamptz:=clock_timestamp();
begin
  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id and status='active';
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_NOT_ACTIVE');
  end if;
  if not v_cfg.group_sync_enabled then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_GROUP_SYNC_DISABLED');
  end if;

  if length(btrim(coalesce(p_display_name,'')))<1
     or length(btrim(coalesce(p_display_name,'')))>160 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_GROUP_DISPLAY_NAME_INVALID');
  end if;
  if nullif(btrim(coalesce(p_external_id,'')),'') is not null
     and length(btrim(p_external_id))>512 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_EXTERNAL_ID_INVALID');
  end if;

  select coalesce(array_agg(distinct x),array[]::text[]) into v_members
  from unnest(coalesce(p_member_ids,array[]::text[])) x
  where nullif(btrim(x),'') is not null;

  if cardinality(v_members)>1000 then
    return jsonb_build_object('ok',false,'status',413,'code','SCIM_GROUP_MEMBER_LIMIT');
  end if;

  select count(*) into v_unknown
  from unnest(v_members) x
  left join public.organization_scim_users u
    on u.organization_id=p_org_id and u.id=x
  where u.id is null;
  if v_unknown>0 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_GROUP_MEMBER_NOT_FOUND');
  end if;

  if nullif(btrim(coalesce(p_group_id,'')),'') is null then
    v_id:='scimgrp_'||replace(gen_random_uuid()::text,'-','');
    v_created:=true;
    insert into public.organization_scim_groups(
      id,organization_id,external_id,display_name,version,created_at,updated_at
    ) values(
      v_id,p_org_id,nullif(btrim(coalesce(p_external_id,'')),''),
      btrim(p_display_name),1,v_now,v_now
    )
    returning * into v_group;
    v_old_members:=array[]::text[];
  else
    v_id:=p_group_id;
    select * into v_group
    from public.organization_scim_groups
    where organization_id=p_org_id and id=v_id
    for update;
    if not found then
      return jsonb_build_object('ok',false,'status',404,'code','SCIM_GROUP_NOT_FOUND');
    end if;

    select coalesce(array_agg(user_id),array[]::text[]) into v_old_members
    from public.organization_scim_group_members
    where organization_id=p_org_id and group_id=v_id;

    update public.organization_scim_groups
    set external_id=nullif(btrim(coalesce(p_external_id,'')),''),
        display_name=btrim(p_display_name),
        version=version+1,
        updated_at=v_now
    where organization_id=p_org_id and id=v_id
    returning * into v_group;
  end if;

  delete from public.organization_scim_group_members
  where organization_id=p_org_id and group_id=v_id;

  insert into public.organization_scim_group_members(
    organization_id,group_id,user_id,created_at
  )
  select p_org_id,v_id,x,v_now from unnest(v_members) x;

  select coalesce(array_agg(distinct x),array[]::text[]) into v_affected
  from unnest(coalesce(v_old_members,array[]::text[])||coalesce(v_members,array[]::text[])) x;

  foreach v_user_id in array v_affected loop
    perform private.trustrelay_scim_reconcile_user_role_v15(p_org_id,v_user_id);
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,
    case when v_created then 'organization.scim.group_created'
         else 'organization.scim.group_updated' end,
    'scim_group',v_id,
    jsonb_build_object(
      'displayName',v_group.display_name,
      'externalId',v_group.external_id,
      'memberCount',cardinality(v_members)
    )
  );

  return private.trustrelay_scim_get_group_core_v15(p_org_id,v_id);
exception
  when unique_violation then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_GROUP_UNIQUENESS_CONFLICT');
end;
$function$;

create or replace function public.trustrelay_scim_upsert_group_v15(
  p_org_id text,p_group_id text,p_external_id text,p_display_name text,p_member_ids text[]
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_upsert_group_core_v15(
    p_org_id,p_group_id,p_external_id,p_display_name,p_member_ids
  );
$function$;

create or replace function private.trustrelay_scim_delete_group_core_v15(
  p_org_id text,p_group_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_group public.organization_scim_groups%rowtype;
  v_members text[];
  v_user_id text;
begin
  select * into v_group
  from public.organization_scim_groups
  where organization_id=p_org_id and id=p_group_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_GROUP_NOT_FOUND');
  end if;

  select coalesce(array_agg(user_id),array[]::text[]) into v_members
  from public.organization_scim_group_members
  where organization_id=p_org_id and group_id=p_group_id;

  delete from public.organization_scim_groups
  where organization_id=p_org_id and id=p_group_id;

  foreach v_user_id in array v_members loop
    perform private.trustrelay_scim_reconcile_user_role_v15(p_org_id,v_user_id);
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,null,'organization.scim.group_deleted',
    'scim_group',p_group_id,
    jsonb_build_object(
      'displayName',v_group.display_name,
      'externalId',v_group.external_id,
      'memberCount',cardinality(v_members)
    )
  );

  return jsonb_build_object('ok',true,'id',p_group_id);
end;
$function$;

create or replace function public.trustrelay_scim_delete_group_v15(
  p_org_id text,p_group_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_delete_group_core_v15(p_org_id,p_group_id);
$function$;

create or replace function private.trustrelay_scim_group_mapping_set_core_v15(
  p_org_id text,p_actor_account_id text,p_group_id text,p_role text,
  p_priority integer,p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $function$
declare
  v_id text;
  v_user record;
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;
  if p_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_GROUP_ROLE_INVALID');
  end if;
  if coalesce(p_priority,100) not between 1 and 1000 then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_GROUP_PRIORITY_INVALID');
  end if;
  if not exists(
    select 1 from public.organization_scim_groups
    where organization_id=p_org_id and id=p_group_id
  ) then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_GROUP_NOT_FOUND');
  end if;

  select id into v_id
  from public.organization_scim_group_mappings
  where organization_id=p_org_id and group_id=p_group_id;
  if v_id is null then
    v_id:='scimmap_'||replace(gen_random_uuid()::text,'-','');
  end if;

  insert into public.organization_scim_group_mappings(
    id,organization_id,group_id,role,priority,enabled,
    created_by_account_id,created_at,updated_at
  ) values(
    v_id,p_org_id,p_group_id,p_role,coalesce(p_priority,100),
    coalesce(p_enabled,true),p_actor_account_id,now(),now()
  )
  on conflict(organization_id,group_id) do update set
    role=excluded.role,
    priority=excluded.priority,
    enabled=excluded.enabled,
    updated_at=now()
  returning id into v_id;

  for v_user in
    select user_id from public.organization_scim_group_members
    where organization_id=p_org_id and group_id=p_group_id
  loop
    perform private.trustrelay_scim_reconcile_user_role_v15(p_org_id,v_user.user_id);
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.group_mapping_set',
    'scim_group',p_group_id,
    jsonb_build_object(
      'mappingId',v_id,'role',p_role,
      'priority',coalesce(p_priority,100),'enabled',coalesce(p_enabled,true)
    )
  );

  return jsonb_build_object(
    'ok',true,'mappingId',v_id,'groupId',p_group_id,
    'role',p_role,'priority',coalesce(p_priority,100),
    'enabled',coalesce(p_enabled,true)
  );
end;
$function$;

create or replace function public.trustrelay_scim_group_mapping_set_v15(
  p_org_id text,p_actor_account_id text,p_group_id text,p_role text,
  p_priority integer,p_enabled boolean
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_group_mapping_set_core_v15(
    p_org_id,p_actor_account_id,p_group_id,p_role,p_priority,p_enabled
  );
$function$;

create or replace function private.trustrelay_scim_group_mapping_delete_core_v15(
  p_org_id text,p_actor_account_id text,p_group_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_mapping public.organization_scim_group_mappings%rowtype;
  v_user record;
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  select * into v_mapping
  from public.organization_scim_group_mappings
  where organization_id=p_org_id and group_id=p_group_id
  for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_GROUP_MAPPING_NOT_FOUND');
  end if;

  delete from public.organization_scim_group_mappings
  where organization_id=p_org_id and group_id=p_group_id;

  for v_user in
    select user_id from public.organization_scim_group_members
    where organization_id=p_org_id and group_id=p_group_id
  loop
    perform private.trustrelay_scim_reconcile_user_role_v15(p_org_id,v_user.user_id);
  end loop;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.group_mapping_deleted',
    'scim_group',p_group_id,
    jsonb_build_object('oldRole',v_mapping.role,'mappingId',v_mapping.id)
  );

  return jsonb_build_object('ok',true,'groupId',p_group_id);
end;
$function$;

create or replace function public.trustrelay_scim_group_mapping_delete_v15(
  p_org_id text,p_actor_account_id text,p_group_id text
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_group_mapping_delete_core_v15(
    p_org_id,p_actor_account_id,p_group_id
  );
$function$;

create or replace function private.trustrelay_scim_set_group_sync_core_v15(
  p_org_id text,p_actor_account_id text,p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  update public.organization_scim_configs
  set group_sync_enabled=coalesce(p_enabled,false),
      updated_at=now(),
      last_error=null
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_scim_reconcile_all_roles_v15(p_org_id);

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.group_sync_changed',
    'organization',p_org_id,
    jsonb_build_object('enabled',coalesce(p_enabled,false))
  );

  return jsonb_build_object('ok',true,'groupSyncEnabled',coalesce(p_enabled,false));
end;
$function$;

create or replace function public.trustrelay_scim_set_group_sync_v15(
  p_org_id text,p_actor_account_id text,p_enabled boolean
)
returns jsonb
language sql
security definer
set search_path to 'private','pg_catalog'
as $function$
  select private.trustrelay_scim_set_group_sync_core_v15(
    p_org_id,p_actor_account_id,p_enabled
  );
$function$;

create or replace function private.trustrelay_scim_admin_status_core_v15(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_base jsonb;
  v_cfg public.organization_scim_configs%rowtype;
  v_groups jsonb:='[]'::jsonb;
  v_group_count bigint:=0;
  v_mapped_count bigint:=0;
begin
  v_base:=private.trustrelay_scim_admin_status_core_v14(p_uid,p_org_id);
  if coalesce((v_base->>'ok')::boolean,false)=false then return v_base; end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=p_org_id;

  if not found then
    return v_base
      || jsonb_build_object('groups','[]'::jsonb,'mappings','[]'::jsonb);
  end if;

  select count(*) into v_group_count
  from public.organization_scim_groups where organization_id=p_org_id;
  select count(*) into v_mapped_count
  from public.organization_scim_group_mappings
  where organization_id=p_org_id and enabled=true;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id',g.id,
    'externalId',g.external_id,
    'displayName',g.display_name,
    'version',g.version,
    'memberCount',(
      select count(*) from public.organization_scim_group_members gm
      where gm.organization_id=p_org_id and gm.group_id=g.id
    ),
    'mappingId',m.id,
    'mappedRole',m.role,
    'mappingPriority',m.priority,
    'mappingEnabled',m.enabled,
    'createdAt',g.created_at,
    'updatedAt',g.updated_at
  ) order by g.display_name,g.id),'[]'::jsonb)
  into v_groups
  from public.organization_scim_groups g
  left join public.organization_scim_group_mappings m
    on m.organization_id=g.organization_id and m.group_id=g.id
  where g.organization_id=p_org_id;

  v_base:=jsonb_set(v_base,'{config,groupSyncEnabled}',to_jsonb(v_cfg.group_sync_enabled),true);
  v_base:=jsonb_set(v_base,'{counts,groups}',to_jsonb(v_group_count),true);
  v_base:=jsonb_set(v_base,'{counts,mappedGroups}',to_jsonb(v_mapped_count),true);

  return v_base || jsonb_build_object('groups',v_groups);
end;
$function$;

create or replace function public.trustrelay_scim_admin_status_v15(p_org_id text)
returns jsonb
language sql
security invoker
set search_path to 'private','auth','pg_catalog'
as $function$
  select private.trustrelay_scim_admin_status_core_v15(auth.uid(),p_org_id);
$function$;

-- Allow v1.4 policy calls to preserve/enable Group Push now that v1.5 exists.
create or replace function private.trustrelay_scim_set_policy_core_v14(
  p_org_id text,p_actor_account_id text,p_default_role text,
  p_allow_static_bearer boolean,p_group_sync_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;
  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if coalesce(p_allow_static_bearer,true)=false then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_BEARER_AUTH_REQUIRED');
  end if;

  update public.organization_scim_configs
  set default_role=p_default_role,
      allow_static_bearer=true,
      group_sync_enabled=coalesce(p_group_sync_enabled,group_sync_enabled),
      updated_at=now()
  where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SCIM_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_scim_reconcile_all_roles_v15(p_org_id);

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.policy_changed','organization',p_org_id,
    jsonb_build_object(
      'defaultRole',p_default_role,
      'authMode','bearer',
      'groupSyncEnabled',coalesce(p_group_sync_enabled,false)
    )
  );
  return jsonb_build_object(
    'ok',true,'defaultRole',p_default_role,'allowStaticBearer',true,
    'groupSyncEnabled',coalesce(p_group_sync_enabled,false)
  );
end;
$function$;

-- Preserve Group Push when a credential is rotated/reissued.
create or replace function private.trustrelay_scim_store_credential_core_v14(
  p_org_id text,p_actor_account_id text,p_client_id text,p_secret_hash text,
  p_secret_last_four text,p_label text,p_default_role text,p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','extensions','pg_catalog'
as $function$
declare
  v_sso public.organization_sso_configs%rowtype;
  v_id text:='scimcred_'||replace(gen_random_uuid()::text,'-','');
  v_active_count integer:=0;
  v_tenant text;
begin
  if not exists(
    select 1 from public.organization_members
    where organization_id=p_org_id and account_id=p_actor_account_id
      and status='active' and role in ('owner','admin')
  ) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ADMIN_REQUIRED');
  end if;

  select * into v_sso
  from public.organization_sso_configs
  where organization_id=p_org_id and status='active'
    and provider_kind in ('entra','okta')
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_ACTIVE_SSO');
  end if;

  if not exists(
    select 1 from public.organization_sso_domains
    where organization_id=p_org_id and verification_status='verified'
  ) then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_REQUIRES_VERIFIED_DOMAIN');
  end if;

  if p_default_role not in ('compliance','verifier','developer','auditor') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_DEFAULT_ROLE_INVALID');
  end if;
  if p_client_id !~ '^tr_scim_[a-z0-9]{24,80}$'
     or p_secret_hash !~ '^[0-9a-f]{64}$'
     or p_secret_last_four !~ '^[A-Za-z0-9_-]{4}$' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_INVALID');
  end if;
  if p_expires_at<=clock_timestamp()+interval '7 days'
     or p_expires_at>clock_timestamp()+interval '3 years 1 day' then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_CREDENTIAL_EXPIRY_INVALID');
  end if;

  select count(*) into v_active_count
  from public.organization_scim_credentials
  where organization_id=p_org_id and status='active'
    and expires_at>clock_timestamp();
  if v_active_count>=2 then
    return jsonb_build_object('ok',false,'status',409,'code','SCIM_ACTIVE_CREDENTIAL_LIMIT');
  end if;

  select tenant_key into v_tenant
  from public.organization_scim_configs
  where organization_id=p_org_id;
  if v_tenant is null then
    v_tenant:='scim_'||replace(gen_random_uuid()::text,'-','');
  end if;

  insert into public.organization_scim_configs(
    organization_id,tenant_key,provider_kind,status,default_role,
    allow_static_bearer,group_sync_enabled,created_by_account_id,
    created_at,updated_at,disabled_at
  ) values(
    p_org_id,v_tenant,v_sso.provider_kind,'active',p_default_role,
    true,false,p_actor_account_id,now(),now(),null
  )
  on conflict(organization_id) do update set
    tenant_key=coalesce(public.organization_scim_configs.tenant_key,excluded.tenant_key),
    provider_kind=excluded.provider_kind,
    status='active',
    default_role=excluded.default_role,
    allow_static_bearer=true,
    group_sync_enabled=public.organization_scim_configs.group_sync_enabled,
    updated_at=now(),
    disabled_at=null,
    last_error=null
  returning tenant_key into v_tenant;

  insert into public.organization_scim_credentials(
    id,organization_id,client_id,secret_hash,secret_last_four,label,status,
    expires_at,created_by_account_id,created_at
  ) values(
    v_id,p_org_id,p_client_id,p_secret_hash,p_secret_last_four,
    left(coalesce(nullif(btrim(p_label),''),'Primary'),80),
    'active',p_expires_at,p_actor_account_id,now()
  );

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,p_actor_account_id,'organization.scim.credential_created',
    'scim_credential',v_id,
    jsonb_build_object(
      'clientId',p_client_id,
      'label',left(coalesce(nullif(btrim(p_label),''),'Primary'),80),
      'expiresAt',p_expires_at,
      'providerKind',v_sso.provider_kind,
      'defaultRole',p_default_role
    )
  );

  return jsonb_build_object(
    'ok',true,'credentialId',v_id,'clientId',p_client_id,
    'secretLastFour',p_secret_last_four,'tenantKey',v_tenant,
    'expiresAt',p_expires_at,'providerKind',v_sso.provider_kind
  );
end;
$function$;

-- Return the real Group Push state in bearer authentication context.
create or replace function private.trustrelay_scim_resolve_bearer_core_v14(p_token_hash text)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_cred public.organization_scim_credentials%rowtype;
  v_cfg public.organization_scim_configs%rowtype;
  v_bucket timestamptz:=date_trunc('minute',clock_timestamp());
  v_count integer;
  v_retry integer;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select c.* into v_cred
  from public.organization_scim_credentials c
  join public.organization_scim_configs cfg on cfg.organization_id=c.organization_id
  where c.secret_hash=p_token_hash
    and c.status='active'
    and c.expires_at>clock_timestamp()
    and cfg.status='active'
    and cfg.allow_static_bearer=true
  limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','INVALID_BEARER_TOKEN');
  end if;

  select * into v_cfg
  from public.organization_scim_configs
  where organization_id=v_cred.organization_id and status='active';

  insert into private.trustrelay_scim_rate_buckets_v14(
    credential_id,bucket_start,request_count
  ) values(v_cred.id,v_bucket,1)
  on conflict(credential_id,bucket_start)
  do update set request_count=private.trustrelay_scim_rate_buckets_v14.request_count+1
  returning request_count into v_count;

  if v_count>v_cfg.rate_limit_per_minute then
    v_retry:=greatest(
      1,
      ceil(extract(epoch from (v_bucket+interval '1 minute'-clock_timestamp())))::integer
    );
    update public.organization_scim_configs
    set last_error='SCIM_RATE_LIMITED',updated_at=clock_timestamp()
    where organization_id=v_cfg.organization_id;
    return jsonb_build_object(
      'ok',false,'status',429,'code','SCIM_RATE_LIMITED','retryAfter',v_retry
    );
  end if;

  delete from private.trustrelay_scim_rate_buckets_v14
  where credential_id=v_cred.id and bucket_start<v_bucket-interval '10 minutes';

  update public.organization_scim_credentials
  set last_used_at=now()
  where id=v_cred.id;

  update public.organization_scim_configs
  set last_sync_at=now(),last_error=null,updated_at=now()
  where organization_id=v_cred.organization_id;

  return jsonb_build_object(
    'ok',true,
    'organizationId',v_cred.organization_id,
    'tenantKey',v_cfg.tenant_key,
    'credentialId',v_cred.id,
    'providerKind',v_cfg.provider_kind,
    'defaultRole',v_cfg.default_role,
    'rateLimitPerMinute',v_cfg.rate_limit_per_minute,
    'groupSyncEnabled',v_cfg.group_sync_enabled,
    'authMode','static_bearer'
  );
end;
$function$;

revoke all on function private.trustrelay_scim_effective_role_v15(text,text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_reconcile_user_role_v15(text,text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_reconcile_all_roles_v15(text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_get_group_core_v15(text,text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_list_groups_core_v15(text,text,text,integer,integer)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_upsert_group_core_v15(text,text,text,text,text[])
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_delete_group_core_v15(text,text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_group_mapping_set_core_v15(text,text,text,text,integer,boolean)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_group_mapping_delete_core_v15(text,text,text)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_set_group_sync_core_v15(text,text,boolean)
from public,anon,authenticated;
revoke all on function private.trustrelay_scim_admin_status_core_v15(uuid,text)
from public,anon;

revoke all on function public.trustrelay_scim_get_group_v15(text,text)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_list_groups_v15(text,text,text,integer,integer)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_upsert_group_v15(text,text,text,text,text[])
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_delete_group_v15(text,text)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_group_mapping_set_v15(text,text,text,text,integer,boolean)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_group_mapping_delete_v15(text,text,text)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_set_group_sync_v15(text,text,boolean)
from public,anon,authenticated;
revoke all on function public.trustrelay_scim_admin_status_v15(text)
from public,anon;

grant execute on function private.trustrelay_scim_effective_role_v15(text,text) to service_role;
grant execute on function private.trustrelay_scim_reconcile_user_role_v15(text,text) to service_role;
grant execute on function private.trustrelay_scim_reconcile_all_roles_v15(text) to service_role;
grant execute on function private.trustrelay_scim_get_group_core_v15(text,text) to service_role;
grant execute on function private.trustrelay_scim_list_groups_core_v15(text,text,text,integer,integer) to service_role;
grant execute on function private.trustrelay_scim_upsert_group_core_v15(text,text,text,text,text[]) to service_role;
grant execute on function private.trustrelay_scim_delete_group_core_v15(text,text) to service_role;
grant execute on function private.trustrelay_scim_group_mapping_set_core_v15(text,text,text,text,integer,boolean) to service_role;
grant execute on function private.trustrelay_scim_group_mapping_delete_core_v15(text,text,text) to service_role;
grant execute on function private.trustrelay_scim_set_group_sync_core_v15(text,text,boolean) to service_role;
grant execute on function private.trustrelay_scim_admin_status_core_v15(uuid,text) to authenticated,service_role;

grant execute on function public.trustrelay_scim_get_group_v15(text,text) to service_role;
grant execute on function public.trustrelay_scim_list_groups_v15(text,text,text,integer,integer) to service_role;
grant execute on function public.trustrelay_scim_upsert_group_v15(text,text,text,text,text[]) to service_role;
grant execute on function public.trustrelay_scim_delete_group_v15(text,text) to service_role;
grant execute on function public.trustrelay_scim_group_mapping_set_v15(text,text,text,text,integer,boolean) to service_role;
grant execute on function public.trustrelay_scim_group_mapping_delete_v15(text,text,text) to service_role;
grant execute on function public.trustrelay_scim_set_group_sync_v15(text,text,boolean) to service_role;
grant execute on function public.trustrelay_scim_admin_status_v15(text) to authenticated;
