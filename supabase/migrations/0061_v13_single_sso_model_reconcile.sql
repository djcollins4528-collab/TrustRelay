-- TrustRelay v1.3 single-model SSO reconciliation
-- Retains multi-auth identity binding, removes the duplicate staging SSO model,
-- and keeps organization_sso_configs / organization_sso_domains as canonical.

create table if not exists public.account_auth_bindings(
  auth_user_id uuid primary key references auth.users(id) on delete cascade,
  account_id text not null references public.accounts(id) on delete cascade,
  provider_protocol text not null default 'email'
    check(provider_protocol in ('email','oidc','saml','other')),
  provider_identifier text,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create index if not exists account_auth_bindings_account_idx
on public.account_auth_bindings(account_id);

insert into public.account_auth_bindings(
  auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
)
select auth_user_id,id,'email','email',now()
from public.accounts
where auth_user_id is not null
on conflict(auth_user_id) do nothing;

alter table public.account_auth_bindings enable row level security;
alter table public.account_auth_bindings force row level security;
revoke all on public.account_auth_bindings from public,anon,authenticated;

drop policy if exists account_auth_bindings_deny_all on public.account_auth_bindings;
create policy account_auth_bindings_deny_all
on public.account_auth_bindings
for all to anon,authenticated
using(false)
with check(false);

create or replace function private.trustrelay_account_id_for_uid_v13(p_uid uuid)
returns text
language sql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
  select coalesce(
    (
      select b.account_id
      from public.account_auth_bindings b
      join public.accounts a on a.id=b.account_id
      where b.auth_user_id=p_uid and a.status='active'
      limit 1
    ),
    (
      select a.id
      from public.accounts a
      where a.auth_user_id=p_uid and a.status='active'
      limit 1
    )
  );
$function$;

create or replace function private.trustrelay_session_sso_context_v13()
returns jsonb
language plpgsql
stable
set search_path to 'auth','pg_catalog'
as $function$
declare
  v_jwt jsonb:=auth.jwt();
  v_provider text:=coalesce(v_jwt#>>'{app_metadata,provider}','');
  v_saml_provider text;
begin
  select x->>'provider' into v_saml_provider
  from jsonb_array_elements(coalesce(v_jwt->'amr','[]'::jsonb)) x
  where x->>'method'='sso/saml'
  limit 1;

  if coalesce(v_saml_provider,'')<>'' then
    return jsonb_build_object(
      'isSso',true,'protocol','saml','providerIdentifier',v_saml_provider
    );
  end if;
  if v_provider like 'custom:%' then
    return jsonb_build_object(
      'isSso',true,'protocol','oidc','providerIdentifier',v_provider
    );
  end if;
  return jsonb_build_object(
    'isSso',false,'protocol',null,'providerIdentifier',v_provider
  );
end;
$function$;

create or replace function private.trustrelay_account_context_core_v10(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_guard jsonb;
  v_caller_uid uuid:=auth.uid();
  v_account_id text;
begin
  if v_caller_uid is not null and v_caller_uid=p_uid then
    v_guard:=private.trustrelay_session_guard_v10(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
  end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_account
  from public.accounts
  where id=v_account_id and status='active'
  limit 1;

  select * into v_person
  from public.persons
  where id=v_account.person_id;

  return jsonb_build_object(
    'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person)
  );
end;
$function$;

create or replace function private.trustrelay_require_org_role_core_v10(
  p_uid uuid,p_org_id text,p_roles text[]
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_account public.accounts%rowtype;
  v_org public.organizations%rowtype;
  v_member public.organization_members%rowtype;
  v_account_id text;
begin
  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select * into v_account
  from public.accounts
  where id=v_account_id and status='active';

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

  if p_roles is not null
     and array_length(p_roles,1) is not null
     and not (v_member.role=any(p_roles)) then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED','role',v_member.role
    );
  end if;

  return jsonb_build_object(
    'ok',true,'accountId',v_account.id,'role',v_member.role,
    'organization',to_jsonb(v_org)
  );
end;
$function$;

create or replace function private.trustrelay_ensure_account_v06(
  p_uid uuid,p_display_name text default null
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_email text;
  v_account public.accounts%rowtype;
  v_person public.persons%rowtype;
  v_person_id text;
  v_account_id text;
  v_bound_account_id text;
  v_sso jsonb;
  v_protocol text:='email';
  v_identifier text:='email';
  v_now text:=to_char(
    clock_timestamp() at time zone 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
begin
  if auth.uid() is not null and p_uid is distinct from auth.uid() then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;

  select lower(email) into v_email
  from auth.users
  where id=p_uid;
  if v_email is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_USER_NOT_FOUND');
  end if;

  v_bound_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_bound_account_id is not null then
    update public.account_auth_bindings
    set last_seen_at=now()
    where auth_user_id=p_uid;
    select * into v_account from public.accounts where id=v_bound_account_id;
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object(
      'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person)
    );
  end if;

  v_sso:=private.trustrelay_session_sso_context_v13();
  if coalesce((v_sso->>'isSso')::boolean,false) then
    v_protocol:=v_sso->>'protocol';
    v_identifier:=v_sso->>'providerIdentifier';
  end if;

  select * into v_account
  from public.accounts
  where lower(email)=v_email and status='active'
  limit 1;

  if found then
    -- Existing accounts may gain a second Auth identity only when the session
    -- came from an enterprise IdP. This prevents email-only account takeover.
    if coalesce((v_sso->>'isSso')::boolean,false)=false then
      return jsonb_build_object(
        'ok',false,'status',409,'code','ACCOUNT_EMAIL_ALREADY_BOUND'
      );
    end if;

    insert into public.account_auth_bindings(
      auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
    ) values(
      p_uid,v_account.id,v_protocol,v_identifier,now()
    )
    on conflict(auth_user_id) do update set
      account_id=excluded.account_id,
      provider_protocol=excluded.provider_protocol,
      provider_identifier=excluded.provider_identifier,
      last_seen_at=now();

    select * into v_person
    from public.persons
    where id=v_account.person_id;

    return jsonb_build_object(
      'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person),
      'identityAlias',true
    );
  end if;

  v_person_id:='person_'||replace(p_uid::text,'-','');
  v_account_id:='acct_'||replace(p_uid::text,'-','');

  insert into public.persons(
    id,display_name,email,identity_status,created_at
  ) values(
    v_person_id,
    coalesce(nullif(btrim(p_display_name),''),split_part(v_email,'@',1)),
    v_email,'unverified',v_now
  ) returning * into v_person;

  insert into public.accounts(
    id,person_id,email,status,created_at,auth_user_id
  ) values(
    v_account_id,v_person_id,v_email,'active',v_now,p_uid
  ) returning * into v_account;

  insert into public.account_auth_bindings(
    auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
  ) values(
    p_uid,v_account.id,v_protocol,v_identifier,now()
  )
  on conflict(auth_user_id) do nothing;

  return jsonb_build_object(
    'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person)
  );
end;
$function$;

create or replace function private.trustrelay_my_organizations_core_v10(p_uid uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $function$
declare
  v_account_id text;
begin
  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_account_id is null then
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
          ),
          'sso',case
            when s.organization_id is null then null
            else jsonb_build_object(
              'providerKind',s.provider_kind,
              'protocol',s.protocol,
              'status',s.status,
              'enforcementMode',s.enforcement_mode
            )
          end
        )
        order by o.created_at desc
      )
      from public.organization_members m
      join public.organizations o on o.id=m.organization_id
      left join public.organization_sso_configs s
        on s.organization_id=o.id and s.status<>'disabled'
      where m.account_id=v_account_id and m.status='active'
    ),'[]'::jsonb)
  );
end;
$function$;

create or replace function private.trustrelay_sso_session_match_v13(
  p_uid uuid,p_org_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $function$
declare
  v_cfg public.organization_sso_configs%rowtype;
  v_account_id text;
  v_ctx jsonb:=private.trustrelay_session_sso_context_v13();
  v_provider_match boolean:=false;
  v_break_glass boolean:=false;
begin
  select * into v_cfg
  from public.organization_sso_configs
  where organization_id=p_org_id
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok',true,'configured',false,'providerMatched',false,'breakGlass',false
    );
  end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);

  v_provider_match:=
    coalesce((v_ctx->>'isSso')::boolean,false)
    and v_ctx->>'protocol'=v_cfg.protocol
    and v_ctx->>'providerIdentifier'=
      case
        when v_cfg.protocol='oidc' then v_cfg.provider_identifier
        else v_cfg.saml_provider_id
      end;

  v_break_glass:=
    coalesce(v_cfg.break_glass_enabled,false)
    and v_account_id is not null
    and v_account_id=v_cfg.break_glass_account_id
    and exists(
      select 1
      from public.organization_members m
      where m.organization_id=p_org_id
        and m.account_id=v_account_id
        and m.status='active'
        and m.role='owner'
    );

  return jsonb_build_object(
    'ok',true,'configured',true,'status',v_cfg.status,
    'protocol',v_cfg.protocol,'providerKind',v_cfg.provider_kind,
    'providerMatched',v_provider_match,'breakGlass',v_break_glass,
    'enforcementMode',v_cfg.enforcement_mode
  );
end;
$function$;

create or replace function private.trustrelay_require_org_role_v07(
  p_uid uuid,p_org_id text,p_roles text[]
)
returns jsonb
language plpgsql
security definer
set search_path to 'private','auth','pg_catalog'
as $function$
declare
  v_guard jsonb;
  v_sso jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if auth.uid() is not null then
    v_guard:=private.trustrelay_require_aal2_v12(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
    v_sso:=private.trustrelay_sso_gate_v13(p_uid,p_org_id);
    if coalesce((v_sso->>'ok')::boolean,false)=false then return v_sso; end if;
  end if;
  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$function$;

-- Remove the alternate staging-only connection model. No connection rows exist.
drop function if exists public.trustrelay_disable_sso_v13(text);
drop function if exists public.trustrelay_register_sso_connection_v13(
  text,text,text,text,text,text,text,text[],boolean,text
);
drop function if exists public.trustrelay_set_sso_enforcement_v13(text,boolean);
drop function if exists public.trustrelay_sso_session_bootstrap_v13();
drop function if exists public.trustrelay_sso_status_v13(text);

drop function if exists private.trustrelay_disable_sso_v13(text);
drop function if exists private.trustrelay_register_sso_connection_v13(
  text,text,text,text,text,text,text,text[],boolean,text
);
drop function if exists private.trustrelay_set_sso_enforcement_v13(text,boolean);
drop function if exists private.trustrelay_sso_session_bootstrap_v13();
drop function if exists private.trustrelay_sso_status_v13(text);
drop function if exists private.trustrelay_sso_discover_v13(text);
drop function if exists private.trustrelay_sso_enforcement_v13(uuid,text);

drop table if exists public.organization_sso_connections;

revoke execute on function private.trustrelay_account_id_for_uid_v13(uuid)
from public,anon;
grant execute on function private.trustrelay_account_id_for_uid_v13(uuid)
to authenticated,service_role;

revoke execute on function private.trustrelay_session_sso_context_v13()
from public,anon;
grant execute on function private.trustrelay_session_sso_context_v13()
to authenticated,service_role;
