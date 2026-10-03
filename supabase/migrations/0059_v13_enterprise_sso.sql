-- TrustRelay v1.3 — Enterprise SSO foundation
-- Final-state migration: organization OIDC/SAML policy, multi-auth account bindings,
-- JIT membership, lockout protection, and public-invoker/private-definer RPC pattern.

create table if not exists public.account_auth_bindings (
  auth_user_id uuid primary key references auth.users(id) on delete cascade,
  account_id text not null references public.accounts(id) on delete cascade,
  provider_protocol text not null default 'email' check (provider_protocol in ('email','oidc','saml','other')),
  provider_identifier text,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);
create index if not exists account_auth_bindings_account_idx on public.account_auth_bindings(account_id);
alter table public.account_auth_bindings enable row level security;
revoke all on table public.account_auth_bindings from public,anon,authenticated;
drop policy if exists account_auth_bindings_deny_direct on public.account_auth_bindings;
create policy account_auth_bindings_deny_direct on public.account_auth_bindings
for all to authenticated using (false) with check (false);

insert into public.account_auth_bindings(auth_user_id,account_id,provider_protocol,provider_identifier)
select a.auth_user_id,a.id,'email','email'
from public.accounts a
where a.auth_user_id is not null
on conflict (auth_user_id) do nothing;

create table if not exists public.organization_sso_connections (
  organization_id text primary key references public.organizations(id) on delete cascade,
  provider_brand text not null check (provider_brand in ('microsoft_entra','okta')),
  protocol text not null check (protocol in ('oidc','saml')),
  provider_identifier text not null,
  display_name text not null,
  issuer_url text,
  metadata_url text,
  domains text[] not null default '{}',
  status text not null default 'configured' check (status in ('configured','verified','disabled')),
  enforcement_mode text not null default 'optional' check (enforcement_mode in ('optional','required')),
  jit_enabled boolean not null default false,
  jit_default_role text not null default 'verifier' check (jit_default_role in ('verifier','developer','auditor','compliance')),
  break_glass_account_id text references public.accounts(id),
  last_verified_at timestamptz,
  verified_by_account_id text references public.accounts(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists organization_sso_provider_identifier_uq
  on public.organization_sso_connections(provider_identifier);
alter table public.organization_sso_connections enable row level security;
revoke all on table public.organization_sso_connections from public,anon,authenticated;
drop policy if exists organization_sso_connections_deny_direct on public.organization_sso_connections;
create policy organization_sso_connections_deny_direct on public.organization_sso_connections
for all to authenticated using (false) with check (false);

create or replace function private.trustrelay_account_id_for_uid_v13(p_uid uuid)
returns text language sql security definer
set search_path=public,private,pg_catalog
as $$
  select coalesce(
    (select b.account_id
       from public.account_auth_bindings b
       join public.accounts a on a.id=b.account_id
      where b.auth_user_id=p_uid and a.status='active' limit 1),
    (select a.id from public.accounts a
      where a.auth_user_id=p_uid and a.status='active' limit 1)
  );
$$;

create or replace function private.trustrelay_session_sso_context_v13()
returns jsonb language plpgsql stable security invoker
set search_path=auth,pg_catalog
as $$
declare
  v_jwt jsonb:=auth.jwt();
  v_provider text:=coalesce(v_jwt#>>'{app_metadata,provider}','');
  v_saml_provider text;
begin
  select x->>'provider' into v_saml_provider
    from jsonb_array_elements(coalesce(v_jwt->'amr','[]'::jsonb)) x
   where x->>'method'='sso/saml' limit 1;
  if v_saml_provider is not null and v_saml_provider<>'' then
    return jsonb_build_object('isSso',true,'protocol','saml','providerIdentifier',v_saml_provider);
  end if;
  if v_provider like 'custom:%' then
    return jsonb_build_object('isSso',true,'protocol','oidc','providerIdentifier',v_provider);
  end if;
  return jsonb_build_object('isSso',false,'protocol',null,'providerIdentifier',v_provider);
end;
$$;

create or replace function private.trustrelay_sso_enforcement_v13(p_uid uuid,p_org_id text)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_conn public.organization_sso_connections%rowtype;
  v_ctx jsonb;
  v_account_id text;
begin
  select * into v_conn
    from public.organization_sso_connections
   where organization_id=p_org_id and status='verified' and enforcement_mode='required'
   limit 1;
  if not found then return jsonb_build_object('ok',true); end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  v_ctx:=private.trustrelay_session_sso_context_v13();

  if coalesce((v_ctx->>'isSso')::boolean,false)
     and v_ctx->>'protocol'=v_conn.protocol
     and v_ctx->>'providerIdentifier'=v_conn.provider_identifier then
    return jsonb_build_object('ok',true,'sso',true);
  end if;

  if v_conn.break_glass_account_id is not null
     and v_account_id=v_conn.break_glass_account_id
     and exists (
       select 1 from public.organization_members m
        where m.organization_id=p_org_id and m.account_id=v_account_id
          and m.status='active' and m.role='owner'
     ) then
    return jsonb_build_object('ok',true,'breakGlass',true);
  end if;

  return jsonb_build_object(
    'ok',false,'status',403,'code','SSO_REQUIRED',
    'providerBrand',v_conn.provider_brand,'protocol',v_conn.protocol
  );
end;
$$;

create or replace function private.trustrelay_ensure_account_v06(p_uid uuid,p_display_name text default null)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
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
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if auth.uid() is not null and p_uid is distinct from auth.uid() then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  select lower(email) into v_email from auth.users where id=p_uid;
  if v_email is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_USER_NOT_FOUND');
  end if;

  v_bound_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_bound_account_id is not null then
    update public.account_auth_bindings set last_seen_at=now() where auth_user_id=p_uid;
    select * into v_account from public.accounts where id=v_bound_account_id;
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
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
    if coalesce((v_sso->>'isSso')::boolean,false)=false then
      return jsonb_build_object('ok',false,'status',409,'code','ACCOUNT_EMAIL_ALREADY_BOUND');
    end if;
    insert into public.account_auth_bindings(
      auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
    ) values(p_uid,v_account.id,v_protocol,v_identifier,now())
    on conflict(auth_user_id) do update
      set account_id=excluded.account_id,
          provider_protocol=excluded.provider_protocol,
          provider_identifier=excluded.provider_identifier,
          last_seen_at=now();
    select * into v_person from public.persons where id=v_account.person_id;
    return jsonb_build_object(
      'ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person),'identityAlias',true
    );
  end if;

  v_person_id:='person_'||replace(p_uid::text,'-','');
  v_account_id:='acct_'||replace(p_uid::text,'-','');
  insert into public.persons(id,display_name,email,identity_status,created_at)
  values(v_person_id,coalesce(nullif(btrim(p_display_name),''),split_part(v_email,'@',1)),v_email,'unverified',v_now)
  returning * into v_person;

  insert into public.accounts(id,person_id,email,status,created_at,auth_user_id)
  values(v_account_id,v_person_id,v_email,'active',v_now,p_uid)
  returning * into v_account;

  insert into public.account_auth_bindings(
    auth_user_id,account_id,provider_protocol,provider_identifier,last_seen_at
  ) values(p_uid,v_account.id,v_protocol,v_identifier,now())
  on conflict(auth_user_id) do nothing;

  return jsonb_build_object('ok',true,'account',to_jsonb(v_account),'person',to_jsonb(v_person));
end;
$$;

create or replace function private.trustrelay_my_organizations_core_v10(p_uid uuid)
returns jsonb language plpgsql security definer
set search_path=public,private,pg_catalog
as $$
declare v_account_id text;
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
          'sso',case when s.organization_id is null then null else jsonb_build_object(
            'providerBrand',s.provider_brand,'protocol',s.protocol,
            'status',s.status,'enforcementMode',s.enforcement_mode
          ) end
        ) order by o.created_at desc
      )
      from public.organization_members m
      join public.organizations o on o.id=m.organization_id
      left join public.organization_sso_connections s
        on s.organization_id=o.id and s.status<>'disabled'
      where m.account_id=v_account_id and m.status='active'
    ),'[]'::jsonb)
  );
end;
$$;

create or replace function private.trustrelay_require_org_role_core_v10(
  p_uid uuid,p_org_id text,p_roles text[]
)
returns jsonb language plpgsql security definer
set search_path=public,private,pg_catalog
as $$
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
  select * into v_account from public.accounts where id=v_account_id and status='active';
  select * into v_org from public.organizations where id=p_org_id limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_NOT_FOUND');
  end if;
  select * into v_member from public.organization_members
   where organization_id=p_org_id and account_id=v_account.id and status='active'
   limit 1;
  if not found then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_ACCESS_DENIED');
  end if;
  if p_roles is not null and array_length(p_roles,1) is not null
     and not (v_member.role=any(p_roles)) then
    return jsonb_build_object(
      'ok',false,'status',403,'code','ORGANIZATION_ROLE_DENIED','role',v_member.role
    );
  end if;
  return jsonb_build_object(
    'ok',true,'accountId',v_account.id,'role',v_member.role,'organization',to_jsonb(v_org)
  );
end;
$$;

create or replace function private.trustrelay_require_org_role_v07(
  p_uid uuid,p_org_id text,p_roles text[]
)
returns jsonb language plpgsql security definer
set search_path=private,auth,pg_catalog
as $$
declare v_guard jsonb; v_sso jsonb;
begin
  if not private.trustrelay_request_actor_matches_v10(p_uid) then
    return jsonb_build_object('ok',false,'status',403,'code','AUTH_USER_MISMATCH');
  end if;
  if auth.uid() is not null then
    v_guard:=private.trustrelay_require_aal2_v12(p_uid);
    if coalesce((v_guard->>'ok')::boolean,false)=false then return v_guard; end if;
    v_sso:=private.trustrelay_sso_enforcement_v13(p_uid,p_org_id);
    if coalesce((v_sso->>'ok')::boolean,false)=false then return v_sso; end if;
  end if;
  return private.trustrelay_require_org_role_core_v10(p_uid,p_org_id,p_roles);
end;
$$;

create or replace function private.trustrelay_accept_org_invite_core_v10(p_uid uuid,p_token text)
returns jsonb language plpgsql security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v_account public.accounts%rowtype;
  v_account_id text;
  v_invite public.organization_invitations%rowtype;
  v_hash text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_account_id:=private.trustrelay_account_id_for_uid_v13(p_uid);
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;
  select * into v_account from public.accounts where id=v_account_id and status='active';

  if p_token is null or length(btrim(p_token))<32 then
    return jsonb_build_object('ok',false,'status',400,'code','ORGANIZATION_INVITATION_INVALID');
  end if;
  v_hash:=encode(digest(btrim(p_token),'sha256'),'hex');

  select * into v_invite
    from public.organization_invitations
   where token_hash=v_hash
   for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','ORGANIZATION_INVITATION_NOT_FOUND');
  end if;
  if v_invite.status<>'pending' then
    return jsonb_build_object('ok',false,'status',409,'code','ORGANIZATION_INVITATION_NOT_PENDING');
  end if;
  if v_invite.expires_at::timestamptz<=clock_timestamp() then
    update public.organization_invitations set status='expired' where id=v_invite.id;
    return jsonb_build_object('ok',false,'status',410,'code','ORGANIZATION_INVITATION_EXPIRED');
  end if;
  if lower(v_invite.invite_email)<>lower(v_account.email) then
    return jsonb_build_object('ok',false,'status',403,'code','ORGANIZATION_INVITATION_EMAIL_MISMATCH');
  end if;

  insert into public.organization_members(
    organization_id,account_id,role,created_at,status,updated_at
  ) values(v_invite.organization_id,v_account.id,v_invite.role,v_now,'active',v_now)
  on conflict(organization_id,account_id)
  do update set role=excluded.role,status='active',updated_at=v_now;

  update public.organization_invitations
     set status='accepted',accepted_by_account_id=v_account.id,accepted_at=v_now
   where id=v_invite.id;

  return jsonb_build_object(
    'ok',true,'organizationId',v_invite.organization_id,
    'membership',jsonb_build_object('role',v_invite.role,'status','active')
  );
end;
$$;

create or replace function private.trustrelay_sso_discover_v13(p_email text)
returns jsonb language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare v_domain text; v_conn public.organization_sso_connections%rowtype;
begin
  v_domain:=lower(split_part(btrim(coalesce(p_email,'')),'@',2));
  if v_domain='' or length(v_domain)>253 then
    return jsonb_build_object('ok',false,'status',400,'code','EMAIL_INVALID');
  end if;

  select * into v_conn
    from public.organization_sso_connections
   where status in ('configured','verified') and v_domain=any(domains)
   order by case when enforcement_mode='required' then 0 else 1 end,updated_at desc
   limit 1;

  if not found then return jsonb_build_object('ok',true,'ssoAvailable',false); end if;
  return jsonb_build_object(
    'ok',true,'ssoAvailable',true,
    'providerBrand',v_conn.provider_brand,'protocol',v_conn.protocol,
    'providerIdentifier',v_conn.provider_identifier,
    'enforcementRequired',v_conn.enforcement_mode='required'
  );
end;
$$;

create or replace function private.trustrelay_sso_status_v13(p_org_id text)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare v_ctx jsonb; v_conn public.organization_sso_connections%rowtype;
begin
  v_ctx:=private.trustrelay_require_org_role_v07(
    auth.uid(),p_org_id,array['owner','admin','compliance','verifier','developer','auditor']
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_conn from public.organization_sso_connections where organization_id=p_org_id;
  if not found then return jsonb_build_object('ok',true,'configured',false); end if;

  return jsonb_build_object('ok',true,'configured',true,'connection',jsonb_build_object(
    'providerBrand',v_conn.provider_brand,'protocol',v_conn.protocol,
    'providerIdentifier',v_conn.provider_identifier,'displayName',v_conn.display_name,
    'issuerUrl',v_conn.issuer_url,'metadataUrl',v_conn.metadata_url,
    'domains',to_jsonb(v_conn.domains),'status',v_conn.status,
    'enforcementMode',v_conn.enforcement_mode,'jitEnabled',v_conn.jit_enabled,
    'jitDefaultRole',v_conn.jit_default_role,'lastVerifiedAt',v_conn.last_verified_at,
    'breakGlassConfigured',v_conn.break_glass_account_id is not null
  ));
end;
$$;

create or replace function private.trustrelay_register_sso_connection_v13(
  p_org_id text,p_provider_brand text,p_protocol text,p_provider_identifier text,
  p_display_name text,p_issuer_url text,p_metadata_url text,p_domains text[],
  p_jit_enabled boolean default false,p_jit_default_role text default 'verifier'
)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare v_ctx jsonb; v_account_id text; v_domains text[];
begin
  v_ctx:=private.trustrelay_require_permission_v09(auth.uid(),p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  if p_provider_brand not in ('microsoft_entra','okta') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_PROVIDER_INVALID');
  end if;
  if p_protocol not in ('oidc','saml') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_PROTOCOL_INVALID');
  end if;
  if length(btrim(coalesce(p_provider_identifier,'')))<3 then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_PROVIDER_IDENTIFIER_INVALID');
  end if;
  if p_jit_default_role not in ('verifier','developer','auditor','compliance') then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_JIT_ROLE_INVALID');
  end if;

  select array_agg(distinct lower(btrim(x))) into v_domains
    from unnest(coalesce(p_domains,'{}'::text[])) x
   where lower(btrim(x)) ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
     and lower(btrim(x)) not in (
       'gmail.com','yahoo.com','outlook.com','hotmail.com',
       'icloud.com','aol.com','proton.me','protonmail.com'
     );
  if coalesce(array_length(v_domains,1),0)=0 then
    return jsonb_build_object('ok',false,'status',400,'code','SSO_DOMAIN_REQUIRED');
  end if;

  v_account_id:=v_ctx->>'accountId';

  insert into public.organization_sso_connections(
    organization_id,provider_brand,protocol,provider_identifier,display_name,
    issuer_url,metadata_url,domains,status,enforcement_mode,jit_enabled,
    jit_default_role,created_at,updated_at
  ) values(
    p_org_id,p_provider_brand,p_protocol,btrim(p_provider_identifier),left(btrim(p_display_name),120),
    nullif(btrim(coalesce(p_issuer_url,'')),''),
    nullif(btrim(coalesce(p_metadata_url,'')),''),
    v_domains,'configured','optional',coalesce(p_jit_enabled,false),
    p_jit_default_role,now(),now()
  )
  on conflict(organization_id) do update
    set provider_brand=excluded.provider_brand,
        protocol=excluded.protocol,
        provider_identifier=excluded.provider_identifier,
        display_name=excluded.display_name,
        issuer_url=excluded.issuer_url,
        metadata_url=excluded.metadata_url,
        domains=excluded.domains,
        status='configured',
        enforcement_mode='optional',
        jit_enabled=excluded.jit_enabled,
        jit_default_role=excluded.jit_default_role,
        last_verified_at=null,
        verified_by_account_id=null,
        break_glass_account_id=null,
        updated_at=now();

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_account_id,'organization.sso.configured','organization',p_org_id,
    jsonb_build_object(
      'providerBrand',p_provider_brand,'protocol',p_protocol,
      'domains',to_jsonb(v_domains),'jitEnabled',coalesce(p_jit_enabled,false)
    )
  );
  return jsonb_build_object('ok',true,'configured',true);
end;
$$;

create or replace function private.trustrelay_sso_session_bootstrap_v13()
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_uid uuid:=auth.uid();
  v_ctx jsonb:=private.trustrelay_session_sso_context_v13();
  v_account_id text;
  v_email text;
  v_domain text;
  v_conn public.organization_sso_connections%rowtype;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_joined jsonb:='[]'::jsonb;
begin
  if v_uid is null then
    return jsonb_build_object('ok',false,'status',401,'code','AUTH_REQUIRED');
  end if;
  if coalesce((v_ctx->>'isSso')::boolean,false)=false then
    return jsonb_build_object('ok',true,'sso',false,'joined',v_joined);
  end if;

  v_account_id:=private.trustrelay_account_id_for_uid_v13(v_uid);
  if v_account_id is null then
    return jsonb_build_object('ok',false,'status',401,'code','ACCOUNT_NOT_BOUND');
  end if;

  select lower(email) into v_email from public.accounts where id=v_account_id;
  v_domain:=split_part(v_email,'@',2);

  for v_conn in
    select * from public.organization_sso_connections
     where status in ('configured','verified')
       and protocol=v_ctx->>'protocol'
       and provider_identifier=v_ctx->>'providerIdentifier'
       and v_domain=any(domains)
  loop
    if not exists(
      select 1 from public.organization_members
       where organization_id=v_conn.organization_id
         and account_id=v_account_id and status='active'
    ) and v_conn.jit_enabled then
      insert into public.organization_members(
        organization_id,account_id,role,created_at,status,title,updated_at
      ) values(
        v_conn.organization_id,v_account_id,v_conn.jit_default_role,
        v_now,'active','SSO JIT',v_now
      )
      on conflict(organization_id,account_id)
      do update set status='active',role=excluded.role,updated_at=v_now;

      perform private.trustrelay_append_org_audit_v09(
        v_conn.organization_id,v_account_id,'organization.member.sso_jit_joined',
        'organization_member',v_account_id,
        jsonb_build_object(
          'providerBrand',v_conn.provider_brand,'protocol',v_conn.protocol,
          'role',v_conn.jit_default_role
        )
      );
      v_joined:=v_joined||jsonb_build_array(v_conn.organization_id);
    end if;

    if exists(
      select 1 from public.organization_members
       where organization_id=v_conn.organization_id
         and account_id=v_account_id and status='active'
    ) then
      update public.organization_sso_connections
         set status='verified',last_verified_at=now(),
             verified_by_account_id=v_account_id,updated_at=now()
       where organization_id=v_conn.organization_id;
    end if;
  end loop;

  return jsonb_build_object('ok',true,'sso',true,'session',v_ctx,'joined',v_joined);
end;
$$;

create or replace function private.trustrelay_set_sso_enforcement_v13(p_org_id text,p_required boolean)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_ctx jsonb;
  v_conn public.organization_sso_connections%rowtype;
  v_sso jsonb;
  v_breakglass text;
  v_actor text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(auth.uid(),p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_actor:=v_ctx->>'accountId';

  select * into v_conn
    from public.organization_sso_connections
   where organization_id=p_org_id
   for update;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SSO_NOT_CONFIGURED');
  end if;

  if coalesce(p_required,false)=false then
    update public.organization_sso_connections
       set enforcement_mode='optional',updated_at=now()
     where organization_id=p_org_id;
    perform private.trustrelay_append_org_audit_v09(
      p_org_id,v_actor,'organization.sso.enforcement_optional','organization',p_org_id,'{}'::jsonb
    );
    return jsonb_build_object('ok',true,'enforcementMode','optional');
  end if;

  if v_conn.status<>'verified' or v_conn.last_verified_at is null then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_VERIFICATION_REQUIRED');
  end if;

  v_sso:=private.trustrelay_session_sso_context_v13();
  if coalesce((v_sso->>'isSso')::boolean,false)=false
     or v_sso->>'protocol'<>v_conn.protocol
     or v_sso->>'providerIdentifier'<>v_conn.provider_identifier then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_CURRENT_SESSION_REQUIRED');
  end if;

  select m.account_id into v_breakglass
    from public.organization_members m
    join public.accounts a on a.id=m.account_id
   where m.organization_id=p_org_id
     and m.status='active'
     and m.role='owner'
     and a.auth_user_id is not null
     and exists(
       select 1 from auth.identities i
        where i.user_id=a.auth_user_id and i.provider='email'
     )
   order by m.created_at
   limit 1;

  if v_breakglass is null then
    return jsonb_build_object('ok',false,'status',409,'code','SSO_BREAK_GLASS_OWNER_REQUIRED');
  end if;

  update public.organization_sso_connections
     set enforcement_mode='required',
         break_glass_account_id=v_breakglass,
         updated_at=now()
   where organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_actor,'organization.sso.enforcement_required','organization',p_org_id,
    jsonb_build_object(
      'breakGlassAccountId',v_breakglass,
      'providerBrand',v_conn.provider_brand,'protocol',v_conn.protocol
    )
  );

  return jsonb_build_object('ok',true,'enforcementMode','required','breakGlassConfigured',true);
end;
$$;

create or replace function private.trustrelay_disable_sso_v13(p_org_id text)
returns jsonb language plpgsql security definer
set search_path=public,private,auth,pg_catalog
as $$
declare v_ctx jsonb; v_actor text;
begin
  v_ctx:=private.trustrelay_require_permission_v09(auth.uid(),p_org_id,'organization.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  v_actor:=v_ctx->>'accountId';

  update public.organization_sso_connections
     set status='disabled',enforcement_mode='optional',
         break_glass_account_id=null,updated_at=now()
   where organization_id=p_org_id;
  if not found then
    return jsonb_build_object('ok',false,'status',404,'code','SSO_NOT_CONFIGURED');
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_actor,'organization.sso.disabled','organization',p_org_id,'{}'::jsonb
  );
  return jsonb_build_object('ok',true,'disabled',true);
end;
$$;

create or replace function public.trustrelay_sso_discover_v13(p_email text)
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$ select private.trustrelay_sso_discover_v13(p_email); $$;

create or replace function public.trustrelay_sso_status_v13(p_org_id text)
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$ select private.trustrelay_sso_status_v13(p_org_id); $$;

create or replace function public.trustrelay_register_sso_connection_v13(
  p_org_id text,p_provider_brand text,p_protocol text,p_provider_identifier text,
  p_display_name text,p_issuer_url text,p_metadata_url text,p_domains text[],
  p_jit_enabled boolean default false,p_jit_default_role text default 'verifier'
)
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$
  select private.trustrelay_register_sso_connection_v13(
    p_org_id,p_provider_brand,p_protocol,p_provider_identifier,p_display_name,
    p_issuer_url,p_metadata_url,p_domains,p_jit_enabled,p_jit_default_role
  );
$$;

create or replace function public.trustrelay_sso_session_bootstrap_v13()
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$ select private.trustrelay_sso_session_bootstrap_v13(); $$;

create or replace function public.trustrelay_set_sso_enforcement_v13(p_org_id text,p_required boolean)
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$ select private.trustrelay_set_sso_enforcement_v13(p_org_id,p_required); $$;

create or replace function public.trustrelay_disable_sso_v13(p_org_id text)
returns jsonb language sql security invoker
set search_path=private,pg_catalog
as $$ select private.trustrelay_disable_sso_v13(p_org_id); $$;

revoke all on function private.trustrelay_account_id_for_uid_v13(uuid) from public,anon,authenticated;
revoke all on function private.trustrelay_session_sso_context_v13() from public,anon,authenticated;
revoke all on function private.trustrelay_sso_enforcement_v13(uuid,text) from public,anon,authenticated;
grant execute on function private.trustrelay_account_id_for_uid_v13(uuid) to service_role;
grant execute on function private.trustrelay_session_sso_context_v13() to service_role;
grant execute on function private.trustrelay_sso_enforcement_v13(uuid,text) to service_role;

revoke all on function private.trustrelay_sso_discover_v13(text) from public;
revoke all on function private.trustrelay_sso_status_v13(text) from public;
revoke all on function private.trustrelay_register_sso_connection_v13(text,text,text,text,text,text,text,text[],boolean,text) from public;
revoke all on function private.trustrelay_sso_session_bootstrap_v13() from public;
revoke all on function private.trustrelay_set_sso_enforcement_v13(text,boolean) from public;
revoke all on function private.trustrelay_disable_sso_v13(text) from public;
grant execute on function private.trustrelay_sso_discover_v13(text) to anon,authenticated;
grant execute on function private.trustrelay_sso_status_v13(text) to authenticated;
grant execute on function private.trustrelay_register_sso_connection_v13(text,text,text,text,text,text,text,text[],boolean,text) to authenticated;
grant execute on function private.trustrelay_sso_session_bootstrap_v13() to authenticated;
grant execute on function private.trustrelay_set_sso_enforcement_v13(text,boolean) to authenticated;
grant execute on function private.trustrelay_disable_sso_v13(text) to authenticated;

revoke all on function public.trustrelay_sso_discover_v13(text) from public;
grant execute on function public.trustrelay_sso_discover_v13(text) to anon,authenticated;

revoke all on function public.trustrelay_sso_status_v13(text) from public,anon;
revoke all on function public.trustrelay_register_sso_connection_v13(text,text,text,text,text,text,text,text[],boolean,text) from public,anon;
revoke all on function public.trustrelay_sso_session_bootstrap_v13() from public,anon;
revoke all on function public.trustrelay_set_sso_enforcement_v13(text,boolean) from public,anon;
revoke all on function public.trustrelay_disable_sso_v13(text) from public,anon;
grant execute on function public.trustrelay_sso_status_v13(text) to authenticated;
grant execute on function public.trustrelay_register_sso_connection_v13(text,text,text,text,text,text,text,text[],boolean,text) to authenticated;
grant execute on function public.trustrelay_sso_session_bootstrap_v13() to authenticated;
grant execute on function public.trustrelay_set_sso_enforcement_v13(text,boolean) to authenticated;
grant execute on function public.trustrelay_disable_sso_v13(text) to authenticated;
