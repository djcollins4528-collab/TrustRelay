-- TrustRelay v1.2 one-time internal verifier capabilities.
-- Replaces reusable verifier-to-partner credentials with 30-second,
-- single-use capabilities bound to user, Supabase session, organization,
-- purpose, and the exact canonical request-body SHA-256.

create table if not exists private.trustrelay_internal_capabilities_v12 (
  id text primary key,
  token_hash text not null unique,
  organization_id text not null,
  auth_user_id uuid not null,
  session_id text not null,
  purpose text not null,
  body_sha256 text not null,
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  consumed_at timestamptz null
);

revoke all on table private.trustrelay_internal_capabilities_v12 from public,anon,authenticated;
grant select,insert,update,delete on table private.trustrelay_internal_capabilities_v12 to service_role;

create index if not exists trustrelay_internal_capabilities_expiry_v12
  on private.trustrelay_internal_capabilities_v12(expires_at);
create index if not exists trustrelay_internal_capabilities_org_v12
  on private.trustrelay_internal_capabilities_v12(organization_id,created_at desc);

create or replace function public.trustrelay_mint_portal_capability_v12(
  p_auth_user_id uuid,
  p_session_id text,
  p_org_id text,
  p_body_sha256 text,
  p_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_rate record;
  v_id text:='icap_'||replace(gen_random_uuid()::text,'-','');
  v_now timestamptz:=clock_timestamp();
  v_expires timestamptz;
begin
  if p_body_sha256 is null or p_body_sha256 !~ '^[0-9a-f]{64}$'
     or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','INTERNAL_CAPABILITY_INPUT_INVALID');
  end if;

  v_ctx:=public.trustrelay_portal_session_context_v12(
    p_auth_user_id,p_session_id,p_org_id
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_rate
  from public.consume_rate_limit_v05(
    'portal-capability-mint:'||p_auth_user_id::text||':'||p_org_id,
    30,
    60
  );
  if not coalesce(v_rate.allowed,false) then
    return jsonb_build_object(
      'ok',false,'status',429,'code','INTERNAL_CAPABILITY_RATE_LIMITED',
      'resetAt',v_rate.reset_at
    );
  end if;

  delete from private.trustrelay_internal_capabilities_v12
  where expires_at < v_now-interval '5 minutes';

  v_expires:=v_now+interval '30 seconds';

  insert into private.trustrelay_internal_capabilities_v12(
    id,token_hash,organization_id,auth_user_id,session_id,purpose,
    body_sha256,created_at,expires_at
  ) values (
    v_id,p_token_hash,p_org_id,p_auth_user_id,p_session_id,
    'portal.decisions.evaluate',p_body_sha256,v_now,v_expires
  );

  return jsonb_build_object(
    'ok',true,
    'capabilityId',v_id,
    'expiresAt',to_char(v_expires at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'ttlSeconds',30
  );
end;
$$;

create or replace function public.trustrelay_consume_portal_capability_v12(
  p_token_hash text,
  p_body_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','auth','pg_catalog'
as $$
declare
  v_cap private.trustrelay_internal_capabilities_v12%rowtype;
  v_ctx jsonb;
  v_now timestamptz:=clock_timestamp();
begin
  if p_body_sha256 is null or p_body_sha256 !~ '^[0-9a-f]{64}$'
     or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'status',401,'code','INTERNAL_CAPABILITY_INVALID');
  end if;

  update private.trustrelay_internal_capabilities_v12
  set consumed_at=v_now
  where token_hash=p_token_hash
    and body_sha256=p_body_sha256
    and purpose='portal.decisions.evaluate'
    and consumed_at is null
    and expires_at>v_now
  returning * into v_cap;

  if not found then
    return jsonb_build_object('ok',false,'status',401,'code','INTERNAL_CAPABILITY_INVALID');
  end if;

  v_ctx:=public.trustrelay_portal_session_context_v12(
    v_cap.auth_user_id,v_cap.session_id,v_cap.organization_id
  );
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  return jsonb_build_object(
    'ok',true,
    'capabilityId',v_cap.id,
    'organizationId',v_cap.organization_id,
    'authUserId',v_cap.auth_user_id,
    'accountId',v_ctx->>'accountId',
    'role',v_ctx->>'role',
    'sessionId',v_cap.session_id,
    'aal',v_ctx->>'aal'
  );
end;
$$;

revoke all on function public.trustrelay_mint_portal_capability_v12(uuid,text,text,text,text)
from public,anon,authenticated;
revoke all on function public.trustrelay_consume_portal_capability_v12(text,text)
from public,anon,authenticated;
grant execute on function public.trustrelay_mint_portal_capability_v12(uuid,text,text,text,text)
to service_role;
grant execute on function public.trustrelay_consume_portal_capability_v12(text,text)
to service_role;

notify pgrst,'reload schema';
