-- TrustRelay v1.2 credential signing-key lifecycle
-- Automatic 30-day ES256 rotation, single active key, and 7-day retired-key JWKS overlap.

create unique index if not exists signing_keys_one_active_v12
  on public.signing_keys ((status)) where status='active';

create or replace function public.trustrelay_get_active_signing_key_v06()
returns jsonb language plpgsql security definer
set search_path to 'public','vault','pg_catalog'
as $$
declare
  v_key public.signing_keys%rowtype;
  v_private text;
  v_activated timestamptz;
  v_due timestamptz;
begin
  select * into v_key from public.signing_keys
  where status='active'
  order by activated_at desc nulls last,created_at desc limit 1;
  if not found then return jsonb_build_object('ok',false,'status',503,'code','SIGNING_KEY_UNAVAILABLE'); end if;

  select decrypted_secret into v_private from vault.decrypted_secrets where id=v_key.vault_secret_id;
  if v_private is null then return jsonb_build_object('ok',false,'status',503,'code','SIGNING_KEY_UNAVAILABLE'); end if;

  begin
    v_activated:=coalesce(nullif(v_key.activated_at,'')::timestamptz,nullif(v_key.created_at,'')::timestamptz,clock_timestamp());
  exception when others then
    v_activated:=clock_timestamp()-interval '31 days';
  end;
  v_due:=v_activated+interval '30 days';

  return jsonb_build_object(
    'ok',true,'kid',v_key.kid,'alg',v_key.alg,
    'publicJwk',v_key.public_jwk::jsonb,'privateJwk',v_private::jsonb,
    'publicThumbprint',v_key.public_thumbprint,'activatedAt',v_key.activated_at,
    'rotationDueAt',to_char(v_due at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'rotationRequired',clock_timestamp()>=v_due
  );
end;
$$;

create or replace function public.trustrelay_rotate_signing_key_v12(
  p_kid text,p_public_jwk text,p_private_jwk text,p_public_thumbprint text,p_force boolean default false
)
returns jsonb language plpgsql security definer
set search_path to 'public','vault','pg_catalog'
as $$
declare
  v_current public.signing_keys%rowtype;
  v_secret_id uuid;
  v_public jsonb;
  v_private jsonb;
  v_now timestamptz:=clock_timestamp();
  v_now_text text:=to_char(v_now at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_active_since timestamptz;
  v_rotation_due timestamptz;
begin
  perform pg_advisory_xact_lock(72120412);

  if p_kid is null or p_kid !~ '^trk_[A-Za-z0-9_-]{8,80}$'
     or length(coalesce(p_public_thumbprint,''))<20
     or length(coalesce(p_public_thumbprint,''))>200
     or length(coalesce(p_public_jwk,''))>8192
     or length(coalesce(p_private_jwk,''))>16384 then
    return jsonb_build_object('ok',false,'status',400,'code','SIGNING_KEY_INPUT_INVALID');
  end if;

  begin v_public:=p_public_jwk::jsonb; v_private:=p_private_jwk::jsonb;
  exception when others then return jsonb_build_object('ok',false,'status',400,'code','SIGNING_KEY_JWK_INVALID'); end;

  if v_public->>'kty'<>'EC' or v_public->>'crv'<>'P-256'
     or coalesce(v_public->>'x','')='' or coalesce(v_public->>'y','')='' or v_public ? 'd'
     or v_private->>'kty'<>'EC' or v_private->>'crv'<>'P-256'
     or coalesce(v_private->>'x','')='' or coalesce(v_private->>'y','')=''
     or coalesce(v_private->>'d','')='' then
    return jsonb_build_object('ok',false,'status',400,'code','SIGNING_KEY_JWK_INVALID');
  end if;

  select * into v_current from public.signing_keys
  where status='active'
  order by activated_at desc nulls last,created_at desc limit 1 for update;

  if found then
    begin
      v_active_since:=coalesce(nullif(v_current.activated_at,'')::timestamptz,nullif(v_current.created_at,'')::timestamptz,v_now);
    exception when others then v_active_since:=v_now-interval '31 days'; end;
    v_rotation_due:=v_active_since+interval '30 days';
    if not coalesce(p_force,false) and v_now<v_rotation_due then
      return jsonb_build_object('ok',true,'rotated',false,'kid',v_current.kid,
        'rotationDueAt',to_char(v_rotation_due at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    end if;
  end if;

  if exists(select 1 from public.signing_keys where kid=p_kid) then
    return jsonb_build_object('ok',false,'status',409,'code','SIGNING_KEY_KID_EXISTS');
  end if;

  v_secret_id:=vault.create_secret(p_private_jwk,'trustrelay-signing-'||p_kid,'TrustRelay ES256 authority credential private JWK');

  if found then
    update public.signing_keys set status='retired',retired_at=v_now_text
    where kid=v_current.kid and status='active';
  end if;

  insert into public.signing_keys(
    kid,alg,public_jwk,public_thumbprint,vault_secret_id,status,created_at,activated_at
  ) values(p_kid,'ES256',p_public_jwk,p_public_thumbprint,v_secret_id,'active',v_now_text,v_now_text);

  return jsonb_build_object(
    'ok',true,'rotated',true,'kid',p_kid,
    'previousKid',case when v_current.kid is null then null else v_current.kid end,
    'activatedAt',v_now_text,
    'rotationDueAt',to_char((v_now+interval '30 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
end;
$$;

create or replace function public.trustrelay_list_public_signing_keys_v06()
returns jsonb language sql security definer
set search_path to 'public','pg_catalog'
as $$
  select jsonb_build_object(
    'ok',true,
    'keys',coalesce(
      jsonb_agg(
        jsonb_build_object('kid',kid,'alg',alg,'publicJwk',public_jwk::jsonb,'status',status)
        order by created_at desc
      ) filter (
        where status='active'
           or (status='retired'
               and coalesce(nullif(retired_at,'')::timestamptz,clock_timestamp()-interval '100 years')
                   > clock_timestamp()-interval '7 days')
      ),
      '[]'::jsonb
    )
  ) from public.signing_keys;
$$;

revoke all on function public.trustrelay_get_active_signing_key_v06() from public,anon,authenticated;
revoke all on function public.trustrelay_rotate_signing_key_v12(text,text,text,text,boolean) from public,anon,authenticated;
revoke all on function public.trustrelay_list_public_signing_keys_v06() from public,anon,authenticated;
grant execute on function public.trustrelay_get_active_signing_key_v06() to service_role;
grant execute on function public.trustrelay_rotate_signing_key_v12(text,text,text,text,boolean) to service_role;
grant execute on function public.trustrelay_list_public_signing_keys_v06() to service_role;
notify pgrst,'reload schema';
