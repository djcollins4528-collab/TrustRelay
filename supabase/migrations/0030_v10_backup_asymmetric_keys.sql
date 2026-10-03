-- TrustRelay v1.0 asymmetric cross-project backup key infrastructure.

create table if not exists public.backup_source_signing_keys (
  kid text primary key,
  alg text not null default 'ES256',
  public_jwk text not null,
  vault_secret_name text,
  status text not null default 'active',
  created_at text not null,
  retired_at text
);
alter table public.backup_source_signing_keys enable row level security;
revoke all on public.backup_source_signing_keys from anon,authenticated;

create table if not exists public.backup_recovery_keys (
  kid text primary key,
  alg text not null default 'RSA-OAEP-256',
  public_jwk text not null,
  vault_secret_name text,
  status text not null default 'active',
  created_at text not null,
  retired_at text
);
alter table public.backup_recovery_keys enable row level security;
revoke all on public.backup_recovery_keys from anon,authenticated;

create or replace function public.trustrelay_store_backup_source_signing_key_v10(
  p_kid text,p_public_jwk text,p_private_jwk text
)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare
  v_name text:='trustrelay_backup_source_signing_private_jwk';
  v_id uuid;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if coalesce(p_kid,'')='' or coalesce(p_public_jwk,'')='' or coalesce(p_private_jwk,'')='' then
    return jsonb_build_object('ok',false,'code','BACKUP_SOURCE_KEY_INVALID');
  end if;
  select id into v_id from vault.secrets where name=v_name limit 1;
  if v_id is null then
    perform vault.create_secret(p_private_jwk,v_name,'TrustRelay production backup signing private key');
  else
    perform vault.update_secret(v_id,p_private_jwk,v_name,'TrustRelay production backup signing private key');
  end if;
  update public.backup_source_signing_keys set status='retired',retired_at=v_now where status='active';
  insert into public.backup_source_signing_keys(kid,alg,public_jwk,vault_secret_name,status,created_at)
  values(p_kid,'ES256',p_public_jwk,v_name,'active',v_now)
  on conflict(kid) do update set public_jwk=excluded.public_jwk,vault_secret_name=v_name,status='active',retired_at=null;
  return jsonb_build_object('ok',true,'kid',p_kid,'publicJwk',p_public_jwk);
end;
$$;

create or replace function public.trustrelay_get_backup_source_signing_key_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare v record; v_private text;
begin
  select * into v from public.backup_source_signing_keys where status='active' order by created_at desc limit 1;
  if not found then return jsonb_build_object('ok',false,'code','BACKUP_SOURCE_KEY_MISSING'); end if;
  select decrypted_secret into v_private from vault.decrypted_secrets where name=v.vault_secret_name limit 1;
  if coalesce(v_private,'')='' then return jsonb_build_object('ok',false,'code','BACKUP_SOURCE_PRIVATE_KEY_MISSING'); end if;
  return jsonb_build_object('ok',true,'kid',v.kid,'publicJwk',v.public_jwk,'privateJwk',v_private);
end;
$$;

create or replace function public.trustrelay_store_backup_recovery_key_v10(
  p_kid text,p_public_jwk text,p_private_jwk text
)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare
  v_name text:='trustrelay_backup_recovery_private_jwk';
  v_id uuid;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if coalesce(p_kid,'')='' or coalesce(p_public_jwk,'')='' or coalesce(p_private_jwk,'')='' then
    return jsonb_build_object('ok',false,'code','BACKUP_RECOVERY_KEY_INVALID');
  end if;
  select id into v_id from vault.secrets where name=v_name limit 1;
  if v_id is null then
    perform vault.create_secret(p_private_jwk,v_name,'TrustRelay disaster-recovery RSA private key');
  else
    perform vault.update_secret(v_id,p_private_jwk,v_name,'TrustRelay disaster-recovery RSA private key');
  end if;
  update public.backup_recovery_keys set status='retired',retired_at=v_now where status='active';
  insert into public.backup_recovery_keys(kid,alg,public_jwk,vault_secret_name,status,created_at)
  values(p_kid,'RSA-OAEP-256',p_public_jwk,v_name,'active',v_now)
  on conflict(kid) do update set public_jwk=excluded.public_jwk,vault_secret_name=v_name,status='active',retired_at=null;
  return jsonb_build_object('ok',true,'kid',p_kid,'publicJwk',p_public_jwk);
end;
$$;

create or replace function public.trustrelay_get_backup_recovery_public_key_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare v record;
begin
  select * into v from public.backup_recovery_keys where status='active' order by created_at desc limit 1;
  if not found then return jsonb_build_object('ok',false,'code','BACKUP_RECOVERY_KEY_MISSING'); end if;
  return jsonb_build_object('ok',true,'kid',v.kid,'publicJwk',v.public_jwk);
end;
$$;

create or replace function public.trustrelay_get_backup_recovery_private_key_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare v record; v_private text;
begin
  select * into v from public.backup_recovery_keys where status='active' order by created_at desc limit 1;
  if not found then return jsonb_build_object('ok',false,'code','BACKUP_RECOVERY_KEY_MISSING'); end if;
  select decrypted_secret into v_private from vault.decrypted_secrets where name=v.vault_secret_name limit 1;
  if coalesce(v_private,'')='' then return jsonb_build_object('ok',false,'code','BACKUP_RECOVERY_PRIVATE_KEY_MISSING'); end if;
  return jsonb_build_object('ok',true,'kid',v.kid,'publicJwk',v.public_jwk,'privateJwk',v_private);
end;
$$;

revoke all on function public.trustrelay_store_backup_source_signing_key_v10(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_get_backup_source_signing_key_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_store_backup_recovery_key_v10(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_get_backup_recovery_public_key_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_get_backup_recovery_private_key_v10() from public,anon,authenticated;
grant execute on function public.trustrelay_store_backup_source_signing_key_v10(text,text,text) to service_role;
grant execute on function public.trustrelay_get_backup_source_signing_key_v10() to service_role;
grant execute on function public.trustrelay_store_backup_recovery_key_v10(text,text,text) to service_role;
grant execute on function public.trustrelay_get_backup_recovery_public_key_v10() to service_role;
grant execute on function public.trustrelay_get_backup_recovery_private_key_v10() to service_role;

notify pgrst,'reload schema';
