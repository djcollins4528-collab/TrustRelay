-- TrustRelay v1.0 cross-project encrypted disaster-recovery sink.

create table if not exists public.disaster_recovery_objects (
  id text primary key,
  source_environment text not null,
  run_id text not null,
  logical_key text not null,
  chunk_index integer not null,
  total_chunks integer not null,
  storage_bucket text not null,
  storage_path text not null unique,
  iv_b64 text not null,
  plain_sha256 text not null,
  cipher_sha256 text not null,
  plain_bytes integer not null,
  cipher_bytes integer not null,
  metadata_json text not null default '{}',
  created_at text not null,
  unique(run_id,logical_key,chunk_index)
);

alter table public.disaster_recovery_objects enable row level security;
revoke all on public.disaster_recovery_objects from anon,authenticated;

create table if not exists private.backup_sink_config (
  singleton boolean primary key default true check (singleton),
  token_sha256 text not null,
  source_project_ref text not null,
  enabled boolean not null default true,
  updated_at text not null
);
revoke all on private.backup_sink_config from public,anon,authenticated;

create or replace function public.trustrelay_validate_backup_sink_v10(p_token text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v private.backup_sink_config%rowtype;
begin
  select * into v from private.backup_sink_config where singleton=true;
  if not found or not v.enabled then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_SINK_DISABLED');
  end if;
  if encode(digest(coalesce(p_token,''),'sha256'),'hex')<>v.token_sha256 then
    return jsonb_build_object('ok',false,'status',401,'code','BACKUP_SINK_TOKEN_INVALID');
  end if;
  return jsonb_build_object('ok',true,'sourceProjectRef',v.source_project_ref);
end;
$$;

create or replace function public.trustrelay_backup_cross_project_config_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare
  v_token text;
  v_key text;
  v_sink text;
begin
  select decrypted_secret into v_token
  from vault.decrypted_secrets where name='trustrelay_backup_sink_token' limit 1;

  select decrypted_secret into v_key
  from vault.decrypted_secrets where name='trustrelay_backup_encryption_key_b64' limit 1;

  select decrypted_secret into v_sink
  from vault.decrypted_secrets where name='trustrelay_backup_sink_url' limit 1;

  return jsonb_build_object(
    'ok',coalesce(v_token,'')<>'' and coalesce(v_key,'')<>'' and coalesce(v_sink,'')<>'',
    'provider','supabase_cross_project_encrypted',
    'sinkToken',v_token,
    'encryptionKeyB64',v_key,
    'sinkUrl',v_sink,
    'bucket','trustrelay-disaster-recovery'
  );
end;
$$;

create or replace function public.trustrelay_backup_run_start_v10(
  p_id text,p_environment text,p_bucket text,p_object_prefix text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  insert into public.backup_runs(
    id,environment,provider,bucket,object_prefix,status,started_at
  ) values(
    p_id,p_environment,'supabase_cross_project_encrypted',p_bucket,p_object_prefix,'running',v_now
  );
  return jsonb_build_object('ok',true,'id',p_id,'startedAt',v_now);
end;
$$;

revoke all on function public.trustrelay_validate_backup_sink_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_cross_project_config_v10() from public,anon,authenticated;
grant execute on function public.trustrelay_validate_backup_sink_v10(text) to service_role;
grant execute on function public.trustrelay_backup_cross_project_config_v10() to service_role;

notify pgrst,'reload schema';
