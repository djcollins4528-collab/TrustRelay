-- TrustRelay v1.0 encrypted cross-project backup v2.
-- Secrets remain inside Supabase Vault/DB functions; callers receive only hashes,
-- request IDs, status, and integrity evidence.

create table if not exists private.cross_project_backup_receiver (
  singleton boolean primary key default true check (singleton),
  ingress_token_sha256 text,
  enabled boolean not null default false,
  recovery_key_received boolean not null default false,
  updated_at text not null default to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);
revoke all on private.cross_project_backup_receiver from public,anon,authenticated;

create table if not exists private.cross_project_backup_sender (
  singleton boolean primary key default true check (singleton),
  destination_url text,
  enabled boolean not null default false,
  updated_at text not null default to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);
revoke all on private.cross_project_backup_sender from public,anon,authenticated;

create table if not exists private.cross_project_backup_trigger (
  singleton boolean primary key default true check (singleton),
  token_sha256 text,
  worker_url text,
  enabled boolean not null default false,
  schedule_cron text,
  updated_at text not null default to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);
revoke all on private.cross_project_backup_trigger from public,anon,authenticated;

create table if not exists public.backup_manifest_entries (
  backup_run_id text not null references public.backup_runs(id) on delete cascade,
  object_key text not null,
  object_kind text not null,
  plaintext_sha256 text not null,
  plaintext_bytes bigint not null,
  source_ref text,
  created_at text not null,
  primary key(backup_run_id,object_key)
);
alter table public.backup_manifest_entries enable row level security;
revoke all on public.backup_manifest_entries from anon,authenticated;

create or replace function public.trustrelay_bootstrap_backup_sender_secrets_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,pg_catalog
as $$
declare
  v_token text:=encode(gen_random_bytes(32),'hex');
  v_key text:=encode(gen_random_bytes(32),'hex');
  v_id uuid;
begin
  select id into v_id from vault.secrets where name='trustrelay_cross_project_backup_token' limit 1;
  if v_id is null then
    perform vault.create_secret(v_token,'trustrelay_cross_project_backup_token','TrustRelay cross-project backup ingress token');
  else
    perform vault.update_secret(v_id,v_token,'trustrelay_cross_project_backup_token','TrustRelay cross-project backup ingress token');
  end if;

  select id into v_id from vault.secrets where name='trustrelay_backup_encryption_key' limit 1;
  if v_id is null then
    perform vault.create_secret(v_key,'trustrelay_backup_encryption_key','TrustRelay AES-256 backup encryption key');
  else
    perform vault.update_secret(v_id,v_key,'trustrelay_backup_encryption_key','TrustRelay AES-256 backup encryption key');
  end if;

  return jsonb_build_object(
    'ok',true,
    'tokenSha256',encode(digest(v_token,'sha256'),'hex'),
    'encryptionKeySha256',encode(digest(v_key,'sha256'),'hex')
  );
end;
$$;

create or replace function public.trustrelay_set_backup_receiver_hash_v10(p_sha256 text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_sha256 is null or length(p_sha256)<>64 then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_TOKEN_HASH_INVALID');
  end if;
  insert into private.cross_project_backup_receiver(singleton,ingress_token_sha256,enabled,recovery_key_received,updated_at)
  values(true,lower(p_sha256),true,false,v_now)
  on conflict(singleton) do update set ingress_token_sha256=excluded.ingress_token_sha256,enabled=true,updated_at=excluded.updated_at;
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.trustrelay_validate_backup_receiver_token_v10(p_token text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare v private.cross_project_backup_receiver%rowtype;
begin
  select * into v from private.cross_project_backup_receiver where singleton=true;
  if not found or not v.enabled then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_RECEIVER_DISABLED');
  end if;
  if encode(digest(coalesce(p_token,''),'sha256'),'hex')<>v.ingress_token_sha256 then
    return jsonb_build_object('ok',false,'status',401,'code','BACKUP_RECEIVER_TOKEN_INVALID');
  end if;
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.trustrelay_store_backup_recovery_key_v10(p_token text,p_key text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,pg_catalog
as $$
declare v_check jsonb; v_id uuid; v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_check:=public.trustrelay_validate_backup_receiver_token_v10(p_token);
  if coalesce((v_check->>'ok')::boolean,false)=false then return v_check; end if;
  if p_key is null or length(p_key)<>64 or p_key !~ '^[0-9a-fA-F]{64}$' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_RECOVERY_KEY_INVALID');
  end if;
  select id into v_id from vault.secrets where name='trustrelay_backup_recovery_key' limit 1;
  if v_id is null then
    perform vault.create_secret(lower(p_key),'trustrelay_backup_recovery_key','Recovery-only copy of TrustRelay backup key');
  else
    perform vault.update_secret(v_id,lower(p_key),'trustrelay_backup_recovery_key','Recovery-only copy of TrustRelay backup key');
  end if;
  update private.cross_project_backup_receiver set recovery_key_received=true,updated_at=v_now where singleton=true;
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.trustrelay_set_backup_sender_destination_v10(p_url text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,pg_catalog
as $$
declare v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_url is null or p_url !~ '^https://[a-z0-9-]+\.supabase\.co/functions/v1/trustrelay-backup-receiver-v10$' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_DESTINATION_INVALID');
  end if;
  insert into private.cross_project_backup_sender(singleton,destination_url,enabled,updated_at)
  values(true,p_url,true,v_now)
  on conflict(singleton) do update set destination_url=excluded.destination_url,enabled=true,updated_at=excluded.updated_at;
  return jsonb_build_object('ok',true,'destinationUrl',p_url);
end;
$$;

create or replace function public.trustrelay_send_backup_recovery_key_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,net,pg_catalog
as $$
declare v_dest text; v_token text; v_key text; v_id bigint;
begin
  select destination_url into v_dest from private.cross_project_backup_sender where singleton=true and enabled=true;
  select decrypted_secret into v_token from vault.decrypted_secrets where name='trustrelay_cross_project_backup_token' limit 1;
  select decrypted_secret into v_key from vault.decrypted_secrets where name='trustrelay_backup_encryption_key' limit 1;
  if coalesce(v_dest,'')='' or coalesce(v_token,'')='' or coalesce(v_key,'')='' then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_SENDER_NOT_READY');
  end if;
  select net.http_post(
    url:=v_dest||'?action=bootstrap',
    headers:=jsonb_build_object('content-type','application/json','x-trustrelay-backup-token',v_token),
    body:=jsonb_build_object('recoveryKey',v_key),
    timeout_milliseconds:=30000
  ) into v_id;
  return jsonb_build_object('ok',true,'requestId',v_id);
end;
$$;

create or replace function public.trustrelay_encrypt_and_send_backup_blob_v10(
  p_object_key text,
  p_plaintext_base64 text,
  p_object_kind text,
  p_source_ref text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,net,pg_catalog
as $$
declare
  v_dest text;
  v_token text;
  v_key text;
  v_plain bytea;
  v_sha text;
  v_cipher text;
  v_id bigint;
begin
  if p_object_key is null or p_object_key='' or p_object_key like '%..%' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_OBJECT_KEY_INVALID');
  end if;
  v_plain:=decode(p_plaintext_base64,'base64');
  v_sha:=encode(digest(v_plain,'sha256'),'hex');

  select destination_url into v_dest from private.cross_project_backup_sender where singleton=true and enabled=true;
  select decrypted_secret into v_token from vault.decrypted_secrets where name='trustrelay_cross_project_backup_token' limit 1;
  select decrypted_secret into v_key from vault.decrypted_secrets where name='trustrelay_backup_encryption_key' limit 1;
  if coalesce(v_dest,'')='' or coalesce(v_token,'')='' or coalesce(v_key,'')='' then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_SENDER_NOT_READY');
  end if;

  v_cipher:=encode(pgp_sym_encrypt(p_plaintext_base64,v_key,'cipher-algo=aes256,compress-algo=1'),'base64');

  select net.http_post(
    url:=v_dest||'?action=put',
    headers:=jsonb_build_object('content-type','application/json','x-trustrelay-backup-token',v_token),
    body:=jsonb_build_object(
      'objectKey',p_object_key,
      'ciphertext',v_cipher,
      'plaintextSha256',v_sha,
      'plaintextBytes',octet_length(v_plain),
      'objectKind',p_object_kind,
      'sourceRef',p_source_ref
    ),
    timeout_milliseconds:=30000
  ) into v_id;

  return jsonb_build_object('ok',true,'requestId',v_id,'plaintextSha256',v_sha,'plaintextBytes',octet_length(v_plain));
end;
$$;

create or replace function public.trustrelay_request_remote_backup_verify_v10(p_object_key text,p_expected_sha256 text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,net,pg_catalog
as $$
declare v_dest text; v_token text; v_id bigint;
begin
  select destination_url into v_dest from private.cross_project_backup_sender where singleton=true and enabled=true;
  select decrypted_secret into v_token from vault.decrypted_secrets where name='trustrelay_cross_project_backup_token' limit 1;
  if coalesce(v_dest,'')='' or coalesce(v_token,'')='' then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_SENDER_NOT_READY');
  end if;
  select net.http_post(
    url:=v_dest||'?action=verify',
    headers:=jsonb_build_object('content-type','application/json','x-trustrelay-backup-token',v_token),
    body:=jsonb_build_object('objectKey',p_object_key,'expectedSha256',p_expected_sha256),
    timeout_milliseconds:=30000
  ) into v_id;
  return jsonb_build_object('ok',true,'requestId',v_id);
end;
$$;

create or replace function public.trustrelay_backup_http_result_v10(p_request_id bigint)
returns jsonb
language plpgsql
security definer
set search_path=public,net,pg_catalog
as $$
declare v_status integer; v_body text; v_error text;
begin
  select status_code,content,error_msg into v_status,v_body,v_error
  from net._http_response where id=p_request_id;
  if not found then return jsonb_build_object('ok',false,'pending',true); end if;
  return jsonb_build_object('ok',v_status between 200 and 299,'pending',false,'status',v_status,'body',v_body,'error',v_error);
end;
$$;

create or replace function public.trustrelay_verify_recovery_ciphertext_v10(p_ciphertext text,p_expected_sha256 text)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,pg_catalog
as $$
declare v_key text; v_plain_b64 text; v_sha text;
begin
  select decrypted_secret into v_key from vault.decrypted_secrets where name='trustrelay_backup_recovery_key' limit 1;
  if coalesce(v_key,'')='' then
    return jsonb_build_object('ok',false,'status',503,'code','RECOVERY_KEY_MISSING');
  end if;
  begin
    v_plain_b64:=pgp_sym_decrypt(decode(p_ciphertext,'base64'),v_key);
  exception when others then
    return jsonb_build_object('ok',false,'status',422,'code','BACKUP_DECRYPT_FAILED');
  end;
  v_sha:=encode(digest(decode(v_plain_b64,'base64'),'sha256'),'hex');
  return jsonb_build_object('ok',v_sha=lower(p_expected_sha256),'sha256',v_sha);
end;
$$;

create or replace function public.trustrelay_backup_run_start_cross_v10(
  p_id text,p_environment text,p_bucket text,p_object_prefix text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  insert into public.backup_runs(id,environment,provider,bucket,object_prefix,status,started_at)
  values(p_id,p_environment,'supabase_cross_project',p_bucket,p_object_prefix,'running',v_now);
  return jsonb_build_object('ok',true,'id',p_id,'startedAt',v_now);
end;
$$;

create or replace function public.trustrelay_backup_manifest_entry_v10(
  p_run_id text,p_object_key text,p_object_kind text,p_sha256 text,p_bytes bigint,p_source_ref text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  insert into public.backup_manifest_entries(backup_run_id,object_key,object_kind,plaintext_sha256,plaintext_bytes,source_ref,created_at)
  values(p_run_id,p_object_key,p_object_kind,lower(p_sha256),p_bytes,p_source_ref,v_now)
  on conflict(backup_run_id,object_key) do nothing;
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.trustrelay_backup_manifest_entries_v10(p_run_id text)
returns jsonb
language sql
security definer
set search_path=public,pg_catalog
as $$
  select jsonb_build_object(
    'ok',true,
    'entries',coalesce(jsonb_agg(jsonb_build_object(
      'objectKey',object_key,'objectKind',object_kind,'sha256',plaintext_sha256,
      'bytes',plaintext_bytes,'sourceRef',source_ref
    ) order by object_key),'[]'::jsonb)
  )
  from public.backup_manifest_entries where backup_run_id=p_run_id;
$$;

create or replace function public.trustrelay_validate_cross_backup_trigger_v10(p_token text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare v private.cross_project_backup_trigger%rowtype;
begin
  select * into v from private.cross_project_backup_trigger where singleton=true;
  if not found or not v.enabled then return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_DISABLED'); end if;
  if encode(digest(coalesce(p_token,''),'sha256'),'hex')<>v.token_sha256 then
    return jsonb_build_object('ok',false,'status',401,'code','BACKUP_TRIGGER_INVALID');
  end if;
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.trustrelay_fire_cross_backup_v10(p_action text default 'run',p_run_id text default null)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,net,pg_catalog
as $$
declare v private.cross_project_backup_trigger%rowtype; v_token text; v_id bigint; v_body jsonb;
begin
  select * into v from private.cross_project_backup_trigger where singleton=true and enabled=true;
  if not found then return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_DISABLED'); end if;
  select decrypted_secret into v_token from vault.decrypted_secrets where name='trustrelay_cross_backup_scheduler_token' limit 1;
  if coalesce(v_token,'')='' then return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_TOKEN_MISSING'); end if;
  v_body:=jsonb_build_object('action',p_action);
  if p_run_id is not null then v_body:=v_body||jsonb_build_object('runId',p_run_id); end if;
  select net.http_post(
    url:=v.worker_url,
    headers:=jsonb_build_object('content-type','application/json','x-trustrelay-backup-trigger',v_token),
    body:=v_body,
    timeout_milliseconds:=300000
  ) into v_id;
  return jsonb_build_object('ok',true,'requestId',v_id);
end;
$$;

create or replace function public.trustrelay_configure_cross_backup_schedule_v10(
  p_worker_url text,p_cron text default '17 4 * * *'
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,extensions,cron,pg_catalog
as $$
declare
  v_token text:=encode(gen_random_bytes(32),'hex');
  v_hash text:=encode(digest(v_token,'sha256'),'hex');
  v_id uuid;
  v_jobid bigint;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_worker_url is null or p_worker_url !~ '^https://[a-z0-9-]+\.supabase\.co/functions/v1/trustrelay-cross-backup-v10$' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_WORKER_URL_INVALID');
  end if;

  select id into v_id from vault.secrets where name='trustrelay_cross_backup_scheduler_token' limit 1;
  if v_id is null then
    perform vault.create_secret(v_token,'trustrelay_cross_backup_scheduler_token','TrustRelay cross-project backup scheduler token');
  else
    perform vault.update_secret(v_id,v_token,'trustrelay_cross_backup_scheduler_token','TrustRelay cross-project backup scheduler token');
  end if;

  insert into private.cross_project_backup_trigger(singleton,token_sha256,worker_url,enabled,schedule_cron,updated_at)
  values(true,v_hash,p_worker_url,true,p_cron,v_now)
  on conflict(singleton) do update set token_sha256=excluded.token_sha256,worker_url=excluded.worker_url,enabled=true,schedule_cron=excluded.schedule_cron,updated_at=excluded.updated_at;

  perform cron.unschedule(jobid) from cron.job where jobname='trustrelay-cross-project-backup-v10';
  select cron.schedule('trustrelay-cross-project-backup-v10',p_cron,$cmd$select public.trustrelay_fire_cross_backup_v10('run',null);$cmd$) into v_jobid;
  return jsonb_build_object('ok',true,'jobId',v_jobid,'schedule',p_cron);
end;
$$;

revoke all on function public.trustrelay_bootstrap_backup_sender_secrets_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_set_backup_receiver_hash_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_validate_backup_receiver_token_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_store_backup_recovery_key_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_set_backup_sender_destination_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_send_backup_recovery_key_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_encrypt_and_send_backup_blob_v10(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_request_remote_backup_verify_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_http_result_v10(bigint) from public,anon,authenticated;
revoke all on function public.trustrelay_verify_recovery_ciphertext_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_run_start_cross_v10(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_manifest_entry_v10(text,text,text,text,bigint,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_manifest_entries_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_validate_cross_backup_trigger_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_fire_cross_backup_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_configure_cross_backup_schedule_v10(text,text) from public,anon,authenticated;

grant execute on function public.trustrelay_bootstrap_backup_sender_secrets_v10() to service_role;
grant execute on function public.trustrelay_set_backup_receiver_hash_v10(text) to service_role;
grant execute on function public.trustrelay_validate_backup_receiver_token_v10(text) to service_role;
grant execute on function public.trustrelay_store_backup_recovery_key_v10(text,text) to service_role;
grant execute on function public.trustrelay_set_backup_sender_destination_v10(text) to service_role;
grant execute on function public.trustrelay_send_backup_recovery_key_v10() to service_role;
grant execute on function public.trustrelay_encrypt_and_send_backup_blob_v10(text,text,text,text) to service_role;
grant execute on function public.trustrelay_request_remote_backup_verify_v10(text,text) to service_role;
grant execute on function public.trustrelay_backup_http_result_v10(bigint) to service_role;
grant execute on function public.trustrelay_verify_recovery_ciphertext_v10(text,text) to service_role;
grant execute on function public.trustrelay_backup_run_start_cross_v10(text,text,text,text) to service_role;
grant execute on function public.trustrelay_backup_manifest_entry_v10(text,text,text,text,bigint,text) to service_role;
grant execute on function public.trustrelay_backup_manifest_entries_v10(text) to service_role;
grant execute on function public.trustrelay_validate_cross_backup_trigger_v10(text) to service_role;
grant execute on function public.trustrelay_fire_cross_backup_v10(text,text) to service_role;
grant execute on function public.trustrelay_configure_cross_backup_schedule_v10(text,text) to service_role;

notify pgrst,'reload schema';
