-- TrustRelay v1.0 off-site backup control-plane.
-- No external backup is activated by this migration. R2 credentials must be
-- supplied separately in Supabase Vault before scheduling a backup.

create table if not exists public.backup_runs (
  id text primary key,
  environment text not null check (environment in ('staging','production')),
  provider text not null default 'cloudflare_r2',
  bucket text,
  object_prefix text,
  status text not null check (status in ('running','completed','failed')),
  manifest_key text,
  manifest_sha256 text,
  table_count integer not null default 0,
  row_count bigint not null default 0,
  storage_object_count integer not null default 0,
  storage_bytes bigint not null default 0,
  started_at text not null,
  completed_at text,
  error_code text,
  error_message text
);

create table if not exists public.backup_restore_tests (
  id text primary key,
  backup_run_id text not null references public.backup_runs(id) on delete cascade,
  test_type text not null default 'integrity_rehearsal',
  status text not null check (status in ('running','completed','failed')),
  checked_objects integer not null default 0,
  checked_bytes bigint not null default 0,
  mismatch_count integer not null default 0,
  evidence_hash text,
  started_at text not null,
  completed_at text,
  error_code text,
  error_message text
);

alter table public.backup_runs enable row level security;
alter table public.backup_restore_tests enable row level security;

revoke all on public.backup_runs from anon,authenticated;
revoke all on public.backup_restore_tests from anon,authenticated;

create table if not exists private.backup_trigger_config (
  singleton boolean primary key default true check (singleton),
  token_sha256 text not null,
  enabled boolean not null default false,
  function_url text,
  schedule_cron text,
  updated_at text not null
);

revoke all on private.backup_trigger_config from public,anon,authenticated;

create or replace function public.trustrelay_backup_inventory_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_tables jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('schema',table_schema,'table',table_name)
           order by table_schema,table_name),'[]'::jsonb)
  into v_tables
  from information_schema.tables
  where table_type='BASE TABLE'
    and (
      (table_schema='public' and table_name not in ('backup_runs','backup_restore_tests'))
      or (table_schema='private' and table_name='identity_reviewers')
      or (table_schema='auth' and table_name in ('users','identities'))
    );

  return jsonb_build_object(
    'ok',true,
    'formatVersion','trustrelay-backup-v1',
    'tables',v_tables
  );
end;
$$;

create or replace function public.trustrelay_backup_page_v10(
  p_schema text,
  p_table text,
  p_offset integer default 0,
  p_limit integer default 500
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,auth,pg_catalog
as $$
declare
  v_allowed boolean:=false;
  v_rows jsonb;
begin
  if p_offset<0 or p_limit<1 or p_limit>1000 then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_PAGE_ARGUMENT_INVALID');
  end if;

  select exists(
    select 1
    from information_schema.tables
    where table_type='BASE TABLE'
      and table_schema=p_schema
      and table_name=p_table
      and (
        (table_schema='public' and table_name not in ('backup_runs','backup_restore_tests'))
        or (table_schema='private' and table_name='identity_reviewers')
        or (table_schema='auth' and table_name in ('users','identities'))
      )
  ) into v_allowed;

  if not v_allowed then
    return jsonb_build_object('ok',false,'status',403,'code','BACKUP_TABLE_NOT_ALLOWED');
  end if;

  execute format(
    'select coalesce(jsonb_agg(to_jsonb(t)),''[]''::jsonb) from (select * from %I.%I offset %s limit %s) t',
    p_schema,p_table,p_offset,p_limit
  ) into v_rows;

  return jsonb_build_object(
    'ok',true,
    'schema',p_schema,
    'table',p_table,
    'offset',p_offset,
    'limit',p_limit,
    'rows',v_rows,
    'rowCount',jsonb_array_length(v_rows)
  );
end;
$$;

create or replace function public.trustrelay_backup_config_v10()
returns jsonb
language plpgsql
security definer
set search_path=public,vault,pg_catalog
as $$
declare
  v_account_id text;
  v_access_key text;
  v_secret_key text;
  v_bucket text;
  v_jurisdiction text;
begin
  select decrypted_secret into v_account_id
  from vault.decrypted_secrets where name='trustrelay_r2_account_id' limit 1;
  select decrypted_secret into v_access_key
  from vault.decrypted_secrets where name='trustrelay_r2_access_key_id' limit 1;
  select decrypted_secret into v_secret_key
  from vault.decrypted_secrets where name='trustrelay_r2_secret_access_key' limit 1;
  select decrypted_secret into v_bucket
  from vault.decrypted_secrets where name='trustrelay_r2_bucket' limit 1;
  select decrypted_secret into v_jurisdiction
  from vault.decrypted_secrets where name='trustrelay_r2_jurisdiction' limit 1;

  return jsonb_build_object(
    'ok',
      coalesce(v_account_id,'')<>'' and coalesce(v_access_key,'')<>''
      and coalesce(v_secret_key,'')<>'' and coalesce(v_bucket,'')<>'',
    'provider','cloudflare_r2',
    'accountId',v_account_id,
    'accessKeyId',v_access_key,
    'secretAccessKey',v_secret_key,
    'bucket',v_bucket,
    'jurisdiction',coalesce(nullif(v_jurisdiction,''),'us')
  );
end;
$$;

create or replace function public.trustrelay_validate_backup_trigger_v10(p_token text)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,pg_catalog
as $$
declare
  v private.backup_trigger_config%rowtype;
begin
  select * into v from private.backup_trigger_config where singleton=true;
  if not found or not v.enabled then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_DISABLED');
  end if;
  if encode(digest(coalesce(p_token,''),'sha256'),'hex')<>v.token_sha256 then
    return jsonb_build_object('ok',false,'status',401,'code','BACKUP_TRIGGER_INVALID');
  end if;
  return jsonb_build_object('ok',true);
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
    p_id,p_environment,'cloudflare_r2',p_bucket,p_object_prefix,'running',v_now
  );
  return jsonb_build_object('ok',true,'id',p_id,'startedAt',v_now);
end;
$$;

create or replace function public.trustrelay_backup_run_finish_v10(
  p_id text,p_manifest_key text,p_manifest_sha256 text,p_table_count integer,
  p_row_count bigint,p_storage_object_count integer,p_storage_bytes bigint
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  update public.backup_runs
  set status='completed',
      manifest_key=p_manifest_key,
      manifest_sha256=p_manifest_sha256,
      table_count=p_table_count,
      row_count=p_row_count,
      storage_object_count=p_storage_object_count,
      storage_bytes=p_storage_bytes,
      completed_at=v_now,
      error_code=null,
      error_message=null
  where id=p_id;
  return jsonb_build_object('ok',found,'id',p_id,'completedAt',v_now);
end;
$$;

create or replace function public.trustrelay_backup_run_fail_v10(
  p_id text,p_error_code text,p_error_message text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  update public.backup_runs
  set status='failed',
      error_code=left(coalesce(p_error_code,'BACKUP_FAILED'),200),
      error_message=left(coalesce(p_error_message,''),2000),
      completed_at=v_now
  where id=p_id;
  return jsonb_build_object('ok',found,'id',p_id,'completedAt',v_now);
end;
$$;

create or replace function public.trustrelay_backup_restore_test_start_v10(
  p_id text,p_backup_run_id text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  insert into public.backup_restore_tests(
    id,backup_run_id,test_type,status,started_at
  ) values(p_id,p_backup_run_id,'integrity_rehearsal','running',v_now);
  return jsonb_build_object('ok',true,'id',p_id,'startedAt',v_now);
end;
$$;

create or replace function public.trustrelay_backup_restore_test_finish_v10(
  p_id text,p_checked_objects integer,p_checked_bytes bigint,p_mismatch_count integer,p_evidence_hash text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  update public.backup_restore_tests
  set status=case when p_mismatch_count=0 then 'completed' else 'failed' end,
      checked_objects=p_checked_objects,
      checked_bytes=p_checked_bytes,
      mismatch_count=p_mismatch_count,
      evidence_hash=p_evidence_hash,
      completed_at=v_now,
      error_code=case when p_mismatch_count=0 then null else 'BACKUP_INTEGRITY_MISMATCH' end
  where id=p_id;
  return jsonb_build_object('ok',found,'id',p_id,'completedAt',v_now);
end;
$$;

create or replace function public.trustrelay_configure_backup_schedule_v10(
  p_function_url text,
  p_cron text default '17 4 * * *'
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,cron,net,pg_catalog
as $$
declare
  v_token text:=encode(gen_random_bytes(32),'hex');
  v_hash text:=encode(digest(v_token,'sha256'),'hex');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_jobid bigint;
  v_command text;
begin
  if p_function_url is null or p_function_url !~ '^https://[a-z0-9-]+\.supabase\.co/functions/v1/trustrelay-backup-v10$' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_FUNCTION_URL_INVALID');
  end if;

  insert into private.backup_trigger_config(singleton,token_sha256,enabled,function_url,schedule_cron,updated_at)
  values(true,v_hash,true,p_function_url,p_cron,v_now)
  on conflict(singleton) do update set
    token_sha256=excluded.token_sha256,
    enabled=true,
    function_url=excluded.function_url,
    schedule_cron=excluded.schedule_cron,
    updated_at=excluded.updated_at;

  perform cron.unschedule(jobid)
  from cron.job
  where jobname='trustrelay-offsite-backup-v10';

  v_command:=format(
    $cmd$select net.http_post(url := %L, headers := jsonb_build_object('content-type','application/json','x-trustrelay-backup-token',%L), body := '{"action":"run"}'::jsonb, timeout_milliseconds := 300000);$cmd$,
    p_function_url,v_token
  );

  select cron.schedule('trustrelay-offsite-backup-v10',p_cron,v_command) into v_jobid;

  return jsonb_build_object('ok',true,'jobId',v_jobid,'schedule',p_cron,'functionUrl',p_function_url);
end;
$$;

revoke all on function public.trustrelay_backup_inventory_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_backup_page_v10(text,text,integer,integer) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_config_v10() from public,anon,authenticated;
revoke all on function public.trustrelay_validate_backup_trigger_v10(text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_run_start_v10(text,text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_run_finish_v10(text,text,text,integer,bigint,integer,bigint) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_run_fail_v10(text,text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_restore_test_start_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_backup_restore_test_finish_v10(text,integer,bigint,integer,text) from public,anon,authenticated;
revoke all on function public.trustrelay_configure_backup_schedule_v10(text,text) from public,anon,authenticated;

grant execute on function public.trustrelay_backup_inventory_v10() to service_role;
grant execute on function public.trustrelay_backup_page_v10(text,text,integer,integer) to service_role;
grant execute on function public.trustrelay_backup_config_v10() to service_role;
grant execute on function public.trustrelay_validate_backup_trigger_v10(text) to service_role;
grant execute on function public.trustrelay_backup_run_start_v10(text,text,text,text) to service_role;
grant execute on function public.trustrelay_backup_run_finish_v10(text,text,text,integer,bigint,integer,bigint) to service_role;
grant execute on function public.trustrelay_backup_run_fail_v10(text,text,text) to service_role;
grant execute on function public.trustrelay_backup_restore_test_start_v10(text,text) to service_role;
grant execute on function public.trustrelay_backup_restore_test_finish_v10(text,integer,bigint,integer,text) to service_role;
grant execute on function public.trustrelay_configure_backup_schedule_v10(text,text) to service_role;

notify pgrst,'reload schema';
