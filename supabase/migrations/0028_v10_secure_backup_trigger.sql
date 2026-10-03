-- TrustRelay v1.0 secure backup trigger.
-- Keep the scheduled backup trigger token encrypted in Supabase Vault and expose
-- only a service-role wrapper to fire run/verify actions.

create or replace function public.trustrelay_fire_backup_v10(
  p_action text default 'run',
  p_run_id text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,vault,net,pg_catalog
as $$
declare
  v private.backup_trigger_config%rowtype;
  v_token text;
  v_request_id bigint;
  v_body jsonb;
begin
  if p_action not in ('run','verify') then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_ACTION_INVALID');
  end if;

  select * into v
  from private.backup_trigger_config
  where singleton=true and enabled=true;

  if not found then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_DISABLED');
  end if;

  select decrypted_secret into v_token
  from vault.decrypted_secrets
  where name='trustrelay_backup_trigger_token'
  limit 1;

  if coalesce(v_token,'')='' then
    return jsonb_build_object('ok',false,'status',503,'code','BACKUP_TRIGGER_TOKEN_MISSING');
  end if;

  v_body:=jsonb_build_object('action',p_action);
  if p_run_id is not null then
    v_body:=v_body||jsonb_build_object('runId',p_run_id);
  end if;

  select net.http_post(
    url:=v.function_url,
    headers:=jsonb_build_object(
      'content-type','application/json',
      'x-trustrelay-backup-token',v_token
    ),
    body:=v_body,
    timeout_milliseconds:=300000
  ) into v_request_id;

  return jsonb_build_object('ok',true,'requestId',v_request_id,'action',p_action);
end;
$$;

create or replace function public.trustrelay_configure_backup_schedule_v10(
  p_function_url text,
  p_cron text default '17 4 * * *'
)
returns jsonb
language plpgsql
security definer
set search_path=public,private,extensions,vault,cron,pg_catalog
as $$
declare
  v_token text:=encode(gen_random_bytes(32),'hex');
  v_hash text:=encode(digest(v_token,'sha256'),'hex');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_jobid bigint;
  v_secret_id uuid;
begin
  if p_function_url is null or p_function_url !~ '^https://[a-z0-9-]+\.supabase\.co/functions/v1/trustrelay-backup-v10$' then
    return jsonb_build_object('ok',false,'status',400,'code','BACKUP_FUNCTION_URL_INVALID');
  end if;

  select id into v_secret_id
  from vault.secrets
  where name='trustrelay_backup_trigger_token'
  limit 1;

  if v_secret_id is null then
    perform vault.create_secret(v_token,'trustrelay_backup_trigger_token','TrustRelay off-site backup scheduler trigger token');
  else
    perform vault.update_secret(v_secret_id,v_token,'trustrelay_backup_trigger_token','TrustRelay off-site backup scheduler trigger token');
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

  select cron.schedule(
    'trustrelay-offsite-backup-v10',
    p_cron,
    $$select public.trustrelay_fire_backup_v10('run',null);$$
  ) into v_jobid;

  return jsonb_build_object('ok',true,'jobId',v_jobid,'schedule',p_cron,'functionUrl',p_function_url);
end;
$$;

revoke all on function public.trustrelay_fire_backup_v10(text,text) from public,anon,authenticated;
revoke all on function public.trustrelay_configure_backup_schedule_v10(text,text) from public,anon,authenticated;
grant execute on function public.trustrelay_fire_backup_v10(text,text) to service_role;
grant execute on function public.trustrelay_configure_backup_schedule_v10(text,text) to service_role;

notify pgrst,'reload schema';
