-- TrustRelay v1.0 encrypted backup run metadata.

alter table public.backup_runs
  add column if not exists recovery_key_kid text,
  add column if not exists wrapped_data_key_b64 text;

create table if not exists public.disaster_recovery_runs (
  run_id text primary key,
  source_environment text not null,
  source_project_ref text not null,
  recovery_key_kid text not null,
  wrapped_data_key_b64 text not null,
  manifest_sha256 text,
  status text not null check (status in ('receiving','completed','failed')),
  created_at text not null,
  completed_at text
);
alter table public.disaster_recovery_runs enable row level security;
revoke all on public.disaster_recovery_runs from anon,authenticated;

create or replace function public.trustrelay_backup_run_crypto_v10(
  p_id text,p_recovery_key_kid text,p_wrapped_data_key_b64 text
)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
begin
  update public.backup_runs
  set recovery_key_kid=p_recovery_key_kid,
      wrapped_data_key_b64=p_wrapped_data_key_b64
  where id=p_id;
  return jsonb_build_object('ok',found,'id',p_id);
end;
$$;

revoke all on function public.trustrelay_backup_run_crypto_v10(text,text,text) from public,anon,authenticated;
grant execute on function public.trustrelay_backup_run_crypto_v10(text,text,text) to service_role;

notify pgrst,'reload schema';
