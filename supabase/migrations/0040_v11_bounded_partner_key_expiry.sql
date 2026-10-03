-- TrustRelay v1.1 maximum hardening
-- Make partner API-key expiration mandatory at storage and runtime boundaries.

update public.api_keys
set expires_at=to_char((clock_timestamp()+interval '90 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    updated_at=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
where revoked_at is null and (expires_at is null or btrim(expires_at)='');

create or replace function private.trustrelay_api_key_unexpired_v10(p_expires_at text)
returns boolean
language plpgsql
volatile
security definer
set search_path='pg_catalog'
as $$
begin
  if p_expires_at is null or btrim(p_expires_at)='' then return false; end if;
  begin
    return p_expires_at::timestamptz > clock_timestamp();
  exception when others then
    return false;
  end;
end;
$$;

revoke all on function private.trustrelay_api_key_unexpired_v10(text) from public,anon,authenticated;
grant execute on function private.trustrelay_api_key_unexpired_v10(text) to service_role;

do $$
declare r record; d text;
begin
  for r in
    select p.oid
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in (
      'trustrelay_prepare_decision_v05',
      'trustrelay_record_decision_partner_v05',
      'trustrelay_get_decision_partner_v05'
    )
  loop
    d:=pg_get_functiondef(r.oid);
    d:=replace(
      d,
      'where key_hash = v_hash and revoked_at is null and (expires_at is null or expires_at::timestamptz > clock_timestamp())',
      'where key_hash = v_hash and revoked_at is null and private.trustrelay_api_key_unexpired_v10(expires_at)'
    );
    d:=replace(
      d,
      'where key_hash = v_hash and revoked_at is null' || chr(10),
      'where key_hash = v_hash and revoked_at is null and private.trustrelay_api_key_unexpired_v10(expires_at)' || chr(10)
    );
    execute d;
  end loop;
end $$;

alter table public.api_keys drop constraint if exists api_keys_active_requires_bounded_expiry;
alter table public.api_keys add constraint api_keys_active_requires_bounded_expiry
check (
  revoked_at is not null or (
    expires_at is not null and btrim(expires_at)<>'' and
    expires_at::timestamptz > created_at::timestamptz and
    expires_at::timestamptz <= created_at::timestamptz + interval '365 days'
  )
) not valid;
alter table public.api_keys validate constraint api_keys_active_requires_bounded_expiry;
