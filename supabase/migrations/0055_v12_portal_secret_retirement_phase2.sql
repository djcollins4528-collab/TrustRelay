-- TrustRelay v1.2 portal-secret retirement, phase 2.
-- Portal rows are non-credential audit identities. Partner credentials remain
-- bounded-expiry credentials. Destroy all recoverable legacy portal secrets.

alter table public.api_keys
  drop constraint if exists api_keys_active_requires_bounded_expiry;

alter table public.api_keys
  add constraint api_keys_active_requires_bounded_expiry
  check (
    (
      key_type='portal'
      and prefix='tr_internal'
      and secret_vault_id is null
      and last_four is null
    )
    or revoked_at is not null
    or (
      key_type='partner'
      and expires_at is not null
      and btrim(expires_at)<>''
      and expires_at::timestamptz > created_at::timestamptz
      and expires_at::timestamptz <= created_at::timestamptz + interval '365 days'
    )
  ) not valid;

with target as materialized (
  select secret_vault_id
  from public.api_keys
  where key_type='portal' and secret_vault_id is not null
),
updated as (
  update public.api_keys
  set
    name='Verifier Portal Internal',
    prefix='tr_internal',
    key_hash=encode(digest(gen_random_bytes(32),'sha256'),'hex'),
    last_four=null,
    secret_vault_id=null,
    expires_at=null,
    updated_at=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  where key_type='portal'
  returning id
)
delete from vault.secrets s
using target t
where s.id=t.secret_vault_id;

alter table public.api_keys
  validate constraint api_keys_active_requires_bounded_expiry;

drop function if exists public.trustrelay_get_portal_key_v07(uuid,text);

notify pgrst,'reload schema';
