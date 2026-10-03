-- TrustRelay v1.2 portal-secret retirement, phase 2.
-- Internal verifier decisions no longer require recoverable portal credentials.
-- Convert any historical portal keys into non-secret audit identities and delete their Vault secrets.

do $$
declare
  v_row record;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_hash text;
begin
  for v_row in
    select id,organization_id,secret_vault_id
    from public.api_keys
    where key_type='portal'
    for update
  loop
    if v_row.secret_vault_id is not null then
      delete from vault.secrets where id=v_row.secret_vault_id;
    end if;

    v_hash:=encode(digest(gen_random_bytes(32),'sha256'),'hex');

    update public.api_keys
    set prefix='tr_internal',
        key_hash=v_hash,
        last_four=null,
        secret_vault_id=null,
        updated_at=v_now
    where id=v_row.id;

    perform private.trustrelay_append_org_audit_v09(
      v_row.organization_id,null,'api_key.portal_secret_retired','api_key',v_row.id,
      jsonb_build_object('credentialStored',false,'retiredAt',v_now)
    );
  end loop;
end $$;

notify pgrst,'reload schema';