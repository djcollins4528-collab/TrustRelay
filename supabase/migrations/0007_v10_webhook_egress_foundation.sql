-- TrustRelay live migration 20261002014240: trustrelay_v10_webhook_egress_foundation
-- Recorded from trustrelay-staging after successful application.

do $$
begin
  if not exists(select 1 from vault.secrets where name='trustrelay-webhook-egress-v10') then
    perform vault.create_secret(
      encode(gen_random_bytes(32),'hex'),
      'trustrelay-webhook-egress-v10',
      'TrustRelay v1.0 internal webhook egress authentication secret'
    );
  end if;

  -- Environment-specific egress URL is provisioned after the Edge Function is deployed.
  -- Never seed a URL from another Supabase project here.
end $$;

create or replace function public.trustrelay_webhook_egress_secret_v10()
returns jsonb
language plpgsql
security definer
set search_path=vault,pg_catalog
as $$
declare
  v_secret text;
begin
  select decrypted_secret into v_secret
  from vault.decrypted_secrets
  where name='trustrelay-webhook-egress-v10'
  order by created_at desc
  limit 1;

  if v_secret is null or length(v_secret)<32 then
    return jsonb_build_object('ok',false,'status',503,'code','WEBHOOK_EGRESS_SECRET_UNAVAILABLE');
  end if;

  return jsonb_build_object('ok',true,'secret',v_secret);
end;
$$;

revoke all on function public.trustrelay_webhook_egress_secret_v10() from public,anon,authenticated;
grant execute on function public.trustrelay_webhook_egress_secret_v10() to service_role;
