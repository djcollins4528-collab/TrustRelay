-- TrustRelay v1.0 pinned-DNS webhook egress hardening.
-- Recorded from the live staging migration history.
-- 20261002013741 trustrelay_v10_pinned_dns_webhook_egress

CREATE OR REPLACE FUNCTION public.trustrelay_dispatch_due_webhooks_v09(p_limit integer DEFAULT 50)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'vault', 'extensions', 'net', 'pg_catalog'
AS $function$
declare
  v_row record;
  v_secret text;
  v_relay_secret text;
  v_timestamp text;
  v_sig text;
  v_req bigint;
  v_attempt integer;
  v_now text;
  v_count integer:=0;
  v_limit integer:=least(greatest(coalesce(p_limit,50),1),200);
  v_relay_url text:='https://trustrelay-v1-runtime-staging.onrender.com/internal/webhook-egress';
begin
  select decrypted_secret into v_relay_secret
  from vault.decrypted_secrets
  where name='trustrelay-webhook-egress-v10'
  order by created_at desc
  limit 1;

  if v_relay_secret is null then
    return jsonb_build_object('ok',false,'status',503,'code','WEBHOOK_EGRESS_NOT_CONFIGURED','dispatched',0);
  end if;

  for v_row in
    select d.*,s.endpoint_url,s.secret_vault_id,s.status subscription_status
    from public.webhook_deliveries d
    join public.webhook_subscriptions s on s.id=d.subscription_id
    where d.status in ('pending','retrying')
      and s.status='active'
      and d.attempt_count<d.max_attempts
      and (d.next_attempt_at is null or d.next_attempt_at::timestamptz<=clock_timestamp())
    order by d.created_at
    for update of d skip locked
    limit v_limit
  loop
    select decrypted_secret into v_secret
    from vault.decrypted_secrets where id=v_row.secret_vault_id;
    if v_secret is null then
      update public.webhook_deliveries
      set status='dead_letter',last_error='WEBHOOK_SECRET_UNAVAILABLE',
          dead_lettered_at=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
          next_attempt_at=null
      where id=v_row.id;
      continue;
    end if;

    v_now:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    v_timestamp:=floor(extract(epoch from clock_timestamp()))::bigint::text;
    v_sig:=encode(hmac(v_timestamp||'.'||v_row.payload_json,v_secret,'sha256'),'hex');
    v_attempt:=v_row.attempt_count+1;

    v_req:=net.http_post(
      url:=v_relay_url,
      body:=jsonb_build_object(
        'endpointUrl',v_row.endpoint_url,
        'body',v_row.payload_json,
        'headers',jsonb_build_object(
          'Content-Type','application/json',
          'User-Agent','TrustRelay-Webhook/0.9',
          'X-TrustRelay-Event',v_row.event_type,
          'X-TrustRelay-Delivery',v_row.id,
          'X-TrustRelay-Timestamp',v_timestamp,
          'X-TrustRelay-Signature','v1='||v_sig
        )
      ),
      headers:=jsonb_build_object(
        'Content-Type','application/json',
        'Authorization','Bearer '||v_relay_secret,
        'User-Agent','TrustRelay-Dispatcher/1.0'
      ),
      timeout_milliseconds:=60000
    );

    update public.webhook_deliveries set
      status='dispatched',attempt_count=v_attempt,attempted_at=v_now,
      net_request_id=v_req,next_attempt_at=null
    where id=v_row.id;

    insert into public.webhook_delivery_attempts(
      id,delivery_id,attempt_number,net_request_id,request_timestamp,created_at
    ) values (
      'wha_'||replace(gen_random_uuid()::text,'-',''),v_row.id,v_attempt,v_req,v_timestamp,v_now
    ) on conflict(delivery_id,attempt_number) do update set
      net_request_id=excluded.net_request_id,request_timestamp=excluded.request_timestamp;

    v_count:=v_count+1;
  end loop;

  return jsonb_build_object('ok',true,'dispatched',v_count,'egress','pinned_dns_tls_v1');
end;
$function$;

REVOKE ALL ON FUNCTION public.trustrelay_dispatch_due_webhooks_v09(integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.trustrelay_dispatch_due_webhooks_v09(integer) TO service_role;

INSERT INTO public.production_readiness_controls(
  control_key,category,required,status,evidence,owner_note,updated_at
) VALUES (
  'webhook_egress_policy','security',true,'unknown',
  'v1.0 pinned-DNS TLS egress relay deployed; real delivery and private-target rejection verification pending.',
  'Production webhook delivery must use the pinned-DNS relay and pass positive/negative E2E verification.',
  to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
)
ON CONFLICT(control_key) DO UPDATE SET
  category='security',
  required=true,
  status='unknown',
  evidence=excluded.evidence,
  owner_note=excluded.owner_note,
  updated_at=excluded.updated_at;
