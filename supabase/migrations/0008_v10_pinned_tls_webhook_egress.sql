-- TrustRelay live migration 20261002014805: trustrelay_v10_pinned_tls_webhook_egress
-- Recorded from trustrelay-staging after successful application.

create or replace function public.trustrelay_dispatch_due_webhooks_v09(p_limit integer default 50)
returns jsonb
language plpgsql
security definer
set search_path=public,vault,extensions,net,pg_catalog
as $$
declare
  v_row record;
  v_webhook_secret text;
  v_egress_secret text;
  v_egress_url text;
  v_timestamp text;
  v_sig text;
  v_req bigint;
  v_attempt integer;
  v_now text;
  v_count integer:=0;
  v_limit integer:=least(greatest(coalesce(p_limit,50),1),200);
begin
  select decrypted_secret into v_egress_secret
  from vault.decrypted_secrets
  where name='trustrelay-webhook-egress-v10'
  order by created_at desc
  limit 1;

  select decrypted_secret into v_egress_url
  from vault.decrypted_secrets
  where name='trustrelay-webhook-egress-url-v10'
  order by created_at desc
  limit 1;

  if v_egress_secret is null or v_egress_url is null or v_egress_url !~ '^https://[^[:space:]]+$' then
    raise exception 'WEBHOOK_EGRESS_CONFIG_UNAVAILABLE';
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
    select decrypted_secret into v_webhook_secret
    from vault.decrypted_secrets where id=v_row.secret_vault_id;

    if v_webhook_secret is null then
      update public.webhook_deliveries
      set status='dead_letter',last_error='WEBHOOK_SECRET_UNAVAILABLE',
          dead_lettered_at=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
          next_attempt_at=null
      where id=v_row.id;
      continue;
    end if;

    v_now:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    v_timestamp:=floor(extract(epoch from clock_timestamp()))::bigint::text;
    v_sig:=encode(hmac(v_timestamp||'.'||v_row.payload_json,v_webhook_secret,'sha256'),'hex');
    v_attempt:=v_row.attempt_count+1;

    v_req:=net.http_post(
      url:=v_egress_url,
      body:=jsonb_build_object(
        'endpointUrl',v_row.endpoint_url,
        'payloadJson',v_row.payload_json,
        'eventType',v_row.event_type,
        'deliveryId',v_row.id,
        'timestamp',v_timestamp,
        'signature','v1='||v_sig
      ),
      headers:=jsonb_build_object(
        'Content-Type','application/json',
        'User-Agent','TrustRelay-Webhook-Dispatcher/1.0',
        'X-TrustRelay-Egress-Key',v_egress_secret
      ),
      timeout_milliseconds:=20000
    );

    update public.webhook_deliveries set
      status='dispatched',attempt_count=v_attempt,attempted_at=v_now,
      net_request_id=v_req,next_attempt_at=null
    where id=v_row.id;

    insert into public.webhook_delivery_attempts(
      id,delivery_id,attempt_number,net_request_id,request_timestamp,created_at
    ) values (
      'wha_'||replace(gen_random_uuid()::text,'-',''),
      v_row.id,v_attempt,v_req,v_timestamp,v_now
    ) on conflict(delivery_id,attempt_number) do update set
      net_request_id=excluded.net_request_id,
      request_timestamp=excluded.request_timestamp;

    v_count:=v_count+1;
  end loop;

  return jsonb_build_object('ok',true,'dispatched',v_count,'transport','pinned_tls_egress_v10');
end;
$$;

create or replace function public.trustrelay_reconcile_webhooks_v09(p_limit integer default 100)
returns jsonb
language plpgsql
security definer
set search_path=public,private,net,pg_catalog
as $$
declare
  v_row record;
  v_success boolean;
  v_now text;
  v_next text;
  v_count integer:=0;
  v_limit integer:=least(greatest(coalesce(p_limit,100),1),500);
  v_sub_failures integer;
  v_threshold integer;
  v_sub_status text;
  v_auto_pause boolean;
  v_duration integer;
begin
  for v_row in
    select d.*,r.status_code,r.content,r.error_msg,r.timed_out,r.created response_created,r.headers response_headers
    from public.webhook_deliveries d
    join net._http_response r on r.id=d.net_request_id
    where d.status='dispatched' and d.net_request_id is not null
    order by d.attempted_at
    for update of d skip locked
    limit v_limit
  loop
    v_now:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    v_success:=not coalesce(v_row.timed_out,false)
      and v_row.error_msg is null
      and v_row.status_code between 200 and 299;

    v_duration:=null;
    begin
      v_duration:=nullif(v_row.response_headers->>'x-trustrelay-egress-duration-ms','')::integer;
    exception when others then
      v_duration:=null;
    end;

    select consecutive_failures,failure_threshold,status
    into v_sub_failures,v_threshold,v_sub_status
    from public.webhook_subscriptions
    where id=v_row.subscription_id
    for update;

    v_sub_failures:=coalesce(v_sub_failures,0);
    v_threshold:=coalesce(v_threshold,10);
    v_auto_pause:=not v_success and v_sub_status='active' and v_sub_failures+1>=v_threshold;

    if not v_success and v_row.attempt_count<v_row.max_attempts then
      v_next:=to_char(
        (clock_timestamp()+case v_row.attempt_count
          when 1 then interval '1 minute'
          when 2 then interval '5 minutes'
          when 3 then interval '30 minutes'
          when 4 then interval '2 hours'
          else interval '6 hours' end
        ) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      );
    else
      v_next:=null;
    end if;

    update public.webhook_deliveries set
      status=case when v_success then 'delivered'
                  when attempt_count>=max_attempts then 'dead_letter'
                  else 'retrying' end,
      response_status=v_row.status_code,
      response_body_excerpt=left(coalesce(v_row.content,''),1000),
      last_error=left(coalesce(
        v_row.error_msg,
        case when v_row.timed_out then 'TIMEOUT'
             when not v_success then 'HTTP_'||coalesce(v_row.status_code::text,'UNKNOWN')
             else null end
      ),1000),
      delivered_at=case when v_success then v_now else delivered_at end,
      dead_lettered_at=case when not v_success and attempt_count>=max_attempts then v_now else dead_lettered_at end,
      next_attempt_at=v_next,
      net_request_id=null,
      last_attempt_at=v_now,
      last_attempt_duration_ms=v_duration
    where id=v_row.id;

    update public.webhook_delivery_attempts set
      response_status=v_row.status_code,
      response_body_excerpt=left(coalesce(v_row.content,''),1000),
      error_text=left(coalesce(
        v_row.error_msg,
        case when v_row.timed_out then 'TIMEOUT'
             when not v_success then 'HTTP_'||coalesce(v_row.status_code::text,'UNKNOWN')
             else null end
      ),1000),
      success=v_success,
      duration_ms=v_duration,
      completed_at=v_now
    where delivery_id=v_row.id and attempt_number=v_row.attempt_count;

    update public.webhook_subscriptions set
      last_delivery_at=v_now,
      last_success_at=case when v_success then v_now else last_success_at end,
      last_failure_at=case when not v_success then v_now else last_failure_at end,
      consecutive_failures=case when v_success then 0 else v_sub_failures+1 end,
      status=case when v_auto_pause then 'paused' else status end,
      paused_at=case when v_auto_pause then coalesce(paused_at,v_now) else paused_at end,
      pause_reason=case when v_auto_pause then 'FAILURE_THRESHOLD_REACHED' else pause_reason end,
      updated_at=v_now
    where id=v_row.subscription_id;

    if v_auto_pause then
      perform private.trustrelay_notify_org_v09(
        v_row.organization_id,array['owner','admin','developer'],'webhook',
        'webhook.subscription.paused','critical',
        'Webhook endpoint automatically paused',
        'TrustRelay paused a webhook endpoint after repeated delivery failures.',
        'webhook_subscription',v_row.subscription_id,
        jsonb_build_object('failureThreshold',v_threshold,'consecutiveFailures',v_sub_failures+1)
      );
      perform private.trustrelay_append_org_audit_v09(
        v_row.organization_id,null,'webhook.subscription.auto_paused',
        'webhook_subscription',v_row.subscription_id,
        jsonb_build_object('failureThreshold',v_threshold,'consecutiveFailures',v_sub_failures+1)
      );
    end if;

    if not v_success and v_row.attempt_count>=v_row.max_attempts then
      perform private.trustrelay_notify_org_v09(
        v_row.organization_id,array['owner','admin','developer'],'webhook',
        'webhook.delivery.dead_lettered','critical',
        'Webhook delivery failed permanently',
        'A TrustRelay webhook exhausted all delivery attempts.',
        'webhook_delivery',v_row.id,
        jsonb_build_object('eventType',v_row.event_type,'responseStatus',v_row.status_code)
      );
      perform private.trustrelay_append_org_audit_v09(
        v_row.organization_id,null,'webhook.delivery.dead_lettered',
        'webhook_delivery',v_row.id,
        jsonb_build_object(
          'subscriptionId',v_row.subscription_id,'eventType',v_row.event_type,
          'eventId',v_row.event_id,'attemptCount',v_row.attempt_count,
          'responseStatus',v_row.status_code
        )
      );
    end if;

    v_count:=v_count+1;
  end loop;

  return jsonb_build_object('ok',true,'reconciled',v_count,'transport','pinned_tls_egress_v10');
end;
$$;

create or replace function public.trustrelay_webhook_maintenance_v09()
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $maint$
declare
  v_reconcile jsonb;
  v_dispatch jsonb;
begin
  v_reconcile:=public.trustrelay_reconcile_webhooks_v09(100);
  v_dispatch:=public.trustrelay_dispatch_due_webhooks_v09(100);
  return jsonb_build_object(
    'ok',true,
    'reconcile',v_reconcile,
    'dispatch',v_dispatch
  );
end;
$maint$;

revoke all on function public.trustrelay_webhook_maintenance_v09() from public,anon,authenticated;
grant execute on function public.trustrelay_webhook_maintenance_v09() to service_role;

revoke all on function public.trustrelay_dispatch_due_webhooks_v09(integer) from public,anon,authenticated;
revoke all on function public.trustrelay_reconcile_webhooks_v09(integer) from public,anon,authenticated;
grant execute on function public.trustrelay_dispatch_due_webhooks_v09(integer) to service_role;
grant execute on function public.trustrelay_reconcile_webhooks_v09(integer) to service_role;

insert into public.production_readiness_controls(
  control_key,category,status,required,evidence,owner_note,updated_at
) values(
  'webhook_egress_ssrf','security','pass',true,
  'Webhook delivery is routed through TrustRelay v1.0 pinned-TLS egress. A/AAAA results are validated at delivery time; private/reserved addresses are rejected; the TCP socket is pinned to the validated IP; TLS certificate verification uses the original hostname; redirects are not followed.',
  'Verified in staging with successful public delivery plus private-address and redirect rejection tests.',
  to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
)
on conflict(control_key) do update set
  status=excluded.status,
  required=excluded.required,
  evidence=excluded.evidence,
  owner_note=excluded.owner_note,
  updated_at=excluded.updated_at;
