-- TrustRelay v1.0 Stripe scheduled-cancellation reconciliation.
-- Resolve invoice events from current Stripe invoice parent/line metadata and persist price IDs.

CREATE OR REPLACE FUNCTION public.trustrelay_apply_stripe_event_v10(p_event_id text, p_event_type text, p_payload_json text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'private', 'extensions', 'pg_catalog'
AS $function$
declare
  v_payload jsonb;
  v_obj jsonb;
  v_org_id text;
  v_plan text;
  v_customer text;
  v_subscription text;
  v_price text;
  v_status text;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_hash text;
  v_livemode boolean;
  v_period_start text;
  v_period_end text;
  v_trial_end text;
  v_cancel boolean:=false;
  v_existing public.billing_events%rowtype;
begin
  if length(btrim(coalesce(p_event_id,'')))<4 or length(btrim(coalesce(p_event_type,'')))<3 then
    return jsonb_build_object('ok',false,'status',400,'code','STRIPE_EVENT_INVALID');
  end if;

  begin v_payload:=p_payload_json::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'status',400,'code','STRIPE_PAYLOAD_INVALID');
  end;

  v_hash:=encode(digest(p_payload_json,'sha256'),'hex');
  v_livemode:=coalesce((v_payload->>'livemode')::boolean,false);

  select * into v_existing
  from public.billing_events
  where provider='stripe' and provider_event_id=p_event_id;

  if found then
    if v_existing.payload_sha256<>v_hash then
      return jsonb_build_object('ok',false,'status',409,'code','STRIPE_EVENT_HASH_MISMATCH');
    end if;
    return jsonb_build_object('ok',true,'idempotent',true,'eventId',p_event_id,'status',v_existing.status);
  end if;

  insert into public.billing_events(
    id,provider,provider_event_id,event_type,payload_sha256,livemode,status,created_at
  ) values (
    'bill_evt_'||replace(gen_random_uuid()::text,'-',''),
    'stripe',p_event_id,p_event_type,v_hash,v_livemode,'received',v_now
  );

  v_obj:=v_payload->'data'->'object';
  v_org_id:=coalesce(
    nullif(v_obj->'metadata'->>'trustrelay_org_id',''),
    nullif(v_obj->'subscription_details'->'metadata'->>'trustrelay_org_id',''),
    nullif(v_obj->'parent'->'subscription_details'->'metadata'->>'trustrelay_org_id',''),
    nullif(v_obj->'lines'->'data'->0->'metadata'->>'trustrelay_org_id','')
  );
  v_plan:=coalesce(
    nullif(v_obj->'metadata'->>'trustrelay_plan_code',''),
    nullif(v_obj->'subscription_details'->'metadata'->>'trustrelay_plan_code',''),
    nullif(v_obj->'parent'->'subscription_details'->'metadata'->>'trustrelay_plan_code',''),
    nullif(v_obj->'lines'->'data'->0->'metadata'->>'trustrelay_plan_code','')
  );
  v_price:=coalesce(
    nullif(v_obj->'items'->'data'->0->'price'->>'id',''),
    nullif(v_obj->'lines'->'data'->0->'pricing'->'price_details'->>'price','')
  );
  v_customer:=nullif(v_obj->>'customer','');
  v_subscription:=nullif(v_obj->>'subscription','');

  if p_event_type like 'customer.subscription.%' then
    v_subscription:=nullif(v_obj->>'id','');
    v_customer:=nullif(v_obj->>'customer','');
    v_price:=coalesce(v_price,nullif(v_obj->'items'->'data'->0->'price'->>'id',''));
    v_org_id:=coalesce(v_org_id,(
      select organization_id from public.organization_billing
      where provider='stripe'
        and (provider_subscription_id=v_subscription or provider_customer_id=v_customer)
      limit 1
    ));
    v_plan:=coalesce(v_plan,(
      select plan_code from public.organization_billing where organization_id=v_org_id
    ));
    v_status:=case v_obj->>'status'
      when 'trialing' then 'trialing'
      when 'active' then 'active'
      when 'past_due' then 'past_due'
      when 'unpaid' then 'unpaid'
      when 'canceled' then 'canceled'
      when 'paused' then 'past_due'
      else 'not_configured'
    end;
    v_cancel:=coalesce((v_obj->>'cancel_at_period_end')::boolean,false)
      or (
        (v_obj->>'cancel_at') ~ '^[0-9]+$'
        and coalesce(v_obj->>'status','') in ('active','trialing','past_due','unpaid')
      );
    if coalesce(v_obj->>'current_period_start',v_obj->'items'->'data'->0->>'current_period_start') ~ '^[0-9]+$' then
      v_period_start:=to_char(to_timestamp(coalesce(v_obj->>'current_period_start',v_obj->'items'->'data'->0->>'current_period_start')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;
    if coalesce(v_obj->>'current_period_end',v_obj->'items'->'data'->0->>'current_period_end') ~ '^[0-9]+$' then
      v_period_end:=to_char(to_timestamp(coalesce(v_obj->>'current_period_end',v_obj->'items'->'data'->0->>'current_period_end')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;
    if (v_obj->>'trial_end') ~ '^[0-9]+$' then
      v_trial_end:=to_char(to_timestamp((v_obj->>'trial_end')::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    end if;

  elsif p_event_type='checkout.session.completed' then
    v_org_id:=coalesce(v_org_id,nullif(v_obj->>'client_reference_id',''));
    v_customer:=nullif(v_obj->>'customer','');
    v_subscription:=nullif(v_obj->>'subscription','');

  elsif p_event_type in ('invoice.paid','invoice.payment_failed') then
    v_customer:=nullif(v_obj->>'customer','');
    v_subscription:=coalesce(
      nullif(v_obj->>'subscription',''),
      nullif(v_obj->'parent'->'subscription_details'->>'subscription',''),
      nullif(v_obj->'lines'->'data'->0->'parent'->'subscription_item_details'->>'subscription','')
    );
    v_price:=coalesce(
      v_price,
      nullif(v_obj->'lines'->'data'->0->'pricing'->'price_details'->>'price','')
    );
    v_org_id:=coalesce(v_org_id,(
      select organization_id from public.organization_billing
      where provider='stripe'
        and (provider_subscription_id=v_subscription or provider_customer_id=v_customer)
      limit 1
    ));
  end if;

  if v_org_id is null or not exists(select 1 from public.organizations where id=v_org_id) then
    update public.billing_events
    set status='ignored',error_code='ORGANIZATION_NOT_RESOLVED',processed_at=v_now
    where provider='stripe' and provider_event_id=p_event_id;
    return jsonb_build_object('ok',true,'ignored',true,'eventId',p_event_id,'reason','ORGANIZATION_NOT_RESOLVED');
  end if;

  if v_plan is not null and not exists(select 1 from public.billing_plans where code=v_plan and status='active') then
    update public.billing_events
    set status='failed',organization_id=v_org_id,error_code='PLAN_NOT_RESOLVED',processed_at=v_now
    where provider='stripe' and provider_event_id=p_event_id;
    return jsonb_build_object('ok',false,'status',409,'code','PLAN_NOT_RESOLVED');
  end if;

  update public.organization_billing
  set
    provider='stripe',
    plan_code=coalesce(v_plan,plan_code),
    provider_customer_id=coalesce(v_customer,provider_customer_id),
    provider_subscription_id=coalesce(v_subscription,provider_subscription_id),
    provider_price_id=coalesce(v_price,provider_price_id),
    status=case
      when p_event_type like 'customer.subscription.%' then v_status
      when p_event_type='invoice.paid' and status<>'canceled' then 'active'
      when p_event_type='invoice.payment_failed' then 'past_due'
      else status end,
    current_period_start=coalesce(v_period_start,current_period_start),
    current_period_end=coalesce(v_period_end,current_period_end),
    trial_end=coalesce(v_trial_end,trial_end),
    cancel_at_period_end=case when p_event_type like 'customer.subscription.%' then v_cancel else cancel_at_period_end end,
    canceled_at=case when p_event_type='customer.subscription.deleted' then v_now else canceled_at end,
    last_payment_at=case when p_event_type='invoice.paid' then v_now else last_payment_at end,
    last_payment_failure_at=case when p_event_type='invoice.payment_failed' then v_now else last_payment_failure_at end,
    updated_at=v_now
  where organization_id=v_org_id;

  update public.billing_events
  set organization_id=v_org_id,status='processed',processed_at=v_now
  where provider='stripe' and provider_event_id=p_event_id;

  perform private.trustrelay_append_org_audit_v09(
    v_org_id,null,'billing.stripe_event.processed','organization_billing',v_org_id,
    jsonb_build_object('eventId',p_event_id,'eventType',p_event_type,'livemode',v_livemode)
  );

  if p_event_type='invoice.payment_failed' then
    perform private.trustrelay_notify_org_v09(
      v_org_id,array['owner','admin'],'organization',
      'billing.payment_failed','critical',
      'Billing payment failed',
      'TrustRelay could not confirm the latest subscription payment. Production access may be affected.',
      'organization_billing',v_org_id,jsonb_build_object('eventId',p_event_id)
    );
  elsif p_event_type in ('customer.subscription.created','customer.subscription.updated','checkout.session.completed') then
    perform private.trustrelay_notify_org_v09(
      v_org_id,array['owner','admin'],'organization',
      'billing.subscription_updated','success',
      'Billing subscription updated',
      'TrustRelay received an updated subscription state from Stripe.',
      'organization_billing',v_org_id,jsonb_build_object('eventId',p_event_id,'eventType',p_event_type)
    );
  end if;

  return jsonb_build_object('ok',true,'eventId',p_event_id,'organizationId',v_org_id,'processed',true);
end;
$function$;


notify pgrst,'reload schema';
