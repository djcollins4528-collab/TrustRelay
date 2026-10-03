-- TrustRelay v1.2 webhook signing-secret lifecycle.
-- Rotation requires webhooks.manage, which is protected by active-session,
-- AAL2/recent-TOTP and sensitive-action rate limiting.

create or replace function private.trustrelay_rotate_webhook_secret_v09(
  p_uid uuid,p_org_id text,p_webhook_id text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','vault','extensions','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_row public.webhook_subscriptions%rowtype;
  v_old_secret_id uuid;
  v_new_secret_id uuid;
  v_secret text:='whsec_'||encode(gen_random_bytes(32),'hex');
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;

  select * into v_row from public.webhook_subscriptions
  where id=p_webhook_id and organization_id=p_org_id
  for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','WEBHOOK_NOT_FOUND'); end if;
  if v_row.status='revoked' then return jsonb_build_object('ok',false,'status',409,'code','WEBHOOK_REVOKED'); end if;

  v_old_secret_id:=v_row.secret_vault_id;
  v_new_secret_id:=vault.create_secret(
    v_secret,
    'trustrelay-webhook-'||p_webhook_id||'-'||replace(gen_random_uuid()::text,'-',''),
    'TrustRelay rotated webhook signing secret'
  );

  update public.webhook_subscriptions
  set secret_vault_id=v_new_secret_id,
      secret_prefix=left(v_secret,12),
      secret_rotated_at=v_now,
      updated_at=v_now
  where id=p_webhook_id and organization_id=p_org_id;

  if v_old_secret_id is not null and v_old_secret_id<>v_new_secret_id then
    delete from vault.secrets where id=v_old_secret_id;
  end if;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.secret_rotated','webhook_subscription',p_webhook_id,
    jsonb_build_object('secretPrefix',left(v_secret,12),'rotatedAt',v_now)
  );

  return jsonb_build_object(
    'ok',true,'signingSecret',v_secret,
    'webhookId',p_webhook_id,'secretPrefix',left(v_secret,12),'rotatedAt',v_now
  );
end;
$$;

create or replace function public.trustrelay_rotate_webhook_secret_v09(
  p_org_id text,p_webhook_id text
)
returns jsonb
language sql
security invoker
set search_path to 'private','auth','pg_catalog'
as $$
  select private.trustrelay_rotate_webhook_secret_v09(auth.uid(),p_org_id,p_webhook_id);
$$;

revoke all on function private.trustrelay_rotate_webhook_secret_v09(uuid,text,text) from public,anon;
grant execute on function private.trustrelay_rotate_webhook_secret_v09(uuid,text,text) to authenticated,service_role;
revoke all on function public.trustrelay_rotate_webhook_secret_v09(text,text) from public,anon;
grant execute on function public.trustrelay_rotate_webhook_secret_v09(text,text) to authenticated,service_role;

create or replace function private.trustrelay_set_webhook_state_v09(
  p_uid uuid,p_org_id text,p_webhook_id text,p_state text,p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','private','pg_catalog'
as $$
declare
  v_ctx jsonb;
  v_now text:=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_exists boolean;
begin
  v_ctx:=private.trustrelay_require_permission_v09(p_uid,p_org_id,'webhooks.manage');
  if coalesce((v_ctx->>'ok')::boolean,false)=false then return v_ctx; end if;
  if p_state not in ('active','paused') then
    return jsonb_build_object('ok',false,'status',400,'code','WEBHOOK_STATE_INVALID');
  end if;

  select true into v_exists from public.webhook_subscriptions
  where id=p_webhook_id and organization_id=p_org_id and status<>'revoked' for update;
  if not found then return jsonb_build_object('ok',false,'status',404,'code','WEBHOOK_NOT_FOUND'); end if;

  update public.webhook_subscriptions
  set status=p_state,
      pause_reason=case when p_state='paused' then nullif(left(btrim(coalesce(p_reason,'')),300),'') else null end,
      paused_at=case when p_state='paused' then v_now else null end,
      updated_at=v_now
  where id=p_webhook_id and organization_id=p_org_id;

  perform private.trustrelay_append_org_audit_v09(
    p_org_id,v_ctx->>'accountId','webhook.'||p_state,'webhook_subscription',p_webhook_id,
    jsonb_build_object('reason',case when p_state='paused' then nullif(left(btrim(coalesce(p_reason,'')),300),'') else null end)
  );

  return jsonb_build_object('ok',true,'webhookId',p_webhook_id,'status',p_state);
end;
$$;

create or replace function public.trustrelay_set_webhook_state_v09(
  p_org_id text,p_webhook_id text,p_state text,p_reason text default null
)
returns jsonb
language sql
security invoker
set search_path to 'private','auth','pg_catalog'
as $$
  select private.trustrelay_set_webhook_state_v09(auth.uid(),p_org_id,p_webhook_id,p_state,p_reason);
$$;

revoke all on function private.trustrelay_set_webhook_state_v09(uuid,text,text,text,text) from public,anon;
grant execute on function private.trustrelay_set_webhook_state_v09(uuid,text,text,text,text) to authenticated,service_role;
revoke all on function public.trustrelay_set_webhook_state_v09(text,text,text,text) from public,anon;
grant execute on function public.trustrelay_set_webhook_state_v09(text,text,text,text) to authenticated,service_role;

notify pgrst,'reload schema';