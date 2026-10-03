-- Partner API credentials may never be permanent.
-- Default lifetime: 90 days. Caller-selected expiry: at most 365 days.

create or replace function private.trustrelay_create_api_key_v07(p_uid uuid,p_org_id text,p_name text,p_scopes jsonb,p_expires_at text)
returns jsonb
language plpgsql
security definer
set search_path='public','private','extensions','pg_catalog'
as $$
declare
  v_ctx jsonb; v_org public.organizations%rowtype; v_account_id text;
  v_key_id text := 'key_' || replace(gen_random_uuid()::text,'-','');
  v_raw text; v_hash text; v_prefix text;
  v_now text := to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_expires_at text := to_char((clock_timestamp()+interval '90 days') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_scope text; v_allowed text[] := array['decisions:read','decisions:write'];
begin
  v_ctx := private.trustrelay_require_org_role_v07(p_uid,p_org_id,array['owner','admin','developer']);
  if coalesce((v_ctx->>'ok')::boolean,false) is false then return v_ctx; end if;
  if length(btrim(coalesce(p_name,''))) < 2 or length(btrim(p_name)) > 100 then return jsonb_build_object('ok',false,'status',400,'code','API_KEY_NAME_INVALID'); end if;
  if p_scopes is null or jsonb_typeof(p_scopes) <> 'array' or jsonb_array_length(p_scopes)=0 then return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPES_REQUIRED'); end if;
  for v_scope in select jsonb_array_elements_text(p_scopes) loop
    if not (v_scope = any(v_allowed)) then return jsonb_build_object('ok',false,'status',400,'code','API_KEY_SCOPE_INVALID','scope',v_scope); end if;
  end loop;
  select * into v_org from public.organizations where id=p_org_id;
  v_account_id := v_ctx->>'accountId';
  if p_expires_at is not null then
    begin
      if p_expires_at::timestamptz <= clock_timestamp() or p_expires_at::timestamptz > clock_timestamp()+interval '365 days' then return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_INVALID'); end if;
      v_expires_at:=to_char(p_expires_at::timestamptz at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    exception when others then return jsonb_build_object('ok',false,'status',400,'code','API_KEY_EXPIRY_INVALID');
    end;
  end if;
  v_prefix := case when v_org.mode='live' then 'tr_live' else 'tr_test' end;
  v_raw := v_prefix || '_' || encode(gen_random_bytes(32),'hex');
  v_hash := encode(digest(v_raw,'sha256'),'hex');
  insert into public.api_keys(id,organization_id,name,prefix,key_hash,scopes_json,created_at,key_type,created_by_account_id,expires_at,last_four,updated_at)
  values(v_key_id,p_org_id,btrim(p_name),v_prefix,v_hash,p_scopes::text,v_now,'partner',v_account_id,v_expires_at,right(v_raw,4),v_now);
  return jsonb_build_object('ok',true,'apiKey',v_raw,'key',jsonb_build_object('id',v_key_id,'name',btrim(p_name),'prefix',v_prefix,'lastFour',right(v_raw,4),'scopes',p_scopes,'createdAt',v_now,'expiresAt',v_expires_at));
end;
$$;

revoke all on function private.trustrelay_create_api_key_v07(uuid,text,text,jsonb,text) from public,anon,authenticated;
grant execute on function private.trustrelay_create_api_key_v07(uuid,text,text,jsonb,text) to service_role;
