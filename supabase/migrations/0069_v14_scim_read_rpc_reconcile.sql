-- TrustRelay v1.4 — SCIM read RPC reproducibility
-- Records the service-role-only Users read functions consumed by trustrelay-scim-v14.

create or replace function public.trustrelay_scim_get_user_v14(
  p_org_id text,p_scim_id text
)
returns jsonb
language sql
security definer
set search_path to 'public','pg_catalog'
as $function$
  select coalesce((
    select jsonb_build_object(
      'ok',true,
      'user',jsonb_build_object(
        'id',u.id,'externalId',u.external_id,'userName',u.user_name,'email',u.email,
        'givenName',u.given_name,'familyName',u.family_name,'displayName',u.display_name,
        'title',u.title,'active',u.active,'accountId',u.account_id,'version',u.version,
        'createdAt',u.created_at,'updatedAt',u.updated_at
      )
    )
    from public.organization_scim_users u
    where u.organization_id=p_org_id and u.id=p_scim_id
  ),jsonb_build_object('ok',false,'status',404,'code','SCIM_USER_NOT_FOUND'));
$function$;

create or replace function public.trustrelay_scim_list_users_v14(
  p_org_id text,
  p_filter_attribute text default null,
  p_filter_value text default null,
  p_start_index integer default 1,
  p_count integer default 100
)
returns jsonb
language plpgsql
security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  v_start integer:=greatest(coalesce(p_start_index,1),1);
  v_count integer:=greatest(1,least(coalesce(p_count,100),200));
  v_total bigint;
  v_users jsonb;
  v_attr text:=lower(coalesce(p_filter_attribute,''));
begin
  if v_attr<>'' and v_attr not in ('id','username','externalid','emails.value') then
    return jsonb_build_object('ok',false,'status',400,'code','SCIM_FILTER_UNSUPPORTED');
  end if;

  select count(*) into v_total
  from public.organization_scim_users u
  where u.organization_id=p_org_id
    and (
      v_attr=''
      or (v_attr='id' and u.id=p_filter_value)
      or (v_attr='username' and lower(u.user_name)=lower(p_filter_value))
      or (v_attr='externalid' and u.external_id=p_filter_value)
      or (v_attr='emails.value' and lower(u.email)=lower(p_filter_value))
    );

  select coalesce(jsonb_agg(x.payload order by x.user_name),'[]'::jsonb)
  into v_users
  from (
    select u.user_name,jsonb_build_object(
      'id',u.id,'externalId',u.external_id,'userName',u.user_name,'email',u.email,
      'givenName',u.given_name,'familyName',u.family_name,'displayName',u.display_name,
      'title',u.title,'active',u.active,'accountId',u.account_id,'version',u.version,
      'createdAt',u.created_at,'updatedAt',u.updated_at
    ) payload
    from public.organization_scim_users u
    where u.organization_id=p_org_id
      and (
        v_attr=''
        or (v_attr='id' and u.id=p_filter_value)
        or (v_attr='username' and lower(u.user_name)=lower(p_filter_value))
        or (v_attr='externalid' and u.external_id=p_filter_value)
        or (v_attr='emails.value' and lower(u.email)=lower(p_filter_value))
      )
    order by u.user_name
    offset (v_start-1)
    limit v_count
  ) x;

  return jsonb_build_object(
    'ok',true,'totalResults',v_total,'startIndex',v_start,
    'itemsPerPage',jsonb_array_length(v_users),'users',v_users
  );
end;
$function$;

revoke all on function public.trustrelay_scim_get_user_v14(text,text)
  from public,anon,authenticated;
revoke all on function public.trustrelay_scim_list_users_v14(text,text,text,integer,integer)
  from public,anon,authenticated;
grant execute on function public.trustrelay_scim_get_user_v14(text,text)
  to service_role;
grant execute on function public.trustrelay_scim_list_users_v14(text,text,text,integer,integer)
  to service_role;
