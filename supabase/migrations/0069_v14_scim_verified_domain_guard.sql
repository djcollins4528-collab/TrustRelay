-- Applied staging migration 20261003233106: v14_scim_verified_domain_guard

create or replace function private.trustrelay_scim_email_allowed_v14(
  p_org_id text,p_email text
)
returns boolean
language sql
stable
security definer
set search_path to 'public','pg_catalog'
as $function$
  select
    lower(btrim(coalesce(p_email,''))) ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    and exists(
      select 1
      from public.organization_sso_domains d
      where d.organization_id=p_org_id
        and d.domain=split_part(lower(btrim(p_email)),'@',2)
        and d.verification_status='verified'
    );
$function$;

revoke all on function private.trustrelay_scim_email_allowed_v14(text,text)
from public,anon,authenticated;
grant execute on function private.trustrelay_scim_email_allowed_v14(text,text)
to service_role;
