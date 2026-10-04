-- TrustRelay v1.5 compatibility reconciliation.
-- Production carried the early SCIM group tables from the v1.3 bundle. The
-- legacy membership table did not include organization_id; v1.5 requires it
-- for tenant-bound group operations and role reconciliation.

alter table public.organization_scim_group_members
  add column if not exists organization_id text;

update public.organization_scim_group_members gm
set organization_id=g.organization_id
from public.organization_scim_groups g
where g.id=gm.group_id
  and gm.organization_id is null;

alter table public.organization_scim_group_members
  alter column organization_id set not null;

do $$
begin
  if not exists(
    select 1 from pg_constraint
    where conrelid='public.organization_scim_group_members'::regclass
      and conname='organization_scim_group_members_organization_id_fkey'
  ) then
    alter table public.organization_scim_group_members
      add constraint organization_scim_group_members_organization_id_fkey
      foreign key(organization_id) references public.organizations(id) on delete cascade;
  end if;
end $$;

create index if not exists organization_scim_group_members_org_idx
  on public.organization_scim_group_members(organization_id);
create index if not exists organization_scim_group_members_user_idx
  on public.organization_scim_group_members(user_id);
