-- TrustRelay v1.0 compliance export storage bootstrap.
-- Private bucket used only by the server-side compliance export flow and signed download URLs.

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values(
  'trustrelay-compliance-exports',
  'trustrelay-compliance-exports',
  false,
  26214400,
  array['application/json','text/csv']::text[]
)
on conflict(id) do update set
  public=false,
  file_size_limit=26214400,
  allowed_mime_types=excluded.allowed_mime_types;
