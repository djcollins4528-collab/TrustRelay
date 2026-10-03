-- TrustRelay v1.0 reviewer malware-scan status reconciliation.
do $$
declare
  v_oid oid;
  ddl text;
begin
  select p.oid into v_oid
  from pg_proc p
  join pg_namespace n on n.oid=p.pronamespace
  where p.prokind='f'
    and n.nspname='private'
    and p.proname='trustrelay_review_document_v08'
    and pg_get_function_identity_arguments(p.oid)='p_uid uuid, p_document_id text, p_decision text, p_reason_code text, p_notes text';

  if v_oid is null then
    raise exception 'trustrelay_review_document_v08 not found';
  end if;

  ddl:=pg_get_functiondef(v_oid);
  ddl:=replace(ddl,'v_doc.scan_status<>''basic_validated''','v_doc.scan_status<>''malware_scanned_clean''');
  execute ddl;
end $$;

notify pgrst,'reload schema';
