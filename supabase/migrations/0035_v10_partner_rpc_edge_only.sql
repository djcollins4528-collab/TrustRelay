-- TrustRelay v1.0 security hardening
-- Partner decision RPCs are implementation details behind trustrelay-partner-v07.
-- Keep service_role execution for the Edge function, but prevent callers from
-- bypassing Edge authentication, request validation, and rate limiting via REST RPC.

revoke execute on function public.trustrelay_get_decision_partner_v05(text,text,integer) from anon;
revoke execute on function public.trustrelay_prepare_decision_v05(text,text,text,text,text,text,text,integer) from anon;
revoke execute on function public.trustrelay_record_decision_partner_v05(text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,integer,text) from anon;
