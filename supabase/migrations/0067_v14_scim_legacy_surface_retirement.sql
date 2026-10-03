-- TrustRelay v1.4 — retire the remaining legacy SCIM control-plane entry points.
-- The authoritative model is organization_scim_credentials + trustrelay_scim_resolve_bearer_v14.
-- Nullable legacy columns remain temporarily for a low-risk rolling database migration,
-- but no callable runtime path can create, rotate, or authenticate them.

drop function if exists public.trustrelay_scim_enable_v14(text,text,integer);
drop function if exists public.trustrelay_scim_rotate_token_v14(text,integer);

drop function if exists private.trustrelay_scim_enable_core_v14(uuid,text,text,integer);
drop function if exists private.trustrelay_scim_rotate_token_core_v14(uuid,text,integer);
drop function if exists private.trustrelay_scim_set_policy_core_v14(uuid,text,text,text);
drop function if exists private.trustrelay_scim_apply_membership_v14(text,text,text,boolean,text);
drop function if exists private.trustrelay_scim_email_allowed_v14(text,text);
