-- TrustRelay live migration 20261002015325: trustrelay_v10_webhook_egress_readiness_reconcile
-- Reconciles the superseded Render relay readiness evidence to the canonical Supabase Edge pinned-TLS path.


update public.production_readiness_controls
set status='pass',
    evidence='TrustRelay v1.0 webhook delivery now uses the Supabase Edge pinned-TLS egress path. At delivery time, A/AAAA answers are resolved and all returned addresses are checked against blocked private/reserved ranges. The outbound TCP socket is opened directly to a validated IP, then upgraded to TLS with the original hostname for certificate verification. Redirects are rejected. Staging validation passed public HTTPS delivery, 127.0.0.1 rejection, redirect rejection, queue-to-cron-to-egress-to-reconcile delivery, exact payload verification, and HMAC-SHA256 recomputation.',
    owner_note='Supersedes the earlier Render relay implementation recorded in 0006. Current receiver User-Agent is TrustRelay-Webhook/1.0. Non-default HTTPS ports remain supported only when the resolved address passes the same public-IP validation.',
    updated_at=to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
where control_key='webhook_egress_policy';

