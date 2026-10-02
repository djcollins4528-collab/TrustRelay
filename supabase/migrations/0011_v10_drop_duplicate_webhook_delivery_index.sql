-- TrustRelay v1.0 clean-bootstrap performance reconciliation.
-- Remove the redundant standalone unique index while retaining the
-- UNIQUE constraint-backed webhook_deliveries_subscription_event_v09 index.

drop index if exists public.uq_webhook_delivery_event;
