# TrustRelay Production Edge Function Manifest

## Required runtime

- trustrelay-profile-v06
- trustrelay-grant-create-v06
- trustrelay-grant-revoke-v06
- trustrelay-invite-accept-v06
- trustrelay-invite-preview-v061
- trustrelay-credential-issue-v06
- trustrelay-credential-verify-v06
- trustrelay-jwks-v06
- trustrelay-evidence-v08
- trustrelay-partner-v07
- trustrelay-verifier-evaluate-v07
- trustrelay-compliance-export-v09
- trustrelay-billing-v10

Each directory contains the current staging `index.ts` plus `function.json` recording the JWT setting and staged source hash at export time.

## One-time bootstrap

- trustrelay-signing-bootstrap-v06

Deploy/invoke this only to establish the production ES256 signing key material, then disable or otherwise restrict the bootstrap surface. Do not leave key-bootstrap capability as an ordinary production runtime feature.

## Intentionally excluded from production runtime

The following staging functions are legacy, duplicate, pilot, diagnostic, superseded, or temporary and should not be deployed as production runtime:

- trustrelay-health-v051
- trustrelay-db-v051
- trustrelay-create-grant-v06
- trustrelay-issue-credential-v06
- trustrelay-verify-credential-v06
- trustrelay-pilot-v061
- trustrelay-one-run-pilot-v061
- trustrelay-auth-config-check
- trustrelay-compliance-v09
- trustrelay-webhook-worker-v09
- trustrelay-webhook-receiver-v09

Production health is provided by the Render `/healthz` endpoint and the Partner API `/healthz` endpoint.

## Required production secrets / configuration

Supabase-managed environment:
- SUPABASE_URL
- SUPABASE_PUBLISHABLE_KEYS
- SUPABASE_SECRET_KEYS

TrustRelay billing:
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_PRICE_STARTER
- STRIPE_PRICE_GROWTH
- TRUSTRELAY_APP_ORIGIN

The Stripe values must be production/test-environment appropriate and must never be committed to Git.
