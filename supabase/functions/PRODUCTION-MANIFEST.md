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
- trustrelay-sso-v13
- trustrelay-webhook-egress-v10

Each directory contains the current staging `index.ts` plus `function.json` where applicable. `trustrelay-webhook-egress-v10` is intentionally `verify_jwt=false` because it is an internal transport endpoint authenticated with a high-entropy Vault-backed `X-TrustRelay-Egress-Key`; it does not trust caller-supplied destination validation and independently resolves/validates/pins the outbound target.

## Signing-key bootstrap

Production does **not** require the retired `trustrelay-signing-bootstrap-v06` endpoint.

`trustrelay-credential-issue-v06` establishes a fresh environment-local ES256 signing key on first credential issuance if no active key exists. The private JWK is stored in that environment's Supabase Vault through the service-role-only `trustrelay_bootstrap_signing_key_v06` RPC. No signing key material is copied between staging and production.

The repository copy of `trustrelay-signing-bootstrap-v06` is an HTTP 410 retired stub and should not be deployed as an ordinary production runtime feature.

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

Webhook delivery uses `trustrelay-webhook-egress-v10` as the required v1.0 pinned-TLS egress boundary. The legacy Render `/internal/webhook-egress` route is retired and returns HTTP 410.

## Required production secrets / configuration

Supabase-managed environment:
- SUPABASE_URL
- SUPABASE_PUBLISHABLE_KEYS
- SUPABASE_SECRET_KEYS

TrustRelay enterprise SSO:
- `trustrelay-sso-v13` uses Supabase-managed `SUPABASE_SECRET_KEYS` only on the server side for Auth provider administration.
- OIDC custom providers are enabled by default and use PKCE.
- `TRUSTRELAY_SAML_ENABLED` remains unset/false until the Supabase project plan supports SAML and the production SAML gate is intentionally approved.
- Entra/Okta client secrets are never stored in TrustRelay application tables or browser storage.

TrustRelay billing:
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_PRICE_STARTER
- STRIPE_PRICE_GROWTH
- TRUSTRELAY_APP_ORIGIN

The Stripe values must be production/test-environment appropriate and must never be committed to Git.


TrustRelay webhook egress:
- Vault secret `trustrelay-webhook-egress-v10` — internal dispatcher-to-egress authentication secret
- Vault secret `trustrelay-webhook-egress-url-v10` — environment-specific Edge Function URL

The v1.0 egress resolves A/AAAA at delivery time, rejects private/reserved addresses, opens the TCP socket directly to a validated IP, upgrades to TLS using the original hostname for certificate validation, and rejects HTTP redirects.
