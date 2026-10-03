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
- trustrelay-scim-admin-v14
- trustrelay-scim-v14
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


## Enterprise SSO control plane

- `trustrelay-sso-v13` provides rate-limited public domain discovery plus authenticated organization-level Entra ID / Okta administration.
- OIDC client secrets are forwarded directly to Supabase Auth's server-only provider API and are never stored in TrustRelay tables.
- SAML provisioning remains fail-closed unless `TRUSTRELAY_SAML_ENABLED=true`; current Supabase plan requirements must be satisfied first.
- Reconfiguration resets enforcement to optional until the exact configured IdP successfully authenticates an owner/admin session. A non-SSO owner break-glass path is retained.

- Enterprise SSO domains require DNS ownership verification at `_trustrelay.<domain>`; only challenge hashes are stored. Provider login remains disabled until verification succeeds.


## SCIM provisioning

- `trustrelay-scim-admin-v14` is the authenticated, MFA-protected organization administration surface for SCIM enablement, token rotation, default-role policy and disable/re-enable.
- `trustrelay-scim-v14` is a server-to-server SCIM 2.0 Users endpoint with ServiceProviderConfig, ResourceTypes and User Schema discovery.
- Each organization receives a tenant-scoped high-entropy Bearer token. The raw token is shown only when created or rotated; TrustRelay stores only its SHA-256 hash and last four characters.
- User provisioning supports create, replace, supported PATCH operations, lookup/filtering and soft deprovisioning. Group provisioning is intentionally not enabled in v1.4.
- Deprovisioning disables only the user's membership in that TrustRelay organization. It does not delete the global TrustRelay person/account.
- SCIM cannot deprovision an organization Owner; ownership must be transferred first.
- New SCIM users must use a corporate domain already verified through Enterprise SSO.
- When SCIM is enabled, SSO JIT will not silently recreate an unprovisioned or deprovisioned membership; an active SCIM assignment is required.
- The SCIM endpoint is independently authenticated and rate limited, so its Edge Function intentionally runs with `verify_jwt=false`.
