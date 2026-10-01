# TrustRelay

TrustRelay v0.5 staging backend: scoped delegated-authority decision engine with auditable ALLOW / DENY / ESCALATE decisions.

This repository is the dedicated source for the Render staging deployment. Sensitive credentials are not committed.


## v0.7 Institutional Verifier Portal + Partner API

TrustRelay v0.7 adds the institutional side of delegated authority.

### Verifier Portal

Staging route:

`/verifier/`

Capabilities:

- Passwordless institutional sign-in
- Sandbox organization onboarding
- Organization roles: owner, admin, verifier, developer, auditor
- Multi-user organization invitations
- Scoped authority evaluation
- Partner API key creation and revocation
- API key scopes: `decisions:read`, `decisions:write`
- Signed webhook endpoint management
- Authorization decision audit history
- Developer integration examples

The browser never receives an internal organization API key. Each organization receives a Vault-protected internal portal key that the authenticated server bridge uses to call the same Partner API used by external integrations.

### Partner API

Edge Function:

`trustrelay-partner-v07`

Version:

`0.7.0`

Endpoints:

- `GET /healthz`
- `POST /v1/decisions/evaluate`
- `GET /v1/decisions/{requestId}`

External partner keys are generated once and stored only as SHA-256 hashes. Sandbox keys use the `tr_test_` prefix.

The policy engine produces only:

- `ALLOW`
- `DENY`
- `ESCALATE`

The v0.7 evaluator supports:

- exact and wildcard resource scope
- prohibited and allowed actions
- maximum amount
- allowed currencies
- required evidence
- above-limit escalation
- conservative escalation for unknown policy rules

### Signed webhooks

Supported events:

- `decision.created`
- `grant.revoked`
- `credential.revoked`

Webhook signing secrets are encrypted in Supabase Vault. Delivery signatures use HMAC-SHA256 over:

`<timestamp>.<raw_body>`

Webhook endpoint creation rejects obvious localhost/private-network targets to reduce SSRF exposure.

### v0.7 verification completed

- Seven deterministic policy-engine cases passed.
- Organization owner bootstrap passed.
- Partner API-key generation passed.
- Organization invitation + verifier acceptance passed.
- Verifier role correctly failed API-key creation.
- Webhook creation passed.
- Valid partner-key context and rate limiting passed.
- Atomic decision/audit persistence passed.
- Evaluation and audit hashes were produced.
- Partner API health returned HTTP 200.
- Invalid partner key returned HTTP 401.
- Supabase Security Advisor has no database/RLS findings introduced by v0.7.

The remaining Supabase Auth warning is the Free-plan-only leaked-password-protection advisory. TrustRelay's user-facing authentication is passwordless.

See:

- `docs/V0.7-PARTNER-API.md`
- `verifier/openapi.json`
