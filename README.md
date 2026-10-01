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


## v0.8 High-Assurance Identity + Evidence

TrustRelay v0.8 adds a high-assurance identity and evidence layer on top of the v0.7 institutional verifier platform.

### Live staging surfaces

- Consumer app: `/web/`
- Institutional Verifier Portal: `/verifier/`
- Internal Identity Review Console: `/reviewer/`
- OpenAPI contract: `/verifier/openapi.json`

### Identity assurance

Assurance levels:

- `none`
- `email_verified`
- `document_verified`
- `high_assurance`

Users can start a consented proofing session and upload private government-ID/address evidence. TrustRelay uses a private Storage bucket, short-lived signed upload/download URLs, and SHA-256 integrity hashes.

Normal users cannot approve their own evidence. Identity reviewers must be explicitly provisioned, and self-review is rejected.

### KYC/provider boundary

v0.8 includes a service-role-only provider adapter that accepts an externally verified result only after provider integration code has authenticated it. Provider result JSON is hashed and the provider cannot promote a user beyond the assurance level the user consented to request.

No external KYC provider is currently configured, and the product does not claim biometric, liveness, AML, sanctions-screening, or regulatory KYC certification.

### Grant policy

New optional rules:

- `minimumAssurance`
- `requireVerifiedEvidence`

An active grant falls back to `pending_verification` if either participant later drops below its explicit minimum assurance.

`requireVerifiedEvidence` is satisfied only by reviewer-approved TrustRelay documents linked to that grant.

### Institutional evidence workflow

After evaluating a grant, an institution can request supporting evidence. The principal/representative must explicitly attach a private document to that request before the requesting institution gets access to it.

Owner/admin/verifier roles can resolve submitted evidence requests. Auditor roles can view explicitly shared evidence but cannot resolve requests.

### Credentials and Partner API

New credentials use TrustRelay credential version `0.8` and include an assurance-at-issuance snapshot. Public verification returns current live assurance separately.

The stable Partner API route remains `trustrelay-partner-v07` for compatibility, but health and persisted decisions report engine version `0.8.0`.

See:

- `docs/V0.8-IDENTITY-EVIDENCE.md`
- `verifier/openapi.json`


## v0.9 Operations + Compliance

TrustRelay v0.9 adds the operational layer needed for institutional pilots.

### Durable signed webhooks

- HMAC-SHA256 signatures with Vault-backed secrets
- canonical JSON payload hashing
- async `pg_net` delivery
- one-minute `pg_cron` maintenance
- bounded exponential retries
- per-attempt evidence
- dead-letter state
- failure-pause threshold
- test delivery, manual retry and secret rotation

Current emitted events include authorization decisions, authority revocations, evidence lifecycle events, organization member lifecycle events, compliance export readiness and webhook tests.

### Notifications

Consumer and institutional users now have in-app notification centers with unread counts, read/dismiss actions and per-category preferences.

### Organization RBAC

Roles:

- owner
- admin
- compliance
- verifier
- developer
- auditor

Authorization uses a centralized permission map. The last active owner cannot be demoted or disabled.

### Organization audit ledger

Operational organization events are appended to a per-organization SHA-256 hash chain. Authorized users can verify the chain from the Verifier Portal.

### Compliance exports

Authorized owner/admin/compliance/auditor users can generate private JSON or CSV exports over a bounded date range.

Exports can contain selected:

- decisions
- webhook deliveries/attempts
- evidence-request workflow metadata
- member/invitation history
- organization audit events
- organization notifications

Private identity-document bodies are deliberately excluded.

Every export records:

- source dataset SHA-256
- exact output SHA-256
- record counts
- byte size
- organization audit-chain state/head
- generation metadata

Download URLs are signed and short-lived.

See:

- `docs/V0.9-OPERATIONS-COMPLIANCE.md`
- `docs/V0.9-IMPLEMENTATION-RESULT.md`
- `verifier/openapi.json`


## v0.9 Webhooks, Notifications, Organization Roles + Compliance/Audit Exports

TrustRelay v0.9 adds the operational controls needed for institutional use while preserving the v0.8 identity/evidence and signed-authority model.

### Organization RBAC

Supported roles:

- `owner`
- `admin`
- `compliance`
- `verifier`
- `developer`
- `auditor`

Permissions are resolved from a canonical server-side permission map instead of scattered UI-only role checks. Owner protections prevent removing or demoting the last active owner.

Role changes, member disable/restore/remove actions, invitations, API-key changes, webhook changes, evidence actions and compliance exports are recorded in the organization audit ledger.

### Notifications

Both the consumer app and Verifier Portal include an in-app notification center with unread state and category preferences.

Categories:

- authority
- evidence
- identity
- organization
- webhook
- compliance
- security

Notifications are stored server-side and deduplicated where appropriate.

### Durable webhooks

Webhook subscriptions use Vault-protected HMAC-SHA256 signing secrets.

v0.9 supports:

- queued asynchronous delivery
- bounded exponential retries
- per-attempt delivery history
- dead-letter state
- failure-threshold pause/disable handling
- manual retry
- signing-secret rotation
- test deliveries
- delivery-failure notifications
- one-minute scheduled maintenance

Current organization webhook events:

- `decision.created`
- `grant.revoked`
- `credential.revoked`
- `evidence.requested`
- `evidence.submitted`
- `evidence.resolved`
- `organization.member.invited`
- `organization.member.joined`
- `organization.member.role_changed`
- `organization.member.disabled`
- `organization.member.restored`
- `organization.member.removed`
- `organization.ownership.transferred`
- `compliance.export.ready`
- `webhook.test`

Webhook endpoint creation rejects obvious localhost/private-network destinations.

### Compliance / audit exports

Authorized owner/admin/compliance/auditor users can create bounded JSON or CSV exports containing selected operational records such as:

- authorization decisions
- webhook deliveries and attempts
- evidence-request history
- organization members and invitations
- organization audit events
- notifications
- partner API-key metadata when requested

Private identity-document bodies are excluded.

Exports are stored in a private bucket, SHA-256 hashed, linked into the export audit chain, and downloaded only through short-lived signed URLs.

### Audit integrity

Organization operational events are hash chained. v0.9 exposes audit-chain verification and includes chain status in compliance export metadata.

### Verified v0.9 behavior

Rollback integration tests passed for:

- last-owner protection
- organization invitation and auditor acceptance
- role promotion to `compliance`
- compliance export permission resolution
- exactly one role-change notification
- webhook queue creation
- webhook event idempotency/deduplication
- compliance export completion + SHA-256
- organization audit-chain verification

All three browser bundles pass JavaScript syntax validation.

See:

- `docs/V0.9-OPERATIONS-COMPLIANCE.md`
- `verifier/openapi.json`
