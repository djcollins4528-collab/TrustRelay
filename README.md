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

Webhook endpoint creation rejects obvious localhost/private-network targets; v1.0 delivery also re-resolves DNS, rejects private/reserved addresses, pins the TLS socket to a validated public IP, and blocks redirects.

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

## v0.9 Webhooks, Notifications, Organization Roles + Compliance/Audit Exports

TrustRelay v0.9 adds the operational controls needed for institutional deployment while preserving the v0.8 passwordless identity, signed-authority, and private-evidence model.

### Organization RBAC

Roles:

- `owner`
- `admin`
- `compliance`
- `verifier`
- `developer`
- `auditor`

Authorization is enforced by the server-side permission matrix rather than UI-only role checks.

Notable separation:

- verifier: evaluate authority and work evidence, but cannot export audit data
- compliance: read decisions/evidence and export audit data, but cannot evaluate authority
- developer: manage API keys/webhooks and read decisions/audit data, but cannot evaluate authority
- auditor: read-only decision/evidence/audit access with export permission
- owner/admin: organization management

Ownership transfer is a dedicated operation. Ordinary role editing cannot assign the owner role.

### Notifications

Consumer and institutional apps include one server-backed in-app notification system using:

- `notifications`
- `notification_preferences`

Categories:

- authority
- evidence
- identity
- organization
- webhook
- compliance
- security

Users can mark notifications read/unread, dismiss them, and suppress in-app delivery by category.

### Durable signed webhooks

Webhook signing secrets remain encrypted in Supabase Vault.

Delivery lifecycle:

- `pending`
- `dispatched`
- `retrying`
- `delivered`
- `dead_letter`

Each HTTP attempt is recorded independently. Automatic maintenance runs once per minute through one `pg_cron` job:

`trustrelay-webhook-maintenance-v09`

Supported event catalog includes:

- `decision.created`
- `grant.revoked`
- `credential.revoked`
- `evidence.requested`
- `evidence.submitted`
- `evidence.resolved`
- `organization.member.joined`
- `organization.member.role_changed`
- `organization.member.disabled`
- `compliance.export.ready`
- `webhook.test`

Operational controls include test delivery, pause/resume, signing-secret rotation, manual redelivery, attempt history, failure thresholds, and dead-letter visibility.

### Compliance and audit exports

Authorized owner/admin/compliance/auditor members can generate JSON or CSV exports.

Default range: 30 days  
Maximum range: 366 days  
Private signed-download URL: 5 minutes  
Export metadata lifetime: 24 hours

Selectable sections:

- decisions
- organization audit
- webhooks and delivery attempts
- members/invitations
- evidence-request workflow
- partner API-key metadata
- organization notifications

Raw API keys, Vault secrets, service-role credentials, and private identity-document bytes are excluded.

Every completed artifact records:

- exact content SHA-256
- row count
- byte size
- organization audit-chain status
- previous export hash
- current export hash

Exports are stored in the private `trustrelay-compliance-exports` bucket.

### Partner API

The compatibility route remains:

`/functions/v1/trustrelay-partner-v07`

Health version:

`0.9.0`

New decisions persist:

- `policy_version = v0.9`
- `engine_version = 0.9.0`

The signed authority credential format remains v0.8 because v0.9 changes operational/institutional behavior rather than the credential claim schema.

### Verification completed

- organization RBAC/ownership rollback matrix passed
- organization audit chain remained valid
- notification read/preferences/dismiss matrix passed
- live webhook HTTP 204 delivery passed
- forced HTTP 500 dead-letter path passed
- webhook smoke artifacts and Vault secret were removed afterward
- verifier was denied compliance export
- compliance role successfully built/finalized an export
- export content hash and per-org export hash were generated
- audit-only export contained organization audit records and a valid chain
- Partner API live health returned HTTP 200 / 0.9.0
- unauthenticated compliance export returned HTTP 401
- all consumer/verifier/reviewer browser bundles pass JavaScript syntax validation
- Supabase Security Advisor reports no v0.9 database/RLS/SECURITY DEFINER finding

The one remaining Auth warning is Supabase Free-plan leaked-password protection; TrustRelay user authentication is passwordless.

See:

- `docs/V0.9-OPERATIONS-COMPLIANCE.md`
- `docs/V0.9-IMPLEMENTATION-RESULT.md`
- `verifier/openapi.json`


## v0.9 Webhooks, Notifications, Roles & Compliance

TrustRelay v0.9 adds the operational controls needed by institutional users:

- explicit organization roles: owner, admin, compliance, verifier, developer, auditor
- server-enforced least-privilege dashboard responses
- signed webhook lifecycle management
- pg_net/Cron delivery with retry, attempt history and dead-letter handling
- in-app notification inboxes and per-category preferences
- hash-chained organization administrative audit events
- private JSON/CSV compliance exports
- SHA-256 artifact integrity
- per-organization export hash chaining
- five-minute signed export downloads
- 24-hour export availability

Canonical webhook delivery runs through the database maintenance job rather than a public worker.

Canonical compliance exporter:

`trustrelay-compliance-export-v09`

See:

- `docs/V0.9-WEBHOOKS-RBAC-COMPLIANCE.md`
- `verifier/openapi.json`


## v1.0 Production Candidate

TrustRelay v1.0 adds production hardening, versioned onboarding/legal acceptance, commercial plan entitlements, a Stripe billing adapter, and fail-closed production activation.

### Production runtime

Sandbox organizations continue to operate within plan limits.

A live organization must continuously satisfy:

- approved production onboarding
- active/trial/manual-contract billing
- plan entitlement capacity

The Partner API remains on its stable compatibility route while reporting engine version `1.0.0`.

### Onboarding

The Verifier Portal now includes a **Launch** workspace for:

- production organization profile
- legal entity/contact details
- legal-package status
- billing plan/state
- production blockers
- activation request

Consumer accounts have a versioned legal-acceptance gate that activates only when binding/effective Consumer Terms and Privacy versions are published.

### Billing

`trustrelay-billing-v10` supports:

- Stripe-hosted Checkout
- Stripe Billing Portal
- signed Stripe webhooks
- idempotent billing-event processing
- replay payload-hash protection

Commercial checkout remains disabled until production Stripe credentials and price IDs are configured.

### Legal & Trust Center

The candidate includes:

- Privacy Notice
- Consumer Terms
- Business Terms
- Data Processing Addendum
- Acceptable Use Policy
- Security Statement
- Subprocessor List
- Retention Notice

Current canonical documents are SHA-256–hashed review drafts and explicitly nonbinding/non-effective until counsel approval.

### Launch gates

Production activation is controlled by database-backed readiness controls and is currently blocked intentionally. See:

- `docs/V1.0-PRODUCTION-READINESS.md`
- `docs/V1.0-IMPLEMENTATION-RESULT.md`
- `docs/V1.0-PRODUCTION-ACTIVATION.md`
- `docs/V1.0-RELEASE-GATE-FINAL.md`
- `docs/V1.0-LEGAL-REVIEW-CHECKLIST.md`
- `docs/V1.0-INCIDENT-RESPONSE.md`
- `docs/V1.0-PRIVACY-REQUEST-PROCEDURE.md`
- `docs/V1.0-DISASTER-RECOVERY.md`

The public candidate remains `noindex` until the production backend, custom domain/SMTP, live billing, effective legal package, recovery controls and remaining security/operations gates are confirmed.
