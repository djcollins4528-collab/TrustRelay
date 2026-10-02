# TrustRelay Incident Response Plan

Status: Production operational runbook
Owner: TrustRelay operations
Security / incident contact: trustrelaysupport@gmail.com

## Purpose
This runbook defines how TrustRelay detects, triages, contains, investigates, remediates, recovers from, and documents security and availability incidents. It applies to the dedicated TrustRelay production stack only: the TrustRelay GitHub repository, dedicated Render workspace, dedicated production Supabase project, dedicated TrustRelay Stripe account, and approved supporting services.

## Severity
- SEV-1 Critical: confirmed unauthorized access to production data or secrets; credential compromise; destructive data loss; active exploitation; production-wide outage affecting authorization/verification; or an incident likely to create material customer harm.
- SEV-2 High: contained security event with credible risk, major partial outage, failed billing/webhook integrity affecting customers, or suspected compromise not yet confirmed.
- SEV-3 Medium: limited-scope operational degradation, recoverable configuration issue, or suspicious activity with no evidence of compromise.
- SEV-4 Low: informational event, blocked abuse, or defect with no material security or availability impact.

## Initial response
1. Record UTC detection time, reporter, affected environment, and initial evidence.
2. Preserve relevant logs before making nonessential changes.
3. Identify whether staging or production is affected. Do not reuse credentials or resources across environments.
4. For SEV-1/SEV-2, suspend risky actions and rotate/revoke affected credentials as soon as practical.
5. Contain the affected service, account, token, webhook, endpoint, or data path while preserving evidence.
6. Do not move production data into unrelated projects, personal storage, AthleteOS, pluggedinpicks, or legacy infrastructure.

## Escalation and ownership
- The monitored incident route is trustrelaysupport@gmail.com.
- The current operator is responsible for technical coordination until incident ownership is explicitly reassigned.
- Any incident involving legal interpretation, regulatory notice, law-enforcement contact, contractual notice, or material financial exposure must be escalated for qualified legal/business review before external representations are made, unless immediate action is required to prevent ongoing harm.

## Investigation
- Establish a timeline from Render logs, Supabase Auth/database/Edge logs, Stripe events, GitHub history, and TrustRelay audit records as applicable.
- Identify affected accounts, organizations, credentials, records, environments, and time window.
- Preserve event IDs, request IDs, hashes, deploy SHAs, and relevant configuration state.
- Determine root cause and whether the event crossed a security boundary.

## Containment
- Revoke or rotate compromised keys and sessions.
- Disable affected integrations, webhooks, routes, or accounts when needed.
- Keep production fail-closed if the integrity of authorization, credential issuance, reviewer approval, or billing state cannot be established.
- Do not lower RLS, reviewer controls, environment isolation, or webhook SSRF/TLS controls as a recovery shortcut.

## Eradication and recovery
- Patch the root cause in the canonical GitHub repository.
- Validate changes in staging first when doing so does not prolong active harm.
- Deploy production from the canonical repository only.
- Confirm service health, security controls, data integrity, and audit continuity after recovery.
- Restore from an approved backup only after validating the restore point and integrity.

## Notifications
- Customer, contractual, regulator, payment-provider, and other external notification requirements are determined from the facts of the incident and applicable contracts/law.
- TrustRelay does not invent a universal breach-notification deadline.
- Preserve the decision record for whether notification was required, who approved it, when it was sent, and the factual basis.

## Post-incident review
For SEV-1/SEV-2 and meaningful SEV-3 incidents:
1. Produce a written timeline and root-cause analysis.
2. Record affected systems/data and confirmed impact.
3. Document containment and recovery actions.
4. Create corrective actions with owners.
5. Update tests, runbooks, alerts, and readiness evidence.
6. Review whether retention, reviewer governance, access control, backup/recovery, or customer communications need changes.

## Evidence handling
Incident evidence must remain in approved TrustRelay systems or approved secure evidence stores. Sensitive evidence must not be emailed in plaintext or copied into unrelated business systems.
