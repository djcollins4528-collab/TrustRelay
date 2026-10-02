# TrustRelay Reviewer Governance Procedure

Status: Production operating procedure
System of record: private.identity_reviewers and public.reviewer_governance_events

## Purpose
Identity/evidence reviewer access is privileged. TrustRelay requires dual-control approval and documented reviewer readiness before a reviewer can be considered production-ready.

## Production reviewer requirements
A production reviewer must:
- have a dedicated TrustRelay account;
- have reviewer status set to active;
- have approval_status=approved;
- have a recorded training attestation;
- have been requested by a different account;
- have been approved by a different account;
- not self-approve;
- not have the reviewer approve their own request;
- be unexpired;
- be subject to periodic access review.

TrustRelay production readiness requires at least two reviewers meeting all of these conditions.

## Request and approval
1. A reviewer request is created by an authorized account.
2. A different authorized account performs the approval.
3. The approver confirms the requested reviewer identity, intended duties, least-privilege need, and training completion.
4. Approval, training attestation, expiry, and governance notes are recorded in the reviewer registry.
5. The governance event is written to reviewer_governance_events.

## Training attestation
Before activation, the reviewer must attest that they understand:
- evidence should be reviewed only for an authorized purpose;
- evidence must not be copied into unrelated systems;
- conflicts of interest must be disclosed;
- reviewer access must not be shared;
- suspicious or potentially fraudulent evidence must be escalated rather than silently accepted;
- reviewer actions are auditable.

## Access review and expiry
- Reviewer access should have an explicit expiry where practical.
- Access must be re-reviewed periodically and when duties change.
- Departed, inactive, or unnecessary reviewers must be disabled promptly.
- Production readiness must fail closed if fewer than two approved, trained, unexpired reviewers remain.

## Separation of duties
The requester, reviewer, and approving account must be distinct where enforced by the TrustRelay registry. No single person should be able to request, approve, and perform all production identity-review functions without independent oversight.

## Incident and exception handling
Any suspected reviewer-account compromise, policy breach, undisclosed conflict, or anomalous review behavior requires immediate suspension of that reviewer pending investigation under docs/INCIDENT-RESPONSE.md.

## Current launch gate
This procedure documents the governance standard but does not itself satisfy the reviewer_governance readiness control. That control becomes pass only when the production registry contains at least two real reviewers satisfying the database-enforced dual-control criteria.
