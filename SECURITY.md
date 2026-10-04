# TrustRelay Security Policy

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use the public TrustRelay vulnerability-disclosure route at `/security/` or email `trustrelaysupport@gmail.com` with the subject `SECURITY REPORT`.

The machine-readable contact is published at `/.well-known/security.txt`. Include the affected component, reproduction steps, impact, and any relevant request/response details with secrets and personal data removed.

## Security posture

TrustRelay uses least-privilege database access, Row Level Security, authenticated or explicitly scoped public Edge Functions, private evidence/export storage, bounded request bodies and timeouts, restrictive browser security headers, runtime rate limiting, and fail-closed production readiness controls.

Never commit production secrets, private keys, service-role credentials, SMTP credentials, webhook signing secrets, Turnstile secrets, or local environment files.

## Supported version

Only the current production version on the `main` branch is supported for security fixes.


## Public assurance surfaces

TrustRelay publishes a Trust Center at `/legal/`, live current-state service health at `/status/`, a vulnerability-disclosure policy at `/security/`, and RFC 9116-compatible security contact metadata at `/.well-known/security.txt`. Historical uptime, third-party certifications, penetration-test completion, and counsel approval are not claimed until independently established.
