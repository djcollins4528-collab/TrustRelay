# TrustRelay Security Policy

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use the repository owner's private security contact or GitHub private vulnerability reporting when enabled.

Include the affected component, reproduction steps, impact, and any relevant request/response details with secrets removed.

## Security posture

TrustRelay uses least-privilege database access, Row Level Security, authenticated or explicitly scoped public Edge Functions, private evidence/export storage, bounded request bodies and timeouts, restrictive browser security headers, runtime rate limiting, and fail-closed production readiness controls.

Never commit production secrets, private keys, service-role credentials, SMTP credentials, webhook signing secrets, Turnstile secrets, or local environment files.

## Supported version

Only the current production version on the `main` branch is supported for security fixes.
