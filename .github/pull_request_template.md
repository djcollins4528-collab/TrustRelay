## TrustRelay change review

### Security-sensitive change check
- [ ] Security Gates pass.
- [ ] CodeQL passes.
- [ ] No secrets, credentials, private keys, signing material, service-role keys, or live webhook secrets are committed.
- [ ] Authentication/authorization changes preserve active-session validation and fail closed.
- [ ] Database changes include a forward migration and preserve RLS/ACL least privilege.
- [ ] Edge-function auth mode is unchanged unless explicitly justified.
- [ ] Production runtime changes preserve host allowlisting, strict CSP, request limits, and internal-path isolation.
- [ ] Any new external dependency is pinned to an immutable version or commit.
- [ ] Legal/readiness controls are not marked PASS without external evidence.

### Deployment
- [ ] Staging validated where applicable.
- [ ] Production health and error logs checked after deployment.
- [ ] Security Advisor reviewed after Supabase security/schema changes.
