# TrustRelay Security Control Plane

This document records the production-security cutover controls without storing secret values.

## Source-control gate

Target state for the GitHub repository:

- Repository visibility: private.
- Default branch: `main`.
- An active branch ruleset targets `main`.
- Direct force-pushes and branch deletion are blocked.
- Pull requests are required before merge.
- Required checks include `Security Gates` and `CodeQL`.
- Linear history is required.
- Because TrustRelay currently has a single operator, the ruleset must not require an approval that the sole author cannot satisfy. Add required independent approval when a second trusted maintainer is available.
- GitHub Actions permissions remain least-privilege and third-party actions remain pinned to immutable commit SHAs.

Changing visibility or repository rules requires GitHub repository-administration permission. Verify Render retains GitHub access after making the repository private.

## Cloudflare edge target

The public production hostname should be a custom domain proxied through Cloudflare. The Render `onrender.com` hostname is not the intended public ingress once cutover is complete.

Recommended Cloudflare controls:

1. Proxy the production DNS record through Cloudflare.
2. Use Full (strict) TLS after Render has issued/validated the custom-domain certificate.
3. Enable Cloudflare DDoS protection.
4. Enable Cloudflare Managed Rules and the OWASP ruleset where the Cloudflare plan supports them.
5. Use Super Bot Fight Mode rather than indiscriminate Bot Fight Mode when API traffic needs explicit exceptions.
6. Add narrowly-scoped WAF/rate-limit rules for authentication, invitation, verification, upload, and API endpoints.
7. Enable DNSSEC after DNS is stable.
8. If CAA records are used, preserve the certificate authorities required by Render.
9. Configure a Cloudflare request-header transform rule that supplies the private origin-authentication header expected by TrustRelay. Never commit the header value.

## Strict-origin cutover

TrustRelay already supports an application-level edge-origin secret through `TRUSTRELAY_EDGE_ORIGIN_SECRET`. When enabled, requests other than the health endpoint must carry the matching `x-trustrelay-edge-origin` header.

Safe activation order:

1. Add and verify the custom domain in Render.
2. Proxy the domain through Cloudflare and confirm normal application behavior.
3. Configure Cloudflare to inject the private origin header on requests to TrustRelay.
4. Set the same secret value as `TRUSTRELAY_EDGE_ORIGIN_SECRET` in Render.
5. Set `TRUSTRELAY_ALLOWED_HOSTS` to the approved custom production hostname(s).
6. Verify the custom domain succeeds through Cloudflare.
7. Verify direct-origin requests without the edge header fail closed.
8. Disable the Render `onrender.com` subdomain after the custom domain is verified.
9. Re-run DAST using the custom-domain target.

Do not enable step 4 before step 3: doing so would deny legitimate production traffic.

## Verification criteria

The cutover is complete only when all of the following are true:

- GitHub reports the repository as private.
- GitHub reports an active ruleset protecting `main`.
- The custom production domain resolves through Cloudflare.
- Cloudflare proxy/WAF/bot protections are active and tested without breaking partner API traffic.
- The Render `onrender.com` production subdomain is disabled.
- A direct-origin request without the private edge header is denied.
- The custom-domain request through Cloudflare succeeds.
- Production DAST scans the actual application and produces no false-clean result caused by an upstream block page.
- An independent third-party penetration test has been completed, findings triaged, fixes applied, and the retest accepted.

