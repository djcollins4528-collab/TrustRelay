import http from "node:http";
import crypto from "node:crypto";

const SUPABASE_URL = "https://awrradmcwgeepwwdrbzi.supabase.co";
const PUBLISHABLE_KEY = "sb_publishable_YHwczFLXsSuJtOQDI_65Lw_dRcyLMjx";
const PORT = Number(process.env.PORT || 10000);

const state = {
  version: "0.6.1",
  phase: "starting",
  overall: null,
  runId: crypto.randomBytes(5).toString("hex"),
  steps: [],
  error: null,
  principalEmail: null,
  representativeEmail: null,
};

function logStep(name, ok, details = {}) {
  const entry = { name, ok, ...details };
  state.steps.push(entry);
  console.log(JSON.stringify({ type: "pilot_step", ...entry }));
}
function safeId(v) {
  if (!v) return null;
  const s = String(v);
  return s.length <= 16 ? s : s.slice(0, 8) + "…" + s.slice(-6);
}
function password() {
  return "Tr!" + crypto.randomBytes(18).toString("base64url") + "9";
}
async function request(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const err = new Error(data?.msg || data?.message || data?.error?.message || data?.error_description || ("HTTP_" + res.status));
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}
async function signup(email, pw, fullName) {
  return request(SUPABASE_URL + "/auth/v1/signup", {
    method: "POST",
    headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ email, password: pw, data: { full_name: fullName } }),
  });
}
async function signin(email, pw) {
  return request(SUPABASE_URL + "/auth/v1/token?grant_type=password", {
    method: "POST",
    headers: { apikey: PUBLISHABLE_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ email, password: pw }),
  });
}
async function edge(name, token, body, method = "POST") {
  const headers = { apikey: PUBLISHABLE_KEY, accept: "application/json" };
  if (token) headers.authorization = "Bearer " + token;
  if (body !== undefined) headers["content-type"] = "application/json";
  return request(SUPABASE_URL + "/functions/v1/" + name, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForConfirmedSignin(email, pw, label) {
  const deadline = Date.now() + 180000;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const session = await signin(email, pw);
      if (session?.access_token) {
        logStep(label + "_confirmed_signin", true);
        return session;
      }
    } catch (e) {
      last = e;
      if (![400, 401].includes(Number(e.status))) throw e;
    }
    await sleep(4000);
  }
  throw new Error(label + "_confirmation_timeout:" + (last?.message || "no_session"));
}

async function runPilot() {
  const suffix = state.runId;
  const pEmail = "trustrelay.pilot.principal." + suffix + "@athleteos-site.vercel.app";
  const rEmail = "trustrelay.pilot.representative." + suffix + "@athleteos-site.vercel.app";
  const pPw = password();
  const rPw = password();
  state.principalEmail = pEmail;
  state.representativeEmail = rEmail;

  try {
    state.phase = "signup";
    const pSignup = await signup(pEmail, pPw, "Pilot Principal");
    const pId = pSignup?.user?.id || pSignup?.id;
    if (!pId) throw new Error("principal_signup_missing_id");
    logStep("principal_signup", true, { userId: safeId(pId), sessionReturned: Boolean(pSignup?.access_token) });

    const rSignup = await signup(rEmail, rPw, "Pilot Representative");
    const rId = rSignup?.user?.id || rSignup?.id;
    if (!rId) throw new Error("representative_signup_missing_id");
    logStep("representative_signup", true, { userId: safeId(rId), sessionReturned: Boolean(rSignup?.access_token) });

    state.phase = "waiting_for_email_confirmation";
    console.log(JSON.stringify({
      type: "pilot_waiting_confirmation",
      principalEmail: pEmail,
      representativeEmail: rEmail
    }));

    const [pSession, rSession] = await Promise.all([
      waitForConfirmedSignin(pEmail, pPw, "principal"),
      waitForConfirmedSignin(rEmail, rPw, "representative")
    ]);

    state.phase = "profile_binding";
    const pProfile = await edge("trustrelay-profile-v06", pSession.access_token, {});
    const rProfile = await edge("trustrelay-profile-v06", rSession.access_token, {});
    if (!pProfile?.person?.id || !rProfile?.person?.id) throw new Error("profile_binding_missing");
    logStep("profile_binding", true, {
      principalVerified: pProfile.person.identity_status === "verified",
      representativeVerified: rProfile.person.identity_status === "verified",
      principalAssurance: pProfile.person.identity_assurance_level || null,
      representativeAssurance: rProfile.person.identity_assurance_level || null,
    });

    state.phase = "grant_creation";
    const start = new Date();
    const until = new Date(start.getTime() + 7 * 86400000);
    const grant = await edge("trustrelay-grant-create-v06", pSession.access_token, {
      representativeEmail: rEmail,
      allowedActions: ["pay_bill", "view_balance"],
      prohibitedActions: ["transfer_funds"],
      resources: ["checking:pilot"],
      rules: { maxAmount: 425, allowedCurrencies: ["USD"], requireEvidence: true },
      escalation: { aboveLimit: "ESCALATE" },
      validFrom: start.toISOString(),
      validUntil: until.toISOString(),
    });
    const grantId = grant?.grant?.id;
    const inviteToken = grant?.invitation?.token;
    if (!grantId || !inviteToken) throw new Error("grant_create_incomplete");
    logStep("grant_creation", true, {
      grantId: safeId(grantId),
      status: grant.grant.status,
      maxAmount: 425,
      evidenceRequired: true
    });

    state.phase = "invitation_review";
    const preview = await edge("trustrelay-invite-preview-v061", rSession.access_token, { token: inviteToken });
    const checks = {
      grantMatch: preview?.grant?.id === grantId,
      principalVisible: Boolean(preview?.principal),
      actionsMatch: Array.isArray(preview?.grant?.allowed) && preview.grant.allowed.includes("pay_bill") && preview.grant.allowed.includes("view_balance"),
      resourceMatch: Array.isArray(preview?.grant?.resources) && preview.grant.resources.includes("checking:pilot"),
      amountMatch: Number(preview?.grant?.rules?.maxAmount) === 425,
      evidenceMatch: preview?.grant?.rules?.requireEvidence === true,
    };
    if (Object.values(checks).some((v) => !v)) throw new Error("invitation_preview_scope_mismatch");
    logStep("invitation_review", true, checks);

    state.phase = "invitation_acceptance";
    const accepted = await edge("trustrelay-invite-accept-v06", rSession.access_token, { token: inviteToken });
    if (accepted?.grant?.id !== grantId) throw new Error("accept_grant_mismatch");
    if (accepted?.grant?.status !== "active") throw new Error("grant_not_active_after_accept:" + accepted?.grant?.status);
    logStep("invitation_acceptance", true, { status: accepted.grant.status });

    state.phase = "credential_issuance";
    const issued = await edge("trustrelay-credential-issue-v06", rSession.access_token, { grantId });
    const credentialToken = issued?.token;
    if (!credentialToken || !issued?.credential?.jti) throw new Error("credential_issue_incomplete");
    logStep("credential_issuance", true, {
      jti: safeId(issued.credential.jti),
      kid: safeId(issued.credential.kid),
      alg: issued.credential.alg,
      expiresAt: issued.credential.expiresAt
    });

    state.phase = "public_verification";
    const verified = await edge("trustrelay-credential-verify-v06", null, { token: credentialToken });
    if (verified?.valid !== true || verified?.reasonCode !== "VALID") throw new Error("verify_before_revoke:" + verified?.reasonCode);
    logStep("public_verification_before_revocation", true, {
      valid: verified.valid,
      reasonCode: verified.reasonCode,
      authorityGrantMatch: verified?.authority?.grantId === grantId,
    });

    state.phase = "revocation";
    const revoked = await edge("trustrelay-grant-revoke-v06", pSession.access_token, {
      grantId,
      reason: "TrustRelay v0.6.1 two-account staging pilot",
    });
    if (revoked?.grant?.status !== "revoked") throw new Error("revoke_status:" + revoked?.grant?.status);
    logStep("principal_revocation", true, { status: revoked.grant.status });

    const after = await edge("trustrelay-credential-verify-v06", null, { token: credentialToken });
    if (after?.valid !== false) throw new Error("credential_still_valid_after_revocation");
    logStep("public_verification_after_revocation", true, {
      valid: after.valid,
      reasonCode: after.reasonCode,
    });

    state.phase = "complete";
    state.overall = "PASS";
    console.log(JSON.stringify({ type: "pilot_complete", overall: state.overall, steps: state.steps }));
  } catch (e) {
    state.phase = "failed";
    state.overall = "FAIL";
    state.error = { message: String(e?.message || e), status: e?.status || null };
    console.error(JSON.stringify({ type: "pilot_failed", error: state.error, steps: state.steps }));
  }
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/" || req.url === "/status")) {
    const sanitized = {
      version: state.version,
      phase: state.phase,
      overall: state.overall,
      runId: state.runId,
      steps: state.steps,
      error: state.error,
      principalEmail: state.principalEmail,
      representativeEmail: state.representativeEmail,
    };
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify(sanitized));
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(JSON.stringify({ type: "pilot_worker_started", port: PORT }));
  runPilot();
});
