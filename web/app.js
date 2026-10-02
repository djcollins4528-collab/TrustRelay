import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm";

const runtimeConfig = await fetch("/runtime-config.json", { cache: "no-store" })
  .then(async (response) => {
    if (!response.ok) throw new Error("RUNTIME_CONFIG_UNAVAILABLE");
    return response.json();
  });
const SUPABASE_URL = String(runtimeConfig.supabaseUrl || "").replace(/\/$/, "");
const SUPABASE_PUBLISHABLE_KEY = String(runtimeConfig.supabasePublishableKey || "");
const TRUSTRELAY_ENVIRONMENT = String(runtimeConfig.environment || "unknown");
const TRUSTRELAY_APP_VERSION = String(runtimeConfig.appVersion || "1.0.0");
if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) throw new Error("RUNTIME_CONFIG_INVALID");

const TURNSTILE_SITE_KEY = String(runtimeConfig.turnstileSiteKey || "");
let turnstileToken = "";
let turnstileWidgetId = null;
let turnstileScriptPromise = null;

function loadTurnstile() {
  if (!TURNSTILE_SITE_KEY) return Promise.resolve(null);
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!turnstileScriptPromise) {
    turnstileScriptPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.defer = true;
      script.onload = () => {
        const started = Date.now();
        const wait = () => {
          if (window.turnstile) return resolve(window.turnstile);
          if (Date.now() - started > 10000) return reject(new Error("SECURITY_CHECK_UNAVAILABLE"));
          setTimeout(wait, 50);
        };
        wait();
      };
      script.onerror = () => reject(new Error("SECURITY_CHECK_UNAVAILABLE"));
      document.head.appendChild(script);
    });
  }
  return turnstileScriptPromise;
}

async function mountTurnstile(form) {
  if (!TURNSTILE_SITE_KEY || !form || form.dataset.turnstileMounted === "1") return;
  form.dataset.turnstileMounted = "1";
  const slot = document.createElement("div");
  slot.className = "turnstile-slot";
  slot.style.margin = "12px 0";
  const submit = form.querySelector('button[type="submit"],input[type="submit"]');
  if (submit) form.insertBefore(slot, submit); else form.appendChild(slot);
  const turnstile = await loadTurnstile();
  turnstileWidgetId = turnstile.render(slot, {
    sitekey: TURNSTILE_SITE_KEY,
    callback: (token) => { turnstileToken = token || ""; },
    "expired-callback": () => { turnstileToken = ""; },
    "error-callback": () => { turnstileToken = ""; }
  });
}

function captchaTokenForAuth() {
  if (TURNSTILE_SITE_KEY && !turnstileToken) {
    throw new Error("Complete the security check and try again.");
  }
  return turnstileToken || undefined;
}

function resetTurnstile() {
  if (!TURNSTILE_SITE_KEY) return;
  turnstileToken = "";
  if (window.turnstile && turnstileWidgetId !== null) {
    try { window.turnstile.reset(turnstileWidgetId); } catch {}
  }
}


const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});

const state = {
  session: null,
  user: null,
  profile: null,
  identity: null,
  notifications: null,
  onboarding: null,
  privacyRequests: null,
  legalGateActive: false,
  grants: [],
  grantFilter: "all",
  currentView: "dashboard",
  customActions: [],
  customResources: [],
};

const $ = (id) => document.getElementById(id);
const qsa = (selector, root = document) => [...root.querySelectorAll(selector)];

const els = {
  authView: $("authView"),
  appView: $("appView"),
  publicVerifyView: $("publicVerifyView"),
  accountTopButton: $("accountTopButton"),
  notificationTopButton: $("notificationTopButton"),
  notificationTopBadge: $("notificationTopBadge"),
  authMessage: $("authMessage"),
  magicLinkForm: $("magicLinkForm"),
  otpForm: $("otpForm"),
  grantList: $("grantList"),
  assuranceBanner: $("assuranceBanner"),
  inviteResult: $("inviteResult"),
  verifyResult: $("verifyResult"),
  publicVerifyResult: $("publicVerifyResult"),
  modalBackdrop: $("modalBackdrop"),
  modalContent: $("modalContent"),
  toastRegion: $("toastRegion"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function parseJson(value, fallback) {
  if (value == null || value === "") return fallback;
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return fallback; }
}

function initials(nameOrEmail) {
  const value = String(nameOrEmail || "TR").trim();
  const words = value.includes("@") ? [value.split("@")[0]] : value.split(/\s+/);
  return words.slice(0, 2).map((x) => x[0]?.toUpperCase() || "").join("") || "TR";
}

function formatDate(value, includeTime = false) {
  if (!value) return "—";
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }
  ).format(d);
}

function formatMoney(value, currency = "USD") {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(n);
}

function statusLabel(status) {
  return {
    draft: "Draft",
    pending_acceptance: "Awaiting acceptance",
    pending_verification: "Pending verification",
    active: "Active",
    revoked: "Revoked",
    expired: "Expired",
    declined: "Declined",
    superseded: "Superseded",
  }[status] || String(status || "Unknown").replaceAll("_", " ");
}

function reasonLabel(code) {
  const map = {
    VALID: "Credential is valid",
    MALFORMED: "Credential format is invalid",
    MALFORMED_OR_UNKNOWN: "Credential is malformed or unknown",
    TOKEN_MISMATCH: "Stored credential does not match",
    CREDENTIAL_REVOKED: "Credential has been revoked",
    CREDENTIAL_EXPIRED: "Credential has expired",
    CREDENTIAL_SUPERSEDED: "Credential has been superseded",
    GRANT_REVOKED: "Authority grant has been revoked",
    GRANT_EXPIRED: "Authority grant has expired",
    GRANT_PENDING_VERIFICATION: "Authority grant is pending required identity verification",
    SIGNING_KEY_REVOKED: "Signing key has been revoked",
    SIGNATURE_INVALID: "Cryptographic signature is invalid",
    NOT_YET_VALID: "Credential is not valid yet",
    EXPIRED: "Credential has expired",
    CREDENTIAL_NOT_FOUND: "Credential is not recognized",
  };
  return map[code] || String(code || "Unknown verification result").replaceAll("_", " ");
}

function toast(message, type = "") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  els.toastRegion.appendChild(node);
  setTimeout(() => node.remove(), 4200);
}

function setMessage(element, message, type = "") {
  element.className = `message ${type}`;
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearMessage(element) {
  element.className = "message hidden";
  element.textContent = "";
}

function setBusy(button, busy, busyText = "Working…") {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

async function currentAccessToken() {
  const { data, error } = await supabase.auth.getSession();
  if (error) throw error;
  return data.session?.access_token || null;
}

async function invokeEdge(name, { method = "POST", body = null, authenticated = true } = {}) {
  const headers = {
    apikey: SUPABASE_PUBLISHABLE_KEY,
    accept: "application/json",
  };
  if (body != null) headers["content-type"] = "application/json";
  if (authenticated) {
    const token = await currentAccessToken();
    if (!token) throw new Error("AUTH_REQUIRED");
    headers.authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${SUPABASE_URL}/functions/v1/${name}`, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body),
  });

  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }

  if (!response.ok) {
    const code = data?.error?.code || data?.code || `HTTP_${response.status}`;
    const err = new Error(code);
    err.code = code;
    err.status = response.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function invokeRpc(name, args = {}) {
  const { data, error } = await supabase.rpc(name, args);
  if (error) throw error;
  if (data?.ok === false) {
    const err = new Error(data.code || "REQUEST_REJECTED");
    err.code = data.code || "REQUEST_REJECTED";
    err.status = data.status || 400;
    throw err;
  }
  return data;
}

function authRedirectUrl() {
  const url = new URL("/web/", window.location.origin);
  const pendingInvite = localStorage.getItem("trustrelay_pending_invite");
  if (pendingInvite) url.searchParams.set("invite", pendingInvite);
  return url.toString();
}

function showOtpEntry(show = true) {
  els.magicLinkForm.classList.toggle("hidden", show);
  els.otpForm.classList.toggle("hidden", !show);
  if (show) {
    const rememberedEmail = localStorage.getItem("trustrelay_last_auth_email") || $("passwordlessEmail").value.trim();
    if (rememberedEmail) $("otpEmail").value = rememberedEmail;
    setTimeout(() => $("otpCode").focus(), 0);
  }
  clearMessage(els.authMessage);
}

function showAuth(message = "") {
  els.publicVerifyView.classList.add("hidden");
  els.appView.classList.add("hidden");
  els.authView.classList.remove("hidden");
  els.accountTopButton.classList.add("hidden");
  els.notificationTopButton?.classList.add("hidden");
  if (message) setMessage(els.authMessage, message, "warning");
}

function showPublicVerify(token = "") {
  els.authView.classList.add("hidden");
  els.appView.classList.add("hidden");
  els.publicVerifyView.classList.remove("hidden");
  if (token) {
    $("publicVerifyToken").value = token;
    verifyCredential(token, els.publicVerifyResult);
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function showApp() {
  els.authView.classList.add("hidden");
  els.publicVerifyView.classList.add("hidden");
  els.appView.classList.remove("hidden");
  els.accountTopButton.classList.remove("hidden");
  els.notificationTopButton?.classList.remove("hidden");
}

function showWorkspaceView(name) {
  state.currentView = name;
  qsa(".workspace-view").forEach((view) => view.classList.add("hidden"));
  const map = {
    dashboard: "dashboardView",
    "new-grant": "newGrantView",
    "accept-invite": "acceptInviteView",
    verify: "verifyView",
    identity: "identityView",
    account: "accountView",
  };
  $(map[name] || "dashboardView").classList.remove("hidden");
  qsa(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  if (name === "dashboard") renderDashboard();
  if (name === "identity") renderIdentityCenter();
  if (name === "account") renderAccount();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function openModal(html) {
  els.modalContent.innerHTML = html;
  els.modalBackdrop.classList.remove("hidden");
}

function closeModal() {
  if (state.legalGateActive) return;
  els.modalBackdrop.classList.add("hidden");
  els.modalContent.innerHTML = "";
}

async function copyText(text, success = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast(success, "success");
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    toast(success, "success");
  }
}

function downloadText(filename, text, mime = "text/plain") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function setDefaultGrantDates() {
  const now = new Date();
  const later = new Date(now.getTime() + 30 * 86400000);
  const local = (d) => {
    const shifted = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    return shifted.toISOString().slice(0, 16);
  };
  $("validFrom").value = local(now);
  $("validUntil").value = local(later);
}

async function bootstrapProfile() {
  await invokeEdge("trustrelay-profile-v06", { method: "POST", body: {} });
  const [result, profileResult, identityResult, notificationResult, onboardingResult, privacyResult] = await Promise.all([
    invokeEdge("trustrelay-profile-v06", { method: "GET" }),
    invokeEdge("trustrelay-profile-v06", { method: "POST", body: {} }),
    invokeRpc("trustrelay_identity_center_v08"),
    invokeRpc("trustrelay_notifications_v09", { p_limit: 25, p_unread_only: false }),
    invokeRpc("trustrelay_user_onboarding_v10"),
    invokeRpc("trustrelay_my_privacy_requests_v10").catch(() => ({ requests: [] })),
  ]);
  state.profile = profileResult;
  state.identity = identityResult;
  state.notifications = notificationResult;
  state.onboarding = onboardingResult;
  state.privacyRequests = privacyResult;
  state.grants = Array.isArray(result?.grants) ? result.grants : [];
  return { profile: state.profile, grants: state.grants, identity: state.identity, notifications: state.notifications, onboarding: state.onboarding, privacyRequests: state.privacyRequests };
}

async function refreshApp({ preserveView = true } = {}) {
  if (!state.session) return showAuth();

  showApp();
  els.grantList.innerHTML = '<div class="loading-shimmer"></div><div class="loading-shimmer"></div>';

  try {
    const { data: userData } = await supabase.auth.getUser();
    state.user = userData.user || state.session.user;
    await bootstrapProfile();
    updateIdentityChrome();
    renderDashboard();
    renderIdentityCenter();
    renderAccount();
    renderNotificationChrome();

    if (await enforceConsumerLegalGate()) return;

    const pendingInvite = localStorage.getItem("trustrelay_pending_invite");
    if (pendingInvite) {
      $("inviteToken").value = pendingInvite;
      showWorkspaceView("accept-invite");
      toast("Invitation loaded. Review it before accepting.", "success");
    } else if (!preserveView) {
      showWorkspaceView("dashboard");
    } else {
      showWorkspaceView(state.currentView || "dashboard");
    }
  } catch (error) {
    console.error(error);
    toast("TrustRelay could not load your account. Try signing in again.", "error");
  }
}


async function enforceConsumerLegalGate() {
  const required = Array.isArray(state.onboarding?.requiredAcceptances) ? state.onboarding.requiredAcceptances : [];
  if (!required.length) {
    state.legalGateActive = false;
    return false;
  }

  state.legalGateActive = true;
  els.modalBackdrop.classList.remove("hidden");
  $("modalClose").classList.add("hidden");

  const rows = required.map(function (d) {
    return '<label class="management-row legal-accept-row">' +
      '<div><strong>' + escapeHtml(d.title || d.documentType) + '</strong>' +
      '<p>Version ' + escapeHtml(d.version) + ' · effective ' + escapeHtml(formatDate(d.effectiveAt)) + '</p>' +
      '<a href="..' + escapeHtml(d.urlPath) + '" target="_blank" rel="noopener">Review document</a></div>' +
      '<input type="checkbox" name="consumerLegalDoc" value="' + escapeHtml(d.id) + '" required>' +
      '</label>';
  }).join("");

  els.modalContent.innerHTML =
    '<p class="eyebrow">REQUIRED ACCOUNT TERMS</p>' +
    '<h2>Review updated TrustRelay terms.</h2>' +
    '<p>These published versions must be accepted before you continue using authenticated TrustRelay account features.</p>' +
    '<form id="consumerLegalAcceptanceForm">' +
      '<div class="management-list">' + rows + '</div>' +
      '<label class="check-consent"><input id="consumerLegalAuthority" type="checkbox" required> ' +
        '<span>I have reviewed the documents above and agree to the published TrustRelay terms that apply to my account.</span></label>' +
      '<button class="button primary full" type="submit">Accept and continue</button>' +
    '</form>';

  const form = $("consumerLegalAcceptanceForm");
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Recording acceptance…");
    try {
      const selected = qsa('input[name="consumerLegalDoc"]:checked', form).map(function (x) { return x.value; });
      if (selected.length !== required.length) throw new Error("Review and accept every required document.");
      for (const documentId of selected) {
        await invokeRpc("trustrelay_accept_legal_v10", {
          p_document_id: documentId,
          p_org_id: null,
          p_context: "consumer",
          p_metadata: { surface: "consumer-v1.0" },
        });
      }
      state.onboarding = await invokeRpc("trustrelay_user_onboarding_v10");
      state.legalGateActive = false;
      $("modalClose").classList.remove("hidden");
      els.modalBackdrop.classList.add("hidden");
      els.modalContent.innerHTML = "";
      renderAccount();
      toast("TrustRelay terms accepted.", "success");
      showWorkspaceView("dashboard");
    } catch (error) {
      toast(String(error?.code || error?.message || "LEGAL_ACCEPTANCE_FAILED").replaceAll("_", " "), "error");
      setBusy(button, false);
    }
  });

  return true;
}

function profileAccount() {
  return state.profile?.account || null;
}

function profilePerson() {
  return state.profile?.person || null;
}

function updateIdentityChrome() {
  const person = profilePerson();
  const name = person?.display_name || state.user?.user_metadata?.full_name || state.user?.email || "TrustRelay user";
  const email = state.user?.email || person?.email || "";
  const avatar = initials(name);

  $("sidebarName").textContent = name;
  $("sidebarEmail").textContent = email;
  $("sidebarAvatar").textContent = avatar;
  els.accountTopButton.textContent = avatar;
  $("dashboardGreeting").textContent = `Hello, ${name.split(" ")[0] || "there"}.`;

  const verified = person?.identity_status === "verified";
  const assurance = person?.identity_assurance_level || "none";
  els.assuranceBanner.innerHTML = `
    <div>
      <strong>${verified ? "Staging identity verified" : "Identity verification pending"}</strong>
      <span> — ${verified
        ? "Your confirmed email currently provides pilot-grade assurance for staging workflows."
        : "Confirm your account email before an authority grant can become active."}</span>
    </div>
    <span class="assurance-pill ${verified ? "verified" : "pending"}">${escapeHtml(assurance.replaceAll("_", " "))}</span>
  `;
}

function roleFor(record) {
  const personId = profilePerson()?.id;
  return record?.grant?.principal_person_id === personId ? "principal" : "representative";
}

function filteredGrants() {
  if (state.grantFilter === "all") return state.grants;
  return state.grants.filter((record) => roleFor(record) === state.grantFilter);
}

function renderNotificationChrome() {
  const count = Number(state.notifications?.unreadCount || 0);
  if (!els.notificationTopBadge) return;
  els.notificationTopBadge.textContent = String(Math.min(count, 99));
  els.notificationTopBadge.classList.toggle("hidden", count < 1);
}

async function openConsumerNotifications() {
  try {
    const data = await invokeRpc("trustrelay_notifications_v09", { p_limit: 50, p_unread_only: false });
    state.notifications = data;
    renderNotificationChrome();
    const notes = Array.isArray(data.notifications) ? data.notifications : [];
    const categories = ["authority","evidence","identity","organization","webhook","compliance","security"];
    openModal(`
      <p class="eyebrow">NOTIFICATIONS</p>
      <h2>TrustRelay activity.</h2>
      <p>${Number(data.unreadCount || 0)} unread notification${Number(data.unreadCount || 0) === 1 ? "" : "s"}.</p>
      <div class="notification-preferences">
        ${categories.map((cat) => `<label><input type="checkbox" data-consumer-pref="${cat}" ${data.preferences?.[cat] === false ? "" : "checked"}> ${cat}</label>`).join("")}
      </div>
      <div class="notification-list">
        ${notes.length ? notes.map((n) => `
          <article class="notification-item ${n.readAt ? "" : "unread"}">
            <div>
              <span class="small-chip">${escapeHtml(n.severity)}</span>
              <strong>${escapeHtml(n.title)}</strong>
              <p>${escapeHtml(n.body)}</p>
              <small>${escapeHtml(formatDate(n.createdAt, true))}</small>
            </div>
            <div class="management-actions">
              ${!n.readAt ? `<button class="button ghost small" data-consumer-note-read="${escapeHtml(n.id)}" type="button">Mark read</button>` : ""}
              <button class="button ghost small" data-consumer-note-dismiss="${escapeHtml(n.id)}" type="button">Dismiss</button>
            </div>
          </article>
        `).join("") : '<div class="empty-management">No notifications.</div>'}
      </div>
    `);
    qsa("[data-consumer-note-read]", els.modalContent).forEach((b) => b.onclick = async () => {
      await invokeRpc("trustrelay_mark_notification_v09", { p_notification_id: b.dataset.consumerNoteRead, p_action: "read" });
      await openConsumerNotifications();
    });
    qsa("[data-consumer-note-dismiss]", els.modalContent).forEach((b) => b.onclick = async () => {
      await invokeRpc("trustrelay_mark_notification_v09", { p_notification_id: b.dataset.consumerNoteDismiss, p_action: "dismiss" });
      await openConsumerNotifications();
    });
    qsa("[data-consumer-pref]", els.modalContent).forEach((box) => box.onchange = async () => {
      await invokeRpc("trustrelay_set_notification_preference_v09", { p_category: box.dataset.consumerPref, p_in_app: box.checked });
      toast("Notification preference updated.", "success");
    });
  } catch (error) {
    toast(String(error?.code || error?.message || "NOTIFICATIONS_FAILED").replaceAll("_", " "), "error");
  }
}

function renderDashboard() {
  const all = state.grants;
  const active = all.filter((r) => r.grant?.status === "active").length;
  const pending = all.filter((r) => ["pending_acceptance", "pending_verification"].includes(r.grant?.status)).length;
  const principal = all.filter((r) => roleFor(r) === "principal").length;
  const representative = all.filter((r) => roleFor(r) === "representative").length;

  $("metricActive").textContent = active;
  $("metricPending").textContent = pending;
  $("metricPrincipal").textContent = principal;
  $("metricRepresentative").textContent = representative;

  renderGrantList(filteredGrants());
}

function renderGrantList(records) {
  if (!records.length) {
    const template = $("emptyGrantTemplate");
    els.grantList.innerHTML = "";
    els.grantList.appendChild(template.content.cloneNode(true));
    return;
  }

  els.grantList.innerHTML = records.map((record) => {
    const g = record.grant || {};
    const role = roleFor(record);
    const other = role === "principal" ? record.representative : record.principal;
    const pendingEmail = g.representative_email;
    const otherLabel = other?.display_name || other?.email || pendingEmail || "Awaiting representative";
    const actions = parseJson(g.allowed_json, []);
    const resources = parseJson(g.resources_json, []);
    const rules = parseJson(g.rules_json, {});
    const credentials = Array.isArray(record.credentials) ? record.credentials : [];
    const activeCred = credentials.find((c) => c.status === "active");
    const canIssue = g.status === "active";
    const canRevoke = role === "principal" && !["revoked", "expired", "declined"].includes(g.status);
    const maxAmount = rules.maxAmount != null ? formatMoney(rules.maxAmount, rules.allowedCurrencies?.[0] || "USD") : "No amount cap";
    const statusClass = escapeHtml(g.status || "unknown");

    return `
      <article class="grant-card" data-grant-id="${escapeHtml(g.id)}">
        <div class="grant-card-main">
          <div>
            <div class="grant-title-row">
              <span class="role-label">${role === "principal" ? "YOU ARE PRINCIPAL" : "YOU ARE REPRESENTATIVE"}</span>
              <span class="status-chip ${statusClass}">${escapeHtml(statusLabel(g.status))}</span>
            </div>
            <h3>${role === "principal" ? "Authority granted to" : "Authority from"} ${escapeHtml(otherLabel)}</h3>
            <p>${actions.length ? escapeHtml(actions.map((x) => x.replaceAll("_", " ")).join(" · ")) : "No actions listed"}</p>
            <div class="grant-scope">
              ${resources.slice(0, 4).map((x) => `<span class="scope-tag">${escapeHtml(x)}</span>`).join("")}
              ${resources.length > 4 ? `<span class="scope-tag">+${resources.length - 4}</span>` : ""}
            </div>
          </div>
          <div class="grant-meta">
            <span><strong>Valid:</strong> ${escapeHtml(formatDate(g.valid_from))} → ${escapeHtml(formatDate(g.valid_until))}</span>
            <span><strong>Limit:</strong> ${escapeHtml(maxAmount)}</span>
            <span><strong>Credential:</strong> ${activeCred ? "Active" : "None active"}</span>
          </div>
          <div class="grant-actions">
            <button class="button ghost small" data-action="details" data-id="${escapeHtml(g.id)}" type="button">Details</button>
            ${canIssue ? `<button class="button secondary small" data-action="issue" data-id="${escapeHtml(g.id)}" type="button">${activeCred ? "Rotate credential" : "Issue credential"}</button>` : ""}
            ${canRevoke ? `<button class="button danger small" data-action="revoke" data-id="${escapeHtml(g.id)}" type="button">Revoke</button>` : ""}
          </div>
        </div>
        <div class="grant-expanded hidden" data-expanded="${escapeHtml(g.id)}">
          <dl class="detail-list">
            <dt>Grant ID</dt><dd>${escapeHtml(g.id)}</dd>
            <dt>Principal</dt><dd>${escapeHtml(record.principal?.display_name || record.principal?.email || g.principal_person_id)}</dd>
            <dt>Representative</dt><dd>${escapeHtml(other && role === "principal" ? (other.display_name || other.email) : (record.representative?.display_name || g.representative_email || "Awaiting acceptance"))}</dd>
            <dt>Status</dt><dd>${escapeHtml(statusLabel(g.status))}</dd>
            <dt>Version</dt><dd>${escapeHtml(g.grant_version || 1)}</dd>
          </dl>
          <dl class="detail-list">
            <dt>Allowed</dt><dd>${escapeHtml(actions.join(", ") || "—")}</dd>
            <dt>Resources</dt><dd>${escapeHtml(resources.join(", ") || "—")}</dd>
            <dt>Evidence</dt><dd>${rules.requireVerifiedEvidence ? "Verified document required" : (rules.requireEvidence ? "Supporting evidence required" : "Not required")}</dd>
            <dt>Minimum assurance</dt><dd>${escapeHtml((rules.minimumAssurance || "email_verified").replaceAll("_"," "))}</dd>
            <dt>Credentials</dt><dd>${credentials.length ? credentials.map((c) => `${escapeHtml(c.jti)} · ${escapeHtml(statusLabel(c.status))}`).join("<br>") : "None"}</dd>
          </dl>
        </div>
      </article>
    `;
  }).join("");
}

async function openPrivacyRequestModal() {
  try {
    const latest = await invokeRpc("trustrelay_my_privacy_requests_v10");
    state.privacyRequests = latest;
    const requests = Array.isArray(latest?.requests) ? latest.requests : [];
    openModal(`
      <p class="eyebrow">PRIVACY REQUESTS</p>
      <h2>Request access, correction or other privacy action.</h2>
      <p>TrustRelay may need to verify your identity and may retain records required for security, fraud prevention, disputes, accounting, authority/revocation evidence or other legal obligations.</p>
      <form id="privacyRequestForm">
        <div class="field">
          <label for="privacyRequestType">Request type</label>
          <select id="privacyRequestType">
            <option value="access">Access</option>
            <option value="correction">Correction</option>
            <option value="deletion">Deletion</option>
            <option value="restriction">Restriction</option>
            <option value="portability">Portability</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="field">
          <label for="privacyRequestDetails">Details <span class="optional-label">avoid unnecessary sensitive information</span></label>
          <textarea id="privacyRequestDetails" rows="5" maxlength="4000" placeholder="Describe what you are requesting."></textarea>
        </div>
        <button class="button primary" type="submit">Submit request</button>
      </form>
      <div class="section-heading"><div><h3>Your request history</h3></div></div>
      <div class="management-list">
        ${requests.length ? requests.map((r) => `
          <div class="management-row">
            <div><strong>${escapeHtml((r.requestType || "request").replaceAll("_"," "))}</strong>
              <p>${escapeHtml(r.status || "submitted")} · ${escapeHtml(formatDate(r.submittedAt,true))}</p>
              ${r.responseSummary ? `<p>${escapeHtml(r.responseSummary)}</p>` : ""}
            </div>
            <span class="small-chip">${escapeHtml(r.identityVerificationStatus || "pending")}</span>
          </div>
        `).join("") : '<div class="empty-management">No privacy requests yet.</div>'}
      </div>
    `);

    $("privacyRequestForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = event.submitter;
      setBusy(button, true, "Submitting…");
      try {
        await invokeRpc("trustrelay_submit_privacy_request_v10", {
          p_request_type: $("privacyRequestType").value,
          p_org_id: null,
          p_details: $("privacyRequestDetails").value.trim() || null,
        });
        toast("Privacy request submitted.", "success");
        state.privacyRequests = await invokeRpc("trustrelay_my_privacy_requests_v10");
        closeModal();
        renderAccount();
      } catch (error) {
        toast(String(error?.code || error?.message || "PRIVACY_REQUEST_FAILED").replaceAll("_"," "), "error");
        setBusy(button, false);
      }
    });
  } catch (error) {
    toast(String(error?.code || error?.message || "PRIVACY_REQUESTS_UNAVAILABLE").replaceAll("_"," "), "error");
  }
}

function renderAccount() {
  if (!state.user) return;
  const person = profilePerson();
  const account = profileAccount();
  $("accountDetails").innerHTML = `
    <dt>Name</dt><dd>${escapeHtml(person?.display_name || state.user.user_metadata?.full_name || "—")}</dd>
    <dt>Email</dt><dd>${escapeHtml(state.user.email || "—")}</dd>
    <dt>Auth user</dt><dd>${escapeHtml(state.user.id)}</dd>
    <dt>TrustRelay person</dt><dd>${escapeHtml(person?.id || "—")}</dd>
    <dt>Account status</dt><dd>${escapeHtml(account?.status || "active")}</dd>
    <dt>Sign-in method</dt><dd>Passwordless email magic link / OTP</dd>
    <dt>Joined</dt><dd>${escapeHtml(formatDate(state.user.created_at, true))}</dd>
  `;


  const legalRequired = Array.isArray(state.onboarding?.requiredAcceptances) ? state.onboarding.requiredAcceptances : [];
  const effectiveLegal = state.onboarding?.effectiveConsumerLegalPackagePublished === true;
  $("consumerLegalDetails").innerHTML =
    '<dl class="detail-list">' +
      '<dt>Published terms status</dt><dd>' + (!effectiveLegal ? "Pre-launch drafts only" : (legalRequired.length ? "Action required" : "Current")) + '</dd>' +
      '<dt>Required documents</dt><dd>' +
        (legalRequired.length ? escapeHtml(legalRequired.map(function (d) { return d.title || d.documentType; }).join(", ")) : "None") +
      '</dd>' +
    '</dl>' +
    '<p>' + (!effectiveLegal
      ? "TrustRelay has not published a binding effective consumer legal package yet. Current legal pages are pre-launch drafts."
      : (legalRequired.length
        ? "TrustRelay will require acceptance before normal authenticated use."
        : "You have no unaccepted effective consumer legal documents.")) + '</p>';

  const privacyItems = Array.isArray(state.privacyRequests?.requests) ? state.privacyRequests.requests : [];
  const openPrivacy = privacyItems.filter((r) => !["completed","denied","cancelled"].includes(r.status)).length;
  $("privacyRequestSummary").innerHTML =
    '<dl class="detail-list"><dt>Privacy requests</dt><dd>' +
    (privacyItems.length ? escapeHtml(String(openPrivacy) + " open · " + String(privacyItems.length) + " total") : "None") +
    '</dd></dl>';

  const verified = person?.identity_status === "verified";
  $("identityDetails").innerHTML = `
    <div class="assurance-banner">
      <div>
        <strong>${verified ? "Identity assurance active" : "Identity verification pending"}</strong>
        <span> — Current TrustRelay assurance reflects the strongest completed verification workflow.</span>
      </div>
      <span class="assurance-pill ${verified ? "verified" : "pending"}">${escapeHtml(person?.identity_assurance_level || "none")}</span>
    </div>
    <p>Email verification proves control of an email address. <strong>Document verified</strong> requires approved government-ID evidence. <strong>High assurance</strong> additionally requires approved address evidence or a future configured external KYC provider result.</p>
  `;
}

function activeProofingSession() {
  return (state.identity?.sessions || []).find((s) => ["collecting", "submitted", "in_review"].includes(s.status)) || null;
}

function renderIdentityCenter() {
  const identity = state.identity || {};
  const person = identity.person || profilePerson() || {};
  const level = person.identity_assurance_level || "none";
  const active = activeProofingSession();

  $("identityAssuranceCard").innerHTML = `
    <div>
      <strong>Current assurance: ${escapeHtml(level.replaceAll("_", " "))}</strong>
      <span> — ${level === "high_assurance"
        ? "Government-ID and address evidence were independently approved."
        : level === "document_verified"
          ? "Government-ID evidence was independently approved."
          : "Passwordless email verification is the current assurance baseline."}</span>
    </div>
    <span class="assurance-pill ${level === "none" ? "pending" : "verified"}">${escapeHtml(level.replaceAll("_", " "))}</span>
  `;

  $("proofingSession").innerHTML = active ? `
    <dl class="detail-list">
      <dt>Status</dt><dd>${escapeHtml(active.status)}</dd>
      <dt>Requested</dt><dd>${escapeHtml((active.requestedAssurance || "—").replaceAll("_", " "))}</dd>
      <dt>Started</dt><dd>${escapeHtml(formatDate(active.createdAt, true))}</dd>
      <dt>Submitted</dt><dd>${escapeHtml(formatDate(active.submittedAt, true))}</dd>
    </dl>
    ${active.status === "collecting" ? '<button id="submitProofingButton" class="button secondary full" type="button">Submit evidence for review</button>' : '<p class="fine-print">Evidence is locked for review. You can still view your uploaded files.</p>'}
  ` : '<div class="empty-state compact-empty"><p>No active proofing session.</p></div>';

  const docs = identity.documents || [];
  const grantOptions = state.grants.map((r) => `<option value="${escapeHtml(r.grant?.id)}">${escapeHtml(r.grant?.id || "")} · ${escapeHtml(statusLabel(r.grant?.status))}</option>`).join("");
  $("identityDocumentList").innerHTML = docs.length ? docs.map((d) => `
    <article class="management-row">
      <div>
        <strong>${escapeHtml(d.displayName || d.classification)}</strong>
        <p>${escapeHtml((d.classification || "other").replaceAll("_"," "))} · ${escapeHtml(d.mimeType || "—")} · ${d.sizeBytes ? Math.ceil(d.sizeBytes/1024) + " KB" : "—"}</p>
        <div class="row-meta">
          <span class="small-chip">${escapeHtml(d.scanStatus || "pending")}</span>
          <span class="small-chip">${escapeHtml(d.reviewStatus || "pending")}</span>
          ${d.contentSha256 ? `<span class="small-chip">sha256 ${escapeHtml(d.contentSha256.slice(0,12))}…</span>` : ""}
        </div>
      </div>
      <div class="management-actions">
        ${d.finalizedAt ? `<button class="button ghost small" data-download-doc="${escapeHtml(d.id)}" type="button">Download</button>` : ""}
        ${d.finalizedAt && grantOptions ? `<select class="compact-select" data-grant-select="${escapeHtml(d.id)}"><option value="">Attach to grant…</option>${grantOptions}</select><button class="button secondary small" data-attach-doc="${escapeHtml(d.id)}" type="button">Attach</button>` : ""}
      </div>
    </article>
  `).join("") : '<div class="empty-management">No private evidence uploaded yet.</div>';

  const requests = identity.evidenceRequests || [];
  $("evidenceRequestList").innerHTML = requests.length ? requests.map((r) => `
    <article class="management-row">
      <div><strong>Evidence request for ${escapeHtml(r.grantId)}</strong><p>Required: ${escapeHtml((r.requiredDocumentTypes || []).join(", ") || "supporting evidence")} · ${escapeHtml(r.status)}</p></div>
      <div class="management-actions">${docs.some((d)=>d.finalizedAt) ? `<select class="compact-select" data-request-doc-select="${escapeHtml(r.id)}"><option value="">Choose document…</option>${docs.filter(d=>d.finalizedAt).map(d=>`<option value="${escapeHtml(d.id)}">${escapeHtml(d.displayName || d.classification)}</option>`).join("")}</select><button class="button secondary small" data-attach-request="${escapeHtml(r.id)}" type="button">Submit</button>` : ""}</div>
    </article>
  `).join("") : '<div class="empty-management">No institutional evidence requests.</div>';

  const submit = $("submitProofingButton");
  if (submit) submit.onclick = async () => {
    setBusy(submit, true, "Submitting…");
    try {
      await invokeRpc("trustrelay_submit_proofing_v08", { p_session_id: active.id });
      toast("Identity evidence submitted for review.", "success");
      await refreshApp();
    } catch (e) {
      toast(String(e.code || e.message).replaceAll("_"," "), "error");
    } finally { setBusy(submit, false); }
  };
}

async function secureUploadIdentityDocument(file, classification, purpose) {
  const active = activeProofingSession();
  if (purpose === "identity" && !active) throw new Error("Start an identity proofing session first.");
  if (!file || !file.size) throw new Error("Choose a file.");
  if (file.size > 10485760) throw new Error("File exceeds the 10 MB limit.");
  const allowed = ["application/pdf","image/jpeg","image/png","image/webp"];
  if (!allowed.includes(file.type)) throw new Error("File type is not allowed.");

  const prepared = await invokeEdge("trustrelay-evidence-v08", {
    body: {
      action: "prepare",
      proofingSessionId: purpose === "identity" ? active.id : null,
      purpose, classification, filename: file.name, mimeType: file.type, sizeBytes: file.size,
    },
  });
  const upload = prepared.upload;
  const { error } = await supabase.storage
    .from(upload.bucket)
    .uploadToSignedUrl(upload.path, upload.token, file, { contentType: file.type, upsert: false });
  if (error) throw error;
  await invokeEdge("trustrelay-evidence-v08", { body: { action: "finalize", documentId: prepared.document.id } });
  return prepared.document.id;
}

function collectGrantPayload() {
  const checkedActions = qsa("#actionOptions input:checked").map((x) => x.value);
  const checkedResources = qsa("#resourceOptions input:checked").map((x) => x.value);
  const allowedActions = [...new Set([...checkedActions, ...state.customActions])];
  const resources = [...new Set([...checkedResources, ...state.customResources])];

  if (!allowedActions.length) throw new Error("Choose at least one allowed action.");
  if (!resources.length) throw new Error("Choose at least one resource.");

  const start = new Date($("validFrom").value);
  const end = new Date($("validUntil").value);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start) {
    throw new Error("Choose a valid start and expiration time.");
  }

  const rules = {};
  const maxRaw = $("maxAmount").value.trim();
  if (maxRaw !== "") {
    const maxAmount = Number(maxRaw);
    if (!Number.isFinite(maxAmount) || maxAmount < 0) throw new Error("Maximum amount must be zero or greater.");
    rules.maxAmount = maxAmount;
    rules.allowedCurrencies = [$("currency").value];
  }
  if ($("requireEvidence").checked) rules.requireEvidence = true;
  if ($("requireVerifiedEvidence").checked) rules.requireVerifiedEvidence = true;
  const minimumAssurance = $("minimumAssurance").value;
  if (minimumAssurance && minimumAssurance !== "email_verified") rules.minimumAssurance = minimumAssurance;

  return {
    representativeEmail: $("representativeEmail").value.trim(),
    allowedActions,
    prohibitedActions: [],
    resources,
    rules,
    escalation: $("escalateAboveLimit").checked ? { aboveLimit: "ESCALATE" } : {},
    validFrom: start.toISOString(),
    validUntil: end.toISOString(),
  };
}

function resetGrantForm() {
  $("grantForm").reset();
  state.customActions = [];
  state.customResources = [];
  renderCustomTags();
  setDefaultGrantDates();
  $("escalateAboveLimit").checked = true;
  $("minimumAssurance").value = "email_verified";
}

function renderCustomTags() {
  const render = (values, rootId, type) => {
    $(rootId).innerHTML = values.map((value, index) => `
      <span class="tag">${escapeHtml(value)}
        <button type="button" data-remove-${type}="${index}" aria-label="Remove">×</button>
      </span>
    `).join("");
  };
  render(state.customActions, "customActionTags", "action");
  render(state.customResources, "customResourceTags", "resource");
}

function modalInvitation(result) {
  const token = result.invitation?.token || "";
  const link = `${window.location.origin}${window.location.pathname}?invite=${encodeURIComponent(token)}`;
  const email = result.invitation?.email || "";
  openModal(`
    <p class="eyebrow">GRANT CREATED</p>
    <h2>Send the representative their invitation.</h2>
    <p>The grant is currently awaiting acceptance. This invitation token is a one-time capability: share it only with <strong>${escapeHtml(email)}</strong>.</p>
    <div class="invite-link-box">
      <label class="field">
        <span>Invitation link</span>
        <div class="secret-box">${escapeHtml(link)}</div>
      </label>
    </div>
    <p class="modal-warning">TrustRelay stores only a SHA-256 hash of the invitation token. If you lose this link before it is accepted, create a new grant invitation rather than trying to recover the token.</p>
    <div class="modal-actions">
      <button class="button ghost" id="copyInviteToken" type="button">Copy token</button>
      <button class="button secondary" id="emailInvite" type="button">Open email</button>
      <button class="button primary" id="copyInviteLink" type="button">Copy invitation link</button>
    </div>
  `);
  $("copyInviteToken").onclick = () => copyText(token, "Invitation token copied");
  $("copyInviteLink").onclick = () => copyText(link, "Invitation link copied");
  $("emailInvite").onclick = () => {
    const subject = encodeURIComponent("TrustRelay authority invitation");
    const body = encodeURIComponent(`You have been invited to accept a scoped TrustRelay authority grant.\n\nOpen this invitation:\n${link}\n\nUse the same email address this invitation was sent to.\n\nThis is a staging TrustRelay workflow.`);
    window.location.href = `mailto:${encodeURIComponent(email)}?subject=${subject}&body=${body}`;
  };
}

async function issueCredential(grantId, button) {
  setBusy(button, true, "Issuing…");
  try {
    const result = await invokeEdge("trustrelay-credential-issue-v06", {
      method: "POST",
      body: { grantId },
    });
    const token = result?.token;
    const credential = result?.credential || {};
    if (!token) throw new Error("Credential token was not returned.");

    openModal(`
      <p class="eyebrow">SIGNED CREDENTIAL ISSUED</p>
      <h2>Authority credential ready.</h2>
      <p>This bearer credential proves the current scoped authority. Treat it like a sensitive access artifact and share it only with the verifier that needs it.</p>
      <div class="secret-box">${escapeHtml(token)}</div>
      <dl class="detail-list" style="margin-top:16px">
        <dt>JTI</dt><dd>${escapeHtml(credential.jti || "—")}</dd>
        <dt>Key ID</dt><dd>${escapeHtml(credential.kid || "—")}</dd>
        <dt>Algorithm</dt><dd>${escapeHtml(credential.alg || "ES256")}</dd>
        <dt>Expires</dt><dd>${escapeHtml(formatDate(credential.expiresAt, true))}</dd>
        <dt>Principal assurance</dt><dd>${escapeHtml(credential.assuranceAtIssue?.principal?.assuranceLevel || "—")}</dd>
        <dt>Representative assurance</dt><dd>${escapeHtml(credential.assuranceAtIssue?.representative?.assuranceLevel || "—")}</dd>
      </dl>
      <div class="modal-actions">
        <button class="button ghost" id="downloadCredential" type="button">Download .jwt</button>
        <button class="button primary" id="copyCredential" type="button">Copy credential</button>
      </div>
    `);
    $("copyCredential").onclick = () => copyText(token, "Credential copied");
    $("downloadCredential").onclick = () => downloadText(`trustrelay-${credential.jti || "credential"}.jwt`, token);
    toast("Signed ES256 credential issued.", "success");
    await refreshApp();
  } catch (error) {
    console.error(error);
    const code = error.code || error.message;
    if (code === "PENDING_VERIFICATION") {
      toast("Both participants must have verified staging identities before a credential can be issued.", "error");
    } else {
      toast(`Credential issuance failed: ${code}`, "error");
    }
  } finally {
    setBusy(button, false);
  }
}

function confirmRevoke(grantId) {
  const record = state.grants.find((r) => r.grant?.id === grantId);
  if (!record) return;
  openModal(`
    <p class="eyebrow">REVOKE AUTHORITY</p>
    <h2>Revoke this grant?</h2>
    <p>Revocation is immediate. Every active credential for this grant will also be revoked and future verification will fail.</p>
    <div class="field">
      <label for="revokeReason">Reason</label>
      <input id="revokeReason" maxlength="500" placeholder="Optional reason for the audit trail">
    </div>
    <div class="modal-actions">
      <button class="button ghost" id="cancelRevoke" type="button">Cancel</button>
      <button class="button danger" id="confirmRevoke" type="button">Revoke grant</button>
    </div>
  `);
  $("cancelRevoke").onclick = closeModal;
  $("confirmRevoke").onclick = async (event) => {
    const button = event.currentTarget;
    setBusy(button, true, "Revoking…");
    try {
      await invokeEdge("trustrelay-grant-revoke-v06", {
        method: "POST",
        body: { grantId, reason: $("revokeReason").value.trim() },
      });
      closeModal();
      toast("Authority grant revoked.", "success");
      await refreshApp();
    } catch (error) {
      toast(`Revocation failed: ${error.code || error.message}`, "error");
      setBusy(button, false);
    }
  };
}

async function verifyCredential(token, resultElement) {
  resultElement.className = "verify-result empty";
  resultElement.innerHTML = `
    <div class="result-mark">…</div>
    <h3>Checking credential</h3>
    <p>Verifying cryptographic signature and live authority state.</p>
  `;

  try {
    const result = await invokeEdge("trustrelay-credential-verify-v06", {
      method: "POST",
      body: { token },
      authenticated: false,
    });
    const valid = Boolean(result?.valid);
    const authority = result?.authority || {};
    const currentAssurance = result?.currentAssurance || {};
    const assuranceAtIssue = result?.credential?.assuranceAtIssue || authority?.assuranceAtIssue || {};
    resultElement.className = `verify-result ${valid ? "valid" : "invalid"}`;
    resultElement.innerHTML = `
      <div class="result-mark">${valid ? "✓" : "×"}</div>
      <h3>${escapeHtml(reasonLabel(result?.reasonCode))}</h3>
      <p>${valid
        ? "The ES256 signature and live TrustRelay authority state passed verification."
        : "This credential should not be treated as current delegated authority."}</p>
      <div class="verify-grid">
        <div class="verify-line"><span>Result</span><span>${valid ? "VALID" : "INVALID"}</span></div>
        <div class="verify-line"><span>Reason code</span><span>${escapeHtml(result?.reasonCode || "—")}</span></div>
        <div class="verify-line"><span>Credential JTI</span><span>${escapeHtml(result?.credential?.jti || "—")}</span></div>
        <div class="verify-line"><span>Key ID</span><span>${escapeHtml(result?.credential?.kid || "—")}</span></div>
        <div class="verify-line"><span>Expires</span><span>${escapeHtml(formatDate(result?.credential?.expiresAt, true))}</span></div>
        ${valid ? `
          <div class="verify-line"><span>Grant ID</span><span>${escapeHtml(authority.grantId || "—")}</span></div>
          <div class="verify-line"><span>Principal</span><span>${escapeHtml(authority.principalPersonId || "—")}</span></div>
          <div class="verify-line"><span>Representative</span><span>${escapeHtml(authority.representativePersonId || "—")}</span></div>
          <div class="verify-line"><span>Allowed actions</span><span>${escapeHtml((authority.allowed || []).join(", ") || "—")}</span></div>
          <div class="verify-line"><span>Resources</span><span>${escapeHtml((authority.resources || []).join(", ") || "—")}</span></div>
          <div class="verify-line"><span>Principal assurance now</span><span>${escapeHtml(currentAssurance?.principal?.assuranceLevel || "—")}</span></div>
          <div class="verify-line"><span>Representative assurance now</span><span>${escapeHtml(currentAssurance?.representative?.assuranceLevel || "—")}</span></div>
          <div class="verify-line"><span>Principal assurance at issue</span><span>${escapeHtml(assuranceAtIssue?.principal?.assuranceLevel || "—")}</span></div>
          <div class="verify-line"><span>Representative assurance at issue</span><span>${escapeHtml(assuranceAtIssue?.representative?.assuranceLevel || "—")}</span></div>
        ` : ""}
      </div>
    `;
  } catch (error) {
    console.error(error);
    resultElement.className = "verify-result invalid";
    resultElement.innerHTML = `
      <div class="result-mark">×</div>
      <h3>Verification unavailable</h3>
      <p>TrustRelay could not complete the verification request. Try again in a moment.</p>
    `;
  }
}

function setupInviteFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const invite = params.get("invite");
  const verify = params.get("verify");
  if (invite) {
    localStorage.setItem("trustrelay_pending_invite", invite);
    $("inviteToken").value = invite;
  }
  if (verify) {
    $("publicVerifyToken").value = verify;
    showPublicVerify(verify);
    return true;
  }
  return false;
}

function setupHandlers() {
  void mountTurnstile(els.magicLinkForm).catch(() => setMessage(els.authMessage, "Security check could not load. Refresh and try again.", "error"));
  els.magicLinkForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(els.authMessage);
    const button = event.submitter;
    setBusy(button, true, "Sending secure link…");

    const email = $("passwordlessEmail").value.trim().toLowerCase();
    const fullName = $("passwordlessName").value.trim();

    try {
      const options = {
        shouldCreateUser: true,
        emailRedirectTo: authRedirectUrl(),
      };
      const captchaToken = captchaTokenForAuth();
      if (captchaToken) options.captchaToken = captchaToken;
      if (fullName) options.data = { full_name: fullName };

      const { error } = await supabase.auth.signInWithOtp({ email, options });
      if (error) throw error;

      localStorage.setItem("trustrelay_last_auth_email", email);
      $("otpEmail").value = email;
      setMessage(
        els.authMessage,
        "Check your email for a one-time TrustRelay sign-in link. If your email contains a six-digit code instead, choose “I have a one-time email code.”",
        "success"
      );
    } catch (error) {
      const message = error?.message || "Could not send the passwordless sign-in email.";
      setMessage(els.authMessage, message, "error");
    } finally {
      resetTurnstile();
      setBusy(button, false);
    }
  });

  $("showOtpButton").addEventListener("click", () => showOtpEntry(true));
  $("backToMagicLinkButton").addEventListener("click", () => showOtpEntry(false));

  els.otpForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(els.authMessage);
    const button = event.submitter;
    setBusy(button, true, "Verifying code…");

    const email = $("otpEmail").value.trim().toLowerCase();
    const token = $("otpCode").value.replace(/\s+/g, "");

    try {
      const { data, error } = await supabase.auth.verifyOtp({
        email,
        token,
        type: "email",
      });
      if (error) throw error;
      if (!data.session) throw new Error("TrustRelay could not establish a session from that code.");

      localStorage.setItem("trustrelay_last_auth_email", email);
      state.session = data.session;
      state.user = data.user;
      await refreshApp({ preserveView: false });
    } catch (error) {
      setMessage(
        els.authMessage,
        error?.message || "That one-time code is invalid or has expired. Request a new sign-in email.",
        "error"
      );
    } finally {
      setBusy(button, false);
    }
  });

  qsa(".nav-item").forEach((button) => button.addEventListener("click", () => showWorkspaceView(button.dataset.view)));
  qsa("[data-go]").forEach((button) => button.addEventListener("click", () => showWorkspaceView(button.dataset.go)));

  $("grantFilter").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-filter]");
    if (!button) return;
    state.grantFilter = button.dataset.filter;
    qsa("#grantFilter button").forEach((b) => b.classList.toggle("active", b === button));
    renderDashboard();
  });

  $("proofingStartForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Starting…");
    try {
      if (!$("proofingConsent").checked) throw new Error("Consent is required.");
      await invokeRpc("trustrelay_start_proofing_v08", {
        p_requested_assurance: $("requestedAssurance").value,
        p_consent_version: "v0.8",
      });
      toast("Identity proofing session started.", "success");
      await refreshApp();
      showWorkspaceView("identity");
    } catch (e) {
      toast(String(e.code || e.message).replaceAll("_"," "), "error");
    } finally { setBusy(button, false); }
  });

  $("identityUploadForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const file = $("documentFile").files?.[0];
    setBusy(button, true, "Uploading…");
    try {
      await secureUploadIdentityDocument(file, $("documentClassification").value, $("documentPurpose").value);
      toast("Private evidence uploaded and integrity-hashed.", "success");
      event.currentTarget.reset();
      await refreshApp();
      showWorkspaceView("identity");
    } catch (e) {
      toast(String(e.code || e.message).replaceAll("_"," "), "error");
    } finally { setBusy(button, false); }
  });

  $("identityDocumentList").addEventListener("click", async (event) => {
    const download = event.target.closest("[data-download-doc]");
    if (download) {
      setBusy(download,true,"Opening…");
      try {
        const x=await invokeEdge("trustrelay-evidence-v08",{body:{action:"download",documentId:download.dataset.downloadDoc}});
        window.open(x.url,"_blank","noopener,noreferrer");
      } catch(e){toast(String(e.code||e.message).replaceAll("_"," "),"error")} finally {setBusy(download,false)}
      return;
    }
    const attach = event.target.closest("[data-attach-doc]");
    if (attach) {
      const select=document.querySelector(`[data-grant-select="${CSS.escape(attach.dataset.attachDoc)}"]`);
      const grantId=select?.value;
      if(!grantId){toast("Choose a grant first.","error");return}
      setBusy(attach,true,"Attaching…");
      try{
        await invokeRpc("trustrelay_attach_document_to_grant_v08",{p_grant_id:grantId,p_document_id:attach.dataset.attachDoc});
        toast("Document attached to grant evidence.","success");
      }catch(e){toast(String(e.code||e.message).replaceAll("_"," "),"error")}finally{setBusy(attach,false)}
    }
  });

  $("evidenceRequestList").addEventListener("click", async (event) => {
    const button=event.target.closest("[data-attach-request]");
    if(!button)return;
    const select=document.querySelector(`[data-request-doc-select="${CSS.escape(button.dataset.attachRequest)}"]`);
    if(!select?.value){toast("Choose a document first.","error");return}
    setBusy(button,true,"Submitting…");
    try{
      await invokeRpc("trustrelay_attach_document_to_request_v08",{p_request_id:button.dataset.attachRequest,p_document_id:select.value});
      toast("Evidence submitted to the request.","success");
      await refreshApp();
    }catch(e){toast(String(e.code||e.message).replaceAll("_"," "),"error")}finally{setBusy(button,false)}
  });

  $("addCustomAction").addEventListener("click", () => {
    const input = $("customAction");
    const value = input.value.trim().replace(/\s+/g, "_").toLowerCase();
    if (value && !state.customActions.includes(value)) state.customActions.push(value);
    input.value = "";
    renderCustomTags();
  });
  $("addCustomResource").addEventListener("click", () => {
    const input = $("customResource");
    const value = input.value.trim();
    if (value && !state.customResources.includes(value)) state.customResources.push(value);
    input.value = "";
    renderCustomTags();
  });
  $("customActionTags").addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-action]");
    if (!button) return;
    state.customActions.splice(Number(button.dataset.removeAction), 1);
    renderCustomTags();
  });
  $("customResourceTags").addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-resource]");
    if (!button) return;
    state.customResources.splice(Number(button.dataset.removeResource), 1);
    renderCustomTags();
  });

  $("grantForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Creating grant…");
    try {
      const payload = collectGrantPayload();
      const result = await invokeEdge("trustrelay-grant-create-v06", { method: "POST", body: payload });
      modalInvitation(result);
      toast("Authority grant created.", "success");
      resetGrantForm();
      await refreshApp();
    } catch (error) {
      const message = error.code || error.message || "Grant creation failed.";
      toast(message.replaceAll("_", " "), "error");
    } finally {
      setBusy(button, false);
    }
  });

  $("inviteForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    clearMessage(els.inviteResult);
    setBusy(button, true, "Reviewing…");
    const token = $("inviteToken").value.trim();
    try {
      const preview = await invokeEdge("trustrelay-invite-preview-v061", {
        method: "POST",
        body: { token },
      });
      const grant = preview?.grant || {};
      const rules = grant.rules || {};
      const actions = Array.isArray(grant.allowed) ? grant.allowed : [];
      const resources = Array.isArray(grant.resources) ? grant.resources : [];
      const currency = Array.isArray(rules.allowedCurrencies) && rules.allowedCurrencies.length ? rules.allowedCurrencies[0] : "USD";
      const limit = rules.maxAmount != null ? formatMoney(rules.maxAmount, currency) : "No amount cap";
      const principal = preview?.principal?.displayName || preview?.principal?.email || "Principal";
      const html =
        '<p class="eyebrow">REVIEW AUTHORITY</p>' +
        '<h2>Accept authority from ' + escapeHtml(principal) + '?</h2>' +
        '<p>Review the exact authority below. Acceptance binds this grant to your authenticated TrustRelay identity. You cannot expand the scope.</p>' +
        '<dl class="detail-list" style="margin-top:18px">' +
          '<dt>Principal</dt><dd>' + escapeHtml(preview?.principal?.displayName || preview?.principal?.email || "—") + '</dd>' +
          '<dt>Starts</dt><dd>' + escapeHtml(formatDate(grant.validFrom, true)) + '</dd>' +
          '<dt>Expires</dt><dd>' + escapeHtml(formatDate(grant.validUntil, true)) + '</dd>' +
          '<dt>Allowed actions</dt><dd>' + escapeHtml(actions.join(", ") || "—") + '</dd>' +
          '<dt>Resources</dt><dd>' + escapeHtml(resources.join(", ") || "—") + '</dd>' +
          '<dt>Amount limit</dt><dd>' + escapeHtml(limit) + '</dd>' +
          '<dt>Evidence</dt><dd>' + (rules.requireVerifiedEvidence ? "Verified TrustRelay document required" : (rules.requireEvidence ? "Supporting evidence required" : "Not required")) + '</dd>' +
          '<dt>Minimum assurance</dt><dd>' + escapeHtml((rules.minimumAssurance || "email_verified").replaceAll("_"," ")) + '</dd>' +
        '</dl>' +
        '<p class="modal-warning">Only accept if you understand and intend to act within this scope. The principal can revoke the grant at any time.</p>' +
        '<div class="modal-actions">' +
          '<button class="button ghost" id="cancelInviteAcceptance" type="button">Cancel</button>' +
          '<button class="button primary" id="confirmInviteAcceptance" type="button">Accept scoped authority</button>' +
        '</div>';
      openModal(html);
      $("cancelInviteAcceptance").onclick = closeModal;
      $("confirmInviteAcceptance").onclick = async (confirmEvent) => {
        const confirmButton = confirmEvent.currentTarget;
        setBusy(confirmButton, true, "Accepting…");
        try {
          const result = await invokeEdge("trustrelay-invite-accept-v06", {
            method: "POST",
            body: { token },
          });
          localStorage.removeItem("trustrelay_pending_invite");
          closeModal();
          const status = result?.grant?.status;
          setMessage(
            els.inviteResult,
            status === "active"
              ? "Invitation accepted. The grant is active and can now issue a signed credential."
              : "Invitation accepted. The grant will activate when both participants complete staging verification.",
            "success"
          );
          toast("Authority invitation accepted.", "success");
          await refreshApp();
        } catch (error) {
          toast("Acceptance failed: " + String(error.code || error.message).replaceAll("_", " "), "error");
          setBusy(confirmButton, false);
        }
      };
    } catch (error) {
      setMessage(els.inviteResult, "Invitation could not be reviewed: " + String(error.code || error.message).replaceAll("_", " "), "error");
    } finally {
      setBusy(button, false);
    }
  });

    els.grantList.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const grantId = button.dataset.id;
    if (button.dataset.action === "details") {
      const expanded = document.querySelector(`[data-expanded="${CSS.escape(grantId)}"]`);
      expanded?.classList.toggle("hidden");
      button.textContent = expanded?.classList.contains("hidden") ? "Details" : "Hide details";
    }
    if (button.dataset.action === "issue") issueCredential(grantId, button);
    if (button.dataset.action === "revoke") confirmRevoke(grantId);
  });

  $("verifyForm").addEventListener("submit", (event) => {
    event.preventDefault();
    verifyCredential($("verifyToken").value.trim(), els.verifyResult);
  });
  $("publicVerifyForm").addEventListener("submit", (event) => {
    event.preventDefault();
    verifyCredential($("publicVerifyToken").value.trim(), els.publicVerifyResult);
  });

  $("verifyTopButton").addEventListener("click", () => {
    if (state.session) showWorkspaceView("verify");
    else showPublicVerify();
  });
  $("backFromPublicVerify").addEventListener("click", () => state.session ? (showApp(), showWorkspaceView("dashboard")) : showAuth());
  $("brandButton").addEventListener("click", () => state.session ? (showApp(), showWorkspaceView("dashboard")) : showAuth());
  els.accountTopButton.addEventListener("click", () => showWorkspaceView("account"));
  $("privacyRequestButton")?.addEventListener("click", openPrivacyRequestModal);
  els.notificationTopButton?.addEventListener("click", openConsumerNotifications);

  $("signOutButton").addEventListener("click", async () => {
    await supabase.auth.signOut();
    state.session = null;
    state.user = null;
    state.profile = null;
    state.identity = null;
    state.notifications = null;
    state.onboarding = null;
    state.privacyRequests = null;
    state.legalGateActive = false;
    state.grants = [];
    showAuth();
    toast("Signed out.", "success");
  });

  $("modalClose").addEventListener("click", closeModal);
  els.modalBackdrop.addEventListener("click", (event) => {
    if (event.target === els.modalBackdrop) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !els.modalBackdrop.classList.contains("hidden")) closeModal();
  });
}

async function initialize() {
  setupHandlers();
  setDefaultGrantDates();
  renderCustomTags();

  const rememberedEmail = localStorage.getItem("trustrelay_last_auth_email");
  if (rememberedEmail) {
    $("passwordlessEmail").value = rememberedEmail;
    $("otpEmail").value = rememberedEmail;
  }

  const specialRouteHandled = setupInviteFromUrl();

  const { data } = await supabase.auth.getSession();
  state.session = data.session;
  state.user = data.session?.user || null;

  supabase.auth.onAuthStateChange((event, session) => {
    state.session = session;
    state.user = session?.user || null;

    if (event === "SIGNED_OUT") {
      setTimeout(() => {
        showOtpEntry(false);
        showAuth();
      }, 0);
      return;
    }

    if (session && ["SIGNED_IN", "TOKEN_REFRESHED", "USER_UPDATED"].includes(event)) {
      setTimeout(() => refreshApp(), 0);
    }
  });

  if (specialRouteHandled && !state.session) return;

  if (state.session) {
    await refreshApp({ preserveView: false });
  } else {
    const pendingInvite = localStorage.getItem("trustrelay_pending_invite");
    showAuth(
      pendingInvite
        ? "Use the invited email address below. TrustRelay will send a one-time sign-in link so you can review the authority invitation."
        : ""
    );
  }
}

initialize().catch((error) => {
  console.error(error);
  showAuth("TrustRelay could not initialize. Refresh the page and try again.");
});
