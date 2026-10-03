
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
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
});

const $ = (id) => document.getElementById(id);

function esc(v) {
  return String(v == null ? "" : v)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function toast(message, type) {
  const node = document.createElement("div");
  node.className = "toast " + (type || "");
  node.textContent = message;
  $("toastRegion").appendChild(node);
  setTimeout(() => node.remove(), 4200);
}

function showMessage(el, text, type) {
  el.className = "message " + (type || "");
  el.textContent = text;
  el.classList.remove("hidden");
}

function clearMessage(el) {
  el.className = "message hidden";
  el.textContent = "";
}

function setBusy(button, on, label) {
  if (!button) return;
  if (on) {
    button.dataset.original = button.textContent;
    button.textContent = label || "Working…";
    button.disabled = true;
  } else {
    button.textContent = button.dataset.original || button.textContent;
    button.disabled = false;
  }
}

function formatDate(v) {
  if (!v) return "—";
  const d = new Date(v);
  if (!Number.isFinite(d.getTime())) return String(v);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(d);
}

async function rpc(name, args) {
  const result = await supabase.rpc(name, args || {});
  if (result.error) throw result.error;
  const data = result.data;
  if (data && data.ok === false) {
    const err = new Error(data.code || "REQUEST_REJECTED");
    err.code = data.code || "REQUEST_REJECTED";
    err.status = data.status || 400;
    throw err;
  }
  return data;
}

async function accessToken() {
  const result = await supabase.auth.getSession();
  if (result.error) throw result.error;
  return result.data.session ? result.data.session.access_token : null;
}

async function evidenceEdge(body) {
  const token = await accessToken();
  if (!token) throw new Error("AUTH_REQUIRED");
  const response = await fetch(SUPABASE_URL + "/functions/v1/trustrelay-evidence-v08", {
    method: "POST",
    headers: {
      apikey: SUPABASE_PUBLISHABLE_KEY,
      authorization: "Bearer " + token,
      "content-type": "application/json",
      accept: "application/json"
    },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!response.ok) {
    const err = new Error(data && data.error ? data.error.code : "REQUEST_FAILED");
    err.code = data && data.error ? data.error.code : "REQUEST_FAILED";
    throw err;
  }
  return data;
}

function showAuth() {
  $("authView").classList.remove("hidden");
  $("consoleView").classList.add("hidden");
  $("signOut").classList.add("hidden");
}

function showConsole() {
  $("authView").classList.add("hidden");
  $("consoleView").classList.remove("hidden");
  $("signOut").classList.remove("hidden");
}

function openModal(html) {
  $("modalContent").innerHTML = html;
  $("modalBackdrop").classList.remove("hidden");
}

function closeModal() {
  $("modalBackdrop").classList.add("hidden");
  $("modalContent").innerHTML = "";
}

function renderQueue(data) {
  const sessions = data && Array.isArray(data.sessions) ? data.sessions : [];
  const root = $("reviewQueue");

  if (!sessions.length) {
    root.innerHTML = '<div class="empty-review"><strong>No identity proofing sessions are awaiting review.</strong><p>The queue is clear.</p></div>';
    return;
  }

  let html = "";
  for (const s of sessions) {
    html += '<article class="review-session" data-session="' + esc(s.id) + '">';
    html += '<div class="review-session-head"><div>';
    html += '<h3>' + esc((s.person && (s.person.displayName || s.person.email)) || "TrustRelay user") + '</h3>';
    html += '<p>' + esc((s.person && s.person.email) || "") +
      ' · requested ' + esc(String(s.requestedAssurance || "—").replaceAll("_", " ")) +
      ' · current ' + esc(String((s.person && s.person.currentAssurance) || "none").replaceAll("_", " ")) + '</p>';
    html += '<p>Session ' + esc(s.id) + ' · submitted ' + esc(formatDate(s.submittedAt || s.createdAt)) + '</p>';
    html += '</div><span class="assurance-pill pending">' + esc(s.status) + '</span></div>';
    html += '<div class="review-docs">';

    const docs = Array.isArray(s.documents) ? s.documents : [];
    for (const d of docs) {
      html += '<div class="review-doc"><div>';
      html += '<strong>' + esc(String(d.classification || "document").replaceAll("_", " ")) + '</strong>';
      html += '<p>' + esc(d.displayName || "") + ' · ' + esc(d.mimeType || "—") +
        ' · ' + (d.sizeBytes ? Math.ceil(d.sizeBytes / 1024) + " KB" : "—") + '</p>';
      html += '<p class="hash">SHA-256 ' + esc(d.contentSha256 || "not finalized") + '</p>';
      html += '<p>Review state: <strong>' + esc(d.reviewStatus || "pending") + '</strong></p>';
      html += '</div><div class="review-actions">';
      html += '<button class="button ghost small" data-view-doc="' + esc(d.id) + '" type="button">View private file</button>';
      if (d.reviewStatus === "pending") {
        html += '<button class="button secondary small" data-review-doc="' + esc(d.id) + '" data-decision="approved" type="button">Approve</button>';
        html += '<button class="button danger small" data-review-doc="' + esc(d.id) + '" data-decision="rejected" type="button">Reject</button>';
      }
      html += '</div></div>';
    }

    html += '</div><div class="session-actions">';
    html += '<button class="button danger" data-review-session="' + esc(s.id) + '" data-decision="rejected" type="button">Reject proofing</button>';
    html += '<button class="button primary" data-review-session="' + esc(s.id) + '" data-decision="approved" type="button">Approve ' +
      esc(String(s.requestedAssurance || "assurance").replaceAll("_", " ")) + '</button>';
    html += '</div></article>';
  }

  root.innerHTML = html;
}

async function loadQueue() {
  clearMessage($("queueMessage"));
  try {
    const data = await rpc("trustrelay_review_queue_v08");
    showConsole();
    renderQueue(data);
  } catch (e) {
    const code = e.code || e.message;
    if (code === "IDENTITY_REVIEWER_REQUIRED") {
      showAuth();
      showMessage($("authMessage"), "This account is authenticated but is not provisioned as a TrustRelay identity reviewer.", "error");
      return;
    }
    if (code === "ACCOUNT_NOT_BOUND") {
      showAuth();
      showMessage($("authMessage"), "This reviewer account is not bound to a TrustRelay account.", "error");
      return;
    }
    showMessage($("queueMessage"), String(code || "QUEUE_FAILED").replaceAll("_", " "), "error");
  }
}

function reviewDialog(kind, id, decision) {
  const approved = decision === "approved";
  let html = '<p class="eyebrow">' + (kind === "document" ? "DOCUMENT REVIEW" : "IDENTITY PROOFING REVIEW") + '</p>';
  html += '<h2>' + (approved ? "Approve" : "Reject") + ' this ' + (kind === "document" ? "document" : "proofing session") + '?</h2>';
  html += '<p>' + (approved
    ? "Confirm that you independently reviewed the private evidence and that it supports the requested TrustRelay decision."
    : "Record a reason so the user and audit trail can distinguish a failed review from an incomplete workflow.") + '</p>';
  html += '<form id="reviewForm">';
  html += '<input type="hidden" id="reviewKind" value="' + esc(kind) + '">';
  html += '<input type="hidden" id="reviewId" value="' + esc(id) + '">';
  html += '<input type="hidden" id="reviewDecision" value="' + esc(decision) + '">';
  html += '<div class="field"><label for="reviewReason">Reason code</label>';
  html += '<input id="reviewReason" maxlength="120" required placeholder="' + (approved ? "EVIDENCE_CONFIRMED" : "EVIDENCE_MISMATCH") + '"></div>';
  html += '<div class="field"><label for="reviewNotes">Reviewer notes <span class="optional-label">max 2,000 characters</span></label>';
  html += '<textarea id="reviewNotes" rows="5" maxlength="2000" placeholder="Internal review notes"></textarea></div>';
  html += '<div class="modal-actions"><button class="button ghost" id="cancelReview" type="button">Cancel</button>';
  html += '<button class="button ' + (approved ? "primary" : "danger") + '" type="submit">' + (approved ? "Approve" : "Reject") + '</button></div></form>';
  openModal(html);
  $("cancelReview").onclick = closeModal;
}

function setupHandlers() {
  void mountTurnstile($("magicForm")).catch(() => showMessage($("authMessage"), "Security check could not load. Refresh and try again.", "error"));
  $("magicForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Sending…");
    clearMessage($("authMessage"));
    try {
      const email = $("email").value.trim().toLowerCase();
      const result = await supabase.auth.signInWithOtp({
        email,
        options: {
          shouldCreateUser: false,
          emailRedirectTo: new URL("/reviewer/", location.origin).toString(),
          ...(captchaTokenForAuth() ? { captchaToken: captchaTokenForAuth() } : {})
        }
      });
      if (result.error) throw result.error;
      showMessage($("authMessage"), "Check the reviewer email for a one-time TrustRelay sign-in link.", "success");
    } catch (err) {
      showMessage($("authMessage"), err.message || "Could not send sign-in link.", "error");
    } finally {
      resetTurnstile();
      setBusy(button, false);
    }
  });

  $("refreshQueue").onclick = loadQueue;
  $("signOut").onclick = () => supabase.auth.signOut();
  $("modalClose").onclick = closeModal;
  $("modalBackdrop").onclick = (event) => {
    if (event.target === $("modalBackdrop")) closeModal();
  };

  $("reviewQueue").addEventListener("click", async (event) => {
    const view = event.target.closest("[data-view-doc]");
    if (view) {
      setBusy(view, true, "Opening…");
      try {
        const x = await evidenceEdge({ action: "download", documentId: view.dataset.viewDoc });
        window.open(x.url, "_blank", "noopener,noreferrer");
      } catch (err) {
        toast(String(err.code || err.message).replaceAll("_", " "), "error");
      } finally {
        setBusy(view, false);
      }
      return;
    }

    const doc = event.target.closest("[data-review-doc]");
    if (doc) {
      reviewDialog("document", doc.dataset.reviewDoc, doc.dataset.decision);
      return;
    }

    const session = event.target.closest("[data-review-session]");
    if (session) reviewDialog("session", session.dataset.reviewSession, session.dataset.decision);
  });

  $("modalContent").addEventListener("submit", async (event) => {
    if (event.target.id !== "reviewForm") return;
    event.preventDefault();
    const button = event.submitter;
    setBusy(button, true, "Recording…");
    try {
      const kind = $("reviewKind").value;
      const id = $("reviewId").value;
      const decision = $("reviewDecision").value;
      const reason = $("reviewReason").value.trim();
      const notes = $("reviewNotes").value.trim() || null;

      if (kind === "document") {
        await rpc("trustrelay_review_document_v08", {
          p_document_id: id,
          p_decision: decision,
          p_reason_code: reason,
          p_notes: notes
        });
      } else {
        await rpc("trustrelay_review_proofing_v08", {
          p_session_id: id,
          p_decision: decision,
          p_reason_code: reason,
          p_notes: notes
        });
      }

      closeModal();
      toast("Review decision recorded.", "success");
      await loadQueue();
    } catch (err) {
      toast(String(err.code || err.message).replaceAll("_", " "), "error");
      setBusy(button, false);
    }
  });
}

async function init() {
  setupHandlers();
  const sessionResult = await supabase.auth.getSession();

  supabase.auth.onAuthStateChange((event, session) => {
    if (event === "SIGNED_OUT") {
      showAuth();
      return;
    }
    if (session && ["SIGNED_IN", "TOKEN_REFRESHED", "USER_UPDATED"].includes(event)) {
      setTimeout(loadQueue, 0);
    }
  });

  if (sessionResult.data.session) await loadQueue();
  else showAuth();
}

init().catch((e) => {
  console.error(e);
  showAuth();
  showMessage($("authMessage"), "Reviewer console could not initialize.", "error");
});
