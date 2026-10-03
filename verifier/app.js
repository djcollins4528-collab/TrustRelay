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
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";\n      script.referrerPolicy = "no-referrer";
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


const AUTH_STORAGE_KEY = (() => {
  try {
    const projectRef = new URL(SUPABASE_URL).hostname.split(".")[0];
    return projectRef ? `sb-${projectRef}-auth-token` : "";
  } catch { return ""; }
})();
if (AUTH_STORAGE_KEY) {
  try { window.localStorage.removeItem(AUTH_STORAGE_KEY); } catch {}
}

const supabase=createClient(SUPABASE_URL,SUPABASE_PUBLISHABLE_KEY,{
  auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true,storage:window.sessionStorage}
});

const state={
  session:null,user:null,organizations:[],orgId:null,dashboard:null,currentView:"dashboard",notifications:null,launch:null,billing:null,platform:null,sso:null,scim:null,
  mfaGateActive:false,portalStarting:false,mfaStepUpPromise:null
};

const $=id=>document.getElementById(id);
const qsa=(s,r=document)=>[...r.querySelectorAll(s)];
const els={
  authView:$("authView"),portalView:$("portalView"),authMessage:$("authMessage"),
  modalBackdrop:$("modalBackdrop"),modalContent:$("modalContent"),toastRegion:$("toastRegion"),
  orgSelect:$("orgSelect"),accountButton:$("accountButton"),notificationButton:$("notificationButton"),notificationBadge:$("notificationBadge")
};

function esc(v){return String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}
function formatDate(v,time=false){if(!v)return"—";const d=new Date(v);if(!Number.isFinite(d.getTime()))return String(v);return new Intl.DateTimeFormat(undefined,time?{dateStyle:"medium",timeStyle:"short"}:{dateStyle:"medium"}).format(d)}
function initials(v){return String(v||"TR").split(/\s+|@/).filter(Boolean).slice(0,2).map(x=>x[0]?.toUpperCase()).join("")||"TR"}
function toast(m,t=""){const n=document.createElement("div");n.className="toast "+t;n.textContent=m;els.toastRegion.appendChild(n);setTimeout(()=>n.remove(),4200)}
function msg(el,m,t=""){el.className="message "+t;el.textContent=m;el.classList.remove("hidden")}
function clearMsg(el){el.className="message hidden";el.textContent=""}
function busy(btn,on,text="Working…"){if(!btn)return;if(on){btn.dataset.originalText=btn.textContent;btn.textContent=text;btn.disabled=true}else{btn.textContent=btn.dataset.originalText||btn.textContent;btn.disabled=false}}
function openModal(html){els.modalContent.innerHTML=html;els.modalBackdrop.classList.remove("hidden")}
function closeModal(){if(state.mfaGateActive)return;els.modalBackdrop.classList.add("hidden");els.modalContent.innerHTML=""}
function finishMfaGate(){state.mfaGateActive=false;$("modalClose").classList.remove("hidden");els.modalBackdrop.classList.add("hidden");els.modalContent.innerHTML=""}
async function copyText(text,label="Copied"){try{await navigator.clipboard.writeText(text);toast(label,"success")}catch{const a=document.createElement("textarea");a.value=text;a.className="clipboard-fallback";document.body.appendChild(a);a.select();document.execCommand("copy");a.remove();toast(label,"success")}}
function authRedirectUrl(){const u=new URL("/verifier/",window.location.origin);const token=sessionStorage.getItem("trustrelay_pending_org_invite");if(token)u.searchParams.set("org_invite",token);return u.toString()}
function showOtp(show){$("magicForm").classList.toggle("hidden",show);$("otpForm").classList.toggle("hidden",!show);if(show){const e=sessionStorage.getItem("trustrelay_verifier_email")||$("authEmail").value.trim();if(e)$("otpEmail").value=e;setTimeout(()=>$("otpCode").focus(),0)}clearMsg(els.authMessage)}
function setAuthenticated(on){els.authView.classList.toggle("hidden",on);els.portalView.classList.toggle("hidden",!on);els.accountButton.classList.toggle("hidden",!on);els.notificationButton?.classList.toggle("hidden",!on)}
const MFA_STEPUP_CODES=new Set(["MFA_ENROLLMENT_REQUIRED","MFA_CHALLENGE_REQUIRED","MFA_REAUTHENTICATION_REQUIRED"]);

async function forceVerifierMfaStepUp(){
  if(state.mfaStepUpPromise)return await state.mfaStepUpPromise;
  state.mfaStepUpPromise=(async()=>{
    const factors=await supabase.auth.mfa.listFactors();
    if(factors.error)throw factors.error;
    const all=[...(factors.data?.totp||[]),...(factors.data?.phone||[])];
    const verified=(factors.data?.totp||[]).find(x=>x.status==="verified");
    if(verified)return await promptMfaChallenge(verified);
    return await promptMfaEnrollment(all);
  })();
  try{return await state.mfaStepUpPromise}
  finally{state.mfaStepUpPromise=null}
}

async function rpc(name,args={},allowMfaRetry=true){
  const {data,error}=await supabase.rpc(name,args);
  if(error)throw error;
  if(data?.ok===false){
    const code=data.code||"REQUEST_REJECTED";
    if(allowMfaRetry&&MFA_STEPUP_CODES.has(code)){
      const ready=await forceVerifierMfaStepUp();
      if(ready)return await rpc(name,args,false);
    }
    const e=new Error(code);e.code=code;e.status=data.status;e.details=data;throw e
  }
  return data
}
async function token(){const {data,error}=await supabase.auth.getSession();if(error)throw error;return data.session?.access_token||null}

async function promptMfaChallenge(factor){
  state.mfaGateActive=true;
  $("modalClose").classList.add("hidden");
  openModal('<p class="eyebrow">ADMIN SECURITY</p><h2>Authenticator verification required.</h2><p class="security-gate-copy">Institutional TrustRelay access requires a verified authenticator factor. Enter the current six-digit code from your authenticator app.</p><form id="mfaChallengeForm"><div class="field"><label for="mfaChallengeCode">Authenticator code</label><input id="mfaChallengeCode" class="otp-input" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required placeholder="123456"></div><div id="mfaGateMessage" class="message hidden"></div><div class="modal-actions"><button class="button primary" type="submit">Verify & continue</button><button id="mfaSignOut" class="button ghost" type="button">Sign out</button></div></form>');
  return await new Promise((resolve)=>{
    $("mfaSignOut").onclick=async()=>{finishMfaGate();await supabase.auth.signOut();resolve(false)};
    $("mfaChallengeForm").onsubmit=async e=>{
      e.preventDefault();
      const b=e.submitter;busy(b,true,"Verifying…");
      try{
        const challenge=await supabase.auth.mfa.challenge({factorId:factor.id});
        if(challenge.error)throw challenge.error;
        const verify=await supabase.auth.mfa.verify({factorId:factor.id,challengeId:challenge.data.id,code:$("mfaChallengeCode").value.trim()});
        if(verify.error)throw verify.error;
        await supabase.auth.refreshSession();
        finishMfaGate();toast("Multi-factor verification complete.","success");resolve(true);
      }catch(err){msg($("mfaGateMessage"),err.message||"Authenticator verification failed.","error");busy(b,false)}
    };
    setTimeout(()=>$("mfaChallengeCode")?.focus(),0);
  });
}

async function promptMfaEnrollment(existingFactors=[]){
  for(const factor of existingFactors.filter(x=>x.factor_type==="totp"&&x.status!=="verified")){
    try{await supabase.auth.mfa.unenroll({factorId:factor.id})}catch{}
  }
  const enrolled=await supabase.auth.mfa.enroll({factorType:"totp",friendlyName:"TrustRelay Verifier"});
  if(enrolled.error)throw enrolled.error;
  const factor=enrolled.data;
  const qr=esc(factor?.totp?.qr_code||"");
  const secret=esc(factor?.totp?.secret||"");
  state.mfaGateActive=true;
  $("modalClose").classList.add("hidden");
  openModal('<p class="eyebrow">REQUIRED SECURITY SETUP</p><h2>Enable an authenticator app.</h2><p class="security-gate-copy">TrustRelay requires TOTP multi-factor authentication before institutional or administrative access. Scan this code with 1Password, Google Authenticator, Microsoft Authenticator, Authy, or another TOTP app.</p><div class="mfa-enrollment"><img class="mfa-qr" src="'+qr+'" alt="Authenticator enrollment QR code"><div><p class="fine-print">If you cannot scan the QR code, enter this secret manually:</p><div class="secret-once mfa-secret">'+secret+'</div></div></div><form id="mfaEnrollForm"><div class="field"><label for="mfaEnrollCode">Six-digit authenticator code</label><input id="mfaEnrollCode" class="otp-input" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required placeholder="123456"></div><div id="mfaGateMessage" class="message hidden"></div><div class="modal-actions"><button class="button primary" type="submit">Enable MFA & continue</button><button id="mfaSignOut" class="button ghost" type="button">Sign out</button></div></form>');
  return await new Promise((resolve)=>{
    $("mfaSignOut").onclick=async()=>{finishMfaGate();await supabase.auth.signOut();resolve(false)};
    $("mfaEnrollForm").onsubmit=async e=>{
      e.preventDefault();
      const b=e.submitter;busy(b,true,"Enabling…");
      try{
        const challenge=await supabase.auth.mfa.challenge({factorId:factor.id});
        if(challenge.error)throw challenge.error;
        const verify=await supabase.auth.mfa.verify({factorId:factor.id,challengeId:challenge.data.id,code:$("mfaEnrollCode").value.trim()});
        if(verify.error)throw verify.error;
        await supabase.auth.refreshSession();
        finishMfaGate();toast("Authenticator MFA enabled.","success");resolve(true);
      }catch(err){msg($("mfaGateMessage"),err.message||"Could not enable MFA.","error");busy(b,false)}
    };
    setTimeout(()=>$("mfaEnrollCode")?.focus(),0);
  });
}

async function ensureVerifierMfa(){
  const factors=await supabase.auth.mfa.listFactors();
  if(factors.error)throw factors.error;
  const all=[...(factors.data?.totp||[]),...(factors.data?.phone||[])];
  const verifiedTotp=(factors.data?.totp||[]).find(x=>x.status==="verified");
  const aal=await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if(aal.error)throw aal.error;
  if(verifiedTotp&&aal.data?.currentLevel==="aal2")return true;
  if(verifiedTotp)return await promptMfaChallenge(verifiedTotp);
  return await promptMfaEnrollment(all);
}

async function edgePost(functionName,body,fallbackCode,allowMfaRetry=true){
  const t=await token();if(!t)throw new Error("AUTH_REQUIRED");
  const r=await fetch(SUPABASE_URL+"/functions/v1/"+functionName,{
    method:"POST",
    headers:{apikey:SUPABASE_PUBLISHABLE_KEY,authorization:"Bearer "+t,"content-type":"application/json",accept:"application/json"},
    body:JSON.stringify(body)
  });
  const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}
  if(!r.ok){
    const code=data?.error?.code||fallbackCode;
    if(allowMfaRetry&&MFA_STEPUP_CODES.has(code)){
      const ready=await forceVerifierMfaStepUp();
      if(ready)return await edgePost(functionName,body,fallbackCode,false);
    }
    const e=new Error(code);e.code=code;e.status=r.status;e.details=data?.error?.details;throw e
  }
  return data
}
async function evaluate(body){return await edgePost("trustrelay-verifier-evaluate-v07",body,"EVALUATION_FAILED")}
async function evidenceFile(body){return await edgePost("trustrelay-evidence-v08",body,"EVIDENCE_REQUEST_FAILED")}
async function complianceEdge(body){return await edgePost("trustrelay-compliance-export-v09",body,"COMPLIANCE_REQUEST_FAILED")}
async function billingEdge(body){return await edgePost("trustrelay-billing-v10",body,"BILLING_REQUEST_FAILED")}
async function ssoEdge(body){return await edgePost("trustrelay-sso-v13",body,"SSO_REQUEST_FAILED")}
async function scimAdminEdge(body){return await edgePost("trustrelay-scim-admin-v14",body,"SCIM_REQUEST_FAILED")}
async function publicSsoEdge(body){
  const r=await fetch(SUPABASE_URL+"/functions/v1/trustrelay-sso-v13",{
    method:"POST",
    headers:{apikey:SUPABASE_PUBLISHABLE_KEY,"content-type":"application/json",accept:"application/json"},
    body:JSON.stringify(body)
  });
  const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}
  if(!r.ok){const e=new Error(data?.error?.code||"SSO_DISCOVERY_FAILED");e.code=data?.error?.code||"SSO_DISCOVERY_FAILED";e.status=r.status;e.details=data?.error?.details;throw e}
  return data
}

async function discoverEnterpriseSso(email){
  const normalized=String(email||"").trim().toLowerCase();
  if(!normalized||!normalized.includes("@"))throw new Error("Enter a valid work email.");
  return await publicSsoEdge({action:"discover",email:normalized});
}
async function startEnterpriseSso(email,known=null){
  const info=known||await discoverEnterpriseSso(email);
  if(!info?.ssoAvailable)throw new Error("No enterprise SSO configuration was found for this email domain.");
  sessionStorage.setItem("trustrelay_verifier_email",String(email||"").trim().toLowerCase());
  const redirectTo=authRedirectUrl();
  if(info.protocol==="oidc"){
    const {error}=await supabase.auth.signInWithOAuth({
      provider:info.providerIdentifier,
      options:{redirectTo}
    });
    if(error)throw error;
    return;
  }
  if(info.protocol==="saml"){
    const {data,error}=await supabase.auth.signInWithSSO({
      providerId:info.providerIdentifier,
      options:{redirectTo}
    });
    if(error)throw error;
    if(data?.url)window.location.assign(data.url);
    return;
  }
  throw new Error("Unsupported enterprise SSO protocol.");
}

function perms(){return state.dashboard?.membership?.permissions||{}}
function hasPerm(name){return perms()[name]===true}
function canManageKeys(){return hasPerm("api_keys.manage")}
function canManageWebhooks(){return hasPerm("webhooks.manage")}
function canInvite(){return hasPerm("members.manage")}
function canManageRoles(){return hasPerm("roles.manage")}
function canResolveEvidence(){return hasPerm("evidence.review")}
function canRequestEvidence(){return hasPerm("evidence.request")}
function canExportAudit(){return hasPerm("audit.export")}
function currentOrg(){return state.organizations.find(x=>x.organization?.id===state.orgId)?.organization||state.dashboard?.organization||null}

function showView(name){
  state.currentView=name;
  qsa(".portal-section").forEach(x=>x.classList.add("hidden"));
  const map={dashboard:"dashboardView",verify:"verifyView",evidence:"evidenceView",keys:"keysView",team:"teamView",sso:"ssoView",provisioning:"provisioningView",webhooks:"webhooksView",compliance:"complianceView",launch:"launchView",audit:"auditView",developer:"developerView"};
  $(map[name]||"dashboardView").classList.remove("hidden");
  qsa(".verifier-nav .nav-item").forEach(b=>b.classList.toggle("active",b.dataset.view===name));
  window.scrollTo({top:0,behavior:"smooth"});
}

async function loadOrganizations(){
  const data=await rpc("trustrelay_my_organizations_v07");
  state.organizations=Array.isArray(data.organizations)?data.organizations:[];
  els.orgSelect.innerHTML=state.organizations.map(x=>`<option value="${esc(x.organization.id)}">${esc(x.organization.name)} · ${esc(x.organization.mode)}</option>`).join("");
  if(state.organizations.length===0){
    state.orgId=null;state.dashboard=null;
    $("noOrgView").classList.remove("hidden");
    $("dashboardView").classList.add("hidden");
    return;
  }
  $("noOrgView").classList.add("hidden");
  if(!state.orgId||!state.organizations.some(x=>x.organization.id===state.orgId))state.orgId=state.organizations[0].organization.id;
  els.orgSelect.value=state.orgId;
  await loadDashboard();
}

async function loadDashboard(){
  if(!state.orgId)return;
  const results=await Promise.all([
    rpc("trustrelay_org_dashboard_v07",{p_org_id:state.orgId}),
    rpc("trustrelay_notifications_v09",{p_limit:1,p_unread_only:true}).catch(()=>({unreadCount:0,notifications:[]})),
    rpc("trustrelay_org_onboarding_v10",{p_org_id:state.orgId}).catch(()=>null),
    billingEdge({action:"status",orgId:state.orgId}).catch(e=>({error:{code:e.code||e.message},providerConfigured:false})),
    rpc("trustrelay_platform_readiness_v10",{p_org_id:state.orgId}).catch(()=>null),
    rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId}).catch(e=>({ok:false,error:{code:e.code||e.message}})),
    scimAdminEdge({action:"status",orgId:state.orgId}).catch(e=>({configured:false,error:{code:e.code||e.message}}))
  ]);
  state.dashboard=results[0];
  state.notifications=results[1];
  state.launch=results[2];
  state.billing=results[3];
  state.platform=results[4];
  state.sso=results[5];
  state.scim=results[6];
  render();
}

function render(){
  const d=state.dashboard;if(!d)return;
  const o=d.organization||{},m=d.metrics||{};
  $("orgHeading").textContent=o.name||"Institution";
  $("orgSubheading").textContent=`${String(o.mode||"sandbox").toUpperCase()} · ${String(d.membership?.role||"member").toUpperCase()} · ${o.slug||""}`;
  $("metricTotal").textContent=m.totalDecisions??0;$("metricAllow").textContent=m.allow??0;$("metricDeny").textContent=m.deny??0;$("metricEscalate").textContent=m.escalate??0;
  $("integrationHealth").innerHTML=`
    <dt>Organization mode</dt><dd><span class="mode-chip">${esc(o.mode||"sandbox")}</span></dd>
    <dt>Active partner keys</dt><dd>${m.activeKeys??0}</dd>
    <dt>Active members</dt><dd>${m.members??0}</dd>
    <dt>Active webhooks</dt><dd>${m.activeWebhooks??0}</dd>
    <dt>Dead-letter webhooks</dt><dd>${m.deadLetterWebhooks??0}</dd>
    <dt>Open evidence requests</dt><dd>${m.openEvidenceRequests??0}</dd>
    <dt>Ready exports</dt><dd>${m.readyExports??0}</dd>
    <dt>Your role</dt><dd>${esc(d.membership?.role||"—")}</dd>`;
  renderDecisions($("recentDecisions"),(d.recentDecisions||[]).slice(0,8),true);
  renderKeys();renderTeam();renderSso();renderScim();renderWebhooks();renderEvidenceRequests();renderCompliance();renderLaunch();renderAudit();renderDeveloper();renderNotificationBadge();
  $("createKeyButton").classList.toggle("hidden",!canManageKeys());
  $("createWebhookButton").classList.toggle("hidden",!canManageWebhooks());
  $("inviteMemberButton").classList.toggle("hidden",!canInvite());
  $("complianceExportForm")?.classList.toggle("hidden",!canExportAudit());
  $("verifyAuditChainButton")?.classList.toggle("hidden",!hasPerm("audit.read"));
  qsa('.verifier-nav [data-view="verify"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("decisions.evaluate")));
  qsa('.verifier-nav [data-view="evidence"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("evidence.read")));
  qsa('.verifier-nav [data-view="keys"]').forEach(x=>x.classList.toggle("hidden",!canManageKeys()));
  qsa('.verifier-nav [data-view="team"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("members.manage")));
  qsa('.verifier-nav [data-view="sso"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("organization.manage")));
  qsa('.verifier-nav [data-view="provisioning"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("organization.manage")));
  qsa('.verifier-nav [data-view="webhooks"]').forEach(x=>x.classList.toggle("hidden",!canManageWebhooks()));
  qsa('.verifier-nav [data-view="compliance"]').forEach(x=>x.classList.toggle("hidden",!canExportAudit()));
  qsa('.verifier-nav [data-view="launch"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("organization.manage")));
  qsa('.verifier-nav [data-view="audit"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("audit.read")));
  qsa('.verifier-nav [data-view="developer"]').forEach(x=>x.classList.toggle("hidden",!(canManageKeys()||canManageWebhooks())));
  qsa('[data-go="verify"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("decisions.evaluate")));
}

function renderDecisions(root,items,compact=false){
  if(!items.length){root.innerHTML='<div class="empty-management">No authorization decisions yet.</div>';return}
  root.innerHTML=items.map(x=>`
    <div class="decision-row">
      <span class="decision-badge ${esc(x.decision)}">${esc(x.decision)}</span>
      <div><strong>${esc(x.action)} → ${esc(x.resource)}</strong><p>${esc(x.reasonCode)} · ${esc(x.source||"api")}</p></div>
      <time>${esc(formatDate(x.decidedAt,true))}</time>
    </div>`).join("");
}

function renderKeys(){
  const items=state.dashboard?.apiKeys||[],root=$("keyList");
  if(!items.length){root.innerHTML='<div class="empty-management">No partner API keys yet. Create one for your server integration.</div>';return}
  root.innerHTML=items.map(k=>`
    <div class="management-row">
      <div><strong>${esc(k.name)}</strong><p>${esc(k.prefix)}••••${esc(k.lastFour||"")} · ${esc((k.scopes||[]).join(", "))}</p>
        <div class="row-meta"><span class="small-chip">${k.revokedAt?"revoked":"active"}</span><span class="small-chip">last used ${esc(formatDate(k.lastUsedAt,true))}</span></div>
      </div>
      <div class="management-actions">${!k.revokedAt&&canManageKeys()?`<button class="button danger small" data-revoke-key="${esc(k.id)}" type="button">Revoke</button>`:""}</div>
    </div>`).join("");
}

function renderTeam(){
  const root=$("teamList"),items=state.dashboard?.members||[];
  const roles=state.dashboard?.membership?.role==="owner"?["admin","compliance","verifier","developer","auditor"]:["compliance","verifier","developer","auditor"];
  root.innerHTML=items.length?items.map(x=>`
    <div class="management-row">
      <div><strong>${esc(x.email)}</strong><p>${esc(x.title||"Institution member")}</p><div class="row-meta"><span class="role-chip">${esc(x.role)}</span><span class="small-chip">${esc(x.status)}</span>${x.roleChangedAt?`<span class="small-chip">role changed ${esc(formatDate(x.roleChangedAt,true))}</span>`:""}</div></div>
      <div class="management-actions">
        ${x.status==="active"&&x.role!=="owner"&&canManageRoles()?`<select class="compact-select" data-role-account="${esc(x.accountId)}">${roles.map(r=>`<option value="${r}" ${r===x.role?"selected":""}>${r}</option>`).join("")}</select><button class="button secondary small" data-save-role="${esc(x.accountId)}" type="button">Save role</button>`:""}
        ${state.dashboard?.membership?.role==="owner"&&x.status==="active"&&x.role!=="owner"?`<button class="button ghost small" data-transfer-owner="${esc(x.accountId)}" type="button">Transfer ownership</button>`:""}
        ${x.role!=="owner"&&x.status==="active"&&canInvite()?`<button class="button danger small" data-disable-member="${esc(x.accountId)}" type="button">Disable</button><button class="button ghost small" data-remove-member="${esc(x.accountId)}" type="button">Remove</button>`:""}
        ${x.role!=="owner"&&x.status==="disabled"&&canInvite()?`<button class="button secondary small" data-enable-member="${esc(x.accountId)}" type="button">Restore</button><button class="button danger small" data-remove-member="${esc(x.accountId)}" type="button">Remove</button>`:""}
      </div>
    </div>`).join(""):'<div class="empty-management">No team members.</div>';
  const pending=state.dashboard?.pendingInvitations||[];
  $("pendingInvites").innerHTML=`<div class="card-heading"><div><h3>Pending invitations</h3><p>One-time team invitations awaiting acceptance.</p></div></div>`+(pending.length?pending.map(x=>`<div class="management-row"><div><strong>${esc(x.email)}</strong><p>${esc(x.role)} · expires ${esc(formatDate(x.expiresAt,true))}</p></div></div>`).join(""):'<div class="empty-management">No pending invitations.</div>');
}

function renderWebhooks(){
  const root=$("webhookList"),items=state.dashboard?.webhooks||[];
  root.innerHTML=items.length?items.map(w=>`
    <div class="management-row"><div><strong>${esc(w.name)}</strong><p>${esc(w.endpointUrl)}</p><div class="row-meta"><span class="small-chip">${esc(w.status)}</span><span class="small-chip">${esc(w.apiVersion||"v0.9")}</span><span class="small-chip">${esc((w.events||[]).join(", "))}</span><span class="small-chip">${w.consecutiveFailures||0}/${w.failureThreshold||10} failures</span>${w.pauseReason?`<span class="small-chip">${esc(w.pauseReason)}</span>`:""}</div></div>
    <div class="management-actions">${canManageWebhooks()&&w.status!=="revoked"?`<button class="button ghost small" data-test-webhook="${esc(w.id)}" type="button">Test</button>${w.status==="active"?`<button class="button ghost small" data-webhook-state="${esc(w.id)}" data-state="paused" type="button">Pause</button>`:["paused","disabled"].includes(w.status)?`<button class="button secondary small" data-webhook-state="${esc(w.id)}" data-state="active" type="button">Resume</button>`:""}<button class="button secondary small" data-rotate-webhook="${esc(w.id)}" type="button">Rotate secret</button><button class="button danger small" data-revoke-webhook="${esc(w.id)}" type="button">Revoke</button>`:""}</div></div>`).join(""):'<div class="empty-management">No webhook endpoints configured.</div>';
  const del=state.dashboard?.recentWebhookDeliveries||[];
  $("deliveryList").innerHTML=del.length?del.map(x=>`<div class="management-row"><div><strong>${esc(x.eventType)}</strong><p>${esc(x.eventId)} · HTTP ${esc(x.responseStatus??"—")} · ${esc(formatDate(x.createdAt,true))}</p><div class="row-meta"><span class="small-chip">${esc(x.status)}</span><span class="small-chip">${x.attemptCount||0}/${x.maxAttempts||5} attempts</span>${x.manualRedeliveries?`<span class="small-chip">${x.manualRedeliveries} manual retries</span>`:""}${x.nextAttemptAt?`<span class="small-chip">next ${esc(formatDate(x.nextAttemptAt,true))}</span>`:""}</div></div><div class="management-actions">${canManageWebhooks()&&["dead_letter","retrying"].includes(x.status)?`<button class="button secondary small" data-retry-webhook="${esc(x.id)}" type="button">Retry</button>`:""}</div></div>`).join(""):'<div class="empty-management">No webhook deliveries yet.</div>';
  const attempts=state.dashboard?.recentWebhookAttempts||[];
  $("webhookAttemptList").innerHTML=attempts.length?attempts.map(a=>`<div class="management-row"><div><strong>Attempt ${esc(a.attemptNumber)} · ${esc(a.deliveryId)}</strong><p>HTTP ${esc(a.responseStatus??"—")} · ${esc(formatDate(a.createdAt,true))}</p><div class="row-meta"><span class="small-chip">${a.success===true?"success":a.success===false?"failed":"pending"}</span>${a.durationMs!=null?`<span class="small-chip">${a.durationMs} ms</span>`:""}${a.error?`<span class="small-chip">${esc(a.error)}</span>`:""}</div></div></div>`).join(""):'<div class="empty-management">No webhook attempts yet.</div>';
}

function renderEvidenceRequests(){
  const root=$("evidenceRequestOrgList"),items=state.dashboard?.evidenceRequests||[];
  if(!root)return;
  if(!items.length){root.innerHTML='<div class="empty-management">No evidence requests yet.</div>';return}
  root.innerHTML=items.map(r=>{
    const docs=Array.isArray(r.documents)?r.documents:[];
    const docHtml=docs.length?docs.map(d=>`
      <div class="management-row">
        <div><strong>${esc(d.displayName||d.classification)}</strong><p>${esc((d.classification||"document").replaceAll("_"," "))} · ${esc(d.mimeType||"—")} · ${d.sizeBytes?Math.ceil(d.sizeBytes/1024)+" KB":"—"}</p><div class="row-meta"><span class="small-chip">${esc(d.reviewStatus||"pending")}</span><span class="small-chip">doc ${esc(d.id)}</span>${d.contentSha256?`<span class="small-chip">sha256 ${esc(d.contentSha256.slice(0,12))}…</span>`:""}</div></div>
        <div class="management-actions"><button class="button ghost small" data-org-evidence-doc="${esc(d.id)}" type="button">View file</button><button class="button secondary small" data-copy-evidence-doc="${esc(d.id)}" type="button">Copy document ID</button></div>
      </div>`).join(""):'<div class="empty-management">Awaiting document submission.</div>';
    return `
      <article class="portal-card">
        <div class="card-heading"><div><h3>Grant ${esc(r.grantId)}</h3><p>Request ${esc(r.id)} · ${esc((r.requiredDocumentTypes||[]).join(", ")||"supporting evidence")}</p></div><span class="small-chip">${esc(r.status)}</span></div>
        <div class="management-list">${docHtml}</div>
        ${r.status==="submitted"&&canResolveEvidence()?`<div class="modal-actions"><button class="button danger small" data-resolve-evidence="${esc(r.id)}" data-resolution="rejected" type="button">Reject evidence</button><button class="button primary small" data-resolve-evidence="${esc(r.id)}" data-resolution="satisfied" type="button">Mark satisfied</button></div>`:""}
      </article>`;
  }).join("");
}

function renderNotificationBadge(){
  const count=Number(state.notifications?.unreadCount||0);
  if(!els.notificationBadge)return;
  els.notificationBadge.textContent=String(Math.min(count,99));
  els.notificationBadge.classList.toggle("hidden",count<1);
}

function renderCompliance(){
  const root=$("complianceExportList");if(!root)return;
  if(!canExportAudit()){root.innerHTML='<div class="empty-management">Your role does not include compliance export permission.</div>';return}
  const items=state.dashboard?.complianceExports||[];
  root.innerHTML=items.length?items.map(e=>`
    <div class="management-row">
      <div><strong>${esc(e.format?.toUpperCase()||"EXPORT")} · ${esc(formatDate(e.createdAt,true))}</strong><p>${esc((e.scopes||[]).join(", "))} · ${esc(formatDate(e.fromAt,true))} → ${esc(formatDate(e.toAt,true))}</p><div class="row-meta"><span class="small-chip">${esc(e.status)}</span>${e.rowCount!=null?`<span class="small-chip">${esc(e.rowCount)} records</span>`:""}${e.sha256?`<span class="small-chip">sha256 ${esc(e.sha256.slice(0,12))}…</span>`:""}${e.exportHash?`<span class="small-chip">chain ${esc(e.exportHash.slice(0,12))}…</span>`:""}</div></div>
      <div class="management-actions">${e.status==="ready"?`<button class="button secondary small" data-download-export="${esc(e.id)}" type="button">Download</button>`:""}</div>
    </div>`).join(""):'<div class="empty-management">No compliance exports yet.</div>';
}

async function openNotifications(){
  try{
    const data=await rpc("trustrelay_notifications_v09",{p_limit:50,p_unread_only:false});
    state.notifications=data;
    const notes=Array.isArray(data.notifications)?data.notifications:[];
    const cats=["authority","evidence","identity","organization","webhook","compliance","security"];
    openModal(`<p class="eyebrow">NOTIFICATIONS</p><h2>TrustRelay activity.</h2><p>${Number(data.unreadCount||0)} unread notification${Number(data.unreadCount||0)===1?"":"s"}.</p>
      <div class="notification-preferences">${cats.map(cat=>`<label><input type="checkbox" data-notification-pref="${cat}" ${data.preferences?.[cat]===false?"":"checked"}> ${cat}</label>`).join("")}</div>
      <div class="notification-list">${notes.length?notes.map(n=>`<article class="notification-item ${n.readAt?"":"unread"}"><div><span class="small-chip">${esc(n.severity)}</span><strong>${esc(n.title)}</strong><p>${esc(n.body)}</p><small>${esc(formatDate(n.createdAt,true))}</small></div><div class="management-actions">${!n.readAt?`<button class="button ghost small" data-note-read="${esc(n.id)}" type="button">Mark read</button>`:""}<button class="button ghost small" data-note-dismiss="${esc(n.id)}" type="button">Dismiss</button></div></article>`).join(""):'<div class="empty-management">No notifications.</div>'}</div>`);
    qsa("[data-note-read]",els.modalContent).forEach(b=>b.onclick=async()=>{await rpc("trustrelay_mark_notification_v09",{p_notification_id:b.dataset.noteRead,p_action:"read"});await loadDashboard();await openNotifications()});
    qsa("[data-note-dismiss]",els.modalContent).forEach(b=>b.onclick=async()=>{await rpc("trustrelay_mark_notification_v09",{p_notification_id:b.dataset.noteDismiss,p_action:"dismiss"});await loadDashboard();await openNotifications()});
    qsa("[data-notification-pref]",els.modalContent).forEach(x=>x.onchange=async()=>{await rpc("trustrelay_set_notification_preference_v09",{p_category:x.dataset.notificationPref,p_in_app:x.checked});toast("Notification preference updated.","success")});
  }catch(e){toast(String(e.code||e.message).replaceAll("_"," "),"error")}
}

function formatMoney(cents,currency="usd"){
  if(cents==null)return "Pricing not configured";
  try{return new Intl.NumberFormat(undefined,{style:"currency",currency:String(currency||"usd").toUpperCase(),maximumFractionDigits:0}).format(Number(cents)/100)+"/month"}
  catch{return "$"+(Number(cents)/100).toFixed(0)+"/month"}
}

function launchBlockerLabel(code){
  const labels={
    ORGANIZATION_WEBSITE_REQUIRED:"Organization website is required",
    PRIMARY_CONTACT_REQUIRED:"Primary contact is required",
    SECURITY_CONTACT_REQUIRED:"Security contact is required",
    BILLING_CONTACT_REQUIRED:"Billing contact is required",
    LEGAL_ENTITY_REQUIRED:"Legal entity details are required",
    EFFECTIVE_LEGAL_PACKAGE_REQUIRED:"Counsel-reviewed effective production legal package is required",
    LEGAL_ACCEPTANCE_REQUIRED:"Effective business terms / DPA / acceptable-use terms must be accepted",
    BILLING_NOT_ACTIVE:"Active billing, trial, or manual contract is required",
    OWNER_REQUIRED:"At least one active owner is required"
  };
  return labels[code]||String(code||"").replaceAll("_"," ");
}

function renderLaunch(){
  const root=$("launchStatusBanner");if(!root)return;
  const x=state.launch,b=state.billing||{},platform=state.platform||{};
  if(!x){
    root.innerHTML='<div class="message warning">Launch-readiness data is unavailable for this account.</div>';
    return;
  }
  const org=x.organization||{},on=x.onboarding||{},billing=x.billing||{},blockers=x.blockers||[];
  $("portalEnvironmentBadge").textContent=String(org.mode||"sandbox").toUpperCase();
  $("portalModeLabel").textContent=String(org.mode||"sandbox");
  root.innerHTML=`
    <div>
      <strong>${org.mode==="live"?"Production active":"Production gated"}</strong>
      <span> — onboarding ${esc(on.status||"incomplete")} · production ${esc(on.production_status||"sandbox")} · billing ${esc(billing.status||"not_configured")}</span>
    </div>
    <span class="assurance-pill ${org.mode==="live"?"verified":"pending"}">${org.mode==="live"?"LIVE":"SANDBOX"}</span>
  `;

  $("launchOrgName").value=org.name||"";
  $("launchOrgIndustry").value=org.industry||"";
  $("launchOrgWebsite").value=org.website||"";
  $("launchPrimaryContact").value=on.primary_contact_email||"";
  $("launchSecurityContact").value=on.security_contact_email||"";
  $("launchBillingContact").value=on.billing_contact_email||billing.billingEmail||"";
  $("launchLegalEntityName").value=on.legal_entity_name||"";
  $("launchLegalCountry").value=on.legal_entity_country||"";
  $("launchLegalRegion").value=on.legal_entity_region||"";
  $("launchLegalAddress").value=on.legal_entity_address||"";

  const req=x.requiredLegalAcceptances||[];
  $("launchLegalList").innerHTML=req.length?req.map(d=>`
    <div class="management-row">
      <div><strong>${esc(d.title||d.documentType)}</strong><p>Version ${esc(d.version)} · effective ${esc(formatDate(d.effectiveAt))}</p></div>
      <div class="management-actions"><a class="button ghost small" href="..${esc(d.urlPath)}" target="_blank" rel="noopener">Review</a><button class="button secondary small" data-accept-legal="${esc(d.id)}" type="button">Accept for organization</button></div>
    </div>`).join(""):`
    <div class="management-row">
      <div><strong>No effective production legal package is currently published.</strong><p>The v1.0 legal documents are available as pre-launch drafts in the Trust Center. They cannot be accepted as binding terms until counsel-reviewed effective versions are published with immutable hashes.</p></div>
      <div class="management-actions"><a class="button ghost small" href="../legal/" target="_blank" rel="noopener">Review drafts</a></div>
    </div>`;

  const bs=b.billing||x.billing||{},current=b.currentPlan||x.plan||{};
  $("billingStatusDetails").innerHTML=`
    <div class="card-heading"><div><h3>Current billing</h3><p>${esc(current.name||current.code||"Sandbox")} · ${esc(bs.status||"not_configured")}</p></div><span class="small-chip">${b.providerConfigured?"Stripe configured":"Stripe not configured"}</span></div>
    <dl class="stats-list">
      <dt>Plan</dt><dd>${esc(current.name||current.code||"—")}</dd>
      <dt>Billing state</dt><dd>${esc(bs.status||"—")}</dd>
      <dt>Billing contact</dt><dd>${esc(bs.billingEmail||"—")}</dd>
      <dt>Commercial checkout</dt><dd>${b.providerConfigured?"Enabled":"Blocked until operator Stripe configuration"}</dd>
    </dl>
    ${bs.hasCustomer?'<div class="modal-actions"><button id="manageBillingPortalButton" class="button secondary" type="button">Open billing portal</button></div>':""}
  `;

  const plans=(b.plans||[]).filter(p=>p.code!=="sandbox");
  const hasLiveSubscription=bs.hasSubscription&&["active","trialing","past_due","unpaid"].includes(String(bs.status||""));
  $("billingPlanList").innerHTML=plans.length?plans.map(p=>`
    <article class="portal-card billing-plan-card ${p.code===bs.planCode?"selected":""}">
      <div class="card-heading"><div><h3>${esc(p.name)}</h3><p>${esc(formatMoney(p.monthlyPriceCents,p.currency))}</p></div>${p.code===bs.planCode?'<span class="small-chip">selected</span>':""}</div>
      <p>${esc((p.features||[]).join(" · "))}</p>
      <div class="row-meta">
        <span class="small-chip">members ${p.limits?.members??"custom"}</span>
        <span class="small-chip">decisions/mo ${p.limits?.decisionsPerMonth??"custom"}</span>
      </div>
      <div class="modal-actions">
        ${p.billingMode==="subscription"?
          (hasLiveSubscription
            ? `<button class="button secondary small" type="button" disabled>${p.code===bs.planCode?"Current plan":"Manage in billing portal"}</button>`
            : `<button class="button secondary small" data-select-plan="${esc(p.code)}" type="button">Select</button><button class="button primary small" data-checkout-plan="${esc(p.code)}" type="button" ${b.providerConfigured?"":"disabled"}>${b.providerConfigured?"Start checkout":"Stripe setup required"}</button>`)
          : '<a class="button ghost small" href="../legal/business-terms.html" target="_blank" rel="noopener">Enterprise contract</a>'}
      </div>
    </article>`).join(""):'<div class="empty-management">No commercial plans configured.</div>';

  const platformBlockers=Array.isArray(platform.blockers)?platform.blockers:[];
  const orgRows=blockers.map(code=>`
    <div class="management-row"><div><strong>${esc(launchBlockerLabel(code))}</strong><p>${esc(code)}</p></div><span class="small-chip">organization</span></div>
  `);
  const platformRows=platformBlockers.map(item=>`
    <div class="management-row"><div><strong>${esc(String(item.key||"platform control").replaceAll("_"," "))}</strong><p>${esc(item.ownerNote||item.category||"Platform readiness control is not complete.")}</p></div><span class="small-chip">${esc(item.status||"blocked")}</span></div>
  `);
  $("productionBlockers").innerHTML=(orgRows.length||platformRows.length)
    ? orgRows.concat(platformRows).join("")
    : '<div class="management-row"><div><strong>Organization and platform production gates are complete.</strong><p>The organization can request final production activation review.</p></div><span class="small-chip">ready</span></div>';

  const canManage=hasPerm("organization.manage");
  $("launchOrgProfileForm").classList.toggle("readonly-card",!canManage);
  $("launchContactsForm").classList.toggle("readonly-card",!canManage);
  qsa("#launchOrgProfileForm input,#launchContactsForm input,#launchContactsForm textarea,#launchOrgProfileForm button,#launchContactsForm button").forEach(el=>el.disabled=!canManage);
  $("requestProductionButton").classList.toggle("hidden",!canManage||org.mode==="live");
  $("requestProductionButton").disabled=!x.readyForProductionRequest||platform.ready!==true;

  const portal=$("manageBillingPortalButton");
  if(portal)portal.onclick=async()=>{
    busy(portal,true,"Opening…");
    try{const r=await billingEdge({action:"portal",orgId:state.orgId});window.open(r.url,"_blank","noopener,noreferrer")}
    catch(e){toast(String(e.code||e.message).replaceAll("_"," "),"error")}finally{busy(portal,false)}
  };
}

function renderAudit(){
  const root=$("auditList"),items=state.dashboard?.recentDecisions||[];
  root.innerHTML=items.length?items.map(x=>`
    <article class="audit-row">
      <span class="decision-badge ${esc(x.decision)}">${esc(x.decision)}</span>
      <div><strong>${esc(x.action)} → ${esc(x.resource)}</strong><p>${esc(x.reasonCode)} — ${esc(x.reasonDetail||"")}</p><p>Request ${esc(x.requestId)} · ${esc(formatDate(x.decidedAt,true))} · source ${esc(x.source||"api")} · policy ${esc(x.policyVersion||"—")} / engine ${esc(x.engineVersion||"—")}</p></div>
      <div class="audit-hashes">decision ${esc(x.id)}<br>eval ${esc(x.evaluationHash||"—")}<br>audit ${esc(x.auditEventId||"—")}</div>
    </article>`).join(""):'<div class="empty-management">No authorization decisions yet.</div>';
  const orgRoot=$("organizationAuditList"),events=state.dashboard?.recentAuditEvents||[];
  orgRoot.innerHTML=events.length?events.map(x=>`<article class="audit-row"><span class="small-chip">ORG</span><div><strong>${esc(x.eventType)}</strong><p>${esc(x.targetType)} · ${esc(x.targetId||"—")} · ${esc(formatDate(x.createdAt,true))}</p></div><div class="audit-hashes">hash ${esc(x.eventHash||"—")}<br>prev ${esc(x.prevHash||"genesis")}</div></article>`).join(""):'<div class="empty-management">No v0.9 organization audit events yet.</div>';
}

function renderDeveloper(){
  const base=SUPABASE_URL+"/functions/v1/trustrelay-partner-v07";
  $("evaluateExample").textContent=`curl -X POST ${base}/v1/decisions/evaluate \\
  -H "X-TrustRelay-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "requestId": "req_123",
    "credential": "eyJ...",
    "action": "pay_bill",
    "resource": "checking:1234",
    "amount": 175,
    "currency": "USD",
    "evidence": {"invoiceId":"INV-1042"},
    "evidenceDocumentIds": ["doc_..."]
  }'`;
  $("getExample").textContent=`curl ${base}/v1/decisions/req_123 \\
  -H "X-TrustRelay-Key: YOUR_API_KEY"`;
}

function showSsoDomainChallenges(challenges){
  const items=Array.isArray(challenges)?challenges:[];
  if(!items.length){
    toast("All configured SSO domains are already verified.","success");
    return;
  }
  const rows=items.map(x=>'<div class="management-row"><div><strong>'+esc(x.domain)+'</strong><p>'+esc(x.recordType||"TXT")+' · '+esc(x.recordName)+'</p><div class="secret-once">'+esc(x.recordValue)+'</div></div></div>').join("");
  openModal('<p class="eyebrow">DOMAIN OWNERSHIP</p><h2>Add these DNS TXT records.</h2><p>Publish each record with your DNS provider, then return to Enterprise SSO and click <strong>Verify domains</strong>. Reopening DNS verification records rotates pending challenges.</p><div class="management-list">'+rows+'</div>');
}

function renderSso(){
  const root=$("ssoConnectionSummary");
  if(!root)return;
  $("ssoCallbackUrl").textContent=SUPABASE_URL+"/auth/v1/callback";
  const c=state.sso||{};
  const configured=Boolean(c?.configured);
  const chip=$("ssoStatusChip");
  chip.textContent=configured?(c.status!=="active"?"VERIFY DOMAINS":c.enforcementMode==="required"?"SSO REQUIRED":"ACTIVE"):"NOT CONFIGURED";
  root.replaceChildren();

  if(!configured){
    const empty=document.createElement("div");
    empty.className="empty-management";
    empty.textContent="No enterprise identity provider is configured for this organization.";
    root.appendChild(empty);
  }else{
    const brand=c.providerKind==="entra"?"Microsoft Entra ID":"Okta";
    const rows=[
      ["Provider",brand],
      ["Protocol",String(c.protocol||"").toUpperCase()],
      ["Domains",(c.domains||[]).join(", ")],
      ["Domain ownership",(()=>{const d=Array.isArray(c.domainVerification)?c.domainVerification:[];const n=d.filter(x=>x.verificationStatus==="verified").length;return d.length?n+"/"+d.length+" verified":"Not verified"})()],
      ["Enforcement",c.enforcementMode||"optional"],
      ["JIT membership",c.jitEnabled?"enabled · "+(c.defaultRole||"verifier"):"disabled"],
      ["Last verified",c.lastTestedAt?formatDate(c.lastTestedAt,true):"Not yet tested"],
      ["Current session",c.session?.providerMatched?"enterprise IdP verified":c.session?.breakGlass?"break-glass owner":"non-SSO"],
      ["Break-glass owner",c.breakGlassEnabled?"enabled":"disabled"]
    ];
    for(const [label,value] of rows){
      const row=document.createElement("div");
      row.className="sso-summary-row";
      const left=document.createElement("span");
      const right=document.createElement("span");
      left.textContent=label;
      right.textContent=String(value??"");
      row.append(left,right);
      root.appendChild(row);
    }
  }

  const pendingDomains=configured&&(Array.isArray(c.domainVerification)?c.domainVerification:[]).some(x=>x.verificationStatus!=="verified");
  $("domainSsoRecordsButton").classList.toggle("hidden",!pendingDomains);
  $("verifySsoDomainsButton").classList.toggle("hidden",!pendingDomains);
  $("testSsoButton").classList.toggle("hidden",!configured||c.status!=="active");
  $("disableSsoButton").classList.toggle("hidden",!configured);
  $("requireSsoButton").classList.toggle("hidden",!configured||c.enforcementMode==="required"||c.session?.providerMatched!==true);
  $("makeSsoOptionalButton").classList.toggle("hidden",!configured||c.enforcementMode!=="required");
  if(configured){
    const uiBrand=c.providerKind==="entra"?"microsoft_entra":"okta";
    const brandRadio=document.querySelector('input[name="ssoProviderBrand"][value="'+CSS.escape(uiBrand)+'"]');
    if(brandRadio)brandRadio.checked=true;
    $("ssoDomains").value=(c.domains||[]).join("\n");
    $("ssoJitEnabled").checked=Boolean(c.jitEnabled);
    $("ssoJitRole").value=c.defaultRole||"verifier";
    $("ssoJitRole").disabled=!$("ssoJitEnabled").checked;
    if(uiBrand==="microsoft_entra"){
      $("entraFields").classList.remove("hidden");$("oktaFields").classList.add("hidden");
    }else{
      $("entraFields").classList.add("hidden");$("oktaFields").classList.remove("hidden");
      if(c.issuer)$("ssoOktaIssuer").value=c.issuer;
    }
  }
}

function showScimCredentials(x){
  const c=x?.credential||{};
  const base=x?.scimBaseUrl||x?.endpoint||"";
  const tokenUrl=x?.oauthTokenUrl||"";
  const clientId=c.clientId||"";
  const clientSecret=c.clientSecret||x?.token||"";
  openModal(
    '<p class="eyebrow">SCIM CREDENTIALS</p>'+
    '<h2>Copy these values now.</h2>'+
    '<p class="warning-copy">The client secret is shown only once. TrustRelay stores only a SHA-256 hash.</p>'+
    '<div class="field"><label>SCIM Base URL</label><div class="secret-once" id="scimBaseOnce">'+esc(base)+'</div></div>'+
    '<div class="field"><label>OAuth token URL</label><div class="secret-once" id="scimOauthOnce">'+esc(tokenUrl)+'</div></div>'+
    '<div class="field"><label>Client ID</label><div class="secret-once" id="scimClientIdOnce">'+esc(clientId)+'</div></div>'+
    '<div class="field"><label>Client secret</label><div class="secret-once" id="scimSecretOnce">'+esc(clientSecret)+'</div></div>'+
    '<p class="fine-print">Microsoft Entra ID: use OAuth 2.0 client credentials. Okta/private integrations may also use the same client secret directly as a Bearer token while bearer compatibility is enabled.</p>'+
    '<div class="modal-actions"><button id="copyScimBase" class="button secondary" type="button">Copy Base URL</button><button id="copyScimClient" class="button secondary" type="button">Copy Client ID</button><button id="copyScimSecret" class="button primary" type="button">Copy Secret</button></div>'
  );
  $("copyScimBase").onclick=()=>copyText(base,"SCIM Base URL copied");
  $("copyScimClient").onclick=()=>copyText(clientId,"SCIM client ID copied");
  $("copyScimSecret").onclick=()=>copyText(clientSecret,"SCIM client secret copied");
}

function renderScim(){
  const root=$("scimSummary"),endpointRoot=$("scimEndpointList"),credRoot=$("scimCredentialList");
  if(!root||!endpointRoot||!credRoot)return;
  const x=state.scim||{},cfg=x.config||{};
  const configured=Boolean(x.configured),active=configured&&cfg.status==="active";
  $("scimStatusChip").textContent=!configured?"NOT CONFIGURED":active?"ACTIVE":"DISABLED";
  $("scimDefaultRole").value=cfg.defaultRole||"verifier";
  $("scimAllowBearer").checked=configured?cfg.allowStaticBearer!==false:true;
  $("scimGroupSync").checked=configured?cfg.groupSyncEnabled!==false:true;

  root.replaceChildren();
  if(!configured){
    const empty=document.createElement("div");
    empty.className="empty-management";
    empty.textContent=state.sso?.configured&&state.sso?.status==="active"
      ?"SCIM is ready. Generate credentials to activate automated provisioning."
      :"Verify and activate Enterprise SSO before enabling SCIM.";
    root.appendChild(empty);
  }else{
    const counts=x.counts||{};
    const rows=[
      ["Provider",String(cfg.providerKind||"enterprise").replaceAll("_"," ")],
      ["Service",cfg.status||"active"],
      ["Default role",cfg.defaultRole||"verifier"],
      ["Users",String(counts.activeUsers??0)+" active / "+String(counts.users??0)+" total"],
      ["Groups",String(counts.groups??0)],
      ["Last sync",cfg.lastSyncAt?formatDate(cfg.lastSyncAt,true):"Never"]
    ];
    for(const [label,value] of rows){
      const row=document.createElement("div");row.className="sso-summary-row";
      const left=document.createElement("span"),right=document.createElement("span");
      left.textContent=label;right.textContent=value;row.append(left,right);root.appendChild(row);
    }
  }

  endpointRoot.replaceChildren();
  const endpointRows=[
    ["SCIM Base URL",x.scimBaseUrl||location.origin+"/scim/v2"],
    ["OAuth token URL",x.oauthTokenUrl||location.origin+"/oauth2/token"],
    ["ServiceProviderConfig",x.serviceProviderConfigUrl||location.origin+"/scim/v2/ServiceProviderConfig"]
  ];
  for(const [label,value] of endpointRows){
    const row=document.createElement("div");row.className="sso-summary-row";
    const left=document.createElement("span"),right=document.createElement("span");
    left.textContent=label;right.textContent=value;row.append(left,right);endpointRoot.appendChild(row);
  }

  const creds=Array.isArray(x.credentials)?x.credentials:[];
  credRoot.innerHTML=creds.length?creds.map(c=>`
    <div class="management-row">
      <div>
        <strong>${esc(c.label||"SCIM credential")}</strong>
        <p>${esc(c.clientId||"")} · expires ${esc(formatDate(c.expiresAt,true))}</p>
        <div class="row-meta"><span class="small-chip">${esc(c.status||"unknown")}</span><span class="small-chip">last used ${esc(c.lastUsedAt?formatDate(c.lastUsedAt,true):"never")}</span></div>
      </div>
      <div class="management-actions">${c.status==="active"?`<button class="button danger small" data-revoke-scim-credential="${esc(c.id)}" type="button">Revoke</button>`:""}</div>
    </div>`).join(""):'<div class="empty-management">No SCIM credentials have been created.</div>';

  const ssoReady=Boolean(state.sso?.configured&&state.sso?.status==="active");
  $("createScimCredentialButton").disabled=!ssoReady;
  $("rotateScimCredentialButton").classList.toggle("hidden",!active);
  $("saveScimPolicyButton").classList.toggle("hidden",!configured);
  $("disableScimButton").classList.toggle("hidden",!active);
}

function showDecision(result){
  const d=result?.decision||{},root=$("decisionResult"),cls=String(d.decision||"").toLowerCase();
  root.className="decision-result "+(cls||"empty");
  root.innerHTML=`<div class="result-mark">${d.decision==="ALLOW"?"✓":d.decision==="DENY"?"×":"!"}</div>
    <h3>${esc(d.decision||"No decision")} — ${esc(d.reasonCode||"")}</h3><p>${esc(d.reasonDetail||"")}</p>
    <div class="decision-meta">
      <div><span>Request ID</span><span>${esc(d.requestId||result.requestId||"—")}</span></div>
      <div><span>Action</span><span>${esc(d.action||"—")}</span></div>
      <div><span>Resource</span><span>${esc(d.resource||"—")}</span></div>
      <div><span>Grant</span><span>${esc(d.grantId||"—")}</span></div>
      <div><span>Credential JTI</span><span>${esc(d.credentialJti||"—")}</span></div>
      <div><span>Evaluation hash</span><span>${esc(d.evaluationHash||"—")}</span></div>
      <div><span>Audit event</span><span>${esc(d.auditEventId||"—")}</span></div>
      <div><span>Latency</span><span>${esc(d.latencyMs??"—")} ms</span></div>
    </div>
    ${d.grantId && canRequestEvidence() ? `<div class="modal-actions"><button class="button secondary" data-request-evidence-grant="${esc(d.grantId)}" type="button">Request supporting evidence</button></div>` : ""}`;
}

async function acceptPendingOrgInvite(){
  const t=sessionStorage.getItem("trustrelay_pending_org_invite");if(!t)return;
  try{const r=await rpc("trustrelay_accept_org_invite_v07",{p_token:t});sessionStorage.removeItem("trustrelay_pending_org_invite");toast("Organization invitation accepted.","success");state.orgId=r.organizationId}catch(e){toast("Organization invitation could not be accepted: "+String(e.code||e.message).replaceAll("_"," "),"error")}
}

function parseUrlInvite(){
  const p=new URLSearchParams(location.search),t=p.get("org_invite");if(t){sessionStorage.setItem("trustrelay_pending_org_invite",t);history.replaceState({},"",location.pathname)}
}

function setup(){
  void mountTurnstile($("magicForm")).catch(()=>msg(els.authMessage,"Security check could not load. Refresh and try again.","error"));
  $("ssoLoginForm").addEventListener("submit",async e=>{
    e.preventDefault();clearMsg(els.authMessage);const b=e.submitter;busy(b,true,"Finding your organization…");
    try{await startEnterpriseSso($("ssoEmail").value)}
    catch(err){msg(els.authMessage,String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}
  });
  $("magicForm").addEventListener("submit",async e=>{e.preventDefault();clearMsg(els.authMessage);const b=e.submitter;busy(b,true,"Sending secure link…");const email=$("authEmail").value.trim().toLowerCase(),name=$("authName").value.trim();try{const options={shouldCreateUser:true,emailRedirectTo:authRedirectUrl()};const captchaToken=captchaTokenForAuth();if(captchaToken)options.captchaToken=captchaToken;if(name)options.data={full_name:name};const {error}=await supabase.auth.signInWithOtp({email,options});if(error)throw error;sessionStorage.setItem("trustrelay_verifier_email",email);$("otpEmail").value=email;msg(els.authMessage,"Check your email for the TrustRelay magic link. If your email contains a six-digit code, use the code option below.","success")}catch(err){msg(els.authMessage,err.message||"Could not send sign-in email.","error")}finally{resetTurnstile();busy(b,false)}});
  $("showOtp").onclick=()=>showOtp(true);$("backToMagic").onclick=()=>showOtp(false);
  qsa('input[name="ssoProviderBrand"]').forEach(r=>r.onchange=()=>{
    const entra=r.value==="microsoft_entra"&&r.checked;
    if(r.checked){$("entraFields").classList.toggle("hidden",!entra);$("oktaFields").classList.toggle("hidden",entra)}
  });
  $("ssoJitEnabled").onchange=()=>{$("ssoJitRole").disabled=!$("ssoJitEnabled").checked};
  $("ssoJitRole").disabled=!$("ssoJitEnabled").checked;
  $("otpForm").addEventListener("submit",async e=>{e.preventDefault();const b=e.submitter;busy(b,true,"Verifying…");try{const {data,error}=await supabase.auth.verifyOtp({email:$("otpEmail").value.trim().toLowerCase(),token:$("otpCode").value.trim(),type:"email"});if(error)throw error;state.session=data.session;state.user=data.user;await startPortal()}catch(err){msg(els.authMessage,err.message||"Invalid or expired code.","error")}finally{busy(b,false)}});

  qsa(".verifier-nav .nav-item").forEach(b=>b.onclick=()=>showView(b.dataset.view));qsa("[data-go]").forEach(b=>b.onclick=()=>showView(b.dataset.go));
  els.orgSelect.onchange=async()=>{state.orgId=els.orgSelect.value;state.launch=null;state.billing=null;state.platform=null;state.sso=null;state.scim=null;await loadDashboard();showView("dashboard")};
  $("newOrgButton").onclick=()=>{state.orgId=null;$("noOrgView").classList.remove("hidden");qsa(".portal-section").filter(x=>x.id!=="noOrgView").forEach(x=>x.classList.add("hidden"))};
  $("orgForm").addEventListener("submit",async e=>{e.preventDefault();const form=e.currentTarget,b=e.submitter;busy(b,true,"Creating…");try{const x=await rpc("trustrelay_create_organization_v07",{p_name:$("orgName").value.trim(),p_industry:$("orgIndustry").value.trim()||null,p_website:$("orgWebsite").value.trim()||null});state.orgId=x.organization.id;toast("Sandbox organization created.","success");form.reset();await loadOrganizations();showView("dashboard")}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}});
  $("ssoConfigForm").addEventListener("submit",async e=>{
    e.preventDefault();const b=e.submitter;busy(b,true,"Configuring provider…");
    try{
      const brand=document.querySelector('input[name="ssoProviderBrand"]:checked')?.value||"microsoft_entra";
      const domains=$("ssoDomains").value.split(/[\s,]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);
      const payload={
        action:"configure_oidc",orgId:state.orgId,providerBrand:brand,domains,
        clientId:$("ssoClientId").value.trim(),clientSecret:$("ssoClientSecret").value,
        tenantId:brand==="microsoft_entra"?$("ssoTenantId").value.trim():null,
        issuerUrl:brand==="okta"?$("ssoOktaIssuer").value.trim():null,
        jitEnabled:$("ssoJitEnabled").checked,jitDefaultRole:$("ssoJitRole").value
      };
      const x=await ssoEdge(payload);
      $("ssoClientSecret").value="";
      toast("Enterprise OIDC configured. Verify your corporate domain before testing SSO.","success");
      state.sso=await rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId});renderSso();
      showSsoDomainChallenges(x.domainChallenges);
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  });
  $("domainSsoRecordsButton").onclick=async()=>{
    const b=$("domainSsoRecordsButton");busy(b,true,"Generating…");
    try{
      const x=await ssoEdge({action:"domain_challenges",orgId:state.orgId});
      showSsoDomainChallenges(x.challenges);
      state.sso=await rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId});renderSso();
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };
  $("verifySsoDomainsButton").onclick=async()=>{
    const b=$("verifySsoDomainsButton");busy(b,true,"Verifying…");
    try{
      const x=await ssoEdge({action:"verify_domains",orgId:state.orgId});
      state.sso=x.config||await rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId});
      renderSso();
      if(x.allVerified)toast("Corporate domain ownership verified. You can now test enterprise sign-in.","success");
      else toast("DNS verification is still pending for: "+(x.pending||[]).map(v=>v.domain).join(", "),"warning");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };
  $("testSsoButton").onclick=async()=>{
    const c=state.sso;if(!c?.configured)return;
    const email=state.user?.email||sessionStorage.getItem("trustrelay_verifier_email")||"";
    if(!email){toast("Your account email is unavailable.","error");return}
    const b=$("testSsoButton");busy(b,true,"Redirecting…");
    try{
      const info={ssoAvailable:true,protocol:c.protocol,providerIdentifier:c.protocol==="saml"?c.ssoProviderId:c.providerIdentifier};
      await supabase.auth.signOut();
      await startEnterpriseSso(email,info);
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}
  };
  $("requireSsoButton").onclick=async()=>{
    const b=$("requireSsoButton");busy(b,true,"Enabling…");
    try{
      const c=state.sso||{};
      await rpc("trustrelay_set_sso_policy_v13",{p_org_id:state.orgId,p_enforcement_mode:"required",p_jit_enabled:Boolean(c.jitEnabled),p_default_role:c.defaultRole||"verifier",p_break_glass_enabled:true});
      toast("Enterprise SSO is now required for this organization.","success");
      state.sso=await rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId});renderSso();
    }catch(err){
      const code=String(err.code||err.message);
      const friendly=code==="SSO_TEST_REQUIRED"?"Test and sign in through the configured enterprise provider before requiring SSO.":code;
      toast(friendly.replaceAll("_"," "),"error");
    }finally{busy(b,false)}
  };
  $("makeSsoOptionalButton").onclick=async()=>{
    const b=$("makeSsoOptionalButton");busy(b,true,"Updating…");
    try{const c=state.sso||{};await rpc("trustrelay_set_sso_policy_v13",{p_org_id:state.orgId,p_enforcement_mode:"optional",p_jit_enabled:Boolean(c.jitEnabled),p_default_role:c.defaultRole||"verifier",p_break_glass_enabled:true});toast("Enterprise SSO is optional again.","success");state.sso=await rpc("trustrelay_sso_config_v13",{p_org_id:state.orgId});renderSso()}
    catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  };
  $("disableSsoButton").onclick=async()=>{
    if(!confirm("Disable enterprise SSO for this organization? Passwordless access will remain available."))return;
    const b=$("disableSsoButton");busy(b,true,"Disabling…");
    try{await ssoEdge({action:"disable",orgId:state.orgId});toast("Enterprise SSO disabled.","success");state.sso={ok:true,configured:false};renderSso()}
    catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  };

  $("createScimCredentialButton").onclick=async()=>{
    const b=$("createScimCredentialButton");busy(b,true,"Generating…");
    try{
      const x=await scimAdminEdge({
        action:"create_credential",orgId:state.orgId,
        defaultRole:$("scimDefaultRole").value,label:"Primary",expirationDays:365
      });
      showScimCredentials(x);
      state.scim=await scimAdminEdge({action:"status",orgId:state.orgId});
      renderScim();toast("SCIM provisioning credentials created.","success");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };

  $("rotateScimCredentialButton").onclick=async()=>{
    const b=$("rotateScimCredentialButton");busy(b,true,"Generating rotation…");
    try{
      const x=await scimAdminEdge({
        action:"rotate_credential",orgId:state.orgId,
        defaultRole:$("scimDefaultRole").value,label:"Rotation",expirationDays:365
      });
      showScimCredentials(x);
      state.scim=await scimAdminEdge({action:"status",orgId:state.orgId});
      renderScim();toast("Rotation credential created. Revoke the old credential after your IdP is updated.","success");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };

  $("saveScimPolicyButton").onclick=async()=>{
    const b=$("saveScimPolicyButton");busy(b,true,"Saving…");
    try{
      await scimAdminEdge({
        action:"policy",orgId:state.orgId,defaultRole:$("scimDefaultRole").value,
        allowStaticBearer:$("scimAllowBearer").checked,groupSyncEnabled:$("scimGroupSync").checked
      });
      state.scim=await scimAdminEdge({action:"status",orgId:state.orgId});
      renderScim();toast("SCIM provisioning policy updated.","success");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };

  $("disableScimButton").onclick=async()=>{
    if(!confirm("Disable SCIM provisioning? All SCIM credentials and access tokens will be revoked. Existing organization memberships remain unchanged."))return;
    const b=$("disableScimButton");busy(b,true,"Disabling…");
    try{
      await scimAdminEdge({action:"disable",orgId:state.orgId});
      state.scim=await scimAdminEdge({action:"status",orgId:state.orgId});
      renderScim();toast("SCIM provisioning disabled and credentials revoked.","success");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };

  $("scimCredentialList").addEventListener("click",async e=>{
    const b=e.target.closest("[data-revoke-scim-credential]");if(!b)return;
    if(!confirm("Revoke this SCIM credential? Identity-provider requests using it will fail immediately."))return;
    busy(b,true,"Revoking…");
    try{
      await scimAdminEdge({action:"revoke_credential",orgId:state.orgId,credentialId:b.dataset.revokeScimCredential});
      state.scim=await scimAdminEdge({action:"status",orgId:state.orgId});
      renderScim();toast("SCIM credential revoked.","success");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
    finally{busy(b,false)}
  };

  $("decisionResult").addEventListener("click", (event) => {
    const button=event.target.closest("[data-request-evidence-grant]");
    if(!button)return;
    openModal(`<p class="eyebrow">EVIDENCE REQUEST</p><h2>Request supporting documents.</h2><p>This request is tied to the evaluated grant and will appear for its principal and representative.</p><form id="evidenceRequestForm"><div class="field"><label>Required document types</label><div class="scope-checks"><label><input type="checkbox" name="evtype" value="authority_document" checked> Authority document</label><label><input type="checkbox" name="evtype" value="invoice"> Invoice / bill</label><label><input type="checkbox" name="evtype" value="supporting_document"> Supporting document</label><label><input type="checkbox" name="evtype" value="address_evidence"> Address evidence</label></div></div><div class="field"><label for="evidenceDueAt">Due date <span class="optional-label">optional</span></label><input id="evidenceDueAt" type="datetime-local"></div><input id="evidenceGrantId" type="hidden" value="${esc(button.dataset.requestEvidenceGrant)}"><div class="modal-actions"><button class="button primary" type="submit">Create evidence request</button></div></form>`);
  });

  $("evaluateForm").addEventListener("submit",async e=>{e.preventDefault();const b=e.submitter;busy(b,true,"Evaluating…");try{let evidence={};const raw=$("decisionEvidence").value.trim();if(raw){evidence=JSON.parse(raw);if(!evidence||typeof evidence!=="object"||Array.isArray(evidence))throw new Error("Evidence must be a JSON object.")}const evidenceDocumentIds=[...new Set($("decisionEvidenceDocuments").value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean))];const amountRaw=$("decisionAmount").value.trim();const result=await evaluate({orgId:state.orgId,requestId:"req_"+crypto.randomUUID().replaceAll("-",""),correlationId:$("correlationId").value.trim()||null,credential:$("credentialToken").value.trim(),action:$("decisionAction").value.trim(),resource:$("decisionResource").value.trim(),amount:amountRaw===""?null:Number(amountRaw),currency:$("decisionCurrency").value||null,evidence,evidenceDocumentIds});showDecision(result);toast("Authorization decision recorded.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}});

  $("createKeyButton").onclick=()=>openModal(`<p class="eyebrow">NEW PARTNER KEY</p><h2>Create server API key.</h2><p>The raw key is shown once. Store it in your server-side secret manager.</p><form id="keyForm"><div class="field"><label for="keyName">Key name</label><input id="keyName" required maxlength="100" placeholder="Production backend"></div><div class="field"><label>Scopes</label><div class="scope-checks"><label><input type="checkbox" name="scope" value="decisions:read" checked> decisions:read</label><label><input type="checkbox" name="scope" value="decisions:write" checked> decisions:write</label></div></div><div class="modal-actions"><button class="button primary" type="submit">Create key</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{
    if(e.target.id!=="evidenceRequestForm")return;
    e.preventDefault();
    const b=e.submitter;busy(b,true,"Creating…");
    try{
      const types=qsa('input[name="evtype"]:checked',e.target).map(x=>x.value);
      if(!types.length)throw new Error("Choose at least one evidence type.");
      const raw=$("evidenceDueAt").value;
      const due=raw?new Date(raw).toISOString():null;
      await rpc("trustrelay_create_evidence_request_v08",{p_org_id:state.orgId,p_grant_id:$("evidenceGrantId").value,p_types:types,p_due_at:due});
      closeModal();toast("Evidence request created.","success");await loadDashboard();
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}
  });

  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="keyForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const scopes=qsa('input[name="scope"]:checked',e.target).map(x=>x.value);const x=await rpc("trustrelay_create_api_key_v07",{p_org_id:state.orgId,p_name:$("keyName").value.trim(),p_scopes:scopes,p_expires_at:null});els.modalContent.innerHTML=`<p class="eyebrow">KEY CREATED</p><h2>Copy this key now.</h2><p class="warning-copy">TrustRelay stores only its SHA-256 hash. This raw key cannot be recovered later.</p><div class="secret-once">${esc(x.apiKey)}</div><div class="modal-actions"><button id="copyNewKey" class="button primary" type="button">Copy API key</button></div>`;$("copyNewKey").onclick=()=>copyText(x.apiKey,"API key copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});

  $("keyList").addEventListener("click",async e=>{const b=e.target.closest("[data-revoke-key]");if(!b)return;if(!confirm("Revoke this API key? Existing integrations using it will immediately fail."))return;busy(b,true,"Revoking…");try{await rpc("trustrelay_revoke_api_key_v07",{p_org_id:state.orgId,p_key_id:b.dataset.revokeKey});toast("API key revoked.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message),"error")}finally{busy(b,false)}});

  $("inviteMemberButton").onclick=()=>openModal(`<p class="eyebrow">TEAM INVITATION</p><h2>Invite organization member.</h2><form id="inviteForm"><div class="field"><label for="inviteEmail">Email</label><input id="inviteEmail" type="email" required></div><div class="field"><label for="inviteRole">Role</label><select id="inviteRole"><option value="verifier">Verifier</option><option value="compliance">Compliance</option><option value="developer">Developer</option><option value="auditor">Auditor</option><option value="admin">Admin</option></select></div><div class="modal-actions"><button class="button primary" type="submit">Create invitation</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="inviteForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const x=await rpc("trustrelay_invite_org_member_v07",{p_org_id:state.orgId,p_email:$("inviteEmail").value.trim(),p_role:$("inviteRole").value});const link=location.origin+"/verifier/?org_invite="+encodeURIComponent(x.invitation.token);els.modalContent.innerHTML=`<p class="eyebrow">INVITATION READY</p><h2>Share this one-time invitation.</h2><p>Send it only to <strong>${esc(x.invitation.email)}</strong>.</p><div class="secret-once">${esc(link)}</div><div class="modal-actions"><button id="copyOrgInvite" class="button primary" type="button">Copy invitation link</button></div>`;$("copyOrgInvite").onclick=()=>copyText(link,"Organization invitation copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});

  $("createWebhookButton").onclick=()=>openModal(`<p class="eyebrow">SIGNED WEBHOOK</p><h2>Add HTTPS endpoint.</h2><form id="webhookForm"><div class="field"><label for="webhookName">Name</label><input id="webhookName" required maxlength="100" placeholder="Authorization events"></div><div class="field"><label for="webhookUrl">HTTPS endpoint</label><input id="webhookUrl" type="url" required placeholder="https://example.com/trustrelay"></div><div class="field"><label>Events</label><div class="scope-checks"><label><input type="checkbox" name="event" value="decision.created" checked> decision.created</label><label><input type="checkbox" name="event" value="grant.revoked"> grant.revoked</label><label><input type="checkbox" name="event" value="credential.revoked"> credential.revoked</label><label><input type="checkbox" name="event" value="evidence.requested"> evidence.requested</label><label><input type="checkbox" name="event" value="evidence.submitted"> evidence.submitted</label><label><input type="checkbox" name="event" value="evidence.resolved"> evidence.resolved</label><label><input type="checkbox" name="event" value="identity.assurance.changed"> identity.assurance.changed</label><label><input type="checkbox" name="event" value="organization.member.invited"> organization.member.invited</label><label><input type="checkbox" name="event" value="organization.member.joined"> organization.member.joined</label><label><input type="checkbox" name="event" value="organization.member.role_changed"> organization.member.role_changed</label><label><input type="checkbox" name="event" value="organization.member.disabled"> organization.member.disabled</label><label><input type="checkbox" name="event" value="organization.member.restored"> organization.member.restored</label><label><input type="checkbox" name="event" value="organization.member.removed"> organization.member.removed</label><label><input type="checkbox" name="event" value="organization.ownership.transferred"> organization.ownership.transferred</label><label><input type="checkbox" name="event" value="compliance.export.ready"> compliance.export.ready</label></div></div><div class="modal-actions"><button class="button primary" type="submit">Create webhook</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="webhookForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const events=qsa('input[name="event"]:checked',e.target).map(x=>x.value);const x=await rpc("trustrelay_create_webhook_v07",{p_org_id:state.orgId,p_name:$("webhookName").value.trim(),p_endpoint_url:$("webhookUrl").value.trim(),p_events:events});els.modalContent.innerHTML=`<p class="eyebrow">WEBHOOK CREATED</p><h2>Save the signing secret.</h2><p class="warning-copy">It is encrypted in Vault and shown only once.</p><div class="secret-once">${esc(x.signingSecret)}</div><div class="modal-actions"><button id="copyWebhookSecret" class="button primary" type="button">Copy signing secret</button></div>`;$("copyWebhookSecret").onclick=()=>copyText(x.signingSecret,"Webhook secret copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});
  $("evidenceRequestOrgList").addEventListener("click",async e=>{
    const view=e.target.closest("[data-org-evidence-doc]");
    if(view){
      busy(view,true,"Opening…");
      try{const x=await evidenceFile({action:"download",documentId:view.dataset.orgEvidenceDoc});window.open(x.url,"_blank","noopener,noreferrer")}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}
      finally{busy(view,false)}
      return;
    }
    const copy=e.target.closest("[data-copy-evidence-doc]");
    if(copy){await copyText(copy.dataset.copyEvidenceDoc,"Document ID copied");return}
    const resolve=e.target.closest("[data-resolve-evidence]");
    if(resolve){
      openModal(`<p class="eyebrow">EVIDENCE RESOLUTION</p><h2>${resolve.dataset.resolution==="satisfied"?"Mark request satisfied?":"Reject submitted evidence?"}</h2><form id="evidenceResolutionForm"><input id="evidenceResolutionRequestId" type="hidden" value="${esc(resolve.dataset.resolveEvidence)}"><input id="evidenceResolution" type="hidden" value="${esc(resolve.dataset.resolution)}"><div class="field"><label for="evidenceResolutionReason">Reason code</label><input id="evidenceResolutionReason" maxlength="120" required placeholder="${resolve.dataset.resolution==="satisfied"?"EVIDENCE_ACCEPTED":"EVIDENCE_INSUFFICIENT"}"></div><div class="field"><label for="evidenceResolutionNotes">Notes <span class="optional-label">optional</span></label><textarea id="evidenceResolutionNotes" rows="4" maxlength="2000"></textarea></div><div class="modal-actions"><button class="button ${resolve.dataset.resolution==="satisfied"?"primary":"danger"}" type="submit">Record resolution</button></div></form>`);
    }
  });

  $("webhookList").addEventListener("click",async e=>{const b=e.target.closest("[data-revoke-webhook]");if(!b)return;if(!confirm("Revoke this webhook endpoint?"))return;busy(b,true,"Revoking…");try{await rpc("trustrelay_revoke_webhook_v07",{p_org_id:state.orgId,p_webhook_id:b.dataset.revokeWebhook});toast("Webhook revoked.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message),"error")}finally{busy(b,false)}});

  els.modalContent.addEventListener("submit",async e=>{
    if(e.target.id!=="evidenceResolutionForm")return;
    e.preventDefault();
    const b=e.submitter;busy(b,true,"Recording…");
    try{
      await rpc("trustrelay_resolve_evidence_request_v08",{
        p_org_id:state.orgId,
        p_request_id:$("evidenceResolutionRequestId").value,
        p_resolution:$("evidenceResolution").value,
        p_reason:$("evidenceResolutionReason").value.trim(),
        p_notes:$("evidenceResolutionNotes").value.trim()||null
      });
      closeModal();toast("Evidence request resolved.","success");await loadDashboard();showView("evidence");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}
  });

  $("teamList").addEventListener("click",async e=>{
    const save=e.target.closest("[data-save-role]");
    if(save){
      const select=document.querySelector(`[data-role-account="${CSS.escape(save.dataset.saveRole)}"]`);
      if(!select)return;
      busy(save,true,"Saving…");
      try{await rpc("trustrelay_manage_org_member_v09",{p_org_id:state.orgId,p_member_account_id:save.dataset.saveRole,p_action:"role",p_role:select.value,p_title:null});toast("Organization role updated.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(save,false)}
      return;
    }
    const transfer=e.target.closest("[data-transfer-owner]");
    if(transfer){
      if(!confirm("Transfer organization ownership to this member? Your role will become admin."))return;
      busy(transfer,true,"Transferring…");
      try{await rpc("trustrelay_transfer_org_owner_v09",{p_org_id:state.orgId,p_new_owner_account_id:transfer.dataset.transferOwner});toast("Organization ownership transferred.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(transfer,false)}
      return;
    }
    const enable=e.target.closest("[data-enable-member]");
    if(enable){
      busy(enable,true,"Restoring…");
      try{await rpc("trustrelay_restore_member_v09",{p_org_id:state.orgId,p_account_id:enable.dataset.enableMember});toast("Member access restored.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(enable,false)}
      return;
    }
    const remove=e.target.closest("[data-remove-member]");
    if(remove){
      if(!confirm("Remove this member from the organization?"))return;
      busy(remove,true,"Removing…");
      try{await rpc("trustrelay_remove_member_v09",{p_org_id:state.orgId,p_account_id:remove.dataset.removeMember,p_reason:"Removed from Verifier Portal"});toast("Member removed.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(remove,false)}
      return;
    }
    const disable=e.target.closest("[data-disable-member]");
    if(disable){
      if(!confirm("Disable this organization member? Their access will stop immediately."))return;
      busy(disable,true,"Disabling…");
      try{await rpc("trustrelay_manage_org_member_v09",{p_org_id:state.orgId,p_member_account_id:disable.dataset.disableMember,p_action:"disable",p_role:null,p_title:null});toast("Member access disabled.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(disable,false)}
    }
  });

  $("webhookList").addEventListener("click",async e=>{
    const stateButton=e.target.closest("[data-webhook-state]");
    if(stateButton){
      busy(stateButton,true,stateButton.dataset.state==="active"?"Resuming…":"Pausing…");
      try{await rpc("trustrelay_set_webhook_state_v09",{p_org_id:state.orgId,p_webhook_id:stateButton.dataset.webhookState,p_state:stateButton.dataset.state,p_reason:stateButton.dataset.state==="paused"?"Paused from Verifier Portal":null});toast(stateButton.dataset.state==="active"?"Webhook resumed.":"Webhook paused.","success");await loadDashboard()}
      catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(stateButton,false)}
      return;
    }
    const test=e.target.closest("[data-test-webhook]");
    if(test){busy(test,true,"Queueing…");try{const x=await rpc("trustrelay_test_webhook_v09",{p_org_id:state.orgId,p_webhook_id:test.dataset.testWebhook});toast("Webhook test queued: "+x.deliveryId,"success");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(test,false)}return}
    const rotate=e.target.closest("[data-rotate-webhook]");
    if(rotate){busy(rotate,true,"Rotating…");try{const x=await rpc("trustrelay_rotate_webhook_secret_v09",{p_org_id:state.orgId,p_webhook_id:rotate.dataset.rotateWebhook});openModal(`<p class="eyebrow">WEBHOOK SECRET ROTATED</p><h2>Copy the new secret now.</h2><p class="warning-copy">The previous signing secret is no longer used for new deliveries. This value is shown once.</p><div class="secret-once">${esc(x.signingSecret)}</div><div class="modal-actions"><button id="copyRotatedSecret" class="button primary" type="button">Copy secret</button></div>`);$("copyRotatedSecret").onclick=()=>copyText(x.signingSecret,"Webhook secret copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(rotate,false)}}
  });

  $("deliveryList").addEventListener("click",async e=>{
    const retry=e.target.closest("[data-retry-webhook]");if(!retry)return;
    busy(retry,true,"Queueing…");
    try{await rpc("trustrelay_retry_webhook_delivery_v09",{p_org_id:state.orgId,p_delivery_id:retry.dataset.retryWebhook});toast("Webhook retry queued.","success");await loadDashboard()}
    catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(retry,false)}
  });

  $("complianceExportForm").addEventListener("submit",async e=>{
    e.preventDefault();const b=e.submitter;busy(b,true,"Generating…");
    try{
      const scopes=qsa('input[name="exportScope"]:checked',e.target).map(x=>x.value);
      if(!scopes.length)throw new Error("Choose at least one export section.");
      const fromRaw=$("exportFrom").value,toRaw=$("exportTo").value;
      const x=await complianceEdge({action:"create",orgId:state.orgId,format:$("exportFormat").value,scopes,fromAt:fromRaw?new Date(fromRaw).toISOString():null,toAt:toRaw?new Date(toRaw).toISOString():null});
      toast("Compliance export generated and hashed.","success");
      await loadDashboard();showView("compliance");
      if(x.url)window.open(x.url,"_blank","noopener,noreferrer");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  });

  $("complianceExportList").addEventListener("click",async e=>{
    const b=e.target.closest("[data-download-export]");if(!b)return;
    busy(b,true,"Preparing…");
    try{const x=await complianceEdge({action:"download",orgId:state.orgId,exportId:b.dataset.downloadExport});window.open(x.url,"_blank","noopener,noreferrer")}
    catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  });

  $("verifyAuditChainButton").onclick=async()=>{
    const b=$("verifyAuditChainButton");busy(b,true,"Verifying…");
    try{const x=await rpc("trustrelay_verify_org_audit_chain_v09",{p_org_id:state.orgId});msg($("auditChainStatus"),x.valid?`Audit chain valid · ${x.eventCount} events · head ${x.headHash||"genesis"}`:`Audit chain verification failed at ${x.failedEventId}`,x.valid?"success":"error")}
    catch(err){msg($("auditChainStatus"),String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  };

  els.notificationButton.onclick=openNotifications;

  $("launchOrgProfileForm").addEventListener("submit",async e=>{
    e.preventDefault();const b=e.submitter;busy(b,true,"Saving…");
    try{
      await rpc("trustrelay_update_org_profile_v10",{
        p_org_id:state.orgId,p_name:$("launchOrgName").value.trim(),
        p_industry:$("launchOrgIndustry").value.trim()||null,p_website:$("launchOrgWebsite").value.trim()
      });
      toast("Organization profile saved.","success");await loadOrganizations();showView("launch");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  });

  $("launchContactsForm").addEventListener("submit",async e=>{
    e.preventDefault();const b=e.submitter;busy(b,true,"Saving…");
    try{
      await rpc("trustrelay_update_org_onboarding_v10",{
        p_org_id:state.orgId,
        p_primary_contact_email:$("launchPrimaryContact").value.trim(),
        p_security_contact_email:$("launchSecurityContact").value.trim(),
        p_billing_contact_email:$("launchBillingContact").value.trim(),
        p_legal_entity_name:$("launchLegalEntityName").value.trim(),
        p_legal_entity_country:$("launchLegalCountry").value.trim()||null,
        p_legal_entity_region:$("launchLegalRegion").value.trim()||null,
        p_legal_entity_address:$("launchLegalAddress").value.trim()||null
      });
      toast("Onboarding contacts saved.","success");await loadDashboard();showView("launch");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  });

  $("launchLegalList").addEventListener("click",async e=>{
    const b=e.target.closest("[data-accept-legal]");if(!b)return;
    if(!confirm("Accept this legal document for the organization in your authorized organization role?"))return;
    busy(b,true,"Accepting…");
    try{
      await rpc("trustrelay_accept_legal_v10",{p_document_id:b.dataset.acceptLegal,p_org_id:state.orgId,p_context:"organization",p_metadata:{surface:"verifier-v1.0"}});
      toast("Legal document accepted.","success");await loadDashboard();showView("launch");
    }catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}
  });

  $("billingPlanList").addEventListener("click",async e=>{
    const select=e.target.closest("[data-select-plan]");
    if(select){busy(select,true,"Selecting…");try{await billingEdge({action:"select_plan",orgId:state.orgId,planCode:select.dataset.selectPlan});toast("Billing plan selected.","success");await loadDashboard();showView("launch")}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(select,false)}return}
    const checkout=e.target.closest("[data-checkout-plan]");
    if(checkout){busy(checkout,true,"Opening checkout…");try{const x=await billingEdge({action:"checkout",orgId:state.orgId,planCode:checkout.dataset.checkoutPlan});window.location.assign(x.url)}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(checkout,false)}}
  });

  $("requestProductionButton").onclick=async()=>{
    const b=$("requestProductionButton");busy(b,true,"Checking readiness…");
    try{
      const x=await rpc("trustrelay_request_production_activation_v10",{p_org_id:state.orgId});
      toast("Production activation requested.","success");await loadDashboard();showView("launch");
    }catch(err){
      const details=err?.details?.platformBlockers||err?.details?.blockers;
      toast(String(err.code||err.message).replaceAll("_"," ")+(details?" — review blockers in Launch":""),"error");
    }finally{busy(b,false)}
  };

  $("modalClose").onclick=closeModal;els.modalBackdrop.onclick=e=>{if(e.target===els.modalBackdrop)closeModal()};
  els.accountButton.onclick=async()=>{if(confirm("Sign out of the Verifier Portal?"))await supabase.auth.signOut()};
}

async function startPortal(){
  if(state.portalStarting)return;
  state.portalStarting=true;
  try{
    setAuthenticated(true);
    const {data}=await supabase.auth.getUser();state.user=data.user||state.session?.user;
    if(!state.user)throw new Error("AUTH_REQUIRED");
    els.accountButton.textContent=initials(state.user?.user_metadata?.full_name||state.user?.email);
    const accountResult=await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:state.user.id,p_display_name:state.user.user_metadata?.full_name||null});
    if(accountResult?.ok===false)throw new Error(accountResult.code||"ACCOUNT_BINDING_FAILED");
    const mfaReady=await ensureVerifierMfa();
    if(!mfaReady)return;
    await rpc("trustrelay_sso_bootstrap_v13").catch(err=>{
      if(String(err.code||err.message)!=="REQUEST_REJECTED")console.warn("SSO bootstrap",err.code||err.message);
    });
    await acceptPendingOrgInvite();
    await loadOrganizations();
    if(state.orgId){await loadDashboard();showView("dashboard")}
  } finally {
    state.portalStarting=false;
  }
}

async function init(){
  setup();parseUrlInvite();
  const remembered=sessionStorage.getItem("trustrelay_verifier_email");if(remembered){$("authEmail").value=remembered;$("otpEmail").value=remembered;$("ssoEmail").value=remembered}
  const {data}=await supabase.auth.getSession();state.session=data.session;state.user=data.session?.user||null;
  supabase.auth.onAuthStateChange((event,session)=>{state.session=session;state.user=session?.user||null;if(event==="SIGNED_OUT"){setAuthenticated(false);return}if(session&&["SIGNED_IN","TOKEN_REFRESHED","USER_UPDATED"].includes(event))setTimeout(()=>startPortal(),0)});
  if(state.session)await startPortal();else{setAuthenticated(false);if(sessionStorage.getItem("trustrelay_pending_org_invite"))msg(els.authMessage,"Sign in with the invited email address to join the organization.","warning")}
}
init().catch(e=>{console.error(e);setAuthenticated(false);msg(els.authMessage,"Verifier Portal could not initialize. Refresh and try again.","error")});
