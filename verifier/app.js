import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm";

const SUPABASE_URL="https://awrradmcwgeepwwdrbzi.supabase.co";
const SUPABASE_PUBLISHABLE_KEY="sb_publishable_YHwczFLXsSuJtOQDI_65Lw_dRcyLMjx";

const supabase=createClient(SUPABASE_URL,SUPABASE_PUBLISHABLE_KEY,{
  auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}
});

const state={
  session:null,user:null,organizations:[],orgId:null,dashboard:null,currentView:"dashboard",notifications:null
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
function closeModal(){els.modalBackdrop.classList.add("hidden");els.modalContent.innerHTML=""}
async function copyText(text,label="Copied"){try{await navigator.clipboard.writeText(text);toast(label,"success")}catch{const a=document.createElement("textarea");a.value=text;a.style.position="fixed";a.style.opacity="0";document.body.appendChild(a);a.select();document.execCommand("copy");a.remove();toast(label,"success")}}
function authRedirectUrl(){const u=new URL("/verifier/",window.location.origin);const token=localStorage.getItem("trustrelay_pending_org_invite");if(token)u.searchParams.set("org_invite",token);return u.toString()}
function showOtp(show){$("magicForm").classList.toggle("hidden",show);$("otpForm").classList.toggle("hidden",!show);if(show){const e=localStorage.getItem("trustrelay_verifier_email")||$("authEmail").value.trim();if(e)$("otpEmail").value=e;setTimeout(()=>$("otpCode").focus(),0)}clearMsg(els.authMessage)}
function setAuthenticated(on){els.authView.classList.toggle("hidden",on);els.portalView.classList.toggle("hidden",!on);els.accountButton.classList.toggle("hidden",!on);els.notificationButton?.classList.toggle("hidden",!on)}
async function rpc(name,args={}){const {data,error}=await supabase.rpc(name,args);if(error)throw error;if(data?.ok===false){const e=new Error(data.code||"REQUEST_REJECTED");e.code=data.code;e.status=data.status;throw e}return data}
async function token(){const {data,error}=await supabase.auth.getSession();if(error)throw error;return data.session?.access_token||null}
async function evaluate(body){const t=await token();if(!t)throw new Error("AUTH_REQUIRED");const r=await fetch(SUPABASE_URL+"/functions/v1/trustrelay-verifier-evaluate-v07",{method:"POST",headers:{apikey:SUPABASE_PUBLISHABLE_KEY,authorization:"Bearer "+t,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(body)});const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}if(!r.ok){const e=new Error(data?.error?.code||"EVALUATION_FAILED");e.code=data?.error?.code||"EVALUATION_FAILED";throw e}return data}
async function evidenceFile(body){const t=await token();if(!t)throw new Error("AUTH_REQUIRED");const r=await fetch(SUPABASE_URL+"/functions/v1/trustrelay-evidence-v08",{method:"POST",headers:{apikey:SUPABASE_PUBLISHABLE_KEY,authorization:"Bearer "+t,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(body)});const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}if(!r.ok){const e=new Error(data?.error?.code||"EVIDENCE_REQUEST_FAILED");e.code=data?.error?.code||"EVIDENCE_REQUEST_FAILED";throw e}return data}
async function complianceEdge(body){const t=await token();if(!t)throw new Error("AUTH_REQUIRED");const r=await fetch(SUPABASE_URL+"/functions/v1/trustrelay-compliance-export-v09",{method:"POST",headers:{apikey:SUPABASE_PUBLISHABLE_KEY,authorization:"Bearer "+t,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(body)});const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}if(!r.ok){const e=new Error(data?.error?.code||"COMPLIANCE_REQUEST_FAILED");e.code=data?.error?.code||"COMPLIANCE_REQUEST_FAILED";throw e}return data}
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
  const map={dashboard:"dashboardView",verify:"verifyView",evidence:"evidenceView",keys:"keysView",team:"teamView",webhooks:"webhooksView",compliance:"complianceView",audit:"auditView",developer:"developerView"};
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
    rpc("trustrelay_notifications_v09",{p_limit:1,p_unread_only:true}).catch(()=>({unreadCount:0,notifications:[]}))
  ]);
  state.dashboard=results[0];
  state.notifications=results[1];
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
  renderKeys();renderTeam();renderWebhooks();renderEvidenceRequests();renderCompliance();renderAudit();renderDeveloper();renderNotificationBadge();
  $("createKeyButton").classList.toggle("hidden",!canManageKeys());
  $("createWebhookButton").classList.toggle("hidden",!canManageWebhooks());
  $("inviteMemberButton").classList.toggle("hidden",!canInvite());
  $("complianceExportForm")?.classList.toggle("hidden",!canExportAudit());
  $("verifyAuditChainButton")?.classList.toggle("hidden",!hasPerm("audit.read"));
  qsa('.verifier-nav [data-view="verify"]').forEach(x=>x.classList.toggle("hidden",!hasPerm("decisions.evaluate")));
  qsa('.verifier-nav [data-view="compliance"]').forEach(x=>x.classList.toggle("hidden",!canExportAudit()));
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
    <div class="management-actions">${canManageWebhooks()&&w.status!=="revoked"?`<button class="button ghost small" data-test-webhook="${esc(w.id)}" type="button">Test</button>${w.status==="active"?`<button class="button ghost small" data-webhook-state="${esc(w.id)}" data-state="paused" type="button">Pause</button>`:w.status==="paused"?`<button class="button secondary small" data-webhook-state="${esc(w.id)}" data-state="active" type="button">Resume</button>`:""}<button class="button secondary small" data-rotate-webhook="${esc(w.id)}" type="button">Rotate secret</button><button class="button danger small" data-revoke-webhook="${esc(w.id)}" type="button">Revoke</button>`:""}</div></div>`).join(""):'<div class="empty-management">No webhook endpoints configured.</div>';
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
  const t=localStorage.getItem("trustrelay_pending_org_invite");if(!t)return;
  try{const r=await rpc("trustrelay_accept_org_invite_v07",{p_token:t});localStorage.removeItem("trustrelay_pending_org_invite");toast("Organization invitation accepted.","success");state.orgId=r.organizationId}catch(e){toast("Organization invitation could not be accepted: "+String(e.code||e.message).replaceAll("_"," "),"error")}
}

function parseUrlInvite(){
  const p=new URLSearchParams(location.search),t=p.get("org_invite");if(t){localStorage.setItem("trustrelay_pending_org_invite",t);history.replaceState({},"",location.pathname)}
}

function setup(){
  $("magicForm").addEventListener("submit",async e=>{e.preventDefault();clearMsg(els.authMessage);const b=e.submitter;busy(b,true,"Sending secure link…");const email=$("authEmail").value.trim().toLowerCase(),name=$("authName").value.trim();try{const options={shouldCreateUser:true,emailRedirectTo:authRedirectUrl()};if(name)options.data={full_name:name};const {error}=await supabase.auth.signInWithOtp({email,options});if(error)throw error;localStorage.setItem("trustrelay_verifier_email",email);$("otpEmail").value=email;msg(els.authMessage,"Check your email for the TrustRelay magic link. If your email contains a six-digit code, use the code option below.","success")}catch(err){msg(els.authMessage,err.message||"Could not send sign-in email.","error")}finally{busy(b,false)}});
  $("showOtp").onclick=()=>showOtp(true);$("backToMagic").onclick=()=>showOtp(false);
  $("otpForm").addEventListener("submit",async e=>{e.preventDefault();const b=e.submitter;busy(b,true,"Verifying…");try{const {data,error}=await supabase.auth.verifyOtp({email:$("otpEmail").value.trim().toLowerCase(),token:$("otpCode").value.trim(),type:"email"});if(error)throw error;state.session=data.session;state.user=data.user;await startPortal()}catch(err){msg(els.authMessage,err.message||"Invalid or expired code.","error")}finally{busy(b,false)}});

  qsa(".verifier-nav .nav-item").forEach(b=>b.onclick=()=>showView(b.dataset.view));qsa("[data-go]").forEach(b=>b.onclick=()=>showView(b.dataset.go));
  els.orgSelect.onchange=async()=>{state.orgId=els.orgSelect.value;await loadDashboard();showView("dashboard")};
  $("newOrgButton").onclick=()=>{state.orgId=null;$("noOrgView").classList.remove("hidden");qsa(".portal-section").filter(x=>x.id!=="noOrgView").forEach(x=>x.classList.add("hidden"))};
  $("orgForm").addEventListener("submit",async e=>{e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const x=await rpc("trustrelay_create_organization_v07",{p_name:$("orgName").value.trim(),p_industry:$("orgIndustry").value.trim()||null,p_website:$("orgWebsite").value.trim()||null});state.orgId=x.organization.id;toast("Sandbox organization created.","success");e.currentTarget.reset();await loadOrganizations();showView("dashboard")}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}});

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

  $("createWebhookButton").onclick=()=>openModal(`<p class="eyebrow">SIGNED WEBHOOK</p><h2>Add HTTPS endpoint.</h2><form id="webhookForm"><div class="field"><label for="webhookName">Name</label><input id="webhookName" required maxlength="100" placeholder="Authorization events"></div><div class="field"><label for="webhookUrl">HTTPS endpoint</label><input id="webhookUrl" type="url" required placeholder="https://example.com/trustrelay"></div><div class="field"><label>Events</label><div class="scope-checks"><label><input type="checkbox" name="event" value="decision.created" checked> decision.created</label><label><input type="checkbox" name="event" value="grant.revoked"> grant.revoked</label><label><input type="checkbox" name="event" value="credential.revoked"> credential.revoked</label><label><input type="checkbox" name="event" value="evidence.requested"> evidence.requested</label><label><input type="checkbox" name="event" value="evidence.submitted"> evidence.submitted</label><label><input type="checkbox" name="event" value="evidence.resolved"> evidence.resolved</label><label><input type="checkbox" name="event" value="organization.member.invited"> organization.member.invited</label><label><input type="checkbox" name="event" value="organization.member.joined"> organization.member.joined</label><label><input type="checkbox" name="event" value="organization.member.role_changed"> organization.member.role_changed</label><label><input type="checkbox" name="event" value="organization.member.disabled"> organization.member.disabled</label><label><input type="checkbox" name="event" value="organization.member.restored"> organization.member.restored</label><label><input type="checkbox" name="event" value="organization.member.removed"> organization.member.removed</label><label><input type="checkbox" name="event" value="organization.ownership_transferred"> organization.ownership_transferred</label><label><input type="checkbox" name="event" value="identity.assurance.changed"> identity.assurance.changed</label><label><input type="checkbox" name="event" value="compliance.export.ready"> compliance.export.ready</label></div></div><div class="modal-actions"><button class="button primary" type="submit">Create webhook</button></div></form>`);
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

  $("modalClose").onclick=closeModal;els.modalBackdrop.onclick=e=>{if(e.target===els.modalBackdrop)closeModal()};
  els.accountButton.onclick=async()=>{if(confirm("Sign out of the Verifier Portal?"))await supabase.auth.signOut()};
}

async function startPortal(){
  setAuthenticated(true);
  const {data}=await supabase.auth.getUser();state.user=data.user||state.session?.user;els.accountButton.textContent=initials(state.user?.user_metadata?.full_name||state.user?.email);
  await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:state.user.id,p_display_name:state.user.user_metadata?.full_name||null}).catch(()=>{});
  await acceptPendingOrgInvite();
  await loadOrganizations();
  if(state.orgId){await loadDashboard();showView("dashboard")}
}

async function init(){
  setup();parseUrlInvite();
  const remembered=localStorage.getItem("trustrelay_verifier_email");if(remembered){$("authEmail").value=remembered;$("otpEmail").value=remembered}
  const {data}=await supabase.auth.getSession();state.session=data.session;state.user=data.session?.user||null;
  supabase.auth.onAuthStateChange((event,session)=>{state.session=session;state.user=session?.user||null;if(event==="SIGNED_OUT"){setAuthenticated(false);return}if(session&&["SIGNED_IN","TOKEN_REFRESHED","USER_UPDATED"].includes(event))setTimeout(()=>startPortal(),0)});
  if(state.session)await startPortal();else{setAuthenticated(false);if(localStorage.getItem("trustrelay_pending_org_invite"))msg(els.authMessage,"Sign in with the invited email address to join the organization.","warning")}
}
init().catch(e=>{console.error(e);setAuthenticated(false);msg(els.authMessage,"Verifier Portal could not initialize. Refresh and try again.","error")});
