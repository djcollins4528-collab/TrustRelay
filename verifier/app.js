import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm";

const SUPABASE_URL="https://awrradmcwgeepwwdrbzi.supabase.co";
const SUPABASE_PUBLISHABLE_KEY="sb_publishable_YHwczFLXsSuJtOQDI_65Lw_dRcyLMjx";

const supabase=createClient(SUPABASE_URL,SUPABASE_PUBLISHABLE_KEY,{
  auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}
});

const state={
  session:null,user:null,organizations:[],orgId:null,dashboard:null,currentView:"dashboard"
};

const $=id=>document.getElementById(id);
const qsa=(s,r=document)=>[...r.querySelectorAll(s)];
const els={
  authView:$("authView"),portalView:$("portalView"),authMessage:$("authMessage"),
  modalBackdrop:$("modalBackdrop"),modalContent:$("modalContent"),toastRegion:$("toastRegion"),
  orgSelect:$("orgSelect"),accountButton:$("accountButton")
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
function setAuthenticated(on){els.authView.classList.toggle("hidden",on);els.portalView.classList.toggle("hidden",!on);els.accountButton.classList.toggle("hidden",!on)}
async function rpc(name,args={}){const {data,error}=await supabase.rpc(name,args);if(error)throw error;if(data?.ok===false){const e=new Error(data.code||"REQUEST_REJECTED");e.code=data.code;e.status=data.status;throw e}return data}
async function token(){const {data,error}=await supabase.auth.getSession();if(error)throw error;return data.session?.access_token||null}
async function evaluate(body){const t=await token();if(!t)throw new Error("AUTH_REQUIRED");const r=await fetch(SUPABASE_URL+"/functions/v1/trustrelay-verifier-evaluate-v07",{method:"POST",headers:{apikey:SUPABASE_PUBLISHABLE_KEY,authorization:"Bearer "+t,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(body)});const text=await r.text();let data=null;try{data=text?JSON.parse(text):null}catch{}if(!r.ok){const e=new Error(data?.error?.code||"EVALUATION_FAILED");e.code=data?.error?.code||"EVALUATION_FAILED";throw e}return data}
function canManage(){return["owner","admin","developer"].includes(state.dashboard?.membership?.role)}
function canInvite(){return["owner","admin"].includes(state.dashboard?.membership?.role)}
function currentOrg(){return state.organizations.find(x=>x.organization?.id===state.orgId)?.organization||state.dashboard?.organization||null}

function showView(name){
  state.currentView=name;
  qsa(".portal-section").forEach(x=>x.classList.add("hidden"));
  const map={dashboard:"dashboardView",verify:"verifyView",keys:"keysView",team:"teamView",webhooks:"webhooksView",audit:"auditView",developer:"developerView"};
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
  state.dashboard=await rpc("trustrelay_org_dashboard_v07",{p_org_id:state.orgId});
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
    <dt>Your role</dt><dd>${esc(d.membership?.role||"—")}</dd>`;
  renderDecisions($("recentDecisions"),(d.recentDecisions||[]).slice(0,8),true);
  renderKeys();renderTeam();renderWebhooks();renderAudit();renderDeveloper();
  $("createKeyButton").classList.toggle("hidden",!canManage());
  $("createWebhookButton").classList.toggle("hidden",!canManage());
  $("inviteMemberButton").classList.toggle("hidden",!canInvite());
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
      <div class="management-actions">${!k.revokedAt&&canManage()?`<button class="button danger small" data-revoke-key="${esc(k.id)}" type="button">Revoke</button>`:""}</div>
    </div>`).join("");
}

function renderTeam(){
  const root=$("teamList"),items=state.dashboard?.members||[];
  root.innerHTML=items.length?items.map(x=>`
    <div class="management-row"><div><strong>${esc(x.email)}</strong><p>${esc(x.title||"Institution member")}</p><div class="row-meta"><span class="role-chip">${esc(x.role)}</span><span class="small-chip">${esc(x.status)}</span></div></div></div>`).join(""):'<div class="empty-management">No team members.</div>';
  const pending=state.dashboard?.pendingInvitations||[];
  $("pendingInvites").innerHTML=`<div class="card-heading"><div><h3>Pending invitations</h3><p>One-time team invitations awaiting acceptance.</p></div></div>`+(pending.length?pending.map(x=>`<div class="management-row"><div><strong>${esc(x.email)}</strong><p>${esc(x.role)} · expires ${esc(formatDate(x.expiresAt,true))}</p></div></div>`).join(""):'<div class="empty-management">No pending invitations.</div>');
}

function renderWebhooks(){
  const root=$("webhookList"),items=state.dashboard?.webhooks||[];
  root.innerHTML=items.length?items.map(w=>`
    <div class="management-row"><div><strong>${esc(w.name)}</strong><p>${esc(w.endpointUrl)}</p><div class="row-meta"><span class="small-chip">${esc(w.status)}</span><span class="small-chip">${esc((w.events||[]).join(", "))}</span><span class="small-chip">${w.consecutiveFailures||0} failures</span></div></div>
    <div class="management-actions">${w.status==="active"&&canManage()?`<button class="button danger small" data-revoke-webhook="${esc(w.id)}" type="button">Revoke</button>`:""}</div></div>`).join(""):'<div class="empty-management">No webhook endpoints configured.</div>';
  const del=state.dashboard?.recentWebhookDeliveries||[];
  $("deliveryList").innerHTML=del.length?del.map(x=>`<div class="management-row"><div><strong>${esc(x.eventType)}</strong><p>${esc(x.eventId)} · HTTP ${esc(x.responseStatus??"—")} · ${esc(formatDate(x.createdAt,true))}</p><div class="row-meta"><span class="small-chip">${esc(x.status)}</span></div></div></div>`).join(""):'<div class="empty-management">No webhook deliveries yet.</div>';
}

function renderAudit(){
  const root=$("auditList"),items=state.dashboard?.recentDecisions||[];
  if(!items.length){root.innerHTML='<div class="empty-management">No audit evidence yet.</div>';return}
  root.innerHTML=items.map(x=>`
    <article class="audit-row">
      <span class="decision-badge ${esc(x.decision)}">${esc(x.decision)}</span>
      <div><strong>${esc(x.action)} → ${esc(x.resource)}</strong><p>${esc(x.reasonCode)} — ${esc(x.reasonDetail||"")}</p><p>Request ${esc(x.requestId)} · ${esc(formatDate(x.decidedAt,true))} · source ${esc(x.source||"api")}</p></div>
      <div class="audit-hashes">decision ${esc(x.id)}<br>eval ${esc(x.evaluationHash||"—")}<br>audit ${esc(x.auditEventId||"—")}</div>
    </article>`).join("");
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
    "evidence": {"invoiceId":"INV-1042"}
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
    </div>`;
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

  $("evaluateForm").addEventListener("submit",async e=>{e.preventDefault();const b=e.submitter;busy(b,true,"Evaluating…");try{let evidence={};const raw=$("decisionEvidence").value.trim();if(raw){evidence=JSON.parse(raw);if(!evidence||typeof evidence!=="object"||Array.isArray(evidence))throw new Error("Evidence must be a JSON object.")}const amountRaw=$("decisionAmount").value.trim();const result=await evaluate({orgId:state.orgId,requestId:"req_"+crypto.randomUUID().replaceAll("-",""),correlationId:$("correlationId").value.trim()||null,credential:$("credentialToken").value.trim(),action:$("decisionAction").value.trim(),resource:$("decisionResource").value.trim(),amount:amountRaw===""?null:Number(amountRaw),currency:$("decisionCurrency").value||null,evidence});showDecision(result);toast("Authorization decision recorded.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error")}finally{busy(b,false)}});

  $("createKeyButton").onclick=()=>openModal(`<p class="eyebrow">NEW PARTNER KEY</p><h2>Create server API key.</h2><p>The raw key is shown once. Store it in your server-side secret manager.</p><form id="keyForm"><div class="field"><label for="keyName">Key name</label><input id="keyName" required maxlength="100" placeholder="Production backend"></div><div class="field"><label>Scopes</label><div class="scope-checks"><label><input type="checkbox" name="scope" value="decisions:read" checked> decisions:read</label><label><input type="checkbox" name="scope" value="decisions:write" checked> decisions:write</label></div></div><div class="modal-actions"><button class="button primary" type="submit">Create key</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="keyForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const scopes=qsa('input[name="scope"]:checked',e.target).map(x=>x.value);const x=await rpc("trustrelay_create_api_key_v07",{p_org_id:state.orgId,p_name:$("keyName").value.trim(),p_scopes:scopes,p_expires_at:null});els.modalContent.innerHTML=`<p class="eyebrow">KEY CREATED</p><h2>Copy this key now.</h2><p class="warning-copy">TrustRelay stores only its SHA-256 hash. This raw key cannot be recovered later.</p><div class="secret-once">${esc(x.apiKey)}</div><div class="modal-actions"><button id="copyNewKey" class="button primary" type="button">Copy API key</button></div>`;$("copyNewKey").onclick=()=>copyText(x.apiKey,"API key copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});

  $("keyList").addEventListener("click",async e=>{const b=e.target.closest("[data-revoke-key]");if(!b)return;if(!confirm("Revoke this API key? Existing integrations using it will immediately fail."))return;busy(b,true,"Revoking…");try{await rpc("trustrelay_revoke_api_key_v07",{p_org_id:state.orgId,p_key_id:b.dataset.revokeKey});toast("API key revoked.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message),"error")}finally{busy(b,false)}});

  $("inviteMemberButton").onclick=()=>openModal(`<p class="eyebrow">TEAM INVITATION</p><h2>Invite organization member.</h2><form id="inviteForm"><div class="field"><label for="inviteEmail">Email</label><input id="inviteEmail" type="email" required></div><div class="field"><label for="inviteRole">Role</label><select id="inviteRole"><option value="verifier">Verifier</option><option value="developer">Developer</option><option value="auditor">Auditor</option><option value="admin">Admin</option></select></div><div class="modal-actions"><button class="button primary" type="submit">Create invitation</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="inviteForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const x=await rpc("trustrelay_invite_org_member_v07",{p_org_id:state.orgId,p_email:$("inviteEmail").value.trim(),p_role:$("inviteRole").value});const link=location.origin+"/verifier/?org_invite="+encodeURIComponent(x.invitation.token);els.modalContent.innerHTML=`<p class="eyebrow">INVITATION READY</p><h2>Share this one-time invitation.</h2><p>Send it only to <strong>${esc(x.invitation.email)}</strong>.</p><div class="secret-once">${esc(link)}</div><div class="modal-actions"><button id="copyOrgInvite" class="button primary" type="button">Copy invitation link</button></div>`;$("copyOrgInvite").onclick=()=>copyText(link,"Organization invitation copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});

  $("createWebhookButton").onclick=()=>openModal(`<p class="eyebrow">SIGNED WEBHOOK</p><h2>Add HTTPS endpoint.</h2><form id="webhookForm"><div class="field"><label for="webhookName">Name</label><input id="webhookName" required maxlength="100" placeholder="Authorization events"></div><div class="field"><label for="webhookUrl">HTTPS endpoint</label><input id="webhookUrl" type="url" required placeholder="https://example.com/trustrelay"></div><div class="field"><label>Events</label><div class="scope-checks"><label><input type="checkbox" name="event" value="decision.created" checked> decision.created</label><label><input type="checkbox" name="event" value="grant.revoked"> grant.revoked</label><label><input type="checkbox" name="event" value="credential.revoked"> credential.revoked</label></div></div><div class="modal-actions"><button class="button primary" type="submit">Create webhook</button></div></form>`);
  els.modalContent.addEventListener("submit",async e=>{if(e.target.id==="webhookForm"){e.preventDefault();const b=e.submitter;busy(b,true,"Creating…");try{const events=qsa('input[name="event"]:checked',e.target).map(x=>x.value);const x=await rpc("trustrelay_create_webhook_v07",{p_org_id:state.orgId,p_name:$("webhookName").value.trim(),p_endpoint_url:$("webhookUrl").value.trim(),p_events:events});els.modalContent.innerHTML=`<p class="eyebrow">WEBHOOK CREATED</p><h2>Save the signing secret.</h2><p class="warning-copy">It is encrypted in Vault and shown only once.</p><div class="secret-once">${esc(x.signingSecret)}</div><div class="modal-actions"><button id="copyWebhookSecret" class="button primary" type="button">Copy signing secret</button></div>`;$("copyWebhookSecret").onclick=()=>copyText(x.signingSecret,"Webhook secret copied");await loadDashboard()}catch(err){toast(String(err.code||err.message).replaceAll("_"," "),"error");busy(b,false)}}});
  $("webhookList").addEventListener("click",async e=>{const b=e.target.closest("[data-revoke-webhook]");if(!b)return;if(!confirm("Revoke this webhook endpoint?"))return;busy(b,true,"Revoking…");try{await rpc("trustrelay_revoke_webhook_v07",{p_org_id:state.orgId,p_webhook_id:b.dataset.revokeWebhook});toast("Webhook revoked.","success");await loadDashboard()}catch(err){toast(String(err.code||err.message),"error")}finally{busy(b,false)}});

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
