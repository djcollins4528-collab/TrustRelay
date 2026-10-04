
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";

function envJson(name) {
  try { return JSON.parse(Deno.env.get(name) || "{}"); } catch { return {}; }
}
function secretKey() {
  const keys = envJson("SUPABASE_SECRET_KEYS");
  return keys.default || Object.values(keys).find(v => typeof v === "string" && v) || "";
}
function publishableKey() {
  const keys = envJson("SUPABASE_PUBLISHABLE_KEYS");
  return keys.default || "";
}
function serviceHeaders() {
  const key = secretKey();
  const h = { apikey: key, "content-type": "application/json", accept: "application/json" };
  if (key && !key.startsWith("sb_secret_")) h.authorization = "Bearer " + key;
  return h;
}
async function internalCapability(req,path) {
  const token=(req.headers.get("x-trustrelay-internal-capability")||"").trim();
  if(!token)return null;
  if(req.method!=="POST"||path!=="/v1/decisions/evaluate")throw {status:401,code:"INTERNAL_CAPABILITY_INVALID"};
  if(!/^icap_[0-9a-f]{64}$/.test(token))throw {status:401,code:"INTERNAL_CAPABILITY_INVALID"};
  const raw=await req.clone().text();
  if(new TextEncoder().encode(raw).byteLength>262144)throw {status:413,code:"PAYLOAD_TOO_LARGE"};
  const bodyHash=await sha256Hex(raw);
  const tokenHash=await sha256Hex(token);
  const cap=await rpc("trustrelay_consume_portal_capability_v12",{
    p_token_hash:tokenHash,p_body_sha256:bodyHash
  });
  if(!cap?.ok)throw {status:Number(cap?.status)||401,code:cap?.code||"INTERNAL_CAPABILITY_INVALID"};
  return cap;
}
function json(data, status=200, extra={}) {
  return Response.json(data, { status, headers: { "cache-control":"no-store", "x-content-type-options":"nosniff", ...extra } });
}
function pathOf(req) {
  const p = new URL(req.url).pathname;
  const marker = "/trustrelay-partner-v07";
  const i = p.indexOf(marker);
  return i >= 0 ? (p.slice(i + marker.length) || "/") : p;
}
function apiKeyFrom(req) {
  const direct = (req.headers.get("x-trustrelay-key") || "").trim();
  if (direct) return direct;
  const auth = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m ? m[1].trim() : "";
}
async function rpc(name, payload) {
  const r = await fetch(SUPABASE_URL + "/rest/v1/rpc/" + name, {
    method:"POST", headers:serviceHeaders(), body:JSON.stringify(payload || {})
  });
  const t = await r.text();
  let d = null; try { d = t ? JSON.parse(t) : null; } catch { d = null; }
  if (!r.ok) throw { status:503, code:"DATABASE_ERROR" };
  return d;
}
async function body(req) {
  const contentLength=Number(req.headers.get("content-length")||0);
  if (Number.isFinite(contentLength) && contentLength > 262144) throw {status:413,code:"PAYLOAD_TOO_LARGE"};
  const t = await req.text();
  if (new TextEncoder().encode(t).byteLength > 262144) throw {status:413,code:"PAYLOAD_TOO_LARGE"};
  if (!t) return {};
  try { return JSON.parse(t); } catch { throw {status:400,code:"INVALID_JSON"}; }
}
async function sha256Hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...d].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") {
    return Object.keys(v).sort().reduce((a,k)=>(a[k]=canonical(v[k]),a),{});
  }
  return v;
}
function resourceMatches(pattern, resource) {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0,-1));
  return pattern === resource;
}
function evaluate(authority, request) {
  const allowed = Array.isArray(authority?.allowed) ? authority.allowed : [];
  const prohibited = Array.isArray(authority?.prohibited) ? authority.prohibited : [];
  const resources = Array.isArray(authority?.resources) ? authority.resources : [];
  const rules = authority?.rules && typeof authority.rules === "object" ? authority.rules : {};
  const escalation = authority?.escalation && typeof authority.escalation === "object" ? authority.escalation : {};

  if (prohibited.includes(request.action)) {
    return {decision:"DENY",reasonCode:"ACTION_PROHIBITED",reasonDetail:"The action is explicitly prohibited by the grant."};
  }
  if (!allowed.includes(request.action)) {
    return {decision:"DENY",reasonCode:"ACTION_NOT_ALLOWED",reasonDetail:"The action is outside the grant's allowed scope."};
  }
  if (!resources.some(p => resourceMatches(String(p), request.resource))) {
    return {decision:"DENY",reasonCode:"RESOURCE_NOT_ALLOWED",reasonDetail:"The resource is outside the grant's resource scope."};
  }

  const supported = new Set(["maxAmount","allowedCurrencies","requireEvidence"]);
  const unknown = Object.keys(rules).filter(k => !supported.has(k));
  if (unknown.length) {
    return {decision:"ESCALATE",reasonCode:"POLICY_REVIEW_REQUIRED",reasonDetail:"The grant contains policy rules that require manual review."};
  }

  const hasCurrencyPolicy = Array.isArray(rules.allowedCurrencies);
  const hasAmountPolicy = rules.maxAmount != null;
  if ((hasCurrencyPolicy || hasAmountPolicy) && request.amount == null) {
    return {decision:"DENY",reasonCode:"AMOUNT_REQUIRED",reasonDetail:"An amount is required when the grant contains monetary policy."};
  }

  if (hasCurrencyPolicy) {
    if (!request.currency) {
      return {decision:"DENY",reasonCode:"CURRENCY_REQUIRED",reasonDetail:"A currency is required for this monetary request."};
    }
    if (!rules.allowedCurrencies.includes(request.currency)) {
      return {decision:"DENY",reasonCode:"CURRENCY_NOT_ALLOWED",reasonDetail:"The requested currency is not permitted by the grant."};
    }
  }

  if (hasAmountPolicy) {
    const amount = Number(request.amount);
    const limit = Number(rules.maxAmount);
    if (!Number.isFinite(limit) || limit < 0) {
      return {decision:"ESCALATE",reasonCode:"POLICY_REVIEW_REQUIRED",reasonDetail:"The amount rule could not be evaluated automatically."};
    }
    if (!Number.isFinite(amount) || amount < 0) {
      return {decision:"DENY",reasonCode:"AMOUNT_INVALID",reasonDetail:"The requested amount is invalid."};
    }
    if (amount > limit) {
      if (escalation.aboveLimit === "ESCALATE") {
        return {decision:"ESCALATE",reasonCode:"AMOUNT_ABOVE_LIMIT",reasonDetail:"The amount exceeds the grant limit and requires escalation."};
      }
      return {decision:"DENY",reasonCode:"AMOUNT_ABOVE_LIMIT",reasonDetail:"The amount exceeds the grant limit."};
    }
  }

  const evidence = request.evidence && typeof request.evidence === "object" && !Array.isArray(request.evidence) ? request.evidence : {};
  if (rules.requireEvidence && Object.keys(evidence).length === 0) {
    return {decision:"ESCALATE",reasonCode:"EVIDENCE_REQUIRED",reasonDetail:"Supporting evidence is required before this request can proceed."};
  }
  if (escalation.always === true) {
    return {decision:"ESCALATE",reasonCode:"MANUAL_REVIEW_REQUIRED",reasonDetail:"This grant requires manual review for every request."};
  }

  return {decision:"ALLOW",reasonCode:"POLICY_SATISFIED",reasonDetail:"The requested action satisfies the active authority grant."};
}
async function verifyCredential(token) {
  const r = await fetch(SUPABASE_URL + "/functions/v1/trustrelay-credential-verify-v06", {
    method:"POST",
    headers:{ apikey:publishableKey(), "content-type":"application/json", accept:"application/json" },
    body:JSON.stringify({token})
  });
  const t = await r.text();
  let d = null; try { d = t ? JSON.parse(t) : null; } catch {}
  if (!r.ok) throw {status:502,code:"CREDENTIAL_VERIFIER_UNAVAILABLE"};
  return d || {};
}
async function dispatchWebhooks(orgId,eventType,eventId,payload){
  try{
    const queued=await rpc("trustrelay_queue_webhooks_v07",{
      p_org_id:orgId,p_event_type:eventType,p_event_id:eventId,p_payload_json:JSON.stringify(payload)
    });
    if(queued?.ok) await rpc("trustrelay_dispatch_due_webhooks_v09",{p_limit:50});
  }catch{}
}
function publicDecision(row) {
  if (!row) return null;
  return {
    id:row.id,requestId:row.request_id,correlationId:row.correlation_id,
    decision:row.decision,reasonCode:row.reason_code,reasonDetail:row.reason_detail,
    action:row.action,resource:row.resource,grantId:row.grant_id,
    credentialJti:row.credential_jti,decidedAt:row.decided_at,
    evaluationHash:row.evaluation_hash,auditEventId:row.audit_event_id,
    latencyMs:row.latency_ms,source:row.source
  };
}

Deno.serve(async req => {
  const started = performance.now();
  try {
    const path = pathOf(req);
    if (req.method==="GET" && path==="/healthz") {
      return json({status:"ok",service:"trustrelay-partner-v07",version:"1.0.0"});
    }

    const internalContext=await internalCapability(req,path);
    const internal=!!internalContext;
    const internalOrgId=internal?String(internalContext.organizationId||""):"";
    const internalUserId=internal?String(internalContext.authUserId||""):"";
    if(internal){
      if(!internalOrgId||internalOrgId.length>160)throw {status:400,code:"INTERNAL_ORGANIZATION_INVALID"};
      if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(internalUserId)){
        throw {status:400,code:"INTERNAL_USER_INVALID"};
      }
    }
    const apiKey=internal?"":apiKeyFrom(req);
    if(!internal&&!apiKey)throw {status:401,code:"API_KEY_REQUIRED"};

    const getMatch = /^\/v1\/decisions\/([^/]+)$/.exec(path);
    if (req.method==="GET" && getMatch) {
      if(internal)throw {status:404,code:"NOT_FOUND"};
      const requestId=decodeURIComponent(getMatch[1]);
      const ctx=await rpc("trustrelay_partner_context_v07",{
        p_api_key:apiKey,p_request_id:requestId,p_required_scope:"decisions:read",p_rate_limit:120
      });
      if (!ctx?.ok) throw {status:Number(ctx?.status)||401,code:ctx?.code||"API_KEY_INVALID"};
      if (!ctx.prior) throw {status:404,code:"DECISION_NOT_FOUND"};
      return json({
        requestId,decision:publicDecision(ctx.prior),
        rate:ctx.rate,organization:{id:ctx.organization.id,name:ctx.organization.name,mode:ctx.organization.mode}
      });
    }

    if (!(req.method==="POST" && path==="/v1/decisions/evaluate")) {
      throw {status:404,code:"NOT_FOUND"};
    }

    const input=await body(req);
    const requestId=String(input.requestId||"").trim();
    const correlationId=input.correlationId==null?null:String(input.correlationId).trim().slice(0,160);
    const token=String(input.credential||input.credentialToken||"").trim();
    const action=String(input.action||"").trim();
    const resource=String(input.resource||"").trim();
    const currency=input.currency==null?null:String(input.currency).trim().toUpperCase();
    const amount=input.amount==null?null:Number(input.amount);
    const evidence=input.evidence&&typeof input.evidence==="object"&&!Array.isArray(input.evidence)?input.evidence:{};
    const evidenceDocumentIds=Array.isArray(input.evidenceDocumentIds)
      ? [...new Set(input.evidenceDocumentIds.filter(x=>typeof x==="string"&&x.trim()).map(x=>x.trim()))].slice(0,25)
      : [];

    if (!requestId || requestId.length>160) throw {status:400,code:"REQUEST_ID_REQUIRED"};
    if (!token || token.length>32768) throw {status:400,code:"CREDENTIAL_REQUIRED"};
    if (!action || action.length>120) throw {status:400,code:"ACTION_REQUIRED"};
    if (!resource || resource.length>240) throw {status:400,code:"RESOURCE_REQUIRED"};
    if (currency && !/^[A-Z]{3}$/.test(currency)) throw {status:400,code:"CURRENCY_INVALID"};
    if (amount!=null && (!Number.isFinite(amount)||amount<0)) throw {status:400,code:"AMOUNT_INVALID"};

    const sanitized={
      requestId,correlationId,action,resource,amount,currency,evidence,evidenceDocumentIds,
      credentialFingerprint:await sha256Hex(token)
    };
    const requestFingerprint=await sha256Hex(JSON.stringify(canonical(sanitized)));

    const ctx=internal
      ? await rpc("trustrelay_internal_partner_context_v12",{
          p_org_id:internalOrgId,p_request_id:requestId,p_rate_limit:120
        })
      : await rpc("trustrelay_partner_context_v07",{
          p_api_key:apiKey,p_request_id:requestId,p_required_scope:"decisions:write",p_rate_limit:120
        });
    if(!ctx?.ok)throw {status:Number(ctx?.status)||401,code:ctx?.code||(internal?"INTERNAL_CONTEXT_DENIED":"API_KEY_INVALID")};
    if(ctx.prior){
      const priorFingerprint=String(ctx.prior.request_fingerprint||"");
      if(!priorFingerprint||priorFingerprint!==requestFingerprint){
        throw {status:409,code:"REQUEST_ID_REUSE_MISMATCH"};
      }
      if(internal){
        const marked=await rpc("trustrelay_mark_portal_decision_v07",{
          p_auth_user_id:internalUserId,p_org_id:ctx.organization.id,p_request_id:requestId
        });
        if(!marked?.ok)throw {status:Number(marked?.status)||403,code:marked?.code||"PORTAL_AUDIT_BINDING_FAILED"};
        ctx.prior.source="portal";
      }
      return json({
        idempotent:true,requestId,decision:publicDecision(ctx.prior),
        rate:ctx.rate,organization:{id:ctx.organization.id,name:ctx.organization.name,mode:ctx.organization.mode}
      });
    }

    const runtime=await rpc("trustrelay_org_runtime_v10",{p_org_id:ctx.organization.id});
    if(!runtime?.ok) throw {status:Number(runtime?.status)||403,code:runtime?.code||"ORGANIZATION_RUNTIME_BLOCKED"};

    const quota=await rpc("trustrelay_plan_capacity_v10",{p_org_id:ctx.organization.id,p_metric:"decisions"});
    if(!quota?.ok) throw {status:Number(quota?.status)||409,code:quota?.code||"PLAN_CONFIGURATION_INVALID"};
    if(quota.allowed===false) throw {status:429,code:"PLAN_LIMIT_EXCEEDED",details:{metric:"decisions",current:quota.current,limit:quota.limit,planCode:quota.planCode}};

    const verified=await verifyCredential(token);
    let result;
    let authority=verified.valid===true ? (verified.authority || null) : null;
    let credentialJti=verified.valid===true ? (verified?.credential?.jti || null) : null;
    let grantId=verified.valid===true ? (authority?.grantId || null) : null;
    let principalId=verified.valid===true ? (authority?.principalPersonId || null) : null;
    let representativeId=verified.valid===true ? (authority?.representativePersonId || null) : null;

    if (verified.valid !== true) {
      result={
        decision:"DENY",
        reasonCode:String(verified.reasonCode||"CREDENTIAL_INVALID"),
        reasonDetail:"The presented TrustRelay credential is not currently valid."
      };
    } else {
      const [assurance,evidenceResolution]=await Promise.all([
        rpc("trustrelay_get_grant_assurance_v08",{p_grant_id:grantId}),
        rpc("trustrelay_resolve_grant_evidence_v08",{p_grant_id:grantId,p_document_ids:evidenceDocumentIds})
      ]);
      authority={
        ...authority,
        currentAssurance:{
          principal:assurance?.principal||null,
          representative:assurance?.representative||null
        }
      };
      const evaluationEvidence={
        metadata:evidence,
        verifiedDocumentCount:Number(evidenceResolution?.verifiedDocumentCount||0),
        documents:Array.isArray(evidenceResolution?.documents)?evidenceResolution.documents:[]
      };
      result=await rpc("trustrelay_evaluate_authority_v07",{
        p_authority:authority,
        p_action:action,
        p_resource:resource,
        p_amount:amount,
        p_currency:currency,
        p_evidence:evaluationEvidence
      });
      evidence.verifiedDocumentCount=evaluationEvidence.verifiedDocumentCount;
      evidence.verifiedDocuments=evaluationEvidence.documents;
    }

    const decidedAt=new Date().toISOString();
    const decisionId="dec_"+crypto.randomUUID().replaceAll("-","");
    const recordRaw=await rpc("record_authorization_decision_v05",{
      p_id:decisionId,
      p_request_id:requestId,
      p_correlation_id:correlationId,
      p_organization_id:ctx.organization.id,
      p_api_key_id:ctx.apiKey.id,
      p_grant_id:grantId,
      p_credential_jti:credentialJti,
      p_principal_person_id:principalId,
      p_representative_person_id:representativeId,
      p_action:action,
      p_resource:resource,
      p_decision:result.decision,
      p_reason_code:result.reasonCode,
      p_reason_detail:result.reasonDetail,
      p_policy_version:"v1.0",
      p_engine_version:"1.0.0",
      p_request_json:JSON.stringify(sanitized),
      p_policy_snapshot_json:JSON.stringify(authority||{}),
      p_evidence_json:JSON.stringify(evidence),
      p_request_fingerprint:requestFingerprint,
      p_latency_ms:Math.max(0,Math.round(performance.now()-started)),
      p_decided_at:decidedAt
    });
    const record=Array.isArray(recordRaw)?recordRaw[0]:recordRaw;
    if (!record) throw {status:503,code:"DECISION_PERSISTENCE_FAILED"};

    if(internal){
      const marked=await rpc("trustrelay_mark_portal_decision_v07",{
        p_auth_user_id:internalUserId,p_org_id:ctx.organization.id,p_request_id:requestId
      });
      if(!marked?.ok)throw {status:Number(marked?.status)||403,code:marked?.code||"PORTAL_AUDIT_BINDING_FAILED"};
    }

    const responseDecision={
      id:decisionId,requestId,correlationId,decision:result.decision,
      reasonCode:result.reasonCode,reasonDetail:result.reasonDetail,
      action,resource,grantId,credentialJti,decidedAt,
      evaluationHash:record.evaluation_hash||record.evaluationHash||null,
      auditEventId:record.audit_event_id||record.auditEventId||null,
      latencyMs:Math.max(0,Math.round(performance.now()-started)),
      source:internal?"portal":"api"
    };

    await rpc("trustrelay_after_decision_v09",{p_org_id:ctx.organization.id,p_decision_id:decisionId}).catch(()=>{});
    const eventId="evt_"+crypto.randomUUID().replaceAll("-","");
    const event={
      id:eventId,type:"decision.created",createdAt:decidedAt,
      organizationId:ctx.organization.id,
      data:{decision:responseDecision}
    };
    EdgeRuntime.waitUntil(dispatchWebhooks(ctx.organization.id,"decision.created",eventId,event));

    return json({
      requestId,decision:responseDecision,
      rate:ctx.rate,
      organization:{id:ctx.organization.id,name:ctx.organization.name,mode:ctx.organization.mode}
    },200);
  } catch (e) {
    const status=Number(e?.status)||500;
    const code=e?.code||"INTERNAL_ERROR";
    return json({error:{code,message:status>=500?"The request could not be completed.":code.replaceAll("_"," ").toLowerCase()}},status);
  }
});