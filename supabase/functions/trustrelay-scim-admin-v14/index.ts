const URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
function adminHeaders(){const k=secretKey();const h={apikey:k,"content-type":"application/json",accept:"application/json"};if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;return h}
function cors(req){const origin=req.headers.get("origin")||"";if(!origin||!APP_ORIGIN||origin!==APP_ORIGIN)return{};return{"access-control-allow-origin":origin,"access-control-allow-methods":"POST, OPTIONS","access-control-allow-headers":"authorization, apikey, content-type","access-control-max-age":"86400",vary:"Origin"}}
function out(data,status=200,req=null){return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...cors(req)}})}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d,text:t}}
async function body(req,max=32768){const n=Number(req.headers.get("content-length")||0);if(Number.isFinite(n)&&n>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};const raw=await req.text();if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
async function userFrom(req){const authorization=req.headers.get("authorization")||"";if(!/^Bearer\s+\S+/i.test(authorization))throw{status:401,code:"AUTH_REQUIRED"};const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:publishableKey(),authorization,accept:"application/json"}});if(!r.ok)throw{status:401,code:"INVALID_SESSION"};const user=await r.json();if(!user?.id)throw{status:401,code:"INVALID_SESSION"};return{user,authorization}}
async function rpcUser(name,payload,authorization){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:{apikey:publishableKey(),authorization,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(payload||{})});const x=await parse(r);if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};return x.data}
async function rpcAdmin(name,payload){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:adminHeaders(),body:JSON.stringify(payload||{})});const x=await parse(r);if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};return x.data}
function randomB64(bytes){const b=crypto.getRandomValues(new Uint8Array(bytes));let s="";for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
async function sha256Hex(value){const b=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value||""))));return[...b].map(x=>x.toString(16).padStart(2,"0")).join("")}
function endpoint(tenantKey){return URL+"/functions/v1/trustrelay-scim-v14/"+encodeURIComponent(tenantKey)}
function cleanRole(value){const r=String(value||"verifier");if(!["compliance","verifier","developer","auditor"].includes(r))throw{status:400,code:"SCIM_DEFAULT_ROLE_INVALID"};return r}

Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS"){
      const origin=req.headers.get("origin")||"";
      if(!APP_ORIGIN||origin!==APP_ORIGIN)return out({error:{code:"CORS_ORIGIN_DENIED"}},403,req);
      return new Response(null,{status:204,headers:cors(req)});
    }
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    if(!URL||!secretKey()||!publishableKey())throw{status:503,code:"SCIM_CONTROL_PLANE_NOT_CONFIGURED"};
    const {authorization}=await userFrom(req);
    const input=await body(req);
    const action=String(input.action||"");
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

    const perms=await rpcUser("trustrelay_my_org_permissions_v09",{p_org_id:orgId},authorization);
    if(perms?.permissions?.["organization.manage"]!==true)throw{status:403,code:"ORGANIZATION_PERMISSION_DENIED"};
    const sso=await rpcUser("trustrelay_sso_config_v13",{p_org_id:orgId},authorization);
    const actor=String(sso?.actorAccountId||"");
    if(!actor)throw{status:403,code:"SCIM_ADMIN_CONTEXT_REQUIRED"};

    if(action==="status"){
      const status=await rpcUser("trustrelay_scim_config_v14",{p_org_id:orgId},authorization);
      if(!status?.configured)return out({configured:false,eligible:Boolean(sso?.configured&&sso?.status==="active")},200,req);
      return out({...status,endpoint:endpoint(status.tenantKey)},200,req);
    }

    if(action==="enable"){
      if(!sso?.configured||sso?.status!=="active")throw{status:409,code:"SCIM_REQUIRES_ACTIVE_ENTERPRISE_SSO"};
      const role=cleanRole(input.defaultRole);
      const existing=await rpcUser("trustrelay_scim_config_v14",{p_org_id:orgId},authorization).catch(()=>({configured:false}));
      const tenantKey=existing?.configured&&existing?.tenantKey?String(existing.tenantKey):"scim_"+randomB64(24);
      const token="trscim_"+randomB64(36);
      const tokenHash=await sha256Hex(token);
      const last4=token.slice(-4);
      const saved=await rpcAdmin("trustrelay_scim_store_config_v14",{
        p_org_id:orgId,p_actor_account_id:actor,p_tenant_key:tenantKey,
        p_token_hash:tokenHash,p_token_last_four:last4,p_default_role:role
      });
      return out({
        configured:true,status:"enabled",endpoint:endpoint(tenantKey),
        token,tokenLastFour:last4,defaultRole:role,shownOnce:true,
        providerKind:sso.providerKind||null,...saved
      },201,req);
    }

    if(action==="rotate"){
      const current=await rpcUser("trustrelay_scim_config_v14",{p_org_id:orgId},authorization);
      if(!current?.configured)throw{status:404,code:"SCIM_NOT_CONFIGURED"};
      const token="trscim_"+randomB64(36);
      const tokenHash=await sha256Hex(token);
      const last4=token.slice(-4);
      await rpcAdmin("trustrelay_scim_rotate_token_v14",{
        p_org_id:orgId,p_actor_account_id:actor,p_token_hash:tokenHash,p_token_last_four:last4
      });
      return out({
        configured:true,status:"enabled",endpoint:endpoint(current.tenantKey),
        token,tokenLastFour:last4,defaultRole:current.defaultRole,shownOnce:true
      },200,req);
    }

    if(action==="policy"){
      const current=await rpcUser("trustrelay_scim_config_v14",{p_org_id:orgId},authorization);
      if(!current?.configured)throw{status:404,code:"SCIM_NOT_CONFIGURED"};
      const status=String(input.status||current.status||"enabled");
      const role=cleanRole(input.defaultRole||current.defaultRole);
      const saved=await rpcAdmin("trustrelay_scim_set_policy_v14",{
        p_org_id:orgId,p_actor_account_id:actor,p_status:status,p_default_role:role
      });
      return out({...saved,configured:true,endpoint:endpoint(current.tenantKey),tokenLastFour:current.tokenLastFour},200,req);
    }

    throw{status:400,code:"ACTION_INVALID"};
  }catch(e){
    return out({error:{code:e?.code||"INTERNAL_ERROR",details:e?.details||null}},Number(e?.status)||500,req);
  }
});